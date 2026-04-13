# 0x0 DEX — Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-07 |
| **Protocol** | 0x0 DEX (Privacy DEX) |
| **Chain** | Ethereum |
| **Loss** | ~$61K |
| **Attacker** | [0xcf28e9b8aa557616...](https://etherscan.io/address/0xcf28e9b8aa557616bc24cc9557ffa7fa2c013d53) |
| **Attack Tx** | [0x00b375f8e90fc54c...](https://explorer.phalcon.xyz/tx/eth/0x00b375f8e90fc54c1345b33c686977ebec26877e2c8cac165429927a6c9bdbec) |
| **Vulnerable Contract** | [0x29d2bcf0d70f95ce...](https://etherscan.io/address/0x29d2bcf0d70f95ce16697e645e2b76d218d66109) |
| **Root Cause** | Certain swap functions allowed funds to be sent to arbitrary addresses without validating the recipient address |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/0x0DEX_exp.sol) |

---
## 1. Vulnerability Overview
0x0 Privacy DEX is a privacy-focused DEX on Ethereum. Certain swap functions allowed the caller to specify an arbitrary recipient address, enabling an attacker to redirect another user's funds to their own address.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Vulnerable code: arbitrary recipient can be specified
function swap(address tokenIn, uint256 amountIn, address recipient) external {
    // ❌ No check that recipient is msg.sender
    IERC20(tokenOut).transfer(recipient, amountOut);
}
// ✅ Fix
function swap(address tokenIn, uint256 amountIn) external {
    IERC20(tokenOut).transfer(msg.sender, amountOut); // ✅ Transfer only to caller
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: certain swap functions allow funds to be sent to arbitrary addresses without recipient validation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Identify victim account
  ├─② Call swap(token, amount, attackerAddress)
  │       └─ Victim's swap output is sent to attacker
  └─③ ~$61K profit
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Intercept victim's swap
dex.swap(
    address(USDC),
    victimAmount,
    address(this) // ❌ Attacker address receives the funds
);
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Missing Access Control |
| Severity | High |

---
## 6. Remediation Recommendations
1. Always fix the swap recipient to `msg.sender`
2. Require explicit authorization when delegated swaps are needed

---
## 7. Lessons Learned
The recipient address in a swap function must always be `msg.sender`. Allowing an externally specified recipient creates an attack vector.