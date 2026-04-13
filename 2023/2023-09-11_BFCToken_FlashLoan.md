# BFC Token — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-11 |
| **Protocol** | BFC Token |
| **Chain** | BSC |
| **Loss** | ~$38K |
| **Attacker** | [0x7cb74265e3e2d2b7...](https://bscscan.com/address/0x7cb74265e3e2d2b707122bf45aea66137c6c8891) |
| **Attack Tx** | [0x8ee76291c1b46d26...](https://bscscan.com/tx/0x8ee76291c1b46d267431d2a528fa7f3ea7035629500bba4f87a69b88fcaf6e23) |
| **Vulnerable Contract** | [0x595eac4a0ce9b717...](https://bscscan.com/address/0x595eac4a0ce9b7175a99094680fbe55a774b5464) |
| **Root Cause** | Token transfer fee reduces the LP pair's reserve, causing a discrepancy between `balanceOf` and reserve — excess can be extracted via `skim()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/BFCToken_exp.sol) |

---
## 1. Vulnerability Overview
BFC Token's transfer fee mechanism allowed price manipulation when combined with a flash loan. Approximately $38K was lost.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: fee + spot price combined
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 fee = amount * feeRate / 100;
    super._transfer(from, feeCollector, fee);
    super._transfer(from, to, amount - fee);
    // ❌ Fee collection alters pool balance → price distortion
}
// ✅ Fix: exempt fees during swaps
```

---
### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: token transfer fee reduces the LP pair's reserve, causing a discrepancy between balanceOf and reserve — excess can be extracted via skim()
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Borrow via flash loan
  ├─② Trigger fee mechanism to manipulate pool price
  ├─③ Execute favorable swap
  └─④ ~$38K profit
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
flashLoan(bnbAmount);
triggerFeeToManipulatePrice();
profitableSwap();
repay();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Fee Mechanism Vulnerability |
| Severity | High |

---
## 6. Remediation Recommendations
1. Audit AMM interactions for fee-on-transfer tokens
2. Use TWAP oracle for price calculations

---
## 7. Lessons Learned
Tokens with fee mechanisms must always be carefully designed with respect to their interactions with AMMs.