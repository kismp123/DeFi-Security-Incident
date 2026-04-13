# MetaLend — Compound Fork Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-24 |
| **Protocol** | MetaLend |
| **Chain** | Ethereum |
| **Loss** | ~$4K |
| **Attacker** | [0x0c06340f5024c114...](https://etherscan.io/address/0x0c06340f5024c114fe196fcb38e42d20ab00f6eb) |
| **Attack Tx** | [0x4c684fb2618c2974...](https://etherscan.io/tx/0x4c684fb2618c29743531dec9253ede1b757bda0b323dc2f305e3b50ab1773da7) |
| **Vulnerable Contract** | [0x5578f2e245e932a5...](https://etherscan.io/address/0x5578f2e245e932a599c46215a0ca88707230f17b) |
| **Root Cause** | Donation attack against an empty Compound fork market |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/MetaLend_exp.sol) |

---
## 1. Vulnerability Overview
MetaLend suffered a $4K loss via the same Compound fork donation attack pattern. Although small in scale, it is a repeat of the identical attack vector.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Same pattern: balanceOf-based rate
function getCash() public view returns (uint256) {
    return underlying.balanceOf(address(this)); // ❌
}
// ✅ Use internal variable instead
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root Cause: Donation attack against an empty Compound fork market
// Source code unverified — based on bytecode analysis
```

---
## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Deposit 1 wei into empty market
  ├─② Manipulate exchange rate via direct transfer
  └─③ Borrow inflated amount
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
cToken.mint(1);
underlying.transfer(address(cToken), giftAmount);
cToken.borrow(inflatedAmount);
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Donation Attack |
| Severity | Medium |

---
## 6. Remediation Recommendations
1. Use an internal cash-tracking variable
2. Review the security patch checklist when forking Compound

---
## 7. Lessons Learned
Throughout 2023, the same Compound donation attack was repeated dozens of times. Any fork must patch this vulnerability before deployment.