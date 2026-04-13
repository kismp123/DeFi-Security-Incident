# LaEeb — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-10-26 |
| **Protocol** | LaEeb |
| **Chain** | BSC |
| **Loss** | ~1.8 WBNB |
| **Attacker** | [0x7cb74265e3e2d2b7...](https://bscscan.com/address/0x7cb74265e3e2d2b707122bf45aea66137c6c8891) |
| **Attack Tx** | [0x0d13a61e9dc81cfa...](https://bscscan.com/tx/0x0d13a61e9dc81cfae324d3d80e49830d9bbae300f760e016a15600889a896a1b) |
| **Vulnerable Contract** | [0x3921e8cb14e2c08d...](https://bscscan.com/address/0x3921e8cb14e2c08db989fdf88d01220a0c53cc91) |
| **Root Cause** | Token reward calculation logic relies on instantaneous balance changes, allowing excess rewards to be claimed by holding a large position within a single transaction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/LaEeb_exp.sol) |

---
## 1. Vulnerability Overview
The internal distribution mechanism of the LaEeb token was manipulable via flash loans. Approximately 1.8 WBNB was lost.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Vulnerable code: pool balance-based distribution
function distribute() public {
    uint256 balance = token.balanceOf(pool);
    distributeToHolders(balance); // ❌ Manipulable via flash loan
}
// ✅ Fix: snapshot-based distribution
```

---
### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: token reward calculation logic relies on instantaneous balance changes, allowing excess rewards to be claimed by holding a large position within a single transaction
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Borrow WBNB via PancakeSwap flash loan
  ├─② Buy large amount of LaEeb tokens to manipulate pool
  ├─③ Call distribute() to receive excess rewards
  └─④ Sell tokens + repay flash loan + ~1.8 WBNB profit
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
pancakePair.swap(wbnbAmount, 0, address(this), data);
// In callback:
buyLaEeb(wbnbAmount);
laEeb.distribute();
sellLaEeb();
repaySwap();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Flash Loan Manipulation |
| Severity | Medium |

---
## 6. Remediation Recommendations
1. Use a snapshot mechanism for reward distribution
2. Prevent buy + reward claim within the same block

---
## 7. Lessons Learned
Small-cap tokens are also targets of flash loan attacks.