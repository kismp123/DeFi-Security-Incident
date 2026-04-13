# KR Token — Token Sell Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-08 |
| **Protocol** | KR Token |
| **Chain** | BSC |
| **Loss** | ~5 ETH |
| **Attacker** | [0x835b45d38cbdccf9...](https://bscscan.com/address/0x835b45d38cbdccf99e609436ff38e31ac05bc502) |
| **Attack Tx** | [0x2abf871eb91d03bc...](https://bscscan.com/tx/0x2abf871eb91d03bc8145bf2a415e79132a103ae9f2b5bbf18b8342ea9207ccd7) |
| **Vulnerable Contract** | [0x15b1ed79ca9d7955...](https://bscscan.com/address/0x15b1ed79ca9d7955af3e169d7b323c4f1eeb5d12) |
| **Root Cause** | Price calculation error in `sellKr()` forcing a sell under unfavorable conditions |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/KR_exp.sol) |

---
## 1. Vulnerability Overview
A price calculation error in the KR Token `sellKr()` function allowed an attacker to sell tokens under favorable conditions.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: sell price calculation error
interface IKR is IERC20 {
    function sellKr(uint256 tokenToSell) external;
    // Internally uses an incorrect price calculation that favors the seller
}
// ✅ Fix: apply correct pricing formula
```

---
### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: price calculation error in sellKr() forcing a sell under unfavorable conditions
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Borrow BNB via flash loan
  ├─② Buy KR tokens (at low price)
  ├─③ Call sellKr() (at favorable price)
  └─④ ~5 ETH profit
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
flashLoan(bnbAmount);
buyKR(bnbAmount);
uint256 proceeds = krToken.sellKr(krBalance); // sell at favorable price
repayFlashLoan();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Price Calculation Error |
| Severity | Medium |

---
## 6. Remediation Recommendations
1. Mathematically verify the sell price formula
2. Confirm buy/sell price parity

---
## 7. Lessons Learned
The pricing formula in token sell functions must always be independently verified.