# SVT — Price Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-08-31 |
| **Protocol** | SVT |
| **Chain** | BSC |
| **Loss** | Unclear |
| **Attacker** | [0x84f37f6cc75ccde5fe...](https://bscscan.com/address/0x84f37f6cc75ccde5fe9ba99093824a11cfdc329d) |
| **Attack Tx** | [0xf2a0c957fef493af44...](https://bscscan.com/tx/0xf2a0c957fef493af44f55b201fbc6d82db2e4a045c5c856bfe3d8cb80fa30c12) |
| **Vulnerable Contract** | [0x84f37f6cc75ccde5fe...](https://bscscan.com/address/0x84f37f6cc75ccde5fe9ba99093824a11cfdc329d) |
| **Root Cause** | SVT token's `buy()` function uses a manipulable price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-08/SVT_exp.sol) |

---
## 1. Vulnerability Overview

The `buy()` function of the SVT pool calculated the price based on the current pool state. An attacker exploited this via a flash loan.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable code
interface ISVTpool {
    function buy(uint256 amount) external;
    // Internally uses spot price → manipulable
}
// ✅ Fix: Use oracle price
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: SVT token's buy() function uses a manipulable price
// Source code unverified — based on bytecode analysis
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  ├─① Borrow large amount of tokens via flash loan
  ├─② Manipulate SVT pool price
  ├─③ Call buy() → purchase at artificially low price
  └─④ Sell at normal price to profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
flashLoan(largeAmount);
// In callback:
manipulateSVTPrice();
svtPool.buy(largeAmount); // Buy at depressed price
sellSVT(); // Sell at normal price
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| Vulnerability Type | Price Manipulation |
| Severity | High |

---
## 6. Remediation Recommendations

1. Use TWAP-based pricing
2. Add slippage protection to the `buy()` function

---
## 7. Lessons Learned

Pool-based prices are always at risk of manipulation.