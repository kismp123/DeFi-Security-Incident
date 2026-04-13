# APIG — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-11 |
| **Protocol** | APIG |
| **Chain** | BSC |
| **Loss** | ~$169K (59.5 ETH + 72K USDT) |
| **Attacker** | [0x73d80500b30a6ca8...](https://bscscan.com/address/0x73d80500b30a6ca840bfab0234409d98cf588089) |
| **Attack Tx** | [0x66dee84591aeeba6...](https://bscscan.com/tx/0x66dee84591aeeba6e5f31e12fe728f2ddc79a06426036793487a980c3b952947) |
| **Vulnerable Contract** | [0xfdc6a621861ed2a8...](https://bscscan.com/address/0xfdc6a621861ed2a846ab475c623e13764f6a5ad0) |
| **Root Cause** | Collateral value calculation relies on AMM spot reserves, allowing collateral value to be inflated via large swaps within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/APIG_exp.sol) |

---
## 1. Vulnerability Overview
The APIG protocol on BSC offered loans collateralized by ETH and USDT. Because collateral value calculation depended on real-time DEX prices, a flash loan manipulation drained $169K.

---
## 2. Vulnerable Code Analysis (❌/✅ annotations)
```solidity
// ❌ Vulnerable code: collateral calculated using DEX spot price
function getCollateralValue(address token, uint256 amount) public view returns (uint256) {
    return amount * getDEXSpotPrice(token) / 1e18; // ❌ manipulable
}
// ✅ Fix: Chainlink oracle
```

---
### On-Chain Source Code

Source: bytecode decompilation

```solidity
// Root cause: collateral value calculation relies on AMM spot reserves,
// allowing collateral value to be inflated via large swaps within a single block
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Borrow large token amount via flash loan
  ├─② Manipulate collateral token price to spike sharply
  ├─③ Borrow ETH+USDT against inflated collateral value
  ├─④ Repay flash loan
  └─⑤ ~$169K profit
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
flashLoan(largeTokenAmount);
manipulateAPIG_Price();
uint256 loan = apig.borrow(ETH_USDT, largeAmount);
repayFlashLoan();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Oracle Manipulation |
| Severity | Critical |

---
## 6. Remediation Recommendations
1. Use Chainlink oracle for collateral value calculation
2. Restrict large collateral changes within a single block

---
## 7. Lessons Learned
In lending protocols, collateral value calculation is the most critical security component.