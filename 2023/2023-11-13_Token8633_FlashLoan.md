# Token8633/9419 — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-13 |
| **Protocol** | Token 8633/9419 |
| **Chain** | BSC |
| **Loss** | ~$52K |
| **Attacker** | [0xe9fac789c947f364...](https://bscscan.com/address/0xe9fac789c947f364f53c3bc28bb6e9e099526468) |
| **Attack Tx** | [0xf6ec3c22b718c3da...](https://explorer.phalcon.xyz/tx/bsc/0xf6ec3c22b718c3da17746416992bac7b65a4ef42ccf5b43cf0716c82bffc2844) |
| **Vulnerable Contract** | [0x11cd2168fc420ae1...](https://bscscan.com/address/0x11cd2168fc420ae1375626655ab8f355f0075bd6) |
| **Root Cause** | Both token contracts use unvalidated AMM spot reserves for reward/price calculation, allowing manipulation within a single transaction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/Token8633_9419_exp.sol) |

---
## 1. Vulnerability Overview
The attacker simultaneously exploited two vulnerable contracts, Token 8633 and Token 9419, draining $52K. Both tokens shared the same vulnerable pattern.

---
## 2. Vulnerable Code Analysis (❌/✅ annotations)
```solidity
// ❌ Both tokens share the same vulnerable pattern
// Price calculation based on pool balance
function getPrice() public view returns (uint256) {
    return token.balanceOf(pool) * 1e18 / BUSD.balanceOf(pool); // ❌
}
// ✅ Use TWAP instead
```

---
### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: both token contracts use unvalidated AMM spot reserves for reward/price calculation, allowing manipulation within a single transaction
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Borrow BUSD via flash loan
  ├─② Manipulate Token 8633 pool price → profit
  ├─③ Manipulate Token 9419 pool price → profit
  └─④ Repay flash loan + ~$52K
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Simultaneously attack both vulnerable tokens
flashLoan(busdAmount);
attackToken8633();
attackToken9419();
repayFlashLoan();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Price Manipulation (multiple tokens) |
| Severity | High |

---
## 6. Remediation Recommendations
1. Adopt a TWAP oracle
2. Apply batch patches across all tokens sharing the same codebase

---
## 7. Lessons Learned
Multiple tokens sharing the same vulnerable codebase can be exploited simultaneously in a single attack.