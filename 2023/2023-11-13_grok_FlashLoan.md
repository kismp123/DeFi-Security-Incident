# Grok Token — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-13 |
| **Protocol** | Grok Token |
| **Chain** | Ethereum |
| **Loss** | ~26 ETH |
| **Attacker** | [0x864e656c57a5a119...](https://etherscan.io/address/0x864e656c57a5a119f332c47326a35422294db5c9) |
| **Attack Tx** | [0x3e9bcee951cdad84...](https://explorer.phalcon.xyz/tx/eth/0x3e9bcee951cdad84805e0c82d2a1e982e71f2ec301a1cbd344c832e0acaee813) |
| **Vulnerable Contract** | [0x8390a1da07e376ef...](https://etherscan.io/address/0x8390a1da07e376ef7add4be859ba74fb83aa02d5) |
| **Root Cause** | Liquidity manipulation vulnerability in the xAI Grok meme token |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/grok_exp.sol) |

---
## 1. Vulnerability Overview
The Grok meme token — launched under the guise of xAI's Grok AI release — was exploited via a liquidity manipulation vulnerability, resulting in approximately 26 ETH stolen.

---
## 2. Vulnerable Code Analysis (❌/✅ annotations)
```solidity
// ❌ Vulnerable code: auto-liquidity is based on spot price
function swapAndAddLiquidity() private {
    uint256 half = tokensForLiquidity / 2;
    uint256 ethAmount = swapTokensForEth(half); // swap at current price
    // ❌ liquidity added at manipulated price
    addLiquidity(half, ethAmount);
}
// ✅ Fix: add liquidity based on TWAP
```

---
### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: liquidity manipulation vulnerability in the xAI Grok meme token
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Flash loan to borrow large amount of Grok tokens
  ├─② Trigger auto-liquidity addition mechanism
  ③ Liquidity added at manipulated price
  └─④ Extract ~26 ETH via LP tokens
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
flashLoan(grokAmount);
triggerAutoLiquidity(); // auto-liquidity at manipulated price
extractLPTokens();
repayFlashLoan();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Auto-liquidity manipulation |
| Severity | High |

---
## 6. Remediation Recommendations
1. Change auto-liquidity addition to be based on TWAP pricing
2. Set a minimum price range for liquidity addition

---
## 7. Lessons Learned
The auto-liquidity feature in meme tokens is particularly susceptible to price manipulation. This is a common risk shared by trending AI/meme-themed tokens.