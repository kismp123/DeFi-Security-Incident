# NeutraFinance — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-08-21 |
| **Protocol** | NeutraFinance |
| **Chain** | Arbitrum |
| **Loss** | Unclear |
| **Attacker** | [0x3747dbbcb5c07786a4...](https://arbiscan.io/address/0x3747dbbcb5c07786a4c59883e473a2e38f571af9) |
| **Attack Tx** | [0x6301d4c9f7ac1c96a6...](https://explorer.phalcon.xyz/tx/arbitrum/0x6301d4c9f7ac1c96a65e83be6ea2fff5000f0b1939ad24955e40890bd9fe6122) |
| **Vulnerable Contract** | [0x3747dbbcb5c07786a4...](https://arbiscan.io/address/0x3747dbbcb5c07786a4c59883e473a2e38f571af9) |
| **Root Cause** | Price oracle directly consumed Balancer AMM spot price without TWAP, making it manipulable via large swaps within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-08/NeutraFinance_exp.sol) |

---
## 1. Vulnerability Overview

NeutraFinance is an Arbitrum-based yield optimization protocol. Its internal price calculation relied on Balancer pool balances, making it vulnerable to flash loan manipulation.

---
## 2. Vulnerable Code Analysis (❌/✅ annotations)

```solidity
// ❌ Vulnerable code: price calculated from Balancer pool balances
function getTokenValue() public view returns (uint256) {
    (, uint256[] memory balances,) = IVault(balancerVault).getPoolTokens(poolId);
    return balances[0] * 1e18 / balances[1]; // ❌ manipulable via flash loan
}
// ✅ Fix: use Chainlink oracle
```

### On-chain Original Code

Source: bytecode decompilation

```solidity
// Root cause: price oracle directly consumed Balancer AMM spot price without TWAP, making it manipulable via large swaps within a single block
// Source code unverified — based on bytecode analysis
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  ├─① Borrow large amount of tokens via Balancer flash loan
  ├─② Manipulate pool balances → price distortion
  ├─③ Open NeutraFinance position at manipulated price
  ├─④ Restore price, then close position for profit
  └─⑤ Repay flash loan
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Balancer flash loan callback
function receiveFlashLoan(IERC20[] memory tokens, uint256[] memory amounts, ...) external {
    manipulateBalancerPool(); // manipulate pool balances
    exploitNeutraFinance();   // attack using manipulated price
    repayBalancer();
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| Vulnerability Type | Oracle Manipulation |
| Severity | High |

---
## 6. Remediation Recommendations

1. Switch price source to Chainlink oracle
2. Redesign to avoid reliance on Balancer pool prices

---
## 7. Lessons Learned

Balancer flash loans can temporarily shift pool balances significantly, making them dangerous to use as an oracle source.