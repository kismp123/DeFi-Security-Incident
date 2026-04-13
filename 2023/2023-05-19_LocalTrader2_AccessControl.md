# LocalTrader2 — Repeated Access Control Vulnerability Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-19 |
| **Protocol** | LocalTrader (2nd incident) |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | 4 additional transactions |
| **Vulnerable Contract** | LocalTrader Contract |
| **Root Cause** | Same missing access control as the 1st attack |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/LocalTrader2_exp.sol) |

---
## 1. Vulnerability Overview

Following the 1st attack on LocalTrader, a 2nd attack occurred exploiting the same vulnerability. A total of 8 attack transactions were recorded.

## 2. Attack Flow

Identical to the 1st attack. The same vulnerability was reused without any patch applied.

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: same missing access control as the 1st attack
// Source code unverified — based on bytecode analysis
```

## 3. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control (repeated) |
| **DASP Classification** | Access Control |

## 4. Remediation Recommendations
Immediate patching, temporary protocol suspension, and emergency asset migration.

## 7. Lessons Learned
The 2nd attack occurred without any immediate response following the 1st attack. A mechanism to immediately suspend the protocol upon vulnerability detection is essential.