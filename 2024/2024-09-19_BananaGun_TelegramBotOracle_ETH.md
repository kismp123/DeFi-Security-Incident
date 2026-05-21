# Banana Gun — Telegram Bot Oracle Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-19 |
| **Protocol** | Banana Gun |
| **Chain** | Ethereum |
| **Loss** | ~$3,000,000 (11 user wallets drained; protocol refunded all victims 100% from treasury — net user loss: $0) |
| **Attacker** | Unknown |
| **Attack Tx** | Multiple transactions across ~36 victim accounts |
| **Vulnerable Contract** | Banana Gun Telegram trading bot backend oracle |
| **Root Cause** | Attacker exploited a vulnerability in the Banana Gun oracle/backend to trigger unauthorized ETH transfers from bot users' wallets, bypassing transaction confirmation |
| **PoC Source** | Not public (backend/oracle exploit, no on-chain PoC available) |

---

## 1. Vulnerability Overview

Banana Gun is a Telegram-based DEX trading bot. Users deposit ETH into bot-controlled wallets to enable automated sniping and trading. On September 19, 2024, an attacker discovered and exploited a vulnerability in the Banana Gun oracle or backend transaction routing system.

The exploit allowed the attacker to initiate ETH transfer transactions from 11 user wallets without user authorization. The transfers occurred while users watched their bot dashboards in real time, observing outgoing transactions they had not initiated. Despite the real-time visibility, the backend flaw allowed the transfers to complete before users could intervene.

## 2. Attack Mechanism

The precise technical root cause was not fully disclosed by Banana Gun. Based on the incident report:

- The attacker appears to have found a way to inject or replay authorization signals accepted by the Banana Gun backend
- The backend oracle that validates and routes user transaction requests failed to properly authenticate the source of transfer commands
- 11 user accounts were drained of ETH totaling ~$3M

```
Attacker
  │
  ├─1─▶ Discover oracle/backend authorization flaw
  │
  ├─2─▶ Inject unauthorized ETH transfer commands for 11 user wallets
  │       (commands accepted as authorized by backend oracle)
  │
  ├─3─▶ ETH transfers execute on-chain before users can react
  │       ~$3M total across 11 accounts
  │
  └─4─▶ Protocol detects anomaly, pauses bot, begins investigation
```

## 3. Post-Incident Response

- Banana Gun paused the bot within hours of the exploit
- Full investigation conducted; root cause not fully published (backend oracle flaw)
- Protocol refunded all 11 affected users 100% from treasury funds
- Bot relaunched with upgraded backend authentication and rate-limit controls
- Zero net user losses after refund

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Vulnerability Type** | Backend Oracle / Authorization Bypass |
| **Attack Vector** | Off-chain backend (Telegram bot oracle layer) |
| **Impact Scope** | 11 Banana Gun users (~$3M) |
| **DASP Classification** | Access Control |
| **CWE** | CWE-287: Improper Authentication |

## 5. Lessons Learned

- Telegram trading bots hold user funds in custodial or semi-custodial wallets; backend authentication is a critical attack surface
- Transaction authorization should require cryptographic signatures from the user's private key, not solely backend session tokens
- Real-time monitoring and automatic circuit breakers can limit losses when anomalous outflow patterns are detected
- Protocol refund capacity (treasury coverage) should be pre-planned for custodial products
