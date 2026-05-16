# ZKsync Era — Airdrop Distributor Admin Key Compromise Analysis

| Field | Details |
|------|------|
| **Date** | 2025-04-15 |
| **Protocol** | ZKsync Era (ZK token airdrop distributor contract) |
| **Chain** | ZKsync Era (L2) |
| **Loss** | ~$5,000,000 (~111,000,000 ZK tokens drained from unclaimed airdrop reserves) |
| **Attacker** | Unknown |
| **Vulnerable Contract** | ZKsync airdrop distributor contract (`sweepUnclaimed()` admin function) |
| **Root Cause** | The private key controlling the admin address of ZKsync's airdrop distributor contract was compromised. The attacker used the admin `sweepUnclaimed()` function to drain approximately 111 million unclaimed ZK tokens from the airdrop reserve, converting them for ~$5M. |
| **CWE** | CWE-284: Improper Access Control; CWE-522: Insufficiently Protected Credentials |
| **PoC Source** | ZKsync official disclosure (Apr 15 2025); ZachXBT and blockchain security firms on-chain analysis |

---
## 1. Vulnerability Overview

ZKsync Era conducted a major ZK token airdrop in 2024. The airdrop was distributed via a smart contract with a `sweepUnclaimed()` function reserved for the admin address — designed to allow the ZKsync Foundation to eventually reclaim unclaimed tokens after a specified deadline.

On April 15, 2025, the admin private key controlling the airdrop distributor contract was compromised. The attacker used the `sweepUnclaimed()` function to transfer approximately 111 million unclaimed ZK tokens to attacker-controlled addresses. At the time of the attack, ZK token price placed the value at approximately $5M.

The ZKsync Foundation confirmed the incident and stated that the attack was limited to the airdrop distributor contract — the ZKsync protocol itself, user funds, and the broader ZK token supply were not affected. The attacker converted a portion of the stolen ZK to ETH and began laundering.

---
## 2. Attack Flow

```
Attacker
    │
    ├─[Pre-exploit] Obtain private key for airdrop distributor admin address
    │       (method: phishing, credential breach, or infrastructure compromise)
    │
    ├─[2025-04-15] Call sweepUnclaimed() with compromised admin key:
    │       Transfer ~111,000,000 unclaimed ZK tokens to attacker addresses
    │       Value at time: ~$5M
    │
    ├─[Partial conversion] Swap portion of stolen ZK to ETH on DEXs
    │       ZK price drops on selling pressure
    │
    ├─[ZKsync Foundation response]
    │       Confirms incident via official channels
    │       States protocol and user funds unaffected
    │       Engages law enforcement and blockchain forensics
    │       Offers 10% white hat bounty (~500K ZK / ~$50K) for return of funds
    │
    └─[Outcome — RESOLVED]
              Attacker accepts 10% bounty within 72-hour safe harbor window
              Returns ~$5.7M (~90% of stolen ZK tokens + price appreciation)
              by April 23, 2025 — ZKsync Foundation confirms no further action taken
              ZK price recovers; ZKsync Foundation closes incident
```

---
## 3. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Airdrop distributor admin key compromise → `sweepUnclaimed()` misuse |
| **CWE** | CWE-284: Improper Access Control; CWE-522: Insufficiently Protected Credentials |
| **OWASP** | A07: Identification and Authentication Failures |
| **Attack Vector** | Compromised admin private key used to call `sweepUnclaimed()` on airdrop distributor |
| **Preconditions** | Single admin key with unilateral sweep authority; key stored insecurely |
| **Impact** | ~$5M in ZK tokens drained from airdrop reserves; broader ZKsync protocol unaffected |

---
## 4. Remediation Recommendations

1. **Multi-sig for all admin functions**: The `sweepUnclaimed()` and similar admin functions must require M-of-N multi-sig approval. A single private key should never have unilateral authority over significant token reserves.
2. **Timelock on sweep operations**: The admin sweep function should be callable only after a timelock period (e.g., 72 hours), giving the team time to detect and cancel unauthorized calls.
3. **HSM for admin keys**: Admin keys for contracts holding significant assets must be stored in HSMs, not hot wallets or server environments.
4. **Limited sweep scope**: Rather than a single sweep of all unclaimed tokens, consider implementing staged sweeps with per-call limits, reducing the blast radius of any single key compromise.

---
## 5. Lessons Learned

- **Airdrop contracts need production-level security**: Airdrop distributor contracts holding millions in unclaimed tokens are high-value targets. They often receive less security attention than core protocol contracts but hold equivalent value.
- **Admin sweep functions are attractive targets**: Any contract with a function that can move large token balances to an arbitrary address with a single key signature will be targeted if the key becomes compromised.
- **Limited blast radius as the correct narrative**: ZKsync's transparent communication that the breach was limited to the airdrop distributor (not the protocol or user funds) was the correct incident response posture — accurate scoping prevents market panic and maintains trust.
- **Bounty negotiation succeeded**: ZKsync's 10% bounty offer (~500K ZK / ~$50K) succeeded — the attacker returned ~$5.7M (~90% of tokens, plus appreciation) by April 23, 2025, within the 72-hour safe harbor window. This is a notable case where the white-hat bounty structure worked as intended, with the attacker accepting the offer rather than attempting to launder stolen funds. Earlier contact attempts have higher success rates; ZKsync's rapid public communication and clear bounty structure enabled this resolution.
