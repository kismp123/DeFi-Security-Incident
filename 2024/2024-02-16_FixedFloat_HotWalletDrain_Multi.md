# FixedFloat Exchange — Hot Wallet Private Key Compromise Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-16 |
| **Protocol** | FixedFloat (non-custodial cryptocurrency exchange) |
| **Chain** | Multiple (Bitcoin, Ethereum) |
| **Loss** | ~$26,100,000 (~1,728 ETH ($4.85M) + ~409 BTC ($21.17M)) |
| **Attacker** | Unknown |
| **Vulnerable System** | FixedFloat hot wallet infrastructure (Bitcoin and Ethereum private keys) |
| **Root Cause** | Hot wallet private keys for both the Bitcoin and Ethereum operational wallets were compromised, enabling simultaneous drain of both chains' hot wallet balances |
| **CWE** | CWE-284: Improper Access Control; CWE-922: Insecure Storage of Sensitive Information |
| **PoC Source** | ZachXBT on-chain analysis; FixedFloat official statement (Feb 16-17 2024) |

---
## 1. Vulnerability Overview

FixedFloat is an automated non-custodial cryptocurrency exchange that processes thousands of currency swaps without requiring user registration. Despite marketing as "non-custodial" (meaning user funds are not held between swaps), FixedFloat maintains operational hot wallets for liquidity and pending order fulfillment.

On February 16, 2024, these operational hot wallets were drained:
- **Ethereum wallet**: ~1,728 ETH (~$4.85M)
- **Bitcoin wallet**: ~409 BTC (~$21.17M)
- **Total**: ~$26.1M

Users reported frozen and failed orders, prompting social media discussion before FixedFloat issued an official acknowledgment. The exchange suspended operations temporarily and later disclosed the hack.

The attacker exploited weak security on FixedFloat's backend infrastructure, with some reports suggesting the breach occurred through access to the exchange's admin panel or internal API — potentially through a compromised employee credential or infrastructure vulnerability rather than a direct key extraction. FixedFloat's post-incident communication was limited, and the precise attack vector was not fully disclosed.

---
## 2. Attack Flow

```
Attacker
    │
    ├─[Pre-exploit] Gain access to FixedFloat infrastructure
    │       (likely: admin panel breach, API credential compromise, or insider)
    │
    ├─[2024-02-16] Drain hot wallets:
    │       Ethereum: ~1,728 ETH ($4.85M) → attacker address
    │       Bitcoin: ~409 BTC ($21.17M) → attacker address
    │       Total: ~$26.1M
    │
    ├─[User reports] Frozen orders trigger user complaints on social media
    │       FixedFloat website shows maintenance mode
    │
    ├─[FixedFloat response]
    │       Acknowledges "minor technical problems" initially
    │       Feb 17: Issues official statement confirming hack
    │       Suspends exchange operations; investigates breach
    │       Later resumes operations with improved security measures
    │
    └─[Laundering] ETH and BTC routed through mixing protocols
              No confirmed attribution or fund recovery
```

---
## 3. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Hot wallet private key compromise (automated exchange operational wallet) |
| **CWE** | CWE-284: Improper Access Control; CWE-922: Insecure Storage of Sensitive Information |
| **OWASP** | A07: Identification and Authentication Failures; A05: Security Misconfiguration |
| **Attack Vector** | Admin/API compromise or direct key theft from hot wallet infrastructure |
| **Preconditions** | Operational hot wallets holding significant BTC and ETH balances; infrastructure accessible via compromised credentials |
| **Impact** | ~$26.1M drained; exchange operations suspended; no confirmed recovery |

---
## 4. Lessons Learned

- **Non-custodial marketing vs. operational custody reality**: FixedFloat markets as "non-custodial" but maintains substantial hot wallets for operations. This creates a custody risk that the branding obscures — security architecture must match operational reality, not marketing claims.
- **Admin panel and backend API hardening**: The likely attack vector through admin/API access highlights that backend infrastructure security is as critical as smart contract security. Rate limiting, IP whitelisting, MFA enforcement, and audit logging are essential for all admin interfaces.
- **February 2024 exchange hack cluster**: FixedFloat ($26.1M, Feb 16) occurred alongside PlayDapp ($32M realized, Feb 9-12) and preceded DMM Bitcoin ($305M, May 31) — all within the same general threat landscape period. Multiple unrelated attackers targeting exchange infrastructure simultaneously suggests opportunistic attacks rather than a coordinated campaign.
