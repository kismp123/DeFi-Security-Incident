# Infini — Retained Developer Admin Access Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2025-02-24 |
| **Protocol** | Infini (stablecoin yield protocol, USDC-based) |
| **Chain** | Ethereum |
| **Loss** | ~$49,500,000 (USDC drained from Infini's yield vault contracts) |
| **Attacker** | Former Infini developer (insider/access retained post-employment) |
| **Vulnerable Contract** | Infini InfiniCard yield vault (admin privilege access control) |
| **Root Cause** | A developer who contributed to the Infini protocol secretly retained admin-level private key access to the protocol's contracts after completing their engagement. On February 24, 2025, this developer used the retained admin access to drain ~$49.5M in USDC from Infini's vault contracts. |
| **CWE** | CWE-284: Improper Access Control; CWE-272: Least Privilege Violation |
| **PoC Source** | Cyvers alert (Feb 24 2025); Infini official post-mortem; on-chain analysis by multiple security firms |

---
## 1. Vulnerability Overview

Infini is a stablecoin yield protocol that offered users yield on USDC deposits through its InfiniCard product. The protocol's vault contracts had admin functions protected by access control — only authorized admin addresses could call privileged functions.

A developer who had worked on building the Infini contracts retained a private key with admin privileges to those contracts without informing the Infini team. This retained access was not revoked when the developer completed their engagement, because the team was unaware the developer had admin keys separate from any official team-managed keys.

On February 24, 2025, the developer exploited this retained access to:
1. Grant their address unlimited withdrawal authority from the vault
2. Drain approximately $49.5M in USDC from Infini's vault contracts
3. Convert USDC to ETH and begin laundering through Tornado Cash

Infini's CEO Christian publicly disclosed the incident and acknowledged the root cause. The attacker was subsequently identified as a former contractor, and law enforcement involvement was reported. Some funds were reportedly linked to on-chain identity traces.

---
## 2. Attack Flow

```
Former Infini developer (attacker)
    │
    ├─[During development] Attacker secretly retains admin private key
    │       Never disclosed to Infini team or security reviewers
    │       Key not included in any access revocation after engagement ends
    │
    ├─[2025-02-24] Use retained admin key:
    │       Call admin function to grant attacker address unlimited withdrawal rights
    │       Drain ~$49.5M USDC from Infini vault contracts
    │       → Flash loan used to amplify the withdrawal in a single transaction
    │
    ├─[Laundering] Convert USDC → DAI (to avoid Circle's USDC blacklisting authority)
    │       Convert DAI → ~17,700 ETH
    │       Route ~15,470 ETH through Tornado Cash mixer
    │       Additional on-chain hops to obscure trail
    │       Note: Two-stage drain — first ~$11.4M USDC, then ~$38M USDC
    │
    ├─[Infini response]
    │       Protocol paused immediately upon detection
    │       CEO discloses incident; confirms insider nature of attack
    │       Law enforcement engaged; blockchain forensics firms retained
    │
    └─[Post-incident]
              On-chain traces identified; attacker's identity partially exposed
              Active criminal investigation
              Protocol reviewing architecture for restart
```

---
## 3. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Retained admin private key — insider threat / access not revoked post-engagement |
| **CWE** | CWE-284: Improper Access Control; CWE-272: Least Privilege Violation; CWE-732: Incorrect Permission Assignment |
| **OWASP** | A01: Broken Access Control; A07: Identification and Authentication Failures |
| **Attack Vector** | Insider with retained admin private key calls privileged protocol functions directly |
| **Preconditions** | Admin functions callable by single private key; key not revoked; no multi-sig for privileged operations |
| **Impact** | ~$49.5M USDC drained; protocol paused; criminal investigation ongoing |

---
## 4. Remediation Recommendations

1. **Multi-signature for all admin operations**: No single private key should have unilateral admin access to a protocol holding significant user funds. All privileged operations must require M-of-N multi-sig approval from the core team.
2. **Key inventory and revocation process**: Maintain an explicit inventory of all addresses with admin privileges. Upon any team member's departure or change in engagement, immediately execute a revocation transaction removing their access.
3. **Timelock on admin operations**: Privileged operations (withdrawals above threshold, role grants) should go through a timelock contract, giving the team time to detect and veto unauthorized actions.
4. **Security review of access control**: Before launch and after each team change, conduct a full audit of all admin key holders — including addresses used during development that may not be in the official key registry.
5. **Segregate development and production keys**: Development/testing admin keys must never have production access. Separate key management for testnet and mainnet is mandatory.

---
## 5. Lessons Learned

- **Insider threats are distinct from external attacks**: Traditional smart contract audits check code logic but not who holds the keys. Access control audits must include personnel and key management reviews, not just code.
- **Admin key retention is a covert long game**: The attacker retained access well in advance of the exploit. The window between "key retention" and "drain" may span months or years — detection requires ongoing monitoring of all admin key activity, not just incident response.
- **February 2025 was a concentrated attack period**: Bybit ($1.4B, Feb 21), Infini ($49.5M, Feb 24), and zkLend ($9.6M, Feb 12) all occurred within the same 2-week window — though these appear to be unrelated attacks by different parties.
- **Contractor and freelancer key management**: Protocols that engage freelance or contract developers face particular risk of retained access. Formal offboarding must include key revocation as a mandatory documented step.
