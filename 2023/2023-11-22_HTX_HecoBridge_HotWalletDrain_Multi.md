# HTX Exchange / Heco Bridge — Hot Wallet Compromise Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-22 |
| **Protocol** | HTX Exchange (formerly Huobi) + Heco Bridge (both Justin Sun-affiliated) |
| **Chain** | Ethereum, Heco Chain, Tron |
| **Loss** | ~$99,000,000–$115,000,000 combined (HTX hot wallets ~$13.6M; Heco Bridge ~$87M; combined total varies by source and timing of assessment; CNBC cited ~$115M including later-discovered HTX losses) |
| **Attacker** | Unknown (DPRK Lazarus Group suspected) |
| **Vulnerable System** | HTX exchange hot wallets; Heco cross-chain bridge custody accounts |
| **Root Cause** | Private keys for both the HTX exchange hot wallets and the Heco Bridge cross-chain bridge custody accounts were compromised simultaneously, allowing the attacker to drain assets across both systems in a coordinated attack |
| **CWE** | CWE-284: Improper Access Control (key management) |
| **PoC Source** | PeckShield, SlowMist on-chain analysis; HTX/Justin Sun official disclosure |

---
## 1. Vulnerability Overview

HTX (formerly Huobi Global) and Heco Bridge are both affiliated with Justin Sun (TRON ecosystem). On November 22, 2023 — just 12 days after the Poloniex hack — attackers struck again at Justin Sun-affiliated infrastructure.

**HTX exchange**: ~$13.6M drained from exchange hot wallets across Ethereum and other chains. HTX had previously suffered a $7.9M hot wallet hack on September 24, 2023.

**Heco Bridge**: The far larger loss (~$87M per ImmuneBytes/Halborn on-chain analysis) came from the Heco cross-chain bridge, which manages an asset pool on Ethereum for cross-chain transfers to/from Heco Chain. The bridge's Ethereum custody address private keys were compromised, allowing the attacker to drain the entire liquidity pool: USDT, ETH, HBTC, SHIB, LINK, UNI, and other tokens. Some sources (CNBC) report the combined total as $115M, which may reflect later-discovered HTX losses beyond the initial $13.6M figure.

The coordinated simultaneous attack on both HTX and Heco Bridge strongly suggests the attacker had pre-obtained private keys for both systems through shared infrastructure compromise.

---
## 2. Attack Flow

```
Attacker (Lazarus Group suspected)
    │
    ├─[Pre-exploit] Obtain private keys for:
    │       - HTX exchange hot wallets
    │       - Heco Bridge Ethereum custody account
    │       (method: phishing, insider, shared infrastructure breach)
    │
    ├─[2023-11-22] Coordinated simultaneous drain:
    │       │
    │       ├─ HTX hot wallets: ~$13.6M
    │       │   (ETH, USDT, HUSD, other tokens)
    │       │
    │       └─ Heco Bridge custody: ~$87M (ImmuneBytes/Halborn on-chain)
    │           (USDT ~$42M, ETH ~$22M, HBTC ~$10M, SHIB/LINK/UNI/others ~$13M)
    │           Total bridge drain: ~$87M
    │
    ├─[Justin Sun response] Acknowledges both hacks publicly
    │       HTX promises to compensate hot wallet losses from revenue
    │       Heco Bridge suspended
    │
    └─[Total combined loss] ~$115M across both platforms
              Funds routed through DeFi protocols and mixers
```

---
## 3. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Private key compromise — exchange hot wallets and bridge custody |
| **CWE** | CWE-284: Improper Access Control; CWE-922: Insecure Storage of Sensitive Information |
| **Attack Vector** | Coordinated multi-system private key extraction |
| **Preconditions** | Shared infrastructure or key management between HTX and Heco Bridge; keys compromised |
| **Impact** | ~$115M combined; Heco Bridge suspended; HTX operations disrupted |

---
## 4. Lessons Learned

- **Shared infrastructure compounds blast radius**: The simultaneous compromise of both HTX and Heco Bridge suggests shared key management infrastructure or administrative access. Organizations managing multiple high-value systems must use completely isolated key management for each.
- **Repeat targeting of Justin Sun entities**: Poloniex (Nov 10), HTX/Heco (Nov 22), and earlier HTX (Sep 24) attacks within a 3-month period against the same entity's infrastructure indicates persistent, targeted reconnaissance — not opportunistic attacks.
- **Bridge TVL is concentrated risk**: The Heco Bridge held ~$87M in a single Ethereum custody address. Bridge designs must shard liquidity across multiple independently-keyed addresses with per-transaction and per-period transfer limits.
- **Serial hack pattern**: The 12-day gap between Poloniex ($126M, Nov 10) and HTX/Heco ($115M, Nov 22) against the same organization is consistent with an attacker systematically exploiting previously-obtained access across multiple affiliated platforms.
