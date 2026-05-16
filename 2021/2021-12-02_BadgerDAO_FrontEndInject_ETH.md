# BadgerDAO — Frontend Script Injection Approval Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2021-12-02 |
| **Protocol** | BadgerDAO (Bitcoin yield aggregator on Ethereum) |
| **Chain** | Ethereum |
| **Loss** | ~$120,000,000 (~2,100 BTC equivalent in ibBTC, WBTC, renBTC, cvxCRV, and other Curve BTC pool tokens) |
| **Attacker** | Unknown (Cloudflare API key compromised; attacker identity never publicly confirmed) |
| **Vulnerable System** | BadgerDAO frontend (app.badger.finance) — injected via Cloudflare CDN |
| **Root Cause** | Attacker obtained a Cloudflare API key giving write access to BadgerDAO's frontend CDN. Malicious JavaScript was injected that intercepted user Web3 transactions and prepended unauthorized `approve()` calls granting the attacker unlimited token allowances. Subsequent `transferFrom()` calls drained approved token balances from affected users. |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting / Frontend Injection); CWE-345: Insufficient Verification of Data Authenticity |
| **PoC Source** | BadgerDAO official post-mortem (Dec 2021); PeckShield on-chain analysis; Cloudflare incident disclosure |

> **Note:** This is a supply chain / frontend injection attack, NOT a smart contract vulnerability. BadgerDAO's on-chain smart contracts were audited and functioned correctly throughout the incident. A traditional smart contract audit would not have detected this attack vector. The vulnerability existed entirely in the web frontend delivery infrastructure.

---
## 1. Vulnerability Overview

BadgerDAO operated a Bitcoin yield aggregator on Ethereum, allowing users to deposit tokenized BTC (WBTC, renBTC, ibBTC, etc.) into Curve-based vaults and earn yield. The protocol's frontend was served via Cloudflare's CDN.

Between November 27 and December 2, 2021, an attacker who had obtained a Cloudflare API key for the BadgerDAO account injected malicious JavaScript into the `app.badger.finance` frontend. This script silently intercepted Web3 wallet transaction requests and inserted an additional `approve()` call before the user's intended transaction. The approval granted the attacker's externally-owned address unlimited spending rights over the user's ERC-20 token balances (ibBTC, WBTC, renBTC, cvxCRV, etc.).

Users who signed the modified transactions—believing they were only performing normal vault operations—unknowingly delegated full control of their token balances to the attacker. Beginning December 2, the attacker executed a series of `transferFrom()` calls draining each victim's approved balance. Badger's team discovered the attack and paused all smart contracts on December 2, 2021, halting further drainage, but approximately $120M had already been transferred.

The attack exploited no vulnerability in any Badger smart contract. The contracts paused successfully and operated as designed. The root cause was entirely in the web infrastructure layer: a compromised third-party CDN credential that granted an attacker the ability to modify the JavaScript served to end users.

---
## 2. Attack Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ Pre-Attack: Attacker obtains Cloudflare API key                      │
│ (via phishing, credential stuffing, or leaked secret)               │
│ → Gains write access to BadgerDAO's Cloudflare CDN zone             │
└────────────────────────┬────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────────┐
│ Step 1: Malicious JS injection (Nov 27 – Dec 2, 2021)               │
│ Attacker uploads tampered JavaScript to Cloudflare CDN              │
│ → app.badger.finance begins serving malicious script to users       │
└────────────────────────┬────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────────┐
│ Step 2: User visits app.badger.finance                               │
│ Browser loads and executes malicious JS alongside legitimate code    │
│ → Script hooks Web3 provider (MetaMask / WalletConnect)             │
└────────────────────────┬────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────────┐
│ Step 3: Transaction interception                                      │
│ User initiates a normal vault deposit / withdrawal                   │
│ → Malicious script intercepts the transaction request               │
│ → Prepends an ERC-20 approve() call:                                │
│   token.approve(attacker_address, type(uint256).max)                │
│ → User sees TWO transaction prompts (or one modified prompt)        │
│ → Users who approve are unknowingly granting unlimited allowance    │
└────────────────────────┬────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────────┐
│ Step 4: Allowance harvesting (Dec 2, 2021)                           │
│ Attacker calls transferFrom() on each victim's token balance        │
│ Tokens drained: ibBTC, WBTC, renBTC, cvxCRV, Curve BTC LP tokens   │
│ → ~2,100 BTC equivalent (~$120M) transferred to attacker            │
└────────────────────────┬────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────────┐
│ Step 5: Discovery and contract pause (Dec 2, 2021)                   │
│ Badger team detects anomalous approvals and on-chain drains         │
│ → All Badger smart contracts paused via guardian role               │
│ → Malicious script removed from Cloudflare CDN                      │
│ → US DOJ / FBI investigation opened; funds never recovered          │
└─────────────────────────────────────────────────────────────────────┘
```

---
## 3. PoC Code

No Foundry PoC is applicable for this incident. The attack did not exploit any on-chain smart contract vulnerability. The exploit was executed entirely at the web frontend layer: malicious JavaScript served via a compromised Cloudflare CDN caused victim browsers to submit crafted `approve()` transactions. The subsequent `transferFrom()` calls required no special contract interaction beyond standard ERC-20 mechanics using allowances that victims had unknowingly granted.

On-chain evidence of the attack is visible as a series of `Approval` events for large or `uint256.max` allowances to the attacker's address, followed by `Transfer` events draining victim balances, traceable on Etherscan across the affected token contracts (ibBTC, WBTC, renBTC, cvxCRV, and related Curve pool tokens).

---
## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------------|----------|-----|
| V-01 | Cloudflare API key compromise enabling frontend script injection | CRITICAL | CWE-345 |
| V-02 | Malicious JS intercepts Web3 transactions and injects unauthorized `approve()` calls | CRITICAL | CWE-79 |
| V-03 | No Content Security Policy (CSP) or Subresource Integrity (SRI) to detect tampered scripts | HIGH | CWE-353 |
| V-04 | Users lacked tooling to verify transaction contents before signing (approve vs. deposit) | MEDIUM | CWE-284 |

---
## 5. Remediation Recommendations

1. **Eliminate single points of failure in CDN credentials.** Rotate all CDN and third-party service API keys regularly. Apply the principle of least privilege: CI/CD deployment keys should have write access only to specific deployment paths, not the entire CDN zone.

2. **Implement Subresource Integrity (SRI) for all frontend assets.** Embed `integrity` attributes (SHA-384 hashes) on all `<script>` and `<link>` tags so browsers reject any asset that does not match the expected hash. This prevents injection even if CDN credentials are compromised.

3. **Deploy a strict Content Security Policy (CSP).** A strict CSP (`script-src 'self'` with nonces or hashes) prevents execution of injected or dynamically loaded scripts outside the expected asset manifest.

4. **Apply multi-factor authentication and IP allowlisting to all third-party infrastructure accounts** (CDN, DNS, hosting). Cloudflare and equivalent providers support hardware-key 2FA and API token scoping.

5. **Implement transaction simulation and human-readable signing prompts.** Integrate tools such as Tenderly, Blowfish, or Pocket Universe into the frontend so users see a plain-language summary of every transaction before signing (e.g., "This will grant address 0x… unlimited access to your WBTC"). Anomalous `approve()` calls to unknown addresses would be immediately visible.

6. **Monitor on-chain approvals in real time.** Set up alerting for large or `uint256.max` approvals originating from the protocol frontend to non-whitelisted addresses. Early detection (even 24 hours earlier) could have substantially reduced losses.

7. **Conduct regular third-party security audits of web infrastructure**, not only smart contracts. Include CDN configuration, DNS security, build pipeline supply chain (npm packages, CI secrets), and access control reviews.

8. **Establish an emergency pause playbook** with pre-tested runbooks so contract pausing can occur within minutes of detection rather than hours. Badger's guardian role did function correctly once the team was alerted.

---
## 6. Lessons Learned

- **Smart contract security is necessary but not sufficient.** BadgerDAO's on-chain contracts were audited, functioned correctly, and were successfully paused. The $120M loss came entirely from the web infrastructure layer. DeFi protocols must treat frontend security with the same rigor as contract security.

- **Supply chain attacks on web frontends are a distinct and underappreciated threat class.** An attacker who can modify a protocol's frontend JavaScript can silently modify every transaction a user signs. This threat does not require any contract vulnerability.

- **Third-party services (CDN, RPC endpoints, npm packages) are trust boundaries.** Any third party with write access to assets served to users is a potential attack vector. Credentials for these services must be treated as high-value secrets equivalent to private keys.

- **Unlimited ERC-20 approvals amplify the blast radius.** Many DeFi frontends request `uint256.max` approvals for user convenience. In this incident, every user who had previously granted unlimited approvals to Badger contracts—even before the malicious script existed—was a potential victim once the attacker obtained those allowances. Protocols should default to exact-amount approvals and educate users to revoke stale allowances.

- **Users need better tooling for transaction inspection.** The malicious `approve()` prompt appeared as a standard MetaMask signature request. Without transaction simulation or human-readable decode overlays, most users cannot distinguish a safe transaction from a malicious one. Wallet-level and dApp-level safeguards are essential.

- **A $120M incident produced no criminal convictions.** Despite US DOJ and FBI involvement, the attacker's identity was never publicly confirmed and no funds were recovered. On-chain forensics alone are insufficient for attribution when funds are laundered through mixers and cross-chain bridges.
