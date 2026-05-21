# WazirX Exchange — Multisig Safe Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-07-18 |
| **Protocol** | WazirX (Indian centralized cryptocurrency exchange — largest by volume in India) |
| **Chain** | Ethereum |
| **Loss** | ~$235,000,000 (SHIB, ETH, WBTC, MATIC, PEPE, USDT, and other ERC-20 tokens) |
| **Attacker** | Lazarus Group (DPRK state-sponsored; multiple attribution sources) |
| **Vulnerable System** | WazirX multi-signature Safe (Gnosis Safe) wallet custody system |
| **Root Cause** | Lazarus Group used targeted social engineering against WazirX multisig co-signers to manipulate them into signing a malicious Safe contract upgrade transaction, replacing the legitimate Safe implementation with an attacker-controlled contract that had a hidden drain function |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity; CWE-284: Improper Access Control |
| **PoC Source** | ZachXBT attribution analysis; Mandiant/Google threat intelligence; WazirX official post-mortem (Jul 2024) |

---
## 1. Vulnerability Overview

WazirX is India's largest cryptocurrency exchange. Its custodial architecture used a Gnosis Safe multisig wallet requiring 4-of-6 signers to authorize transactions, with Liminal Custody managing one signer key on WazirX's behalf.

On July 18, 2024, attackers — later attributed to Lazarus Group — successfully manipulated the multisig signing process to authorize an upgrade of the Safe's implementation contract to a malicious contract they controlled. Once the malicious implementation was in place, the attackers called its hidden `sweepFunds()` function to drain all assets from the Safe in a single transaction.

The attack combined:
1. **Social engineering** of WazirX signers to approve what appeared to be a routine Safe upgrade
2. **UI spoofing** (the Liminal Custody interface showed benign transaction data while the actual calldata authorized a malicious upgrade)
3. **Fake transaction simulation** — the signed transaction appeared safe in simulation, but the actual contract behavior differed after upgrade

The $235M loss represented approximately 45% of WazirX's total customer holdings at the time. WazirX subsequently suspended INR and crypto withdrawals, entered insolvency proceedings in Singapore, and proposed a creditor restructuring plan.

---
## 2. Attack Flow

```
Lazarus Group
    │
    ├─[Pre-attack preparation]
    │       Deploy malicious Safe implementation contract (looks legitimate)
    │       Forge UI metadata / transaction preview to appear as routine Safe upgrade
    │       Target individual WazirX signers with social engineering (email, Telegram)
    │
    ├─[2024-07-18 Step 1 — Transaction 1]
    │       Attacker submits transaction to Safe: "upgrade to new implementation"
    │       WazirX signers approve — Liminal Custody UI shows benign-looking data
    │       Actual calldata: upgradeTo(attacker_malicious_implementation)
    │       3 WazirX signers sign; Liminal signs as 4th
    │       → Safe implementation replaced with malicious contract
    │
    ├─[2024-07-18 Step 2 — Transaction 2 (minutes later)]
    │       Attacker calls hidden sweepFunds() on malicious implementation
    │       Drains all Safe assets in one transaction:
    │           SHIB: ~$102M
    │           ETH: ~$52M
    │           WBTC: ~$8M
    │           MATIC: ~$6M
    │           Others: remaining ~$67M
    │           Total: ~$235M
    │
    ├─[WazirX response]
    │       Suspends INR and crypto withdrawals immediately
    │       Engages Mandiant (Google), Binance, and blockchain forensics firms
    │       Files police complaint; reports to India's FIU and ED
    │       Enters moratorium proceedings in Singapore High Court (Aug 2024)
    │
    └─[Attacker laundering]
              Funds swapped to ETH (wash trading SHIB/MATIC for ETH)
              Routed through Tornado Cash and cross-chain bridges
              ZachXBT/Mandiant link to Lazarus Group infrastructure
```

---
## 3. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Multisig manipulation via UI spoofing + social engineering of co-signers |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity; CWE-1021: Improper Restriction of Rendered UI (UI spoofing) |
| **OWASP** | A08: Software and Data Integrity Failures; A07: Identification and Authentication Failures |
| **Attack Vector** | Social engineering co-signers to approve malicious Safe upgrade → drain via hidden function |
| **Preconditions** | Custody UI displaying transaction data not independently verified; signers not checking raw calldata |
| **Impact** | ~$235M drained; WazirX enters insolvency; ~45% of customer assets lost |

---
## 4. Remediation Recommendations

1. **Independent transaction verification**: Each multisig signer must verify the raw calldata using an independent tool (e.g., Tenderly simulation, raw calldata decoder) — never trust the custody UI alone.
2. **Simulate with independent fork**: Before signing any upgrade transaction, run an independent mainnet fork simulation and verify post-state matches expectations.
3. **Delay between upgrade and execution**: After an implementation upgrade, impose a mandatory time-lock (e.g., 48-72 hours) before any function calls on the new implementation are permitted. This allows signers to verify the upgrade before funds are accessible.
4. **Immutable emergency freeze**: One signer key should have freeze-only permission that can halt the Safe without requiring 4-of-6 approval — enabling rapid response to suspected compromise.
5. **Hardware wallets with calldata display**: Signers must use hardware wallets (Ledger, Trezor) that display the actual transaction calldata, and must compare this with the expected calldata before signing.

---
## 5. Lessons Learned

- **Multisig is not sufficient if signers are manipulated**: WazirX had a 4-of-6 multisig — considered a strong custody model. Lazarus Group circumvented it not by breaking the cryptography, but by manipulating the human signers into approving a malicious transaction that looked legitimate in the custody UI.
- **UI spoofing attacks on custody platforms**: The Liminal Custody interface displayed what appeared to be a routine transaction, masking the actual malicious calldata. This is a documented Lazarus Group technique — custody UI providers must implement calldata verification independent of display layer.
- **Largest 2024 DeFi hack after DMM Bitcoin**: WazirX ($235M) was the second-largest 2024 crypto theft after DMM Bitcoin ($305M), both attributed to Lazarus Group. Together they account for ~$540M of DPRK's estimated 2024 crypto theft total.
- **Indian exchange regulatory gap**: Despite India's crypto regulation (VDA taxation, FIU registration), no security standard comparable to Japan's FSA custody requirements existed. The WazirX hack prompted discussions about security auditing requirements for Indian exchanges.
- **Customer insolvency impact**: Unlike Stake.com ($41M) or Binance (which survived the 2019 $40M hack), WazirX entered formal insolvency proceedings. The 45% of customer assets lost far exceeded reserves, demonstrating that exchange solvency guarantees are only as good as the exchange's security architecture.
