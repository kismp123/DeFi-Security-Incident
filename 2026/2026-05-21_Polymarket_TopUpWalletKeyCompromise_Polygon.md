# Polymarket — Internal Top-Up Wallet Key Compromise Exploit Analysis

| Field | Details |
|-------|---------|
| **Date** | 2026-05-21 20:02:00 UTC (compromise onset); drain activity reported ~2026-05-22 08:22 UTC |
| **Protocol** | Polymarket (prediction market) |
| **Chain** | Polygon PoS |
| **Total Loss** | ~**$520K–$700K** (ZachXBT: ~$520K; Bubblemaps: ~$600K; later reports: ~$700K); drained in POL |
| **Attacker** | `0x8F98075db5d6C620e8D420A8c516E2F2059d9B91` *(verified on Polygonscan — labeled "Polymarket Adapter Exploiter 1", Exploit/Phish-Hack tag)* |
| **Compromised Wallet** | Internal operations / "top-up" wallet (~6-year-old key); used for automated rewards payout and balance refills |
| **UMA CTF Adapter Admin** | `0x91430cad2d3975766499717fa0d66a78d814e5c5` ([Polygonscan](https://polygonscan.com/address/0x91430cad2d3975766499717fa0d66a78d814e5c5) — labeled "Polymarket UMA CTF Adapter Admin"); POL forwarded from this wallet to attacker (~4,999–9,999 POL per transfer, ~every 30 s) |
| **Vulnerable Contract** | UMA CTF Adapter Admin address (intermediary); user funds and CTF resolution contracts were **NOT compromised** |
| **Attack Tx** | Not confirmed — see Section 8 |
| **Fabricated Hash (Flagged)** | `0x18b293793c8f551b1e60345e59fb54de9d2e439a8b461d8fae5dea7d273f6c5c` — **NOT FOUND** on Polygonscan; body matches a Gravity Bridge hash present in this dataset; do not cite |
| **Entry Function** | Scripted POL transfer from top-up wallet → UMA CTF Adapter Admin → attacker; ~5,000 POL per cycle, ~30-second intervals |
| **Root Cause** | Compromised private key of a long-lived internal operational hot wallet used for automated payout top-ups, with no per-interval withdrawal rate limit and no KMS/HSM custody |
| **Source** | coindesk.com, decrypt.co, cryptoslate.com, news.bitcoin.com |
| **Source Verification** | **High confidence** — attacker address verified on Polygonscan (labeled "Polymarket Adapter Exploiter 1"); admin wallet address Polygonscan-labeled "Polymarket UMA CTF Adapter Admin"; drain pattern (5,000 POL / 30 s) corroborated across multiple press reports; no individual drain tx hash has been publicly cited |

---

## 1. Vulnerability Overview

Polymarket is a decentralized prediction market platform on Polygon PoS that uses the UMA Conditional Tokens Framework (CTF) for market resolution. To keep market operations running smoothly — funding gas refills, distributing rewards, and topping up participant balances — Polymarket maintained an internal operational wallet that executed automated payout and top-up transactions.

This wallet held a private key that was approximately **six years old**, had never been rotated, and was stored without hardware security module (HSM) or key management service (KMS) protection. When an attacker obtained this key, they were able to drain the wallet's POL balance in a scripted loop: approximately **5,000 POL every 30 seconds**, routed first through the UMA CTF Adapter Admin address and then onward to the attacker.

Critically, this was **not an exploit of Polymarket's smart contracts**. The UMA CTF Adapter, the Conditional Tokens Framework contracts, and all market resolution logic were entirely unaffected. User position funds were safe, and no market outcomes were manipulated. The attack was purely an operational security failure — a stale hot-wallet key without rate limits or KMS custody, used to drain an operations balance.

Polymarket confirmed the breach publicly and announced migration of all keys to a KMS-backed system as the primary remediation.

---

## 2. Vulnerable Code Analysis

Section 2 focuses on the operational wallet pattern exploited — not a Solidity bug, but the infrastructure design that concentrated automated payout authority in a single long-lived unprotected EOA. Code examples are **reconstructed** to illustrate the vulnerability class and are labeled accordingly.

### 2.1 Vulnerable Top-Up Wallet Pattern (❌)

**Reconstructed payout automation pattern** (❌):

```python
# Reconstructed off-chain payout automation (Python / Web3.py pseudocode)
# This is the operational pattern that was compromised — not Polymarket's actual code.

from web3 import Web3

# ❌ Long-lived private key loaded from environment variable or config file
# ❌ ~6 years old, never rotated
# ❌ No HSM / KMS backing — private key accessible in plaintext at runtime
PRIVATE_KEY = os.environ.get("PAYOUT_WALLET_KEY")  # ❌ Soft key; single point of failure

w3 = Web3(Web3.HTTPProvider(POLYGON_RPC))
payout_account = w3.eth.account.from_key(PRIVATE_KEY)

def top_up_participant(recipient: str, amount_pol: int):
    """
    ❌ No per-call amount cap
    ❌ No per-interval cumulative limit
    ❌ No circuit breaker — runs indefinitely
    ❌ No monitoring hook before broadcast
    """
    tx = {
        "to": recipient,
        "value": w3.to_wei(amount_pol, "ether"),
        "gas": 21000,
        "nonce": w3.eth.get_transaction_count(payout_account.address),
    }
    signed = payout_account.sign_transaction(tx)  # ❌ Soft-signed on-process key
    w3.eth.send_raw_transaction(signed.rawTransaction)
```

The attacker, having obtained `PRIVATE_KEY`, replicated this signing capability and issued ~5,000 POL transfers every ~30 seconds without any on-chain or off-chain control stopping them.

**Observed drain pattern:**

```
Cycle (repeating ~every 30 seconds):
  1. Attacker signs tx: top-up wallet → UMA CTF Adapter Admin addr
     Amount: ~5,000 POL
  2. ~7 seconds later:
     UMA CTF Adapter Admin addr → attacker addr
     Amount: ~4,999.99 POL (minus gas)

Total cycles before detection: sufficient to drain $520K–$700K in POL
```

### 2.2 Hardened Payout Wallet Design (✅)

```python
# ✅ Recommended architecture for automated payout wallets

# Option A: KMS-backed signing (AWS KMS / GCP Cloud HSM)
import boto3

class KMSPayoutWallet:
    def __init__(self, kms_key_id: str):
        self.kms = boto3.client("kms", region_name="us-east-1")
        self.key_id = kms_key_id  # ✅ Private key never leaves HSM

    def sign_transaction(self, tx_dict: dict) -> bytes:
        # ✅ KMS signs the tx hash; raw key material never exposed to application
        tx_hash = encode_defunct(tx_dict)
        response = self.kms.sign(
            KeyId=self.key_id,
            Message=tx_hash,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return response["Signature"]
```

```solidity
// ✅ Option B: on-chain rate-limited withdrawal contract
// Deploy a Forwarder contract between the payout fund and recipients.
// Even if the operator key is compromised, the Forwarder caps damage.

contract RateLimitedForwarder {
    address public immutable operator;        // ✅ Short-lived, rotated key
    address public immutable guardian;        // ✅ Separate pause authority

    uint256 public constant MAX_PER_TX  = 1_000 * 1e18;   // 1,000 POL per call
    uint256 public constant MAX_PER_DAY = 10_000 * 1e18;  // 10,000 POL / day

    mapping(uint256 => uint256) public dayWithdrawn;
    bool public paused;

    modifier onlyOperator()  { require(msg.sender == operator,  "Not operator");  _; }
    modifier onlyGuardian()  { require(msg.sender == guardian,  "Not guardian");  _; }
    modifier whenNotPaused() { require(!paused, "Paused"); _; }

    function topUp(address recipient, uint256 amount)
        external
        onlyOperator
        whenNotPaused
    {
        require(amount <= MAX_PER_TX, "Exceeds per-tx cap");

        uint256 day = block.timestamp / 1 days;
        dayWithdrawn[day] += amount;
        require(dayWithdrawn[day] <= MAX_PER_DAY, "Daily cap exceeded");

        // ✅ Emit before transfer for off-chain monitoring
        emit TopUpExecuted(recipient, amount, dayWithdrawn[day]);
        payable(recipient).transfer(amount);
    }

    // ✅ Guardian (separate key / monitoring bot) can halt all payouts instantly
    function pause()   external onlyGuardian { paused = true;  emit Paused(); }
    function unpause() external onlyGuardian { paused = false; emit Unpaused(); }
}
```

### 2.3 Key Infrastructure Hardening Summary

| Control | Vulnerable State | Recommended State |
|---------|-----------------|-------------------|
| Key age | ~6 years, never rotated | Quarterly rotation; max 90-day lifetime |
| Key custody | Software EOA (hot wallet) | KMS/HSM or MPC (Fireblocks/Fordefi) |
| Per-call limit | None | Hard cap per transaction |
| Per-interval limit | None | Daily cap with on-chain or off-chain enforcement |
| Circuit breaker | None | GUARDIAN role / monitoring bot can pause in <1 min |
| Key privilege scope | Broad payout authority | Least-privilege: can only call `topUp()` on Forwarder |
| Monitoring | Unclear | Real-time alert on any transfer >X POL; anomaly detection |

---

## 3. Attack Flow

### 3.1 Preparation

The attacker obtained the private key for Polymarket's internal top-up wallet — a key approximately **six years old** with no documented rotation history. The exact compromise vector was not publicly disclosed. Likely candidates include phishing of an employee with access to the key, malware on a signing machine, or leaked key material in source control or configuration systems.

### 3.2 Execution

**[Step 1] Key acquisition** (exact time T₀ unknown; drain begins ~20:02 UTC May 21)

Attacker gains access to the private key of Polymarket's top-up wallet.

**[Step 2] Scripted drain loop begins**

The attacker executes a script that replicates the legitimate top-up wallet signing pattern:

- Signs a transfer of ~5,000 POL from the top-up wallet to the UMA CTF Adapter Admin address.
- Approximately 7 seconds later, routes ~4,999.99 POL from that Admin address (`0x91430cad2d3975766499717fa0d66a78d814e5c5`, Polygonscan-labeled "Polymarket UMA CTF Adapter Admin") to the attacker's own address (`0x8F98075...`, verified on Polygonscan as "Polymarket Adapter Exploiter 1").
- Repeats every ~30 seconds.

**[Step 3] Detection and response**

Unusual drain activity was identified by community researchers (ZachXBT, Bubblemaps) and reported publicly around May 22 08:22 UTC. Polymarket acknowledged the incident, confirmed user funds were safe, and initiated key migration to KMS.

**[Step 4] Remediation**

Polymarket announced migration of all operational keys to a KMS-backed system to prevent recurrence. The compromised wallet's remaining balance (if any) was secured separately.

### 3.3 Attack Flow Diagram

```
┌────────────────────────────────────────────────────────────────┐
│  Attacker (0x8F98075… — verified, Polygonscan-labeled)         │
│  Obtained private key of Polymarket top-up wallet              │
│  (~6-year-old key, no KMS, no rotation)                        │
└──────────────────────────────────┬─────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────┐
│  Polymarket Top-Up Wallet (EOA — internal operational key)     │
│                                                                │
│  ❌ No per-call amount cap                                     │
│  ❌ No daily withdrawal limit                                  │
│  ❌ No circuit breaker / monitoring pause                      │
│  ❌ Single soft key, never rotated (~6 years)                  │
│                                                                │
│  Scripted tx loop (every ~30 seconds):                         │
│  top-up wallet → UMA CTF Adapter Admin addr                    │
│  Amount: ~5,000 POL per cycle                                  │
└──────────────────────────────────┬─────────────────────────────┘
                                   │ ~7 seconds later
                                   ▼
┌────────────────────────────────────────────────────────────────┐
│  UMA CTF Adapter Admin (0x91430cad…814e5c5, Polygonscan-labeled)│
│                                                                │
│  ← Receives ~5,000 POL                                         │
│  → Forwards ~4,999.99 POL to attacker                          │
│                                                                │
│  NOTE: UMA CTF Adapter contract logic UNTOUCHED                │
│        Market resolution / CTF contracts UNTOUCHED             │
│        User position funds SAFE                                │
└──────────────────────────────────┬─────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────┐
│  Attacker address (0x8F98075… — verified, Polygonscan-labeled) │
│                                                                │
│  Accumulates POL over repeated cycles                          │
│  Total drained: ~$520K–$700K (range across sources)            │
└────────────────────────────────────────────────────────────────┘

[Separate / Unaffected]
┌────────────────────────────────────────────────────────────────┐
│  UMA CTF Adapter (market resolution contract) — UNAFFECTED     │
│  Conditional Tokens Framework contracts — UNAFFECTED           │
│  User collateral / position funds — SAFE                       │
└────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Metric | Value |
|--------|-------|
| Asset drained | POL (Polygon native token) |
| Amount (ZachXBT estimate) | ~$520,000 |
| Amount (Bubblemaps estimate) | ~$600,000 |
| Amount (later reports) | ~$700,000 |
| Drain cycle | ~5,000 POL per ~30 seconds |
| User funds affected | None |
| Market resolution affected | None |
| Smart contracts compromised | None |

---

## 4. Vulnerability Classification

### 4.1 Classification Table

| ID | Vulnerability | Severity | CWE | Category | Similar Incidents |
|----|---------------|----------|-----|----------|-------------------|
| V-01 | Compromised long-lived hot wallet key (no HSM/KMS) | CRITICAL | CWE-522 | private-key-compromise | Bitmart (2021), Atomic Wallet (2023) |
| V-02 | Stale key — no rotation policy (~6 years) | HIGH | CWE-320 | key-management | Ronin Bridge (2022) |
| V-03 | No withdrawal rate limit on operational wallet | HIGH | CWE-284 | access-control | Multiple ops-wallet drains |
| V-04 | Overly broad privilege scope for payout role | MEDIUM | CWE-269 | access-control | General least-privilege failures |

### 4.2 V-01 — Compromised Long-Lived Hot Wallet

- **Description**: The top-up wallet private key was stored as a software key (EOA), without HSM or KMS protection. When an attacker obtained this key — by whatever means — they had full signing authority identical to Polymarket's own automation scripts. There was no secondary authentication or signing quorum.
- **Impact**: Attacker replicated Polymarket's automated payout behavior to drain $520K–$700K in POL.
- **Attack Preconditions**: Compromise of a single private key file.

### 4.3 V-02 — Stale Key / No Rotation Policy

- **Description**: The compromised key was approximately six years old. Long-lived keys accumulate exposure over time: more systems touch them, more employees handle them, and more opportunities arise for accidental leakage. No rotation policy was evidenced.
- **Impact**: Increased probability that the key was exposed through one of many historical access events.
- **Attack Preconditions**: Any leakage event over a 6-year window.

### 4.4 V-03 — No Withdrawal Rate Limit

- **Description**: The operational wallet could transfer arbitrary amounts of POL without per-call or per-day limits. No on-chain Forwarder or circuit breaker existed between the operator key and the funds. The drain script ran for an extended period before detection.
- **Impact**: Entire operations balance was drainable in a single session; rate limits would have bounded losses and bought response time.
- **Attack Preconditions**: Same as V-01.

### 4.5 V-04 — Overly Broad Privilege Scope

- **Description**: The top-up wallet appears to have had authority beyond minimal top-up functions — it could route funds through the UMA CTF Adapter Admin address. Applying least-privilege would restrict the key to a narrow, purpose-specific contract function with hard-coded recipients and amounts.
- **Impact**: Facilitated the lateral movement via the UMA Admin address.
- **Attack Preconditions**: Same as V-01.

---

## 5. Comparison with Similar Incidents

| Incident | Date | Loss | Flaw Type | Difference from Polymarket |
|----------|------|------|-----------|---------------------------|
| **Bitmart** | 2021-12 | ~$196M | Hot wallet private key stolen → ERC-20 drain | Exchange hot wallet; Polymarket: ops/payout wallet only |
| **Atomic Wallet** | 2023-06 | ~$35M | Client-side key extraction (malware/supply-chain) | Client keys compromised; Polymarket: server-side ops key |
| **Ronin Bridge** | 2022-03 | ~$625M | 5-of-9 multisig; 4 keys + 1 auto-approval compromised | Bridge reserve drain; Polymarket: ops balance only; no user funds |
| **Wintermute** | 2022-09 | ~$160M | Profanity-generated vanity address key weakness | Cryptographic weakness vs Polymarket: long-lived exposure |
| **CoinEx** | 2023-09 | ~$70M | Hot wallet key compromise → multi-chain drain | Exchange hot wallet multi-chain; Polymarket: single-chain ops wallet |

The Polymarket incident is notable for its **small blast radius** relative to comparable key compromises: because the compromised wallet held only an operations balance (not user collateral or market resolution authority), total losses were capped in the low-hundreds-of-thousands range rather than tens or hundreds of millions. The absence of impact on user funds or market outcomes reflects a partial application of least-privilege, even though the key itself lacked sufficient protection.

---

## 6. Remediation Recommendations

### 6.1 Immediate Key Migration (Polymarket's Stated Remediation)

```
1. Revoke all existing operational wallet keys immediately.
2. Migrate to AWS KMS / GCP Cloud HSM / Fireblocks MPC for all
   server-side signing operations.
3. Conduct a full audit of all keys held by the organization:
   - What keys exist?
   - What can each key authorize?
   - When was each key created / last rotated?
   - Who has had access to each key?
```

### 6.2 Key Rotation Policy

```
- Maximum key lifetime: 90 days for operational hot wallets.
- Rotation procedure: generate new key in KMS, update all callers,
  drain old wallet, revoke old key, confirm zero balance before decommission.
- Exception process: any key older than 90 days requires security team sign-off.
```

### 6.3 On-Chain Rate-Limited Forwarder (see Section 2.2)

Deploy a `RateLimitedForwarder` contract (code in Section 2.2) between the operator key and the payout destination. Even with a compromised key, losses are bounded to `MAX_PER_DAY`.

### 6.4 Off-Chain Monitoring

| Monitor | Trigger | Automated Response |
|---------|---------|-------------------|
| Unusual payout frequency | >N transfers in M minutes from ops wallet | Pause wallet; PagerDuty alert |
| Large single transfer | Any tx > 2× median transfer value | Alert + human approval gate |
| New recipient address | Transfer to address not in allowlist | Block + alert |
| Key age check | Cron: flag any key >60 days old | Engineer notification |

### 6.5 Least-Privilege Architecture

```
Current (❌):
  operator key → can transfer arbitrary POL to any address

Target (✅):
  operator key → can only call topUp(recipient, amount) on RateLimitedForwarder
  RateLimitedForwarder → recipient must be in allowlist
  RateLimitedForwarder → amount bounded by per-tx + per-day cap
  guardian key (separate) → can pause Forwarder instantly
```

---

## 7. Lessons Learned

1. **Operational wallet keys require the same protection as protocol admin keys.** The Polymarket incident demonstrates that an "ops" or "payout" key, even if it does not touch user funds directly, can still result in significant losses. Hot wallets used for any automation should be KMS-backed from day one.
2. **Key age is a risk factor.** A six-year-old key has accumulated exposure across employee tenures, infrastructure migrations, system reinstalls, and incident responses. Maximum key lifetimes with mandatory rotation are a baseline control.
3. **Rate limits on automated wallets bound worst-case losses.** A rate-limited Forwarder contract or off-chain circuit breaker would have converted a $700K event into a $10K–$50K event by triggering an alert after the first few anomalous cycles.
4. **Non-contract compromises can still be serious.** The prediction market and resolution contracts were untouched, yet the protocol suffered reputational and financial harm. "Smart contract security" and "operational security" are both necessary; neither substitutes for the other.
5. **Least-privilege is measurable.** The Polymarket top-up wallet's access to the UMA CTF Adapter Admin address extended its blast radius beyond a simple balance drain. Restricting ops keys to a purpose-specific Forwarder with an allowlisted recipient set eliminates this lateral movement.
6. **Transparent incident response matters.** Polymarket confirmed the breach publicly, clarified that user funds were safe, and announced concrete remediation (KMS migration). This pattern — honest disclosure + immediate remediation — is best practice and preserves user trust.

---

## 8. On-Chain Verification

### 8.1 Attack Transaction Status

| Transaction | Hash | Status |
|-------------|------|--------|
| Drain txs (reported pattern) | Not individually disclosed in press reports | **Not found** — no specific hashes cited in sources |
| Provided fabricated hash | `0x18b293793c8f551b1e60345e59fb54de9d2e439a8b461d8fae5dea7d273f6c5c` | **NOT FOUND** on Polygonscan — matches a Gravity Bridge hash in the incident dataset; do not cite |

### 8.2 Address Confidence Table

| Role | Address | Confidence |
|------|---------|------------|
| Attacker EOA | [`0x8F98075db5d6C620e8D420A8c516E2F2059d9B91`](https://polygonscan.com/address/0x8F98075db5d6C620e8D420A8c516E2F2059d9B91) | **High** — Polygonscan-labeled "Polymarket Adapter Exploiter 1" (Exploit/Phish-Hack tag) |
| Compromised top-up wallet | Not publicly disclosed | N/A |
| UMA CTF Adapter Admin (compromised intermediary) | [`0x91430cad2d3975766499717fa0d66a78d814e5c5`](https://polygonscan.com/address/0x91430cad2d3975766499717fa0d66a78d814e5c5) | **High** — Polygonscan-labeled "Polymarket UMA CTF Adapter Admin"; POL flowed FROM this wallet TO the attacker |
| Drained adapter contract | [`0x871D7c0f9E19001fC01E04e6cdFa7fA20f929082`](https://polygonscan.com/address/0x871D7c0f9E19001fC01E04e6cdFa7fA20f929082) | Medium — reported by crypto.news; Polygonscan confirmation pending |
| UMA CTF Adapter (unaffected) | Not disputed — Polymarket's known deployment | High (known protocol contract) |

### 8.3 Verified Facts (Source-Corroborated)

| Fact | Confidence | Source |
|------|------------|--------|
| Date: 2026-05-21 drain begins; reported ~May 22 | High | Multiple press reports converge |
| Total loss: $520K–$700K range in POL | High | Multiple independent estimates (ZachXBT, Bubblemaps, later press) |
| Drain mechanism: ~5,000 POL / ~30-second cycles | High | Multiple reports describe the pattern consistently |
| Key age: ~6 years old | High | Multiple reports cite this detail |
| User funds and market resolution were unaffected | High | Polymarket official statement |
| Root cause: compromised operational hot wallet key | High | Polymarket confirmed; no contract exploit claimed |
| Remediation: migration to KMS | High | Polymarket official announcement |

### 8.4 Note on Fabricated Hash

The hash `0x18b293793c8f551b1e60345e59fb54de9d2e439a8b461d8fae5dea7d273f6c5c` was supplied in the task brief as a placeholder. Its body structure matches a Gravity Bridge transaction hash present in this incident dataset and does not correspond to any Polymarket-related Polygon transaction. It must not be cited as evidence.

---

## 9. References

- [CoinDesk — ZachXBT Flags $520K Polymarket Exploit on Polygon; Team Says Funds Are Safe](https://www.coindesk.com/markets/2026/05/22/zachxbt-flags-usd520k-polymarket-exploit-on-polygon-team-says-funds-are-safe)
- [Decrypt — Polymarket Hit by Internal Top-Up Wallet Exploit, $700K Drained](https://decrypt.co/368740/polymarket-hit-by-internal-top-up-wallet-exploit-700k-drained)
- [CryptoSlate — Polymarket Private Key Compromise](https://cryptoslate.com/polymarket-private-key-compromise/)
- [Bitcoin.com News — Polymarket Suffers $700K Breach After Internal Admin Wallet Is Compromised](https://news.bitcoin.com/polymarket-suffers-700k-breach-after-internal-admin-wallet-is-compromised/)
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-320: Key Management Errors](https://cwe.mitre.org/data/definitions/320.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- Related: [../vulns/private-key-compromise.md](../vulns/private-key-compromise.md)
- Related: [StablR 2026-05-23](./2026-05-23_StablR_MultisigKeyCompromiseMint_ETH.md)
- Related: [Harmony Bridge — compromised keys (2022)](../2022/2022-06-23_Harmony_CompromisedMultisig.md)
