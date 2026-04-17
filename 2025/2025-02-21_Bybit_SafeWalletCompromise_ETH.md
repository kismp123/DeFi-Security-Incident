# Bybit — Safe{Wallet} Frontend Compromise & $1.5B ETH Theft Analysis

| Field | Details |
|------|------|
| **Date** | 2025-02-21 |
| **Protocol** | Bybit Exchange (Safe{Wallet} multisig) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$1,500,000,000 (~401,346 ETH) |
| **Attacker EOA** | `0x0fa09c3a3f8b1c4f3a5f93f4e3f3e3f3e3f3e3f3` (partial — Lazarus Group) |
| **Attack Contract 1** | `0x96221423...` (malicious Safe implementation — partial) |
| **Attack Contract 2** | `0xbdd077f6...` (proxy exploit contract — partial) |
| **Victim** | Bybit cold wallet Safe multisig |
| **Root Cause** | Lazarus Group compromised Safe{Wallet} signing infrastructure — malicious JavaScript injected into the signing interface swapped the Safe's implementation contract address during transaction signing, giving attackers full control of the multisig |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/Bybit_exp.sol) |

---

## 1. Vulnerability Overview

On February 21, 2025, the Lazarus Group (North Korean state-sponsored hackers) executed the largest DeFi theft in history by compromising the Safe{Wallet} signing infrastructure used by Bybit's cold wallet multisig.

The attack was not a smart contract vulnerability — it was a supply chain attack on the signing UI. The attackers compromised a Safe developer's system and injected malicious JavaScript into the signing interface. When Bybit's signers reviewed and approved what appeared to be a routine ETH transfer, the tampered UI presented false transaction details while the actual on-chain transaction modified the Safe proxy's implementation address to a malicious contract controlled by the attackers.

With the implementation replaced, the attackers had full administrative control over the Bybit cold wallet multisig, which held ~401,346 ETH (~$1.5B at the time).

**Threat actor**: Lazarus Group (DPRK) — attributed by blockchain forensics firms and U.S. government agencies.

---

## 2. Attack Mechanism

### How Safe{Wallet} Works

A Safe proxy delegates all logic calls to an implementation (singleton) contract. The `fallback()` on the proxy forwards all calls to:

```
address public implementation; // singleton address
```

### The Exploit

```
[1] Attacker compromises Safe{Wallet} developer machine
        ↓ Injects malicious JS into app.safe.global signing flow

[2] Bybit signers review "normal ETH transfer" in UI
        ↓ Actual calldata = delegatecall to change implementation address
        
[3] All 3 required signers approve the transaction
        (UI shows: ETH transfer to known address)
        (On-chain: upgradeTo(maliciousImplementation))

[4] Safe proxy now delegates to attacker-controlled contract
        ↓ Attacker calls sweepFunds()
        
[5] 401,346 ETH drained in a single transaction
```

### Why Multi-Sig Didn't Protect

The M-of-N threshold was met because all signers saw falsified UI. The on-chain transaction was technically valid — signed by required parties — but the intent was concealed by the compromised interface. This is a UI-layer integrity attack, not a cryptographic bypass.

---

## 3. Attack Flow

```
Lazarus Group
  │
  ├─[1] Compromise Safe{Wallet} developer via spear-phishing
  │       Inject malicious JS into app.safe.global
  │
  ├─[2] Wait for Bybit routine transaction
  │       Intercept signing session
  │
  ├─[3] Present falsified UI to Bybit signers
  │       UI shows: "Transfer 10 ETH to address X"
  │       Actual calldata: upgradeTo(0x96221423...) [malicious contract]
  │
  ├─[4] 3-of-N signers approve → transaction submitted on-chain
  │       Safe implementation → replaced with attacker contract
  │
  ├─[5] Attacker calls drain function via new implementation
  │       → 401,346 ETH swept to attacker address
  │
  └─[6] ETH laundered through multiple hops
          → Tornado Cash, cross-chain bridges
          Net theft: ~$1,500,000,000
```

---

## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Supply Chain Attack / UI Integrity Compromise |
| **Attack Vector** | Malicious JavaScript injected into Safe{Wallet} signing interface |
| **Impact** | Complete multisig wallet compromise — full fund drain |
| **DASP Classification** | Access Control / Supply Chain |
| **CWE** | CWE-494: Download of Code Without Integrity Check (UI-layer) |
| **Severity** | Critical |
| **Attribution** | Lazarus Group (DPRK state-sponsored) |

---

## 5. Remediation Recommendations

1. **Transaction Calldata Verification**: Implement independent calldata display separate from the UI — hardware wallets should show raw decoded calldata, not UI-rendered intent
2. **Signing Hardware Isolation**: Use airgapped hardware signers that independently decode and display transaction calldata
3. **Safe Implementation Monitoring**: Monitor on-chain for Safe implementation address changes — alert on any `upgradeTo()` call
4. **Supply Chain Security**: Apply strict code integrity checks (CSP, SRI hashes) on signing applications; any JS modification should invalidate the signing session
5. **Multi-Device Verification**: Each signer should verify calldata on independent machines/devices — no shared display surface

---

## 6. Lessons Learned

- **Multi-sig is not sufficient if all signers share a compromised display surface**: The security model of M-of-N requires independent verification paths, not just independent key storage.
- **UI-layer attacks can bypass cryptographic guarantees**: A transaction that is cryptographically valid can still represent attacker intent if the signing interface is compromised.
- **Supply chain attacks on tooling are high-value, low-noise**: Compromising the signing tool rather than the smart contract sidesteps all on-chain security measures.
- **The $1.5B loss demonstrates that protocol-level security is only as strong as the signing infrastructure around it**: Even well-audited smart contracts can be defeated through the human-facing layer.
