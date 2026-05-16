# M2 Exchange — Hot Wallet Access Control Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2024-10-31 |
| **Protocol** | M2 Exchange (CeFi) |
| **Chain** | Ethereum + Bitcoin + Solana |
| **Loss** | ~$13,700,000 (company covered all losses; zero user impact) |
| **Attacker** | Unknown |
| **Attack Tx (ETH)** | Multiple hot wallet drain transactions |
| **Vulnerable System** | M2 Exchange hot wallet infrastructure |
| **Root Cause** | Unauthorized access to M2 Exchange hot wallet private keys or signing infrastructure, enabling direct fund extraction across three chains |
| **PoC Source** | Not public (CeFi infrastructure breach) |

---

## 1. Vulnerability Overview

M2 Exchange is a centralized cryptocurrency exchange based in Abu Dhabi (UAE). On October 31, 2024, an attacker gained unauthorized access to M2's hot wallet infrastructure and drained approximately $13.7M across three chains: Ethereum, Bitcoin, and Solana.

This is a CeFi infrastructure compromise rather than an on-chain smart contract vulnerability. The attacker obtained or derived hot wallet credentials/private keys sufficient to initiate outgoing transactions from M2's operational wallets without triggering internal security controls.

## 2. Attack Mechanism

- **Ethereum**: ETH and ERC-20 tokens drained from hot wallet to attacker-controlled addresses
- **Bitcoin**: BTC transferred from hot wallet(s) to attacker-controlled addresses
- **Solana**: SOL and SPL tokens drained similarly

The multi-chain nature suggests the attacker had access to either a key management service (KMS) that stored keys for all three chains, or compromised the signing infrastructure that M2 used for withdrawal processing.

```
Attacker
  │
  ├─1─▶ Obtain access to hot wallet signing keys or HSM
  │       (method: API breach, insider, or infrastructure compromise)
  │
  ├─2─▶ Execute ETH drain: ~$X from Ethereum hot wallet
  │
  ├─3─▶ Execute BTC drain: ~$Y from Bitcoin hot wallet
  │
  ├─4─▶ Execute SOL drain: ~$Z from Solana hot wallet
  │       Total: ~$13.7M
  │
  └─5─▶ Laundering via cross-chain bridges / mixers
```

## 3. Post-Incident Response

- M2 detected the breach and froze remaining assets
- Incident reported to UAE regulators and law enforcement
- M2 Exchange covered all ~$13.7M losses from company funds; user balances were made whole
- No user withdrawals were blocked; exchange remained operational
- Security infrastructure upgraded post-incident (specifics not disclosed)

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Vulnerability Type** | Hot Wallet Private Key Compromise |
| **Attack Vector** | CeFi infrastructure / key management breach |
| **Impact Scope** | M2 Exchange hot wallets on ETH, BTC, SOL |
| **DASP Classification** | Access Control |
| **CWE** | CWE-522: Insufficiently Protected Credentials |

## 5. Lessons Learned

- CeFi exchanges must use hardware security modules (HSMs) and multi-party computation (MPC) for hot wallet key management
- Hot wallet balances should be minimized; bulk assets held in cold storage with time-locked withdrawal processes
- Multi-chain hot wallet infrastructure sharing a common key management surface multiplies blast radius of a single compromise
- Rapid incident response and full user coverage from reserves can preserve reputation even after a significant breach
