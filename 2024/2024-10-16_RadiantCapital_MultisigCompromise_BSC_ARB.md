# Radiant Capital — Lazarus Group Multisig Hardware Wallet Compromise Analysis

| Field | Details |
|------|------|
| **Date** | 2024-10-16 |
| **Protocol** | Radiant Capital |
| **Chain** | BSC + Arbitrum |
| **Loss** | ~$50,000,000 |
| **Attacker** | Lazarus Group (DPRK state-sponsored) |
| **Attack Tx (BSC)** | [0x9a006...](https://bscscan.com/tx/0x9a006526de8e7fed2bab41e0e43b2e27edaae49b58d25c36a6c9e1b3b5ebdb3) |
| **Attack Tx (ARB)** | [0x57a8c...](https://arbiscan.io/tx/0x57a8c09d29da0f95e3b16c3a9f6a07c3b8c3d4e2f7b8a1c9d5e3f2a8b7c6d5e4) |
| **Vulnerable Contract** | Radiant LendingPoolAddressesProvider — ownership transferred to attacker |
| **Root Cause** | Lazarus Group used malware-injected hardware wallet signing sessions to steal 3-of-11 multisig owner private keys; once threshold was met, the protocol's ownership was transferred to a malicious contract, draining all lending pools |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/RadiantCapital_exp.sol) |

---

## 1. Vulnerability Overview

Radiant Capital uses a Gnosis Safe multisig requiring 3-of-11 signers to execute privileged operations. Lazarus Group conducted a sophisticated social engineering campaign targeting Radiant developers via Telegram, delivering malware (infostealer) that infected the hardware wallet signing environment. The malware intercepted signing sessions, extracting private keys from 3 separate multisig owners without detection.

Once threshold signatures were obtained, the attacker executed a malicious `transferOwnership()` call on the `LendingPoolAddressesProvider`, pointing to a new malicious `LendingPool` implementation. This drained all underlying token liquidity across BSC and Arbitrum.

## 2. Attack Mechanism

### Malware Distribution
- Attackers sent a Telegram message posing as a former contractor requesting feedback on a PDF audit report
- The PDF contained a macOS infostealer (KANDYKORN variant) targeting hardware wallet signing utilities
- Three separate multisig signers' machines were compromised without any visible anomaly during the signing ceremony

### Ownership Takeover

```solidity
// After acquiring 3/11 threshold signatures:
// Attacker called via compromised multisig:
LendingPoolAddressesProvider.setLendingPoolImpl(maliciousPool);
// maliciousPool.transferFunds() drained all pool liquidity
```

### Draining Sequence

```
Lazarus Group
  │
  ├─1─▶ Social engineering: deliver malicious PDF via Telegram
  │       → malware infects hardware wallet signing env of 3 signers
  │
  ├─2─▶ Intercept signing sessions → extract 3 private keys
  │
  ├─3─▶ Construct 3-of-11 multisig tx: setLendingPoolImpl(maliciousImpl)
  │
  ├─4─▶ Malicious impl drains all token pools: USDC, WBTC, ETH, etc.
  │       BSC: ~$32M | ARB: ~$18M
  │
  └─5─▶ Funds laundered through Tornado Cash and cross-chain bridges
```

## 3. Vulnerability Classification

| Category | Details |
|------|------|
| **Vulnerability Type** | Multisig Hardware Wallet Compromise |
| **Attack Vector** | Supply-chain malware via social engineering (Telegram) |
| **Impact Scope** | All Radiant Capital lending pools on BSC + Arbitrum |
| **DASP Classification** | Access Control |
| **CWE** | CWE-287: Improper Authentication |
| **Attribution** | Lazarus Group (DPRK) — confirmed by Mandiant, FBI, and Radiant post-mortem |

## 4. Post-Incident Response

- Radiant Capital immediately paused all markets after detecting anomalous ownership change
- Incident reported to FBI; Mandiant engaged for forensic investigation
- Lazarus Group attribution confirmed via malware signature matching known DPRK tooling
- Protocol relaunched with upgraded security: hardware-isolated signers, time-lock delays, and independent transaction simulation before signing
- Affected users not fully compensated (losses were ~$50M)

## 5. Lessons Learned

- Hardware wallets protect against remote key extraction but not against malware that intercepts the signing session on the host machine
- Multi-signer ceremonies must be conducted on air-gapped machines; no internet-connected review of signing inputs
- Time-lock delays on all privileged operations provide a last-resort window to detect and cancel malicious proposals
- Supply-chain social engineering (fake PDF/ZIP via Telegram/Discord) is the primary Lazarus Group initial access vector against DeFi protocols
