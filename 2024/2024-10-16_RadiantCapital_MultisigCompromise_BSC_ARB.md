# Radiant Capital — Lazarus Group Multisig Hardware Wallet Compromise Analysis

| Field | Details |
|------|------|
| **Date** | 2024-10-16 |
| **Protocol** | Radiant Capital |
| **Chain** | BSC + Arbitrum |
| **Loss** | ~$50,000,000 |
| **Attacker** | Lazarus Group (DPRK state-sponsored) |
| **Attack Tx (BSC)** | [0xd97b...841c](https://bscscan.com/tx/0xd97b93f633aee356d992b49193e60a571b8c466bf46aaf072368f975dc11841c) |
| **Attack Tx (ARB)** | [0x7856...2fb1](https://arbiscan.io/tx/0x7856552db409fe51e17339ab1e0e1ce9c85d68bf0f4de4c110fc4e372ea02fb1) |
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

### Ownership Takeover — Verified On-Chain Source

Source: **Sourcify-verified** (full match) — Radiant Capital `LendingPoolAddressesProvider` (`0x091d52CacE1edc5527C99cDCFA6937C1635330E4`, Arbitrum)
https://sourcify.dev/server/files/any/42161/0x091d52CacE1edc5527C99cDCFA6937C1635330E4

The privileged function used by the attacker (once 3/11 multisig threshold was met) was `setLendingPoolImpl()`, which calls `_updateImpl()` to upgrade the proxy implementation to a malicious contract:

```solidity
function setLendingPoolImpl(address pool) external override onlyOwner {
    _updateImpl(LENDING_POOL, pool); // ❌ replaces the live LendingPool implementation
    emit LendingPoolUpdated(pool);
}

function _updateImpl(bytes32 id, address newAddress) internal {
    address payable proxyAddress = payable(_addresses[id]);

    InitializableImmutableAdminUpgradeabilityProxy proxy = InitializableImmutableAdminUpgradeabilityProxy(
        proxyAddress
    );
    bytes memory params = abi.encodeWithSignature("initialize(address)", address(this));

    if (proxyAddress == address(0)) {
        proxy = new InitializableImmutableAdminUpgradeabilityProxy(address(this));
        proxy.initialize(newAddress, params);
        _addresses[id] = address(proxy);
        emit ProxyCreated(id, address(proxy));
    } else {
        proxy.upgradeToAndCall(newAddress, params); // ❌ atomically upgrades proxy to malicious impl
    }
}
```

**Why it is exploitable (identify the bug from the code):**

- `setLendingPoolImpl()` is gated only by `onlyOwner`. Once the attacker satisfied the 3-of-11 Gnosis Safe threshold (via stolen private keys from hardware wallets), they became the effective `owner` of the `LendingPoolAddressesProvider`.
- `_updateImpl()` calls `proxy.upgradeToAndCall(newAddress, params)` — a single atomic transaction that replaces the entire LendingPool logic contract with an attacker-supplied implementation. The new implementation contained a function to drain all underlying token balances from every pool.
- There is no time-lock, no guardian veto, and no secondary delay between the upgrade proposal and execution. The attack was irreversible the moment the threshold signatures were obtained.

```solidity
// ✅ Fix: add a time-lock between setLendingPoolImpl() proposal and execution
// (e.g., 48-hour delay with a guardian that can cancel malicious proposals)
// Also: conduct signing ceremonies on air-gapped, internet-isolated machines
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
