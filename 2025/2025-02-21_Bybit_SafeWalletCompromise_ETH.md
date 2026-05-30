# Bybit — Safe{Wallet} Frontend Compromise & $1.5B ETH Theft Analysis

| Field | Details |
|------|------|
| **Date** | 2025-02-21 |
| **Protocol** | Bybit Exchange (Safe{Wallet} multisig) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$1,500,000,000 (~401,346 ETH) |
| **Attacker EOA** | Attributed to Lazarus Group / DPRK state-sponsored actors; no single confirmed EOA |
| **Fund Receiver** | `0x47666fab8bd0ac7003bce3f5c3585383f09486e2` |
| **Attack Contract 1** | `0x96221423...` (malicious Safe implementation — partial) |
| **Attack Contract 2** | `0xbdd077f6...` (proxy exploit contract — partial) |
| **Impl Upgrade Tx** | [0x46deef0f...](https://etherscan.io/tx/0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882) |
| **ETH Drain Tx** | [0xb61413c4...](https://etherscan.io/tx/0xb61413c495fdad6114a7aa863a00b2e3c28945979a10885b12b30316ea9f072c) (401,346 ETH) |
| **stETH Drain Tx** | [0xa284a1bc...](https://etherscan.io/tx/0xa284a1bc4c7e0379c924c73fcea1067068635507254b03ebbbd3f4e222c1fae0) (90,375 stETH) |
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

A Safe proxy delegates all logic calls to an implementation (singleton) contract stored at slot 0 (`masterCopy`). The proxy's fallback unconditionally `delegatecall`s the current `masterCopy` — whoever controls that pointer controls every subsequent call.

#### On-Chain Source Code — Safe Proxy (Victim Contract)

Source: **Sourcify-verified** — Proxy.sol / 0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4 (Ethereum)
https://sourcify.dev/server/files/any/1/0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4

```solidity
pragma solidity ^0.5.3;

/// @title Proxy - Generic proxy contract allows to execute all transactions
///        applying the code of a master contract.
contract Proxy {

    // masterCopy always needs to be first declared variable, to ensure that
    // it is at the same location in the contracts to which calls are delegated.
    address internal masterCopy; // ❌ slot 0 — whoever writes this controls the proxy

    constructor(address _masterCopy) public {
        require(_masterCopy != address(0), "Invalid master copy address provided");
        masterCopy = _masterCopy;
    }

    function () external payable {
        assembly {
            let masterCopy := and(sload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            // ❌ If sload(0) is overwritten (via execTransaction → delegatecall), this
            //    address changes to whatever the attacker's contract wrote there.
            if eq(calldataload(0), 0xa619486e00000000000000000000000000000000000000000000000000000000) {
                mstore(0, masterCopy)
                return(0, 0x20)
            }
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas, masterCopy, 0, calldatasize(), 0, 0) // ❌ unconditional delegatecall
            returndatacopy(0, 0, returndatasize())
            if eq(success, 0) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}
```

**Why it is exploitable (identify the bug from the code):**

- The proxy's entire security depends on `sload(0)` returning the correct `masterCopy` address. There is no immutability or access-control on slot 0 at the proxy level — it is the *Safe singleton logic* (the implementation at `masterCopy`) that is supposed to guard `upgradeTo` calls.
- The Safe singleton exposes `execTransaction()` which, when given a properly signed payload, can call any function including `upgradeTo(newImpl)`. There is no on-chain mechanism that prevents signers from authorizing an upgrade to a malicious implementation — it is a social/UI concern.
- The Lazarus Group exploited this: the signing UI was tampered so that signers approved a transaction whose actual calldata called `upgradeTo(0x96221423...)` instead of the displayed ETH transfer. Once the `masterCopy` pointer was replaced, every subsequent `delegatecall` went to the attacker's contract.
- The proxy code itself is correct — **there is no on-chain vulnerability in the proxy**. The exploit path was entirely through the off-chain signing interface, bypassing all smart-contract-level guards by obtaining legitimate signatures through deception.

```solidity
// ✅ Mitigation — not a code change but a process change:
// Hardware signers must independently decode and display raw calldata.
// Any transaction that touches `masterCopy` (slot 0) should trigger
// mandatory review against a known-good implementation address.
//
// On-chain monitoring: alert if execTransaction calldata contains
// the upgradeTo(address) selector (0x3659cfe6) on the Safe singleton.
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
