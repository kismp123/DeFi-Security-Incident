# Poly Network — Cross-Chain Administrator Privilege Hijacking Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-08-10 |
| **Protocol** | Poly Network |
| **Chain** | Ethereum (+ BSC, Polygon) |
| **Loss** | ~$611,000,000 (Largest DeFi hack in history) |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 12,996,658) |
| **Vulnerable Contract** | EthCrossChainManager [0x838bf9E95CB12Dd76a54C9f9D2E3082EAF928270](https://etherscan.io/address/0x838bf9E95CB12Dd76a54C9f9D2E3082EAF928270) |
| **Root Cause** | `verifyHeaderAndExecuteTx()` does not block calls to the `EthCrossChainData` contract, allowing cross-chain messages to replace the keeper public key and transfer arbitrary funds |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-08/PolyNetwork_exp.sol) |

---
## 1. Vulnerability Overview

Poly Network's `EthCrossChainManager.verifyHeaderAndExecuteTx()` validates cross-chain messages and invokes functions on destination contracts. This function did not verify whether the destination contract was `EthCrossChainData` (the admin data contract). An attacker crafted a malicious cross-chain message to call `EthCrossChainData.putCurEpochConPubKeyBytes()`, replacing the consensus public key, then used a subsequent cross-chain message signed with the new key to transfer ETH to an arbitrary address.

---
## 2. Vulnerable Code Analysis

### 2.1 verifyHeaderAndExecuteTx() — No Restriction on Destination Contract Address

```solidity
// ❌ EthCrossChainManager @ 0x838bf9E95CB12Dd76a54C9f9D2E3082EAF928270
function verifyHeaderAndExecuteTx(
    bytes memory proof,
    bytes memory rawHeader,
    bytes memory headerProof,
    bytes memory curRawHeader,
    bytes memory headerSig
) external whenNotPaused returns (bool) {
    // Header validation...
    // Cross-chain data parsing...

    // ❌ Does not block cases where target is EthCrossChainData
    // Anyone can call EthCrossChainData functions via cross-chain message
    address toContract = Utils.bytesToAddress(toContractBytes);

    // _executeCrossChainTx calls arbitrary contracts
    require(
        _executeCrossChainTx(toContract, toMethodName, args, fromContract, fromChainId),
        "Failed to execute cross chain tx"
    );
}

// _executeCrossChainTx: calls arbitrary functions on the destination contract
function _executeCrossChainTx(address _toContract, bytes memory _method, ...) internal returns (bool) {
    // ❌ No check for _toContract == EthCrossChainData
    (bool success, bytes memory returnData) = _toContract.call(
        abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bytes,bytes,uint64)"))), ...)
    );
    return success;
}
```

**Fixed Code**:
```solidity
// ✅ Does not allow EthCrossChainData as a destination
function _executeCrossChainTx(address _toContract, ...) internal returns (bool) {
    // Block calls to core admin contracts
    require(
        _toContract != address(EthCrossChainData),
        "CrossChainManager: cannot call EthCrossChainData"
    );
    require(
        _toContract != address(this),
        "CrossChainManager: cannot call self"
    );
    // ...
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**PolyNetwork_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: verifyHeaderAndExecuteTx() does not block calls to EthCrossChainData contract, allowing cross-chain messages to replace the keeper public key and transfer arbitrary funds
    function verifyHeaderAndExecuteTx(bytes arg0, bytes arg1, bytes arg2, bytes arg3, bytes arg4) external {}  // 0xd450e04c  // ❌ Vulnerability
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Step 1: Craft malicious cross-chain message                   │
│ target = EthCrossChainData (0xcF2afe10...)                   │
│ method = putCurEpochConPubKeyBytes (f1121318093)             │
│ args   = attacker-controlled public key                       │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 2: Call EthCrossChainManager.verifyHeaderAndExecuteTx() │
│ @ 0x838bf9E95CB12Dd76a54C9f9D2E3082EAF928270                │
│ → EthCrossChainData.putCurEpochConPubKeyBytes(attackerKey)   │
│ → Consensus public key replacement complete                  │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 3: Transfer ETH via cross-chain message signed with new key │
│ → Transfer hundreds of millions in assets to attacker-controlled address │
│ → Executed simultaneously across ETH, BSC, and Polygon       │
└──────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — Mainnet fork block 12,996,658
// Composed of two transactions

// Transaction 1: Change consensus key
// EthCrossChainManager.verifyHeaderAndExecuteTx(
//   proof, rawHeader, headerProof, curRawHeader, headerSig
// )
// → Internally calls EthCrossChainData.putCurEpochConPubKeyBytes(attackerKey)

// Transaction 2: Transfer ETH using new key authority
// EthCrossChainManager.verifyHeaderAndExecuteTx(
//   proof2, rawHeader2, ...
// )
// → ETH transfer approved based on new key in EthCrossChainData

// EthCrossChainManager @ 0x838bf9E95CB12Dd76a54C9f9D2E3082EAF928270
// EthCrossChainData   @ 0xcF2afe102057bA5c16f899271045a0A37fCb10f2
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `verifyHeaderAndExecuteTx()` allows calls to `EthCrossChainData` | CRITICAL | CWE-284 |
| V-02 | Administrator privileges can be bypassed via cross-chain message | CRITICAL | CWE-284 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Blacklist calls to core admin contracts
mapping(address => bool) public blacklistedTargets;

function initialize() external {
    // EthCrossChainData and self can never be a destination
    blacklistedTargets[address(EthCrossChainData)] = true;
    blacklistedTargets[address(this)] = true;
}

function _executeCrossChainTx(address _toContract, ...) internal returns (bool) {
    require(!blacklistedTargets[_toContract], "CrossChainManager: blacklisted target");
    // Additionally verify that the destination is a contract, not an EOA
    require(_toContract.code.length > 0, "CrossChainManager: not a contract");
    // ...
}
```

---
## 7. Lessons Learned

- **Failing to restrict the destination contract address in a cross-chain bridge is catastrophic.** It is essential to verify whether the message path can reach privileged admin contracts.
- **The largest DeFi hack in history ($611M) originated from a single missing address validation check.** A single line of code can be worth hundreds of millions of dollars.
- **The attacker returned the funds, but this was an exceptional case.** Security cannot rely on the goodwill of attackers.