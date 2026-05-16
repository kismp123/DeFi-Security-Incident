# BNB Chain Cross-Chain Bridge — IAVL Proof Forgery Mint Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10-06 |
| **Protocol** | BNB Chain (Binance) BSC Bridge (BSC Token Hub) |
| **Chain** | BSC (BNB Beacon Chain → BSC) |
| **Loss** | ~$100,000,000 drained (attacker minted 2M BNB; ~$568M at risk but cross-chain bridge paused by validators before full extraction) |
| **Attacker** | [0x489a8756c18c0b8b24ec2a2b9ff3d4d447f79bec](https://bscscan.com/address/0x489a8756c18c0b8b24ec2a2b9ff3d4d447f79bec) |
| **Vulnerable Contract** | BSC Token Hub bridge contract (cross-chain proof verification) |
| **Root Cause** | A bug in the IAVL Merkle proof verification library used by the BNB Beacon Chain bridge allowed an attacker to forge a valid Merkle proof for an arbitrary message — specifically, a proof of a cross-chain transfer from Beacon Chain that never actually occurred, enabling minting of 2M BNB on BSC |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |
| **PoC Source** | SlowMist, PeckShield post-mortems; Binance official disclosure |

---
## 1. Vulnerability Overview

BNB Chain's cross-chain bridge connects BNB Beacon Chain (formerly Binance Chain) and BNB Smart Chain (BSC). When a user transfers BNB from Beacon Chain to BSC, a Merkle proof of the Beacon Chain state transition is submitted to the BSC Token Hub contract, which verifies the proof and mints the corresponding BNB on BSC.

The bridge used an **IAVL (Immutable AVL) Merkle tree** proof library to verify Beacon Chain state proofs. A critical bug in the IAVL proof verification allowed an attacker to construct a **forged Merkle proof** that appeared valid to the verifier without corresponding to any real Beacon Chain transaction. By submitting this forged proof twice to the `handlePackage()` function on the BSC Token Hub, the attacker minted **2,000,000 BNB** (~$568M at the time) out of thin air.

The BSC validator community detected the anomaly and coordinated an emergency halt of the BSC chain approximately 8 hours after the exploit began, freezing ~$430M of the minted BNB before it could be bridged out. The attacker successfully withdrew approximately $100M across multiple chains before the freeze.

---
## 2. Vulnerable Code Analysis

```go
// ❌ Vulnerable IAVL Merkle proof verification (simplified pseudocode)
// The IAVL library had an edge case where certain crafted proof structures
// could pass verification without corresponding to real Beacon Chain state

func (prt *ProofRuntime) VerifyAbsence(root []byte, proof *iavl.RangeProof, key []byte) error {
    // ❌ Certain crafted inner node combinations could satisfy the
    //    Merkle hash computation without a real leaf commitment
    return proof.Verify(root)  // ❌ Forged proofs passed this check
}

// The attacker constructed a proof with crafted inner nodes that hashed to
// a valid-looking root, bypassing the leaf-existence requirement

// ✅ Correct pattern: verify specific leaf existence and enforce strict path constraints
func verifyLeafExistence(root []byte, proof *iavl.RangeProof, key, value []byte) error {
    // Enforce that the proof contains the specific key-value leaf
    // and that the path from leaf to root is strictly valid
    return proof.VerifyItem(key, value)  // Leaf-specific verification
}
```

---
## 3. Attack Flow

```
Attacker
    │
    ├─[1] Research IAVL Merkle proof library for edge cases
    │       in BNB Beacon Chain → BSC bridge proof verification
    │
    ├─[2] Construct a forged IAVL Merkle proof that passes
    │       BSC Token Hub's handlePackage() verification
    │       without any real Beacon Chain transaction
    │
    ├─[3] Submit forged proof #1 to BSC Token Hub
    │       → 1,000,000 BNB minted to attacker address
    │
    ├─[4] Submit forged proof #2 to BSC Token Hub
    │       → 1,000,000 BNB minted to attacker address
    │       Total: 2,000,000 BNB (~$568M)
    │
    ├─[5] Begin bridging minted BNB to other chains (Ethereum, Fantom, etc.)
    │       via various cross-chain protocols
    │
    ├─[6] ~8 hours later: BSC validators vote to pause the chain
    │       ~$430M frozen on BSC; ~$100M already extracted
    │
    └─[7] Attacker retains ~$100M across multiple chains
```

---
## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | IAVL Merkle proof forgery enabling unauthorized cross-chain mint |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |
| **OWASP DeFi** | Bridge message authentication bypass |
| **Attack Vector** | Crafted IAVL proof submitted to BSC Token Hub bridge contract |
| **Preconditions** | IAVL library edge case allowing forged proof; bridge accepts single-source Merkle proof without additional validator quorum |
| **Impact** | 2M BNB minted (~$568M at risk); ~$100M drained before chain halt |

---
## 5. Remediation Recommendations

1. **Formally verify Merkle proof libraries**: Cross-chain bridge proof verification code is safety-critical and must be formally verified or subjected to exhaustive adversarial testing.
2. **Require multi-validator signature quorum in addition to Merkle proof**: A Merkle proof alone is insufficient for high-value bridges; validators should co-sign cross-chain messages.
3. **Enforce per-epoch minting caps**: Bridge contracts should cap the maximum amount that can be minted within a time window, limiting blast radius.
4. **Emergency pause capability**: BSC's validator-coordinated chain pause (while controversial) limited losses. Every bridge must have a guardian-controlled emergency pause mechanism.

---
## 6. Lessons Learned

- **Centralized chain halt as a last resort**: BSC validators paused the entire chain to limit losses — a decision only possible due to BSC's relatively centralized validator set (21 validators). This prevented ~$430M in additional losses but highlighted the centralization tradeoff.
- **IAVL proof library trust**: The bridge trusted an off-the-shelf IAVL library without adversarial proof-of-concept testing for forged proofs. Cryptographic library choices for bridge security require independent security review.
- **Bridge TVL concentration**: Cross-chain bridges concentrate enormous value in a single contract. The $2B+ locked in BNB Chain bridge made it a prime target; TVL limits and sharding would reduce exposure.
- **Rapid community response**: The BNB validator community's rapid coordination (8 hours) and the ability to freeze assets prevented a much larger loss, demonstrating the value of pre-planned incident response.
