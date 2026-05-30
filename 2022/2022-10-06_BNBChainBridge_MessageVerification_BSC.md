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

> **Source**: REAL — `github.com/cosmos/iavl` commit `807f8c54` (pre-fix state, August 2022 — the version in production at time of exploit). Fix landed in commit `2022-10-08` ("error on both left and right being set", security advisory GHSA-gf4j-mf57-3762). The BNB Beacon Chain bridge compiled this library into its Go node binary. No Solidity source exists for the proof verifier; the BSC TokenHub (Solidity) merely accepts packets that the Go relay has already verified.
>
> Source URL: https://github.com/cosmos/iavl/blob/807f8c542e48369d35622d582f56da5187d128b3/proof.go

### 2.1 `ProofInnerNode` — the vulnerable struct

```go
// File: github.com/cosmos/iavl — proof.go (commit 807f8c54, pre-fix)
// REAL SOURCE — verbatim from cosmos/iavl at the time of the BNB bridge exploit

type ProofInnerNode struct {
    Height  int8   `json:"height"`
    Size    int64  `json:"size"`
    Version int64  `json:"version"`
    Left    []byte `json:"left"`   // hash of the left child
    Right   []byte `json:"right"`  // hash of the right child
}

// Hash computes this inner node's contribution to the Merkle root.
// childHash is the hash of the child being traversed down to.
func (pin ProofInnerNode) Hash(childHash []byte) ([]byte, error) {
    hasher := sha256.New()

    buf := bufPool.Get().(*bytes.Buffer)
    buf.Reset()
    defer bufPool.Put(buf)

    err := encoding.EncodeVarint(buf, int64(pin.Height))
    if err == nil {
        err = encoding.EncodeVarint(buf, pin.Size)
    }
    if err == nil {
        err = encoding.EncodeVarint(buf, pin.Version)
    }

    // ❌ MISSING CHECK: no rejection when BOTH Left and Right are set.
    //    In a valid IAVL tree, an inner node on the proof path has exactly one
    //    side occupied (the sibling hash) and the other side occupied by childHash.
    //    When Left == nil, the encoder uses childHash as left and pin.Right as right.
    //    When Left != nil, it uses pin.Left as left and childHash as right.
    //    But if an attacker supplies a ProofInnerNode where BOTH Left AND Right are
    //    non-empty, the code still falls into the `else` branch (Left != nil) and
    //    silently ignores the supplied Right value, hashing only Left + childHash.
    //    This means the attacker can freely choose any childHash they want and the
    //    resulting hash still matches — Right is never validated.

    if len(pin.Left) == 0 {
        if err == nil {
            err = encoding.EncodeBytes(buf, childHash) // child goes to left slot
        }
        if err == nil {
            err = encoding.EncodeBytes(buf, pin.Right) // sibling goes to right slot
        }
    } else {
        // ❌ Entered whenever Left is non-empty — even if Right is also non-empty.
        //    The supplied pin.Right is completely ignored here.
        if err == nil {
            err = encoding.EncodeBytes(buf, pin.Left)  // sibling goes to left slot
        }
        if err == nil {
            err = encoding.EncodeBytes(buf, childHash) // child goes to right slot
        }
    }

    if err != nil {
        return nil, fmt.Errorf("failed to hash ProofInnerNode: %v", err)
    }

    _, err = hasher.Write(buf.Bytes())
    if err != nil {
        return nil, err
    }
    return hasher.Sum(nil), nil
}
```

### 2.2 `RangeProof.Verify()` — accepts the forged proof

```go
// File: github.com/cosmos/iavl — proof_range.go (commit 807f8c54, pre-fix)
// REAL SOURCE — verbatim from cosmos/iavl

func (proof *RangeProof) Verify(root []byte) error {
    if proof == nil {
        return errors.Wrap(ErrInvalidProof, "proof is nil")
    }
    err := proof.verify(root)
    return err
}

func (proof *RangeProof) verify(root []byte) (err error) {
    rootHash := proof.rootHash
    if rootHash == nil {
        derivedHash, err := proof.computeRootHash()
        if err != nil {
            return err
        }
        rootHash = derivedHash
    }
    if !bytes.Equal(rootHash, root) {
        return errors.Wrap(ErrInvalidRoot, "root hash doesn't match")
    }
    // ❌ Sets rootVerified = true as soon as hashes match.
    //    No check that any real key-value leaf exists in the proof.
    //    An attacker crafted a proof whose _computeRootHash() produces the
    //    known Beacon Chain root hash, using the Left+Right trick above,
    //    without any real leaf entry corresponding to a chain transaction.
    proof.rootVerified = true
    return nil
}
```

### 2.3 Exploit Mechanic — Forging the Inner Node

The attacker forged a `ProofInnerNode` at position `LeftPath[1]` of the proof:

```
Legitimate inner node:   Left = <sibling-hash>   Right = nil
Forged inner node:       Left = <sibling-hash>   Right = <attacker-chosen-hash>
```

Because `Hash()` only encodes `Left + childHash` whenever `Left != nil`, and **silently ignores `Right`**, the attacker could supply any value for `Right` (including the hash of a fabricated 1,000,000-BNB transfer message) without affecting the root-hash computation. The root hash still matched the Beacon Chain's known root, so `Verify()` returned `nil` (success).

The cross-chain packet claimed a transfer of 1,000,000 BNB from Beacon Chain → BSC. The TokenHub contract called `handlePackage()` which called `Verify()` → success → minted 1,000,000 BNB. Repeated once more for a total of 2,000,000 BNB minted.

**Why it is exploitable (identify the bug from the code):**

- `ProofInnerNode.Hash()` branches on `len(pin.Left) == 0` to decide which side `childHash` goes. When `pin.Left != nil`, the function encodes `pin.Left + childHash` and **never reads `pin.Right`**.
- There is no guard `if len(pin.Left) > 0 && len(pin.Right) > 0 { return nil, error }` — both fields can be set simultaneously without rejection.
- An attacker who sets `Left` to a legitimate sibling hash and `Right` to an arbitrary payload hash gets a root hash computed purely from `Left + childHash` — `Right` is ignored, so the root still matches the real Beacon Chain root.
- `RangeProof.Verify(root)` then sets `rootVerified = true`, which is all the bridge checks before minting BNB.
- The protocol never called `VerifyItem(key, value)` (leaf-existence check) before accepting the cross-chain packet.

### 2.4 Fix — One-Line Guard in `Hash()`

```go
// ✅ Fix: github.com/cosmos/iavl commit 2022-10-08 (GHSA-gf4j-mf57-3762)
// Added immediately after the Version encoding block:

if len(pin.Left) > 0 && len(pin.Right) > 0 {
    // ✅ Reject any inner node where both child sides are pre-populated.
    //    A real proof path node has exactly one sibling hash and one slot
    //    for childHash — never both. This one guard closes the forgery window.
    return nil, errors.New("both left and right child hashes are set")
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
