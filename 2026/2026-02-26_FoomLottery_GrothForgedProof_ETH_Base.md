# FOOM Lottery — Groth16 Zero-Knowledge Proof Forgery Attack Analysis (ETH + Base)

| Field | Details |
|------|------|
| **Date** | 2026-02-26 |
| **Protocol** | FOOM Lottery ([foom.club](https://foom.club)) |
| **Chain** | Ethereum Mainnet + Base (simultaneous attack) |
| **Total Loss** | **~24.28 trillion FOOM** (≈13.9% of total supply of 175 trillion FOOM) |
| **ETH Loss** | 19,695,576,757,802 FOOM (30 forged claims) |
| **Base Loss** | 4,588,196,709,631 FOOM (10 forged claims) |
| **Root Cause** | Groth16 zkSNARK proof forgery — trusted setup secret (τ) leak or insufficient circuit constraints |
| **ETH Attack TX** | [`0xce20448...e275e48`](https://etherscan.io/tx/0xce20448233f5ea6b6d7209cc40b4dc27b65e07728f2cbbfeb29fc0814e275e48) |
| **Base Attack TX** | [`0xa88317a...e48d929d`](https://basescan.org/tx/0xa88317a105155b464118431ce1073d272d8b43e87aba528a24b62075e48d929d) |
| **ETH Attacker** | [`0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72`](https://etherscan.io/address/0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72) |
| **Base Attacker** | [`0x73f55A95D6959D95B3f3f11dDd268ec502dAB1Ea`](https://basescan.org/address/0x73f55A95D6959D95B3f3f11dDd268ec502dAB1Ea) |
| **ETH Exploit Contract** | [`0x256a5d6852fa5b3c55d3b132e3669a0bde42e22c`](https://etherscan.io/address/0x256a5d6852fa5b3c55d3b132e3669a0bde42e22c) |
| **Base Exploit Contract** | [`0x005299b37703511b35d851e17dd8d4615e8a2c9b`](https://basescan.org/address/0x005299b37703511b35d851e17dd8d4615e8a2c9b) |

---

## 1. Vulnerability Overview

This attack **forged zero-knowledge proofs** in a Groth16 zkSNARK-based lottery protocol, enabling the attacker to repeatedly withdraw arbitrary rewards without actually participating in or winning the lottery.

FOOM Lottery is a Tornado Cash-style zkSNARK lottery where participants submit a secret commitment hash (`play()`), the protocol processes them in batches (`reveal()`), and winners claim rewards with a Groth16 proof via `collect()`. The sole line of defense for verifying win eligibility is the `withdraw.verifyProof()` call inside `collect()`. However, **the secret parameter (toxic waste, τ) of the Groth16 trusted setup was leaked**, allowing the attacker to freely generate valid proofs for arbitrary public inputs (root, nullifierHash, rewardbits, recipient, etc.).

The attacker executed a total of 40 forged claims across ETH and Base, draining ~24.28 trillion FOOM — approximately 13.9% of the total FOOM supply.

---

## 2. Protocol Structure

### 2.1 FOOM Lottery Workflow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  play()     │────▶│  reveal()    │────▶│  collect()      │
│  Submit     │     │  Batch       │     │  Proof verify + │
│  secret     │     │  process     │     │  Claim reward   │
│  commit     │     │  Merkle tree │     └─────────────────┘
└─────────────┘     │  root gen    │
                    └──────────────┘
```

1. **play()**: Participant submits a commitment hash derived from a `secret` and deposits the bet amount (minimum `betMin` = 1,000,000 FOOM)
2. **reveal()**: Protocol processes commitments in batches, constructs a Merkle tree, and registers the valid root in the `roots[root]` mapping
3. **collect()**: Winner submits a Groth16 proof (`pA`, `pB`, `pC`) along with public inputs (`root`, `nullifierHash`, `rewardbits`, `recipient`, etc.) to claim the reward

### 2.2 Reward Calculation Formula

```solidity
// betMin = 1,000,000 FOOM
// betPower1 = 10, betPower2 = 16, betPower3 = 22
uint reward = betMin * (
    (_rewardbits & 0x1 > 0 ? 1 : 0) * 2**betPower1 +  // 2^10 = 1,024x
    (_rewardbits & 0x2 > 0 ? 1 : 0) * 2**betPower2 +  // 2^16 = 65,536x
    (_rewardbits & 0x4 > 0 ? 1 : 0) * 2**betPower3    // 2^22 = 4,194,304x
);
// With rewardbits = 7 (all bits set):
// 1,000,000 * (1,024 + 65,536 + 4,194,304) = 4,260,864,000,000 FOOM ≈ 4.26 trillion/claim
```

The attacker used `rewardbits = 7` in every claim to demand the **maximum reward (≈4.26 trillion FOOM/claim)**. As the pool balance decreased, later claims were capped by the remaining balance.

### 2.3 Groth16 Verifier Structure (IWithdraw)

| Field | Details |
|------|------|
| **Interface** | `IWithdraw` (48,439 constraints) |
| **ETH Verifier** | [`0xc043865fb4d542e2bc5ed5ed9a2f0939965671a6`](https://etherscan.io/address/0xc043865fb4d542e2bc5ed5ed9a2f0939965671a6) |
| **Base Verifier** | [`0x02c30d32a92a3c338bc43b78933d293ded4f68c6`](https://basescan.org/address/0x02c30d32a92a3c338bc43b78933d293ded4f68c6) |
| **Curve** | BN254 (alt_bn128) |
| **Public Inputs** | `[root, nullifierHash, rewardbits, recipient, relayer, fee, refund]` (7 values) |

The same verifier contract was deployed on both ETH and Base, meaning a compromise of the trusted setup on one chain rendered both chains vulnerable.

### 2.4 Core Contracts

| Role | ETH Address | Base Address |
|------|----------|-----------|
| **FoomLottery** | [`0x239af915abcd0a5dcb8566e863088423831951f8`](https://etherscan.io/address/0x239af915abcd0a5dcb8566e863088423831951f8) | [`0xdb203504ba1fea79164af3ceffba88c59ee8aafd`](https://basescan.org/address/0xdb203504ba1fea79164af3ceffba88c59ee8aafd) |
| **FOOM Token** | [`0xd0d56273290d339aaf1417d9bfa1bb8cfe8a0933`](https://etherscan.io/address/0xd0d56273290d339aaf1417d9bfa1bb8cfe8a0933) | [`0x02300ac24838570012027e0a90d3feccef3c51d2`](https://basescan.org/address/0x02300ac24838570012027e0a90d3feccef3c51d2) |
| **Withdraw Verifier** | [`0xc043865fb4d542e2bc5ed5ed9a2f0939965671a6`](https://etherscan.io/address/0xc043865fb4d542e2bc5ed5ed9a2f0939965671a6) | [`0x02c30d32a92a3c338bc43b78933d293ded4f68c6`](https://basescan.org/address/0x02c30d32a92a3c338bc43b78933d293ded4f68c6) |

---

## 3. Vulnerable Code Analysis

### 3.1 collect() Function — Verification Logic

**❌ Vulnerable collect() function** (based on Sourcify-verified source):

```solidity
function collect(
    uint[2] calldata _pA,
    uint[2][2] calldata _pB,
    uint[2] calldata _pC,
    uint _root,
    uint _nullifierHash,
    address _recipient,
    address _relayer,
    uint _fee,
    uint _refund,
    uint _rewardbits,
    uint _invest
) payable external nonReentrant {
    // [1] Nullifier duplicate check — prevents reuse
    require(nullifier[_nullifierHash] == 0, "Incorrect nullifier");
    nullifier[_nullifierHash] = 1;

    // ...

    // [2] Merkle root validity check — verifies root is registered
    require(roots[_root] > 0, "Cannot find your merkle root");

    // ...

    // ❌ [3] zkSNARK proof verification — the sole critical line of defense
    // If the trusted setup is compromised, this verification is nullified
    require(withdraw.verifyProof(
        _pA, _pB, _pC,
        [_root, _nullifierHash, _rewardbits,
         uint(uint160(_recipient)), uint(uint160(_relayer)),
         _fee, _refund]
    ), "Invalid withdraw proof");  // ❌ Forged proof passes this check

    // ... Reward calculation and FOOM transfer
    emit LogWin(uint(_nullifierHash), reward, _recipient);
}
```

**Issue Analysis:**

- **Nullifier check (`[1]`)**: Does not verify that `nullifierHash` is actually the result of `poseidon(secret, 0)` — only checks that it hasn't been used before. The attacker used arbitrary sequential integers (`0xdead0000`, `0x174876c0f0`, etc.).
- **Root check (`[2]`)**: Any previously registered Merkle root can be used. The attacker reused the `lastRoot` value.
- **Proof verification (`[3]`)**: With the toxic waste (τ) of the Groth16 trusted setup known, a valid proof `(A, B, C)` can be computed algebraically for any arbitrary public inputs. This single line is the entire security anchor, and **forged proofs pass the check**.

### 3.2 Groth16 Verifier Vulnerability

**Field validation in Withdraw.sol verifier:**

```solidity
// BN254 scalar field order check
function checkField(v) {
    // r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    if iszero(lt(v, r)) {  // Verify v < r
        mstore(0, 0)
        return(0, 0x20)    // Return false if out of range
    }
}
```

This verifier checks that public inputs are within the BN254 scalar field range and performs an elliptic curve pairing check (`e(A, B) = e(alpha, beta) * e(C, delta) * e(input_acc, gamma)`). However, this mathematical verification is only sound under the assumption that **the proving key and verification key were generated from an honest trusted setup**.

**Trusted setup compromise scenario:**

If the secret parameter `τ` (toxic waste) generated during the Groth16 trusted setup is known:

```
// Attacker's proof forgery process with known τ (conceptual)
1. Choose arbitrary public inputs x = [root, nullifierHash, rewardbits, ...]
2. Use τ to directly compute group elements (A, B, C) satisfying the polynomial relations
3. Verification equation e(A, B) = e(α, β) · e(C, δ) · e(Σ xᵢ·[βuᵢ(τ)+αvᵢ(τ)+wᵢ(τ)]₁, γ) holds
4. verifyProof() → returns true (accepted as a valid proof)
```

This means valid proofs can be generated purely algebraically without needing to actually satisfy any constraints encoded in the circuit (commitment hashes, Merkle paths, etc.).

### 3.3 Remediation Recommendations

**✅ Hardened collect() (recommended):**

```solidity
function collect(
    uint[2] calldata _pA,
    uint[2][2] calldata _pB,
    uint[2] calldata _pC,
    uint _root,
    uint _nullifierHash,
    address _recipient,
    address _relayer,
    uint _fee,
    uint _refund,
    uint _rewardbits,
    uint _invest
) payable external nonReentrant {
    require(nullifier[_nullifierHash] == 0, "Incorrect nullifier");
    nullifier[_nullifierHash] = 1;

    // ✅ [Fix 1] Merkle root freshness check — blocks use of stale roots
    require(roots[_root] > 0, "Cannot find your merkle root");
    require(
        block.number - roots[_root] <= ROOT_EXPIRY_BLOCKS,
        "Merkle root expired"
    );

    // ✅ [Fix 2] Use verifier regenerated from transparent MPC-based trusted setup
    // Recommend proof systems that require no trusted setup (e.g., PLONK/FFlonk) instead of Groth16
    require(withdraw.verifyProof(
        _pA, _pB, _pC,
        [_root, _nullifierHash, _rewardbits,
         uint(uint160(_recipient)), uint(uint160(_relayer)),
         _fee, _refund]
    ), "Invalid withdraw proof");

    // ✅ [Fix 3] Single claim cap and per-epoch withdrawal limit
    uint reward = _calculateReward(_rewardbits);
    require(reward <= MAX_SINGLE_CLAIM, "Claim exceeds single limit");
    epochWithdrawn[currentEpoch()] += reward;
    require(
        epochWithdrawn[currentEpoch()] <= EPOCH_WITHDRAW_LIMIT,
        "Epoch withdraw limit exceeded"
    );

    // ✅ [Fix 4] Emergency pause
    require(!paused, "Contract paused");

    // ... Transfer reward
}
```

---

## 4. Attack Flow

### 4.1 Base Attack (First, 07:23:13 UTC)

| Field | Details |
|------|------|
| **Block** | 42,650,623 |
| **Time** | 2026-02-26 07:23:13 UTC |
| **TX** | [`0xa88317a...e48d929d`](https://basescan.org/tx/0xa88317a105155b464118431ce1073d272d8b43e87aba528a24b62075e48d929d) |
| **Attacker** | [`0x73f55A95D6959D95B3f3f11dDd268ec502dAB1Ea`](https://basescan.org/address/0x73f55A95D6959D95B3f3f11dDd268ec502dAB1Ea) |
| **Exploit Contract** | [`0x005299b37703511b35d851e17dd8d4615e8a2c9b`](https://basescan.org/address/0x005299b37703511b35d851e17dd8d4615e8a2c9b) |
| **Target** | Base FoomLottery [`0xdb203504...e8aafd`](https://basescan.org/address/0xdb203504ba1fea79164af3ceffba88c59ee8aafd) |
| **Forged Claims** | 10 (nullifier: `0xdead0000` ~ `0xdead0009`) |
| **Amount Drained** | 4,588,196,709,631 FOOM |

**Per-claim amounts (decreasing as pool balance is drained):**

| # | Nullifier | FOOM Drained | Notes |
|---|-----------|----------|------|
| 1 | `0xdead0000` | ~4.05T | Near maximum reward |
| 2 | `0xdead0001` | ~271B | Pool balance decreasing |
| 3 | `0xdead0002` | ~135B | |
| 4 | `0xdead0003` | ~68B | |
| 5 | `0xdead0004` | ~34B | |
| 6 | `0xdead0005` | ~17B | |
| 7 | `0xdead0006` | ~8.5B | |
| 8 | `0xdead0007` | ~4.25B | |
| 9 | `0xdead0008` | ~2.1B | |
| 10 | `0xdead0009` | ~1.06B | Remaining balance exhausted |

### 4.2 ETH Attack (Second, 07:39:11 UTC)

| Field | Details |
|------|------|
| **Block** | 24,539,650 |
| **Time** | 2026-02-26 07:39:11 UTC (~16 minutes after Base attack) |
| **TX** | [`0xce20448...e275e48`](https://etherscan.io/tx/0xce20448233f5ea6b6d7209cc40b4dc27b65e07728f2cbbfeb29fc0814e275e48) |
| **Attacker** | [`0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72`](https://etherscan.io/address/0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72) |
| **Exploit Contract** | [`0x256a5d6852fa5b3c55d3b132e3669a0bde42e22c`](https://etherscan.io/address/0x256a5d6852fa5b3c55d3b132e3669a0bde42e22c) |
| **Target** | ETH FoomLottery [`0x239af915...1951f8`](https://etherscan.io/address/0x239af915abcd0a5dcb8566e863088423831951f8) |
| **Forged Claims** | 30 (nullifier: `0x174876c0f0` ~ `0x174876c10d`, sequential) |
| **Root Used** | `0x1133f8fc791e2940aa6097725856d044ed272b4bf861c166a37260c39ae4be6e` (`roots[root]` = 13600) |
| **Amount Drained** | 19,695,576,757,802 FOOM |

### 4.3 Attack Execution Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Exploit contract deployment (constructor)          │
│                    Single CREATE transaction = atomic execution       │
└──────────────────────┬───────────────────────────────────────────────┘
                       │
                       ▼
            ┌─────────────────────┐
            │   constructor(      │
            │     lottery,        │
            │     token,          │
            │     count           │
            │   )                 │
            └──────────┬──────────┘
                       │
                       ▼
            ┌─────────────────────┐
            │  for i = 0..count   │◀──────────────────────┐
            │  {                  │                        │
            │    ┌────────────────┴───────────────┐       │
            │    │ Compute forged proof (pA, pB,   │       │
            │    │ pC) via BN254 field arithmetic  │       │
            │    │ (using τ toxic waste)           │       │
            │    └────────────────┬───────────────┘       │
            │                    │                        │
            │                    ▼                        │
            │    ┌────────────────────────────────┐       │
            │    │ lottery.collect(               │       │
            │    │   pA, pB, pC,                 │       │
            │    │   lastRoot,                   │       │
            │    │   sequential_nullifier,       │       │
            │    │   attacker_addr,              │       │
            │    │   0, 0, 7, 0                  │       │
            │    │ )                             │       │
            │    └────────────────┬───────────────┘       │
            │                    │                        │
            │                    ▼                        │
            │    ┌────────────────────────────────┐       │
            │    │ verifyProof() → true ❌         │       │
            │    │ (Forged proof passes check)    │       │
            │    │                                │       │
            │    │ FOOM reward → exploit contract │       │
            │    └────────────────┬───────────────┘       │
            │                    │                        │
            │  }                 └────────────────────────┘
            └─────────────────────┘
                       │
                       ▼
            ┌─────────────────────┐
            │  Full remaining     │
            │  FOOM balance →     │
            │  attacker EOA       │
            └─────────────────────┘
```

---

## 5. Transaction Details

| Field | Base Attack (First) | ETH Attack (Second) |
|------|-----------------|----------------|
| **TX Hash** | [`0xa88317a...e48d929d`](https://basescan.org/tx/0xa88317a105155b464118431ce1073d272d8b43e87aba528a24b62075e48d929d) | [`0xce20448...e275e48`](https://etherscan.io/tx/0xce20448233f5ea6b6d7209cc40b4dc27b65e07728f2cbbfeb29fc0814e275e48) |
| **Block** | 42,650,623 | 24,539,650 |
| **Time (UTC)** | 2026-02-26 07:23:13 | 2026-02-26 07:39:11 |
| **Attacker EOA** | `0x73f55A95...dAB1Ea` | `0x46c403e3...Eb72` |
| **Exploit Deploy** | `0x005299b3...2c9b` | `0x256a5d68...e22c` |
| **Target Lottery** | `0xdb203504...e8aafd` | `0x239af915...1951f8` |
| **Claim Count** | 10 | 30 |
| **Nullifier Range** | `0xdead0000` ~ `0xdead0009` | `0x174876c0f0` ~ `0x174876c10d` |
| **rewardbits** | 7 (maximum reward) | 7 (maximum reward) |
| **Amount Drained** | 4,588,196,709,631 FOOM | 19,695,576,757,802 FOOM |
| **TX Type** | Contract creation (CREATE) | Contract creation (CREATE) |

---

## 6. Forged Proof Structure Analysis

### 6.1 BN254 Constants in Exploit Bytecode

The bytecodes of both exploit contracts contain hardcoded core constants of the BN254 elliptic curve, proving that proof forgery was performed **dynamically on-chain**.

| Constant | Value | Location |
|------|-----|----------|
| **Base field prime (q)** | `0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47` | ETH exploit |
| **Scalar field order (r)** | `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001` | Base exploit |

- **ETH exploit**: Uses base field prime `q` as a constant — applied in elliptic curve point (G1/G2) coordinate arithmetic
- **Base exploit**: Uses scalar field order `r` as a constant — applied in scalar multiplication and modular arithmetic

Both exploits perform BN254 field arithmetic **within the constructor** to dynamically compute proof components `(pA, pB, pC)`. This means rather than simply replaying pre-computed proofs, the attacker **generated a fresh proof matching each new nullifier in real time**, with knowledge of the trusted setup's secret parameter.

### 6.2 Sequential Nullifier Pattern

A legitimate nullifierHash should be the output of `poseidon(secret, 0)` — a 256-bit hash value. However, the nullifiers used in the attack were:

| Chain | Nullifier Range | Pattern |
|------|---------------|------|
| **Base** | `0xdead0000` ~ `0xdead0009` | `0xdead` magic bytes + sequential counter |
| **ETH** | `0x174876c0f0` ~ `0x174876c10d` | Sequential integers (100000000240 ~ 100000000269) |

This pattern proves two things:
1. **Insufficient circuit constraints**: A correct circuit would enforce `nullifierHash = poseidon(secret, 0)`, making arbitrary integers unusable as nullifiers. This confirms the circuit constraints were bypassed during proof forgery.
2. **Deliberate differentiation**: The `0xdead` prefix and sequential pattern were intentional — the attacker understood that only uniqueness per claim was required.

### 6.3 Cross-Chain Attacker Linkage

**Base attacker address embedded in ETH exploit bytecode:**

```
Constant in ETH exploit bytecode:
0x73f55a95d6959d95b3f3f11ddd268ec502dab1ea = Base attacker EOA
```

This strongly suggests that both attacks were carried out by **the same actor or a coordinated team**. They executed the Base attack first (07:23 UTC) and then scaled the same technique to ETH 16 minutes later (07:39 UTC, expanding to 30 claims).

---

## 7. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Description |
|----|--------|--------|-----|------|
| **V-01** | Trusted Setup Compromise / Proof Forgery | **CRITICAL** | CWE-320 (Key Management Error), CWE-347 (Improper Verification of Cryptographic Signature) | Leaked toxic waste (τ) from Groth16 trusted setup allows attacker to generate valid proofs for arbitrary public inputs |
| **V-02** | Acceptance of Arbitrary Nullifiers | **HIGH** | CWE-345 (Insufficient Verification of Data Authenticity) | `collect()` does not validate the format or origin of nullifierHash, allowing arbitrary values such as sequential integers to be used as nullifiers |
| **V-03** | Missing Circuit Constraint Enforcement | **HIGH** | CWE-697 (Incorrect Comparison) | Circom circuit does not sufficiently enforce constraints such as `nullifierHash = poseidon(secret, 0)`, or the constraints themselves are nullified by the trusted setup compromise |

---

## 8. Loss Summary

| Chain | Claim Count | FOOM Drained | % of Total Supply |
|------|----------|----------|----------------|
| **Ethereum** | 30 | 19,695,576,757,802 | ≈11.3% |
| **Base** | 10 | 4,588,196,709,631 | — |
| **Total** | **40** | **24,283,773,467,433** | **≈13.9%** (based on ETH supply of 175T) |

- USD loss cannot be calculated as no public FOOM token price was available
- Approximately 13.9% of total supply being drained in a single incident constitutes a critical blow to the token economy

---

## 9. Remediation Recommendations

### 9.1 Immediate Actions (Emergency)

| Priority | Action | Description |
|---------|------|------|
| **P0** | Emergency pause | Immediately halt all `collect()` calls (activate pause mechanism) |
| **P0** | Fund freeze | Block FOOM token transfers from attacker addresses (blacklist) |
| **P0** | Defend additional chains | Immediately pause on all chains where the same verifier is deployed |

### 9.2 Fundamental Fixes (Medium-Term)

| Priority | Action | Description |
|---------|------|------|
| **P1** | Redo trusted setup | Conduct a new trusted setup via a transparent MPC (Multi-Party Computation) ceremony with at least dozens of independent participants |
| **P1** | Replace proof system | Migrate from Groth16 to a **transparent** (trustless setup) proof system such as **PLONK, FFlonk, or Halo2** |
| **P1** | Circuit audit | Perform an independent audit to verify that Circom circuit constraints fully enforce `nullifierHash = poseidon(secret, 0)`, Merkle path validity, etc. |

### 9.3 Defense in Depth (Long-Term)

| Priority | Action | Description |
|---------|------|------|
| **P2** | Introduce withdrawal limits | Set maximum per-epoch total withdrawals and per-single-claim caps |
| **P2** | Merkle root expiration | Block use of stale Merkle roots to narrow the attack window |
| **P2** | Real-time monitoring | Alert on anomalous claim patterns (multiple maximum-reward claims, repeated claims within a single TX) |
| **P3** | Timelock | Introduce a time-delay mechanism for large withdrawals |

---

## 10. Lessons Learned

### 10.1 Trusted Setup Is a Single Point of Failure

The security of Groth16 relies entirely on the assumption that the toxic waste (τ) generated during the trusted setup was permanently destroyed. **If this assumption breaks down, the entire proof system is nullified** — no matter how correctly the verifier is implemented on-chain, it cannot reject forged proofs.

- A protocol team that conducts its own trusted setup cannot escape suspicion of retaining the toxic waste
- A **public MPC ceremony with at least dozens of independent participants** is essential
- Where possible, migrate to proof systems that require no trusted setup (PLONK, STARKs, etc.)

### 10.2 Defense in Depth for zkSNARK-Based Protocols

Zero-knowledge proof verification must not be the sole security mechanism. This incident demonstrates the need for **defense-in-depth** to handle scenarios where the cryptographic layer fails:

- **Withdrawal limits**: Cap maximum withdrawals per transaction or per time window
- **Emergency pause**: Mechanism to halt the contract immediately upon detecting anomalies
- **Monitoring**: Real-time detection of abnormal patterns (sequential nullifiers, repeated maximum-reward claims, etc.)

### 10.3 Cross-Chain Deployment Amplifies Risk

Deploying the same verifier contract across multiple chains means a single vulnerability **simultaneously affects all deployments**. In this incident, the attacker attacked Base and ETH 16 minutes apart, maximizing damage.

### 10.4 Atomic Attack via Contract Creation Transactions

The attacker used a **contract creation (CREATE) transaction** rather than a regular function call, executing all attack logic inside the constructor. This enabled:
- 30 forged claims in a single atomic transaction
- Complete rollback with no trace left if the attack fails
- On-chain proof computation, enabling dynamic attacks without pre-computation