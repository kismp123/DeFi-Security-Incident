# FOOMCASH — Business Logic Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2026-02-26 |
| **Protocol** | FOOMCASH ([foom.club](https://foom.club)) |
| **Chain** | Ethereum (+ Base simultaneous attack) |
| **Loss** | ~$2,260,000 (24.28 trillion FOOM; ≈13.9% of total supply) |
| **Attacker (ETH)** | [`0x46c4...Eb72`](https://etherscan.io/address/0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72) |
| **Attack Contract (ETH)** | [`0x256a...e22c`](https://etherscan.io/address/0x256a5d6852fa5b3c55d3b132e3669a0bde42e22c) |
| **Attack Tx** | [`0xce20...e48`](https://etherscan.io/tx/0xce20448233f5ea6b6d7209cc40b4dc27b65e07728f2cbbfeb29fc0814e275e48) |
| **Vulnerable Contract** | FoomLottery [`0x239a...1f8`](https://etherscan.io/address/0x239af915abcd0a5dcb8566e863088423831951f8) |
| **Root Cause** | Business logic flaw — Groth16 verifier neutralized due to incomplete snarkjs Phase 2 Trusted Setup |
| **PoC Reference** | [DeFiHackLabs (not registered)](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

FOOMCASH (foom.cash) is a Groth16 zkSNARK-based lottery protocol where participants submit a secret commitment hash (`play()`) and winners claim rewards by presenting a zero-knowledge proof (`collect()`).

The core vulnerability is classified as a **business logic flaw**. When the protocol team deployed the Groth16 verifier, they omitted required CLI commands from the `snarkjs Phase 2 trusted setup`, leaving the verification parameters `gamma (γ)` and `delta (δ)` at their snarkjs defaults (identical BN254 G2 generator points). As a result:

- **γ = δ = G2 generator** at deployment
- The verification equation degenerates into an essentially `1 = 1` identity
- An attacker can produce a **forged proof that always passes for any public input** simply by setting `pC = −vk_x`, `pA = α`, `pB = β`
- Regardless of lottery participation history, secret commitment, or actual winning status, repeatedly calling `collect()` allows draining the entire pool balance

The attacker embedded the attack loop inside the constructor of a contract-creation (CREATE) transaction on both the ETH and Base chains, executing 30 forged claims on ETH and 10 on Base as a **single atomic transaction** each.

---

## 2. Vulnerable Code Analysis

### 2.1 Incomplete snarkjs Phase 2 — Groth16 Verification Parameter Error (Root Cause)

**❌ Vulnerable verification key state (deployed with snarkjs defaults)**

```solidity
// Groth16 Verifier (0xc043865fb4d542e2bc5ed5ed9a2f0939965671a6)
// The following CLI should have been run during snarkjs Phase 2, but was skipped:
// $ snarkjs groth16 contribute circuit.zkey circuit_final.zkey --name="contributor1"
//
// ❌ gamma(γ) and delta(δ) left as identical G2 generator points
//    gamma_neg_x = delta_neg_x  (same value)
//    gamma_neg_y = delta_neg_y  (same value)
//
// Groth16 verification equation:
//   e(pA, pB) == e(alpha, beta) * e(vk_x, gamma) * e(pC, delta)
//
// When gamma == delta, the equation can be transformed as follows:
//   Setting pC = -(vk_x) gives
//   e(pC, delta) == e(-vk_x, gamma)
//   e(vk_x, gamma) * e(pC, delta) == e(vk_x, gamma) * e(-vk_x, gamma) == 1
//
// Result: only e(pA, pB) == e(alpha, beta) needs to hold,
//         setting pA = alpha, pB = beta always returns true → verifier fully neutralized
function verifyProof(
    uint[2] calldata _pA,
    uint[2][2] calldata _pB,
    uint[2] calldata _pC,
    uint[7] calldata _pubSignals
) public view returns (bool) {
    // ... BN254 pairing verification ...
    // ❌ Forged proof (alpha, beta, -vk_x combination) passes this verification
}
```

**✅ Corrected deployment procedure**

```solidity
// Required snarkjs Phase 2 trusted setup commands:
// $ snarkjs powersoftau new bn128 16 pot16_0000.ptau
// $ snarkjs powersoftau contribute pot16_0000.ptau pot16_0001.ptau --name="contributor1"
// $ snarkjs powersoftau beacon pot16_0001.ptau pot16_beacon.ptau <HASH> 10
// $ snarkjs powersoftau prepare phase2 pot16_beacon.ptau pot16_final.ptau
// $ snarkjs groth16 setup circuit.r1cs pot16_final.ptau circuit_0000.zkey
//
// ✅ At least 1 Phase 2 contributor required (multiple independent contributors recommended):
// $ snarkjs zkey contribute circuit_0000.zkey circuit_0001.zkey --name="contributor1"
//
// ✅ Explicitly verify gamma ≠ delta before deployment:
// $ snarkjs zkey verify circuit.r1cs pot16_final.ptau circuit_final.zkey
// $ snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
// # Confirm "gamma2" ≠ "delta2" in verification_key.json
```

**Issue**: Skipping the snarkjs `groth16 contribute` command leaves the γ and δ parameters at their defaults (identical G2 generators). This completely breaks the soundness guarantee of Groth16, making it possible to forge a valid proof for any public input.

---

### 2.2 collect() — Vulnerable Verification-Dependent Structure

**❌ Vulnerable collect() function** (FoomLottery contract)

```solidity
function collect(
    uint[2] calldata _pA,
    uint[2][2] calldata _pB,
    uint[2] calldata _pC,
    uint _root,
    uint _nullifierHash,   // ❌ Accepts arbitrary sequential integers (e.g. 0x174876c0f0)
    address _recipient,
    address _relayer,
    uint _fee,
    uint _refund,
    uint _rewardbits,      // ❌ Can always be set to 7 (maximum value)
    uint _invest
) payable external nonReentrant {
    // [1] Nullifier double-spend prevention — passes if value is a new arbitrary integer
    require(nullifier[_nullifierHash] == 0, "Incorrect nullifier");
    nullifier[_nullifierHash] = 1;

    // [2] Merkle root check — previously registered arbitrary root can be reused
    require(roots[_root] > 0, "Cannot find your merkle root");

    // ❌ [3] zkSNARK verification — completely neutralized by gamma==delta
    //        Forged proof (pA=alpha, pB=beta, pC=-vk_x) always returns true
    require(withdraw.verifyProof(
        _pA, _pB, _pC,
        [_root, _nullifierHash, _rewardbits,
         uint(uint160(_recipient)), uint(uint160(_relayer)),
         _fee, _refund]
    ), "Invalid withdraw proof");

    // [4] Reward calculation — rewardbits=7 pays maximum reward
    // betMin=1,000,000 FOOM, betPower1=10, betPower2=16, betPower3=22
    uint reward = betMin * (
        (_rewardbits & 0x1 > 0 ? 1 : 0) * 2**betPower1 +  // 2^10 = 1,024x
        (_rewardbits & 0x2 > 0 ? 1 : 0) * 2**betPower2 +  // 2^16 = 65,536x
        (_rewardbits & 0x4 > 0 ? 1 : 0) * 2**betPower3    // 2^22 = 4,194,304x
    );
    // rewardbits=7: 1,000,000 * (1,024 + 65,536 + 4,194,304) ≈ 4.26 trillion FOOM per call

    FOOM.transfer(_recipient, reward);
    emit LogWin(uint(_nullifierHash), reward, _recipient);
}
```

**Issue**: `collect()` relies solely on the zkSNARK proof verification as its only security defense. With the verifier itself broken, there are no additional business-logic defenses — no withdrawal limits, rate limiting, or emergency pause — leaving the entire pool drainable.

---

## 3. Attack Flow

### 3.1 Preparation Phase

| Item | Details |
|------|------|
| **Prior Research** | Designed as a copycat attack based on the identical vulnerability in Veil Cash ($427K, 2026-02) |
| **Vulnerability Confirmation** | Confirmed gamma2 == delta2 in the verification key (via verification_key.json or on-chain contract constants) |
| **Attack Contract Design** | Loop embedded in constructor; forged proofs generated dynamically using BN254 field arithmetic |
| **Pre-funding** | Acquired ETH for attack gas costs |

### 3.2 Execution Phase

**Base Pre-Attack (2026-02-26 07:23:13 UTC, Block 42,650,623)**

1. Attacker (`0x73f55A95...dAB1Ea`) deploys exploit contract (`0x005299b3...2c9b`)
2. Constructor loop executes 10 times:
   - nullifier = `0xdead0000` ~ `0xdead0009` (sequential arbitrary integers)
   - Forged proof generated with pA=α, pB=β, pC=−vk_x
   - `FoomLottery.collect()` called → verifyProof() passes
   - rewardbits=7 → maximum reward claimed (pool balance rapidly drained)
3. **Stolen: 4,588,196,709,631 FOOM (Base pool ≈99.97% drained)**

**ETH Follow-up Attack (2026-02-26 07:39:11 UTC, Block 24,539,650, 16 minutes after Base attack)**

4. Attacker (`0x46c403e3...Eb72`) deploys exploit contract (`0x256a5d68...e22c`)
5. Constructor loop executes 30 times:
   - nullifier = `0x174876c0f0` ~ `0x174876c10d` (sequential integers)
   - lastRoot = `0x1133f8fc...be6e` reused
   - Same forged proof technique used to call `collect()` 30 times
6. **Stolen: 19,695,576,757,802 FOOM (ETH pool ≈99.99% drained)**

### 3.3 Attack Flow Diagram

```
  Attacker EOA
  0x46c403...Eb72
       │
       │ CREATE (contract creation transaction)
       ▼
┌─────────────────────────────────────────────────────┐
│         Exploit Contract constructor()              │
│         0x256a5d6852fa5b3c55d3b132e3669a0bde42e22c  │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │  for i = 0..29  (30 iterations)              │   │
│  │                                              │   │
│  │  [Step 1] Generate forged proof via          │   │
│  │           BN254 field arithmetic             │   │
│  │           pA = α (vk.alpha1)                 │   │
│  │           pB = β (vk.beta2)                  │   │
│  │           pC = −vk_x  ← exploiting gamma==delta  │
│  │           nullifier = 0x174876c0f0 + i       │   │
│  │                          │                   │   │
│  │                          ▼                   │   │
│  │  [Step 2] Call FoomLottery.collect()         │   │
│  │           (0x239af915...1951f8)               │   │
│  │                          │                   │   │
│  │                          ▼                   │   │
│  │  ┌───────────────────────────────────────┐   │   │
│  │  │  nullifier[hash] == 0 ?  → OK (new)   │   │   │
│  │  │  roots[lastRoot] > 0 ?   → OK (registered) │  │
│  │  │  verifyProof(pA,pB,pC) ? → OK ❌forged │   │   │
│  │  │  (gamma==delta → verification degenerates) │  │
│  │  │           │                           │   │   │
│  │  │           ▼                           │   │   │
│  │  │  Reward calculation (rewardbits=7)    │   │   │
│  │  │  = 1,000,000 * (2^10+2^16+2^22) FOOM │   │   │
│  │  │  ≈ 4.26 trillion FOOM                 │   │   │
│  │  │           │                           │   │   │
│  │  │           ▼                           │   │   │
│  │  │  FOOM.transfer(exploit contract)      │   │   │
│  │  └───────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────┘   │
│                       │                             │
│                       ▼                             │
│    Remaining FOOM → transferred to attacker EOA     │
└─────────────────────────────────────────────────────┘
       │
       ▼
  Attacker wallet
  19,695,576,757,802 FOOM received
  (ETH pool 99.99% drained)
```

### 3.4 Outcome

| Item | Figure |
|------|------|
| Total forged claims | 40 (ETH 30 + Base 10) |
| Total stolen FOOM | 24,283,773,467,433 FOOM (~$2.26M) |
| ETH attack duration | Single TX (1 block) |
| Net loss | ~$420K (after white-hat return of $1.84M) |

---

## 4. Vulnerability Classification (CWE)

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Incomplete snarkjs Phase 2 — gamma==delta misconfiguration | **CRITICAL** | CWE-1277 (Incomplete Cryptographic Key Initialization), CWE-320 (Key Management Error) |
| V-02 | Arbitrary claims enabled by verifier neutralization | **CRITICAL** | CWE-347 (Improper Verification of Cryptographic Signature) |
| V-03 | Arbitrary nullifiers accepted — no format/origin validation | **HIGH** | CWE-345 (Insufficient Verification of Data Authenticity) |
| V-04 | Unlimited withdrawals in a single TX — no rate limiting | **HIGH** | CWE-770 (Allocation of Resources Without Limits) |
| V-05 | Reliance on a single security layer — no emergency pause | **MEDIUM** | CWE-636 (Not Failing Securely / Principle of Least Privilege Violation) |

### V-01: Incomplete snarkjs Phase 2 (gamma==delta)

- **Description**: Skipping `zkey contribute` during Groth16 trusted setup Phase 2 leaves γ and δ fixed at the same BN254 G2 generator point. The verification equation degenerates to requiring only `e(pA, pB) = e(α, β)`.
- **Impact**: For any public input (root, nullifierHash, rewardbits, etc.), simply setting `pA=α, pB=β, pC=−vk_x` always passes verification, enabling unlimited reward claims.
- **Attack condition**: Confirm that the deployed verifier's gamma2 and delta2 values are identical (easily discoverable by querying on-chain constants or analyzing verification_key.json).

### V-02: Arbitrary Claims Enabled

- **Description**: With verifyProof() broken, collect() can be called repeatedly regardless of any actual lottery participation (play()) history or winning status.
- **Impact**: Complete theft of all protocol funds.
- **Attack condition**: Automatically enabled when V-01 is satisfied.

### V-03: Arbitrary Nullifiers Accepted

- **Description**: `collect()` does not verify that `nullifierHash` conforms to the `poseidon(secret, 0)` format. Arbitrary values such as sequential integers are accepted as nullifiers.
- **Impact**: Even without V-01, if nullifiers can be generated outside the circuit, the double-spend defense can be bypassed.
- **Attack condition**: Combined with proof forgery under V-01, facilitates repeated claims with ease.

### V-04: Unlimited Withdrawals in a Single TX

- **Description**: 30 consecutive withdrawals are possible within the constructor loop of a single contract-creation TX. No per-epoch withdrawal cap or maximum single-claim amount.
- **Impact**: 100% of pool balance can be drained in a single transaction.
- **Attack condition**: Automatically enabled when V-01 is satisfied.

### V-05: No Emergency Pause

- **Description**: No pause mechanism exists to immediately halt the protocol upon detecting abnormal claim patterns.
- **Impact**: No defensive action possible while an attack is in progress.
- **Attack condition**: Applies under all conditions.

---

## 5. Remediation Recommendations

### Immediate Actions (P0)

```solidity
// 1. Emergency pause mechanism (cannot be applied to already-deployed contracts → mandatory for new deployments)
modifier whenNotPaused() {
    require(!paused, "Contract paused");
    _;
}

// 2. Verification key validation script before new deployments (mandatory automation)
// scripts/verify_vkey.js
const vkey = require('./verification_key.json');
const assert = require('assert');
// ✅ Explicitly confirm gamma2 ≠ delta2
assert.notDeepStrictEqual(
    vkey.gamma2, vkey.delta2,
    "CRITICAL: gamma2 == delta2. Phase 2 trusted setup is incomplete."
);
console.log("Verification key check passed: gamma2 ≠ delta2");
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| **V-01** | Run snarkjs Phase 2 `zkey contribute` without exception. Conduct an MPC ceremony with at least 2 independent contributors (more recommended for independence). Integrate `gamma2 ≠ delta2` automated validation script into CI before deployment. |
| **V-01 Alternative** | Migrate from Groth16 to **PLONK, FFlonk, or Halo2** (transparent proof systems that require no trusted setup) |
| **V-02** | Add withdrawal rate limiting to `collect()`. Limit the maximum number of claims per single TX. |
| **V-03** | Add nullifierHash format validation. Enforce the `nullifierHash = poseidon(secret, 0)` constraint within the circuit. |
| **V-04** | Implement per-epoch withdrawal caps and maximum single-claim amount limits. |
| **V-05** | Introduce the Pausable pattern. Add monitoring alerts for abnormal patterns (sequential nullifiers, multiple max-value claims in a single TX). |

```solidity
// ✅ Fixed collect() — multi-layered defense applied
function collect(
    uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC,
    uint _root, uint _nullifierHash, address _recipient,
    address _relayer, uint _fee, uint _refund, uint _rewardbits, uint _invest
) payable external nonReentrant whenNotPaused {
    // ✅ 1. Nullifier double-spend prevention
    require(nullifier[_nullifierHash] == 0, "Incorrect nullifier");
    nullifier[_nullifierHash] = 1;

    // ✅ 2. Merkle root validity + expiry check
    require(roots[_root] > 0, "Cannot find your merkle root");
    require(block.number - roots[_root] <= ROOT_EXPIRY_BLOCKS, "Merkle root expired");

    // ✅ 3. zkSNARK proof verification (using corrected verification key)
    require(withdraw.verifyProof(
        _pA, _pB, _pC,
        [_root, _nullifierHash, _rewardbits,
         uint(uint160(_recipient)), uint(uint160(_relayer)), _fee, _refund]
    ), "Invalid withdraw proof");

    // ✅ 4. Reward calculation and withdrawal limit check
    uint reward = _calculateReward(_rewardbits);
    require(reward <= MAX_SINGLE_CLAIM, "Claim exceeds single limit");
    uint epoch = block.number / EPOCH_BLOCKS;
    epochWithdrawn[epoch] += reward;
    require(epochWithdrawn[epoch] <= EPOCH_WITHDRAW_LIMIT, "Epoch withdraw limit exceeded");

    FOOM.transfer(_recipient, reward);
    emit LogWin(uint(_nullifierHash), reward, _recipient);
}
```

---

## 6. Lessons Learned

### 6.1 Do Not Trust Cryptographic Library Defaults

The default initial values in snarkjs Phase 2 (G2 generators) are intended for testing and must never be used in production. **Default values in cryptographic libraries are often intentionally insecure**, designed to force developers to complete the full configuration procedure. A "verification key state automated check" step must be mandatorily integrated into the CI/CD pipeline before any deployment.

### 6.2 Do Not Rely on a Single Cryptographic Defense Layer

Zero-knowledge proof verification must never be the **sole** line of defense. Multi-layered business-logic defenses against cryptographic implementation failures — withdrawal limits, rate limiting, emergency pause, real-time monitoring — are essential. Every DeFi protocol using zkSNARKs should include the scenario "what if the ZKP breaks?" in its threat model.

### 6.3 Phase 2 Trusted Setup Requires Multiple Independent Contributors

A trusted setup conducted by a single team cannot be free from suspicion of holding toxic waste. A **public MPC ceremony** with at minimum dozens of independent contributors must be conducted. Where possible, consider migrating to **PLONK, FFlonk, or STARK** transparent proof systems that require no trusted setup at all.

### 6.4 Cross-Chain Deployment Amplifies Vulnerabilities

Deploying the same verifier contract across multiple chains means a single vulnerability **simultaneously affects all chains**. In this incident, the Base attack (07:23) was followed by the ETH attack (07:39) just 16 minutes later, maximizing damage. Cross-chain deployments require per-chain independent monitoring and individual emergency pause mechanisms.

### 6.5 Atomic Attacks via Contract Creation Transactions

When an attacker uses a **contract creation (CREATE) transaction** instead of a regular function call, all logic within the constructor executes as a single atomic transaction. This meant 30 withdrawals were processed atomically within a single block, making intermediate-state detection or front-running impossible. Protocols must implement separate defense logic against repeated calls within a single TX.

### 6.6 Failure to Learn from Prior Incidents (Veil Cash)

This attack was a **copycat** of the identical vulnerability exploited in Veil Cash approximately two weeks earlier ($427K loss). Similar zkSNARK-based protocols must cultivate a security culture of promptly reviewing security incidents in competing protocols and verifying whether the same vulnerability exists in their own systems.

---

## 7. On-Chain Verification

### 7.1 Attack Tx Basic Information

| Item | ETH Attack Tx | Base Attack Tx |
|------|------------|-------------|
| **TX Hash** | `0xce20448233f5ea6b6d7209cc40b4dc27b65e07728f2cbbfeb29fc0814e275e48` | `0xa88317a105155b464118431ce1073d272d8b43e87aba528a24b62075e48d929d` |
| **Block** | 24,539,650 | 42,650,623 |
| **Time (UTC)** | 2026-02-26 07:39:11 | 2026-02-26 07:23:13 |
| **TX Type** | CREATE (contract deployment) | CREATE (contract deployment) |

### 7.2 PoC vs On-Chain Amount Comparison

| Item | Analyzed Value | On-Chain Actual | Match |
|------|--------|------------|------|
| ETH stolen FOOM | 19,695,576,757,802 | 19,695,576,757,802 | ✅ |
| Base stolen FOOM | 4,588,196,709,631 | 4,588,196,709,631 | ✅ |
| Total stolen FOOM | 24,283,773,467,433 | 24,283,773,467,433 | ✅ |
| USD loss | ~$2,260,000 | ~$2,260,000 | ✅ |
| ETH claim count | 30 | 30 | ✅ |
| Base claim count | 10 | 10 | ✅ |

### 7.3 Nullifier Pattern Verification

| Chain | Nullifier Range | Format |
|------|--------------|------|
| **Base** | `0xdead0000` ~ `0xdead0009` | `0xdead` magic bytes + sequential counter |
| **ETH** | `0x174876c0f0` ~ `0x174876c10d` | Decimal 100,000,000,240 ~ 100,000,000,269 (sequential integers) |

The fact that arbitrary sequential integers — rather than legitimate `poseidon(secret, 0)` hash values — were accepted as nullifiers proves that circuit constraint verification was completely neutralized.

---

## References

- [FOOMCASH Loses $2.26M in Copycat zkSNARK Exploit — CryptoTimes](https://www.cryptotimes.io/2026/02/26/foomcash-loses-2-26m-in-copycat-zksnark-exploit/)
- [Front-running the Exploiter: $1.84M Foomcash White-Hat Rescue — DEV Community](https://dev.to/cryip/front-running-the-exploiter-a-technical-breakdown-of-the-184m-foomcash-white-hat-rescue-14bl)
- [The Unfinished Proof — Rekt News](https://rekt.news/the-unfinished-proof)
- [Month in Review: Top DeFi Hacks of February 2026 — Halborn](https://www.halborn.com/blog/post/month-in-review-top-defi-hacks-of-february-2026)
- [Newsletter February 2026 — BlockSec Blog](https://blocksec.com/blog/newsletter-february-2026)
- [White hat helps recover $1.8M after $2.3M Foom Cash exploit — TradingView](https://www.tradingview.com/news/cointelegraph:81d493b91094b:0-white-hat-helps-recover-1-8m-after-2-3m-foom-cash-exploit/)
- [Attack Tx (ETH)](https://etherscan.io/tx/0xce20448233f5ea6b6d7209cc40b4dc27b65e07728f2cbbfeb29fc0814e275e48)
- [Attack Tx (Base)](https://basescan.org/tx/0xa88317a105155b464118431ce1073d272d8b43e87aba528a24b62075e48d929d)
- [Prior Analysis Document (Groth16 Perspective)](./2026-02-26_FoomLottery_GrothForgedProof_ETH_Base.md)