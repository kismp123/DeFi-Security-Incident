# Low-Carb-Crusader — Business Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-03 (UTC; attack preparation began 04-02) |
| **Project** | Low-Carb-Crusader (MEV-Boost Relay Exploit) |
| **Chain** | Ethereum |
| **Loss** | ~$25,000,000 (stolen from 5 sandwich MEV bots) |
| **Attacker** | [0x3c98d617db017f51c6a73a13e80e1fe14cd1d8eb](https://etherscan.io/address/0x3c98d617db017f51c6a73a13e80e1fe14cd1d8eb) |
| **Attack Contract** | [0xe73f1576af5573714404a2e3181f7336d3d978f9](https://etherscan.io/address/0xe73f1576af5573714404a2e3181f7336d3d978f9) |
| **Attack Tx (example)** | [0x4b2a2d03b3dc136ef94ebe2f3bc36231b104172bcb598104730898f7d81a55db](https://etherscan.io/tx/0x4b2a2d03b3dc136ef94ebe2f3bc36231b104172bcb598104730898f7d81a55db) |
| **Attack Block** | 16,964,664 |
| **Root Cause** | Business logic flaw in MEV-Boost relay — block body (bundle) exposed to proposer even when block header signature is invalid |
| **References** | [Flashbots Post-Mortem](https://collective.flashbots.net/t/post-mortem-april-3rd-2023-mev-boost-relay-incident-and-related-timing-issue/1540) · [BlockSec Analysis](https://blocksec.com/blog/harvesting-mev-bots-by-exploiting-vulnerabilities-in-flashbots-relay) |

---

## 1. Vulnerability Overview

### Background: PBS (Proposer-Builder Separation) and MEV-Boost

After Ethereum's transition to PoS, most validators propose blocks via MEV-Boost. Roles in this system are separated as follows:

- **Builder**: Collects and orders transactions to construct a maximum-extractable-value block
- **Relay**: Acts as an intermediary between builder and proposer — reveals only the block header first, then discloses the block body once the proposer submits a signed header
- **Proposer (Validator)**: Requests a block header from the relay, signs it, and finalizes the block

The core of the trust model rests on the premise that **"the relay will not expose the block body (transaction list) until the proposer submits a valid signature."** That premise was broken.

### Core Vulnerability

The Flashbots MEV-Boost relay had a flaw where it returned the block body **even when the block header submitted by the proposer was invalid**. The attacker exploited this by:

1. Submitting a **forged signed header** to the relay with `state_root` and `parent_root` intentionally set to `0x00...0`
2. After the relay attempted — and failed — to propagate the block to the beacon chain, it still **returned the block body (the sandwich bot's private bundle) to the proposer**
3. Using the exposed bundle contents to backrun the MEV bot's attack

This is not a smart contract vulnerability — it is a **business logic error in off-chain relay software**.

---

## 2. Vulnerable Code Analysis

### 2.1 Relay Block Body Disclosure Logic (Core Vulnerability)

```go
// ❌ Vulnerable logic — mev-boost-relay GetPayload handler (pseudocode)
func (r *Relay) GetPayload(signedBlindedBlock *SignedBlindedBeaconBlock) (*ExecutionPayload, error) {
    header := signedBlindedBlock.Message.Body.ExecutionPayloadHeader

    // Signature validation
    if err := r.verifySignature(signedBlindedBlock); err != nil {
        return nil, err
    }

    // Attempt to publish block to beacon chain
    err := r.publishBlock(signedBlindedBlock)
    // ❌ Execution continues regardless of error (invalid block)
    //    err is not checked — payload is returned unconditionally

    payload, exists := r.blockStore.Get(header.BlockHash)
    if !exists {
        return nil, ErrMissingPayload
    }

    return payload, nil  // ❌ Block body exposed even on publish failure!
}
```

**Problem**: Even when `publishBlock()` returns an error (i.e., the block is rejected by the beacon node as invalid), the relay still returns the `ExecutionPayload` (the full transaction list) to the proposer. The attacker extracts the sandwich bot's private bundle from this return value.

```go
// ✅ Fixed logic
func (r *Relay) GetPayload(signedBlindedBlock *SignedBlindedBeaconBlock) (*ExecutionPayload, error) {
    header := signedBlindedBlock.Message.Body.ExecutionPayloadHeader

    if err := r.verifySignature(signedBlindedBlock); err != nil {
        return nil, err
    }

    // ✅ Return payload only if block publication succeeds
    if err := r.publishBlock(signedBlindedBlock); err != nil {
        // Do not return payload on publish failure — prevents bundle exposure
        return nil, fmt.Errorf("block publication failed, payload withheld: %w", err)
    }

    payload, exists := r.blockStore.Get(header.BlockHash)
    if !exists {
        return nil, ErrMissingPayload
    }

    return payload, nil
}
```

### 2.2 Missing Invalid Header Detection

```go
// ❌ Vulnerable header validation — state_root / parent_root values not checked
func (r *Relay) verifySignature(block *SignedBlindedBeaconBlock) error {
    // Only checks the mathematical validity of the BLS signature itself
    pubkey := r.knownValidators[block.Message.ProposerIndex]
    if !bls.Verify(pubkey, block.Message, block.Signature) {
        return ErrInvalidSignature
    }
    // ❌ Does not detect state_root == 0x00...0 or parent_root == 0x00...0
    return nil
}

// ✅ Fixed header validation
func (r *Relay) verifySignature(block *SignedBlindedBeaconBlock) error {
    pubkey := r.knownValidators[block.Message.ProposerIndex]
    if !bls.Verify(pubkey, block.Message, block.Signature) {
        return ErrInvalidSignature
    }
    // ✅ Additional integrity check on header fields
    header := block.Message.Body.ExecutionPayloadHeader
    if header.StateRoot == (common.Hash{}) || header.ParentHash == (common.Hash{}) {
        return ErrInvalidBlockHeader  // Detects tampered header
    }
    return nil
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker registered 1 Ethereum validator on March 16, 2023 (staking 32 ETH)
- Attack funds were laundered through Aztec Protocol (a privacy layer) to obscure the source
- Deployed attack contract (`0xe73f...`): equipped with honeypot transaction sending + backrun functionality
- Pre-selected target pools (WETH-STG and other ultra-low-liquidity V2 pools)

### 3.2 Execution Phase

```
Step 1: Send honeypot transaction
  Attacker EOA ──[small WETH→STG swap, ultra-low-liquidity V2 pool]──▶ public mempool

Step 2: Lure MEV sandwich bot
  Sandwich bot ──[constructs front-run bundle: large STG buy + victim Tx + backrun]──▶ builder0x69 (builder)

Step 3: Builder submits block to relay
  builder0x69 ──[block body + header]──▶ ultra sound relay

Step 4: Attacker calls relay with tampered header (GetPayload)
  Attacker validator ──[state_root=0x00, parent_root=0x00 header + valid BLS signature]──▶ relay

Step 5: Relay's business logic flaw triggers
  Relay: attempts block publication → beacon node rejects (invalid header)
         ↓ (error ignored)
  Relay ──[returns full block body]──▶ attacker validator
         ※ Sandwich bot's private bundle exposed!

Step 6: Construct and propose backrun block
  Attacker: inspects exposed bundle, identifies MEV bot's buy transactions
           → reconstructs own block: [bot front-run Tx] + [attacker backrun Tx (absorbs bot assets)]
  Attacker validator ──[crafted block]──▶ beacon network direct propagation (slot 6137846)

Step 7: Profit
  Attacker backrun Tx: seizes entire 2,454 WETH purchased by MEV bot
  ─ Victim MEV bot: 2,454 WETH (~$4.5M) lost (single instance)
  ─ Combined losses from 5 bots: ~$25,000,000
```

### 3.3 Attack Flow ASCII Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Low-Carb-Crusader MEV-Boost Relay Exploit               │
└─────────────────────────────────────────────────────────────────────────────┘

  [Attacker]                  [Public Mempool]       [Sandwich MEV Bot]
     │                            │                        │
     │  ① Send honeypot Tx        │                        │
     │  (0.04 WETH→STG,           │                        │
     │   ultra-low-liq V2 pool)   │                        │
     │──────────────────────────▶│                        │
     │                            │  ② Detect honeypot     │
     │                            │     & build bundle     │
     │                            │◀──────────────────────│
     │                            │                        │
     │                    [builder0x69 (Builder)]          │
     │                            │  ③ Submit sandwich     │
     │                            │     bundle             │
     │                            │◀──────────────────────│
     │                            │
     │                    [ultra sound relay]
     │                            │
     │  ④ GetPayload request      │
     │  (state_root=0x00,          │
     │   parent_root=0x00)        │
     │──────────────────────────▶│
     │                            │  ④-A Attempt block publication
     │                            │──────────────────────▶[Beacon Chain]
     │                            │                        │
     │                            │◀──── ❌ Rejected (invalid header) ─┤
     │                            │
     │                            │  ⑤ ❌ Business logic flaw:
     │                            │     error ignored → block body returned
     │◀──────────── block body ───│
     │  (sandwich bot bundle      │
     │   contents exposed)        │
     │
     │  ⑥ Reconstruct backrun block
     │  [bot front-run Tx]
     │  + [attacker backrun: absorbs bot's WETH]
     │
     │──────────────────────────────────────────▶[Beacon Network Direct Propagation]
     │                                           (slot 6137846 finalized)
     │
     │  ⑦ Profit: ~$25M WETH/tokens seized
     │◀─────────────────────────────────────────────────────────────────────
     │
  [Attacker Wallet]
```

### 3.4 Outcome

| Field | Details |
|------|------|
| Attacker Profit | ~$25,000,000 (WETH and other tokens) |
| Victims | 5 sandwich MEV bots |
| Single Transaction Loss (example) | 2,454 WETH (~$4.5M) |
| Attack Duration | Single block (~12 seconds) |
| Legal Outcome | Brothers Anton & James Peraire-Bueno indicted (2024); jury deadlock in 2025 → mistrial |

---

## 4. PoC Code Core Logic (Reconstructed)

> Note: No official PoC for this specific incident is registered in DeFiHackLabs.
> The following is pseudocode reconstructing the attack logic based on publicly available analysis.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Honeypot + backrun contract deployed by attacker (0xe73f1576...)
// Actual address: https://etherscan.io/address/0xe73f1576af5573714404a2e3181f7336d3d978f9

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract LowCarbCrusaderAttack {
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant STG  = 0xAf5191B0De278C7286d6C7CC6ab6BB8A73bA2Cd6;

    // Step 1: Honeypot transaction — small swap on ultra-low-liquidity V2 pool
    // Lures sandwich bot into constructing a large front-run bundle
    function sendHoneypot(address v2Pool) external {
        // 0.04 WETH → STG swap (pool liquidity: 0.005 WETH / 4.5 STG)
        // From bot's perspective, V2/V3 price gap looks like ~$700 arbitrage opportunity
        IUniswapV2Pair(v2Pool).swap(
            4, // STG amount out (small)
            0,
            address(this),
            "" // simple swap — no callback
        );
    }

    // Step 2: Backrun transaction — absorbs WETH that bot purchased via front-run
    // Attacker already knows the post-buy pool state from the bundle exposed by the relay
    function backrunBot(address v2Pool, uint256 stgAmountIn) external {
        // Exploits pool state immediately after bot spent 2,454 WETH buying all STG
        // 158 STG → reclaims full 2,454 WETH
        // Attacker uses pre-held STG to absorb the overpriced WETH the bot created
        IUniswapV2Pair(v2Pool).swap(
            2454 ether, // WETH amount out — total WETH bot put in
            0,
            address(this),
            ""
        );
        // Result: attacker +2,454 WETH, MEV bot -2,454 WETH
    }

    // Self-protection logic: if no victim (bot), reverse swap to recover honeypot loss
    function reverseIfNoVictim(address v2Pool) external {
        // Protects 0.35 ETH honeypot investment
        // If bot did not front-run, reverses the original swap
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Type |
|----|--------|--------|-----|------|
| V-01 | Missing error handling — payload returned on block publication failure | CRITICAL | CWE-754 | Business Logic Flaw |
| V-02 | Missing input validation — tampered block header fields not checked | HIGH | CWE-20 | Improper Input Validation |
| V-03 | Trust model violation — block finalization not verified before payload disclosure | HIGH | CWE-284 | Access Control Error |
| V-04 | MEV bot excessive capital concentration (full assets deployed per single opportunity) | MEDIUM | CWE-400 | Economic Logic Flaw |

### V-01: Missing Error Handling (Root Cause)
- **Description**: The `GetPayload` handler returns `ExecutionPayload` regardless of whether `publishBlock()` fails. When an invalid block header (state_root=0, parent_root=0) is submitted, the relay exposes the bundle contents.
- **Impact**: Premature exposure of private transaction bundles → theft of sandwich bot assets
- **Attack Conditions**: Must hold an Ethereum validator slot + access to a MEV-Boost relay

### V-02: Missing Input Validation
- **Description**: The relay does not verify whether the `state_root` or `parent_root` fields of the block header are zero values.
- **Impact**: Relay can be manipulated with intentionally invalidated headers
- **Attack Conditions**: Must possess a valid BLS signing key (validator registration)

### V-03: Trust Model Violation
- **Description**: The relay implementation violates the core invariant of PBS design: "payload is only disclosed after block finalization on-chain."
- **Impact**: Enables a "Look-Then-Decide" attack where the proposer can inspect the block before selectively finalizing it
- **Attack Conditions**: Abusing the trust model between relay and proposer

### V-04: MEV Bot Economic Logic Flaw
- **Description**: Sandwich bots commit their entire holdings (2,454 WETH) per arbitrage opportunity. If bundle atomicity is broken, all assets are lost.
- **Impact**: Complete asset loss for a bot from a single attack
- **Attack Conditions**: Requires prior knowledge of the bot's bundle structure

---

## 6. Remediation Recommendations

### Immediate Action (Relay Software)

```go
// ✅ Fix 1: Verify publishBlock success before returning payload
func (r *Relay) GetPayload(signedBlindedBlock *SignedBlindedBeaconBlock) (*ExecutionPayload, error) {
    if err := r.verifySignature(signedBlindedBlock); err != nil {
        return nil, fmt.Errorf("signature verification failed: %w", err)
    }

    // ✅ Must confirm publication success
    if err := r.publishBlock(signedBlindedBlock); err != nil {
        r.log.Warn("block publication failed — payload withheld", "error", err)
        return nil, ErrBlockPublishFailed  // Prevents bundle exposure
    }

    payload, exists := r.blockStore.Get(
        signedBlindedBlock.Message.Body.ExecutionPayloadHeader.BlockHash,
    )
    if !exists {
        return nil, ErrMissingPayload
    }
    return payload, nil
}

// ✅ Fix 2: Add header field integrity validation
func validateBlockHeader(header *ExecutionPayloadHeader) error {
    if header.StateRoot == (common.Hash{}) {
        return errors.New("state_root is 0x00 — tampered header")
    }
    if header.ParentHash == (common.Hash{}) {
        return errors.New("parent_hash is 0x00 — tampered header")
    }
    return nil
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Missing Error Handling | Always check `publishBlock` return value; block payload return on publish failure |
| V-02 Missing Input Validation | Add header field validity checks at `GetPayload` entry point (zero values, future timestamps, etc.) |
| V-03 Trust Model Violation | Block `getPayload` requests before slot t=0; only disclose payload after beacon block finalization |
| V-04 MEV Bot Economic Model | Set per-opportunity exposure limit (e.g., 20% of holdings); include self-protection (own backrun) in bundles |
| General | Mandate independent security audits of relay implementations; publish a formal spec defining the PBS trust model |

---

## 7. Lessons Learned

1. **Off-chain infrastructure must be audited with the same rigor as smart contracts**: This incident was caused by missing error handling in Go relay software, not Solidity code. Limiting the security scope of DeFi protocols to on-chain contracts means infrastructure-layer vulnerabilities will be missed.

2. **Trust model invariants must be enforced at the implementation level**: The PBS design specification clearly stated "payload is disclosed only after block finalization," but the relay implementation failed to guarantee this. The gap between design intent and implementation led to $25M in losses.

3. **Missing error handling is a severe security vulnerability**: Just a few lines of code that continued executing after `publishBlock` failed destroyed the entire system's trust model. Every error on a critical path must be handled explicitly.

4. **Economic incentive design is directly tied to security**: MEV bots committing their entire assets to a single opportunity is a rational choice to maximize profit in a short time window, but when bundle atomicity is broken the result is catastrophic. Protocol designers must consider mechanisms that limit participant risk concentration.

5. **Privacy layers work equally well for attackers**: The attacker laundered fund origins through Aztec Protocol before executing the attack. The dual-use nature of privacy technology must be recognized, and on-chain monitoring for anomalous behavior should be strengthened.

6. **Bundle Atomicity is a foundational assumption of the MEV ecosystem**: This attack profited by artificially breaking that assumption. Relay, builder, and mempool designs must all defensively handle cases where atomicity guarantees fail.

---

## 8. On-Chain Verification

### 8.1 Attack Block Information

| Field | Value |
|------|-----|
| Attack Block Number | 16,964,664 |
| Beacon Chain Slot | 6,137,846 |
| Attack Timestamp | 2023-04-03 (UTC) |
| Relay | ultra sound relay, Flashbots relay |
| Builder | builder0x69 |

### 8.2 Key Transactions (within block 16964664)

| Tx Hash | Role | Description |
|---------|------|------|
| `0xd2edf726fd3a7f179c1a93343e5c0c6ed13417837deb6fc61601d1ce9380e8dc` | Honeypot Tx | Victim transaction detected by MEV bot |
| `0xd534c46ba5a444e886feedeb4dbe698b68be74a65356b5cc46c49f2dd07f7edf` | Attacker Honeypot | Bait planted by attacker (small WETH→STG swap) |
| `0x4b2a2d03b3dc136ef94ebe2f3bc36231b104172bcb598104730898f7d81a55db` | Backrun Tx | Attacker backrun — seizes bot's 2,454 WETH |

### 8.3 Loss Breakdown (single attack, block 16964664)

| Asset Lost | Amount | Estimated USD Value |
|----------|------|--------------|
| WETH | 2,454 ETH | ~$4,500,000 |
| Other bot losses combined | — | ~$20,500,000 |
| **Total** | — | **~$25,000,000** |

### 8.4 Relay Post-Incident Response

Flashbots deployed a patch immediately after the incident, fixing the relay to withhold the payload when `publishBlock` fails. An additional mitigation was applied to restrict `getPayload` call timing to after slot t=0.

---

**References**

- [Flashbots Official Post-Mortem (2023-04-03)](https://collective.flashbots.net/t/post-mortem-april-3rd-2023-mev-boost-relay-incident-and-related-timing-issue/1540)
- [BlockSec Analysis: Harvesting MEV Bots](https://blocksec.com/blog/harvesting-mev-bots-by-exploiting-vulnerabilities-in-flashbots-relay)
- [Halborn Incident Explanation](https://www.halborn.com/blog/post/explained-the-mev-bots-hack-april-2023)
- [EigenPhi X Thread (Block 16964664 Analysis)](https://x.com/EigenPhi/status/1642847587786194946)
- [Flashbots Transparency Report](https://collective.flashbots.net/t/flashbots-transparency-report-mev-share-relay-exploits-shapella-and-rev/1742)
- [DOJ Indictment Coverage (Unchained, 2024)](https://unchainedcrypto.com/doj-alleges-two-brothers-stole-25-million-from-mev-bots-last-year/)
- [Coindesk In-Depth Analysis](https://www.coindesk.com/tech/2024/05/16/how-2-brothers-allegedly-cheated-a-noxious-but-accepted-ethereum-practice-for-25m)