# Aztec Connect — Proof/Settlement Transaction-Count Mismatch Exploit Analysis

| Field | Details |
|-------|---------|
| **Date** | 2026-06-14 12:26:23 UTC |
| **Protocol** | Aztec Connect (deprecated zk-rollup / DeFi-bridge product, sunset March 2023; contracts immutable) |
| **Chain** | Ethereum L1 |
| **Total Loss** | **~$2.19M** (BlockSec ~$2.15M / SlowMist ~$2.19M) — ~909 ETH + ~270,000 DAI + 167 wstETH; funds reported still in attacker EOA |
| **Attacker EOA** | [0x0f18d8b4...edd17](https://etherscan.io/address/0x0f18d8b44a740272f0be4d08338d2b165b7edd17) (funded earlier via Tornado Cash) |
| **Helper / Entry Contract** | [0x06f585f7...d0fcd](https://etherscan.io/address/0x06f585f74e0da633ae813a0f23fb9900b61d0fcd) (attacker-deployed driver, called with selector `0x6f3ce701`) |
| **Vulnerable Contract** | [0xFF1F2B4A...80455](https://etherscan.io/address/0xFF1F2B4ADb9dF6FC8eAFecDcbF96A2B351680455) (Aztec Connect `RollupProcessor` V3 proxy) |
| **Attack Tx** | [0x074ec931…aeeb1](https://etherscan.io/tx/0x074ec9317d8336db37e8c348fbdd7515573ff4088239c77ab429f522509aeeb1) (Block 25315715, 2026-06-14 12:26:23 UTC) |
| **Entry Selector / Function** | `0x6f3ce701` on the helper contract → drives ~14 `processRollup()` calls into `RollupProcessor` |
| **Root Cause** | Mismatch between the transaction count committed by the ZK proof (decoded transaction slots in the L2 state root) and the count settled on L1 (`numRealTxs`); the contract never asserted `settled-tx-count == proof-verified-tx-count`, allowing settlement of transactions the proof never validated |
| **GitHub / Source** | https://github.com/AztecProtocol/aztec-connect (open source, immutable deployment) |
| **Source Verification** | Attack tx and all addresses verified on Etherscan. Note: the two hashes originally in the source list (`0x1f94d07b…` / `0x31ae2641…`) were synthetic placeholders and have been replaced by the verified on-chain tx above. |

---

## 1. Vulnerability Overview

Aztec Connect was Aztec's first-generation privacy zk-rollup and DeFi bridge, allowing users to deposit ERC-20/ETH into a shielded pool, transact privately on L2, and bridge into mainnet DeFi protocols (Lido, Element, Aave, etc.). The product was formally **deprecated and sunset in March 2023**; its on-chain contracts are immutable and were left running purely to let remaining users withdraw. There were no further audits, monitoring SLAs, or upgrade authority after sunset.

> **Scope clarification:** This incident concerns the *deprecated Aztec Connect* contracts only. It is **not** the current Aztec Network mainnet, and it is **not** the AZTEC token. The Aztec Foundation publicly confirmed zero impact on the current network and token.

On 2026-06-14, an attacker drained roughly **$2.19M** (~909 ETH, ~270,000 DAI, 167 wstETH) from the Aztec Connect `RollupProcessor` by exploiting a **transaction-count mismatch between two independently-supplied inputs**:

1. **What the ZK proof commits** — the rollup proof decodes a batch of inner transactions and folds them into the L2 Merkle state root. The proof circuit commits up to 31 of the 32 public-input transaction slots into the new data root.
2. **What L1 settlement executes** — the `RollupProcessor` settlement path only iterates and pays out a *subset* of those slots, bounded by a separately-decoded scalar, `numRealTxs`.

The contract treated these two quantities as if they were always equal, but **never asserted equality**. By crafting a deliberate boundary gap between `numRealTxs` and the number of transaction slots the proof had actually committed, the attacker forced the contract to *settle and credit deposit/withdraw transactions that the proof never validated*. In effect this minted unbacked L2 balances and then withdrew them to L1.

The exploit was executed as approximately **14 `processRollup()` calls inside a single atomic transaction**, following a clean **two-phase "7 mints then 7 withdrawals"** pattern: the first phase manufactured unbacked credits via the count gap, and the second phase converted those credits into real on-chain assets (ETH, DAI, wstETH) drawn from the rollup's reserve.

This is a textbook **input-validation / data-authenticity** failure (CWE-20, CWE-345): the proof system was sound in isolation, but a non-cryptographic scalar (`numRealTxs`) supplied alongside the proof was trusted without being cross-checked against the value the proof itself had committed.

---

## 2. Vulnerable Code Analysis

Aztec Connect is open source (`github.com/AztecProtocol/aztec-connect`, `src/core/processors/RollupProcessor.sol`). The settlement entry point is `processRollup(bytes encodedProofData, bytes signatures)`. The rollup header and proof public inputs are decoded from `encodedProofData` in assembly inside the `Decoder` library; the verifier is then invoked over those public inputs. The relevant logic is the gap between (a) the transaction count the verifier commits and (b) the `numRealTxs`/`numTxs` scalar that drives the L1 settlement loop.

### 2.1 `processRollup()` / `Decoder` — Missing Count Cross-Check (❌ vulnerable)

The contract decodes `rollupSize` and a per-rollup `numRealTxs` from the calldata header, verifies the SNARK over the public inputs (which includes the new data root committing the decoded tx slots), and then loops settlement over `numRealTxs` *without ever asserting that this count matches the number of slots the proof committed*.

```solidity
// core/processors/RollupProcessor.sol  (decoded behaviour, annotated)
// NOTE: Aztec uses heavy assembly in the Decoder library; the Solidity
// shown here is a faithful behavioural reconstruction of the decode +
// settle path, with the missing invariant highlighted.

function processRollup(bytes calldata encodedProofData, bytes calldata signatures)
    external
    whenNotPaused
{
    // (1) Decode the rollup header from calldata.
    //     rollupSize  = circuit-fixed batch size (e.g. 32 tx slots)
    //     numRealTxs  = attacker-influenceable scalar in the header that
    //                   the L1 settlement loop will iterate over.
    (bytes32 oldDataRoot,
     bytes32 newDataRoot,
     uint256 rollupSize,
     uint256 numRealTxs) = decodeHeader(encodedProofData);

    require(oldDataRoot == dataRoot, "INCORRECT_DATA_ROOT");

    // (2) Verify the SNARK over the public inputs. The proof commits the
    //     DECODED transaction slots into newDataRoot. Up to 31 of 32 slots
    //     can be committed here. The verifier is sound about WHAT it proves.
    require(verifier.verify(encodedProofData), "PROOF_VERIFICATION_FAILED");

    // ❌ CRITICAL OMISSION:
    //    There is NO assertion that `numRealTxs` (the L1 settlement count)
    //    equals the number of transaction slots actually committed by the
    //    proof into newDataRoot. The proof-committed count and the
    //    settlement count are two INDEPENDENT inputs that are never reconciled.

    // (3) Settle: iterate ONLY over numRealTxs, decoding each tx slot and
    //     executing its deposit/withdraw effect against the rollup reserves.
    for (uint256 i = 0; i < numRealTxs; i++) {
        InnerTx memory txn = decodeInnerTx(encodedProofData, i);
        _settleInnerTx(txn);          // credits / debits real reserves
    }

    // (4) Commit the new state root. Because newDataRoot was authenticated
    //     by the proof, it is accepted as canonical — even though the set of
    //     slots the proof committed differs from the set L1 just settled.
    dataRoot = newDataRoot;
    emit RollupProcessed(nextRollupId++, newDataRoot);
}
```

The decisive flaw: the proof authenticates `newDataRoot` (and therefore the committed transaction slots), while `numRealTxs` is an independent header scalar that bounds the settlement loop. Nothing forces `numRealTxs` to equal the committed slot count. An attacker can therefore commit one set of transactions into the state root while settling a *different* set on L1 — or settle slots the proof padded as "empty" but which the attacker populated with deposit/withdraw effects.

### 2.2 `_settleInnerTx()` — Unbacked Credit Path (❌ vulnerable)

Because settlement trusts the per-slot decode rather than a proof-bound count, a slot that the proof treated as outside its committed range can still be settled as a real deposit/credit:

```solidity
function _settleInnerTx(InnerTx memory txn) internal {
    if (txn.proofId == DEPOSIT) {
        // ❌ Credits an L2 note / balance even though the count gap means
        //    this slot was NOT validated by the proof's committed range.
        userPendingDeposits[txn.assetId][txn.owner] += txn.amount;
    } else if (txn.proofId == WITHDRAW) {
        // Pays real reserves out to L1 for a (now unbacked) credit.
        _transferOut(txn.assetId, txn.owner, txn.amount);
    }
    // ... defi-bridge / send branches omitted
}
```

### 2.3 Fixed Code (✅)

The fix binds the settlement count to the proof. The number of transactions settled on L1 must be exactly the number of transactions the proof committed; this count must itself be a **public input of the SNARK**, not a free-floating header scalar.

```solidity
function processRollup(bytes calldata encodedProofData, bytes calldata signatures)
    external
    whenNotPaused
{
    (bytes32 oldDataRoot,
     bytes32 newDataRoot,
     uint256 rollupSize,
     uint256 numRealTxs,
     uint256 provenTxCount) = decodeHeader(encodedProofData); // ✅ provenTxCount is a PUBLIC INPUT

    require(oldDataRoot == dataRoot, "INCORRECT_DATA_ROOT");
    require(verifier.verify(encodedProofData), "PROOF_VERIFICATION_FAILED");

    // ✅ [PATCH 1] The settlement count MUST equal the proof-committed count.
    require(numRealTxs == provenTxCount, "TX_COUNT_MISMATCH");

    // ✅ [PATCH 2] And it must not exceed the circuit's fixed batch size.
    require(numRealTxs <= rollupSize, "TX_COUNT_OVERFLOW");

    for (uint256 i = 0; i < numRealTxs; i++) {
        InnerTx memory txn = decodeInnerTx(encodedProofData, i);
        // ✅ [PATCH 3] Every settled slot must lie inside the proof-committed range.
        require(i < provenTxCount, "SLOT_NOT_PROVEN");
        _settleInnerTx(txn);
    }

    dataRoot = newDataRoot;
    emit RollupProcessed(nextRollupId++, newDataRoot);
}
```

> **Note:** Because the deployed Aztec Connect contracts are immutable post-sunset, the patch above is illustrative of what a maintained deployment would require. No fix can be applied to the on-chain contract; mitigation is limited to off-chain user withdrawal and monitoring.

---

## 3. Attack Flow

### 3.1 Preparation

- The attacker EOA `0x0f18d8b4...edd17` was **funded earlier via Tornado Cash**, severing the trail to any funding exchange — a standard pre-attack laundering step.
- The attacker studied the **immutable, unmonitored** Aztec Connect contracts. Because the product was sunset in March 2023, there was no active security team, no upgrade authority, and no real-time alerting — an ideal target for a deliberate, patient exploit.
- The attacker deployed a **helper/driver contract** at `0x06f585f7...d0fcd`. Its single entry selector `0x6f3ce701` orchestrates the entire multi-call sequence atomically, so the two-phase mint/withdraw cannot be interrupted or front-run.
- The attacker crafted rollup proof payloads exploiting the **boundary gap between `numRealTxs` and the proof-committed transaction-slot count** (up to 31 of the 32 public-input slots can be committed without L1 settlement validation).

### 3.2 Execution

**[Step 1] Enter via helper selector `0x6f3ce701`**
The attacker calls the helper contract; it begins driving `processRollup()` calls into the `RollupProcessor` proxy `0xFF1F2B4A...80455` within a single atomic transaction.

**[Step 2] Phase A — 7 "mint" rollups (manufacture unbacked credits)**
For each of ~7 `processRollup()` calls, the attacker supplies a valid SNARK whose committed `newDataRoot` covers one set of slots, while the header `numRealTxs` causes L1 settlement to credit *deposit* effects on slots the proof never validated. Because no `numRealTxs == provenTxCount` assertion exists, each call **mints unbacked L2 balances** into attacker-controlled notes.

**[Step 3] Phase B — 7 "withdraw" rollups (drain reserves)**
For each of the subsequent ~7 `processRollup()` calls, the attacker settles *withdraw* transactions against the freshly minted (unbacked) credits, causing the `RollupProcessor` to `_transferOut` real reserve assets to L1 — **~909 ETH + ~270,000 DAI + 167 wstETH**.

**[Step 4] Funds retained**
Per BlockSec and SlowMist, the drained assets were reported as **still sitting in the attacker EOA** at time of reporting (no immediate DEX laundering observed for the principal).

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Tornado Cash                                               │
│  (Anonymous funding)  →  Attacker EOA 0x0f18d8b4…edd17       │
└──────────────────────────────────┬──────────────────────────┘
                                   │ deploy + drive
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Helper / driver contract  0x06f585f7…d0fcd                 │
│  entry selector 0x6f3ce701  →  atomic multi-call             │
└──────────────────────────────────┬──────────────────────────┘
                                   │ ~14 × processRollup()
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Aztec Connect RollupProcessor (V3 proxy) 0xFF1F2B4A…80455  │
│                                                             │
│  PHASE A — 7 "mint" rollups                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ verify(proof) ✓  → commits newDataRoot (slots ≤ 31)    │  │
│  │ ❌ numRealTxs ≠ proven slot count (NEVER ASSERTED)     │  │
│  │ settle loop credits DEPOSITs on UNPROVEN slots         │  │
│  │ → unbacked L2 balances minted                          │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  PHASE B — 7 "withdraw" rollups                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ settle WITHDRAW against unbacked credits               │  │
│  │ _transferOut → real reserves leave the rollup          │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────────────┬──────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Attacker EOA 0x0f18d8b4…edd17                              │
│  ~909 ETH + ~270,000 DAI + 167 wstETH  ≈ $2.19M            │
│  (reported still held in EOA)                               │
└─────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Asset | Amount | Approx. USD | Notes |
|-------|--------|-------------|-------|
| ETH | ~909 | ~$1.8M | Drained from rollup reserves |
| DAI | ~270,000 | ~$0.27M | Stablecoin reserve |
| wstETH | 167 | ~$0.12M+ | Lido-bridged reserve |
| **Total** | — | **~$2.15M – $2.19M** | BlockSec ~$2.15M / SlowMist ~$2.19M; funds reported still in attacker EOA |

---

## 4. Vulnerability Classification

### 4.1 Classification Table

| ID | Vulnerability | Severity | CWE | Category | Similar Incidents |
|----|---------------|----------|-----|----------|-------------------|
| V-01 | Settlement transaction count not bound to proof-committed count | CRITICAL | CWE-20 | bridge-crosschain, accounting-sync | Nomad Bridge, Verus Bridge |
| V-02 | Proof authenticity conflated with settlement completeness | CRITICAL | CWE-345 | accounting-sync, business-logic | Hyperbridge, Verus Bridge |
| V-03 | Boundary/off-by-N gap between decoded slots and `numRealTxs` | HIGH | CWE-129 | logic-error | — |
| V-04 | Immutable, unmonitored deprecated contract left funded | MEDIUM | CWE-1059 | operational | Multiple sunset-protocol drains |

### 4.2 V-01 — Settlement Count Not Bound to Proof-Committed Count

- **Description:** The L1 settlement loop iterates over `numRealTxs`, a header scalar decoded independently of the proof. The SNARK commits the decoded transaction slots into `newDataRoot`, but the contract never asserts `numRealTxs == provenTxCount`. The two inputs are reconciled nowhere.
- **Impact:** The attacker settles deposit/withdraw effects on transaction slots the proof never validated, minting unbacked balances and withdrawing real reserves. Full reserve exposure (~$2.19M drained).
- **Attack Preconditions:** Ability to construct a valid rollup proof payload (the circuits are public) and call `processRollup()`. No privileged role required.

### 4.3 V-02 — Proof Authenticity Conflated with Settlement Completeness

- **Description:** The design assumed "valid SNARK ⇒ the settled transaction set is exactly the proven set." A SNARK proves a statement about *its* committed inputs; it says nothing about a separate scalar that drives the L1 loop. Authenticity and completeness are distinct properties requiring independent enforcement.
- **Impact:** The entire trust model collapses: a sound proof system is rendered economically meaningless because the value moved on L1 is decoupled from what was proven.
- **Attack Preconditions:** Same as V-01.

### 4.4 V-03 — Boundary Gap Between Decoded Slots and `numRealTxs`

- **Description:** Up to 31 of 32 public-input transaction slots can be committed without L1 settlement validation. The off-by-N relationship between "slots the proof committed" and "slots the loop settles" is the concrete primitive the attacker tuned to create unbacked credits.
- **Impact:** Enables precise, repeatable mint/withdraw cycles — here, a deterministic "7 mints then 7 withdrawals" pattern inside one atomic transaction.
- **Attack Preconditions:** Knowledge of the calldata header layout and circuit slot semantics (public).

### 4.5 V-04 — Immutable, Unmonitored Deprecated Contract

- **Description:** Post-sunset (March 2023), the contracts were immutable, unaudited going forward, and unmonitored, yet still held user reserves. There was no upgrade path to patch a discovered bug and no alerting to interrupt the drain.
- **Impact:** Even though only ~$2.19M remained, the absence of any defensive response surface guaranteed full extraction of whatever remained.
- **Attack Preconditions:** A funded, deprecated contract with no active maintainers.

---

## 5. Comparison with Similar Incidents

| Incident | Date | Loss | Flaw Type | Difference from Aztec Connect |
|----------|------|------|-----------|-------------------------------|
| **Nomad Bridge** | 2022-08 | ~$190M | `acceptableRoot[0] = true` → every message auto-valid | Verification *entirely absent* vs. Aztec: proof is genuine but settlement count is unbound |
| **Verus Bridge** | 2026-05 | ~$11.58M | Source-deposit total never compared to payout total | Both are **economic-consistency gaps next to a valid proof/signature**; Verus omits an amount check, Aztec omits a count check |
| **Hyperbridge** | 2026-04 | ~$2.5M | Forged MMR proof accepted → fake mint | Hyperbridge **forges the proof**; Aztec uses a **genuine proof** but decouples settlement from it |
| **Aztec Connect** | 2026-06 | ~$2.19M | Settlement tx-count not bound to proof-committed count | Proof is fully valid; the gap is a non-cryptographic scalar (`numRealTxs`) trusted without cross-check |

The defining trait Aztec Connect shares with Verus Bridge is that **no cryptographic primitive was broken**. The SNARK verified correctly; the failure was that a number controlling *how much* gets settled on L1 was never tied back to *what* the proof actually committed. Where Verus omits a value comparison, Aztec omits a count comparison — the same class of "valid proof, unvalidated economic content" flaw.

---

## 6. Remediation Recommendations

### 6.1 Immediate Fix — Bind Settlement Count to the Proof

```solidity
// ✅ provenTxCount must be a PUBLIC INPUT of the SNARK, committed alongside newDataRoot.
require(numRealTxs == provenTxCount, "TX_COUNT_MISMATCH");
require(numRealTxs <= rollupSize, "TX_COUNT_OVERFLOW");

for (uint256 i = 0; i < numRealTxs; i++) {
    require(i < provenTxCount, "SLOT_NOT_PROVEN");   // ✅ every settled slot is proven
    _settleInnerTx(decodeInnerTx(encodedProofData, i));
}
```

### 6.2 Make the Transaction Count a Proof Public Input

The root issue is that `numRealTxs` lives in the calldata header, outside the proof. The circuit must expose the number of real (non-padding) transactions as a public input so the verifier itself authenticates it:

```solidity
// Pseudocode for the verifier interface
struct PublicInputs {
    bytes32 oldDataRoot;
    bytes32 newDataRoot;
    uint256 provenTxCount;   // ✅ committed by the circuit, not the caller
}
// settlement loop bound = publicInputs.provenTxCount
```

### 6.3 Structural Improvements

| Weakness | Recommended Fix |
|----------|-----------------|
| Settlement count is a free header scalar | Move it into the SNARK public inputs (`provenTxCount`) |
| Empty/padding slots can be settled | Require every settled slot index `< provenTxCount` |
| Unbacked credits possible mid-batch | Enforce a per-batch reserve-conservation invariant: `Σ deposits − Σ withdrawals` must reconcile against actual token deltas |
| No circuit breaker | Add per-asset / per-block withdrawal caps to bound damage from any settlement bug |
| Deprecated contract left funded & unmonitored | For sunset products, escrow residual reserves behind a timelocked withdrawal queue and keep watchtower alerting active |

---

## 7. Lessons Learned

1. **A valid proof is not a valid settlement.** A SNARK authenticates only the statement over its committed public inputs. Any scalar that controls how much value moves on L1 must itself be a public input — never a free-floating calldata field trusted by convention.
2. **Two independently-supplied inputs that "should" match must be asserted to match.** The entire exploit is the absence of one `require(numRealTxs == provenTxCount)`. Wherever two sources describe the same quantity (proof-committed count vs. settlement count), reconcile them explicitly.
3. **Padding/boundary slots are an attack surface.** Allowing up to 31 of 32 slots to be committed without settlement validation created an off-by-N primitive. Fixed-size batch circuits must constrain the real-vs-padding boundary inside the proof.
4. **Deprecated does not mean safe.** Immutable, unmonitored contracts that still custody funds are high-value, low-defense targets. Sunsetting a product does not remove its attack surface; it removes its defenders.
5. **Reserve-conservation invariants are the last line of defense.** A per-batch check that settled deposits/withdrawals reconcile against real token balance deltas would have reverted the unbacked mint phase regardless of the count gap.
6. **Scope your incident comms precisely.** The Aztec Foundation's prompt clarification that the current network and AZTEC token were unaffected limited contagion and panic — a model for handling exploits of deprecated infrastructure.

---

## 8. On-Chain Verification

### 8.1 Transaction Hash — Verified

| Field | Value |
|-------|-------|
| **Attack tx** | [0x074ec931…aeeb1](https://etherscan.io/tx/0x074ec9317d8336db37e8c348fbdd7515573ff4088239c77ab429f522509aeeb1) |
| **Block** | 25315715 (2026-06-14 12:26:23 UTC) |
| **From** | Attacker EOA [0x0f18d8b4…edd17](https://etherscan.io/address/0x0f18d8b44a740272f0be4d08338d2b165b7edd17) (Etherscan-labeled "Aztec Exploiter 1", CertiK tag) |
| **To** | Helper contract [0x06f585f7…d0fcd](https://etherscan.io/address/0x06f585f74e0da633ae813a0f23fb9900b61d0fcd) (deployed by attacker EOA ~1 day prior) |
| **Execution** | Single atomic tx — ~14 batched `processRollup()` calls; rollup IDs 13277–13290 |
| **Vulnerable proxy** | [0xFF1F2B4A…80455](https://etherscan.io/address/0xFF1F2B4ADb9dF6FC8eAFecDcbF96A2B351680455) labeled "Aztec: Connect" (TransparentUpgradeableProxy, EIP-1967) |
| **Implementation** | `0x7d657Ddc…08AdC2728` (`RollupProcessor` implementation) |

> The two hashes originally listed in the source list (`0x1f94d07b469446bd01f7823b1853d9e4860b094326db97fcdb6e22fbcf4319fb` and `0x31ae2641a9437ffb1e60054a3a35abcf155725ef11e64903ffb6e15d86ca39cb`) were **synthetic placeholders** and have been replaced by the above verified on-chain transaction.

### 8.2 Verified Address Data

| Field | Value |
|-------|-------|
| Attacker EOA | [0x0f18d8b44a740272f0be4d08338d2b165b7edd17](https://etherscan.io/address/0x0f18d8b44a740272f0be4d08338d2b165b7edd17) (Tornado-funded) |
| Helper / driver contract | [0x06f585f74e0da633ae813a0f23fb9900b61d0fcd](https://etherscan.io/address/0x06f585f74e0da633ae813a0f23fb9900b61d0fcd) (entry selector `0x6f3ce701`) |
| Vulnerable contract | [0xFF1F2B4ADb9dF6FC8eAFecDcbF96A2B351680455](https://etherscan.io/address/0xFF1F2B4ADb9dF6FC8eAFecDcbF96A2B351680455) (Aztec Connect `RollupProcessor` V3 proxy) |
| Entry selector | `0x6f3ce701` (helper) → ~14 × `processRollup()` |

### 8.3 Asset Movements — Verified Token Breakdown

| Token | From | To | Amount (verified) | Approx. USD |
|-------|------|----|-------------------|-------------|
| ETH | RollupProcessor (0xFF1F2B4A…) | Attacker (0x0f18d8b4…) | 908.99 | ~$1.8M |
| DAI | RollupProcessor (0xFF1F2B4A…) | Attacker (0x0f18d8b4…) | 270,513.05 | ~$0.27M |
| wstETH | RollupProcessor (0xFF1F2B4A…) | Attacker (0x0f18d8b4…) | 167.89 | ~$0.12M+ |
| yvDAI | RollupProcessor (0xFF1F2B4A…) | Attacker (0x0f18d8b4…) | 4,873.86 | — |
| yvWETH | RollupProcessor (0xFF1F2B4A…) | Attacker (0x0f18d8b4…) | 16.57 | — |
| LUSD | RollupProcessor (0xFF1F2B4A…) | Attacker (0x0f18d8b4…) | 9,273.73 | — |
| yvLUSD | RollupProcessor (0xFF1F2B4A…) | Attacker (0x0f18d8b4…) | 359.05 | — |
| **Total** | — | — | — | **≈ $2.19M** |

### 8.4 Notes on Reconciliation

- BlockSec reported total loss ~$2.15M; SlowMist reported ~$2.19M. The spread reflects price snapshots and wstETH/ETH valuation, not a disagreement on the asset set.
- Funds were reported **still held in the attacker EOA** at the time of public reporting — no immediate laundering of the principal was observed.
- The execution shape (~14 batched `processRollup()` calls, rollup IDs 13277–13290, in a "7 mints then 7 withdrawals" two-phase pattern) is confirmed by the verified on-chain transaction (Block 25315715), consistent with the count-mismatch root cause.

---

## 9. References

- [Aztec Foundation statement (X / @aztecnetwork)](https://x.com/aztecnetwork/status/2066175938887619055)
- [crypto.news — "Aztec Connect loses $2.1M after old contract exploit"](https://crypto.news/aztec-connect-loses-2-1m-after-old-contract-exploit/)
- [NewsBTC — "Deprecated Aztec Connect contract exploited for $2.19M, SlowMist says"](https://www.newsbtc.com/news/deprecated-aztec-connect-contract-exploited-for-219m-slowmist-says/)
- [SlowMist — "Root Cause of $2.19M Aztec Connect Exploit" (via CryptoTimes)](https://www.cryptotimes.io/2026/06/15/slowmist-details-root-cause-of-2-19m-aztec-connect-exploit/)
- [dev.to/cryip — "How a single validation mismatch can drain millions: lessons from the Aztec Connect exploit"](https://dev.to/cryip/how-a-single-validation-mismatch-can-drain-millions-lessons-from-the-aztec-connect-exploit-2598)
- [Aztec Connect contracts (GitHub)](https://github.com/AztecProtocol/aztec-connect)
- [Attacker EOA (Etherscan)](https://etherscan.io/address/0x0f18d8b44a740272f0be4d08338d2b165b7edd17)
- [Helper contract (Etherscan)](https://etherscan.io/address/0x06f585f74e0da633ae813a0f23fb9900b61d0fcd)
- [RollupProcessor V3 proxy (Etherscan)](https://etherscan.io/address/0xFF1F2B4ADb9dF6FC8eAFecDcbF96A2B351680455)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)
- Related: [Verus Bridge (2026)](../2026/2026-05-18_VerusBridge_SourceAmountValidationBypass_ETH.md), [Nomad Bridge (2022)](../2022/2022-08-01_NomadBridge_MessageVerification.md), [Hyperbridge (2026)](./2026-04-13_Hyperbridge_TokenGateway_ForgedProof_FakeMint_ETH.md)
