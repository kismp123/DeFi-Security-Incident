# Verus Ethereum Bridge — Cross-Chain Source Amount Validation Bypass Exploit Analysis

| Field | Details |
|-------|---------|
| **Date** | 2026-05-17 23:55:23 UTC / reported 2026-05-18 (Block 25118335) |
| **Protocol** | Verus Ethereum Bridge |
| **Chain** | Ethereum |
| **Total Loss** | **$11.58M** (tBTC $7.95M + USDC $0.15M + ETH $3.4M) |
| **Analyzed Tx Loss** | tBTC 103.56766017 + USDC 147,658.836798 ≈ **$8.1M** |
| **Separate Tx Loss** | ETH 1,625 ≈ **$3.4M** |
| **Attacker EOA** | [0x5aBb91B9...D5777](https://etherscan.io/address/0x5aBb91B9c01A5Ed3aE762d32B236595B459D5777) (Verus Exploiter 1) |
| **Profit Receiver** | [0x65Cb8b12...C25F9](https://etherscan.io/address/0x65Cb8b128bF6E690761044CCEca422bB239C25F9) (Verus Exploiter 2) |
| **Vulnerable Contract** | [0x71518580...cd7f63](https://etherscan.io/address/0x71518580f36FeCEFfE0721F06bA4703218cD7F63) (Verus: Ethereum Bridge / Delegator) |
| **Attack Tx** | [0x6990f017...b321](https://etherscan.io/tx/0x6990f01720f57fc515d0e976a0c4f8157e0a9529194c4c15d190e98d087eb321) |
| **Entry Selector** | `0x8c49b257` (`submitImports(CReserveTransferImport)`) |
| **Gas Used** | 685,456 / 751,143 (91.3%) |
| **Root Cause** | `checkCCEValues()` failed to verify that the sum of payout amounts in the import payload did not exceed the actual source-chain deposit totals (`CCE.totalAmounts[]`) |
| **GitHub** | https://github.com/VerusCoin/Verus-Ethereum-Contracts |
| **Source Verification** | Not verified on-chain (bytecode only). Analysis is based on the GitHub repository |

---

## 1. Vulnerability Overview

The Verus Ethereum Bridge is a bidirectional asset transfer bridge connecting the Verus mainchain to Ethereum. Its trust model relies on Verus notaries signing a state root via multisig, which the Ethereum contract then trusts. A user deposits assets on the Verus chain via a `CReserveTransfer` transaction; once a `CCrossChainExport (CCE)` bundle containing that transaction is submitted to Ethereum's `Delegator.submitImports()` along with notary signatures, the corresponding assets are paid out on the Ethereum side.

This incident broke the most fundamental assumption of that trust model: **"if the notary signatures are valid, the payout is legitimate."** Specifically, the Ethereum-side `checkCCEValues()` function verified only three things:

1. Payload hash integrity (`keccak256(serializedTransfers) == hashTransfers`)
2. CCE metadata format (sourceSystemID, destSystemID, height range)
3. Validity of the notary multisig signatures

However, it **never checked whether the sum of payout amounts encoded in the payload exceeded the actual amount deposited on the source chain (`CCE.totalAmounts[]`)**. The attacker deposited only ~0.02 VRSC (roughly $0.01) on the Verus chain, while encoding instructions in the payout blob to pay out tBTC 103.56 + USDC 147,658. Because the notaries only signed the fact that "this data exists in a Verus chain block," this asymmetry went undetected at the multisig stage.

This is a design-level flaw that incorrectly equates **cryptographic validity** with **economic validity**, creating a single point of failure where the entire bridge reserves could be drained in a single transaction.

---

## 2. Vulnerable Code Analysis

### 2.1 `checkCCEValues()` — Missing Source Amount Validation

`checkCCEValues()` in `SubmitImports.sol` only verified the structural integrity of the CCE payload and hash consistency. The data authenticated by the notary signatures (`hashTransfers`) is the hash of the serialized transfer array, but that hash carries no self-validating information about "how much was actually deposited on the source chain."

**Estimated vulnerable code** (❌):

```solidity
// VerusBridge/SubmitImports.sol (vulnerable version, estimated)
function checkCCEValues(
    VerusObjects.CReserveTransferImport calldata _import,
    VerusObjects.CCrossChainExport memory _cce,
    uint256 height
) internal view returns (bool) {
    // ❌ 1. Only verifies hash integrity — relies on the assumption that notary signatures authenticate H
    bytes32 hashOfTransfers = keccak256(_import.serializedTransfers);
    require(hashOfTransfers == _import.hashTransfers, "Hash mismatch");

    // ❌ 2. Only verifies CCE metadata format
    require(_cce.sourceSystemID == VerusConstants.VerusSystemId, "Wrong source");
    require(_cce.destSystemID == VerusConstants.EthSystemID, "Wrong dest");
    require(_cce.startHeight <= height && _cce.endHeight >= height, "Bad range");

    // ❌ 3. CRITICAL OMISSION:
    //    No comparison between _cce.totalAmounts[] (actual source-chain deposit)
    //    and the summed payout amounts from the blob
    return true;
}
```

The critical flaw is the absence of step 3. The CCE struct has a `totalAmounts[]` field declaring "how much, in total, the transfers bundled in this export deposited on the source chain." The function neither reads this field nor compares it against the summed payout amounts from the payload blob.

**Fixed code** (✅, ~10-line patch):

```solidity
function checkCCEValues(
    VerusObjects.CReserveTransferImport calldata _import,
    VerusObjects.CCrossChainExport memory _cce,
    uint256 height
) internal view returns (bool) {
    bytes32 hashOfTransfers = keccak256(_import.serializedTransfers);
    require(hashOfTransfers == _import.hashTransfers, "Hash mismatch");
    require(_cce.sourceSystemID == VerusConstants.VerusSystemId, "Wrong source");
    require(_cce.destSystemID == VerusConstants.EthSystemID, "Wrong dest");
    require(_cce.startHeight <= height && _cce.endHeight >= height, "Bad range");

    // ✅ [PATCH] Compare declared source-chain export totals vs summed payout blob amounts
    VerusObjects.CCurrencyValueMap[] memory payoutSums =
        VerusSerializer.sumTransfers(_import.serializedTransfers);
    require(payoutSums.length == _cce.totalAmounts.length, "Currency count mismatch");
    for (uint256 i = 0; i < payoutSums.length; i++) {
        require(payoutSums[i].currency == _cce.totalAmounts[i].currency, "Currency mismatch");
        // ✅ Payout cannot exceed the amount declared in the export
        require(payoutSums[i].amount <= _cce.totalAmounts[i].amount, "Payout exceeds source");
    }
    return true;
}
```

### 2.2 `_createImports()` — Actual Source Code & Vulnerability Annotation

`Delegator.submitImports()` delegates execution to `SubmitImports._createImports()` via `delegatecall`.

> **Note on section 2.1**: The `checkCCEValues()` function shown above is a reconstructed representation of the missing validation logic. The actual on-chain contract (GitHub: `contracts/VerusBridge/SubmitImports.sol`) does not contain a `checkCCEValues()` call. Instead, `_createImports()` calls `proveImports()` for signature/proof verification and `processTransactions()` for payout execution — with no economic validation between them. The reconstructed code in 2.1 illustrates what *should* exist but is absent.

**Actual `_createImports()` source code** (VerusBridge/SubmitImports.sol):

```solidity
function _createImports(bytes calldata data) external returns(uint64, uint176) {

    uint256 gasleftStart = gasleft();
    VerusObjects.CReserveTransferImport memory _import = abi.decode(data, (VerusObjects.CReserveTransferImport));
    bytes32 txidfound;
    bytes memory elVchObj = _import.partialtransactionproof.components[0].elVchObj;
    uint32 nVins;

    assembly {
        txidfound := mload(add(elVchObj, ELVCHOBJ_TXID_OFFSET))
        nVins     := mload(add(elVchObj, ELVCHOBJ_NVINS_OFFSET))
    }

    // ✅ Replay protection: reject already-processed txids
    if (processedTxids[txidfound]) {
        revert();
    }

    bool success;
    bytes memory returnBytes;

    // reverse 32-bit endianness
    nVins = ((nVins & 0xFF00FF00) >> 8) | ((nVins & 0x00FF00FF) << 8);
    nVins = (nVins >> 16) | (nVins << 16);

    bytes32 hashOfTransfers;
    uint64 fees;
    uint128 CCEHeightsAndnIndex;

    // Hash the serialized transfer blob
    hashOfTransfers = keccak256(_import.serializedTransfers);

    address verusProofAddress = contracts[uint(VerusConstants.ContractType.VerusProof)];

    // [Step A] ✅ Notary signature + MMR proof verification
    //           proveImports() checks: notary multisig, stateRoot inclusion, CCE metadata format
    //           Returns: CCEHeightsAndnIndex (height range + nIndex) and exporter address
    (success, returnBytes) = verusProofAddress.delegatecall(
        abi.encodeWithSignature("proveImports(bytes)", abi.encode(_import, hashOfTransfers))
    );
    require(success);
    uint176 exporter;
    (CCEHeightsAndnIndex, exporter) = abi.decode(returnBytes, (uint128, uint176));

    // strip flags from exporter
    exporter = exporter & 0x0fffffffffffffffffffffffffffffffffffffffffff;

    // [Step B] ✅ Sequential height ordering check (CCE must follow immediately after last import)
    isLastCCEInOrder(uint32(CCEHeightsAndnIndex));

    // Recalculate nIndex offset relative to vins
    CCEHeightsAndnIndex = (CCEHeightsAndnIndex & 0xffffffff00000000ffffffffffffffff)
        | (uint128(uint32(uint32(CCEHeightsAndnIndex >> 64) - (1 + (2 * nVins)))) << 64);

    // Mark txid as processed and record last import info
    setLastImport(txidfound, hashOfTransfers, CCEHeightsAndnIndex);

    // ❌ [MISSING STEP] No economic validation here:
    //    There is no check that sum(payout amounts in serializedTransfers)
    //    ≤ CCE.totalAmounts[] (declared source-chain deposit totals).
    //    proveImports() authenticated the DATA, not its economic soundness.

    // [Step C] ✅ Decode and execute payouts via TokenManager
    //           processTransactions() reads serializedTransfers directly
    //           and transfers tokens from bridge reserves to recipients.
    //           With no prior bound check, attacker-controlled amounts pass through.
    (success, returnBytes) = contracts[uint(VerusConstants.ContractType.TokenManager)].delegatecall(
        abi.encodeWithSelector(
            TokenManager.processTransactions.selector,
            _import.serializedTransfers,
            uint256(uint8(CCEHeightsAndnIndex >> 96))
        )
    );
    require(success);

    uint176[] memory refundAddresses;
    (returnBytes, fees, refundAddresses) = abi.decode(returnBytes, (bytes, uint64, uint176[]));

    CCEHeightsAndnIndex = (uint32(CCEHeightsAndnIndex >> 32) - uint32(CCEHeightsAndnIndex));

    calulateGasFees(gasleftStart, fees, refundAddresses, CCEHeightsAndnIndex, exporter);

    if (returnBytes.length > 0) {
        refund(returnBytes);
    }
    return (0, 0);
}
```

**Execution flow summary:**

```
submitImports(CReserveTransferImport data)
    │
    ▼
delegatecall → SubmitImports._createImports(data)
    │
    ├─ [Check]   processedTxids[txidfound] ✅ (txid-level replay guard — PASSES on first call)
    │
    ├─ [Step A]  proveImports() via delegatecall → VerusProof contract
    │            ✅ Verifies: notary multisig signatures, stateRoot MMR inclusion,
    │               CCE metadata (sourceSystemID, destSystemID, height range)
    │            ✅ Authenticates: keccak256(serializedTransfers) == hashTransfers
    │            ❌ Does NOT compare: payout amounts vs CCE.totalAmounts[]
    │
    ├─ [Step B]  isLastCCEInOrder() ✅ (height sequencing check — PASSES)
    │
    │            ══════════════════════════════════════════════════
    │            ❌ MISSING: sum(payout blob) ≤ CCE.totalAmounts[]
    │            ══════════════════════════════════════════════════
    │
    └─ [Step C]  TokenManager.processTransactions(serializedTransfers) via delegatecall
                 ❌ Executes payouts with no upper bound — attacker-specified amounts used as-is
                    → tBTC.transfer(Exploiter2, 103.56766017e8)
                    → USDC.transfer(Exploiter2, 147,658.836798e6)
```

The flaw is in the gap between Step A and Step C: `proveImports()` authenticates the *integrity* of the transfer blob (the hash matches, the signatures are genuine), but nothing bounds the *amounts* inside that blob to what was actually deposited. By the time `processTransactions()` runs, it treats the attacker-specified payout values as authoritative.

---

## 3. Attack Flow

### 3.1 Preparation

Approximately 14 hours before the attack, the attacker withdrew 1 ETH from Tornado Cash to anonymize the funding source. This ETH was consumed as gas for the `submitImports()` call on Ethereum; the Verus-side gas (~0.02 VRSC) was obtained separately.

### 3.2 Execution

**[Step 1] Verus chain — Create an export transaction with a malicious payout blob**

The attacker created a `CReserveTransfer` transaction on the Verus chain depositing only ~0.02 VRSC (market value ~$0.01). The source totals field was empty or negligibly small, but the payout blob encoded instructions to pay tBTC 103.56766017 and USDC 147,658.836798 to the Exploiter 2 address. The keccak256 hash of this payout blob was committed into the Verus state root.

**[Step 2] Verus notaries — Multisig-sign the state root**

The Verus notaries multisig-signed the state root for the relevant block. Their responsibility is to certify that "this hash exists within a Verus block." **The protocol defined no independent procedure for notaries to verify whether source deposit amounts match payout amounts.**

**[Step 3] Ethereum — Call `submitImports()`, pass signature verification**

The attacker called `Delegator.submitImports()`:
- data → `abi.encode` → `delegatecall` → `_createImports()`
- Notary signature verification: PASS (signatures are genuine)
- `checkCCEValues()`: PASS (source amount vs payout comparison absent)
- Blob decoded → fund transfer executed

**[Step 4] Bridge Reserves → Verus Exploiter 2**
- tBTC 103.56766017 → 0x65Cb8b128bF6E690761044CCEca422bB239C25F9
- USDC 147,658.836798 → 0x65Cb8b128bF6E690761044CCEca422bB239C25F9

**[Step 5] Monetization**

An additional ETH 1,625 was drained in a separate transaction. All assets were subsequently swapped on DEXes, consolidating the proceeds into approximately 5,402 ETH (~$11.4M).

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Tornado Cash                                               │
│  (Anonymous funding)                                        │
│  Withdraw 1 ETH → Verus Exploiter 1                         │
└──────────────────────────────────┬──────────────────────────┘
                                   │ T-14h (14 hours before attack)
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Verus Chain (source chain)                                 │
│                                                             │
│  Create CReserveTransfer transaction                        │
│  ├─ Actual deposit: ~0.02 VRSC ($0.01)                      │
│  ├─ source totals: empty                                    │
│  └─ payout blob: tBTC 103.56 + USDC 147,658 specified       │
│                                                             │
│  keccak256(payout_blob) → committed to state root           │
└──────────────────────────────────┬──────────────────────────┘
                                   │ state root propagation
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Verus Notaries                                             │
│                                                             │
│  Multisig-sign state root hash                              │
│  [!] No verification of source amount vs payout amount      │
│  → Only confirms "hash exists in the block"                 │
└──────────────────────────────────┬──────────────────────────┘
                                   │ signed state root
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Ethereum — Delegator.sol (0x71518580…cd7f63)              │
│                                                             │
│  submitImports(CReserveTransferImport data) called          │
│  │                                                          │
│  ├─ _createImports() [delegatecall]                         │
│  │   ├─ Notary signature verification ✓ (PASS)              │
│  │   ├─ checkCCEValues() ← [❌ VULNERABLE]                  │
│  │   │   └─ payout vs source_total comparison absent → PASS │
│  │   └─ blob decoded → payout amounts confirmed             │
│  │                                                          │
│  └─ Pay out funds from bridge Reserves                      │
│      ├─ tBTC 103.56766017 → Exploiter 2                    │
│      └─ USDC 147,658.836798 → Exploiter 2                  │
└──────────────────────────────────┬──────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Verus Exploiter 2 (0x65Cb8b12…9C25F9)                     │
│  tBTC $7.95M + USDC $0.15M + ETH $3.4M = $11.58M           │
│  → DEX swaps → consolidated into ~5,402 ETH                 │
└─────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Asset | Amount | Market Value | Notes |
|-------|--------|-------------|-------|
| tBTC | 103.56766017 | $7,950,267.87 | Analyzed tx |
| USDC | 147,658.836798 | $147,621.77 | Analyzed tx |
| ETH | 1,625 | ~$3,400,000 | Separate transaction |
| **Total** | — | **~$11.58M** | Consolidated to ~5,402 ETH after DEX swaps |

---

## 4. Vulnerability Classification

### 4.1 Classification Table

| ID | Vulnerability | Severity | CWE | Category | Similar Incidents |
|----|---------------|----------|-----|----------|-------------------|
| V-01 | Cross-chain import source amount not validated | CRITICAL | CWE-345 | bridge-crosschain | Nomad Bridge, Hyperbridge |
| V-02 | Cryptographic validity and economic validity conflated | CRITICAL | CWE-20 | bridge-crosschain, business-logic | Wormhole (partial) |
| V-03 | Insufficient notary signature scope | HIGH | CWE-347 | signature-replay | Wormhole |

### 4.2 V-01 — Cross-Chain Import Source Amount Not Validated

- **Description**: `checkCCEValues()` only verified hash consistency of the CCE payload without comparing the declared source-chain deposit totals (`CCE.totalAmounts[]`) against the Ethereum-side payout amounts (sum of payout blob). The attacker deposited only 0.02 VRSC while committing multi-million-dollar payout instructions in the payload blob.
- **Impact**: The entire bridge reserves could be drained with a negligible deposit. $11.58M lost.
- **Attack Preconditions**: Ability to create a transaction on the Verus network + ability to call `submitImports()` on Ethereum. No special privileges required.

### 4.3 V-02 — Cryptographic Validity and Economic Validity Conflated

- **Description**: At the system design level, the assumption "valid signature = legitimate payout" was baked in. However, hash/signature verification guarantees only data integrity, not the economic soundness of the data's content. These two properties require independent verification layers.
- **Impact**: Requires re-evaluation of the entire cross-chain validation architecture, not just a single function patch. The full bridge liquidity was attackable.
- **Attack Preconditions**: Sufficient to be able to submit a correctly formatted transaction on the source chain.

### 4.4 V-03 — Insufficient Notary Signature Scope

- **Description**: When notaries signed the state root, they did not independently verify that the CCE's `source amount totals` matched the payout blob amounts. Their signature only attested that "this data exists in a Verus chain block"; the responsibility for verifying "amounts match actual deposits" was never explicitly assigned to anyone.
- **Impact**: The multisig trust model failed to compensate for the absence of economic validation. Increasing the number of notaries does not prevent the same attack.
- **Attack Preconditions**: The current protocol state in which notaries do not validate source totals.

---

## 5. Comparison with Similar Incidents

| Incident | Date | Loss | Flaw Type | Difference from Verus |
|----------|------|------|-----------|-----------------------|
| **Nomad Bridge** | 2022-08 | ~$190M | `acceptableRoot[bytes32(0)] = true` initialization error → all messages auto-valid | Validation **entirely absent** vs. Verus has validation but with **insufficient scope** |
| **Wormhole** | 2022-02 | ~$325M | Solana sysvar spoofing → forged signatures pass | **Forged signatures** vs. Verus: **genuine signatures on forged content** |
| **Hyperbridge** | 2026-04 | ~$2.5M | Forged MMR proof submitted → proof forgery | **Proof forgery** vs. Verus: **genuine proof, but economic consistency absent** |
| **Verus Bridge** | 2026-05 | ~$11.58M | Signatures/hashes/proofs all genuine — validation scope excludes economic consistency | The most **sophisticated form** among the above |

What makes the Verus incident unique is that **no forgery occurred at any stage of the attack transaction**. The payload was correctly formatted, the hash matched, and the notary signatures were genuine. The flaw existed solely in a "semantic gap not covered by any validation" — the ratio between source deposit amounts and payout amounts.

---

## 6. Remediation Recommendations

### 6.1 Immediate Fix (`checkCCEValues` core patch, ~10 lines)

```solidity
// ✅ Add at the end of checkCCEValues
VerusObjects.CCurrencyValueMap[] memory payoutSums =
    VerusSerializer.sumTransfers(_import.serializedTransfers);
require(payoutSums.length == _cce.totalAmounts.length, "Currency count mismatch");
for (uint256 i = 0; i < payoutSums.length; i++) {
    require(
        payoutSums[i].currency == _cce.totalAmounts[i].currency,
        "Currency mismatch"
    );
    require(
        payoutSums[i].amount <= _cce.totalAmounts[i].amount,
        "Payout exceeds source amount"   // ✅ Core invariant
    );
}
```

### 6.2 Replay Protection (add to `_createImports`)

```solidity
// ✅ Block re-submission (replay) of the same export
bytes32 exportKey = keccak256(abi.encode(
    cce.sourceSystemID, cce.startHeight, cce.endHeight, _import.hashTransfers
));
require(!processedExports[exportKey], "Replay attack");
processedExports[exportKey] = true;
```

### 6.3 Structural Improvements

| Vulnerability | Recommended Fix |
|---------------|----------------|
| Notaries sign only the hash; semantic content is outside signature scope | Include the full tuple `(sourceSystemID, exportHeightRange, totalAmounts[], hashTransfers)` in the notarization |
| Source amounts not compared to payout amounts | Enforce `sum(payouts) ≤ totalAmounts` per currency in `checkCCEValues` (patch above) |
| No replay protection | Block re-submission of the same export via `processedExports[exportKey]` mapping |
| Unlimited withdrawal possible | Introduce per-asset / per-day withdrawal limits (circuit breaker) |
| Source not verified on-chain | Mandate Etherscan source verification and public audit |

---

## 7. Lessons Learned

1. **Cryptographic verification does not substitute economic verification.** Signatures, hashes, and MMR proofs guarantee data integrity only. Economic invariants such as "payout ≤ source_deposit" must be enforced in a separate layer.
2. **Cross-chain invariants must be enforced on both sides.** Logic comparing the source chain's `totalAmounts` against the destination chain's payout must not be absent from either side.
3. **The scope of notary/oracle responsibility must be explicitly defined.** "Certifying data existence" and "certifying data economic correctness" are distinct responsibilities. The moment these are implicitly assumed to be covered by the same multisig, the security model collapses.
4. **A simple validation gap maps directly to total reserve exposure.** The missing logic in this incident was approximately 10 lines, yet its absence led to $11.58M in losses.
5. **Circuit breakers are the last line of defense against validation bugs.** Per-asset/per-day withdrawal limits would have capped the maximum damage to tens of thousands of dollars even with the same underlying bug.

---

## 8. On-Chain Verification

### 8.1 Analyzed Transaction Data

| Field | Value |
|-------|-------|
| Attack Tx | [0x6990f01720f57fc515d0e976a0c4f8157e0a9529194c4c15d190e98d087eb321](https://etherscan.io/tx/0x6990f01720f57fc515d0e976a0c4f8157e0a9529194c4c15d190e98d087eb321) |
| Block Number | 25118335 |
| From | [0x5aBb91B9c01A5Ed3aE762d32B236595B459D5777](https://etherscan.io/address/0x5aBb91B9c01A5Ed3aE762d32B236595B459D5777) (Verus Exploiter 1) |
| To | [0x71518580f36FeCEFfE0721F06bA4703218cD7F63](https://etherscan.io/address/0x71518580f36FeCEFfE0721F06bA4703218cD7F63) (Verus: Ethereum Bridge) |
| Function Called | `submitImports(CReserveTransferImport)` |

### 8.2 Asset Movements (This Tx)

| Token | From | To | Amount | USD Value |
|-------|------|----|--------|-----------|
| tBTC (Threshold Network) | Bridge (0x71518580…) | Exploiter 2 (0x65Cb8b12…) | 103.56766017 | $7,950,267.87 |
| USDC (Circle) | Bridge (0x71518580…) | Exploiter 2 (0x65Cb8b12…) | 147,658.836798 | $147,621.77 |

### 8.3 Gas Funding Source

The attacker EOA withdrew 1 ETH from Tornado Cash approximately 14 hours before the attack to fund gas costs. This is a typical pre-attack preparation pattern used to evade fund tracing.

### 8.4 Separate Attack Transaction

An additional ETH 1,625 (~$3.4M) was drained via the same vulnerability in a separate transaction. The combined loss across both transactions is $11.58M, and all proceeds were subsequently DEX-swapped into ~5,402 ETH.

---

## 9. References

- [Verus Official GitHub (Verus-Ethereum-Contracts)](https://github.com/VerusCoin/Verus-Ethereum-Contracts)
- [Attack Transaction (Etherscan)](https://etherscan.io/tx/0x6990f01720f57fc515d0e976a0c4f8157e0a9529194c4c15d190e98d087eb321)
- [Vulnerable Contract (Verus: Ethereum Bridge)](https://etherscan.io/address/0x71518580f36FeCEFfE0721F06bA4703218cD7F63)
- [Attacker EOA (Verus Exploiter 1)](https://etherscan.io/address/0x5aBb91B9c01A5Ed3aE762d32B236595B459D5777)
- [Profit Receiver (Verus Exploiter 2)](https://etherscan.io/address/0x65Cb8b128bF6E690761044CCEca422bB239C25F9)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- Related: [Nomad Bridge (2022)](../2022/2022-08-01_NomadBridge_MessageVerification.md), [Hyperbridge (2026)](./2026-04-13_Hyperbridge_TokenGateway_ForgedProof_FakeMint_ETH.md)
