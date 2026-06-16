# Gravity Bridge — Validator Signing-Key Compromise Exploit Analysis

| Field | Details |
|-------|---------|
| **Date** | 2026-05-30 02:51:00 UTC (drain cluster ~02:30–02:51 UTC, May 30; valset precursor May 28 22:40 UTC) |
| **Protocol** | Gravity Bridge (Cosmos ↔ Ethereum asset bridge) |
| **Chain** | Ethereum (drained side) / Gravity Bridge Cosmos zone (orchestration side) |
| **Total Loss** | **~$5.4M** (~$4.3M USDC + 274 WETH ~$553K + ~$434K USDT + 14.164 PAXG ~$64K) |
| **Attacker EOA (Exploiter 1)** | [0x7B582033061b96cC3F9421e73a749ED7C62da1F9](https://etherscan.io/address/0x7B582033061b96cC3F9421e73a749ED7C62da1F9) |
| **Attacker EOA (Exploiter 2)** | [0x4d3ca32e687e871a58b78AcAc73bE59AC37C7A47](https://etherscan.io/address/0x4d3ca32e687e871a58b78AcAc73bE59AC37C7A47) |
| **Vulnerable Contract** | [0xa4108aA1Ec4967F8b52220a4f7e94A8201F2D906](https://etherscan.io/address/0xa4108aA1Ec4967F8b52220a4f7e94A8201F2D906) (Gravity.sol — bridge vault) |
| **Attack Tx (batch drain)** | [0x59e52302c53e862fcf833b61eb851ff66e098e3d29db19fd66e5a04734eeb84b](https://etherscan.io/tx/0x59e52302c53e862fcf833b61eb851ff66e098e3d29db19fd66e5a04734eeb84b) (`submitBatch`, ~274.35 WETH) |
| **Valset Precursor Tx** | [0x4ae66025236aa0c05e78beb46bde7d6d75b188822f3cb5d338e2493a35bc83c4](https://etherscan.io/tx/0x4ae66025236aa0c05e78beb46bde7d6d75b188822f3cb5d338e2493a35bc83c4) (`updateValset`, set 58 → 34) |
| **Entry Selector / Function** | `submitBatch(...)` / `updateValset(...)` — both gated by `checkValidatorSignatures()` |
| **Root Cause** | Off-chain validator/orchestrator signing keys compromised; attacker produced genuinely-signed valset updates and withdrawal batches that the on-chain contract correctly accepts |
| **GitHub / Source** | https://github.com/Gravity-Bridge/Gravity-Bridge — `solidity/contracts/Gravity.sol` |
| **Source Verification** | Gravity.sol is open-source and verified on Etherscan. All 5 transaction hashes in this report are Etherscan-verified and real. Root-cause analysis is based on the contract source plus public incident reports (The Block, CryptoTimes, Bitcoin.com). |

---

## 1. Vulnerability Overview

Gravity Bridge is a trust-minimized asset bridge connecting a Cosmos SDK zone (the "Gravity Bridge" chain) to Ethereum. On the Ethereum side, a single vault contract — `Gravity.sol` (`0xa4108aA1…F2D906`) — custodies all bridged ERC-20 reserves. The contract's security model is a **validator-set (valset) signature threshold**: it stores the current set of Ethereum addresses corresponding to the Cosmos validators, each weighted by its staking power, and it will execute a state transition (a withdrawal batch, a logic call, or a valset rotation) only if signatures representing **more than 2/3 of the cumulative voting power** are presented.

Crucially, this is a sound design **at the contract level**. The Solidity code does exactly what it is supposed to do: it recovers signers via `ecrecover`, checks each signer against the stored valset, sums their powers, and reverts unless the 2/3 threshold is met. There is no integer bug, no reentrancy, no missing access modifier, and no signature-malleability or replay flaw in the verified bytecode.

The incident was **not a contract exploit**. It was an **off-chain key compromise**. The attacker obtained control of enough validator/orchestrator Ethereum signing keys to *legitimately* satisfy the contract's 2/3 power threshold. With those keys, the attacker:

1. **Shrank the active validator set** from 58 to 34 members (tx `0x4ae66025…`, May 28 22:40 UTC, `updateValset`), concentrating signing power into a smaller, attacker-favorable set and lowering the absolute number of honest signatures needed to clear the threshold thereafter.
2. **Withdrew bridge reserves** via one or more `submitBatch` calls (the verified WETH batch is tx `0x59e52302…`, May 30 02:30 UTC), draining ~$5.4M of USDC, WETH, USDT, and PAXG to the attacker EOAs.

Because every signature presented to `checkValidatorSignatures()` was **cryptographically genuine** — produced by keys the contract trusts — the contract had no basis to reject the transactions. The trust boundary that failed was the **off-chain custody of validator signing keys** and the operational assumption that a sudden valset contraction would be noticed and halted. The on-chain code is the wrong place to look for the bug; the "fix" is operational (key custody hardening, HSMs, valset-churn alerting), not a code patch.

This makes Gravity Bridge a textbook **CWE-345 / CWE-347 / CWE-522** failure: the on-chain verifier correctly verifies authenticity, but the *authority* it trusts (the signing keys) was itself compromised, so "valid signature" no longer implies "authorized action."

---

## 2. Vulnerable Code Analysis

### 2.1 `checkValidatorSignatures()` — Genuine Signatures Pass by Design

The heart of Gravity.sol's security is `checkValidatorSignatures()`. It is **not buggy**; it is doing precisely what it was written to do. The vulnerability is that its trust input (the validator keys) was compromised off-chain, so genuine-but-malicious signatures clear the threshold.

**Actual on-chain logic** (Gravity.sol, `checkValidatorSignatures`, lightly condensed from the open-source repository):

```solidity
// solidity/contracts/Gravity.sol  (open-source, Etherscan-verified)
// Checks that enough validators (by cumulative power) signed `_theHash`.
function checkValidatorSignatures(
    address[] memory _currentValidators,
    uint256[] memory _currentPowers,
    ValSignature[] memory _sigs,
    bytes32 _theHash,
    uint256 _powerThreshold
) private pure {
    uint256 cumulativePower = 0;

    for (uint256 i = 0; i < _currentValidators.length; i++) {
        // If v == 0 this signer abstained; skip without counting power.
        if (_sigs[i].v != 0) {
            // ✅ ecrecover MUST return exactly the stored validator address.
            //    A forged signature would fail here. The attacker did NOT forge —
            //    the keys were genuinely controlled, so this passes legitimately.
            if (verifySig(_currentValidators[i], _theHash, _sigs[i]) == false) {
                revert InvalidSignature();
            }
            cumulativePower += _currentPowers[i];

            // ✅ Early exit once > 2/3 power is reached.
            if (cumulativePower > _powerThreshold) {
                break;
            }
        }
    }

    // ✅ Reverts unless the 2/3 power threshold is satisfied.
    if (cumulativePower <= _powerThreshold) {
        revert InsufficientPower({
            cumulativePower: cumulativePower,
            powerThreshold: _powerThreshold
        });
    }
    // No bug: control returns only when genuine signers clear the threshold.
}

function verifySig(
    address _signer,
    bytes32 _theHash,
    ValSignature memory _sig
) private pure returns (bool) {
    bytes32 messageDigest =
        keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _theHash));
    return _signer == ecrecover(messageDigest, _sig.v, _sig.r, _sig.s);
}
```

There is no `❌` line to point at inside this function. **That is the point.** Each branch behaves correctly. The exploit lives entirely *outside* the EVM: whoever holds the keys for addresses in `_currentValidators` can produce signatures that `verifySig()` accepts as genuine, because they *are* genuine.

### 2.2 `updateValset()` — Legitimate Rotation Used to Concentrate Power

`updateValset()` rotates the stored validator set. It requires the *current* valset to sign off (via `checkValidatorSignatures`) on the *new* valset. The attacker used this — tx `0x4ae66025…` (May 28 22:40 UTC) — to shrink the set from 58 to 34, concentrating signing power.

**Actual on-chain logic** (Gravity.sol, `updateValset`, condensed):

```solidity
function updateValset(
    ValsetArgs calldata _newValset,
    ValsetArgs calldata _currentValset,
    ValSignature[] calldata _sigs
) external {
    // 1. New valset must be internally consistent.
    require(
        _newValset.validators.length == _newValset.powers.length,
        "Malformed new validator set"
    );
    // 2. Current valset must hash to the stored checkpoint.
    require(
        _currentValset.validators.length == _currentValset.powers.length &&
        _currentValset.validators.length == _sigs.length,
        "Malformed current validator set"
    );
    bytes32 currentValsetCheckpoint = makeCheckpoint(_currentValset, state_gravityId);
    require(
        state_lastValsetCheckpoint == currentValsetCheckpoint,
        "Supplied current validators and powers do not match checkpoint."
    );
    // 3. New valset nonce must increase.
    require(
        _newValset.valsetNonce > _currentValset.valsetNonce,
        "New valset nonce must be greater than the current nonce"
    );
    // 4. New valset must still represent >2/3 of total power (anti-griefing guard).
    uint256 cumulativePower = 0;
    for (uint256 i = 0; i < _newValset.powers.length; i++) {
        cumulativePower += _newValset.powers[i];
        if (cumulativePower > constant_powerThreshold) break;
    }
    require(
        cumulativePower > constant_powerThreshold,
        "Submitted validator set signatures do not have enough power."
    );

    bytes32 newCheckpoint = makeCheckpoint(_newValset, state_gravityId);

    // ✅ The CURRENT valset must sign the NEW checkpoint.
    //    With compromised current keys, this signature is genuine → passes.
    checkValidatorSignatures(
        _currentValset.validators,
        _currentValset.powers,
        _sigs,
        newCheckpoint,
        constant_powerThreshold
    );

    // ✅ Commit the new (smaller, attacker-favorable) checkpoint.
    state_lastValsetCheckpoint = newCheckpoint;
    state_lastValsetNonce = _newValset.valsetNonce;
    emit ValsetUpdatedEvent(
        _newValset.valsetNonce,
        state_lastEventNonce,
        _newValset.rewardAmount,
        _newValset.rewardToken,
        _newValset.validators,
        _newValset.powers
    );
}
```

Again, every check passes legitimately. The 58→34 contraction satisfies the `>2/3` guard for the *new* set, and the *current* (compromised) set signs the new checkpoint genuinely. The on-chain code cannot tell "operator-authorized rotation" from "attacker-driven rotation" — both look identical at the signature layer.

### 2.3 `submitBatch()` — Reserves Drained With a Valid Batch

`submitBatch()` executes a batch of outgoing ERC-20 transfers from the vault. It requires the current valset to sign the batch hash. The attacker's WETH drain is the verified tx `0x59e52302…` (May 30 02:30 UTC).

**Actual on-chain logic** (Gravity.sol, `submitBatch`, condensed):

```solidity
function submitBatch(
    ValsetArgs calldata _currentValset,
    ValSignature[] calldata _sigs,
    uint256[] calldata _amounts,
    address[] calldata _destinations,
    uint256[] calldata _fees,
    uint256 _batchNonce,
    address _tokenContract,
    uint256 _batchTimeout
) external nonReentrant {
    {
        // 1. Batch nonce must strictly increase (replay guard).
        require(
            state_lastBatchNonces[_tokenContract] < _batchNonce,
            "New batch nonce must be greater than the current nonce"
        );
        // 2. Timeout guard.
        require(block.number < _batchTimeout, "Batch timeout must be greater than the current block height");
        // 3. Current valset must hash to stored checkpoint.
        require(
            makeCheckpoint(_currentValset, state_gravityId) == state_lastValsetCheckpoint,
            "Supplied current validators and powers do not match checkpoint."
        );
        require(
            _amounts.length == _destinations.length && _amounts.length == _fees.length,
            "Malformed batch of transactions"
        );

        // ✅ Current valset must sign the batch digest.
        //    With compromised keys, signatures are genuine → passes.
        checkValidatorSignatures(
            _currentValset.validators,
            _currentValset.powers,
            _sigs,
            keccak256(abi.encode(
                state_gravityId, 0x7472616e73616374696f6e426174636800000000000000000000000000000000,
                _amounts, _destinations, _fees, _batchNonce, _tokenContract, _batchTimeout
            )),
            constant_powerThreshold
        );

        // ✅ Commit new batch nonce.
        state_lastBatchNonces[_tokenContract] = _batchNonce;

        // ❌ (NOT a code bug) Transfers leave the vault to attacker destinations.
        //    The contract has no notion of "this withdrawal is anomalous" — it only
        //    knows the signatures cleared the threshold.
        uint256 totalFee;
        for (uint256 i = 0; i < _amounts.length; i++) {
            IERC20(_tokenContract).safeTransfer(_destinations[i], _amounts[i]);
            totalFee = totalFee + _fees[i];
        }
        IERC20(_tokenContract).safeTransfer(msg.sender, totalFee);
    }
    state_lastEventNonce = state_lastEventNonce + 1;
    emit TransactionBatchExecutedEvent(_batchNonce, _tokenContract, state_lastEventNonce);
}
```

### 2.4 Why There Is No "Fixed Code" in the Usual Sense

For most incidents, Section 2 ends with a `✅ fixed` Solidity patch. **Gravity Bridge has no such patch**, because the contract is not where the bug is. Below is what a *misguided* "fix" would look like versus what an effective remediation actually requires.

```solidity
// ❌ MISGUIDED "fix": trying to patch the contract.
// Adding more on-chain checks does NOT help — every signature is already genuine.
function submitBatch(/* ... */) external {
    // e.g. require(_amounts[i] < SOME_CAP) — a rate limit only slows, never prevents,
    //      a fully-compromised 2/3 valset. It is a mitigation, not a fix.
}
```

```text
// ✅ EFFECTIVE remediation is OPERATIONAL, off-chain:
//   1. Validator signing keys MUST live in HSMs / threshold-signing infra,
//      never in hot orchestrator processes reachable from the internet.
//   2. Orchestrator key rotation + per-validator key isolation so one breach
//      cannot reach 2/3 of power.
//   3. Off-chain monitoring that ALERTS and (optionally) auto-pauses on:
//        - sudden valset contraction (58 -> 34 in one update),
//        - large/anomalous submitBatch withdrawals,
//        - valset/batch nonces advancing outside normal cadence.
//   4. An on-chain emergency pause/guardian (timelocked) so a human can halt
//      the vault between detection and full key-compromise drain.
```

The only *contract-level* hardening that meaningfully helps is a **guardian-controlled circuit breaker** (Section 6.2): it does not prevent a 2/3-key compromise, but it caps the blast radius by letting a human pause the vault once the anomalous valset contraction (tx `0x4ae66025…`) is detected — there were ~28 hours between that May 28 precursor and the May 30 drain.

---

## 3. Attack Flow

### 3.1 Preparation

**Off-chain key compromise (timing not publicly disclosed).** The attacker obtained control of enough validator/orchestrator signing keys to represent more than 2/3 of Gravity Bridge's cumulative voting power. Public reporting (The Block, citing researchers) attributes the loss to a **suspected key compromise** rather than a smart-contract exploit, consistent with the on-chain evidence: every malicious transaction carried genuine, threshold-satisfying signatures.

**Gas funding.** On **May 30 00:51:35 UTC** (block 25204721), Exploiter 1 received **0.9988 ETH** from Binance20 (tx `0x68b29379…`), funding the gas for the upcoming on-chain operations. The use of a CEX-sourced gas top-up immediately before the drain is consistent with the laundering pattern observed afterward (ChangeNOW + Binance).

### 3.2 Execution

**[Step 1 — May 28 22:40:59 UTC, block 25196898] Valset contraction (precursor).**
The attacker submitted `updateValset` (tx `0x4ae66025…`), rotating the active validator set from **58 → 34** members. Because the *current* (compromised) valset signed the *new* checkpoint genuinely, and the new 34-member set still cleared the contract's `>2/3` internal guard, the rotation was accepted as fully legitimate. This concentrated signing power and reduced the absolute number of honest signatures required thereafter.

**[Step 2 — May 30 00:51:35 UTC, block 25204721] Gas funding.**
Exploiter 1 received 0.9988 ETH from Binance20 (tx `0x68b29379…`) to pay for the drain transactions.

**[Step 3 — May 30 ~02:30 UTC, block 25205212] Reserve drain via `submitBatch`.**
The attacker submitted withdrawal batches against the now-concentrated valset. The Etherscan-verified WETH batch (tx `0x59e52302…`) moved **~274.35 WETH** from the Gravity.sol vault to Exploiter 1. Parallel batches drained the USDC (~$4.3M), USDT (~$434K), and PAXG (14.164, ~$64K) reserves. Total losses ~$5.4M. Every batch carried genuine 2/3-power signatures, so `checkValidatorSignatures()` accepted them all.

**[Step 4 — May 30 02:51:23 UTC, block 25205318] Internal consolidation.**
Exploiter 1 forwarded **500 ETH** to Exploiter 2 (tx `0xafb1ee55…`), consolidating proceeds across the two attacker EOAs.

**[Step 5 — May 31 23:31:23 UTC, block 25218654] Laundering.**
Exploiter 2 sent **100 ETH** to `0xC8c7…f562` (tx `0x4d864ec4…`) as part of laundering. Proceeds were subsequently routed through **ChangeNOW** and **Binance** per public reporting.

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  OFF-CHAIN: Validator/orchestrator signing-key compromise   │
│  Attacker controls keys representing > 2/3 of voting power  │
│  (root cause — NOT a contract bug)                          │
└──────────────────────────────────┬──────────────────────────┘
                                   │
            ┌──────────────────────┴───────────────────────┐
            │  T-precursor: May 28 22:40 UTC (blk 25196898)│
            ▼                                              │
┌─────────────────────────────────────────────────────────────┐
│  updateValset()  tx 0x4ae66025…                             │
│  Active validator set:  58  ──►  34                         │
│  ├─ current (compromised) set signs new checkpoint ✓ genuine │
│  └─ new 34-set still > 2/3 internal guard ✓ → ACCEPTED      │
│  Effect: signing power concentrated, honest sigs needed ↓   │
└──────────────────────────────────┬──────────────────────────┘
                                   │ ~28h later
   May 30 00:51 (blk 25204721)     ▼
┌─────────────────────────────────────────────────────────────┐
│  Binance20 ── 0.9988 ETH ──► Exploiter 1  (gas funding)     │
│  tx 0x68b29379…                                             │
└──────────────────────────────────┬──────────────────────────┘
                                   │
   May 30 ~02:30 (blk 25205212)    ▼
┌─────────────────────────────────────────────────────────────┐
│  Gravity.sol vault (0xa4108aA1…F2D906)                      │
│  submitBatch()  tx 0x59e52302…  (+ parallel token batches)  │
│  ├─ checkValidatorSignatures() ✓ (signatures GENUINE)       │
│  └─ safeTransfer → attacker destinations                    │
│      ├─ ~274.35 WETH  (~$553K)  → Exploiter 1               │
│      ├─ ~$4.3M USDC                                          │
│      ├─ ~$434K USDT                                          │
│      └─ 14.164 PAXG (~$64K)                                  │
└──────────────────────────────────┬──────────────────────────┘
                                   │
   May 30 02:51 (blk 25205318)     ▼
┌─────────────────────────────────────────────────────────────┐
│  Exploiter 1 ── 500 ETH ──► Exploiter 2   tx 0xafb1ee55…    │
└──────────────────────────────────┬──────────────────────────┘
                                   │
   May 31 23:31 (blk 25218654)     ▼
┌─────────────────────────────────────────────────────────────┐
│  Exploiter 2 ── 100 ETH ──► 0xC8c7…f562   tx 0x4d864ec4…    │
│  → laundering via ChangeNOW + Binance                       │
└─────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Asset | Amount | Approx. USD | Notes |
|-------|--------|-------------|-------|
| USDC | — | ~$4,300,000 | Largest single component of the drain |
| WETH | 274.35 | ~$553,000 | Etherscan-verified batch tx `0x59e52302…` |
| USDT | — | ~$434,000 | Drained from vault reserves |
| PAXG | 14.164 | ~$64,000 | Drained from vault reserves |
| **Total** | — | **~$5.4M** | Consolidated across two EOAs, laundered via ChangeNOW + Binance |

---

## 4. Vulnerability Classification

### 4.1 Classification Table

| ID | Vulnerability | Severity | CWE | Category | Similar Incidents |
|----|---------------|----------|-----|----------|-------------------|
| V-01 | Validator/orchestrator signing-key compromise (off-chain) | CRITICAL | CWE-522 | off-chain-signing, key-management | Ronin, Harmony Horizon |
| V-02 | Trust placed in signature authenticity without authority integrity | CRITICAL | CWE-345 | bridge-crosschain | Ronin, Harmony Horizon |
| V-03 | On-chain verifier accepts genuine-but-malicious signatures | HIGH | CWE-347 | signature-trust | Ronin |
| V-04 | No alerting / circuit breaker on anomalous valset contraction | HIGH | CWE-754 | operational, monitoring | Multichain, Harmony |

### 4.2 V-01 — Off-Chain Validator Signing-Key Compromise

- **Description**: The attacker obtained control of validator/orchestrator signing keys representing more than 2/3 of cumulative voting power. With those keys, every on-chain action (`updateValset`, `submitBatch`) is *authorized by construction*. This is a credential-protection failure (CWE-522), not a contract logic flaw.
- **Impact**: Total control over the bridge vault; ~$5.4M drained.
- **Attack Preconditions**: Compromise of enough independent validator key custodians to cross the 2/3 power threshold. The May 28 valset contraction (58→34) lowered the number of distinct honest keys needed.

### 4.3 V-02 — Authenticity Verified, Authority Not

- **Description**: `checkValidatorSignatures()` verifies that signatures are *authentic* (recover to trusted addresses) but cannot verify that the *authority* behind those keys is still honest. Once keys are stolen, "valid signature" no longer implies "authorized action." This is the core conflation captured by CWE-345.
- **Impact**: The on-chain security model collapses entirely upon key compromise; no contract check can compensate.
- **Attack Preconditions**: Control of the trusted keys.

### 4.4 V-03 — Verifier Accepts Genuine-But-Malicious Signatures

- **Description**: Unlike Wormhole (forged signatures) or Nomad (auto-valid root), here the signatures are real. The verifier is correct and gives no false negatives — which is exactly why it provides no defense once the keys are stolen (CWE-347, from the trust-boundary perspective).
- **Impact**: Indistinguishable from legitimate operation at the EVM layer; no on-chain revert path.
- **Attack Preconditions**: Genuine signing keys.

### 4.5 V-04 — No Anomaly Alerting / Circuit Breaker

- **Description**: A sudden validator-set contraction (58→34) and large, rapid reserve withdrawals are strong anomaly signals. There was no on-chain circuit breaker or enforced alerting that paused the vault between the May 28 precursor and the May 30 drain (~28 hours). (CWE-754: improper check for unusual conditions.)
- **Impact**: ~28-hour detection window went unused; full reserves drained.
- **Attack Preconditions**: Absence of a guardian pause / monitoring auto-halt.

---

## 5. Comparison with Similar Incidents

| Incident | Date | Loss | Flaw Type | Difference from Gravity Bridge |
|----------|------|------|-----------|--------------------------------|
| **Ronin Bridge** | 2022-03 | ~$625M | 5 of 9 validator keys compromised → genuine multisig signatures drain the bridge | Same class — stolen keys producing genuine signatures. Ronin needed 5/9 keys; Gravity needed >2/3 power, aided by a deliberate valset contraction |
| **Harmony Horizon** | 2022-06 | ~$100M | 2 of 5 multisig signer keys compromised | Same class — off-chain key custody failure; Harmony's 2/5 threshold was far weaker than Gravity's 2/3 power |
| **Verus Bridge** | 2026-05 | ~$11.58M | Genuine notary signatures over economically-invalid payload (validation-scope gap) | Verus keys were NOT stolen — signatures were genuine over *forged content*. Gravity keys *were* stolen — signatures genuine over *legitimate-looking actions* |
| **Gravity Bridge** | 2026-05 | ~$5.4M | Off-chain validator signing-key compromise; valset shrunk 58→34 then reserves drained | The on-chain contract is sound; the failure is purely in off-chain key custody + the 2/3 trust threshold |

The defining trait of Gravity Bridge — shared with **Ronin** and **Harmony Horizon** but contrasting with **Verus** — is that **the on-chain contract did nothing wrong**. The signatures were genuine and the validation logic executed correctly. Where Verus's failure was a *missing economic check* in otherwise-genuine signing, Gravity's failure was the *theft of the signing authority itself*. No amount of additional on-chain validation defends against an attacker who legitimately holds 2/3 of the keys.

---

## 6. Remediation Recommendations

> **Important**: Because the root cause is off-chain key compromise, the primary remediations are operational. On-chain measures can only *cap blast radius*, not *prevent* a 2/3-key compromise.

### 6.1 Operational: Validator Key Custody Hardening (primary fix)

```text
1. Move ALL validator/orchestrator signing keys into HSMs or threshold-signature
   modules. No raw private keys in hot orchestrator processes.
2. Enforce per-validator key isolation and independent custody, so compromising
   one operator cannot cascade toward the 2/3 power threshold.
3. Mandatory periodic key rotation + post-incident full rotation.
4. Network isolation of orchestrator signing endpoints (no public reachability).
```

### 6.2 On-Chain: Guardian Circuit Breaker (blast-radius cap)

```solidity
// ✅ Add a timelocked guardian pause. Does NOT prevent a 2/3-key compromise,
//    but lets a human halt the vault once anomalies (e.g., 58→34 valset
//    contraction) are detected — there were ~28h of warning here.
address public guardian;
bool public paused;

modifier whenNotPaused() {
    require(!paused, "Bridge paused");
    _;
}

function emergencyPause() external {
    require(msg.sender == guardian, "Only guardian");
    paused = true;
    emit EmergencyPaused(block.timestamp);
}

// Gate state-changing entrypoints:
function submitBatch(/* ... */) external whenNotPaused nonReentrant { /* ... */ }
function updateValset(/* ... */) external whenNotPaused { /* ... */ }
```

### 6.3 On-Chain: Valset-Churn Guard (anomaly resistance)

```solidity
// ✅ Reject (or timelock) abrupt validator-set contractions. A 58→34 drop in a
//    single update should require an extended timelock + off-chain confirmation,
//    raising the cost and visibility of an attacker-driven concentration.
uint256 constant MAX_VALSET_SHRINK_BPS = 1500; // ≤15% membership drop per update

function updateValset(ValsetArgs calldata _newValset, ValsetArgs calldata _currentValset, ValSignature[] calldata _sigs) external {
    uint256 prevLen = _currentValset.validators.length;
    uint256 newLen  = _newValset.validators.length;
    if (newLen < prevLen) {
        require(
            (prevLen - newLen) * 10000 <= prevLen * MAX_VALSET_SHRINK_BPS,
            "Valset contraction too large; requires timelocked governance path"
        );
    }
    // ... existing checks ...
}
```

### 6.4 Off-Chain: Monitoring & Auto-Halt

| Signal | Recommended Response |
|--------|---------------------|
| Valset membership drops sharply (e.g., 58→34) | Page on-call + invoke guardian `emergencyPause()` |
| `submitBatch` withdraws abnormal % of a token's reserve | Auto-pause + manual review before nonce advance |
| Valset / batch nonce advances outside normal cadence | Alert + freeze |
| New CEX-funded EOA interacts with the vault | Watchlist + correlate with batch destinations |

### 6.5 Structural

| Weakness | Recommended Fix |
|----------|-----------------|
| 2/3 power threshold over hot keys | Threshold signatures (TSS) + HSM custody; raise effective key-diversity requirement |
| No withdrawal rate limit | Per-asset / per-window withdrawal caps (circuit breaker) |
| No emergency halt | Timelocked guardian pause (6.2) |
| Abrupt valset churn allowed | Valset-shrink guard (6.3) |

---

## 7. Lessons Learned

1. **A bridge is only as secure as its off-chain key custody.** Gravity.sol's on-chain verification was flawless, yet ~$5.4M was drained because the *keys* the contract trusts were stolen. Audited, verified Solidity gives zero protection against compromised signing authority.
2. **"Valid signature" ≠ "authorized action."** Cryptographic authenticity (CWE-347) verifies *who signed*, not *whether the signer is still honest*. Once keys are stolen, the verifier becomes the attacker's tool, not the protocol's defense.
3. **Validator-set concentration is an attack primitive.** Shrinking the active set (58→34) before draining is a deliberate move to reduce the number of honest keys needed. Sudden valset contraction must be treated as a first-class security alert, not routine churn.
4. **Detection windows are worthless without a halt mechanism.** There were ~28 hours between the anomalous May 28 valset update and the May 30 drain. With a guardian circuit breaker and monitoring, the loss could have been prevented even after key compromise.
5. **This class repeats (Ronin, Harmony, now Gravity).** Bridges that custody large reserves behind a key-threshold model must invest disproportionately in HSM/TSS key management and operational monitoring — the contract layer is necessary but nowhere near sufficient.
6. **Threshold signatures and key diversity raise the bar.** A 2/3 power threshold concentrated on hot orchestrator keys is fragile. TSS + HSM + per-operator isolation makes reaching the threshold materially harder for an attacker.

---

## 8. On-Chain Verification

> All five transactions below are **Etherscan-verified and real**.

### 8.1 Transaction Index

| # | Tx Hash | Block | Time (UTC) | Role |
|---|---------|-------|-----------|------|
| 1 | [0x68b293793c8f551b1e60345e59fb54de9d2e439a8b461d8fae5dea7d273f6c5c](https://etherscan.io/tx/0x68b293793c8f551b1e60345e59fb54de9d2e439a8b461d8fae5dea7d273f6c5c) | 25204721 | 2026-05-30 00:51:35 | Binance20 → Exploiter 1, 0.9988 ETH (gas funding) |
| 2 | [0x4ae66025236aa0c05e78beb46bde7d6d75b188822f3cb5d338e2493a35bc83c4](https://etherscan.io/tx/0x4ae66025236aa0c05e78beb46bde7d6d75b188822f3cb5d338e2493a35bc83c4) | 25196898 | 2026-05-28 22:40:59 | `updateValset` shrinking set 58 → 34 (pre-exploit setup) |
| 3 | [0x59e52302c53e862fcf833b61eb851ff66e098e3d29db19fd66e5a04734eeb84b](https://etherscan.io/tx/0x59e52302c53e862fcf833b61eb851ff66e098e3d29db19fd66e5a04734eeb84b) | 25205212 | 2026-05-30 02:30:11 | `submitBatch` — ~274.35 WETH withdrawn to Exploiter 1 |
| 4 | [0xafb1ee5593e6f083aa7cd9a1fe42bea82b552c7654564eff058985ffb354302f](https://etherscan.io/tx/0xafb1ee5593e6f083aa7cd9a1fe42bea82b552c7654564eff058985ffb354302f) | 25205318 | 2026-05-30 02:51:23 | Exploiter 1 → Exploiter 2, 500 ETH (internal consolidation) |
| 5 | [0x4d864ec4550cb735b1a155aafc6293b8cdd1b0e6fb2524ff6a5c0d5c48787baa](https://etherscan.io/tx/0x4d864ec4550cb735b1a155aafc6293b8cdd1b0e6fb2524ff6a5c0d5c48787baa) | 25218654 | 2026-05-31 23:31:23 | Exploiter 2 → 0xC8c7…f562, 100 ETH (laundering) |

### 8.2 Addresses

| Role | Address |
|------|---------|
| Vulnerable contract (Gravity.sol vault) | [0xa4108aA1Ec4967F8b52220a4f7e94A8201F2D906](https://etherscan.io/address/0xa4108aA1Ec4967F8b52220a4f7e94A8201F2D906) |
| Exploiter 1 | [0x7B582033061b96cC3F9421e73a749ED7C62da1F9](https://etherscan.io/address/0x7B582033061b96cC3F9421e73a749ED7C62da1F9) |
| Exploiter 2 | [0x4d3ca32e687e871a58b78AcAc73bE59AC37C7A47](https://etherscan.io/address/0x4d3ca32e687e871a58b78AcAc73bE59AC37C7A47) |

### 8.3 Key On-Chain Sequence (chronological)

```
May 28 22:40:59  blk 25196898  tx2  updateValset      58 → 34 valset contraction (precursor)
May 30 00:51:35  blk 25204721  tx1  Binance20 → Exp1  0.9988 ETH gas funding
May 30 02:30:11  blk 25205212  tx3  submitBatch       ~274.35 WETH → Exploiter 1 (drain)
May 30 02:51:23  blk 25205318  tx4  Exp1 → Exp2        500 ETH consolidation
May 31 23:31:23  blk 25218654  tx5  Exp2 → 0xC8c7…     100 ETH laundering
```

### 8.4 Loss Composition

| Token | Amount | Approx. USD |
|-------|--------|-------------|
| USDC | — | ~$4.3M |
| WETH | 274.35 | ~$553K |
| USDT | — | ~$434K |
| PAXG | 14.164 | ~$64K |
| **Total** | — | **~$5.4M** |

### 8.5 Laundering Path

Proceeds were consolidated across the two attacker EOAs (tx4) and then laundered via **ChangeNOW** and **Binance** (tx5 is one verified hop, 100 ETH to `0xC8c7…f562`), consistent with public reporting.

---

## 9. References

- [The Block — "Cosmos-based Gravity Bridge drained of $5.4 million in suspected key compromise, researchers say"](https://www.theblock.co/post/403108/cosmos-based-gravity-bridge-drained-of-5-4-million-in-suspected-key-compromise-researchers-say)
- [CryptoTimes — "Gravity Bridge hit in $5.4M exploit amid suspected key compromise"](https://www.cryptotimes.io/2026/05/30/gravity-bridge-hit-in-5-4m-exploit-amid-suspected-key-compromise/)
- [Bitcoin.com News — "Gravity Bridge exploit: $5.4 million, Binance, ChangeNOW"](https://news.bitcoin.com/gravity-bridge-exploit-5-4-million-binance-changenow-2026/)
- [Gravity Bridge GitHub — Gravity.sol](https://github.com/Gravity-Bridge/Gravity-Bridge/blob/main/solidity/contracts/Gravity.sol)
- [Vulnerable Contract (Gravity.sol vault, Etherscan)](https://etherscan.io/address/0xa4108aA1Ec4967F8b52220a4f7e94A8201F2D906)
- [Batch-drain Tx (Etherscan)](https://etherscan.io/tx/0x59e52302c53e862fcf833b61eb851ff66e098e3d29db19fd66e5a04734eeb84b)
- [Valset-contraction Tx (Etherscan)](https://etherscan.io/tx/0x4ae66025236aa0c05e78beb46bde7d6d75b188822f3cb5d338e2493a35bc83c4)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
- Related: [Ronin Bridge (2022)](../2022/), [Harmony Horizon Bridge (2022)](../2022/), [Verus Ethereum Bridge (2026)](./2026-05-18_VerusBridge_SourceAmountValidationBypass_ETH.md)
