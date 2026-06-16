# Alephium TokenBridge — Forged Guardian VAA (Fabricated Transfer Event) Exploit Analysis

| Field | Details |
|-------|---------|
| **Date** | 2026-05-29 17:16:00 UTC (source-list date) — **NOTE:** Alephium's official on-chain report timestamps the actual drain at **2026-05-30 09:16:59 UTC**, executed over ~64 seconds. Both are noted for traceability. |
| **Protocol** | Alephium TokenBridge (Wormhole-style guardian/VAA bridge) |
| **Chain** | Ethereum + BNB Chain (collateral side) ↔ Alephium (wALPH mint side) |
| **About Alephium** | A PoW Layer-1 using BlockFlow (sharded UTXO) + a stateful execution layer. The bridge mirrors the Wormhole model: off-chain "guardians" observe source-chain events and co-sign VAAs (Verifiable Action Approvals) authorizing mints/redemptions on the other side. |
| **Total Loss** | **~$815K headline** (~$305K of backed collateral drained; **13.76M unbacked wALPH minted**; ~500K wALPH sold on Uniswap before pause) |
| **Attacker EOA (ETH side)** | [0x6681ebC82551fE52fDB48E65872e85a3ae06921d](https://etherscan.io/address/0x6681ebC82551fE52fDB48E65872e85a3ae06921d) |
| **Vulnerable Contract (ETH TokenBridge)** | [0x579a3bDE631c3d8068CbFE3dc45B0F14EC18dD43](https://etherscan.io/address/0x579a3bDE631c3d8068CbFE3dc45B0F14EC18dD43) |
| **Vulnerable Contract (BSC TokenBridge)** | [0x2971F580C34d3D584e0342741c6a622f69424dD8](https://bscscan.com/address/0x2971F580C34d3D584e0342741c6a622f69424dD8) |
| **wALPH (ETH)** | [0x590f820444fa3638e022776752c5eef34e2f89a6](https://etherscan.io/address/0x590f820444fa3638e022776752c5eef34e2f89a6) |
| **Alephium fake-event contract** | `24ZjqcvV8vVCn29zd1TThqAtaS8pMvJ4Co1MK5zncPcAB` (Alephium chain) |
| **Attack Tx (provided)** | `0x9fb1ee5593e6f083aa7cd9a1fe42bea82b552c7654564eff058985ffb354302f` — **NOT FOUND on-chain (synthetic)** |
| **Entry Selector / Function** | `completeTransfer(bytes encodedVm)` (Wormhole-style VAA redemption) |
| **Root Cause** | Off-chain guardian backend signed VAAs for a **forged transfer event** emitted by an attacker-deployed Alephium contract; valid VAAs then authorized **unbacked** wALPH mints on ETH/BSC |
| **GitHub / Source** | https://github.com/alephium/wormhole-fork (Alephium's Wormhole fork) |
| **Source Verification** | **Provided ETH tx hash not found on-chain (synthetic — a one-nibble mutation of a real Gravity Bridge transaction).** Analysis is based on Alephium's official on-chain report and public writeups (The Defiant, BeInCrypto, CryptoTimes). All addresses are drawn from those verified sources. |

---

## 1. Vulnerability Overview

The Alephium TokenBridge is a **Wormhole-fork guardian bridge**. Its trust model is identical in shape to Wormhole's: a fixed set of off-chain **guardians** runs backend nodes that watch source chains for `transfer` events, and when a qualifying event is observed, the guardians co-sign a **VAA (Verifiable Action Approval)**. On the destination chain, a TokenBridge contract verifies the guardian signatures inside the VAA and, if valid, **mints or releases** the corresponding tokens. For Alephium, a deposit/lock on Ethereum or BNB Chain mints wrapped ALPH (wALPH) — and, in the reverse direction, an Alephium-side transfer event authorizes release of ETH/BSC collateral.

This incident is frequently mislabeled as a "stolen guardian keys" event. **It was not.** The guardian private keys were never compromised. Instead, the attacker exploited the **off-chain event-observation layer** — the boundary where guardians decide *which source-chain events are real and worth signing*.

Specifically, the attacker:

1. **Deployed a malicious contract on the Alephium chain** (`24ZjqcvV8vVCn29zd1TThqAtaS8pMvJ4Co1MK5zncPcAB`) whose **only purpose** was to **emit a forged transfer event** (an Alephium `LOG7` log shaped to mimic a legitimate bridge transfer) — without any real underlying deposit backing it.
2. **Degraded bridge-node connectivity** (deliberately disrupting the bridge nodes roughly **07:00–09:00 UTC**) to push the guardian backend onto **fallback validation paths** that, in a specific edge case, accepted the forged event as genuine.
3. Caused the **guardian backend to observe and co-sign the fabricated event into valid VAAs.** Because the VAAs were signed by the real guardians over data the guardians *believed* was a real transfer, the destination TokenBridge contracts on ETH/BSC verified them as legitimate.
4. Used those VAAs to **mint 13.76M unbacked wALPH** and drain **~$305K of genuinely-backed collateral**, then **sold ~500K wALPH on Uniswap** before the bridge was paused.

Alephium's post-mortem attributed the loss to **"an off-chain vulnerability in the bridge backend triggered in specific edge cases,"** not to key theft or a destination-contract bug. This places the incident squarely in the **CWE-345 (Insufficient Verification of Data Authenticity)** / **CWE-20 (Improper Input Validation)** family: the destination contracts correctly verified *signatures*, but the *signed content was fabricated upstream* because the guardian backend's event authenticity check failed under attacker-induced edge conditions.

---

## 2. Vulnerable Code Analysis

> **Source-availability note**: Alephium's Wormhole-fork is open-source, but the failing component is the **off-chain guardian backend's event-observation/validation logic**, whose exact patched lines were not published in full. The on-chain destination logic below is faithful to the Wormhole/Alephium TokenBridge contract pattern; the off-chain logic shown is a **reconstructed/estimated** representation of the edge-case path Alephium described.

### 2.1 On-Chain `completeTransfer()` — Correctly Verifies Genuine VAAs

The ETH/BSC TokenBridge `completeTransfer()` is **not where the bug is**. It verifies the guardian signatures inside the VAA and mints/releases accordingly. Because the VAAs were genuinely signed, this function accepts them — exactly as designed.

**Actual on-chain pattern** (Wormhole/Alephium TokenBridge, condensed):

```solidity
// TokenBridge.sol  (Wormhole-fork pattern)
function completeTransfer(bytes memory encodedVm) public {
    // 1. Parse + verify the VAA against the current guardian set.
    //    ✅ Signatures are GENUINE (guardians really signed) → verification PASSES.
    (IWormhole.VM memory vm, bool valid, string memory reason) =
        wormhole().parseAndVerifyVM(encodedVm);
    require(valid, reason);

    // 2. Only accept VAAs emitted by the registered peer TokenBridge.
    require(verifyBridgeVM(vm), "invalid emitter");

    // 3. Replay guard: each VAA hash consumed once.
    require(!isTransferCompleted(vm.hash), "transfer already completed");
    setTransferCompleted(vm.hash);

    // 4. Decode the transfer payload (recipient, amount, token).
    BridgeStructs.Transfer memory transfer = parseTransfer(vm.payload);
    require(transfer.toChain == chainId(), "invalid target chain");

    address recipient = address(uint160(uint256(transfer.to)));
    address tokenAddr = address(uint160(uint256(transfer.tokenAddress)));

    // 5. ❌ (NOT a contract bug) Mint/release exactly what the VAA says.
    //    The contract has NO way to know the underlying Alephium event was forged.
    //    It trusts the guardian-signed payload as ground truth.
    if (transfer.tokenChain == chainId()) {
        // wrapped asset native here → release locked collateral
        SafeERC20.safeTransfer(IERC20(tokenAddr), recipient, transfer.amount);
    } else {
        // remote asset → MINT wrapped tokens (e.g., wALPH)
        TokenImplementation(wrappedAsset(transfer.tokenChain, transfer.tokenAddress))
            .mint(recipient, transfer.amount);
    }
}
```

Every line here is correct. `parseAndVerifyVM()` returns `valid == true` because the guardians genuinely signed the VAA. The contract cannot — and is not designed to — re-derive whether the *source-chain event* the guardians observed was real. **The trust boundary is upstream, in the guardian backend.**

### 2.2 Off-Chain Guardian Backend — The Real Vulnerability (reconstructed/estimated)

The guardian backend watches Alephium for bridge transfer events and decides whether to sign a VAA. Alephium described the failure as an **edge case in the backend's validation**, exploitable when bridge-node connectivity was degraded and a **fallback path** was taken. The reconstruction below illustrates the class of flaw.

**Estimated vulnerable backend logic** (❌, reconstructed — not verbatim Alephium source):

```typescript
// guardian-node/observe-alephium.ts  (RECONSTRUCTED / ESTIMATED)
// Observes Alephium LOG7 events and decides whether to sign a VAA.
async function observeTransferEvent(log: AlephiumLog): Promise<VAA | null> {
    // Parse the emitted LOG7 as a bridge transfer event.
    const ev = parseTransferLog(log);                 // ❌ trusts log shape only

    // ✅ Normal path: confirm the event against an authoritative bridge node
    //    that re-derives the event from canonical chain state.
    if (primaryBridgeNode.isHealthy()) {
        const confirmed = await primaryBridgeNode.confirmEvent(ev.txId, ev.eventIndex);
        if (!confirmed) return null;
    } else {
        // ❌ FALLBACK PATH (taken when nodes were disrupted ~07:00–09:00 UTC):
        //    Accepts the event based on the emitting contract's LOG7 alone,
        //    WITHOUT re-deriving that a real, backed deposit occurred.
        //    An attacker-deployed contract can emit this log at will.
        if (looksLikeTransfer(ev)) {                   // ❌ structural check only
            // proceeds to sign — NO authenticity / backing check
        } else {
            return null;
        }
    }

    // ❌ Sign a VAA for an event that may have NO underlying collateral.
    return signVAA(ev);   // genuine guardian signature over forged content
}
```

The defect: the fallback path validates the **shape** of the emitted log, not the **authenticity/backing** of the transfer. Any contract on Alephium can emit a `LOG7` that *looks like* a bridge transfer; only re-derivation against canonical, backed bridge state distinguishes a real deposit from a forged event. By forcing the backend onto the fallback path (via connectivity disruption), the attacker got genuine guardians to sign VAAs for events with no collateral behind them.

**Estimated fixed backend logic** (✅, reconstructed):

```typescript
// guardian-node/observe-alephium.ts  (RECONSTRUCTED FIX)
async function observeTransferEvent(log: AlephiumLog): Promise<VAA | null> {
    const ev = parseTransferLog(log);

    // ✅ ALWAYS re-derive the event from canonical chain state, even on fallback.
    //    No structural-only acceptance path. If no authoritative confirmation is
    //    available, DO NOT SIGN (fail closed) rather than trusting a raw LOG7.
    const confirmed = await confirmAgainstCanonicalState(ev.txId, ev.eventIndex);
    if (!confirmed) return null;

    // ✅ Verify the emitting contract is the registered bridge contract,
    //    not an arbitrary attacker-deployed contract.
    if (ev.emitter !== REGISTERED_ALEPHIUM_BRIDGE_CONTRACT) return null;

    // ✅ Verify the locked/burned collateral actually exists and matches `ev.amount`
    //    before authorizing a mint on the destination chain.
    const backing = await verifyCollateralLocked(ev.tokenId, ev.amount, ev.txId);
    if (!backing.ok) return null;

    return signVAA(ev);   // signs only authenticated, fully-backed transfers
}
```

The corrected design **fails closed**: if the authoritative confirmation path is unavailable, the guardian does not sign at all, rather than falling back to a structural log check. It also pins the **emitter** to the registered bridge contract (rejecting the attacker's `24Zjqcv…` contract) and verifies that collateral genuinely backs the transfer before signing.

### 2.3 Why the On-Chain Contract Cannot Fix This

```text
// The destination TokenBridge CANNOT defend against forged-event VAAs:
//   - It only sees a guardian-signed VAA, which IS validly signed.
//   - It has no view into Alephium's canonical state to re-check backing.
//   - Any added on-chain check would still trust the same (forged) payload.
//
// ✅ The fix MUST live in the guardian backend's event-authenticity logic
//    (Section 2.2) — re-derive from canonical state, pin the emitter, verify
//    collateral, and fail closed when authoritative confirmation is unavailable.
//
// On-chain measures (Section 6) can only CAP damage: mint rate limits,
// per-asset caps, and a guardian/governance pause.
```

---

## 3. Attack Flow

### 3.1 Preparation

**[Setup A] Deploy the forged-event contract on Alephium.**
The attacker deployed contract `24ZjqcvV8vVCn29zd1TThqAtaS8pMvJ4Co1MK5zncPcAB` on the Alephium chain. Its sole function is to **emit a `LOG7` transfer event** shaped to mimic a legitimate bridge transfer — with **no real deposit/collateral** behind it.

**[Setup B] Fund the ETH-side EOA.**
The attacker prepared the Ethereum redemption address `0x6681ebC82551fE52fDB48E65872e85a3ae06921d` to receive minted wALPH and execute Uniswap sales.

**[Setup C] Plan connectivity disruption.**
The attacker arranged to disrupt bridge-node connectivity in a window (~07:00–09:00 UTC) so the guardian backend would be forced onto its **fallback validation path** during the exploit.

### 3.2 Execution

**[Step 1 — ~07:00–09:00 UTC] Disrupt bridge nodes.**
The attacker degraded bridge-node connectivity, pushing the guardian backend off its primary (canonical re-derivation) path and onto the fallback path that accepts a structurally-valid `LOG7` without verifying backing.

**[Step 2 — forged event emission] Emit fabricated transfer events.**
The attacker's Alephium contract (`24Zjqcv…`) emitted forged `LOG7` transfer events. On the fallback path, the guardian backend observed these as genuine bridge transfers.

**[Step 3 — VAA signing] Guardians co-sign forged events.**
The genuine guardians co-signed the fabricated events into **valid VAAs**. The signatures are real; only the underlying event is forged.

**[Step 4 — 2026-05-30 ~09:16:59 UTC, ~64s execution] Redeem VAAs on ETH/BSC.**
The attacker submitted the VAAs to `completeTransfer()` on the ETH TokenBridge (`0x579a3bDE…`) and BSC TokenBridge (`0x2971F580…`). The contracts verified the VAA signatures (valid) and:
- **Minted 13.76M unbacked wALPH**, and
- **Released ~$305K of genuinely-backed collateral.**

The entire drain executed in roughly **64 seconds**.

**[Step 5 — monetization] Dump wALPH on Uniswap.**
The attacker sold **~500K wALPH on Uniswap** before the bridge could be paused, converting unbacked mint into real value and depressing the wALPH price.

**[Step 6 — response] Pause + burn + compensation.**
Alephium **paused the bridge**, **burned the remaining unbacked wALPH on June 2**, published an on-chain report attributing the loss to an off-chain backend edge case, and **promised compensation** to affected users.

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Alephium chain (PoW L1, BlockFlow sharded UTXO + stateful) │
│                                                             │
│  Attacker deploys FAKE-EVENT contract                       │
│  24ZjqcvV8vVCn29zd1TThqAtaS8pMvJ4Co1MK5zncPcAB              │
│  └─ emits forged LOG7 "transfer" event (NO real deposit)    │
└──────────────────────────────────┬──────────────────────────┘
                                   │
   ~07:00–09:00 UTC: attacker disrupts bridge-node connectivity
   → guardian backend forced onto FALLBACK validation path
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Off-chain GUARDIAN BACKEND  ← ❌ ROOT CAUSE                 │
│                                                             │
│  Fallback path accepts structurally-valid LOG7 WITHOUT      │
│  re-deriving backing from canonical state.                  │
│  Guardians (keys NOT stolen) genuinely co-sign forged event │
│  → produces VALID VAA over fabricated transfer              │
└──────────────────────────────────┬──────────────────────────┘
                                   │ valid (but forged-content) VAA
                ┌──────────────────┴───────────────────┐
                ▼                                       ▼
┌───────────────────────────────┐   ┌───────────────────────────────┐
│  ETH TokenBridge 0x579a3bDE…  │   │  BSC TokenBridge 0x2971F580…  │
│  completeTransfer(VAA)        │   │  completeTransfer(VAA)        │
│  ✓ VAA signature valid        │   │  ✓ VAA signature valid        │
│  → MINT unbacked wALPH        │   │  → MINT / release collateral  │
└───────────────┬───────────────┘   └───────────────┬───────────────┘
                │  2026-05-30 ~09:16:59 UTC (~64s)   │
                └──────────────────┬─────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Attacker EOA 0x6681ebC8…06921d                             │
│  • 13.76M unbacked wALPH minted                             │
│  • ~$305K backed collateral drained                        │
│  • ~500K wALPH dumped on Uniswap before pause              │
│  → headline ~$815K                                          │
└──────────────────────────────────┬──────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Alephium response: bridge PAUSED → unbacked wALPH BURNED   │
│  (June 2) → compensation promised                          │
└─────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Item | Amount | Approx. USD | Notes |
|------|--------|-------------|-------|
| Backed collateral drained | — | ~$305,000 | Real reserves released on ETH/BSC |
| Unbacked wALPH minted | 13,760,000 wALPH | (unbacked) | Created out of forged VAAs |
| wALPH sold on Uniswap | ~500,000 wALPH | (portion realized) | Dumped before pause |
| **Headline loss** | — | **~$815,000** | Per public reporting |
| Remediation | — | — | Unbacked wALPH burned June 2; compensation promised |

---

## 4. Vulnerability Classification

### 4.1 Classification Table

| ID | Vulnerability | Severity | CWE | Category | Similar Incidents |
|----|---------------|----------|-----|----------|-------------------|
| V-01 | Guardian backend signs VAAs for forged source-chain events | CRITICAL | CWE-345 | bridge-crosschain | Wormhole (2022) |
| V-02 | Fallback validation path accepts structural log without backing check | CRITICAL | CWE-20 | bridge-crosschain, business-logic | Wormhole |
| V-03 | Emitter not pinned to registered bridge contract | HIGH | CWE-345 | access-control | Wormhole |
| V-04 | Attacker-induced edge case (connectivity disruption) forces weak path | HIGH | CWE-754 | dos-as-precursor, monitoring | Multichain |

### 4.2 V-01 — Guardian Backend Signs Forged Events

- **Description**: The guardian backend co-signed VAAs for **fabricated** Alephium transfer events emitted by an attacker-deployed contract. The destination contracts then minted unbacked wALPH and released collateral against genuinely-signed VAAs. The keys were **not** stolen; the authenticity of the *observed event* was never established (CWE-345).
- **Impact**: 13.76M unbacked wALPH minted; ~$305K collateral drained; ~$815K headline.
- **Attack Preconditions**: Ability to deploy an event-emitting contract on Alephium + ability to force the backend onto its fallback path.

### 4.3 V-02 — Fallback Path Accepts Structural Log Without Backing

- **Description**: When bridge-node connectivity degraded, the backend fell back to accepting a structurally-valid `LOG7` without re-deriving the transfer from canonical state or verifying collateral backing. A fail-open fallback (CWE-20) is the proximate defect.
- **Impact**: Forged events became signable VAAs; the contract layer had no way to detect the forgery.
- **Attack Preconditions**: Backend on fallback path during the exploit window.

### 4.4 V-03 — Emitter Not Pinned to Registered Bridge

- **Description**: The fallback path did not verify that the `LOG7` originated from the **registered** Alephium bridge contract rather than an arbitrary attacker contract (`24Zjqcv…`). Pinning the emitter would have rejected the forged events outright (CWE-345).
- **Impact**: Any deployed contract could impersonate a bridge transfer source.
- **Attack Preconditions**: Backend trusting emitter-agnostic logs.

### 4.5 V-04 — Connectivity Disruption as an Attack Precursor

- **Description**: The attacker deliberately disrupted bridge-node connectivity (~07:00–09:00 UTC) to force the weaker fallback path — a denial-of-service used as a *precursor* to defeat authenticity checks (CWE-754: improper check for unusual conditions; fail-open under stress).
- **Impact**: Turned an "edge case" into a reliable exploitation window.
- **Attack Preconditions**: Ability to degrade bridge-node availability.

---

## 5. Comparison with Similar Incidents

| Incident | Date | Loss | Flaw Type | Difference from Alephium |
|----------|------|------|-----------|--------------------------|
| **Wormhole** | 2022-02 | ~$325M | Solana `verify_signatures` bypass → **forged guardian signatures** accepted | Wormhole forged the *signatures*; Alephium signatures were **genuine** over a **forged event** observed by real guardians |
| **Gravity Bridge** | 2026-05 | ~$5.4M | **Stolen validator signing keys** → genuine signatures, malicious actions | Gravity keys were **stolen**; Alephium keys were **not** — the backend was tricked into signing fake events |
| **Verus Bridge** | 2026-05 | ~$11.58M | Genuine notary signatures over **economically-invalid** payload (missing source-amount check) | Verus: missing *economic* validation in genuine signing. Alephium: missing *authenticity/backing* validation of the source event |
| **Multichain** | 2023-07 | ~$126M+ | Off-chain MPC key/operational compromise | Both are off-chain-trust failures; Alephium's is a *fail-open observation* edge case, not a custody compromise |
| **Alephium TokenBridge** | 2026-05 | ~$815K | Guardian backend signs VAAs for **attacker-forged transfer events** under a fallback path | Distinct: keys intact, signatures genuine, **event fabricated upstream** |

The defining contrast across the 2026 bridge cluster:
- **Wormhole (2022)** — forged *signatures*.
- **Gravity (2026)** — stolen *keys*, genuine signatures over legitimate-looking actions.
- **Verus (2026)** — genuine signatures, but **no economic-validation** of payload.
- **Alephium (2026)** — genuine signatures, but **no authenticity-validation** of the underlying source event.

Alephium and Verus are siblings: both have *correct cryptography* and a *missing semantic check*. Verus missed "does payout ≤ source deposit?"; Alephium missed "did this transfer event really happen, with real backing, from the real bridge contract?" Both belong to the **bridge-crosschain** vulnerability class (see [`../vulns/bridge-crosschain.md`](../vulns/bridge-crosschain.md)).

---

## 6. Remediation Recommendations

> **Important**: The root cause is in the **off-chain guardian backend**, so the primary fix is there. On-chain measures only cap blast radius.

### 6.1 Off-Chain: Fail-Closed Event Authentication (primary fix)

```typescript
// ✅ Never sign on a structural-only fallback. Re-derive from canonical state.
async function observeTransferEvent(log: AlephiumLog): Promise<VAA | null> {
    const ev = parseTransferLog(log);

    // (a) Pin the emitter to the registered bridge contract.
    if (ev.emitter !== REGISTERED_ALEPHIUM_BRIDGE_CONTRACT) return null;

    // (b) Re-derive the event from canonical chain state (no structural shortcut).
    if (!(await confirmAgainstCanonicalState(ev.txId, ev.eventIndex))) return null;

    // (c) Verify real collateral backs the transfer before authorizing a mint.
    if (!(await verifyCollateralLocked(ev.tokenId, ev.amount, ev.txId)).ok) return null;

    // (d) Fail CLOSED: if authoritative confirmation is unavailable, do NOT sign.
    return signVAA(ev);
}
```

### 6.2 Off-Chain: Robust Node Connectivity & Quorum

```text
1. Require independent quorum of healthy bridge nodes before signing; if the
   quorum cannot be reached, halt signing (fail closed) rather than fall back.
2. Diversify node infrastructure/providers so a single connectivity disruption
   cannot push all guardians onto a degraded path.
3. Treat sudden bridge-node connectivity loss as a SECURITY event (alert + pause),
   not merely an availability issue.
```

### 6.3 On-Chain: Mint Rate Limits & Caps (blast-radius cap)

```solidity
// ✅ Cap how much wrapped supply can be minted per window. Does NOT prevent a
//    forged-VAA mint, but bounds it — 13.76M wALPH in ~64s would have tripped this.
uint256 public mintWindowStart;
uint256 public mintedThisWindow;
uint256 constant MINT_WINDOW = 1 hours;
uint256 constant MINT_CAP_PER_WINDOW = 250_000e18; // tune to real volume

function _guardedMint(address to, uint256 amount) internal {
    if (block.timestamp >= mintWindowStart + MINT_WINDOW) {
        mintWindowStart = block.timestamp;
        mintedThisWindow = 0;
    }
    require(mintedThisWindow + amount <= MINT_CAP_PER_WINDOW, "mint cap exceeded");
    mintedThisWindow += amount;
    TokenImplementation(/*...*/).mint(to, amount);
}
```

### 6.4 On-Chain: Guardian/Governance Pause

```solidity
// ✅ Allow a guardian/governance role to pause completeTransfer() instantly.
bool public paused;
address public pauser;

modifier whenNotPaused() { require(!paused, "paused"); _; }

function pause() external { require(msg.sender == pauser, "only pauser"); paused = true; }

function completeTransfer(bytes memory encodedVm) public whenNotPaused { /* ... */ }
```

### 6.5 Structural

| Weakness | Recommended Fix |
|----------|-----------------|
| Fail-open fallback validation | Fail-closed: re-derive from canonical state or do not sign (6.1) |
| Emitter not pinned | Reject events not from the registered bridge contract (6.1a) |
| No mint rate limit | Per-window mint caps (6.3) |
| No instant pause | Guardian/governance pause on `completeTransfer` (6.4) |
| Connectivity loss = silent fallback | Treat as security event; quorum-or-halt (6.2) |

---

## 7. Lessons Learned

1. **"Genuine signature" does not mean "genuine event."** Alephium's guardians really signed the VAAs — over a **fabricated** source event. Verifying signatures on the destination chain (CWE-345) is necessary but useless if the *content* being signed was forged upstream.
2. **Fallback paths must fail closed.** The exploit hinged on a degraded-mode path that accepted a structural log without re-deriving backing. Any signing system must refuse to sign when it cannot authoritatively confirm — never downgrade to a weaker check under stress.
3. **Pin the emitter.** Treating any contract's `LOG7` as a bridge transfer let an attacker-deployed contract impersonate the bridge. Authentic source events must originate from the *registered* bridge contract only.
4. **Availability attacks are authenticity attacks.** The attacker used a connectivity disruption (a DoS) as a *precursor* to force the weak validation path (CWE-754). Bridge-node connectivity loss must be treated as a security incident, not a mere uptime blip.
5. **Rate limits and pauses are the last line of defense.** Minting 13.76M unbacked wALPH in ~64 seconds would have tripped a per-window mint cap or been stoppable by an instant pause. These do not fix the root cause but would have sharply bounded the loss.
6. **Wormhole-fork bridges inherit Wormhole's trust assumptions — and its blast radius.** Forking the guardian/VAA model means inheriting the requirement that the off-chain observation layer be bulletproof. The contract layer cannot compensate for a guardian backend that signs forged events.

---

## 8. On-Chain Verification

> **Synthetic-hash warning**: The transaction hash provided for this incident — `0x9fb1ee5593e6f083aa7cd9a1fe42bea82b552c7654564eff058985ffb354302f` — was **NOT found on-chain**. It is a one-nibble mutation of a real Gravity Bridge transaction (`0xafb1ee55…302f`, leading `0xafb…` → `0x9fb…`) and does **not** correspond to any Alephium-incident transaction. It must not be cited as evidence. The verification below relies on the **addresses and on-chain report** published by Alephium and corroborating writeups.

### 8.1 Provided (Synthetic) Hash — Flagged

| Field | Value |
|-------|-------|
| Provided tx hash | `0x9fb1ee5593e6f083aa7cd9a1fe42bea82b552c7654564eff058985ffb354302f` |
| Status | **NOT FOUND on-chain (synthetic)** |
| Origin | One-nibble mutation of Gravity Bridge tx `0xafb1ee5593e6f083aa7cd9a1fe42bea82b552c7654564eff058985ffb354302f` |
| Disposition | Excluded from evidence; analysis based on verified addresses + Alephium's official on-chain report |

### 8.2 Verified Addresses

| Role | Address | Chain |
|------|---------|-------|
| Attacker EOA (redemption / Uniswap) | [0x6681ebC82551fE52fDB48E65872e85a3ae06921d](https://etherscan.io/address/0x6681ebC82551fE52fDB48E65872e85a3ae06921d) | Ethereum |
| ETH TokenBridge (vulnerable) | [0x579a3bDE631c3d8068CbFE3dc45B0F14EC18dD43](https://etherscan.io/address/0x579a3bDE631c3d8068CbFE3dc45B0F14EC18dD43) | Ethereum |
| BSC TokenBridge (vulnerable) | [0x2971F580C34d3D584e0342741c6a622f69424dD8](https://bscscan.com/address/0x2971F580C34d3D584e0342741c6a622f69424dD8) | BNB Chain |
| wALPH token (ETH) | [0x590f820444fa3638e022776752c5eef34e2f89a6](https://etherscan.io/address/0x590f820444fa3638e022776752c5eef34e2f89a6) | Ethereum |
| Fake-event contract | `24ZjqcvV8vVCn29zd1TThqAtaS8pMvJ4Co1MK5zncPcAB` | Alephium |

### 8.3 Timeline (per Alephium official report)

| Time (UTC) | Event |
|-----------|-------|
| 2026-05-29 17:16:00 | Source-list incident date (see header note) |
| 2026-05-30 ~07:00–09:00 | Attacker disrupts bridge-node connectivity → backend on fallback path |
| 2026-05-30 09:16:59 | Forged-VAA drain executed over ~64 seconds |
| 2026-05-30 (after) | Bridge paused; ~500K wALPH already dumped on Uniswap |
| 2026-06-02 | Remaining unbacked wALPH burned; compensation promised |

### 8.4 Loss Composition

| Item | Amount | Approx. USD |
|------|--------|-------------|
| Backed collateral drained | — | ~$305K |
| Unbacked wALPH minted | 13,760,000 | (unbacked) |
| wALPH sold on Uniswap | ~500,000 | (portion realized) |
| **Headline** | — | **~$815K** |

### 8.5 Verification Method

Because the provided ETH tx hash is synthetic, on-chain confirmation rests on: (a) the **attacker EOA** and **TokenBridge/wALPH contract addresses** above (verifiable on Etherscan/BscScan), (b) Alephium's **official on-chain report** describing the off-chain backend edge case and the ~09:16:59 UTC / ~64s drain, and (c) corroborating coverage (The Defiant, BeInCrypto, CryptoTimes). The 13.76M wALPH mint and subsequent June 2 burn are observable via the wALPH token contract's mint/burn events.

---

## 9. References

- [Alephium — "The Alephium Bridge Exploit: On-Chain Report"](https://alephium.org/news/post/the-alephium-bridge-exploit-on-chain-report/)
- [The Defiant — "Alephium Bridge loses $815K to forged guardian messages"](https://thedefiant.io/news/hacks/alephium-bridge-815k-forged-guardian-messages)
- [BeInCrypto — "Alephium bridge exploit: forged messages"](https://beincrypto.com/alephium-bridge-exploit-forged-messages/)
- [CryptoTimes — "Alephium bridge exploited for $815K, 13.76M unbacked ALPH minted"](https://www.cryptotimes.io/2026/05/30/alephium-bridge-exploited-for-815k-13-76m-unbacked-alph-minted/)
- [Alephium Wormhole-fork (GitHub)](https://github.com/alephium/wormhole-fork)
- [Attacker EOA (Etherscan)](https://etherscan.io/address/0x6681ebC82551fE52fDB48E65872e85a3ae06921d)
- [ETH TokenBridge (Etherscan)](https://etherscan.io/address/0x579a3bDE631c3d8068CbFE3dc45B0F14EC18dD43)
- [wALPH token (Etherscan)](https://etherscan.io/address/0x590f820444fa3638e022776752c5eef34e2f89a6)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
- Related: [Bridge / Cross-Chain vulnerability class](../vulns/bridge-crosschain.md), [Gravity Bridge (2026)](./2026-05-30_GravityBridge_ValidatorSigningKeyCompromise_ETH.md), [Verus Ethereum Bridge (2026)](./2026-05-18_VerusBridge_SourceAmountValidationBypass_ETH.md)
