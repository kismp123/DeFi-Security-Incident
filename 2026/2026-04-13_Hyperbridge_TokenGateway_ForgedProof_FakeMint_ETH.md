# Hyperbridge — TokenGateway Forged-Proof Admin Takeover & Fake Mint (Ethereum)

| Item | Details |
|------|------|
| **Date** | 2026-04-13 (UTC 03:39 – 05:08) |
| **Protocol** | Hyperbridge (ISMP / TokenGateway on Ethereum) |
| **Chain** | Ethereum |
| **Loss** | ~108.2 ETH (~$237,000) actually realized; ~1 billion bridged DOT forged (theoretical ~$1.17B at mid-market, but pool liquidity was too thin to monetize) |
| **Attacker EOA** | [0xC513E4f5…F1F8E7](https://etherscan.io/address/0xC513E4f5D7a93A1Dd5B7C4D9f6cC2F52d2F1F8E7) |
| **Attack Hub Contract** | [0x365084B0…bAB5b8](https://etherscan.io/address/0x365084B05Fa7d5028346bD21D842eD0601bAB5b8) (master attack contract) |
| **Vulnerable HandlerV1** | 0x6c8…4E6D64 (ISMP message handler) |
| **Fake-Bridged DOT Token** | [0x8d010bf9…8F90b8](https://etherscan.io/address/0x8d010bf9C26881788b4e6bf5Fd1bdC358c8F90b8) |
| **Additional Forged Tokens** | 0x6A9143…55155, 0x64CBd3…5f01 |
| **Monetization Venue** | Uniswap V4 PoolManager [0x00000000…08A90](https://etherscan.io/address/0x000000000004444c5dc75cB358380D2e3dE08A90), Uniswap V3 USDC/DAI/WETH pools |
| **Block Range** | 24,868,216 – 24,868,658 |
| **Root Cause** | HandlerV1 accepts a forged ISMP state proof; TokenGateway.onAccept() executes a `ChangeAssetAdmin` action that transfers admin / minter role to the attacker, who then mints arbitrary bridged ERC20s |

---

## 1. Vulnerability Overview

Hyperbridge is a coprocessor-style bridge that relays cross-chain state via ISMP (Interoperable State-Machine Protocol). Its Ethereum-side **TokenGateway** trusts messages delivered through `HandlerV1`, which in turn verifies Merkle Mountain Range (MMR) state proofs from the Hyperbridge consensus.

`HandlerV1.handlePostRequest(...)` **failed to correctly validate an attacker-supplied proof**: either a missing root check, a replay of a historical MMR leaf, or insufficient domain separation in the verifier. Once past the proof check, TokenGateway treated the message as canonical and invoked one of its privileged handlers — specifically `ChangeAssetAdmin` — which rewrote the `admin` / `minter` slot of a bridged ERC20 to an attacker-controlled address.

With mint authority over the fake "bridged DOT" ERC20 (`0x8d01…90b8`) and two sibling bridged-asset tokens, the attacker minted up to **1,000,000,000 tokens** per asset, then routed them through Uniswap V4 and legacy V3 pools to extract ~**108.2 ETH** (≈ $237K). The discrepancy between the theoretical ~$1.17B face value and the actual loss is entirely a **liquidity cap**: the bridged-DOT markets were too shallow to absorb more than a few hundred ETH of sell-pressure before collapsing to zero price.

---

## 2. Attack Flow

### 2.1 Overview
```
[Setup, tx1]  attacker borrows/acquires DAI (423.18 DAI from 0x792A…) for gas & slippage buffer
       │
       ▼
[Proof Forgery, tx2–tx7]  master contract 0x365084… submits forged ISMP proof
       │     HandlerV1 accepts  →  TokenGateway.onAccept(ChangeAssetAdmin)
       │                         →  attacker becomes admin/minter of bridged ERC20
       ▼
[Mint]  bridged DOT (and siblings) minted from 0x0 to fresh per-tx recipient
       │       (Tx2: 1e9, Tx4: 1e4, Tx5: 1e6, Tx6: 7.12e5, Tx7: 1e3; total ≈ 1.0017B DOT)
       ▼
[Monetize] minted tokens pulled into hub 0x365084… then
           forwarded to Uniswap V4 PoolManager (0x000000…08A90)
           swapped for WETH / USDC through V4 + V3 pools
       ▼
[Exit]  ~108.2 ETH to attacker EOA 0xC513E4F5…F1F8E7
```

### 2.2 Per-Transaction Trace

| # | Tx Hash | Block | Role | Key Effect |
|---|---------|-------|------|------------|
| 1 | 0xfa23fb22…61b6f6 | 24,868,216 | Gas/DAI preparation | 423.18 DAI routed 0x792A… → 0x989F17… → 0x3269Bf4… |
| 2 | 0x240aeb9a…401109 | 24,868,295 | **First forgery mint** | 1,000,000,000 bridged DOT minted → Uniswap V4 PoolManager |
| 3 | 0xb28ab952…f8ac09 | 24,868,422 | **Multi-token forgery** | Mints 1B of token `0x6A9143…55155` and 1B of `0x64CBd3…5f01`; swaps chunks for USDC / WETH on V3 pools; sinks ~1e27 of `0x6A91…` to attacker EOA |
| 4 | 0xb80c7d4c…443c3a | 24,868,450 | Mint + V4 swap | 10,000 DOT → PoolManager → 0.00677 WETH back to recipient |
| 5 | 0x743f4bdb…227125 | 24,868,484 | Mint to V4 | 1,000,000 DOT → PoolManager |
| 6 | 0x6f1efcde…0a0808 | 24,868,577 | DAI/WETH swap + mint | 0.493 DAI ↔ 0.000225 WETH on Uniswap V3 DAI/WETH, then 712,403 DOT minted → PoolManager |
| 7 | 0xb93aab83…4a0634 | 24,868,658 | Mint to V4 | 1,000 DOT → PoolManager |

All seven transactions share subject EOA `0xC513E4f5…F1F8E7` and hub `0x365084B0…bAB5b8`, and they terminate in the canonical Uniswap V4 PoolManager address `0x000000000004444c5dc75cB358380D2e3dE08A90`.

### 2.3 Tokens Minted from Zero Address
These `from = 0x000…0` entries confirm the attacker held genuine `mint()` authority (not a pool drain):

| Token | Symbol (as deployed) | Total Minted in this Campaign |
|-------|----------------------|-------------------------------|
| 0x8d010bf9…8F90b8 | bridged DOT (Hyperbridge) | 1,001,723,403 DOT |
| 0x6A9143…55155 | (bridged asset A) | 1,000,000,000 |
| 0x64CBd3…5f01 | (bridged asset B) | 1,000,000,000 |

---

## 3. Vulnerable Design

### 3.1 HandlerV1 proof acceptance (conceptual)

```solidity
function handlePostRequest(PostRequest calldata req, MmrProof calldata proof) external {
    // ❌ The committed root, leaf index, or commitment hash is not rebound to
    //    (sourceChain, nonce, destChain). A replayed or rotated-root leaf is
    //    accepted as fresh.
    require(_verifyMmr(proof.root, proof.leaf, proof.indices), "bad proof");

    IDispatcher(destModule).onAccept(req);  // trusts the payload
}
```

### 3.2 TokenGateway.onAccept privileged branch

```solidity
function onAccept(PostRequest calldata req) external onlyHandler {
    Action action = abi.decode(req.body, (Action));
    if (action.kind == ActionKind.ChangeAssetAdmin) {
        // ❌ No domain check that req came from the registered Hyperbridge
        //    hyperbridge.stateMachine (relies purely on HandlerV1 trust).
        assetAdmin[action.asset] = action.newAdmin;
        IBridgedERC20(action.asset).setMinter(action.newAdmin);
    }
    // ...
}
```

Because HandlerV1 accepted a forged proof, the `ChangeAssetAdmin` action was treated as canonical and the bridged ERC20 handed its `minter` role over to the attacker's contract.

### 3.3 Why liquidation cap was $237K, not $1.17B

Uniswap V4 bridged-DOT pool depth was tiny (a few WETH of reserve). Each mint-and-dump round collapsed price geometrically; the marginal ETH-out curve bent to zero well before 1B DOT had been sold. The attacker realized that further minting produced no marginal ETH, and stopped at tx7.

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|---------------|----------|-----|
| V-01 | Forged / replayed MMR proof accepted by HandlerV1 | CRITICAL | CWE-347 (Improper Verification of Cryptographic Signature) |
| V-02 | TokenGateway `ChangeAssetAdmin` action lacks origin-chain / admin-sender check | CRITICAL | CWE-284 (Improper Access Control) |
| V-03 | Bridged ERC20 `setMinter` callable without delay / timelock | HIGH | CWE-732 (Incorrect Permission Assignment for Critical Resource) |
| V-04 | No per-asset mint rate limit on TokenGateway mints | HIGH | CWE-770 (Allocation without Limits) |

### V-01 — Forged Proof Acceptance
Attackers can mint any bridged asset if they can craft a proof HandlerV1 accepts. Remediation: bind proof context to `(sourceStateMachine, nonce, body hash)` and ensure the MMR root is the *current* committed root, not any historically valid root.

### V-02 — Privileged Payload Without Origin Check
`ChangeAssetAdmin` should require that the decoded request originated from the hyperbridge governance state-machine (`req.source == HYPERBRIDGE_STATEMACHINE && req.sender == HB_GOV`).

### V-03 — Instant Admin Rotation
Transferring mint authority should go through a time-locked two-step handoff rather than immediate write.

### V-04 — Unlimited Mint
A rolling per-epoch mint cap per bridged asset would have reduced the worst case from "pool depth" to the cap.

---

## 5. Remediation (Post-Incident)

1. **Pause Ethereum TokenGateway** (performed) and all bridged-asset mints.
2. **Patch HandlerV1** proof verification: rebind MMR leaf → `keccak256(abi.encode(sourceStateMachine, destStateMachine, nonce, body))` and forbid root reuse.
3. **Harden onAccept**: explicit allow-list of (source, sender) for `ChangeAssetAdmin` / `ChangeAssetOwner` / `ChangeAssetDecimals` actions.
4. **Timelock + multisig** on bridged ERC20 `setMinter`.
5. **Per-asset mint caps** and emergency circuit breaker triggered by sudden mint > cap × N.
6. **Blacklist** attacker EOA `0xC513E4…F1F8E7` and hub `0x365084…bAB5b8` at the TokenGateway level.

---

## 6. Lessons Learned

1. **Proof verifier bugs are terminal for bridges**: once a forged proof is accepted, every privileged handler downstream is attacker-controllable. HandlerV1 is the single point where trust is established — it must be audited with the same rigor as a consensus-layer verifier.
2. **Privileged bridge payloads need redundant checks**: even with a perfect proof verifier, actions like `ChangeAssetAdmin` should re-check origin inside the destination contract. Defense in depth means the attack also has to corrupt the origin check, not just the proof.
3. **Pool depth is a loss limiter, not a defense**: the attacker forged $1.17B of face value and could only monetize 0.02% of it. That is luck, not security — the same bug on a deeply liquid asset would have been catastrophic. Rate limits and timelocks are the real defenses.
4. **Time-windowed admin rotations beat instant ones**: an instant-effective `setMinter` turned a proof-verifier bug into an 80-minute $237K loss. With a 24-hour timelock, the same bug would have been caught and reversed by monitoring before any mint completed.
5. **Bridged-asset ERC20 wrappers are not "just ERC20s"**: their `minter` slot is a cross-chain trust root. Governance around it must match the bridge's consensus trust model.

---

## 7. Additional Information

- **Related same-day incident**: OpenUSDT (oUSDT) Hyperlane warp-route USDC/USDT arbitrage (attacker `0x8Fb4…290E`, ~410K USDC) — unrelated protocol (Hyperlane ≠ Hyperbridge) but same 24-hour window.
- **Monetization pool**: Uniswap V4 PoolManager `0x000000000004444c5dc75cB358380D2e3dE08A90` is the canonical V4 singleton. Attacker also touched Uniswap V3 USDC/WETH pool `0x88e6A0c2DDD26FEEb64F039a2c41296FcB3f5640` and DAI/WETH pool `0x60594a405d53811d3BC4766596EFD80fd545A270`.
- **DAI source** `0x792A6236AF69787C40cF76b69B4c8c7B28c4cA20`: contract delivering initial 423.18 DAI used as swap seed in tx1 / tx6.
- **Token classification**: the "bridged DOT" ERC20 is a Hyperbridge-issued wrapper with a governable `minter` slot — mint authority, not reserve drain, was the exploited surface.

| Address | Role |
|---------|------|
| 0xC513E4f5D7a93A1Dd5B7C4D9f6cC2F52d2F1F8E7 | Attacker EOA (tx subject) |
| 0x365084B05Fa7d5028346bD21D842eD0601bAB5b8 | Attacker master / hub contract |
| 0x8d010bf9C26881788b4e6bf5Fd1bdC358c8F90b8 | Fake bridged DOT (exploited wrapper) |
| 0x6A9143639D8b70D50b031fFaD55d4CC65EA55155 | Bridged asset A (minted 1B) |
| 0x64CBd3aa07d427E385Cb55330406508718E55f01 | Bridged asset B (minted 1B) |
| 0x000000000004444c5dc75cB358380D2e3dE08A90 | Uniswap V4 PoolManager (monetization) |
| 0x88e6A0c2DDD26FEEb64F039a2c41296FcB3f5640 | Uniswap V3 USDC/WETH 0.05% |
| 0x60594a405d53811d3BC4766596EFD80fd545A270 | Uniswap V3 DAI/WETH |
| 0x6B175474E89094C44Da98b954EedeAC495271d0F | DAI |
| 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 | USDC |
| 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 | WETH |
