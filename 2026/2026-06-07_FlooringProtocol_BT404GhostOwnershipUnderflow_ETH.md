# Flooring Protocol — BT404 Ghost-Ownership Underflow Exploit Analysis

| Field | Details |
|-------|---------|
| **Date** | 2026-06-07 16:16:00 UTC (widely reported June 7–8, 2026) |
| **Protocol** | Flooring Protocol (formerly Floor Protocol) — NFT fractionalization; "fp" hybrid tokens use the **BT404** standard (a DN404 / ERC-404-style fork mirroring an ERC-20 `fpToken` with its NFT inside one contract) |
| **Chain** | Ethereum |
| **Total Loss** | **~$1.5M – $1.6M** (NFTs ultimately sold on Blur). On-chain direct drain ~$40K. Yuga Labs + whitehat "Quit" rescued **68 blue-chip NFTs** ($500K+: 29 BAYC, 4 MAYC, 2 CryptoPunks) |
| **Attacker (fpCloneX pool)** | [0x223CBC5B...FcAbb](https://etherscan.io/address/0x223CBC5B865A96ddA75D3b0A98536De4f49FcAbb) |
| **Attacker (fpCyberKongz pool)** | [0x5a0416fb...2e49](https://etherscan.io/address/0x5a0416fbAFc21D8f45a355E6cA6fD66f2acA2e49) |
| **Vulnerable Contract** | BT404 hybrid token implementation (per-pool `fp*` clones; e.g. `fpCloneX`, `fpCyberKongz`) — bit-packed NFT ownership/index bookkeeping |
| **Attack Tx (fpCLNX pool)** | [0x5abc52a4...0aaad](https://etherscan.io/tx/0x5abc52a438734151ebd2cc122f7ae86ed04a390a6dc884f04abd679ed380aaad) (REAL, verified) |
| **Attack Tx (fpCKBB pool)** | [0xb139f048...b26a](https://etherscan.io/tx/0xb139f048033a9205c5a62ca43016263cfcca9bab74c48fdc06f43bd29307b26a) (REAL, verified) |
| **Entry Selector / Function** | Transfer/unwrap/burn path on the BT404 hybrid token, triggered with a forged high-bit token-ID alias |
| **Root Cause** | BT404 packs NFT ownership/indexing into bitfields for gas. A forged high-bit token-ID alias makes the ownership check record the attacker as owner ("ghost ownership"); a subsequent unchecked balance subtraction underflows past zero, wrapping the `fpToken` balance to ~2²⁵⁶ (near-infinite) |
| **GitHub / Source** | Reference standard: https://github.com/Vectorized/dn404 — BT404 specifics not fully public; BT404 code here is **reconstructed/estimated** |
| **Source Verification** | Attack transactions verified on Etherscan. BT404 source is not fully public; Solidity in §2 is reconstructed from the DN404 reference standard with the bit-packing + underflow annotated. |

---

## 1. Vulnerability Overview

Flooring Protocol (formerly Floor Protocol) is an NFT fractionalization platform. Users deposit (wrap) an NFT and receive a fungible **`fpToken`** — an ERC-20 representation of that NFT — and can later redeem (unwrap) an `fpToken` back into an underlying NFT. To make this efficient, Flooring's "fp" hybrid assets use the **BT404 standard**, a fork of DN404 / ERC-404 in which a single contract mirrors an ERC-20 balance against an ERC-721 collection: minting `fpToken` mints/assigns NFTs, and burning `fpToken` burns/releases NFTs, all kept in sync inside one contract.

DN404-style designs are notoriously delicate because they maintain **two accounting systems that must stay perfectly synchronized**: fungible balances and discrete NFT ownership. BT404 went further than DN404 by **packing NFT ownership and per-owner index data into bitfields** to save gas. Those gas-saving bit-level routines are exactly where the vulnerability lived — code subtle enough that it escaped audit and then propagated into multiple BT404 forks.

On 2026-06-07, an attacker drained two Flooring pools — **fpCloneX** and **fpCyberKongz** — using a two-part primitive:

1. **Ghost / phantom ownership.** BT404 derives ownership and index slots from packed token-ID bits. By supplying a **forged high-bit token-ID alias** — a token ID the attacker does not actually hold but which collides into the same packed bookkeeping slot — the ownership check and the internal index update record the **attacker as the owner** of a token they never legitimately owned.

2. **Unchecked underflow → near-infinite balance.** Acting on that ghost ownership, the subsequent transfer/unwrap/burn path performs an **unchecked balance subtraction**. Because the attacker's real balance for the aliased position is zero, the subtraction underflows past zero and **wraps the `fpToken` balance to ~2²⁵⁶** (near-infinite).

With a near-infinite `fpToken` balance, the attacker dumped tokens into the **Uniswap V3 `fpToken`/WETH pool**, crashing the price toward zero while extracting the pool's WETH liquidity, and then **redeemed the underlying blue-chip NFTs cheaply** with the now-worthless-but-abundant `fpToken`. The rescued and stolen NFTs (BAYC, MAYC, CloneX, CyberKongz, CryptoPunks) were the real prize; stolen NFTs were sold on **Blur**.

This is a **CWE-191 integer underflow** combined with a **CWE-345 / CWE-840 ownership-accounting** flaw. The same bug class affected downstream BT404 forks (e.g. BitmapPunks `$BMP`, Asterix).

---

## 2. Vulnerable Code Analysis

> **Reconstruction notice:** BT404's exact source is not fully public. The code below is **reconstructed/estimated** from the DN404 reference implementation (`github.com/Vectorized/dn404`) with BT404's bit-packing and the unchecked-subtraction site annotated. It illustrates the *mechanism* of the exploit; it is not a verbatim copy of the deployed BT404 bytecode.

### 2.1 Packed Ownership Bookkeeping — Ghost Ownership (❌ vulnerable)

DN404/BT404 stores NFT ownership and the per-owner index in packed words to save gas. BT404's variant derives the storage slot and the ownership flag from token-ID bits. When a **high-bit alias** of a token ID is supplied, it collides into a slot the attacker can influence, so the ownership predicate returns true for a token the attacker does not hold.

```solidity
// BT404 (reconstructed) — packed ownership + index, gas-optimized
// Ownership data for a token id is packed: [ ownerAddress(160) | indexData(88) | flags(8) ]
mapping(uint256 => uint256) internal _ownershipData; // tokenId(aliased) => packed

function _ownerAt(uint256 id) internal view returns (address owner) {
    // ❌ The aliased/high-bit id is masked into a packed slot WITHOUT validating
    //    that `id` is a real, in-range, currently-minted token id.
    uint256 packed = _ownershipData[_aliasOf(id)];
    owner = address(uint160(packed));
}

function _aliasOf(uint256 id) internal pure returns (uint256) {
    // ❌ High bits are truncated to derive the storage key. Two DISTINCT ids
    //    (a real one and an attacker's forged high-bit id) collapse to the
    //    SAME key — the core "ghost ownership" collision.
    return id & 0xffffffffff; // 40-bit truncation (illustrative)
}

function _setOwnerAndIndex(uint256 id, address owner, uint256 index) internal {
    // ❌ Records the CALLER as owner of the aliased slot. No check that the
    //    caller legitimately holds `id`; the packed write simply trusts `id`.
    _ownershipData[_aliasOf(id)] =
        uint256(uint160(owner)) | (index << 160);
}
```

The decisive flaw: `_aliasOf()` truncates the token ID to form the storage key, so a forged high-bit ID (e.g. `id | (1 << 200)`) maps to the **same packed slot** as a legitimate token. `_setOwnerAndIndex()` then writes the attacker as owner of that slot with **no verification that the attacker actually holds the underlying token** — establishing *ghost ownership*.

### 2.2 Transfer / Unwrap / Burn — Unchecked Underflow (❌ vulnerable)

Once ghost ownership is established, the fungible side performs an **unchecked subtraction** of the `fpToken` balance. With the attacker's true balance for the aliased position at zero, the subtraction wraps:

```solidity
mapping(address => uint256) internal _balanceOf; // fpToken (ERC-20 side)

function _transferFromNFT(address from, address to, uint256 id) internal {
    require(_ownerAt(id) == from, "NOT_OWNER"); // ❌ passes via ghost ownership

    // The hybrid keeps fungible balance in sync with NFT moves.
    unchecked {
        // ❌ from's real fpToken balance for this position is 0.
        //    0 - _unit underflows and WRAPS to ~2**256.
        _balanceOf[from] -= _unit;          // underflow
        _balanceOf[to]   += _unit;
    }

    _setOwnerAndIndex(id, to, _nextIndex());
    emit Transfer(from, to, _unit);
}
```

Because the arithmetic sits inside an `unchecked { }` block (used throughout DN404-style code for gas), the underflow is **not reverted**. The attacker's `fpToken` balance becomes ~`2²⁵⁶ − _unit` — effectively infinite mintless supply.

### 2.3 Fixed Code (✅)

The fix is twofold: validate token-ID provenance before trusting packed ownership, and never allow the balance subtraction to underflow.

```solidity
function _aliasOf(uint256 id) internal pure returns (uint256) {
    // ✅ Reject ids outside the legitimate minted range BEFORE deriving a key.
    require(id != 0 && id <= _MAX_TOKEN_ID, "BAD_TOKEN_ID");
    return id; // ✅ no lossy truncation → no slot collision / aliasing
}

function _transferFromNFT(address from, address to, uint256 id) internal {
    // ✅ Authoritative ownership check against a collision-free key.
    require(_ownerAt(id) == from, "NOT_OWNER");

    // ✅ Checked subtraction: an attempt to move a position the holder does
    //    not actually back reverts instead of wrapping.
    uint256 bal = _balanceOf[from];
    require(bal >= _unit, "INSUFFICIENT_BALANCE"); // ✅ underflow guard
    _balanceOf[from] = bal - _unit;
    _balanceOf[to]  += _unit;

    _setOwnerAndIndex(id, to, _nextIndex());
    emit Transfer(from, to, _unit);
}
```

> Removing the unchecked underflow alone closes the drain primitive; eliminating the alias truncation closes the ghost-ownership primitive. Both are required for defense in depth.

---

## 3. Attack Flow

### 3.1 Preparation

- The attacker identified that BT404's **bit-packed ownership bookkeeping** could be aliased by a forged high-bit token ID and that the synchronized fungible-side subtraction was **unchecked**.
- Two separate attacker EOAs were used, one per targeted pool: `0x223CBC5B…FcAbb` for **fpCloneX** and `0x5a0416fb…2e49` for **fpCyberKongz**.
- The targets were liquid **Uniswap V3 `fpToken`/WETH pools** holding meaningful WETH, backed by blue-chip NFT reserves (CloneX, CyberKongz, plus blue chips reachable via Flooring's pools).

### 3.2 Execution

**[Step 1] Forge a high-bit token-ID alias → ghost ownership**
The attacker calls the BT404 transfer/unwrap path with a **forged high-bit token-ID alias** that collides into a packed ownership slot. The ownership check and index bookkeeping record the attacker as owner of a token they never held.

**[Step 2] Trigger the unchecked underflow → near-infinite `fpToken`**
Acting on the ghost ownership, the transfer/unwrap/burn path subtracts `_unit` from the attacker's zero real balance inside an `unchecked` block. The balance **underflows past zero**, wrapping to ~2²⁵⁶ `fpToken`.

**[Step 3] Dump into Uniswap V3 → drain WETH**
With a near-infinite `fpToken` supply, the attacker sells `fpToken` into the `fpToken`/WETH V3 pool, **crashing the `fpToken` price toward zero** and extracting the pool's WETH liquidity. In the fpCKBB trace, a single swap of **"40,000,000,000 fpCKBB → 5.861 ETH"** is visible.

**[Step 4] Redeem underlying NFTs cheaply**
With abundant `fpToken`, the attacker unwraps/redeems the **underlying blue-chip NFTs** at near-zero effective cost. Traces show heavy ERC-721 movement — TX1 (fpCLNX) includes **192 ERC-721 transfers** (fpCloneX mint/burn to `rtfkt.liquidity.flooringlab.eth`); TX2 (fpCKBB) includes **41 ERC-721 CyberKongz transfers**.

**[Step 5] Monetize / rescue**
Stolen NFTs were sold on **Blur**. Separately, **Yuga Labs and whitehat "Quit"** executed a counter-operation that **rescued 68 blue-chip NFTs** (29 BAYC, 4 MAYC, 2 CryptoPunks, $500K+) before the attacker could extract them.

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Attacker EOA (per pool)                                    │
│  fpCloneX: 0x223CBC5B…FcAbb   fpCyberKongz: 0x5a0416fb…2e49 │
└──────────────────────────────────┬──────────────────────────┘
                                   │ forged high-bit token-id alias
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  BT404 hybrid token  (fp* clone, bit-packed bookkeeping)    │
│                                                             │
│  [1] _aliasOf(id) truncates high bits → SLOT COLLISION       │
│      _ownerAt(id) == attacker  → 👻 GHOST OWNERSHIP          │
│                                                             │
│  [2] unchecked { balanceOf[attacker] -= _unit; }            │
│      0 - _unit  →  UNDERFLOW  →  ~2^256 fpToken              │
└──────────────────────────────────┬──────────────────────────┘
                                   │ near-infinite fpToken
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Uniswap V3  fpToken / WETH pool                            │
│  dump fpToken → price ≈ 0 → drain WETH                       │
│  (fpCKBB: 40,000,000,000 fpCKBB → 5.861 ETH)                │
└──────────────────────────────────┬──────────────────────────┘
                                   │ cheap fpToken
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Redeem underlying NFTs cheaply                             │
│  TX1: 192 ERC-721 (fpCloneX)   TX2: 41 ERC-721 (CyberKongz) │
│                                                             │
│         ┌──────────────┐        ┌───────────────────────┐    │
│  stolen │ sold on Blur │        │ Yuga Labs + "Quit"     │    │
│  NFTs   └──────────────┘        │ RESCUE 68 NFTs ($500K+)│    │
│                                 │ 29 BAYC/4 MAYC/2 Punks │    │
│                                 └───────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

| Item | Value | Notes |
|------|-------|-------|
| On-chain direct drain | ~$40K | WETH extracted from V3 pools |
| Total economic loss | ~$1.5M – $1.6M | Driven by NFT value; stolen NFTs sold on Blur |
| Rescued by Yuga Labs + "Quit" | 68 NFTs, $500K+ | 29 BAYC, 4 MAYC, 2 CryptoPunks |
| Pools hit | fpCloneX, fpCyberKongz | Two separate attacker EOAs / txs |
| Downstream forks affected | BitmapPunks `$BMP`, Asterix | Same BT404 bug class |

---

## 4. Vulnerability Classification

### 4.1 Classification Table

| ID | Vulnerability | Severity | CWE | Category | Similar Incidents |
|----|---------------|----------|-----|----------|-------------------|
| V-01 | Unchecked integer underflow wraps `fpToken` balance to ~2²⁵⁶ | CRITICAL | CWE-191 | integer-precision | ERC-404/DN404 class |
| V-02 | Forged high-bit token-ID alias → ghost/phantom ownership | CRITICAL | CWE-345 / CWE-840 | nft-vulnerabilities, bit-encoding | DN404 forks |
| V-03 | Dual (fungible + NFT) accounting desync in packed bookkeeping | HIGH | CWE-840 | accounting-sync | DN404 / ERC-404 |
| V-04 | Gas-saving bit-level code escaped audit and propagated to forks | MEDIUM | CWE-1059 | process / supply-chain | BitmapPunks, Asterix |

### 4.2 V-01 — Unchecked Integer Underflow

- **Description:** The hybrid token keeps the ERC-20 balance in sync with NFT moves using `unchecked { _balanceOf[from] -= _unit; }`. When the source position's real balance is zero (via ghost ownership), the subtraction underflows and wraps the balance to ~2²⁵⁶.
- **Impact:** Near-infinite `fpToken` minted with no backing, enabling pool drain and cheap NFT redemption. Primary loss driver.
- **Attack Preconditions:** Establish ghost ownership (V-02) so the ownership `require` passes, then trigger the unchecked subtraction.

### 4.3 V-02 — Ghost / Phantom Ownership via High-Bit Alias

- **Description:** BT404 derives packed ownership/index storage keys by truncating token-ID bits. A forged high-bit token-ID alias collides into a legitimate slot, and the bookkeeping write records the attacker as owner without verifying real possession.
- **Impact:** Bypasses the `NOT_OWNER` guard, which is the gate to the underflow primitive. Without it, V-01 is unreachable.
- **Attack Preconditions:** Ability to call the transfer/unwrap path with an attacker-chosen token ID.

### 4.4 V-03 — Dual-Accounting Desynchronization

- **Description:** DN404/BT404 must keep fungible balances and discrete NFT ownership perfectly synchronized. The packed, gas-optimized representation allowed the two views to diverge under a crafted ID, so an NFT-side action drove an inconsistent fungible-side mutation.
- **Impact:** The desync is what lets an NFT-ownership forgery translate into an ERC-20 balance corruption.
- **Attack Preconditions:** Packed bookkeeping that ties NFT ownership to fungible balance arithmetic without invariant checks.

### 4.5 V-04 — Audit-Escaping Gas Code Propagated to Forks

- **Description:** The vulnerable logic lived in low-level, gas-saving bit manipulation that was not adequately covered by audit, then was copied into downstream BT404 forks (BitmapPunks `$BMP`, Asterix), widening the blast radius.
- **Impact:** Multiple protocols share the same latent flaw; a single disclosure endangers the whole fork lineage.
- **Attack Preconditions:** Reuse of unaudited bit-level code across forks.

---

## 5. Comparison with Similar Incidents

| Incident | Date | Loss | Flaw Type | Difference from Flooring/BT404 |
|----------|------|------|-----------|--------------------------------|
| **DN404 / ERC-404 class bugs** | 2024–2026 | varies | Fungible↔NFT accounting desync | Same hybrid-standard family; BT404 adds bit-packing that creates the alias collision |
| **BitmapPunks `$BMP` / Asterix** | 2026 | — | Same BT404 underflow lineage | Downstream forks inheriting the identical gas-code flaw |
| **Integer-precision peers** | various | varies | Unchecked over/underflow | Flooring's underflow is *gated by an ownership forgery*, not a raw arithmetic bug |
| **Flooring Protocol (BT404)** | 2026-06 | ~$1.5M–$1.6M | Ghost ownership → unchecked underflow → infinite mint | Two-primitive chain: forged ID alias enables the wrapping subtraction |

The Flooring incident is distinctive because the underflow is **not reachable directly** — it is *unlocked* by first forging NFT ownership through the packed-bitfield alias. It combines an NFT-accounting forgery (CWE-345/840) with a classic arithmetic underflow (CWE-191), and the gas-optimization that caused it propagated across an entire fork family.

See also: [Integer & precision vulnerability patterns](../vulns/integer-precision.md).

---

## 6. Remediation Recommendations

### 6.1 Immediate Fix — Checked Subtraction

```solidity
// ✅ Never subtract a fungible balance inside `unchecked` without a guard.
uint256 bal = _balanceOf[from];
require(bal >= _unit, "INSUFFICIENT_BALANCE");  // ✅ blocks the wrap to 2**256
_balanceOf[from] = bal - _unit;
_balanceOf[to]  += _unit;
```

### 6.2 Eliminate the Token-ID Alias Collision

```solidity
function _aliasOf(uint256 id) internal pure returns (uint256) {
    // ✅ Reject out-of-range ids; do NOT truncate high bits into the key.
    require(id != 0 && id <= _MAX_TOKEN_ID, "BAD_TOKEN_ID");
    return id; // collision-free key
}
```

### 6.3 Enforce a Hybrid Invariant

```solidity
// ✅ After every mutation, the fungible supply must equal the NFT count × unit.
function _checkInvariant() internal view {
    require(totalSupply == _mintedNftCount() * _unit, "ACCOUNTING_DESYNC");
}
```

### 6.4 Structural Improvements

| Weakness | Recommended Fix |
|----------|-----------------|
| `unchecked` balance subtraction | Use checked arithmetic (or explicit `require(bal >= amt)`) on all balance debits |
| High-bit token-ID aliasing | Validate token-ID range; use collision-free storage keys (no lossy truncation) |
| Ownership trusted from packed slot | Cross-check ownership against an authoritative, range-validated registry before debits |
| Fungible↔NFT desync | Assert the hybrid invariant `totalSupply == nftCount * unit` after each state change |
| Bit-level gas code unaudited | Mandate dedicated audit coverage and differential tests for packed-bitfield routines; re-audit before forking |
| AMM pool fully drainable | Add per-block sell caps / price-impact circuit breakers on `fpToken`/WETH pools |

---

## 7. Lessons Learned

1. **`unchecked` is a loaded gun for balance arithmetic.** DN404-style code uses `unchecked` blocks pervasively for gas. Any subtraction of a user-controlled balance inside `unchecked` must be preceded by an explicit `require(bal >= amount)`, or an underflow wraps to ~2²⁵⁶ and mints infinite supply.
2. **Gas-optimized bit-packing is a first-class attack surface.** Truncating token-ID bits to derive storage keys created an alias collision that forged ownership. Lossy encoding of identity-bearing values must be treated as security-critical, not a micro-optimization.
3. **Hybrid (ERC-20 ↔ ERC-721) accounting must hold an explicit invariant.** When two accounting systems are kept "in sync" by procedure rather than by an asserted invariant, a single crafted input can desynchronize them. Enforce `totalSupply == nftCount * unit` after every mutation.
4. **Forking unaudited gas code propagates the bug.** The same flaw reached BitmapPunks `$BMP` and Asterix because the vulnerable bit-level routines were copied. Treat shared low-level code as a supply-chain risk and re-audit on every fork.
5. **Whitehat counter-rescue is a real mitigation lane.** Yuga Labs and "Quit" salvaged 68 blue-chip NFTs ($500K+) by acting faster than the attacker. Protocols custodying high-value NFTs should pre-plan rescue runbooks and key relationships.
6. **NFT exit liquidity, not on-chain drain, was the real loss.** The direct on-chain WETH drain was only ~$40K; the ~$1.5M–$1.6M loss came from redeeming and selling underlying NFTs on Blur. Damage models must include downstream NFT marketplaces, not just the exploited contract.

---

## 8. On-Chain Verification

### 8.1 Verified Attack Transactions

| Field | Value |
|-------|-------|
| Attack Tx (fpCLNX pool) | [0x5abc52a438734151ebd2cc122f7ae86ed04a390a6dc884f04abd679ed380aaad](https://etherscan.io/tx/0x5abc52a438734151ebd2cc122f7ae86ed04a390a6dc884f04abd679ed380aaad) |
| Attack Tx (fpCKBB pool) | [0xb139f048033a9205c5a62ca43016263cfcca9bab74c48fdc06f43bd29307b26a](https://etherscan.io/tx/0xb139f048033a9205c5a62ca43016263cfcca9bab74c48fdc06f43bd29307b26a) |
| Attacker (fpCloneX) | [0x223CBC5B865A96ddA75D3b0A98536De4f49FcAbb](https://etherscan.io/address/0x223CBC5B865A96ddA75D3b0A98536De4f49FcAbb) |
| Attacker (fpCyberKongz) | [0x5a0416fbAFc21D8f45a355E6cA6fD66f2acA2e49](https://etherscan.io/address/0x5a0416fbAFc21D8f45a355E6cA6fD66f2acA2e49) |

### 8.2 TX1 — fpCLNX Pool (`0x5abc52a4…0aaad`)

| Observation | Detail |
|-------------|--------|
| Swap activity | Heavy ETH ↔ fpCLNX swaps on Uniswap V3 (price crash via near-infinite supply) |
| ERC-721 transfers | **192** fpCloneX mint/burn transfers |
| NFT sink | `rtfkt.liquidity.flooringlab.eth` (fpCloneX/RTFKT liquidity address) |
| Mechanism | Ghost ownership → unchecked underflow → dump fpCLNX → redeem CloneX NFTs |

### 8.3 TX2 — fpCKBB Pool (`0xb139f048…b26a`)

| Observation | Detail |
|-------------|--------|
| Headline swap | **40,000,000,000 fpCKBB → 5.861 ETH** (near-infinite supply dumped for WETH) |
| ERC-721 transfers | **41** CyberKongz transfers |
| Mechanism | Same ghost-ownership + underflow chain on the fpCyberKongz pool |

### 8.4 Asset-Movement Summary

| Flow | Direction | Notes |
|------|-----------|-------|
| `fpToken` (fpCLNX / fpCKBB) | Attacker → Uniswap V3 pool | Near-infinite supply dumped, price → ~0 |
| WETH | V3 pool → Attacker | ~$40K direct on-chain drain |
| Underlying NFTs (CloneX, CyberKongz, blue chips) | Pool/protocol → Attacker | Redeemed cheaply; stolen NFTs later sold on Blur |
| 68 blue-chip NFTs (29 BAYC, 4 MAYC, 2 CryptoPunks) | Protocol → Yuga Labs / "Quit" rescue | $500K+ salvaged before attacker extraction |

---

## 9. References

- [The Crypto Times — "Yuga Labs rescues 68 blue-chip NFTs from Flooring Protocol exploit"](https://www.cryptotimes.io/2026/06/08/yuga-labs-rescues-68-blue-chip-nfts-from-flooring-protocol-exploit/)
- [Crypto Briefing — "Yuga Labs rescues NFTs from Flooring Protocol exploit"](https://cryptobriefing.com/yuga-labs-rescues-nfts-flooring-protocol-exploit/)
- [KuCoin News — "White hat team salvages $500K in NFTs from Flooring Protocol vulnerability"](https://www.kucoin.com/news/flash/white-hat-team-salvages-500k-in-nfts-from-flooring-protocol-vulnerability)
- [Flooring BT404 docs](https://docs.fp.io/bt404/introduction)
- [DN404 reference implementation (GitHub)](https://github.com/Vectorized/dn404)
- [Attack Tx — fpCLNX (Etherscan)](https://etherscan.io/tx/0x5abc52a438734151ebd2cc122f7ae86ed04a390a6dc884f04abd679ed380aaad)
- [Attack Tx — fpCKBB (Etherscan)](https://etherscan.io/tx/0xb139f048033a9205c5a62ca43016263cfcca9bab74c48fdc06f43bd29307b26a)
- [CWE-191: Integer Underflow (Wrap or Wraparound)](https://cwe.mitre.org/data/definitions/191.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-840: Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
- Related: [Integer & precision patterns](../vulns/integer-precision.md), [Verus Bridge (2026)](../2026/2026-05-18_VerusBridge_SourceAmountValidationBypass_ETH.md)
