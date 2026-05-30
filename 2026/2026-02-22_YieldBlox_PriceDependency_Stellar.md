# YieldBlox — Reflector VWAP Oracle Manipulation via Illiquid Market on Stellar

| Item | Details |
|------|------|
| **Date** | 2026-02-22 |
| **Protocol** | YieldBlox DAO |
| **Chain** | Stellar (Soroban smart contracts) |
| **Loss** | ~$10,000,000 |
| **Attacker** | Unidentified |
| **Root Cause** | Pool configuration vulnerability — USTRY collateral priced via Reflector VWAP oracle with no minimum liquidity or volume threshold; attacker placed a single sell at 501 USDC/USTRY in an illiquid market with no prior trades in the 15-minute VWAP window, inflating price 100× |
| **Attack Tx** | `3e81a3f7b6e17cc22d0a1f33e9dcf90e5664b125b9e61f108b8d2f082f2d4657` |
| **Attack Tx 2** | `ae721cacee382bdecac8d2c47286ecd42cb4711f658bb2aec7cba60dc64a31ff` |
| **Reference** | [DefimonAlerts Twitter](https://x.com/DefimonAlerts/status/2025689939979960539) |

---

## 1. Vulnerability Overview

YieldBlox DAO is a decentralized lending and yield protocol built on top of **Blend V2** (Stellar's lending primitive) via Soroban smart contracts. The protocol allows users to deposit collateral and borrow against it, with collateral values determined by the **Reflector oracle** — a volume-weighted average price (VWAP) oracle that sources prices from trading activity on the Stellar Decentralized Exchange (SDEX).

The critical flaw was a **pool configuration issue, not a Blend V2 core contract bug**. YieldBlox's pool accepted **USTRY** (a Stellar-native bond-like token pegged to ~$1.05) as collateral, with its price fed by the Reflector VWAP oracle reading the USTRY/USDC SDEX market. The pool was configured without minimum liquidity thresholds or volume requirements on the oracle source — a safe assumption when a market is healthy, but catastrophic on an illiquid market.

In the 15 minutes before the attack, the sole market maker for USTRY/USDC had withdrawn all their liquidity from the SDEX order book. The Reflector oracle's VWAP window contained **zero legitimate trades**. The attacker exploited this by placing a single abnormal sell offer: **0.05 USTRY for 501 USDC per USTRY** (approximately $106.70 per USTRY at execution — 100× the fair value of ~$1.05).

Because this single trade dominated the VWAP window entirely, the Reflector oracle updated the USTRY price to approximately $106.70. With this inflated collateral valuation, the attacker's existing USTRY holdings were massively overcollateralized. They immediately borrowed the entirety of the pool's reserves: approximately **1,000,196 USDC** and **61,250,000 XLM** (worth ~$9M at prevailing XLM prices), draining the pool completely.

After the exploit, Stellar Tier-1 validators froze approximately $7.2M of the stolen assets within the attacker's accounts. YieldBlox offered a 10% bounty with a 72-hour deadline; the attacker did not respond.

## 2. Vulnerable Code Analysis

**Language:** Rust (compiled to Wasm via Soroban SDK). No Solidity source applies — Stellar Soroban uses Rust.
**Source provenance:** ANALYZED/RECONSTRUCTED — YieldBlox's Soroban pool configuration contract and the Blend V2 pool factory are not publicly indexed. The vulnerability was a **pool configuration issue** in the Blend V2 pool that YieldBlox operated, not a flaw in the Blend V2 core contracts themselves. The code below is reconstructed from Halborn, BlockSec, and QuillAudits analyses. Labeled accordingly.

> ⚠️ This was NOT a Blend V2 protocol flaw. The core issue was that YieldBlox configured a Blend V2 pool to accept USTRY as collateral with a Reflector oracle that had no minimum volume or liquidity depth requirements on the price source market.

### Pool Configuration (the vulnerable settings)

```rust
// YieldBlox pool configuration — ANALYZED/RECONSTRUCTED
// ⚠️ Not verbatim source — reconstructed from post-mortem descriptions
// Language: Rust (Soroban SDK), Stellar blockchain
//
// When YieldBlox created their Blend V2 pool, they configured:
//   collateral_asset   = USTRY  (Stellar-native bond token, ~$1.05 fair value)
//   price_oracle       = Reflector oracle (VWAP from SDEX USTRY/USDC market)
//   min_volume_check   = NONE   // ❌ no minimum 15-min volume threshold
//   min_liquidity_check = NONE  // ❌ no minimum order book depth check
//   price_deviation_guard = NONE // ❌ no circuit breaker for abnormal prices
//
// Blend V2 pool initialization (simplified):
fn initialize_pool(
    e: &Env,
    admin: Address,
    oracle: Address,   // ← Reflector oracle address
    assets: Vec<ReserveConfig>,
) {
    // Registers the oracle for all assets in the pool.
    // No validation that the oracle's price source has adequate liquidity.
    // BUG: the oracle address is trusted unconditionally.
    // If the oracle's VWAP can be manipulated (e.g., single trade in empty window),
    // all collateral valuations in this pool are attackable.
    storage::set_oracle(e, &oracle);
    for asset in assets {
        storage::set_reserve(e, &asset);
    }
}
```

### Reflector Oracle — how VWAP is computed and manipulated

```rust
// Reflector Oracle VWAP mechanism — ANALYZED/RECONSTRUCTED
// ⚠️ Not verbatim Reflector source — illustrative of the documented behavior
//
// Reflector computes VWAP over a 15-minute (approx. 18-ledger) window on SDEX:
//   VWAP = Σ(price_i × volume_i) / Σ(volume_i)
//        for all trades in the window
//
// ATTACK: If the window contains exactly ONE trade:
//   VWAP = price_attack × volume_attack / volume_attack = price_attack
//   → The oracle price IS the attacker's trade price, regardless of fair value.
//
// Attacker's trade:
//   sell 0.05 USTRY at 501 USDC/USTRY
//   → executed at ~106.70 USDC/USTRY (clearing price against existing bids)
//   → Reflector VWAP for the window = ~106.70 USDC/USTRY (100× fair value)

fn get_oracle_price(e: &Env, asset: &Address) -> i128 {
    // Fetch VWAP from Reflector oracle
    let oracle_client = ReflectorClient::new(e, &REFLECTOR_ORACLE);
    let price_data = oracle_client.lastprice(asset);
    // ❌ No check: is this price within N% of a secondary source?
    // ❌ No check: was there a minimum volume in the VWAP window?
    // ❌ No check: is the deviation from the previous price reasonable?
    price_data.price   // returns 106_700_000 (scaled) — 100× inflated
}
```

### Collateral valuation at borrow time

```rust
// Blend V2 collateral valuation — ANALYZED/RECONSTRUCTED
// Shows how the oracle price flows into borrow capacity

fn get_collateral_value(
    e: &Env,
    user: &Address,
    collateral_asset: &Address,
    collateral_amount: i128,
) -> i128 {
    let price = get_oracle_price(e, collateral_asset);
    // price = 106_700_000 (100× inflated by attacker's single trade)

    let collateral_value = collateral_amount
        .checked_mul(price).unwrap()
        / PRECISION;
    // 13_003 USTRY × 106.70 USDC = ~1,387,211 USDC equivalent (real value: ~13,653 USDC)

    let borrow_capacity = collateral_value * LTV_NUMERATOR / LTV_DENOMINATOR;
    borrow_capacity   // ← returns ~1M USDC borrowable — entire pool reserves
}
```

### Fixed Pool Configuration

```rust
// YieldBlox pool (fixed) — ANALYZED/RECONSTRUCTED
// Shows the configuration guards that should have been present

fn initialize_pool_safe(
    e: &Env,
    admin: Address,
    oracle: Address,
    assets: Vec<ReserveConfig>,
    oracle_config: OracleConfig,  // ✅ added
) {
    storage::set_oracle(e, &oracle);
    // ✅ Require minimum 15-minute trading volume before accepting price
    storage::set_oracle_min_volume(e, &oracle_config.min_volume_usdc);   // e.g., $10,000
    // ✅ Circuit breaker: reject price if it deviates >10% from prior oracle reading
    storage::set_oracle_max_deviation_bps(e, &oracle_config.max_deviation_bps); // e.g., 1000
    // ✅ Require minimum open order book depth at time of price read
    storage::set_oracle_min_liquidity(e, &oracle_config.min_liquidity_usdc); // e.g., $50,000
    for asset in assets {
        storage::set_reserve(e, &asset);
    }
}

fn get_oracle_price_safe(e: &Env, asset: &Address) -> i128 {
    let oracle_client = ReflectorClient::new(e, &REFLECTOR_ORACLE);
    let price_data = oracle_client.lastprice(asset);
    let volume_15m = oracle_client.volume_15m(asset);

    // ✅ Reject if insufficient volume dominated the VWAP window
    require(volume_15m >= MIN_VOLUME_USDC, Error::InsufficientOracleVolume);

    // ✅ Reject if price moved more than MAX_DEVIATION from previous reading
    let prev_price = storage::get_last_price(e, asset);
    let deviation = (price_data.price - prev_price).abs() * 10000 / prev_price;
    require(deviation <= MAX_DEVIATION_BPS, Error::PriceDeviationExceeded);

    storage::set_last_price(e, asset, price_data.price);
    price_data.price
}
```

## 3. Attack Flow

```
PRE-CONDITIONS
  — USTRY/USDC SDEX market: sole market maker withdraws all liquidity
  — Reflector oracle VWAP window (15 min) contains ZERO prior trades
  — YieldBlox Blend V2 pool: no minimum volume/liquidity guard on oracle

STEP 1 — Oracle Poisoning (Tx: 3e81a3f7b6e17cc22d0a1f33e9dcf90e5664b125...)
  Attacker places a sell offer: 501 USDC per USTRY on SDEX
  Executes a counter-buy: purchases 0.05 USTRY at ~106.70 USDC
  → This single trade is the ONLY trade in the Reflector VWAP window
  → Reflector VWAP = 106.70 USDC/USTRY  (real value: ~1.05 USDC/USTRY)
  → Price inflation: ~100×

STEP 2 — Oracle Update (Tx: ae721cacee382bdecac8d2c47286ecd42cb4711f...)
  Reflector oracle updates its on-chain price feed with the VWAP result
  → USTRY price in YieldBlox pool = ~106.70 USDC  (from legitimate VWAP calc on bad data)

STEP 3 — Borrow #1 (USDC)
  Attacker supplies 12,881 USTRY as collateral
    (real value: ~$13,525; oracle value: ~$1,374,250)
  YieldBlox Blend V2 pool accepts collateral at inflated valuation
  Attacker calls borrow():
    → borrows 1,000,196 USDC  (entire USDC reserve of the pool)

STEP 4 — Borrow #2 (XLM)
  Attacker supplies 14,987,610 additional USTRY as collateral
    (real value: ~$15.7M; oracle value: ~$1.6B — absurdly overcollateralized)
  Attacker calls borrow():
    → borrows 61,250,000,000 stroops XLM (61.25 million XLM, entire XLM reserve)

STEP 5 — Bridge Out
  Stolen USDC and XLM bridged to Ethereum Base, BSC, and Ethereum mainnet
  Cross-chain transactions across multiple hops to obscure trail

RESULT
  YieldBlox pool drained: ~$10,000,000 total
    - 1,000,196 USDC
    - 61,250,000 XLM  (~$9M at time of attack)
  $7,200,000 frozen by Stellar Tier-1 validators in attacker's accounts
  Net attacker profit (unfrozen): ~$2,800,000
  YieldBlox offers 10% bounty ($1M); attacker does not respond
```

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Oracle Manipulation — VWAP oracle with no minimum volume/liquidity guard; pool-operator configuration failure |
| **Severity** | Critical |
| **CWE** | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere); CWE-284 (Improper Access Control — no sanity guard on oracle input) |
| **Root Category** | Pool configuration vulnerability — not a Blend V2 core contract flaw |
| **Collateral Asset** | USTRY (Stellar-native bond token, fair value ~$1.05) |
| **Oracle** | Reflector VWAP (sourced from SDEX USTRY/USDC market) |
| **Attack Cost** | ~0.05 USTRY + swap fees (~$0.05) |

## 5. Remediation Recommendations

1. **Minimum volume threshold on oracle price source**: The Reflector oracle is a legitimate price feed, but YieldBlox's pool should have rejected any VWAP reading based on a 15-minute window with less than a configurable minimum volume (e.g., $10,000 USDC). A single $0.05 trade should never be able to set collateral prices for a $10M pool.
2. **Price deviation circuit breaker**: Reject any oracle price that deviates more than N% from the previous accepted price (e.g., 10% max change per oracle update). A 100× price increase in one update is an unambiguous manipulation signal.
3. **Minimum order book depth check**: Before accepting an oracle price, verify that the SDEX order book for the collateral asset has at least $X in open bids/asks within Y% of the oracle price. Zero liquidity depth = invalid price.
4. **Secondary oracle cross-check**: For illiquid assets, require price confirmation from a second independent source (e.g., a time-averaged on-chain price from a different market or a manual governance-updated price with bounds).
5. **Conservative LTV for illiquid collateral**: Apply additional haircuts to LTV ratios for collateral assets with thin markets. A 50% LTV for USTRY instead of the implicit near-full collateralization would have limited the borrow to $6,500 (real value) rather than $1.4M (inflated value).
6. **Market maker SLA or minimum TVL requirement**: If the protocol's oracle depends on SDEX liquidity, require a documented minimum TVL in the oracle's source market at pool creation and continuously. Loss of the sole market maker should trigger pool suspension.

## 6. Lessons Learned

- **Using a legitimate oracle is not enough — the oracle's data source must also be secured**: YieldBlox used the Reflector oracle, a real and legitimate Stellar price feed. The attack succeeded because the underlying data source (SDEX USTRY/USDC market) was illiquid and unguarded, not because the oracle itself was broken.
- **VWAP oracles are only manipulation-resistant when the market has adequate volume**: A VWAP over zero legitimate trades is just the attacker's price. Protocols must enforce minimum volume requirements on oracle inputs, especially for non-mainstream collateral assets.
- **Single-trade market manipulation does not require flash loans**: Stellar lacks atomic flash loans, but this attack cost approximately $0.05 and took two transactions. Thin markets are trivially manipulable even without flash loan atomicity.
- **Pool operator responsibility**: Blend V2's core contracts were sound; the vulnerability was in YieldBlox's choice of collateral asset and oracle configuration. In permissionless lending platforms, pool operators bear responsibility for safe collateral selection and oracle configuration — a responsibility that requires ongoing monitoring, not a one-time setup.
- **$7.2M frozen by network validators**: Stellar's validator set was able to freeze funds in the attacker's accounts — a capability unavailable on Ethereum or Solana. This "social layer" recovery mechanism is double-edged: it demonstrates Stellar's reduced censorship resistance, but provided partial victim recovery.
- **The incident is classified as a pool-configuration vulnerability, not a smart contract bug**: Standard smart contract audits of the Blend V2 core contracts would not have caught this. Audits of protocol configurations and oracle setups are a separate and equally important security review.

## References

- [DefimonAlerts on Twitter](https://x.com/DefimonAlerts/status/2025689939979960539)
- [Halborn: Explained The YieldBlox Hack (February 2026)](https://www.halborn.com/blog/post/explained-the-yieldblox-hack-february-2026)
- [BlockSec: YieldBlox DAO Incident — Oracle Misconfiguration](https://blocksec.com/blog/yieldblox-dao-incident-on-stellar-oracle-misconfiguration-enabled-a-10m-drain)
- [QuillAudits: How a Single Trade Caused YieldBlox $10M Loss](https://dev.to/quillaudits/how-a-single-trade-caused-yieldblox-10m-loss-34hk)
- [Protos: YieldBlox lending pool hit by $10M hack on Stellar](https://protos.com/yieldblox-lending-pool-hit-by-10m-hack-on-stellar/)
- [Reflector Oracle — Stellar Decentralized Price Feed](https://reflector.network)
- [Stellar Soroban Developer Documentation](https://developers.stellar.org/docs/build/smart-contracts/overview)
- [Blend V2 Protocol Documentation](https://docs.blend.capital)
