# YieldBlox — AMM Spot Price Oracle Manipulation on Stellar

| Item | Details |
|------|------|
| **Date** | 2026-02-22 |
| **Protocol** | YieldBlox DAO |
| **Chain** | Stellar (Soroban smart contracts) |
| **Loss** | ~$10,000,000 |
| **Attacker** | Unidentified |
| **Root Cause** | Vulnerable Price Dependency — collateral valued using SDEX AMM spot price, manipulable via large sequential swaps |
| **Attack Tx** | `3e81a3f7b6e17cc22d0a1f33e9dcf90e5664b125b9e61f108b8d2f082f2d4657` |
| **Attack Tx 2** | `ae721cacee382bdecac8d2c47286ecd42cb4711f658bb2aec7cba60dc64a31ff` |
| **Reference** | [DefimonAlerts Twitter](https://x.com/DefimonAlerts/status/2025689939979960539) |

---

## 1. Vulnerability Overview

YieldBlox DAO is a decentralized lending and yield protocol deployed on the Stellar blockchain via Soroban smart contracts. The protocol allows users to deposit collateral and borrow against it, with collateral values determined at borrow time by an on-chain price oracle. Rather than integrating an external, manipulation-resistant oracle such as Reflector Oracle, YieldBlox computed collateral value by reading the instantaneous spot price from a Stellar DEX (SDEX) AMM liquidity pool — the ratio of reserves in the pool at the moment of the call.

Unlike Ethereum, Stellar's transaction model does not support atomic flash loans within a single transaction, meaning the attacker could not inflate and drain in one atomic step. However, this does not eliminate AMM manipulation — it merely requires the attacker to execute the attack across multiple sequential transactions. By deploying capital to execute large swaps on a thin SDEX pool, the attacker moved the spot price of the collateral token sharply upward over several transactions. With the artificially elevated price reflecting in the collateral oracle, the attacker deposited a modest amount of the collateral token, which the protocol now valued far above market reality.

Borrowing against the inflated collateral, the attacker extracted liquid assets — stablecoins or other tokens held by the protocol — far exceeding the true value of their collateral. They then exited the swap positions, restoring the pool price while YieldBlox was left holding undercollateralized positions. The protocol's assumption that the SDEX spot price was a reliable, manipulation-resistant measure of fair value was the core design flaw.

## 2. Vulnerable Code Analysis

```rust
// YieldBlox collateral oracle — VULNERABLE
fn get_collateral_price(
    e: &Env,
    asset: Address,
) -> i128 {
    // BUG: reads current AMM pool reserve ratio (spot price)
    // This value is trivially manipulable by large swaps on thin pools.
    // No time-weighting, no external price source, no sanity bounds.
    let pool = stellar_sdex_pool::get_pool(e, &asset, &USDC);
    pool.spot_price()  // returns reserve_usdc / reserve_asset at this instant
}

fn max_borrow(
    e: &Env,
    user: Address,
    collateral_asset: Address,
    collateral_amount: i128,
) -> i128 {
    let price = get_collateral_price(e, collateral_asset);  // manipulated price
    let collateral_value = collateral_amount * price / PRECISION;
    collateral_value * LTV_RATIO / 100  // LTV applied to inflated value
}
```

```rust
// YieldBlox collateral oracle — FIXED
fn get_collateral_price(
    e: &Env,
    asset: Address,
) -> i128 {
    // Use Reflector Oracle (Stellar's decentralized price feed)
    // or a TWAP accumulated over N ledgers (e.g., last 30 ledgers ~150 seconds).
    let oracle = reflector_oracle::client(&e, &REFLECTOR_ORACLE_ADDRESS);
    let price_data = oracle.lastprice(&asset);

    // Sanity check: reject prices deviating more than MAX_DEVIATION from TWAP
    let twap = get_twap(e, &asset, TWAP_WINDOW_LEDGERS);
    let deviation = (price_data.price - twap).abs() * 10000 / twap;
    if deviation > MAX_DEVIATION_BPS {
        panic_with_error!(e, Error::OracleManipulationDetected);
    }

    price_data.price
}
```

## 3. Attack Flow

```
1. SETUP — Attacker identifies a thin SDEX AMM pool for target collateral token / USDC.

2. PRICE INFLATION (Tx 1-N)
   Attacker executes a series of large buy orders for the collateral token
   on the SDEX pool, draining USDC reserves and inflating the spot price.
   3e81a3f7... — first large swap, price moves significantly upward.
   ae721cac... — follow-up swap, price pushed to target level.

3. BORROW AGAINST INFLATED COLLATERAL
   Attacker calls YieldBlox deposit() with a small amount of collateral token.
   get_collateral_price() returns inflated SDEX spot price.
   max_borrow() returns a loan limit far exceeding true collateral value.
   Attacker calls borrow(), receiving liquid assets (stablecoins).

4. EXIT SWAP POSITIONS
   Attacker reverses the SDEX swaps, recovering most of the swap capital.
   Pool spot price returns to fair market value.

5. RESULT
   YieldBlox holds undercollateralized loans worth ~$10M.
   Attacker nets the difference between borrowed value and true collateral value.
```

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Price Dependency / Oracle Manipulation (AMM Spot Price) |
| **Severity** | Critical |
| **CWE** | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |

## 5. Remediation Recommendations

- Replace SDEX spot price reads with Reflector Oracle integration, which aggregates prices from multiple sources and is resistant to single-pool manipulation.
- Implement a Stellar-native TWAP by storing pool price snapshots at each ledger closure and computing a volume-weighted or time-weighted average over a minimum observation window (e.g., 30 ledgers).
- Add circuit-breaker logic: if the current spot price deviates more than a configurable threshold (e.g., 5%) from the TWAP, reject the collateral valuation and revert the transaction.
- Apply conservative loan-to-value (LTV) ratios with additional haircuts for illiquid or thin-market collateral assets.
- Monitor pool liquidity depth as part of oracle validity; reject price reads when pool TVL falls below a minimum threshold.

## 6. Lessons Learned

- Stellar's sequential transaction model does not provide flash-loan atomicity guarantees, but it does not eliminate AMM price manipulation — multi-transaction attacks are fully viable on thin markets and should be modeled during threat assessment.
- On non-EVM chains, the absence of well-known oracle solutions (Chainlink, Uniswap TWAP) does not mean oracle manipulation is impossible; protocols must identify and integrate chain-native alternatives (e.g., Reflector Oracle on Stellar) rather than defaulting to AMM spot prices.
- Lending protocols must treat collateral price as a security-critical input and apply defense-in-depth: external oracle, on-chain TWAP cross-check, deviation guards, and liquidity-depth gating working in concert.

## References

- [DefimonAlerts on Twitter](https://x.com/DefimonAlerts/status/2025689939979960539)
- [Reflector Oracle — Stellar Decentralized Price Feed](https://reflector.network)
- [Stellar Soroban Developer Documentation](https://developers.stellar.org/docs/build/smart-contracts/overview)
