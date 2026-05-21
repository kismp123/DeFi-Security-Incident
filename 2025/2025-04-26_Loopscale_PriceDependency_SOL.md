# Loopscale — RateX PT Token Price Oracle Manipulation (Price Dependency)

| Item | Details |
|------|------|
| **Date** | 2025-04-26 |
| **Protocol** | Loopscale (formerly Loop Finance) |
| **Chain** | Solana |
| **Loss** | ~$5,800,000 |
| **Root Cause** | Vulnerable Price Dependency — RateX PT token pricing function used as collateral oracle, manipulable via spot price of the underlying Raydium concentrated liquidity pool in a single transaction |
| **Attack Tx** | `2SkCkmX2Q8R7W7RDzgfc6ZFCmYgehmENw72sgTQLfNLHGupNdPDeNkW6S7qCNgYtintFcxhkBCsyf81XA9NSF2RJ` |
| **Reference** | https://x.com/LoopscaleLabs/status/1916230435291713786 |

---

## 1. Vulnerability Overview

Loopscale is a yield loop protocol on Solana that allows users to create leveraged yield positions backed by yield-bearing collateral tokens such as JLP (Jupiter Liquidity Provider tokens). The protocol computes collateral value at borrow time by querying an on-chain price source and uses that valuation to determine how much a user may borrow.

**Core Vulnerability**: Loopscale used the **spot price from a Raydium concentrated liquidity pool** as its collateral oracle rather than a time-weighted average price (TWAP) or an off-chain attested feed (e.g., Pyth, Switchboard). Because the spot price reflects the current instantaneous state of the pool, it can be moved within a single transaction by executing a sufficiently large swap. An attacker exploited this by:

1. Obtaining a large flash loan of SOL.
2. Executing a large swap in the Raydium pool to spike the spot price of the collateral token.
3. Opening a leveraged position in Loopscale while the inflated price was active — receiving far greater borrowing capacity than the collateral's true value warranted.
4. Withdrawing the borrowed funds (USDC/SOL).
5. Reversing the swap to recover the flash loan.
6. Leaving Loopscale holding undercollateralized debt (collateral worth far less than the outstanding loan), resulting in ~$5.8M in bad debt.

The protocol lacked a TWAP buffer, a price deviation guard, and any flash-loan-manipulation protection on its oracle reads.

---

## 2. Vulnerable Code Analysis

### 2.1 Spot-Price Oracle — No TWAP or Deviation Guard

```rust
// Loopscale collateral valuation — vulnerable (Rust/Anchor pseudocode)
pub fn get_collateral_value(
    collateral_mint: Pubkey,
    collateral_amount: u64,
    pool: &RaydiumPool,
) -> u64 {
    // BUG: reads instantaneous spot price from AMM pool
    // This price can be moved within the same transaction via a large swap
    let spot_price = pool.current_sqrt_price.to_price();

    // No TWAP window, no deviation check, no flash-loan protection
    collateral_amount * spot_price
}
```

```rust
// Fixed version — use Pyth/Switchboard TWAP with staleness + deviation guards
pub fn get_collateral_value_safe(
    collateral_mint: Pubkey,
    collateral_amount: u64,
    pyth_price_account: &AccountInfo,
    clock: &Clock,
) -> Result<u64> {
    let price_feed = load_price_feed_from_account_info(pyth_price_account)?;
    let current_price = price_feed
        .get_price_no_older_than(clock.unix_timestamp, MAX_STALENESS_SECS)
        .ok_or(ErrorCode::StaleOraclePrice)?;

    // Confidence interval guard: reject if uncertainty is too wide
    require!(
        current_price.conf <= current_price.price as u64 / MAX_CONF_RATIO,
        ErrorCode::OraclePriceTooUncertain
    );

    // Optional: cross-validate against a secondary oracle (Switchboard)
    let secondary_price = get_switchboard_price(switchboard_feed)?;
    let deviation = abs_diff(current_price.price as u64, secondary_price);
    require!(
        deviation * 10_000 / secondary_price <= MAX_DEVIATION_BPS,
        ErrorCode::OraclePriceDeviation
    );

    Ok(collateral_amount * current_price.price as u64)
}
```

**Problem**: `pool.current_sqrt_price` reflects state at the current slot only. A swap that occurs in the same transaction (or the same block on networks without intra-block finality boundaries) changes this value before the oracle read, making the manipulation atomic and capital-efficient with a flash loan.

### 2.2 Missing Flash-Loan Manipulation Guard at Position Open

```rust
// Vulnerable: no check that the price is consistent with recent history
pub fn open_loop_position(
    ctx: Context<OpenPosition>,
    collateral_amount: u64,
    leverage: u64,
) -> Result<()> {
    // BUG: collateral value computed from manipulated spot price
    let collateral_value = get_collateral_value(
        ctx.accounts.collateral_mint.key(),
        collateral_amount,
        &ctx.accounts.raydium_pool,
    );

    let borrow_amount = collateral_value * (leverage - 1);
    // No sanity check — borrow_amount can be tens of times the real value
    mint_debt_and_transfer(ctx, borrow_amount)?;
    Ok(())
}
```

```rust
// Fixed: validate price age and cross-check with trusted oracle
pub fn open_loop_position(
    ctx: Context<OpenPosition>,
    collateral_amount: u64,
    leverage: u64,
) -> Result<()> {
    let collateral_value = get_collateral_value_safe(
        ctx.accounts.collateral_mint.key(),
        collateral_amount,
        &ctx.accounts.pyth_price_account,
        &ctx.accounts.clock,
    )?;

    // Circuit breaker: compare trusted price against pool spot price
    let spot_value = get_collateral_value(
        ctx.accounts.collateral_mint.key(),
        collateral_amount,
        &ctx.accounts.raydium_pool,
    );
    let deviation = abs_diff(collateral_value, spot_value);
    require!(
        deviation * 10_000 / collateral_value <= MAX_ORACLE_DEVIATION_BPS,
        ErrorCode::SuspiciousPriceDeviation // reject if spot diverged too far
    );

    let borrow_amount = collateral_value * (leverage - 1);
    mint_debt_and_transfer(ctx, borrow_amount)?;
    Ok(())
}
```

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                      Step 1: Flash Loan                          │
│  Attacker borrows a large amount of SOL via flash loan           │
│  (single-transaction atomicity on Solana)                        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│              Step 2: Raydium Pool Price Manipulation             │
│  Execute large swap in the Raydium CLMM pool for the            │
│  collateral token (e.g., JLP/SOL)                                │
│  Spot price of collateral token artificially spiked              │
│  pool.current_sqrt_price → inflated value                        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│            Step 3: Open Leveraged Position in Loopscale          │
│  Call open_loop_position with collateral deposit                 │
│  Loopscale reads spot price → collateral massively over-valued   │
│  Protocol grants borrow capacity far exceeding true value        │
│  Attacker withdraws USDC/SOL (real funds) from protocol          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│              Step 4: Reverse Swap / Flash Loan Repay             │
│  Reverse the large swap to recover the flash-loaned SOL          │
│  Spot price returns to fair value                                │
│  Collateral still locked in Loopscale — now worth far less       │
│  than the outstanding loan                                        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Step 5: Bad Debt Left Behind                   │
│  Attacker defaults — collateral value << loan value              │
│  Loopscale absorbs ~$5.8M in undercollateralized bad debt        │
│  Affected pools: primarily USDC and SOL lending pools            │
└─────────────────────────────────────────────────────────────────┘
```

**Attack Flow Summary**:

```
Attacker
  │
  ├──▶ [Flash Loan] → large SOL borrowed
  │
  ├──▶ [Raydium CLMM Pool]
  │    Large swap → spot price of collateral token spiked
  │    collateral real value: $X  →  oracle reports: $tens-of-X
  │
  ├──▶ [Loopscale Protocol]
  │    Deposit collateral → borrow at inflated valuation
  │    Withdraw USDC/SOL → ~$5.8M extracted
  │
  ├──▶ [Raydium CLMM Pool]
  │    Reverse swap → SOL recovered → flash loan repaid
  │
  └──▶ Protocol left with undercollateralized position (~$5.8M bad debt)
```

---

## 4. Vulnerability Classification

| ID | Vulnerability | Category | CWE | Severity |
|----|--------------|---------|-----|----------|
| V-01 | AMM spot price used as collateral oracle | Vulnerable Price Dependency / Oracle Manipulation | CWE-807 (Reliance on Untrusted Inputs) | **CRITICAL** |
| V-02 | No TWAP or time-delay mechanism on price reads | Missing Temporal Price Averaging | CWE-1038 (Insecure Automated Optimizations) | **CRITICAL** |
| V-03 | No price deviation check between oracle and secondary source | Absence of Cross-Oracle Validation | CWE-20 (Improper Input Validation) | **HIGH** |
| V-04 | No flash-loan / same-transaction manipulation protection | Atomicity Abuse | CWE-362 (Race Condition) | **HIGH** |

---

## 5. Remediation Recommendations

### Immediate Actions

1. **Replace spot price oracle with Pyth Network or Switchboard**: Both provide off-chain attested price feeds that cannot be moved within a single on-chain transaction. Enforce staleness checks (`MAX_STALENESS_SECS`).

2. **Add confidence interval guard (Pyth)**: Reject price reads where `conf > price / CONF_RATIO` to filter out feeds under high market stress.

3. **Implement a cross-oracle deviation check**: Compare the primary oracle price against a secondary source (e.g., Raydium TWAP vs. Pyth). Revert if deviation exceeds a threshold (e.g., 5%).

### Structural Improvements

| Vulnerability | Recommended Action |
|--------------|-------------------|
| V-01 (AMM spot price) | Switch to Pyth / Switchboard attested feeds; never read from DEX spot price alone |
| V-02 (No TWAP) | If DEX price must be used, implement on-chain TWAP accumulation over ≥30 minutes |
| V-03 (No cross-validation) | Cross-validate primary oracle against a secondary; halt on >5% deviation |
| V-04 (Flash-loan protection) | Record slot number of last price read; reject if price updated in same slot as borrow |

```rust
// Slot-based flash-loan protection example
pub fn open_loop_position(ctx: Context<OpenPosition>, ...) -> Result<()> {
    let current_slot = ctx.accounts.clock.slot;
    // Require that the last price update is at least 1 slot old
    require!(
        ctx.accounts.price_feed.last_update_slot < current_slot,
        ErrorCode::PriceUpdatedInSameSlot
    );
    // ... proceed with validated price
}
```

---

## 6. Lessons Learned

1. **AMM spot prices are trivially manipulable**: Any protocol that reads `sqrtPrice` or `currentPrice` directly from a DEX pool without a temporal averaging window is vulnerable to flash-loan or large-trade oracle manipulation within a single atomic transaction.

2. **Solana's atomicity makes same-slot manipulation especially dangerous**: Because all instructions in a Solana transaction execute atomically, an attacker can manipulate state and exploit it within a single transaction at negligible cost beyond the capital required for the swap.

3. **TWAP alone is insufficient without liquidity validation**: If a TWAP-based oracle is used, the underlying pool must have sufficient liquidity — a low-liquidity pool can be pushed to a manipulated price and held there for the TWAP window duration (see also PeapodsFinance, July 2025).

4. **Yield-bearing collateral protocols require extra oracle rigor**: JLP tokens and similar yield-bearing assets often have thin secondary markets. Using such a pool as an oracle source amplifies manipulation risk and requires stricter validation.

5. **Similar incidents**: Mango Markets (Solana, October 2022, $114M), Rodeo Finance (Arbitrum, July 2023, $1.5M), and UwU Lend (Ethereum, June 2024, $20M) all exploited the same class of price dependency vulnerability.

---

## References

- [Loopscale Official Statement (Twitter/X)](https://x.com/LoopscaleLabs/status/1916230435291713786)
- [Pyth Network — Price Feed Integration Guide](https://docs.pyth.network/price-feeds)
- [Switchboard — Solana Oracle Docs](https://docs.switchboard.xyz/)
- [Attack Transaction (Solscan)](https://solscan.io/tx/2SkCkmX2Q8R7W7RDzgfc6ZFCmYgehmENw72sgTQLfNLHGupNdPDeNkW6S7qCNgYtintFcxhkBCsyf81XA9NSF2RJ)
