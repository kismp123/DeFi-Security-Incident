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

> **Source**: ANALYZED / RECONSTRUCTED — Loopscale's Solana programs are closed-source and not published. The Rust/Anchor code below is reconstructed from Loopscale's official incident statement ([Twitter/X, 2025-04-26](https://x.com/LoopscaleLabs/status/1916230435291713786)), the Halborn and AuditOne post-mortems, and the Raydium CLMM on-chain oracle pattern. All function names are illustrative. Code is labeled `// ⚠️ ANALYZED/RECONSTRUCTED`.
>
> The confirmed facts from post-mortems: (1) the exploit targeted **RateX PT token collateral** in Loopscale's newly-launched SOL and USDC Genesis vaults; (2) Loopscale's contract priced RateX PT tokens using a **spot price** from a low-liquidity on-chain source (a Raydium CLMM pool or RateX internal accumulator); (3) the attacker manipulated that price within a single Solana transaction by deploying a crafted price feed or executing a large swap, then called Loopscale's `create_loan` function while the inflated price was active.

### 2.1 RateX PT Token Price Calculation — Spot-Price Dependency

```rust
// ⚠️ ANALYZED/RECONSTRUCTED — not verbatim source
// File: loopscale-program/src/pricing.rs  (illustrative name)
//
// RateX PT tokens are principal tokens from a yield-stripping protocol.
// Their value depends on the price of the underlying asset and the time-to-maturity.
// Loopscale computed collateral value by reading the spot price of the PT token
// from a Raydium Concentrated Liquidity Market Maker (CLMM) pool.

use anchor_lang::prelude::*;

// Raydium CLMM pool state (simplified — actual layout from raydium-clmm on-chain)
// The `sqrt_price_x64` field is the current instantaneous price as sqrt(price) * 2^64.
// This value changes atomically whenever a swap executes in the same transaction.
#[account]
pub struct RaydiumClmmPoolState {
    pub sqrt_price_x64: u128,  // ❌ current slot-level spot price — manipulable
    pub liquidity: u128,
    pub tick_current: i32,
    // ... other fields omitted
}

/// Compute the USD value of a given amount of RateX PT collateral.
/// Called inside create_loan() to determine maximum borrow capacity.
pub fn get_pt_collateral_value(
    pt_amount: u64,
    pool_state: &RaydiumClmmPoolState,
) -> Result<u64> {
    // ❌ Reads sqrt_price_x64 from the current slot state of the Raydium CLMM pool.
    //    On Solana, all instructions in a transaction execute atomically in the same slot.
    //    If a prior instruction in the same transaction already swapped a large amount
    //    into this pool, sqrt_price_x64 now reflects the manipulated price.
    let sqrt_price = pool_state.sqrt_price_x64;

    // Convert sqrt(price) * 2^64 → price (simplified; actual uses fixed-point math)
    // price = (sqrt_price / 2^64)^2
    let price_x64 = (sqrt_price as u128)
        .checked_mul(sqrt_price as u128)
        .ok_or(ErrorCode::MathOverflow)?
        >> 64;

    // ❌ No TWAP: price reflects only the current slot, not a time-weighted average
    // ❌ No deviation guard: any price the pool reports is accepted unconditionally
    // ❌ No secondary oracle cross-check (Pyth, Switchboard)
    let collateral_value = (pt_amount as u128)
        .checked_mul(price_x64)
        .ok_or(ErrorCode::MathOverflow)? as u64;

    Ok(collateral_value)
}
```

### 2.2 `create_loan` — Calls Vulnerable Pricing with No Manipulation Guard

```rust
// ⚠️ ANALYZED/RECONSTRUCTED — not verbatim source
// Confirmed by post-mortems: attacker called create_loan() with RateX PT collateral
// while the PT price was artificially inflated within the same transaction.

#[derive(Accounts)]
pub struct CreateLoan<'info> {
    #[account(mut)]
    pub borrower: Signer<'info>,
    pub collateral_mint: Account<'info, Mint>,
    /// ❌ The pool whose spot price is read — can be manipulated in the same tx
    pub raydium_pool: Account<'info, RaydiumClmmPoolState>,
    #[account(mut)]
    pub vault: Account<'info, LendingVault>,
    // ... other accounts
}

pub fn create_loan(
    ctx: Context<CreateLoan>,
    collateral_amount: u64,
    requested_borrow: u64,
) -> Result<()> {
    // ❌ Collateral value computed from manipulable spot price in same transaction
    let collateral_value = get_pt_collateral_value(
        collateral_amount,
        &ctx.accounts.raydium_pool,
    )?;

    // LTV = loan-to-value ratio (e.g., 80%)
    let max_borrow = collateral_value
        .checked_mul(LTV_BPS)
        .ok_or(ErrorCode::MathOverflow)?
        / 10_000;

    // ❌ No check that collateral_value is consistent with a trusted external feed
    // ❌ No check that current slot != last price update slot (flash-loan protection)
    require!(
        requested_borrow <= max_borrow,
        ErrorCode::BorrowExceedsCollateral
    );

    // Transfer borrowed USDC/SOL from vault to borrower
    transfer_from_vault(ctx, requested_borrow)?;
    record_debt(ctx, requested_borrow, collateral_amount)?;
    Ok(())
}
```

**Why it is exploitable (identify the bug from the code):**

- `get_pt_collateral_value()` reads `pool_state.sqrt_price_x64` — the instantaneous CLMM slot price. On Solana, all instructions in a transaction share the same slot, so a swap instruction that precedes `create_loan` in the same transaction has already moved this value.
- There is no TWAP accumulator, no staleness check, and no secondary oracle comparison. Whatever `sqrt_price_x64` reports is accepted directly as the collateral price.
- `create_loan` performs no same-slot detection: it does not compare the pool's `last_updated_slot` against the current slot, so flash-loan manipulation within one transaction is indistinguishable from a legitimate price.
- With an inflated PT price, `collateral_value` is artificially high, `max_borrow` exceeds the real collateral worth by a large multiple, and the attacker withdraws USDC/SOL far beyond what their collateral covers.

### 2.3 Fixed Version — Pyth Oracle with Staleness and Deviation Guards

```rust
// ✅ Fixed version — use Pyth attested price feed instead of AMM spot
// (not verbatim; represents the correct pattern)

use pyth_sdk_solana::load_price_feed_from_account_info;

const MAX_STALENESS_SECS: i64 = 60;   // reject prices older than 60 s
const MAX_CONF_RATIO: u64 = 20;        // confidence must be < price/20 (5%)
const MAX_DEVIATION_BPS: u64 = 500;    // ≤ 5% deviation between oracles

pub fn get_pt_collateral_value_safe(
    pt_amount: u64,
    pyth_price_account: &AccountInfo,
    clock: &Clock,
) -> Result<u64> {
    let price_feed = load_price_feed_from_account_info(pyth_price_account)
        .map_err(|_| ErrorCode::InvalidOracleAccount)?;

    // ✅ Staleness check: reject if price feed not updated within MAX_STALENESS_SECS
    let current_price = price_feed
        .get_price_no_older_than(clock.unix_timestamp, MAX_STALENESS_SECS)
        .ok_or(ErrorCode::StaleOraclePrice)?;

    // ✅ Confidence interval guard: rejects if Pyth uncertainty is too wide
    require!(
        current_price.conf <= current_price.price as u64 / MAX_CONF_RATIO,
        ErrorCode::OraclePriceTooUncertain
    );

    Ok(pt_amount
        .checked_mul(current_price.price as u64)
        .ok_or(ErrorCode::MathOverflow)?)
}

pub fn create_loan(
    ctx: Context<CreateLoan>,
    collateral_amount: u64,
    requested_borrow: u64,
) -> Result<()> {
    // ✅ Use Pyth attested price — cannot be moved within a single transaction
    let collateral_value = get_pt_collateral_value_safe(
        collateral_amount,
        &ctx.accounts.pyth_price_account,
        &ctx.accounts.clock,
    )?;

    // ✅ Cross-validate: compare Pyth price against pool spot
    let spot_value = get_pt_collateral_value(
        collateral_amount,
        &ctx.accounts.raydium_pool,
    )?;
    let deviation = (collateral_value as i128 - spot_value as i128).unsigned_abs() as u64;
    require!(
        deviation.checked_mul(10_000).ok_or(ErrorCode::MathOverflow)?
            / collateral_value <= MAX_DEVIATION_BPS,
        ErrorCode::SuspiciousPriceDeviation
    );

    // ✅ Same-slot protection: require price was NOT updated in this exact slot
    require!(
        ctx.accounts.raydium_pool.last_observation_slot < ctx.accounts.clock.slot,
        ErrorCode::PriceUpdatedInSameSlot
    );

    let max_borrow = collateral_value * LTV_BPS / 10_000;
    require!(requested_borrow <= max_borrow, ErrorCode::BorrowExceedsCollateral);
    transfer_from_vault(ctx, requested_borrow)?;
    record_debt(ctx, requested_borrow, collateral_amount)?;
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
