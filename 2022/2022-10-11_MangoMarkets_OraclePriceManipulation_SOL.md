# Mango Markets — Oracle Price Manipulation Governance Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10-11 |
| **Protocol** | Mango Markets |
| **Chain** | Solana |
| **Loss** | ~$114,000,000 (USDC, MNGO, SOL, BTC, ETH, and other assets drained from treasury) |
| **Attacker** | Avraham Eisenberg (self-disclosed) |
| **Attack Tx** | On-chain Solana; attacker publicly claimed responsibility post-exploit |
| **Vulnerable Contract** | Mango Markets lending/trading program (oracle-based margin borrowing) |
| **Root Cause** | The attacker used two accounts and a large coordinated trade to manipulate the MNGO/USDC spot price on the Mango exchange itself — the same venue used as the oracle for MNGO collateral valuation — allowing artificial inflation of collateral value and subsequent over-borrowing of all liquid assets |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere (self-referential oracle) |
| **PoC Source** | Avraham Eisenberg Twitter disclosure; OtterSec / Sec3 post-mortem |

---
## 1. Vulnerability Overview

Mango Markets is a Solana-based perpetual exchange and lending platform where users can deposit collateral (including MNGO tokens) and borrow against it. The protocol used an **internal oracle**: MNGO collateral was priced based on the MNGO/USDC spot price on Mango Markets' own orderbook.

The attacker exploited the circular dependency: by controlling a large MNGO position on the Mango orderbook, they could set the reference price used to value their own collateral, creating an unbounded feedback loop.

**Attack summary**: The attacker opened a large MNGO short position from Account A and a large MNGO long position from Account B (funded with flash-borrowed USDC). By rapidly buying MNGO with Account B, they pumped the MNGO price from ~$0.038 to ~$0.91 (~24x). Account B's MNGO position was then valued at ~$423M on paper. Against this inflated collateral, Account B borrowed every liquid asset in the Mango treasury — USDC, BTC, ETH, SOL, MSOL, USDT, SRM — totaling ~$114M. Account A's short position was left as worthless bad debt.

The attacker then submitted a governance proposal to have Mango DAO pay $47M from the insurance fund to cover the bad debt, in exchange for the attacker returning $67M and not pursuing legal action. The proposal passed (the attacker controlled enough MNGO votes) and a settlement was reached.

---
## 2. Vulnerable Code Analysis

**Language**: Rust (Solana BPF program, not EVM/Solidity)
**Source provenance**: Real open-source code from the mango-v3 repository.
Repository: https://github.com/blockworks-foundation/mango-v3

The exploit chained three real functions in the program: `cache_prices` (populates oracle cache from on-chain oracle accounts), `get_price` (reads that cache), and `get_health` (computes collateral value using the cached price). For the MNGO token, the oracle account at the time of the exploit was a Mango-controlled **Stub oracle** whose price was updated to reflect the Mango spot market's own fill price — making it self-referential and trivially manipulable.

### 1. Oracle Price Caching (real source: `program/src/processor.rs`, line 1063)

```rust
// File: program/src/processor.rs
// Source: https://github.com/blockworks-foundation/mango-v3/blob/main/program/src/processor.rs

fn cache_prices(program_id: &Pubkey, accounts: &[AccountInfo]) -> MangoResult<()> {
    let mango_group = MangoGroup::load_checked(mango_group_ai, program_id)?;
    let mut mango_cache =
        MangoCache::load_mut_checked(mango_cache_ai, program_id, &mango_group)?;
    let last_update = clock.unix_timestamp as u64;

    for oracle_ai in oracle_ais.iter() {
        let oracle_index = mango_group.find_oracle_index(oracle_ai.key).ok_or(throw!())?;
        // ❌ read_oracle reads from whatever oracle account was registered for this token.
        //    For MNGO, this was a Stub oracle — whose price was set by the Mango team
        //    to track the Mango spot market's own last-fill price.
        if let Ok(price) = read_oracle(
            &mango_group,
            oracle_index,
            oracle_ai,
            mango_cache.price_cache[oracle_index].price,
        ) {
            mango_cache.price_cache[oracle_index] = PriceCache { price, last_update };
        }
    }
    Ok(())
}
```

### 2. Oracle Reading by Type (real source: `program/src/processor.rs`, line 8459)

```rust
// File: program/src/processor.rs — pub fn read_oracle (line 8459)
// Source: https://github.com/blockworks-foundation/mango-v3/blob/main/program/src/processor.rs

pub fn read_oracle(
    mango_group: &MangoGroup,
    token_index: usize,
    oracle_ai: &AccountInfo,
    last_known_price_in_cache: I80F48,
) -> MangoResult<I80F48> {
    let oracle_type = determine_oracle_type(oracle_ai);

    let price = match oracle_type {
        OracleType::Pyth => {
            let oracle_data = oracle_ai.try_borrow_data()?;
            let price_account = pyth_client::load_price(&oracle_data).unwrap();
            // ✅ Pyth provides an external, manipulation-resistant price feed
            let value = I80F48::from_num(price_account.agg.price);
            // ... confidence filter applied ...
            value
        }
        OracleType::Stub => {
            // ❌ StubOracle price is simply a u128 field set by the program admin.
            //    For MNGO, this field was periodically updated to the Mango spot price —
            //    the same venue the attacker was trading on. No TWAP, no external source.
            let oracle = StubOracle::load(oracle_ai)?;
            I80F48::from_num(oracle.price)  // ❌ returns the manipulated spot price directly
        }
        OracleType::Switchboard => {
            // ✅ Switchboard is an external feed (used for other tokens, not MNGO)
            let result = FastRoundResultAccountData::deserialize(&oracle_ai.try_borrow_data()?).unwrap();
            I80F48::from_num(result.result.result)
        }
        OracleType::Unknown => return Err(throw_err!(MangoErrorCode::InvalidOracleType)),
    };
    Ok(price)
}
```

### 3. Price Retrieval from Cache (real source: `program/src/state.rs`, line 801)

```rust
// File: program/src/state.rs — impl MangoCache
// Source: https://github.com/blockworks-foundation/mango-v3/blob/main/program/src/state.rs

pub fn get_price(&self, i: usize) -> I80F48 {
    if i == QUOTE_INDEX {
        ONE_I80F48
    } else {
        // ❌ Returns whatever was last cached by cache_prices.
        //    For MNGO: this is the Stub oracle value = Mango's own spot price.
        self.price_cache[i].price  // ❌ attacker-controlled via on-exchange trading
    }
}
```

### 4. Health / Collateral Calculation (real source: `program/src/state.rs`)

```rust
// File: program/src/state.rs — impl HealthCache
// Source: https://github.com/blockworks-foundation/mango-v3/blob/main/program/src/state.rs

pub fn get_health(&mut self, mango_group: &MangoGroup, health_type: HealthType) -> I80F48 {
    let health_index = health_type as usize;
    match self.health[health_index] {
        None => {
            let mut health = self.quote;  // start with USDC balance
            for i in 0..mango_group.num_oracles {
                let spot_market_info = &mango_group.spot_markets[i];
                let perp_market_info = &mango_group.perp_markets[i];

                let (spot_asset_weight, spot_liab_weight, perp_asset_weight, perp_liab_weight) =
                    match health_type {
                        HealthType::Init => (
                            spot_market_info.init_asset_weight,
                            spot_market_info.init_liab_weight,
                            perp_market_info.init_asset_weight,
                            perp_market_info.init_liab_weight,
                        ),
                        // ... Maint / Equity cases ...
                    };

                if self.active_assets.spot[i] {
                    let (base, quote) = self.spot[i];
                    // ❌ `base` is the MNGO position size;
                    //    the price embedded in `base` comes from get_price(i) above,
                    //    which returned the Stub oracle value = manipulated spot price.
                    //    Attacker's 488M MNGO @ $0.91 = $423M phantom collateral.
                    if base.is_negative() {
                        health += base * spot_liab_weight + quote;
                    } else {
                        health += base * spot_asset_weight + quote;  // ❌ inflated by 24x
                    }
                }
            }
            self.health[health_index] = Some(health);
            health
        }
        Some(h) => h,
    }
}
```

### Borrow check that approved the theft

```rust
// File: program/src/processor.rs — withdraw (simplified)
let health = health_cache.get_health(&mango_group, HealthType::Init);
// ❌ With ~$423M phantom MNGO collateral, health is strongly positive even after
//    borrowing the entire $114M treasury. The borrow is approved unconditionally.
check!(health >= ZERO_I80F48, MangoErrorCode::InsufficientFunds)?;
```

### Fix applied in mango-v4

```rust
// ✅ mango-v4 replaced Stub oracles with Pyth + staleness + confidence checks:
let oracle_price = load_pyth_price(oracle_ai, clock)?;
// Reject if confidence interval > threshold (price uncertainty too high)
require!(
    oracle_price.conf.checked_div(oracle_price.price).unwrap() < MAX_CONFIDENCE_RATIO,
    MangoError::OraclePriceConfidenceTooLow
);
// Additionally: circuit breakers on >20% single-block price moves
```

**Why it is exploitable (identify the bug from the code):**

- `read_oracle()` for the MNGO token dispatched to `OracleType::Stub`, returning `oracle.price` — a plain integer field stored on-chain in a Mango-controlled account, periodically synced to Mango's own spot market last-fill price.
- There is no TWAP window, no external oracle, and no staleness or confidence check for the Stub oracle path.
- `get_price(i)` returns this value verbatim from the cache, and `get_health()` multiplies it by the attacker's full MNGO position (488M tokens).
- At the manipulated price of $0.91/MNGO, the health calculation yields ~$423M phantom collateral.
- The withdraw path's only guard is `health >= ZERO_I80F48` — trivially satisfied with $423M fake collateral minus $114M real borrow, so every asset in the treasury was released.

---
## 3. Attack Flow

```
Attacker (with ~$10M USDC initial capital)
    │
    ├─[1] Account A: Open large MNGO perpetual SHORT position on Mango
    │       → Account A now short MNGO (will profit if MNGO falls)
    │
    ├─[2] Account B: Deposit flash-borrowed USDC as collateral
    │       → Use as buying power on Mango spot market
    │
    ├─[3] Account B: Buy massive amounts of MNGO on Mango spot
    │       MNGO spot price: $0.038 → $0.91 (~24x in minutes)
    │       Account B accumulates ~488M MNGO (Mango's entire float)
    │
    ├─[4] Mango's oracle reflects the manipulated price $0.91
    │       Account B paper collateral: ~$423M
    │
    ├─[5] Account B borrows ALL liquid assets against inflated collateral:
    │       ~$114M: USDC, BTC, ETH, SOL, MSOL, USDT, SRM, MNGO
    │       → Mango treasury effectively emptied
    │
    ├─[6] Account A's short position becomes worthless bad debt
    │       (MNGO price already manipulated up; short loses)
    │       Mango insurance fund must cover the bad debt
    │
    ├─[7] Attacker submits DAO governance proposal:
    │       "Pay $47M from insurance fund; attacker returns $67M"
    │       → Attacker votes YES with stolen MNGO; proposal passes
    │
    └─[8] Settlement: attacker returns ~$67M; keeps ~$47M
              Eisenberg later arrested by FBI (Dec 2022) for market manipulation
```

---
## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Self-referential oracle — collateral priced by the same exchange that is being traded |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Oracle price manipulation (spot price used as collateral oracle on same venue) |
| **Attack Vector** | Coordinated large buy on Mango spot market inflates internal oracle → collateral inflated → over-borrowing |
| **Preconditions** | MNGO collateral priced by Mango's own spot price; no TWAP or external oracle; low liquidity allowing large price impact |
| **Impact** | ~$114M drained from protocol treasury; ~$47M net attacker profit after settlement |

---
## 5. Remediation Recommendations

1. **Use external time-weighted oracles for collateral pricing**: Never use the same venue's spot price as the collateral oracle for that venue's own assets. Use Pyth, Switchboard, or Chainlink with TWAP windows.
2. **Impose concentration limits on low-liquidity collateral**: MNGO had very low liquidity; accepting it as margin collateral at market price enabled unlimited manipulation. Apply haircuts and position limits for illiquid assets.
3. **Circuit breakers on abnormal price moves**: Reject collateral valuations that deviate more than a threshold (e.g., 20%) from a reference price in a single block.
4. **Governance proposal quorum from uncompromised tokens**: Governance votes during or immediately after an exploit should require quorum from tokens not involved in the exploit.

---
## 6. Lessons Learned

- **Self-referential oracles are a critical design flaw**: Using an exchange's own orderbook to price collateral on that same exchange creates a closed feedback loop that any large actor can exploit.
- **"Intentional" market manipulation is still illegal**: Avraham Eisenberg publicly claimed the attack was a "legal" use of the protocol's mechanics. He was arrested in December 2022 on federal commodities fraud and manipulation charges, demonstrating that on-chain exploits have off-chain legal consequences.
- **Governance as an exit path**: The attacker weaponized Mango's governance to legitimize the theft. Protocols must prevent governance votes during active exploits and require multi-day timelocks for treasury access proposals.
- **Low-liquidity collateral is high risk**: MNGO's thin market made the price manipulation cheap relative to the profit. Strict collateral whitelisting and liquidity requirements are essential for lending protocols.
