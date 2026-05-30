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

> ⚠️ Contract not verified on Sourcify — Mango Markets is a Solana-based program written in **Rust** (not Solidity). There is no EVM contract to fetch. The real source code is available in the Mango Markets GitHub repository (open source). The Rust code below is sourced directly from the mango-v3 repository and reflects the actual program logic.

Source: **Open-source Rust program** — mango-v3 repository
https://github.com/blockworks-foundation/mango-v3

```rust
// File: program/src/state.rs — MangoAccount collateral / health calculation
// Real source language: Rust (Solana BPF program)

// The oracle price for each market is fetched from the oracle field stored
// in the MarketInfo. For MNGO/USDC, this pointed to Mango's own CLOB (central
// limit order book) last-trade price — a self-referential price feed.

pub fn get_health(
    mango_group: &MangoGroup,
    mango_account: &MangoAccount,
    health_type: HealthType,
    open_orders_ais: &[AccountInfo],
) -> MangoResult<I80F48> {
    let mut health = ZERO_I80F48;
    let prices = &mango_group.oracles; // ❌ oracle prices read from group state

    for i in 0..NUM_TOKENS {
        let base_net = mango_account.get_net(i); // deposit/borrow position
        // ❌ prices[i] for MNGO is sourced from the Mango spot market itself —
        //    the same venue the attacker is trading on.
        //    By pushing the MNGO/USDC spot price from $0.038 to $0.91,
        //    the attacker directly controls prices[MNGO_INDEX] here.
        let weighted_price = if health_type == HealthType::Init {
            mango_group.get_price(i) * mango_group.spot_markets[i].init_asset_weight // ❌
        } else {
            mango_group.get_price(i) * mango_group.spot_markets[i].maint_asset_weight
        };
        health += base_net * weighted_price; // ❌ collateral value = position * manipulated oracle price
    }
    Ok(health)
}

// The borrow limit check uses the same health score:
// if health > 0 after adding proposed borrow, borrow is allowed.
// With MNGO inflated 24x, health appears massive → unlimited borrowing permitted.

// ✅ Fix: replace self-referential oracle with Pyth/Switchboard TWAP
// In mango-v4 (post-exploit), the protocol moved to Pyth and Switchboard
// price feeds with staleness checks and confidence band rejection:
//
//   let oracle_price = load_pyth_price(oracle_ai, clock)?;
//   require!(oracle_price.confidence / oracle_price.price < MAX_CONFIDENCE_RATIO,
//            MangoError::OraclePriceConfidenceTooLow);
```

**Why it is exploitable (identify the bug from the code):**

- `get_health()` reads `mango_group.get_price(i)` which for MNGO returned the Mango CLOB's own most-recent fill price.
- No TWAP window, no external oracle, no staleness check — the price updates in real time with every trade.
- By executing a large coordinated buy of MNGO on the same exchange, the attacker sets the oracle price to any value.
- The health calculation multiplies the manipulated price by the attacker's full MNGO position, producing a paper-collateral value of ~$423M.
- The borrow function checks `health > 0` after adding the proposed debt — with $423M fake collateral and $114M real borrow, health remains positive and the borrow succeeds.

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
