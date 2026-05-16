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

```rust
// ❌ Vulnerable Mango Markets collateral pricing (simplified)
// MNGO collateral value is derived from Mango's own internal oracle
// which reflects the most recent trade price on the Mango spot market

fn get_collateral_value(account: &MangoAccount, market_prices: &[I80F48]) -> I80F48 {
    let mngo_price = market_prices[MNGO_MARKET_INDEX]; // ❌ Self-referential: Mango's own spot price
    let mngo_balance = account.deposits[MNGO_INDEX];
    
    // If attacker controls the MNGO spot price on this same exchange,
    // they control the collateral value calculation
    mngo_balance * mngo_price  // ❌ Unlimited manipulation possible
}

fn max_borrow(account: &MangoAccount, market_prices: &[I80F48]) -> I80F48 {
    let collateral_value = get_collateral_value(account, market_prices);
    collateral_value * INIT_LEVERAGE  // ❌ Based on manipulated price
}

// ✅ Correct pattern: use external, manipulation-resistant oracle (Pyth, Switchboard TWAP)
fn get_collateral_value_safe(account: &MangoAccount) -> I80F48 {
    // Use time-weighted average price from external oracle network
    let mngo_price = pyth_oracle.get_twap(MNGO_USD, TWAP_WINDOW_SECONDS);
    let mngo_balance = account.deposits[MNGO_INDEX];
    mngo_balance * mngo_price
}
```

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
