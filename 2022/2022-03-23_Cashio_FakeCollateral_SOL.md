# Cashio — Fake Collateral Infinite Mint Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-23 |
| **Protocol** | Cashio (CASH stablecoin on Solana) |
| **Chain** | Solana |
| **Loss** | ~$52,000,000 (CASH stablecoin minted without real collateral; protocol effectively wiped out) |
| **Attacker** | Address on Solana: unconfirmed (multiple transfer hops) |
| **Vulnerable Contract** | Cashio CASH mint program (collateral account validation) |
| **Root Cause** | Cashio's mint function did not validate that the collateral LP token accounts passed by the user were officially registered in the protocol — an attacker could pass arbitrary accounts they created, which were accepted as valid collateral, allowing unlimited CASH minting without real backing |
| **CWE** | CWE-284: Improper Access Control (missing account ownership/registration check) |
| **PoC Source** | Neodyme, OtterSec post-mortems; no public DeFiHackLabs PoC (Solana) |

---
## 1. Vulnerability Overview

Cashio was a Solana-based algorithmic stablecoin backed by USDC-USDT Saber LP tokens. Users deposited Saber LP tokens as collateral and received CASH stablecoins in return. The Cashio mint program was supposed to verify that the collateral LP token accounts passed were legitimate, registered Saber LP positions.

The critical flaw: the Cashio program checked that a "collateral account" had a certain relationship to an "arrow" (Cashio's collateral tracking structure), but it **did not verify that the arrow itself was created and registered by Cashio protocol**. An attacker could create their own fake arrow account, link it to a fake collateral account, and pass these through the mint flow. Because Cashio only validated the relationship between the user-supplied accounts (which the attacker controlled), it accepted the fake collateral chain as valid and minted CASH against it.

The attacker created a chain of fake accounts pointing to each other and ultimately to a tiny amount of real LP tokens, then minted ~$52M in CASH which was immediately swapped for USDC, UST, and other stablecoins across Solana DEXes.

---
## 2. Vulnerable Code Analysis

> ⚠️ Contract not verified on Sourcify — Cashio is a Solana (non-EVM) program; Sourcify does not index Solana. The Rust code below is reconstructed from Neodyme and OtterSec post-mortems and public analysis, not a verified on-chain source dump.

The real language is **Rust** (Anchor framework, Solana BPF). No Solidity exists.

```rust
// ⚠️ RECONSTRUCTED — not verified on Sourcify (Solana program, non-EVM).
// Derived from Neodyme / OtterSec post-mortems and Anchor account validation patterns.
// Cashio CASH mint program — print_cash instruction

#[program]
pub mod cashio {
    use super::*;

    pub fn print_cash(ctx: Context<PrintCash>, amount: u64) -> Result<()> {
        let collateral = &ctx.accounts.collateral;
        let arrow      = &ctx.accounts.arrow;        // ❌ user-supplied — not verified as Cashio PDA

        // ❌ Only checks internal consistency between two user-supplied accounts.
        //    Does NOT verify that `arrow` was derived from Cashio's program ID.
        //    An attacker creates a fake `arrow` that satisfies this check.
        require!(
            arrow.collateral_mint == collateral.mint,
            CashioError::InvalidCollateral   // ❌ passes with attacker's fake arrow
        );

        // ❌ Both `arrow` and `collateral` are attacker-controlled accounts.
        //    The attacker sets arrow.price_per_token to any value they like.
        let collateral_value = (collateral.amount as u128)
            .checked_mul(arrow.price_per_token as u128)
            .unwrap();

        // Mint CASH against the (fake) collateral_value
        token::mint_to(
            ctx.accounts.into_mint_cash_context(),
            amount,  // ❌ amount not bounded by actual collateral value
        )?;
        Ok(())
    }
}

// ✅ Fix: verify arrow is a PDA derived from Cashio's own program (cannot be forged by attacker)
pub fn print_cash_fixed(ctx: Context<PrintCash>, amount: u64) -> Result<()> {
    let arrow = &ctx.accounts.arrow;

    // ✅ PDA check — only Cashio's program can have created an account at this address
    let (expected_pda, _bump) = Pubkey::find_program_address(
        &[b"arrow", arrow.collateral_mint.as_ref()],
        ctx.program_id,
    );
    require!(
        arrow.key() == expected_pda,
        CashioError::InvalidArrow  // ✅ rejects any arrow not created by Cashio
    );

    // ✅ Additional: whitelist check on collateral mint
    require!(
        APPROVED_COLLATERAL_MINTS.contains(&arrow.collateral_mint),
        CashioError::UnauthorizedCollateral
    );

    let collateral_value = (collateral.amount as u128)
        .checked_mul(arrow.price_per_token as u128)
        .unwrap();
    token::mint_to(ctx.accounts.into_mint_cash_context(), amount)?;
    Ok(())
}
```

**Why it is exploitable (identify the bug from the code):**
- Solana programs receive all accounts as instruction arguments. `print_cash` does **not** derive or verify the `arrow` account's address — it only checks that `arrow.collateral_mint == collateral.mint`, a consistency check between two attacker-controlled accounts.
- The attacker creates a fake `arrow` account whose `collateral_mint` field matches a real LP mint, funding the fake `collateral` account with 1 lamport of real LP tokens.
- Both accounts are attacker-owned, so all Anchor `constraint` checks pass. Cashio mints CASH proportional to whatever `amount` the attacker requests.
- The fix is a PDA derivation check: `Pubkey::find_program_address(seeds, program_id)` produces an address that only the program itself can sign for — an attacker cannot forge it.

---
## 3. Attack Flow

```
Attacker (Solana)
    │
    ├─[1] Create a fake "arrow" account that mimics a Cashio arrow
    │       Set arrow.collateral_mint = legitimate LP mint address
    │       Set arrow.price_per_token = real LP price
    │       (Arrow is NOT registered in Cashio protocol)
    │
    ├─[2] Create a fake "collateral" account referencing the fake arrow
    │       Fund it with a tiny amount of real LP tokens (1 wei equivalent)
    │
    ├─[3] Call Cashio print_cash() with the fake accounts
    │       Cashio checks: arrow.collateral_mint == collateral.mint ✓ (both attacker-set)
    │       Cashio does NOT check: is this arrow a real Cashio PDA? ✗
    │       → CASH minted against fake collateral
    │
    ├─[4] Repeat with inflated amounts — mint ~$52M CASH
    │
    ├─[5] Swap CASH → USDC, UST, other stablecoins on Saber, Mercurial
    │       → Protocol treasury and LP pools drained
    │
    └─[6] Funds routed through multiple hops; ~$52M extracted
              Cashio protocol effectively destroyed; CASH depegged to ~$0
```

---
## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing account provenance check — fake accounts accepted as valid protocol collateral |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Input validation failure (Solana account validation) |
| **Attack Vector** | Attacker-created fake arrow and collateral accounts passed to print_cash() |
| **Preconditions** | Arrow account not validated as a Cashio PDA; no whitelist check on arrow registration |
| **Impact** | ~$52M CASH minted without real backing; protocol fully insolvent |

---
## 5. Remediation Recommendations

1. **Validate all accounts as program-owned PDAs**: In Solana programs, every account passed to an instruction must be verified as a PDA derived from known seeds and the program's own ID. Attacker-created accounts will not match the expected PDA.
2. **Maintain an on-chain whitelist of approved collateral accounts**: The protocol should have a master registry of all approved arrows/collateral types, stored in a PDA only the protocol can write to, and verified for every mint operation.
3. **Use Anchor's `has_one` and `constraint` guards**: Anchor framework provides declarative account validation that catches these account substitution attacks at the framework level.
4. **Formal audit of all account validation paths**: Every account in the instruction context must have an explicit validation — any unvalidated account is an attack surface.

---
## 6. Lessons Learned

- **Solana account validation is the primary attack surface**: Unlike EVM contracts where state lives in the contract itself, Solana programs receive all accounts as function arguments. Every single account must be explicitly validated — its owner, its derivation seeds, its mint, and its data structure.
- **"Checking relationships" is not the same as "validating provenance"**: Cashio checked that arrow and collateral were consistent with each other, but not that either was legitimate. Consistency checks on attacker-controlled data provide no security.
- **Anchor's constraints are not optional**: The Anchor framework provides macros like `constraint`, `has_one`, and `seeds` that enforce account validity. Bypassing or under-using these is a common Solana exploit pattern.
- **Stablecoin protocols are high-value targets**: CASH's collateral design was a single point of failure — one account validation bug caused total protocol insolvency.
