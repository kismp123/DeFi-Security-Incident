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

**Language:** Rust (Anchor framework, Solana BPF). No Solidity exists — Cashio is a Solana program.
**Source provenance:** REAL SOURCE — retrieved verbatim from [`cashioapp/cashio`](https://github.com/cashioapp/cashio) on GitHub (public repository). The `brrr` program handles `print_cash`; the `bankman` program manages the collateral allowlist.

### The Vulnerable `BrrrCommon::validate()` — pre-patch

The patch commit [`7df6581`](https://github.com/cashioapp/cashio/commit/7df658184c2610139fa2c0058363c66b28add4c4) added one line to `programs/brrr/src/actions/mod.rs`. The **pre-patch** (vulnerable) validate was:

```rust
// programs/brrr/src/actions/mod.rs  — VULNERABLE (pre-patch)
// Real source: cashioapp/cashio, commit prior to 7df6581
// Language: Rust, Anchor framework

impl<'info> Validate<'info> for BrrrCommon<'info> {
    fn validate(&self) -> Result<()> {
        assert_keys_eq!(self.bank, self.collateral.bank);
        // ❌ MISSING: assert_keys_eq!(self.bank.crate_mint, self.crate_mint);
        //    Without this check, an attacker can supply a `bank` account that is
        //    a legitimate Bankman PDA for a *different* crate_mint, breaking
        //    the chain of trust between bank → crate_mint → collateral mint.
        assert_keys_eq!(self.crate_token, self.crate_collateral_tokens.owner);
        assert_keys_eq!(self.crate_mint, self.crate_token.mint);
        assert_keys_eq!(self.crate_collateral_tokens.mint, self.collateral.mint);

        // saber swap (SaberSwapAccounts::validate below)
        self.saber_swap.validate()?;
        assert_keys_eq!(self.collateral.mint, self.saber_swap.arrow.mint);

        Ok(())
    }
}
```

### `SaberSwapAccounts::validate()` — real source

```rust
// programs/brrr/src/saber.rs — real source (cashioapp/cashio, master branch)
impl<'info> Validate<'info> for SaberSwapAccounts<'info> {
    fn validate(&self) -> Result<()> {
        assert_keys_eq!(self.arrow.vendor_miner.mint, self.pool_mint);
        assert_keys_eq!(self.saber_swap.pool_mint, self.pool_mint);
        assert_keys_eq!(self.saber_swap.token_a.reserves, self.reserve_a);
        assert_keys_eq!(self.saber_swap.token_b.reserves, self.reserve_b);
        // ❌ MISSING: no check that `self.saber_swap` (the Arrow PDA) was
        //    created and registered by the Cashio Bankman program.
        //    The attacker supplies a self-created Arrow account whose
        //    `vendor_miner.mint` and `pool_mint` they control.
        Ok(())
    }
}
```

### The `print_cash` instruction entry point — real source

```rust
// programs/brrr/src/lib.rs — real source (cashioapp/cashio, master branch)
#[program]
pub mod brrr {
    use super::*;

    /// Prints $CASH.
    /// $CASH can be printed by depositing Saber LP tokens.
    #[access_control(ctx.accounts.validate())]  // ← calls BrrrCommon::validate() above
    pub fn print_cash(ctx: Context<PrintCash>, deposit_amount: u64) -> Result<()> {
        // After the exploit, Cashio added: vipers::invariant!(false, "temporarily disabled");
        // The vulnerable on-chain version did NOT have this guard.
        actions::print_cash::print_cash(ctx, deposit_amount)
    }
}
```

### `print_cash` action — real source

```rust
// programs/brrr/src/actions/print_cash.rs — real source (cashioapp/cashio, master branch)
pub fn print_cash(ctx: Context<PrintCash>, deposit_amount: u64) -> Result<()> {
    ctx.accounts.print_cash(deposit_amount)
}

impl<'info> PrintCash<'info> {
    fn print_cash(&self, deposit_amount: u64) -> Result<()> {
        let current_balance = self.common.crate_collateral_tokens.amount;
        require!(
            unwrap_int!(current_balance.checked_add(deposit_amount))
                <= self.common.collateral.hard_cap,
            CollateralHardCapHit
        );

        // swap.calculate_cash_for_pool_tokens() uses the Saber LP virtual price.
        // With a fake arrow, the attacker controls pool reserve values → arbitrary print_amount.
        let swap: CashSwap = (&self.common.saber_swap).try_into()?;
        let print_amount = unwrap_int!(swap.calculate_cash_for_pool_tokens(deposit_amount));
        if print_amount == 0 {
            return Ok(());
        }

        // Transfer attacker's fake LP tokens to the crate.
        anchor_spl::token::transfer(
            CpiContext::new(
                self.common.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: self.depositor_source.to_account_info(),
                    to: self.common.crate_collateral_tokens.to_account_info(),
                    authority: self.depositor.to_account_info(),
                },
            ),
            deposit_amount,
        )?;

        // ❌ Issues CASH against attacker-supplied collateral with no provenance check.
        crate_token::cpi::issue(
            CpiContext::new_with_signer(
                self.common.crate_token_program.to_account_info(),
                crate_token::cpi::accounts::Issue {
                    crate_token: self.common.crate_token.to_account_info(),
                    crate_mint: self.common.crate_mint.to_account_info(),
                    issue_authority: self.issue_authority.to_account_info(),
                    mint_destination: self.mint_destination.to_account_info(),
                    author_fee_destination: self.mint_destination.to_account_info(),
                    protocol_fee_destination: self.mint_destination.to_account_info(),
                    token_program: self.common.token_program.to_account_info(),
                },
                ISSUE_AUTHORITY_SIGNER_SEEDS,
            ),
            print_amount,
        )?;
        Ok(())
    }
}
```

### Fixed Version (real patch — commit `7df6581`)

```rust
// programs/brrr/src/actions/mod.rs — PATCHED (post-exploit)
impl<'info> Validate<'info> for BrrrCommon<'info> {
    fn validate(&self) -> Result<()> {
        assert_keys_eq!(self.bank, self.collateral.bank);
        // ✅ ADDED: ensures the `bank` account's registered crate_mint matches
        //    the crate_mint account actually passed in.
        //    An attacker cannot forge this: bank is a PDA derived by Bankman,
        //    and bank.crate_mint is stored on-chain by the protocol at bank creation.
        assert_keys_eq!(self.bank.crate_mint, self.crate_mint);   // ← ONE LINE FIX
        assert_keys_eq!(self.crate_token, self.crate_collateral_tokens.owner);
        assert_keys_eq!(self.crate_mint, self.crate_token.mint);
        assert_keys_eq!(self.crate_collateral_tokens.mint, self.collateral.mint);
        self.saber_swap.validate()?;
        assert_keys_eq!(self.collateral.mint, self.saber_swap.arrow.mint);
        Ok(())
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- Solana programs receive all accounts as instruction arguments. `BrrrCommon::validate()` checks a chain of `assert_keys_eq!` relationships between user-supplied accounts, but the root anchor of that chain — the `bank` account — was not fully verified before the patch.
- Specifically, the check `assert_keys_eq!(self.bank.crate_mint, self.crate_mint)` was absent. Without it, an attacker could supply a legitimate-looking `bank` PDA (created by Bankman for a different crate) paired with attacker-created `crate_token`, `crate_mint`, and `collateral` accounts. The chain of `assert_keys_eq!` checks all passed because the attacker crafted each account to satisfy the pairwise comparison with the next.
- The `SaberSwapAccounts::validate()` similarly only checks internal field consistency within the attacker-supplied arrow — it does not verify that the arrow was registered in Cashio's Bankman allowlist.
- The fix is a single `assert_keys_eq!(self.bank.crate_mint, self.crate_mint)` that ensures the bank's on-chain `crate_mint` field matches the `crate_mint` account passed in — a fact the attacker cannot forge because `bank` is a Bankman PDA and `bank.crate_mint` was written by the protocol, not the user.

---
## 3. Attack Flow

```
Attacker (Solana)
    │
    ├─[1] Craft a fake account chain that satisfies pairwise assert_keys_eq! checks
    │       Create a fake `bank` PDA (mirroring a legitimate Bankman bank structure)
    │       Create a fake `collateral` account with collateral.bank = fake_bank.key()
    │       Create a fake `crate_token` with crate_token.mint = fake_crate_mint
    │       Create a fake `crate_mint` (newly created SPL mint controlled by attacker)
    │       Create a fake Arrow account with arrow.vendor_miner.mint = pool_mint
    │       Create a fake `crate_collateral_tokens` account
    │
    ├─[2] Verify pairwise checks will pass:
    │       bank == collateral.bank                  ✓ (both attacker-set)
    │       -- bank.crate_mint == crate_mint          ✗ MISSING CHECK (pre-patch)
    │       crate_token == crate_collateral_tokens.owner ✓ (attacker-set)
    │       crate_mint == crate_token.mint            ✓ (attacker-set)
    │       crate_collateral_tokens.mint == collateral.mint ✓ (attacker-set)
    │       arrow.vendor_miner.mint == pool_mint      ✓ (attacker-set)
    │       saber_swap.pool_mint == pool_mint         ✓ (attacker-set)
    │       collateral.mint == arrow.mint             ✓ (attacker-set)
    │       → All validate() checks PASS
    │
    ├─[3] Call print_cash() with fake account bundle
    │       CashSwap.calculate_cash_for_pool_tokens() uses attacker-controlled
    │       pool reserves → returns arbitrary print_amount
    │       crate_token::issue() mints CASH to attacker-controlled destination
    │       → Billions of CASH minted with negligible real collateral
    │
    ├─[4] Repeat — attacker minted ~2,000,000,000 CASH total
    │
    ├─[5] Swap CASH → USDC, UST, other stablecoins on Saber, Mercurial
    │       → Protocol LP pools and treasury drained
    │
    └─[6] Funds routed through multiple hops; ~$52M extracted
              CASH depegged to $0.00005; Cashio protocol permanently shut down
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

1. **Every account relationship in the chain must be verified, not just adjacent pairs**: The Cashio bug was not missing a single check — it was assuming that checking `A == B` and `B == C` and `C == D` implied trust in `A`. An attacker who controls `A` can create `B`, `C`, `D` to form a consistent chain. Each account must be independently verified against a trusted, protocol-owned on-chain source.
2. **Anchor `has_one` on every critical relationship**: The `BrrrCommon` struct's `bank` should have an Anchor-level `has_one = crate_mint` constraint so the framework enforces `bank.crate_mint == crate_mint` declaratively, not just in `validate()`.
3. **PDA ownership check for the root of trust**: The `bank` account's address should be verified as a PDA derived by the Bankman program (`seeds = [b"Bank", crate_token.key]`). An attacker cannot forge a PDA derived by a program they don't control.
4. **Arrow registration whitelist**: All legitimate Cashio arrows should be registered in the Bankman program's state. `SaberSwapAccounts::validate()` should check that `self.arrow.key()` appears in the Bankman-owned collateral registry.
5. **Formal audit of all account validation paths**: Every account in the instruction context must have an explicit validation — any unvalidated account is an attack surface.

---
## 6. Lessons Learned

- **"Checking relationships" is not the same as "validating provenance"**: Cashio checked that arrow and collateral were consistent with each other, but not that either was legitimate. Consistency checks on attacker-controlled data provide no security — the attacker crafted every account to satisfy the pairwise checks.
- **The missing check was one line**: `assert_keys_eq!(self.bank.crate_mint, self.crate_mint)` — added in commit `7df6581`. This is the canonical example of a "one-line fix, $52M loss" Solana account validation bug.
- **Anchor's constraints are not optional**: The Anchor framework provides macros like `constraint`, `has_one`, and `seeds` that enforce account validity at the framework level. Manual validate() implementations are harder to get right; prefer declarative Anchor constraints where possible.
- **Solana account validation is the primary attack surface**: Unlike EVM contracts where state lives in the contract itself, Solana programs receive all accounts as function arguments. Every single account must be explicitly validated — especially the root-of-trust accounts like `bank`.
- **Stablecoin protocols are high-value targets**: CASH's collateral design was a single point of failure — one missing account validation check caused total protocol insolvency. ~2 billion CASH was minted in the attack.

## References

- [Cashio GitHub (cashioapp/cashio)](https://github.com/cashioapp/cashio)
- [Patch commit 7df6581 — adds missing bank.crate_mint check](https://github.com/cashioapp/cashio/commit/7df658184c2610139fa2c0058363c66b28add4c4)
- [Ackee Blockchain: 2022 Solana Hacks Explained — Cashio](https://ackee.xyz/blog/2022-solana-hacks-explained-cashio/)
- [sec3 (Soteria): CashioApp Attack — What's the Vulnerability](https://medium.com/coinmonks/cashioapp-attack-whats-the-vulnerability-and-how-soteria-detects-it-2e96b9c6d1d3)
- [NaryaAI Cashio Exploit Workshop](https://github.com/NaryaAI/cashio-exploit-workshop)
