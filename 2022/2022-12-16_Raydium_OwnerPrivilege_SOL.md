# Raydium — Admin Private Key Compromise LP Fee Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12-16 |
| **Protocol** | Raydium (Solana DEX) |
| **Chain** | Solana |
| **Loss** | ~$4,400,000 (LP fees and pool reserves drained across 6 pools) |
| **Attacker** | Exploiter address on Solana (unconfirmed public identity) |
| **Vulnerable Contract** | Raydium AMM program (admin withdraw_pnl function) |
| **Root Cause** | Raydium's AMM program contained a privileged `withdraw_pnl()` admin function to collect trading fees; the attacker compromised the admin private key and called this function to drain collected fees, then exploited a secondary function to withdraw LP token reserves beyond the intended fee amounts |
| **CWE** | CWE-284: Improper Access Control (compromised admin key) |
| **PoC Source** | Raydium official post-mortem (Dec 2022); OtterSec analysis |

---
## 1. Vulnerability Overview

Raydium is one of Solana's largest AMMs with billions in TVL. The Raydium AMM program included an administrative `withdraw_pnl()` function intended for the team to collect accumulated trading protocol fees. This function was guarded by an admin keypair held by the Raydium team.

On December 16, 2022, the attacker obtained the admin private key through an unconfirmed means (suspected infrastructure compromise — Raydium's internal systems were breached). With the admin key, the attacker:
1. Called `withdraw_pnl()` on 6 Raydium AMM pools to drain the accumulated protocol fees.
2. Additionally exploited the admin parameters to withdraw **pool LP reserves directly**, beyond what `withdraw_pnl()` was intended to allow — indicating either a second vulnerability in parameter handling or that the admin key had broader authority than intended.

Affected pools included SOL-USDC, SOL-USDT, RAY-USDC, RAY-USDT, RAY-SOL, and stSOL-USDC. Total drained: approximately $4.4M.

---
## 2. Vulnerable Code Analysis

```rust
// ❌ Vulnerable Raydium AMM admin function (pseudocode)
#[program]
pub mod raydium_amm {
    // Admin function to collect protocol fees — guarded only by single admin key
    pub fn withdraw_pnl(ctx: Context<WithdrawPnl>) -> Result<()> {
        // ❌ Single admin key controls all fee withdrawal
        require!(
            ctx.accounts.amm_authority.key() == ADMIN_PUBKEY,
            AmmError::InvalidAuthority
        );
        
        // Transfer accumulated fees to admin
        let fee_amount = ctx.accounts.amm_pool.total_fees;
        token::transfer(
            ctx.accounts.into_transfer_fees_context(),
            fee_amount,
        )?;
        ctx.accounts.amm_pool.total_fees = 0;
        
        Ok(())
    }
    
    // ❌ Additional admin parameter that allowed broader reserve access
    pub fn set_params(ctx: Context<SetParams>, params: AmmParams) -> Result<()> {
        require!(
            ctx.accounts.amm_authority.key() == ADMIN_PUBKEY,
            AmmError::InvalidAuthority
        );
        // ❌ Parameter manipulation could expose reserve withdrawal beyond fees
        ctx.accounts.amm_pool.apply_params(params)?;
        Ok(())
    }
}

// ✅ Correct pattern: multisig authority + separate fee collection cap
pub fn withdraw_pnl_safe(ctx: Context<WithdrawPnl>) -> Result<()> {
    // ✅ Require multisig approval (Squads, SPL Governance)
    require!(
        ctx.accounts.multisig_approved,
        AmmError::MultisigRequired
    );
    
    // ✅ Withdraw only tracked fees, not pool reserves
    let fee_amount = ctx.accounts.amm_pool.claimable_fees;
    require!(fee_amount > 0, AmmError::NoFeesToWithdraw);
    
    // ✅ Enforce cap: fees cannot exceed reasonable % of pool TVL
    let pool_tvl = ctx.accounts.amm_pool.total_reserves;
    require!(fee_amount <= pool_tvl / 10, AmmError::ExceedsFeeCap);
    
    token::transfer(ctx.accounts.into_transfer_fees_context(), fee_amount)?;
    ctx.accounts.amm_pool.claimable_fees = 0;
    Ok(())
}
```

---
## 3. Attack Flow

```
Attacker
    │
    ├─[1] Compromise Raydium admin private key
    │       (Raydium suspects infrastructure breach of internal systems)
    │
    ├─[2] Call withdraw_pnl() on 6 AMM pools using admin key
    │       Drains accumulated protocol fees from each pool
    │
    ├─[3] Exploit admin parameter control to access pool LP reserves
    │       (beyond intended fee amounts)
    │       Additional SOL, USDC, RAY, stSOL drained
    │
    ├─[4] Total ~$4.4M extracted across:
    │       SOL-USDC pool: largest portion
    │       SOL-USDT, RAY-USDC, RAY-USDT, RAY-SOL, stSOL-USDC pools
    │
    └─[5] Raydium team identifies exploit, migrates admin authority to new key
              LP providers informed; Raydium DAO votes on reimbursement
```

---
## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Compromised admin private key — privileged fee withdrawal and parameter manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP** | A07: Identification and Authentication Failures |
| **Attack Vector** | Attacker obtains admin EOA key; calls privileged withdraw and set_params functions |
| **Preconditions** | Single admin key controls all fee withdrawal; admin has access to pool reserves |
| **Impact** | ~$4.4M drained from 6 AMM pools; LP providers partially reimbursed by Raydium DAO |

---
## 5. Remediation Recommendations

1. **Replace single admin key with multisig (Squads Protocol)**: All privileged admin functions must require M-of-N multisig approval, where N ≥ 3 and keys are on separate hardware wallets.
2. **Separate fee collection from pool reserve access**: The `withdraw_pnl()` function should only be able to access tracked fee accumulation, never the pool's LP reserve balances. Enforce this distinction in the data model.
3. **Timelock on parameter changes**: Admin parameter changes should have a 24-48h timelock, allowing the community to detect and react before changes take effect.
4. **Real-time monitoring and circuit breakers**: Anomalous large withdrawals from admin functions should trigger automatic pool pause alerts.

---
## 6. Lessons Learned

- **Admin key compromise is a recurring DeFi threat**: Multiple 2022 incidents (Ronin, Harmony, Ankr, Raydium) involved compromised privileged keys. Hardware wallets and air-gapped signing are minimum requirements for admin keys.
- **Solana program admin functions need multisig**: Solana's Squads Protocol and SPL Governance provide on-chain multisig and DAO governance for program admin authority. Using them is not optional for high-TVL protocols.
- **Minimize admin function scope**: The admin should be able to collect fees without having access to pool reserves. Overprivileged admin functions turn a key compromise into a total loss.
- **Community reimbursement**: Raydium DAO voted to use buyback treasury funds to partially reimburse affected LPs, demonstrating how having a protocol treasury can mitigate user impact after exploits.
