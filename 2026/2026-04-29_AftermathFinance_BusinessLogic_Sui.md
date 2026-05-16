# Aftermath Finance — Integer Underflow in Perp Fee Calculation Drains ~$1.14M

| Field | Details |
|------|------|
| **Date** | 2026-04-29 |
| **Protocol** | Aftermath Finance (Perpetuals module, Sui) |
| **Chain** | Sui |
| **Loss** | ~$1,140,000 |
| **Root Cause** | Integer Underflow / Business Logic Flaw — `integrator_taker_fees` calculation underflows to `≈ u256::MAX` when an integrator sets `max_taker_fee = 0`, causing the protocol to credit astronomically large fees to the attacker-controlled integrator account |
| **Perps Package** | `0x21d001e8b07da2e3facb3e2d636bbaef43ba3c978bd84810368840b7d57c5068` |
| **Attack Tx** | [`4pGQdfFG96Ghqj1xqkaeeAgMQCpttivdkgSRUGc6wVD8`](https://suivision.xyz/txblock/4pGQdfFG96Ghqj1xqkaeeAgMQCpttivdkgSRUGc6wVD8) |
| **Reference** | [Phalcon Alert](https://x.com/Phalcon_xyz/status/2049509576488403365) |

---

## 1. Vulnerability Overview

Aftermath Finance is a DeFi protocol on Sui offering an AMM, staking, and a **perpetuals trading** module. The perp module supports third-party integrators — frontend operators who can register with the protocol, earn a portion of taker fees from orders placed through their interface, and configure their own `max_taker_fee` rate.

On April 29, 2026, an attacker exploited an **integer underflow** in the integrator fee split calculation of Aftermath's perp module. By registering as an integrator with `max_taker_fee = 0` and then self-trading between two attacker-controlled accounts, the fee calculation produced `integrator_taker_fees ≈ u256::MAX` — effectively treating a zero-fee configuration as a massive negative fee that the protocol owed to the integrator. Each iteration yielded ~$79,610 USDC profit. The attack was repeated across multiple transactions to accumulate ~$1.14M.

**On-chain evidence (tx `4pGQdfFG...`):**

| Event | Key Values |
|-------|-----------|
| `CreatedAccount` | Accounts 1227 (maker) and 1228 (integrator/taker) — same user |
| `AddedIntegratorConfig` | `account_id: 1228, integrator_address: attacker, max_taker_fee: 0` |
| `DepositedCollateral` | `account_id: 1227, collateral: 100000000` (100 USDC) |
| `FilledTakerOrder` | `integrator_taker_fees: 115792089237316195423570985008687907853269984665640563689698454007913129639936` (≈ u256::MAX) |
| `PaidIntegratorFees` | Same ≈u256::MAX fee "paid" to integrator (attacker) |
| `DeallocatedCollateral` | `account_id: 1228, collateral: 349833465873` (~349,833 USDC) vs. 100 USDC deposited |
| Balance change | Attacker: `+79,610,446,067 USDC` net per tx |

The `integrator_taker_fees` value is exactly `u256::MAX - 349,759,130,000,000,000,000,000 + 1` — a textbook integer underflow where a subtraction result that should be negative wraps around to near-maximum in unsigned arithmetic.

---

## 2. Vulnerable Code Analysis

### Fee Calculation — Integer Underflow (Reconstructed)

```move
// Aftermath perp clearing house — fee split logic (vulnerable, reconstructed)
// Package: 0x21d001e8b07da2e3facb3e2d636bbaef43ba3c978bd84810368840b7d57c5068

// taker_fees: total fee charged to the taker position (u64 in perp units)
// integrator_rebate: fraction of taker fees given back to the integrator
// max_integrator_fee: the integrator's configured maximum fee rate (0 in this attack)

fun compute_integrator_fees(
    taker_fees: u64,
    integrator_config: &IntegratorConfig,
): u256 {
    // BUG: when max_taker_fee == 0, the "integrator portion" should be 0.
    // Instead, the calculation computes:
    //   integrator_share = taker_fees * (PRECISION - max_taker_fee) / PRECISION
    // With max_taker_fee == 0:
    //   integrator_share = taker_fees * PRECISION / PRECISION = taker_fees
    //
    // Then: integrator_taker_fees = integrator_share - protocol_base_fee
    //   If protocol_base_fee > integrator_share (due to independent fee layer),
    //   the subtraction underflows in u256 arithmetic.

    let integrator_share = (taker_fees as u256)
        * ((BASIS_POINTS - integrator_config.max_taker_fee) as u256)
        / (BASIS_POINTS as u256);

    // BUG: when integrator_config.max_taker_fee == 0:
    //   integrator_share = taker_fees (full fee)
    // Then if a protocol_fee is subtracted from integrator_share but
    // protocol_fee is computed on the original taker_fees independently:
    //   result = integrator_share - protocol_fee
    //          = small_positive - larger_positive
    //          = UNDERFLOW → u256::MAX - (protocol_fee - integrator_share)
    let protocol_fee = compute_protocol_fee(taker_fees);
    integrator_share - protocol_fee   // underflows if protocol_fee > integrator_share
}
```

### Attack Sequence Using Two Controlled Accounts

```move
// Step 1: Register as integrator with max_taker_fee = 0
// This makes the integrator_share = 0, ensuring underflow when protocol_fee is subtracted

// Step 2: Open two accounts (maker: 1227, taker/integrator: 1228)
//         Deposit minimal collateral (100 USDC) into account 1228

// Step 3: Post a limit order from account 1227 (maker)
//         Place market order from account 1228 (taker, using own interface as integrator)

// Step 4: Fee settlement
//   taker_fees charged to account 1228 = 1,573,916,085,000,000 (internal units)
//   integrator_taker_fees = underflow → ≈ 2^256 - 1  (credited to integrator)

// Step 5: PaidIntegratorFees credits ≈2^256 USDC to integrator vault
//         Protocol caps realized payout to available collateral in account 1228
//         DeallocatedCollateral: 349,833,465,873 units (~349,833 USDC) withdrawn
//         Net per tx: +79,610 USDC profit after gas and taker fees

// Step 6: Repeat ×14 → ~$1.14M total
```

### Fixed Version

```move
// Fixed: use checked_sub and validate result before crediting fees
fun compute_integrator_fees(
    taker_fees: u64,
    integrator_config: &IntegratorConfig,
): u256 {
    // Guard: max_taker_fee == 0 means integrator earns nothing
    if (integrator_config.max_taker_fee == 0) {
        return 0u256
    };

    let integrator_share = (taker_fees as u256)
        * (integrator_config.max_taker_fee as u256)
        / (BASIS_POINTS as u256);

    let protocol_fee = compute_protocol_fee(taker_fees);

    // Use checked subtraction — if protocol_fee > integrator_share, return 0
    if (protocol_fee >= integrator_share) {
        return 0u256
    };

    integrator_share - protocol_fee
}
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[1] Register as Aftermath Finance perp integrator
  │       Set max_taker_fee = 0 on IntegratorConfig for account 1228
  │
  ├─[Tx: 4pGQdfFG...]
  │   ├─ CreateAccount(1227) — maker account
  │   ├─ CreateAccount(1228) — integrator/taker account
  │   ├─ AddIntegratorConfig(1228, max_taker_fee=0)
  │   ├─ DepositCollateral(1227, 100 USDC)
  │   ├─ PostOrder(1227) — limit order at specific price
  │   ├─ FillOrder(1228 as taker, integrator=attacker)
  │   │     → FilledTakerOrder: integrator_taker_fees ≈ u256::MAX
  │   ├─ PaidIntegratorFees → credits ≈u256::MAX "fees" to integrator vault
  │   └─ DeallocatedCollateral(1228): 349,833 USDC withdrawn
  │       Net balance change: +79,610 USDC
  │
  ├─[Repeated ×14 across multiple txs]
  │
  └─[Result] ~$1.14M extracted from Aftermath Finance perp collateral pools
             Phalcon alert triggers; protocol pauses
```

---

## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Integer Underflow / Business Logic Flaw — Fee Calculation with Zero Rate |
| **CWE** | CWE-191: Integer Underflow (Wrap or Wraparound); CWE-682: Incorrect Calculation |
| **Attack Vector** | External — self-trading via two attacker-controlled accounts with integrator-registered account |
| **DApp Category** | Perpetuals / Derivatives Trading |
| **Chain** | Sui (Move) |
| **Module** | `0x21d001e8b07da2e3facb3e2d636bbaef43ba3c978bd84810368840b7d57c5068` (Aftermath Perps) |
| **Impact** | ~$1.14M USDC drained from perp collateral pools |
| **Severity** | High |
| **DASP Classification** | Bad Arithmetic / Business Logic Error |

---

## 5. Remediation Recommendations

1. **Explicit zero-fee guard**: Any fee calculation that involves multiplication and division must explicitly guard the `max_fee = 0` case and return 0 rather than proceeding through the normal formula.
2. **Checked arithmetic in fee splits**: All intermediate subtraction operations in fee distribution must use `checked_sub` (or `safe_sub` equivalent in Move) that returns 0 on underflow rather than wrapping. Unsigned integer underflow in fee logic should never be allowed to produce a payout.
3. **Fee invariant assertion**: Assert post-computation that `integrator_fee + protocol_fee <= taker_fee`. If this invariant is violated, abort the transaction.
4. **Self-trading detection**: Detect when the same address is both the maker (via one account) and the integrator for the taker (via a second account) in the same matched order. Flag or prohibit self-trading with integrator rebate collection.
5. **Integration test for zero-rate edge case**: Explicitly test fee calculation with `max_taker_fee = 0`, `max_taker_fee = BASIS_POINTS`, and values near u64::MAX. Property-based testing with fuzzing of fee parameters should catch underflow conditions before deployment.

---

## 6. Lessons Learned

- **Zero is a dangerous edge case in multiplicative fee formulas**: Fee calculations designed for rates in `[1, BASIS_POINTS]` often fail silently when `rate = 0`, either returning 0 correctly or triggering underflow in the surrounding arithmetic. Every fee formula must be explicitly tested with `rate = 0`.
- **The perps module, not the AMM**: Initial analysis attributed this exploit to a share/reserve calculation in Aftermath's AMM or staking module. On-chain transaction data confirms the vulnerability was in the **perpetuals trading module** — specifically the integrator fee split calculation. On-chain evidence overrides classification.
- **u256 arithmetic wraps silently in Move**: Move's `u256` type does not panic on overflow/underflow in all contexts. Developers must use checked arithmetic primitives for any calculation involving subtraction of values that could be larger than the minuend.
- **Self-trading as an attack vector**: Permissionless integrator registration combined with self-trading (owning both maker and taker accounts) creates a closed economic loop where fee edge cases can be exploited without counterparty risk.
- **~$79K per iteration scales to $1.14M**: The exploit needed ~14 iterations. Rate limiting or per-block collateral deallocation caps would have bounded the blast radius.

---

## References

- [Phalcon Attack Alert](https://x.com/Phalcon_xyz/status/2049509576488403365)
- [Attack Transaction on Sui Vision](https://suivision.xyz/txblock/4pGQdfFG96Ghqj1xqkaeeAgMQCpttivdkgSRUGc6wVD8)
- [Aftermath Finance Perps Package on Suiscan](https://suiscan.xyz/mainnet/object/0x21d001e8b07da2e3facb3e2d636bbaef43ba3c978bd84810368840b7d57c5068)
