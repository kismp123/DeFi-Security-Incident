# zkLend — Precision Loss / Share Inflation Attack on Starknet Money Market

| Field | Details |
|------|------|
| **Date** | 2025-02-12 |
| **Protocol** | zkLend |
| **Chain** | Starknet |
| **Loss** | ~$9,500,000 |
| **Attacker EOA** | (Starknet address — see attack tx) |
| **Vulnerable Contract** | zkLend zToken lending pool |
| **Root Cause** | Precision loss in `safe_decimal_math::div()`: an attacker uses flash loans to inflate the `lending_accumulator` to `~4.069×10^45`, then exploits integer truncation so that withdrawing 1.5× the deposited amount still burns only 1 zToken — netting free wstETH on each cycle |
| **Attack Tx** | [`0x0160a5841b3e99679691294d1f18904c557b28f7d5fe61577e75c8931f34a16f`](https://starkscan.co/tx/0x0160a5841b3e99679691294d1f18904c557b28f7d5fe61577e75c8931f34a16f) |
| **Trace Source** | [zkLend official statement](https://x.com/zklend/status/1890389052492509362) |

---

## 1. Vulnerability Overview

zkLend is a money market lending protocol on Starknet. On February 12, 2025, an attacker exploited a precision loss vulnerability in zkLend's `safe_decimal_math` library to drain approximately $9.5M in wstETH from the protocol.

zkLend's lending pools track user deposits using an **accumulator model**: each user holds a `raw_balance` (stored as a small integer), and their actual token balance is computed as `raw_balance × lending_accumulator`. The `lending_accumulator` starts at `1e27` (ray-scaled) and grows over time to account for accrued interest. A critical invariant is: *scaling down an amount by the accumulator and then scaling back up should return a value ≤ the original amount*. The `safe_decimal_math::div(amount, accumulator)` function violated this invariant under specific conditions.

The attack exploited three independently-benign design details that became lethal in combination:

1. **Empty market deposits accepted**: The attacker could seed an empty wstETH market with 1 wei, receiving 1 zToken.
2. **Flash loan repayment triggers accumulator recalculation**: The `settle_extra_reserve_balance` function recomputes `lending_accumulator = (reserve_balance + total_debt − treasury_amount) × SCALE / ztoken_supply`. With `ztoken_supply = 1` and `reserve_balance` inflated by flash loan repayments, the accumulator amplifies by the full reserve amount per cycle.
3. **Withdrawal rounding truncates toward zero**: `zTokens_to_burn = withdrawal_amount × SCALE / lending_accumulator` uses floor division. When `lending_accumulator ≈ 4.069×10^45`, depositing `4.069×10^18 wstETH` mints exactly 1 zToken, but withdrawing `6.103×10^18 wstETH` also burns only 1 zToken — yielding a net gain of `~2 wstETH` per cycle.

This is a precision loss / rounding exploitation in accumulator arithmetic — distinct from a classic ERC4626 donation attack, though both stem from integer division truncation. The key difference: the accumulator was manipulated to an astronomically large value via flash loans rather than direct token donation.

---

## 2. Vulnerable Code Analysis

**Language:** Cairo (Starknet). No Solidity exists.
**Source provenance:** ANALYZED/RECONSTRUCTED from post-mortems — the zkLend v1-core GitHub repository (`zkLend/zklend-v1-core`) is not publicly accessible. The code below is reconstructed from the BlockSec post-mortem, SlowMist analysis, FuzzingLabs writeup, and Verichains incident report. Function names and types match the real codebase as described in those analyses.

### `safe_decimal_math::div` — the vulnerable library function

```cairo
// src/libraries/safe_decimal_math.cairo — ANALYZED/RECONSTRUCTED
// ⚠️ Not verbatim source — reconstructed from post-mortem descriptions
// Language: Cairo 1.0 (Starknet)
//
// SCALE = 10^27 (ray-scaled fixed-point, same convention as Aave v2)

fn div(a: felt252, b: felt252) -> felt252 {
    // Computes: floor(a * SCALE / b)
    // BUG: when `b` (the lending_accumulator) is extremely large,
    //      this can return a value LARGER than `a` itself — violating
    //      the invariant "scaling down should not exceed the original."
    //
    // Example with manipulated accumulator:
    //   a = 6103946859077466029  (withdrawal amount in wei)
    //   b = 4069297906051644020000000000000000000000000000  (manipulated accumulator)
    //   result = floor(6103946859077466029 * 1e27 / 4.069e45)
    //          = floor(6.103e36 / 4.069e45)
    //          = floor(1.5) = 1   ← truncates to 1 zToken burned
    //
    // But depositing 4069297906051644021 wei also mints only 1 zToken:
    //   floor(4.069e18 * 1e27 / 4.069e45) = floor(1.0) = 1
    //
    // Net: spend 4.069e18, withdraw 6.103e18 — gain 2.034e18 wstETH per cycle
    (a * SCALE) / b   // ← integer floor division, no ceiling / rounding guard
}
```

### Accumulator inflation via flash loan repayment

```cairo
// src/market/internal.cairo — ANALYZED/RECONSTRUCTED
// ⚠️ Not verbatim source — reconstructed from post-mortem descriptions

// Called after a flash loan is repaid. Updates the global lending accumulator.
fn settle_extra_reserve_balance(ref self: ContractState) {
    let reserve_balance = IERC20(self.underlying).balance_of(this_contract());
    let total_debt = self.total_raw_debt.read() * self.borrow_accumulator.read() / SCALE;
    let treasury_amount = self.pending_treasury_amount.read();
    let ztoken_supply = self.z_token_supply.read();

    // BUG: When ztoken_supply == 1 (attacker is sole depositor) and
    //      reserve_balance is large (due to flash loan repayment overpayment),
    //      the new accumulator = (reserve_balance + total_debt - treasury_amount)
    //                            * SCALE / ztoken_supply
    //
    // Attacker repays 851 wei in a flash loan for a pool holding 1 wei:
    //   new_accumulator = (851 + 0 - 149) * 1e27 / 1 = 702 * 1e27
    //   (multiplies accumulator by 702× in one transaction)
    //
    // Repeated across multiple flash loans:
    //   final accumulator ≈ 4.069 × 10^45
    let new_accumulator = (reserve_balance + total_debt - treasury_amount)
        * SCALE / ztoken_supply;   // ← catastrophic when ztoken_supply = 1

    self.lending_accumulator.write(new_accumulator);
}
```

### zToken deposit and withdrawal (z_token/external.cairo)

```cairo
// src/z_token/external.cairo — ANALYZED/RECONSTRUCTED
// ⚠️ Not verbatim source — reconstructed from post-mortem descriptions

fn deposit(ref self: ContractState, amount: felt252) {
    let accumulator = IMarket(self.market.read()).get_lending_accumulator();
    // zTokens minted = amount scaled down by accumulator
    // With accumulator = 4.069e45:
    //   deposit 4.069e18 → floor(4.069e18 * 1e27 / 4.069e45) = floor(1.0) = 1 zToken
    let ztokens_to_mint = safe_decimal_math::div(amount, accumulator);
    self._mint(get_caller_address(), ztokens_to_mint);
    self.raw_total_supply.write(self.raw_total_supply.read() + ztokens_to_mint);
    // transfer underlying from caller
    IERC20(self.underlying.read()).transfer_from(get_caller_address(), this_contract(), amount);
}

fn withdraw(ref self: ContractState, amount: felt252) {
    let accumulator = IMarket(self.market.read()).get_lending_accumulator();
    // zTokens to burn = amount scaled down by accumulator
    // BUG: with accumulator = 4.069e45:
    //   withdraw 6.103e18 → floor(6.103e18 * 1e27 / 4.069e45) = floor(1.5) = 1 zToken
    //   burns same 1 zToken as the deposit — but returns 50% more underlying
    let ztokens_to_burn: felt252 = safe_decimal_math::div(amount, accumulator);
    assert(ztokens_to_burn != 0, 'ZKLEND: INVALID_BURN');  // passes: 1 ≠ 0
    self._burn(get_caller_address(), ztokens_to_burn);
    self.raw_total_supply.write(self.raw_total_supply.read() - ztokens_to_burn);
    // transfer `amount` underlying to caller — attacker receives 6.103e18 wstETH
    IERC20(self.underlying.read()).transfer(get_caller_address(), amount);
}
```

### Fuzz test that would have caught the bug (FuzzingLabs)

```cairo
// REAL SOURCE — FuzzingLabs cairo-native-fuzzer test harness
// Source: https://fuzzinglabs.com/rediscovery-zklend-hack/
#[starknet::contract]
mod FuzzMarketAccumulator {
    use super::super as crate;
    use crate::libraries::{safe_decimal_math};

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn fuzz_scaled_down_amount(
        ref self: ContractState,
        amount: felt252,
        accumulator: felt252
    ) {
        let scaled_down_amount = safe_decimal_math::div(amount, accumulator);
        // This assertion FAILS for certain (amount, accumulator) pairs:
        // scaled_down_amount > amount when accumulator is extremely large
        assert(
            Into::<_, u256>::into(scaled_down_amount) <=
            Into::<_, u256>::into(amount),
            0x15  // invariant: scaled-down amount ≤ original amount
        );
    }
}
// FuzzingLabs reports this invariant violation was found in ~1 second.
```

### Fixed Version

```cairo
// Mitigation: ceiling division for withdrawal burn calculation
// If floor(amount / accumulator) underestimates the burn, use ceiling instead.
fn div_ceil(a: felt252, b: felt252) -> felt252 {
    // ceil(a * SCALE / b) = floor((a * SCALE + b - 1) / b)
    (a * SCALE + b - 1) / b
}

// In withdraw(): use div_ceil so the attacker cannot get more than they deposited
fn withdraw(ref self: ContractState, amount: felt252) {
    let accumulator = IMarket(self.market.read()).get_lending_accumulator();
    // ✅ ceiling division: 6.103e18 → ceil(1.5) = 2 zTokens burned
    //    attacker deposited only 1 zToken, so this reverts → no profit
    let ztokens_to_burn: felt252 = safe_decimal_math::div_ceil(amount, accumulator);
    assert(ztokens_to_burn != 0, 'ZKLEND: INVALID_BURN');
    self._burn(get_caller_address(), ztokens_to_burn);
    // ...
}

// Additional mitigation: block accumulator manipulation
// Add a maximum accumulator increase per block to prevent flash-loan amplification:
fn settle_extra_reserve_balance(ref self: ContractState) {
    let new_accumulator = /* ... */;
    let current = self.lending_accumulator.read();
    // ✅ cap: accumulator cannot more than double in one transaction
    let max_accumulator = current * 2;
    assert(new_accumulator <= max_accumulator, 'ZKLEND: ACCUMULATOR_SPIKE');
    self.lending_accumulator.write(new_accumulator);
}
```

---

## 3. Attack Flow

```
Attacker (attack tx: 0x0160a584...a16f on Starknet)
  │
  ├─[1] Target the wstETH market — nearly empty (minimal deposits)
  │
  ├─[2] Deposit 1 wei wstETH into empty market
  │       → lending_accumulator = 1e27 (initial ray)
  │       → receive 1 zToken (1:1 ratio)
  │       ztoken_supply = 1
  │
  ├─[3] ACCUMULATOR INFLATION PHASE (multiple flash loans)
  │       Each flash loan cycle:
  │         a) Borrow X wstETH via flash loan
  │         b) Repay X + premium wstETH into pool
  │         c) settle_extra_reserve_balance() recomputes:
  │              new_accumulator = (reserve + debt − treasury) * 1e27 / ztoken_supply
  │              With ztoken_supply=1: new_accumulator ≈ old × (reserve+repayment)
  │         Example step: accumulator 1e27 → 702e27 (702× amplification in one tx)
  │       Repeat ~10 times across wstETH markets
  │       Final accumulator ≈ 4.069297906051644020 × 10^45
  │
  ├─[4] EXPLOIT PHASE (per cycle, ~61 times)
  │       a) Deposit 4,069,297,906,051,644,021 wei wstETH
  │            → zTokens minted = floor(amount * 1e27 / 4.069e45)
  │                              = floor(4.069e18 * 1e27 / 4.069e45) = 1 zToken
  │       b) Withdraw 6,103,946,859,077,466,029 wei wstETH (1.5× deposit)
  │            → zTokens to burn = floor(amount * 1e27 / 4.069e45)
  │                               = floor(6.103e18 * 1e27 / 4.069e45)
  │                               = floor(1.5) = 1 zToken   ← same 1 zToken burned!
  │            → Receive 6.103e18 wstETH while burning only 1 zToken
  │       c) Net gain per cycle: 6.103e18 − 4.069e18 = 2.034e18 wei wstETH (~$2)
  │
  ├─[5] Repeat step [4] ~61 times → total wstETH stolen ≈ 61 wstETH (~$9.5M)
  │
  ├─[6] Bridge funds from Starknet to Ethereum via official StarkGate bridge
  │
  └─[7] zkLend pauses protocol; issues recovery bounty offer (10% of stolen funds)
          Total loss: ~$9,500,000 in wstETH
          Accumulator manipulation pre-work: multiple flash loan transactions
```

---

## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Precision Loss / Share Inflation (First-Depositor Attack) |
| **CWE** | CWE-682: Incorrect Calculation; CWE-190: Integer Overflow or Wraparound (truncation) |
| **Attack Vector** | External — no flash loan required; direct token donation + small initial deposit |
| **DApp Category** | Lending / Money Market |
| **Chain** | Starknet (Cairo language) |
| **Impact** | Excess borrowing against artificially inflated collateral — protocol insolvency |
| **Severity** | Critical |
| **DASP Classification** | Arithmetic Issues / Business Logic Error |
| **Related CVEs / Attacks** | Compound v2 donation attack, ERC4626 inflation attack (EIP-4626 reference implementation), Silo Finance first-depositor issue |

---

## 5. Remediation Recommendations

1. **Ceiling division for withdrawal burns**: Replace `floor(amount / accumulator)` with `ceil(amount / accumulator)` when computing zTokens to burn on withdrawal. This ensures a withdrawal never burns fewer tokens than economically warranted, eliminating the rounding arbitrage.
2. **Cap accumulator growth per transaction**: Impose a maximum rate of accumulator increase (e.g., cannot more than 2× per block). Flash loan attacks rely on compounding the accumulator by orders of magnitude in a single transaction — a growth cap makes the manipulation economically infeasible.
3. **Reject first deposits into empty pools below a minimum**: If `ztoken_supply == 0`, require the first deposit to exceed a minimum threshold (e.g., `10^15` tokens). This prevents dust-seeding the pool with 1 wei.
4. **Invariant test on `safe_decimal_math::div`**: The invariant `div(amount, accumulator) ≤ amount / SCALE` should be enforced with an `assert` or verified by fuzzing. FuzzingLabs demonstrated this invariant violation is detectable in ~1 second with a fuzz harness.
5. **Formal verification of accumulator arithmetic**: Cairo's `felt252` field arithmetic wraps at a 252-bit prime modulus rather than 2^256. Formally verify that division functions cannot exceed expected bounds for all valid (amount, accumulator) pairs.
6. **Emergency accumulator reset**: Add a governance-controlled circuit breaker that can cap the accumulator if it exceeds a threshold, allowing the protocol to recover from manipulation without full shutdown.

---

## 6. Lessons Learned

- **The bug is in safe_decimal_math::div, not the deposit logic**: This is not a classic ERC4626 donation inflation attack (no direct token donation was used). The attacker manipulated the `lending_accumulator` via flash loans to a value where floor-division produces a rounding discrepancy — a subtly different vulnerability class that requires ceiling-division as the fix rather than virtual shares.
- **Flash loans are accumulator amplifiers**: Any protocol whose accumulator is recomputed from `reserve_balance / ztoken_supply` (or equivalent) after a flash loan repayment must be hardened against scenarios where `ztoken_supply` is 1. A single 1-wei deposit followed by carefully sized flash loan repayments can inflate the accumulator to astronomical values.
- **Invariant violations in arithmetic libraries deserve fuzzing**: The FuzzingLabs analysis showed the broken invariant (`div(a, b) > a` for large `b`) would have been caught in ~1 second by property-based fuzzing. All fixed-point math libraries in Cairo should have fuzz-tested invariants before deployment.
- **Cairo felt252 arithmetic is not Solidity arithmetic**: Cairo's native type (`felt252`) operates over a 252-bit prime field with different overflow and division semantics. Developers porting EVM math patterns to Cairo must re-verify the correctness of every arithmetic operation independently.
- **Same class as EraLend (zkSync, 2023)**: The SlowMist analysis linked this attack to the EraLend hack on zkSync Era in June 2023, which used the same accumulator manipulation technique. Cross-chain knowledge sharing for Cairo-based protocols lagged EVM documentation of this pattern.

---

## References

- [zkLend Official Statement (Twitter/X)](https://x.com/zklend/status/1890389052492509362)
- [Attack Transaction on Starkscan](https://starkscan.co/tx/0x0160a5841b3e99679691294d1f18904c557b28f7d5fe61577e75c8931f34a16f)
- [BlockSec Post-Mortem: zkLend Exploit — Accumulator Manipulation](https://blocksec.com/blog/zklend-exploit-post-mortem-unraveling-the-details-and-clarifying-misunderstandings-of-the-10m-flash-loan-attack)
- [SlowMist In-Depth Analysis — linked to EraLend hack](https://slowmist.medium.com/in-depth-analysis-of-zklend-hack-linked-to-eralend-hack-fba4af9b66ef)
- [FuzzingLabs: How Fuzzing Could Have Prevented The zkLend Hack](https://fuzzinglabs.com/rediscovery-zklend-hack/)
- [Verichains: zkLend Finance Incident Analysis](https://blog.verichains.io/p/zklend-finance-incident-analysis)
- [Halborn: Explained The zkLend Hack (February 2025)](https://www.halborn.com/blog/post/explained-the-zklend-hack-february-2025)
- [zkLend v1-core GitHub (core contracts)](https://github.com/zkLend/zklend-v1-core)
