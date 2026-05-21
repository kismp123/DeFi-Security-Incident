# Cetus Protocol — Arithmetic Overflow in CLMM Pool Math Drains $223M

| Field | Details |
|------|------|
| **Date** | 2025-05-22 |
| **Protocol** | Cetus Protocol (CLMM DEX) |
| **Chain** | Sui |
| **Loss** | ~$223,000,000 |
| **Attacker EOA** | (Sui address — attributed via on-chain tracing) |
| **Vulnerable Contract** | Cetus CLMM Move package (`cetus_clmm`) |
| **Root Cause** | Unchecked bit-shift (`shl`) in `checked_shlw` produces silent integer overflow in Move, causing near-zero denominators in sqrt price computation and allowing pool reserves to be drained for essentially zero input |
| **Attack Tx** | [`6hAcrsQpT83mz2hVpkf87EYdTSL8bwy5dVUNZiVBDrtt`](https://suivision.xyz/txblock/6hAcrsQpT83mz2hVpkf87EYdTSL8bwy5dVUNZiVBDrtt) |
| **Trace Source** | [BlockSec Blog](https://blocksec.com/blog/cetus-incident-one-unchecked-shift-drains-223m-largest) |

---

## 1. Vulnerability Overview

Cetus Protocol is the largest concentrated liquidity market maker (CLMM) DEX on the Sui blockchain. On May 22, 2025, an attacker exploited an arithmetic overflow bug in Cetus's Move smart contract, resulting in approximately $223M in losses — the largest single DeFi hack of 2025.

The bug resided in the `checked_shlw` function, a custom wide-shift-left helper used when computing sqrt price limits and delta amounts for liquidity positions. The function was intended to abort on overflow but used a plain `shl` (shift left) operation on u128/u256 values without a correct overflow guard. In the Move version deployed by Cetus, a shift of 64 bits on a u128 with high bits set silently wraps — it does not revert — producing a result close to zero.

When the overflow result was used as the numerator in subsequent price calculations, it created a near-zero or zero denominator in the division that followed. The protocol therefore believed the pool's effective liquidity was negligible, allowing the attacker to withdraw the entire pool reserve in exchange for a trivially small input amount.

Multiple Cetus pools (USDC, SUI, USDT, and other token pairs) were drained within minutes. The attacker subsequently bridged proceeds off Sui. Cetus's admin invoked an emergency pause function and froze approximately $163M of the stolen funds on-chain; the remaining ~$60M was bridged out before the freeze.

---

## 2. Vulnerable Code Analysis

### The Flawed Shift Function

```move
// cetus_clmm package — checked_shlw (vulnerable)
fun checked_shlw(n: u128): u256 {
    // INTENT: shift n left by 64 bits in a 256-bit context, abort on overflow
    // BUG: the cast to u256 happens first, but Move's << operator on the
    //      intermediate form does not abort when high bits are silently dropped.
    //      If n has bits set at positions >= 192, the result wraps to a small
    //      value rather than aborting.
    (n as u256) << 64  // ← no overflow assertion; wraps silently
}
```

### How the Overflow Propagates to Price Calculation

```move
// get_next_sqrt_price_from_input — uses checked_shlw for numerator
fun get_next_sqrt_price_from_input(
    sqrt_price: u128,
    liquidity: u128,
    amount: u64,
    a_to_b: bool
): u128 {
    // numerator = liquidity << 64 (should be large; overflows to ~0)
    let numerator = checked_shlw(liquidity);  // ← BUG: returns near-zero

    // denominator = numerator + amount * sqrt_price (also near-zero)
    // result: sqrt_price barely changes — pool thinks it has no liquidity
    let denominator = numerator + (amount as u256) * (sqrt_price as u256);

    // division of near-zero by near-zero produces extreme or undefined price
    // → swap_step concludes the entire reserve is available for the input amount
    ...
}
```

### Why Move Did Not Revert

In the Move version deployed on Sui at the time of the exploit, integer shift operations on `u256` values did not trap on overflow; they wrapped. A correctly written safe-math library would use an explicit `assert!(result >> 64 == (n as u256), ERROR_OVERFLOW)` post-condition check. Cetus's `checked_shlw` omitted this assertion.

### Fixed Version (Post-Patch)

```move
// checked_shlw — fixed
fun checked_shlw(n: u128): u256 {
    let result = (n as u256) << 64;
    // Verify no bits were lost: shifting back must recover the original value
    assert!(result >> 64 == (n as u256), E_OVERFLOW);
    result
}
```

Cetus additionally migrated price computation to audited safe-math libraries and added circuit-breaker limits on per-swap output amounts.

---

## 3. Attack Flow

```
Attacker
  │
  ├─[1] Identify target pools with deep liquidity (USDC/SUI, USDT/SUI, etc.)
  │
  ├─[2] Craft swap parameters that trigger checked_shlw overflow
  │       - Choose liquidity value n with high bits set
  │       - Pass to swap() with crafted amount_in
  │
  ├─[3] checked_shlw(liquidity) returns ≈0 instead of large numerator
  │       get_next_sqrt_price_from_input returns extreme sqrt price
  │       Pool believes remaining liquidity ≈ 0 after swap
  │
  ├─[4] Protocol sends entire pool reserve to attacker as swap output
  │       Input cost: ~0 tokens
  │       Output received: full pool reserve
  │
  ├─[5] Repeat across all major Cetus pools
  │       Multiple transactions within minutes
  │       Total drained: ~$223M equivalent
  │
  ├─[6] Cetus admin triggers emergency pause + asset freeze
  │       ~$163M frozen on-chain (partially recoverable)
  │       ~$60M bridged to external chains before freeze
  │
  └─[7] On-chain governance vote initiated for recovery of frozen funds
```

---

## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arithmetic Overflow / Unchecked Bit-Shift |
| **CWE** | CWE-190: Integer Overflow or Wraparound |
| **Attack Vector** | External — crafted swap parameters, no flash loan required |
| **DApp Category** | CLMM DEX (Concentrated Liquidity Market Maker) |
| **Chain** | Sui (Move language) |
| **Impact** | Complete drain of multiple liquidity pools |
| **Severity** | Critical |
| **DASP Classification** | Arithmetic Issues |

---

## 5. Remediation Recommendations

1. **Post-condition overflow assertions**: After every shift operation, verify the result is consistent with the input by shifting back and comparing. Do not rely on the language runtime to trap overflows.
2. **Audited safe-math libraries**: Use formally verified fixed-point arithmetic libraries rather than custom implementations. On Sui/Move, prefer libraries that have undergone independent security review.
3. **Per-swap output caps**: Implement circuit breakers that revert any swap where the output exceeds a configurable fraction of total pool reserves. This limits blast radius even if arithmetic bugs exist.
4. **Differential fuzz testing**: Fuzz price-math functions with extreme inputs (max u64, max u128) and compare results against a reference implementation.
5. **Emergency pause mechanisms**: Cetus's ability to freeze assets post-exploit was only partially effective. Pause logic should be triggered automatically by anomaly detectors (e.g., if a single swap output > X% of pool TVL).
6. **Independent audit of custom math**: Any custom arithmetic function used in AMM core logic must be audited separately, not just the surrounding protocol code.

---

## 6. Lessons Learned

- **Naming a function `checked_`  does not make it safe**: The `checked_shlw` function name implied overflow safety but lacked the assertion that would have enforced it. Code must be verified, not just named defensively.
- **Silent wraparound is a critical hazard in AMM math**: Concentrated liquidity AMMs perform many high-precision fixed-point calculations; a single overflow that produces zero in a denominator can drain an entire pool.
- **Emergency admin controls saved ~73% of stolen funds**: The existence of a protocol-level pause and asset freeze function allowed Cetus to recover $163M. Protocols without such controls would have lost everything.
- **Sui Move's shift semantics require explicit guards**: Developers migrating from EVM (where `SafeMath` or Solidity 0.8's built-in revert-on-overflow is standard) must explicitly implement equivalent checks in Move.
- **Pool isolation limits contagion**: If each Cetus pool had a separate emergency circuit breaker, the attacker might have been stopped after the first pool drain rather than sweeping all pools.

---

## References

- [BlockSec Incident Analysis — "One Unchecked Shift Drains $223M"](https://blocksec.com/blog/cetus-incident-one-unchecked-shift-drains-223m-largest)
- [Cetus Protocol Official Post-Mortem](https://x.com/CetusProtocol)
- [Attack Transaction on Sui Explorer](https://suivision.xyz/txblock/6hAcrsQpT83mz2hVpkf87EYdTSL8bwy5dVUNZiVBDrtt)
