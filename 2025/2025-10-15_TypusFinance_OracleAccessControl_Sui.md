# Typus Finance — Unauthorized TLP Oracle Update Drains ~$3.44M

| Field | Details |
|------|------|
| **Date** | 2025-10-15 |
| **Protocol** | Typus Finance (Options / Structured Products, TLP Vault) |
| **Chain** | Sui |
| **Loss** | ~$3,440,000 |
| **Root Cause** | Access Control Issue — `update_tlp_price` lacked a capability parameter, allowing any address to overwrite the TLP oracle NAV |
| **Attack Tx 1** | [`8stTi5mYWFtwoKNW1YiHRnhkXe48qPjgZHTHgXUzm9ZV`](https://suivision.xyz/txblock/8stTi5mYWFtwoKNW1YiHRnhkXe48qPjgZHTHgXUzm9ZV) |
| **Attack Tx 2** | [`6KJvWtmrZDi5MxUPkJfDNZTLf2DFGKhQA2WuVAdSRUgH`](https://suivision.xyz/txblock/6KJvWtmrZDi5MxUPkJfDNZTLf2DFGKhQA2WuVAdSRUgH) |
| **Reference** | [Typus Finance Post-Mortem](https://medium.com/@TypusFinance/typus-finance-tlp-oracle-exploit-post-mortem-report-response-plan-ce2d0800808b) |

---

## 1. Vulnerability Overview

Typus Finance is a DeFi options and structured-products protocol on the Sui blockchain. Its TLP (Typus Liquidity Provider) vault allows users to deposit assets, receive TLP tokens representing their proportional share, and earn yield from options premiums. The TLP oracle is the authoritative source for the NAV (Net Asset Value) of TLP tokens; it is consumed by the options pricing engine and the redemption module to determine how many underlying assets a given TLP balance is worth.

On October 15, 2025, an attacker discovered that the Move function responsible for updating the TLP oracle price contained no access control guard. Specifically, the function accepted a mutable reference to the `TLPOracle` shared object but required no capability token or admin signature — any account on the Sui network could call it directly. The attacker invoked this function with a manipulated price, causing the oracle to report an artificially skewed NAV. With the oracle poisoned, the attacker redeemed TLP tokens or exercised options positions at a rate that did not reflect true pool assets, extracting approximately $3.44M before the discrepancy was detected and the protocol was paused.

The two-transaction structure is consistent with (1) an initial oracle manipulation call followed by (2) a profit-extraction call that consumed the false price.

---

## 2. Vulnerable Code Analysis

### Missing Capability Gate (Vulnerable)

```move
// Typus Finance — TLPOracle update, vulnerable version
// Any address can call this; no capability object required
public fun update_tlp_price(
    oracle: &mut TLPOracle,
    new_price: u64,
    clock: &Clock,
) {
    // BUG: no AdminCap, PriceFeedCap, or sender assertion
    oracle.price       = new_price;
    oracle.last_updated = sui::clock::timestamp_ms(clock);
}
```

In Sui Move, shared objects passed as `&mut` are accessible to any transaction that correctly names the object ID. The intended protection is the requirement to also pass a capability object (`&AdminCap`, `&PriceFeedCap`, etc.) that only authorized accounts hold. When the capability parameter is absent, the function is effectively public to the entire network.

### Fixed Version (Capability-Gated)

```move
// Typus Finance — TLPOracle update, fixed version
public fun update_tlp_price(
    _feed_cap: &PriceFeedCap,      // ← only authorized price feeders hold this
    oracle: &mut TLPOracle,
    new_price: u64,
    clock: &Clock,
) {
    assert!(new_price > 0, E_INVALID_PRICE);
    assert!(
        sui::clock::timestamp_ms(clock) > oracle.last_updated,
        E_STALE_UPDATE
    );
    oracle.price       = new_price;
    oracle.last_updated = sui::clock::timestamp_ms(clock);
}
```

The `PriceFeedCap` capability object is created once during protocol initialization and transferred only to the designated price-feed operator. Without possessing that object, a transaction cannot satisfy the function's type requirements and will be rejected by the Move VM at the module boundary.

### Downstream Consumption of Manipulated Price

```move
// Options pricing module — consumes TLPOracle NAV
public fun calculate_premium(
    oracle: &TLPOracle,
    strike: u64,
    expiry: u64,
): u64 {
    // oracle.price injected by attacker; all downstream math is corrupted
    let nav = oracle.price;
    // ... Black-Scholes / parametric premium calculation using nav ...
}

// Redemption module — converts TLP tokens to underlying
public fun redeem_tlp(
    pool: &mut TLPPool,
    oracle: &TLPOracle,
    tlp_amount: u64,
    ctx: &mut TxContext,
) {
    let nav = oracle.price;          // poisoned value
    let out = (tlp_amount as u128) * (nav as u128) / PRECISION;
    // out is inflated; attacker receives more underlying than they deposited
    transfer::public_transfer(coin::split(pool.reserve, out as u64, ctx), sender(ctx));
}
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[Tx 1] Call update_tlp_price(oracle, manipulated_price, clock)
  │         - No capability required; call succeeds
  │         - TLPOracle.price overwritten with attacker-controlled value
  │         - Oracle now reports inflated or deflated NAV
  │
  ├─[Tx 2] Call redeem_tlp(pool, oracle, tlp_amount)
  │         - redeem_tlp reads oracle.price (poisoned)
  │         - Calculates out_amount = tlp_amount * manipulated_nav / PRECISION
  │         - out_amount >> actual pool share entitlement
  │         - Protocol transfers excess underlying assets to attacker
  │
  ├─[Detection] Oracle price discrepancy flagged by monitoring
  │              Typus admin triggers emergency pause
  │
  └─[Result] ~$3.44M extracted; protocol paused; post-mortem published
```

---

## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Access Control — Missing Capability Check |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External — direct call to permissionless oracle function |
| **DApp Category** | Options Protocol / Structured Products / Liquidity Vault |
| **Chain** | Sui (Move language) |
| **Impact** | Oracle price manipulation enabling over-redemption of vault assets |
| **Severity** | Critical |
| **DASP Classification** | Access Control |

---

## 5. Remediation Recommendations

1. **Capability-based access control on all state-mutating oracle functions**: Every function that writes to a shared oracle object must require a capability token (`&AdminCap`, `&PriceFeedCap`) as a parameter. The Move type system enforces this at the module boundary — no runtime assertion required.
2. **Separate read and write interfaces**: Publish oracle write functions in a restricted module visible only to the price-feed operator; publish read functions in a public module consumed by pricing and redemption logic.
3. **Price bounds and staleness checks**: Even with capability gating, enforce sanity bounds: `assert!(new_price >= MIN_PRICE && new_price <= MAX_PRICE)` and `assert!(new_price is within X% of previous price)`. These limit damage if a price-feed key is compromised.
4. **TWAP or multi-feeder consensus**: Aggregate prices from multiple authorized feeders and require M-of-N agreement before accepting an update. A single compromised key cannot unilaterally move the oracle.
5. **Circuit breakers on redemptions**: Add a per-epoch cap on total redemption volume. Anomalously large redemptions relative to TVL should trigger an automatic pause.
6. **Automated invariant monitoring**: Deploy off-chain monitoring that compares the on-chain TLP NAV against reference prices (e.g., derived from underlying asset prices). Alert and pause if divergence exceeds a threshold.

---

## 6. Lessons Learned

- **Sui's capability model is the correct pattern for access control in Move**: Unlike EVM's `msg.sender` checks, Sui Move enforces authority through object ownership. Omitting the capability parameter is not a subtle mistake — it removes the entire access control mechanism.
- **Shared objects are not inherently protected**: On Sui, any shared object can be read or mutated by any transaction that names its ID, unless the function signature requires a co-located capability. Developers must not assume that a complex object ID provides obscurity-based protection.
- **Oracle manipulation is a high-leverage attack**: A single unauthorized price write that costs near zero in gas can drain an entire liquidity vault. The asymmetry between attack cost and potential gain makes oracle access control a critical security boundary.
- **Two-transaction exploits indicate deliberate setup**: The use of two transactions — one to poison the oracle, one to profit — shows the attacker understood the protocol's architecture. This pattern suggests the vulnerability was discovered through careful code review, not fuzzing.
- **Emergency pause mechanisms must be pre-planned**: Typus was able to halt further losses by pausing. Protocols should test pause paths in advance and ensure pause authority cannot itself be bypassed.

---

## References

- [Typus Finance Post-Mortem Report](https://medium.com/@TypusFinance/typus-finance-tlp-oracle-exploit-post-mortem-report-response-plan-ce2d0800808b)
- [Attack Tx 1 on Sui Vision](https://suivision.xyz/txblock/8stTi5mYWFtwoKNW1YiHRnhkXe48qPjgZHTHgXUzm9ZV)
- [Attack Tx 2 on Sui Vision](https://suivision.xyz/txblock/6KJvWtmrZDi5MxUPkJfDNZTLf2DFGKhQA2WuVAdSRUgH)
- [Sui Move Capability Pattern — Official Docs](https://docs.sui.io/concepts/object-ownership/shared)
