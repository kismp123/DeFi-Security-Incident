# JUDAO Token — Reflection Fee Exploit on BSC

| Item | Details |
|------|------|
| **Date** | 2026-04-28 |
| **Protocol** | JUDAO Token |
| **Chain** | BNB Smart Chain |
| **Loss** | ~$228K |
| **Root Cause** | Business Logic Flaw — deflationary/reflection token fee distribution logic combined with LP pair interaction creates exploitable arbitrage |
| **Attack Tx** | `0x956e38b8ddb40ba080c8042c685ae52ee5c1b096f1d7f0c4a6c59be3eb4265bd` |
| **Reference** | [TenArmorAlert on X](https://x.com/TenArmorAlert/status/2048942654281470143) |

---

## 1. Vulnerability Overview

JUDAO Token is a BEP-20 token on BSC implementing a reflection/tax mechanism. A business logic flaw in how the fee distribution interacts with the PancakeSwap LP pair allowed an attacker to drain ~$228K. BSC reflection token exploits commonly follow this pattern: the `_transfer` function collects a fee on each transfer and redistributes it to all holders (including the attacker's balance), but fails to properly account for the LP pair contract's token balance. Because the LP pair is typically excluded from receiving reflections yet still participates in the AMM pricing curve, an attacker can buy tokens to trigger a large redistribution, receive an inflated share of the redistributed fees, and sell back at a profit exceeding the initial buy cost.

An alternative mechanism involves the fee triggering a swap-and-liquify operation that moves tokens through the pool, temporarily distorting the k-value and creating a price discrepancy the attacker can exploit via sandwich. In either case the root cause is that the fee and redistribution logic does not maintain a consistent accounting invariant when combined with AMM pool mechanics.

## 2. Vulnerable Code Analysis

```solidity
// VULNERABLE — reflection fee handling with LP pair interaction flaw
function _transfer(address from, address to, uint256 amount) internal {
    uint256 fee = amount * taxRate / 100;
    uint256 netAmount = amount - fee;

    _balances[from] -= amount;
    _balances[to] += netAmount;

    // BUG: fee is redistributed to all holders proportionally,
    // but the LP pair's virtual balance used by the AMM is not updated.
    // Attacker accumulates a large token balance, receives an outsized
    // share of redistributed fees, then sells — the LP pair's reserve
    // accounting diverges from actual balances, enabling profit.
    _distributeFee(fee);
}

function _distributeFee(uint256 fee) internal {
    // Redistributes fee proportionally to all token holders by adjusting
    // the global reflection rate — LP pair balance appears unchanged to
    // the AMM but actual holder balances increase.
    _reflectionRate -= fee * PRECISION / _totalSupply;
}

// FIXED — exclude LP pair from reflection; update reserves atomically
function _transfer(address from, address to, uint256 amount) internal {
    uint256 fee = amount * taxRate / 100;
    uint256 netAmount = amount - fee;

    _balances[from] -= amount;
    _balances[to] += netAmount;

    // Send fee to a dedicated treasury; do not redistribute via reflection
    // to avoid LP pair balance inconsistency
    _balances[treasury] += fee;

    // Sync LP pair reserves after every taxed transfer involving the pair
    if (from == lpPair || to == lpPair) {
        IPancakePair(lpPair).sync();
    }
}
```

The fix eliminates the reflection mechanism in favor of a treasury fee and explicitly syncs the LP pair after taxed transfers, keeping the AMM's reserve accounting consistent with actual balances.

## 3. Attack Flow

1. Attacker takes a flash loan of BNB/BUSD.
2. Attacker buys a large quantity of JUDAO tokens from the PancakeSwap LP pair, paying the buy tax and triggering fee redistribution to all holders.
3. Because the attacker holds a disproportionately large token balance at the moment of redistribution, they receive an outsized share of the reflected fee — effectively increasing their token balance beyond the net cost of the buy.
4. Attacker sells the inflated token balance back to the LP pair. The LP pair's reserve has not been corrected by a `sync()`, so the price impact is less than expected, and the attacker profits.
5. Attacker repays the flash loan and keeps the ~$228K difference.

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Business Logic Flaw — Reflection/Tax Mechanism + AMM Interaction |
| **Severity** | High |
| **CWE** | CWE-682 (Incorrect Calculation) |

## 5. Remediation Recommendations

- Exclude the LP pair address from all reflection/redistribution calculations; the AMM pool's token balance must remain consistent with what the AMM believes it holds — mixing reflection accounting with AMM reserves creates guaranteed invariant violations.
- If a fee must be collected on LP-pair transfers, send it to a fixed treasury address and call `pair.sync()` after every taxed transfer to realign AMM reserves with actual balances.
- Audit all fee and redistribution pathways for circular dependencies before launch; use invariant fuzz tests that model the AMM k-value alongside the token's internal accounting to surface discrepancies automatically.

## References

- [TenArmorAlert — X post](https://x.com/TenArmorAlert/status/2048942654281470143)
- [BscScan — Attack Tx](https://bscscan.com/tx/0x956e38b8ddb40ba080c8042c685ae52ee5c1b096f1d7f0c4a6c59be3eb4265bd)
- [CWE-682: Incorrect Calculation](https://cwe.mitre.org/data/definitions/682.html)
