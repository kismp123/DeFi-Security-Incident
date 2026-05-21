# Alchemix V2 — alETH Vault Strategy Yield Calculation Bug Analysis

| Field | Details |
|------|------|
| **Date** | 2021-06-16 |
| **Protocol** | Alchemix V2 (self-repaying loan protocol) |
| **Chain** | Ethereum |
| **Loss** | ~$6,500,000 (~2,200 ETH over-distributed to users via yield calculation bug; ~$4.8M voluntarily returned by users) |
| **Attacker** | None (protocol-discovered bug; no malicious exploitation) |
| **Vulnerable Contract** | Alchemix V2 alETH vault TransmuterB strategy contract (Ethereum mainnet) |
| **Root Cause** | Incorrect yield distribution calculation in the alETH vault's TransmuterB strategy. The contract over-credited yield to user debt repayment positions, allowing users to claim more collateral than the protocol had actually earned from the underlying Yearn ETH vault. |
| **CWE** | CWE-682: Incorrect Calculation; CWE-840: Business Logic Errors |
| **PoC Source** | Alchemix official post-mortem and forum disclosure (June 2021) |

---
## 1. Vulnerability Overview

Alchemix V2 is a self-repaying loan protocol: users deposit ETH as collateral and receive alETH (a synthetic debt token) representing up to 50% of their deposit value. The deposited ETH is deployed into yield-generating strategies (primarily Yearn Finance ETH vaults), and as yield accrues, the protocol automatically reduces users' alETH debt. When a user's debt is fully repaid by yield, they can call `claim()` to withdraw their original ETH collateral.

On June 16, 2021, the Alchemix team discovered a bug in the `TransmuterB` contract — the component responsible for tracking yield from the Yearn ETH strategy and distributing that yield to reduce user debt positions. The bug caused the contract to over-credit yield to users' debt positions. As a result, users' alETH debt appeared to be repaid faster than actual underlying yields justified. When users called `claim()` to retrieve collateral, they received more ETH than the protocol had genuinely earned, effectively draining the protocol's yield buffer and a portion of other users' collateral.

**This was not an external attack.** No malicious actor discovered or exploited this vulnerability. The Alchemix team identified the anomaly through abnormal yield reporting metrics, immediately paused the alETH vault, and conducted a public post-mortem. The team then issued a community appeal — "Do the right thing" — asking users who had received excess ETH to voluntarily return it. Approximately $4.8M of the ~$6.5M over-distributed was recovered through voluntary repayment, making this incident notable as a rare example of community-driven fund recovery after a protocol-side logic error.

---
## 2. Vulnerable Code Analysis

### 2.1 Invariant That Was Violated

The fundamental correctness invariant of the TransmuterB yield distribution system is:

```
Total yield credited to user debt positions
    == Total yield actually harvested from the underlying Yearn ETH strategy
```

Any violation of this invariant — where credited yield exceeds harvested yield — means users can claim collateral that has not yet been earned, drawing down the protocol's real ETH reserve.

### 2.2 The Yield Calculation Logic Error

The `TransmuterB` contract tracked two quantities that must remain in lockstep:

1. **`totalSupplied`** — the total amount of alETH debt deposited into the Transmuter for repayment.
2. **`buffer`** — the pool of harvested ETH yield available to credit against outstanding alETH debt.

When the strategy harvested yield from Yearn, the contract called an internal distribution function to allocate newly harvested ETH proportionally across all depositors in the Transmuter. The bug resided in this allocation step: the contract incorrectly calculated the per-depositor share of harvested yield, producing a credited amount that exceeded the actual harvest.

Conceptually, the flawed logic resembled:

```solidity
// ❌ Vulnerable (illustrative pseudocode — exact source unavailable)
function distributeYield(uint256 harvested) internal {
    // BUG: totalWeight is stale or incorrectly computed,
    // causing the per-unit allocation to be inflated.
    uint256 perUnit = harvested * PRECISION / totalWeight;

    for (uint256 i = 0; i < depositors.length; i++) {
        // Each depositor's credited yield is larger than their fair share.
        // Summed across all depositors, total credits > harvested.
        uint256 credit = depositorWeight[i] * perUnit / PRECISION;
        userDebtCredit[depositors[i]] += credit;
    }

    // buffer is decremented by `harvested`, but userDebtCredit totals
    // across all users may exceed `harvested` due to precision or
    // weight accounting error — the invariant is broken.
    buffer -= harvested;
}
```

The key failure modes consistent with the post-mortem are:

- **Stale or incorrectly accumulated weight denominators**: if `totalWeight` was not updated atomically with individual weight changes (e.g., when users deposited or withdrew alETH from the Transmuter mid-cycle), the per-unit allocation could be computed against a denominator that was smaller than the true outstanding share sum, inflating each user's credit.
- **Double-counting on harvest**: if the distribution function was invoked more than once for the same harvest event (e.g., triggered by both a strategy call and a subsequent user interaction that also triggered distribution), credits would be applied twice against a buffer decremented only once.

Either mechanism results in the same observable outcome: `sum(userDebtCredit) > buffer`, which means users can collectively claim more ETH than the protocol holds in yield.

### 2.3 Downstream Impact on `claim()`

```solidity
// ❌ Vulnerable claim path (illustrative pseudocode)
function claim() external {
    uint256 claimable = userDebtCredit[msg.sender];
    require(claimable > 0, "Nothing to claim");

    // Over-credited userDebtCredit allows withdrawal
    // exceeding what the protocol actually earned.
    userDebtCredit[msg.sender] = 0;
    (bool ok,) = msg.sender.call{value: claimable}("");
    require(ok, "Transfer failed");
}
```

Because `userDebtCredit` was inflated, `claim()` transferred ETH that the protocol had not earned from yield — effectively distributing principal collateral belonging to other depositors or the protocol reserve.

### 2.4 Why Standard Testing Missed This

The yield distribution logic is correct for the simple case (fixed depositor set, single harvest per cycle). The bug manifests only under dynamic conditions — users entering or exiting the Transmuter mid-cycle, or the distribution being triggered at unexpected intervals. Standard unit tests operating on static state would not exercise these paths. **Invariant-based testing** (asserting `sum(userDebtCredit) <= buffer` after every state transition) would have caught this immediately.

---
## 3. Bug Discovery and Impact

> Note: There was no attacker. The following diagram traces how the bug was discovered by the Alchemix team and the subsequent community response.

```
┌─────────────────────────────────────────────────────────────┐
│ Normal Operation                                            │
│ Users deposit ETH → Yearn earns yield → TransmuterB        │
│ credits yield to user debt → users call claim()            │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Bug Active (TransmuterB yield distribution error)           │
│ Over-credited yield causes userDebtCredit to exceed         │
│ actual harvested ETH in the buffer                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Users call claim() in good faith                            │
│ ~2,200 ETH over-distributed across multiple claimants       │
│ Each user receives more than their yield entitled them to   │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ June 16, 2021: Alchemix team detects anomalous yield data   │
│ Internal accounting: buffer deficit identified              │
│ → alETH vault PAUSED immediately                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Public post-mortem published                                │
│ Team identifies ~2,200 ETH (~$6.5M) over-distributed       │
│ Community appeal issued: "Do the right thing"               │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Community voluntary repayment campaign                      │
│ Many users return excess ETH in good faith                  │
│ ~$4.8M (~74%) recovered voluntarily                         │
│ Remaining ~$1.7M unrecovered (users did not return)         │
└─────────────────────────────────────────────────────────────┘
```

---
## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|---------------|----------|-----|
| V-01 | TransmuterB yield distribution credits more ETH to user debt positions than actually harvested from Yearn strategy | CRITICAL | CWE-682: Incorrect Calculation |
| V-02 | Lack of invariant enforcement: no on-chain check that `sum(userDebtCredit) <= buffer` after each distribution cycle | HIGH | CWE-840: Business Logic Errors |
| V-03 | Dynamic depositor set (mid-cycle deposits/withdrawals) not handled correctly in weight-based yield allocation | HIGH | CWE-682: Incorrect Calculation |
| V-04 | Absence of invariant-based tests; static unit tests did not cover dynamic deposit/withdrawal mid-harvest scenarios | MEDIUM | CWE-1068: Inconsistency Between Implementation and Documented Design |

---
## 5. Remediation Recommendations

1. **Enforce the core accounting invariant on-chain**: after every `distributeYield()` call, assert that `sum(all pending userDebtCredit) <= buffer`. If the assertion fails, revert the transaction rather than silently crediting inflated amounts.

2. **Atomic weight updates**: whenever a user deposits or withdraws alETH from the Transmuter, update both the individual `depositorWeight` and `totalWeight` in the same transaction before any yield distribution that references those values.

3. **Snapshot-based distribution**: calculate and commit yield distribution at the start of each harvest cycle against a snapshotted `totalWeight`, ignoring mid-cycle weight changes. Apply mid-cycle deposit/withdrawal weight changes only to the next cycle.

4. **Introduce invariant-based tests**: use property-based or fuzzing frameworks (e.g., Foundry's `invariant` test harness) to assert after every action sequence that total credited yield never exceeds total harvested yield. This class of bug is invisible to unit tests but trivially caught by invariant tests.

5. **Circuit breaker on harvest anomalies**: if a harvest reports yield that implies a distribution-per-unit above a configurable ceiling (e.g., more than 10% APY in a single block), revert and emit an alert rather than proceeding with the distribution.

6. **Formal accounting review before strategy upgrades**: all changes to yield accounting logic in Transmuter-style contracts should require a dedicated audit focused specifically on the invariant `credits_out <= yield_in` under all state transition orderings.

---
## 6. Lessons Learned

- **Protocol-discovered bugs exist and matter.** The security community's attention is heavily weighted toward adversarial exploits, but the Alchemix V2 incident demonstrates that logic errors causing material financial harm can be discovered and disclosed by the protocol team itself — with no attacker involved. These cases deserve the same rigorous post-mortem treatment as external attacks.

- **Yield accounting is a high-risk surface area.** Any contract that tracks yield accumulation and distributes it across a dynamic set of participants (where weights change over time) is susceptible to over- or under-crediting bugs. The complexity grows with the number of state transitions that can interleave with distribution cycles.

- **Invariant testing is the appropriate tool for accounting correctness.** Standard unit tests verify correctness for specific inputs; invariant tests verify that fundamental properties hold across all reachable states. The invariant `sum(userDebtCredit) <= buffer` is simple to express and would have caught this bug during development or audit.

- **"Do the right thing" — community trust as a recovery mechanism.** Alchemix's voluntary repayment campaign recovered approximately 74% of the over-distributed funds. This outcome was only possible because the protocol had built substantial community trust and acted transparently. It sets a meaningful (if not legally binding) precedent that DeFi communities can coordinate ethical recovery responses when bugs — rather than attackers — cause losses.

- **The contrast with malicious exploits is significant.** In a typical DeFi exploit, the attacker has already bridged funds across chains, swapped through mixers, and disappeared within minutes. Here, the recipients were ordinary users who had interacted with the protocol in good faith. The team's decision to appeal to community ethics rather than pursue legal remedies reflects both the nature of the incident and the culture of the protocol.

- **Pausing is not optional when accounting invariants are violated.** The Alchemix team's immediate pause of the alETH vault upon detecting the anomaly was the correct response and prevented further over-distribution. Protocols should build pause mechanisms with low activation friction specifically for accounting anomalies, not only for reentrancy or access control failures.
