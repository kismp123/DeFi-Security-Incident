# KyberSwap — Concentrated Liquidity Tick Math Bug Analysis

| Item | Details |
|------|------|
| **Date** | 2023-11-22 |
| **Protocol** | KyberSwap Elastic |
| **Chain** | Optimism, Arbitrum, Ethereum, Polygon, Base, Avalanche, and others |
| **Loss** | $46,000,000 (total damage ~$54.7M, net loss ~$46M after recovery) |
| **Attacker** | Unknown (4 addresses identified, blacklisted) |
| **Root Cause** | Double liquidity counting bug at tick boundaries caused by incorrect rounding direction in the `estimateIncrementalLiquidity` function |
| **Representative Transaction** | `0x485e08dc2b6a4b3aeadcb89c3d18a37666dc7d9424961a2091d6b3696792f0f3` (Optimism) |

---

## 1. Vulnerability Overview

KyberSwap Elastic is a Concentrated Liquidity AMM similar to Uniswap v3. Liquidity providers place liquidity only within specific price ranges (tick intervals), and the pool determines the active liquidity (`baseL`) based on which tick interval the current price falls in.

KyberSwap Elastic additionally introduces a **Reinvestment Curve**. This feature manages accumulated trading fees as separate liquidity (reinvestment liquidity, `deltaL`) to automatically provide compounding returns.

A **rounding direction error** existed inside the `estimateIncrementalLiquidity` function during this reinvestment liquidity calculation. The intent of the code was to use ceiling rounding for `deltaL` to floor `nextSqrtP`, preventing it from exceeding the tick boundary. However, the `mulDivFloor` function was actually used, causing `deltaL` to be floored — which in turn caused `nextSqrtP` to actually exceed the next tick's sqrtPrice, yet the system incorrectly determined that no tick crossing had occurred.

The attacker exploited this subtle precision error by manipulating the pool state and inducing the `updateLiquidityAndCrossTick` function to not be called during the first step of a swap, but to be called twice during the reverse swap — causing the pool to count non-existent liquidity twice and withdraw excess tokens from the pool.

---

## 2. Vulnerable Code Analysis

### 2.1 Core Function Structure

```
SwapMath.computeSwapStep()
  ├── calcReachAmount()         // Calculates token amount needed to reach tick boundary (includes baseL + deltaL)
  ├── estimateIncrementalLiquidity()  // Calculates additional liquidity (deltaL) from accumulated fees ← vulnerability
  └── calcFinalPrice()          // Calculates the final nextSqrtP
```

```
Pool._updateLiquidityAndCrossTick()
  └── Called on tick boundary crossing — performs baseL update
```

### 2.2 Vulnerable Code (Pseudocode)

```solidity
// SwapMath.sol — estimateIncrementalLiquidity()
// ❌ Vulnerable: floors deltaL, causing nextSqrtP to exceed the tick boundary

function estimateIncrementalLiquidity(
    uint256 absDelta,
    uint256 liquidity,
    uint160 currentSqrtP,
    uint256 feeInFeeUnits,
    bool isExactInput,
    bool isToken0
) internal pure returns (uint256 deltaL) {
    // ...
    // Intent: use mulDivCeil → ceil deltaL → floor nextSqrtP (prevent boundary overshoot)
    // Actual: use mulDivFloor → floor deltaL → ceil nextSqrtP → boundary overshoot allowed
    deltaL = FullMath.mulDivFloor(liquidity, feeInFeeUnits, ...); // ❌ incorrect rounding
}
```

```solidity
// Pool.sol — tick crossing condition check inside swap()
// ❌ Vulnerable: tick crossing determined solely by sqrtP comparison — condition fails due to rounding error

if (swapData.sqrtP != swapData.nextSqrtP) {
    // If this condition is false, _updateLiquidityAndCrossTick() is not called
    // → liquidity state is not updated, causing double-counting on the next swap
}
```

### 2.3 Error Magnitude Example

Swap amount used by attacker: `387,170,294,533,119,999,999`
Actual amount to reach tick boundary: `387,170,294,533,120,000,000`
**Difference: just 1 wei (less than ~0.000000000001%)**

This 1 wei difference caused `_updateLiquidityAndCrossTick` to not execute, ultimately leading to tens of millions of dollars worth of double-counted liquidity.

### 2.4 Normal vs. Vulnerable Behavior Comparison

| Item | Normal Behavior | Vulnerable Behavior |
|------|-----------|-----------|
| `deltaL` calculation | `mulDivCeil` → ceiling | `mulDivFloor` → floor ❌ |
| `nextSqrtP` calculation | Stays at or below tick boundary | Slightly exceeds tick boundary ❌ |
| Tick crossing detection | Correctly detected | Not detected (condition false) ❌ |
| `_updateLiquidityAndCrossTick` | Called normally | Not called → state mismatch ❌ |
| Liquidity on reverse swap | Normal, counted once | Double-counted (baseL × 2) ❌ |

---

## 3. Attack Flow (with ASCII Diagram)

### 3.1 Step-by-Step Attack Flow

```
Attacker
  │
  ├─[1] Flash Loan ─────────────────────────────────────────────────────┐
  │       Borrow 2,000 WETH from AAVE                                   │
  │                                                                     │
  ├─[2] Initial Swap (Positioning)                                      │
  │       Swap 6.8496 WETH → frxETH                                     │
  │       Purpose: Move currentSqrtP into a zero-liquidity interval     │
  │       (tick range: region with no existing liquidity providers)     │
  │                                                                     │
  ├─[3] Add/Remove Liquidity (State Manipulation)                       │
  │       Add liquidity at tick range [110909, 111310]                  │
  │       Then remove some liquidity                                    │
  │       Purpose: Precisely control pool state (nextTick == currentTick condition) │
  │                                                                     │
  ├─[4] Key Manipulation Swap (1 wei undershot)                         │
  │       Swap 387.17 WETH → 0.005789 frxETH                           │
  │       Set swap amount to exactly (tick boundary amount - 1 wei)    │
  │                                                                     │
  │       ┌─────────────────────────────────────────────────────────┐  │
  │       │  Inside computeSwapStep():                               │  │
  │       │  • calcReachAmount → compute amount to boundary (ceil)   │  │
  │       │  • swap amount < boundary amount → "no tick cross" ruling │  │
  │       │  • estimateIncrementalLiquidity → floor deltaL ❌         │  │
  │       │  • calcFinalPrice → nextSqrtP slightly exceeds tick boundary │
  │       │  • Condition: sqrtP != nextSqrtP → FALSE (actually exceeded) │
  │       │  • _updateLiquidityAndCrossTick not called ← state mismatch │
  │       └─────────────────────────────────────────────────────────┘  │
  │                                                                     │
  │       Result: currentSqrtP > sqrtP of tick 111310                  │
  │               but pool state records no tick crossing               │
  │               (baseL still includes liquidity from tick 111310 interval) │
  │                                                                     │
  ├─[5] Reverse Swap (Double-Count Trigger)                             │
  │       Swap 0.005868 frxETH → ~396.2 WETH reverse swap              │
  │                                                                     │
  │       ┌─────────────────────────────────────────────────────────┐  │
  │       │  Reverse computeSwapStep() called twice:                 │  │
  │       │                                                          │  │
  │       │  1st call: Move from currentSqrtP toward tick 111310    │  │
  │       │    → _updateLiquidityAndCrossTick called (normal)        │  │
  │       │    → Add tick 111310 interval liquidity to baseL         │  │
  │       │                                                          │  │
  │       │  2nd call: Cross tick 111310 again                       │  │
  │       │    → _updateLiquidityAndCrossTick called again ← double count! │
  │       │    → Same liquidity added to baseL again (2× state)     │  │
  │       └─────────────────────────────────────────────────────────┘  │
  │                                                                     │
  │       Result: baseL is 2× actual → output tokens calculated at 2×  │
  │               Receive 396.2 WETH (~9 WETH more than actual value)  │
  │                                                                     │
  ├─[6] Repay Flash Loan + Realize Profit                               │
  │       Repay 2,000 WETH                                              │
  │       Net profit: 6.364 WETH + 1.117 frxETH (per single pool)      │
  │       → Repeated across multiple pools for total ~$48.7M drained   │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Price State Diagram at Tick Boundary

```
            sqrtP of tick 111310 (boundary)
                    │
Low price  ←────────┼──────────  High price
                    │
   [State after Step 4]  │
   currentSqrtP──────────┼──► Slightly exceeds boundary
   (actually to the right) │  but pool records it as "left"
                    │
   Liquidity zone A  ───┤─── Liquidity zone B
   (still active)    ←──┘    (should be active but not reflected)

   ↓ On reverse swap

   _updateLiquidityAndCrossTick called × 2
   → Zone A liquidity added to baseL twice
   → Swap output calculated at 2× → excess withdrawal
```

---

## 4. Vulnerability Classification (Table + Details)

### 4.1 Vulnerability Classification Table

| Classification Item | Details |
|-----------|-----------|
| **Vulnerability Type** | Precision Loss / Rounding Error |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Pattern** | Flash loan + AMM state manipulation + arithmetic boundary condition exploit |
| **Impact Scope** | Confidentiality (N), Integrity (Y), Availability (Y) |
| **Estimated CVSS** | 9.1 (Critical) |
| **Prerequisites** | Sufficient capital (flash loan capable) + identification of vulnerable pool |
| **Complexity** | Very high (requires precision calculations at 1 wei granularity) |
| **DeFiHackLabs PoC** | Not provided (independent analysis) |

### 4.2 Detailed Classification

#### (A) Precision Loss / Rounding Error
- **Location:** `SwapMath.estimateIncrementalLiquidity()` line 189
- **Issue:** `mulDivFloor` used → floors `deltaL` → ceils `nextSqrtP`
- **Mismatch with intent:** Code comment specifies ceiling calculation, but implementation does the opposite
- **Cumulative effect:** Just 1 wei of error leads to condition evaluation failure

#### (B) Tick Crossing Detection Failure
- **Location:** `swapData.sqrtP != swapData.nextSqrtP` condition inside `Pool.swap()`
- **Issue:** Due to rounding error, condition returns false even when the actual tick boundary has been exceeded
- **Result:** `_updateLiquidityAndCrossTick` not executed → state mismatch

#### (C) AMM Internal State Mismatch
- **Location:** `Pool._updateLiquidityAndCrossTick()`
- **Issue:** After swap [4], mismatch between `currentSqrtP` and the recorded tick state
- **Result:** Same liquidity double-counted during reverse swap

#### (D) Insufficient Separation Between Reinvestment Curve and Base Liquidity Calculation
- **Location:** `calcReachAmount()` — includes both `baseL` and reinvestment `deltaL`
- **Issue:** Fee-based reinvestment liquidity included in tick boundary calculation amplifies the error
- **Lesson:** In composite liquidity structures, the rounding direction of each component must be verified independently

---

## 5. Remediation Recommendations

### 5.1 Immediate Fix (Patch)

```solidity
// ✅ Fix: Change mulDivFloor → mulDivCeil

function estimateIncrementalLiquidity(
    uint256 absDelta,
    uint256 liquidity,
    uint160 currentSqrtP,
    uint256 feeInFeeUnits,
    bool isExactInput,
    bool isToken0
) internal pure returns (uint256 deltaL) {
    // ✅ Ceiling calculation overestimates deltaL → underestimates nextSqrtP → prevents tick boundary overshoot
    deltaL = FullMath.mulDivCeil(liquidity, feeInFeeUnits, ...); // ✅ fixed
}
```

### 5.2 Defensive Coding Additions

```solidity
// ✅ Double-verify tick crossing using tick index in addition to sqrtP comparison

function _computeSwapStep(...) {
    // ... existing logic ...

    // ✅ Added: explicit check whether nextSqrtP exceeds tick boundary
    if (nextSqrtP >= nextTick.sqrtP && !willCrossTick) {
        revert InconsistentTickState(); // or force-process tick crossing
    }
}
```

### 5.3 Before/After Fix Comparison

| Item | Before Fix ❌ | After Fix ✅ |
|------|-----------|-----------|
| `estimateIncrementalLiquidity` rounding | `mulDivFloor` (floor) | `mulDivCeil` (ceiling) |
| `deltaL` value | Underestimated | Appropriately conservative estimate |
| `nextSqrtP` value | Can exceed tick boundary | Guaranteed to stay at or below tick boundary |
| Tick crossing detection | Can produce errors | Accurate detection |
| `_updateLiquidityAndCrossTick` call | May not be called (state mismatch) | Always called exactly once |
| Double liquidity counting | Possible | Not possible |

### 5.4 Process Recommendations

1. **Strengthen mathematical verification:** Explicitly document the rounding direction of all division operations in the AMM and verify with invariant tests
2. **Boundary condition fuzzing:** Write fuzz tests covering ±1 wei scenarios near tick boundaries
3. **Composite liquidity structure audit:** Independently audit the impact of additional liquidity components such as the reinvestment curve on base AMM logic
4. **Real-time invariant monitoring:** Continuously monitor on-chain for the condition `baseL ≤ actual deposited liquidity`
5. **Emergency pause mechanism:** Implement automatic pool suspension upon detection of anomalous liquidity changes

---

## 6. Lessons Learned

### 6.1 Key Takeaways

**"A 1 wei error can cause tens of millions of dollars in losses"**

The KyberSwap incident starkly illustrates how critical the rounding direction of arithmetic operations is in DeFi smart contracts. The fact that code comments explicitly specified ceiling rounding, yet the implementation used the opposite direction, suggests the following:

1. **Limits of code review:** Discrepancies between comments and implementation are difficult to catch through static code review alone. Mathematical invariant verification is essential.
2. **Limits of auditing:** Such vulnerabilities can still be found in externally audited code. In particular, complex AMM math operations require specialized formal verification.
3. **Risk of composite liquidity structures:** When adding complexity on top of the base Uniswap v3 structure — such as a Reinvestment Curve — all interactions must be carefully reviewed.

### 6.2 Similar Incidents

| Protocol | Date | Cause | Loss |
|----------|------|------|------|
| KyberSwap | 2023-11 | Tick boundary rounding error (floor deltaL) | ~$46M |
| Euler Finance | 2023-03 | Missing reserve donation logic | ~$197M |
| Mango Markets | 2022-10 | Oracle price manipulation | ~$117M |

### 6.3 Developer Checklist

- [ ] All division operations: Is the rounding direction conservative (in the protocol's favor)?
- [ ] AMM tick crossing logic: Are there tests covering ±1 wei boundary condition cases?
- [ ] Composite liquidity structures: Do additional liquidity components (e.g., fee reinvestment) break the invariants of the base logic?
- [ ] Invariant tests: Does `actual balance >= calculated claimable amount` always hold?
- [ ] Emergency pause: Is there an automatic response mechanism upon detection of abnormal liquidity changes?

### 6.4 References

- [KyberSwap Official Post-Mortem](https://blog.kyberswap.com/post-mortem-kyberswap-elastic-exploit/)
- [BlockSec In-Depth Analysis: A Tragedy of Precision Loss](https://blocksec.com/blog/yet-another-tragedy-of-precision-loss-an-in-depth-analysis-of-the-kyber-swap-incident-1)
- [BlockSec: Masterful Exploitation of Rounding Errors](https://blocksec.com/blog/kyberswap-incident-masterful-exploitation-of-rounding-errors-with-exceedingly-subtle-calculations)
- [SlowMist In-Depth Analysis](https://slowmist.medium.com/a-deep-dive-into-the-kyberswap-hack-3e13f3305d3a)
- [Halborn Explanation](https://www.halborn.com/blog/post/explained-the-kyberswap-hack-november-2023)