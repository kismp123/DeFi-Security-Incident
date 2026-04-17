# Balancer V2 — Precision Loss Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-11-03 |
| **Protocol** | Balancer V2 (Composable Stable Pool) |
| **Chain** | Arbitrum, Ethereum, Polygon, Base, Sonic, Optimism (multi-chain) |
| **Loss** | $120,000,000 |
| **Attacker** | Unconfirmed (previous address was unverified) |
| **Attack Tx** | Unconfirmed (previous hash was unverified) |
| **Root Cause** | Invariant D manipulation via Rounding Direction Mismatch in scaling logic |

---

## 1. Vulnerability Overview

On November 3, 2025 at 07:48 UTC, Balancer V2's **Composable Stable Pool (CSP)** was exploited through a precision loss vulnerability. A total of $120 million was drained across 6 chains — Ethereum, Arbitrum, Polygon, Base, Sonic, and Optimism — making this one of the largest DeFi attacks in 2025.

### Core Vulnerability Summary

Balancer V2's `ComposableStablePool` performs **upscale** and **downscale** operations internally to convert token amounts to a standard unit (1e18). The problem is that the **rounding direction between these two operations is asymmetric**.

- `_upscale()`: uses `FixedPoint.mulDown()` → **always rounds down (truncation)**
- `_downscale()`: conditionally uses `divUp()` or `divDown()` → **variable direction**

During `EXACT_OUT` swaps (fixed output amount), applying `_upscale()` with round-down to the input amount calculation causes the pool to perceive that **less tokens need to be paid** than actually required. The attacker exploited this subtle discrepancy by repeating it dozens to hundreds of times within `batchSwap()`, progressively reducing invariant D, which in turn artificially lowered the BPT (Balancer Pool Token) price to realize profit.

### Key Affected Assets

- osETH (StakeWise)
- wstETH, cbETH, ezETH, weETH, ankrETH (LST family)
- USDC and stablecoins

---

## 2. Vulnerable Code Analysis

### 2-1. The Core Problem: `_upscale()` Round-Down ❌

```solidity
// ❌ Vulnerable code (BasePool.sol)
function _upscale(uint256 amount, uint256 scalingFactor)
    internal pure returns (uint256)
{
    // mulDown = floor(amount * scalingFactor / 1e18)
    // Rounds down the input value in EXACT_OUT swaps → returns a value smaller than actual
    return FixedPoint.mulDown(amount, scalingFactor);
}
```

**Problem**: When upscaling the output amount during an `EXACT_OUT` swap with round-down, the pool perceives the user as withdrawing fewer tokens than they actually are. This discrepancy is reflected in the invariant D calculation, causing D to gradually decrease.

### 2-2. `_swapGivenOut()` — Error Propagation in the EXACT_OUT Path ❌

```solidity
// ❌ Vulnerable code (BaseGeneralPool.sol)
function _swapGivenOut(
    SwapRequest memory swapRequest,
    uint256[] memory balances,
    uint256 indexIn,
    uint256 indexOut
) internal virtual override returns (uint256) {
    // Converts swapRequest.amount (output amount) with _upscale()
    // → Round-down makes amountOut smaller than actual
    swapRequest.amount = _upscale(swapRequest.amount, _scalingFactor(swapRequest.tokenOut));

    // Recalculates invariant D with underestimated amountOut → D value shrinks
    uint256 amountIn = _onSwapGivenOut(swapRequest, balances);
    // ...
}
```

### 2-3. Relationship Between Invariant D and BPT Price

```
BPT Price = D / totalSupply

Attack flow:
  mulDown round-down → amountOut underestimated
  → Invariant D decreases
  → BPT Price = D / totalSupply decreases
  → Attacker: sells BPT at lower price → realizes profit
```

### 2-4. Correct Fix: Directional Rounding ✅

```solidity
// ✅ Fixed code
function _upscaleGivenOut(uint256 amount, uint256 scalingFactor)
    internal pure returns (uint256)
{
    // Apply ceiling when upscaling output amount in EXACT_OUT
    // → Pool perceives more tokens being withdrawn → prevents D from decreasing
    return FixedPoint.mulUp(amount, scalingFactor);
}
```

**Principle**: Regardless of swap direction, rounding must **always be applied in the direction favorable to the protocol**.
- Input amount (amountIn) calculation: ceiling → user pays more
- Output amount (amountOut) calculation: floor → user receives less

---

## 3. Attack Flow (with ASCII Diagram)

### Step-by-Step Attack Flowchart

```
Attacker (EOA: 0xaa760d...)
    │
    │  1. Fund sourcing (via Tornado Cash)
    ▼
Deploy helper contract
    │  ┌─────────────────────────────────────────────────┐
    │  │  Off-chain parameter calculation                 │
    │  │  - Read pool state (balances, amp,              │
    │  │    scalingFactor, fee)                          │
    │  │  - Calculate optimal trickAmt via               │
    │  │    StableMath mirror contract                   │
    │  │  - Goal: position a specific token balance      │
    │  │    at a boundary value (9 wei)                  │
    │  └─────────────────────────────────────────────────┘
    │
    │  2. Positioning phase
    ▼
Call batchSwap()
    │
    │  [Step A] BPT → base token swap (large amount)
    │           Specific token balance in pool → reaches boundary value (9 wei)
    │
    │  [Step B] Execute small EXACT_OUT swap (core vulnerability)
    │   ┌─────────────────────────────────────────────────────┐
    │   │  Request: wstETH → cbETH, amountOut = 8 wei        │
    │   │                                                     │
    │   │  _upscale(8, scalingFactor)                        │
    │   │    = mulDown(8, scalingFactor)                      │
    │   │    = floor(8.918...) = 8  ← decimal truncated!     │
    │   │                                                     │
    │   │  Underestimated Δy = 8 (actual: 8.918)             │
    │   │  → Invariant D decreases on recalculation          │
    │   │  → Δx(amountIn) underestimated → attacker profits  │
    │   └─────────────────────────────────────────────────────┘
    │
    │  [Step C] Base token → BPT reverse swap
    │           BPT price calculated based on reduced D
    │           → Receives more BPT (arbitrage profit)
    │
    │  ⟳ Repeat Steps A~C (65+ times within a single transaction)
    │    Each iteration further reduces D → cumulative profit grows
    │
    │  3. Profit realization
    ▼
Call manageUserBalance()
    │  Withdraw accumulated vault balance to EOA
    ▼
Launder / hold profits

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Loss: $125,000,000
  ├─ Ethereum:  ~$100,000,000 (largest impact)
  ├─ Arbitrum:  partial loss ($49K recovered by whitehats)
  ├─ Polygon:   partial loss
  ├─ Base:      partial loss
  ├─ Sonic:     partial loss
  └─ Optimism:  partial loss

Whitehat recovery: ~$19,300,000 (counter-exploit of contract)
Net final loss:    ~$105,700,000
```

### Precision Loss Accumulation Mechanism

```
Iteration 1:  D = 1,000,000    BPT Price = 1.000000
Iteration 2:  D = 999,999      BPT Price = 0.999999  (-0.0001%)
Iteration 3:  D = 999,997      BPT Price = 0.999997  (-0.0002%)
   ...             ...
Iteration 65: D = 999,850      BPT Price = 0.999850  (-0.015%)

Total cumulative error: 0.015% × Pool TVL ($800M) ≈ $120M extractable
```

---

## 4. Vulnerability Classification (Table + Details)

### 4-1. Vulnerability Classification Table

| Category | Detail | Status |
|------|-----------|------|
| **CWE-682** | Incorrect Calculation | ❌ Vulnerable |
| **Precision Loss** | Fixed-point mulDown unidirectional round-down | ❌ Vulnerable |
| **Invariant Violation** | Allows monotonic decrease of D after swaps | ❌ Vulnerable |
| **Boundary Value Not Checked** | No handling of rounding boundary conditions on small trades | ❌ Vulnerable |
| **Compound Transaction Abuse** | Unlimited iterations allowed within batchSwap | ❌ Vulnerable |
| **No Emergency Pause** | Absence of automatic pause mechanism for CSP | ❌ Vulnerable |

### 4-2. Precision Loss Detail

**Vulnerability ID**: TOB-BALANCER-004 (already identified in Trail of Bits 2021 audit)

In fixed-point arithmetic, integer division truncates the fractional part. Balancer V2 performs 1e18-unit fixed-point arithmetic via the `FixedPoint` library, where under certain conditions `mulDown` can return a value meaningfully smaller than the true value.

**Example**: For the osETH/WETH pool:
```
osETH balance upscale:
  True value: 17.98825094772952 wei × scalingFactor
  mulDown result: 17 wei
  Error: 0.988 wei ≈ 5.8% (critical for small-amount trades)
```

### 4-3. Invariant Manipulation Detail

The StableSwap invariant D must satisfy:
```
∀ valid swaps: D(after) ≥ D(before)
```

However, due to the round-down in `_upscale()`, D can decrease when processing `EXACT_OUT` swaps. Since this condition is not explicitly validated in the code, the attacker was able to reduce D to an arbitrary level through repeated calls.

### 4-4. Compound Attack Vector (Composable Pool BPT Abuse) Detail

The Composable Stable Pool allows the pool's own BPT to be included as a base token for trading. This enables:
1. Large BPT sells to drive a token balance to a boundary value
2. Precision loss reduces D
3. Re-buy BPT at the reduced D basis → arbitrage profit locked in

This attack was impossible in a regular StableSwap and was a risk unique to the Composable Pool design.

---

## 5. Remediation Recommendations

### 5-1. Immediate Fix: Unify Rounding Direction ✅

```solidity
// ✅ Apply ceiling when upscaling output amount in EXACT_OUT swaps
function _swapGivenOut(
    SwapRequest memory swapRequest,
    uint256[] memory balances,
    uint256 indexIn,
    uint256 indexOut
) internal virtual override returns (uint256) {
    // Change mulDown → mulUp: round in direction favorable to the protocol
    swapRequest.amount = _upscaleGivenOut(
        swapRequest.amount,
        _scalingFactor(swapRequest.tokenOut)
    );
    // ...
}

function _upscaleGivenOut(uint256 amount, uint256 scalingFactor)
    internal pure returns (uint256)
{
    return FixedPoint.mulUp(amount, scalingFactor);  // ✅ ceiling
}
```

### 5-2. Add Post-Swap Invariant Verification ✅

```solidity
// ✅ Verify monotonic increase of invariant D after each swap
function _validateInvariant(
    uint256 invariantBefore,
    uint256 invariantAfter
) internal pure {
    // D must not decrease after a swap (should increase when fees are included)
    require(
        invariantAfter >= invariantBefore,
        "INVARIANT_DECREASED"
    );
}
```

### 5-3. Implement Emergency Pause Mechanism ✅

```solidity
// ✅ Automatically pause pool upon detecting anomalous D change
uint256 private constant MAX_INVARIANT_DECREASE_BPS = 1; // 0.01%

function _checkAndPauseIfAnomalous(
    uint256 invariantBefore,
    uint256 invariantAfter
) internal {
    if (invariantBefore > 0) {
        uint256 decreaseBps = (invariantBefore - invariantAfter)
            * 10000 / invariantBefore;
        if (decreaseBps > MAX_INVARIANT_DECREASE_BPS) {
            _pause(); // automatic pause
            emit AnomalousInvariantChange(invariantBefore, invariantAfter);
        }
    }
}
```

### 5-4. Enforce Minimum Trade Amount ✅

```solidity
// ✅ Set minimum trade amount to prevent boundary value manipulation
uint256 private constant MIN_SWAP_AMOUNT = 1e6; // adjust per token

modifier minSwapAmount(uint256 amount) {
    require(amount >= MIN_SWAP_AMOUNT, "SWAP_AMOUNT_TOO_SMALL");
    _;
}
```

### 5-5. Structural Resolution in Balancer V3 ✅

Balancer V3 structurally eliminates this class of vulnerability through:
- **18-decimal standardization**: Always normalizes all tokens to 18 decimals, eliminating scaling errors at the source
- **ERC4626 buffer**: Removes internal BPT trading by replacing Composable Pools with ERC4626 buffers
- **Enforced unidirectional rounding**: Explicitly applies protocol-favorable rounding direction across all arithmetic operations

---

## 6. Lessons Learned

### 6-1. Do Not Dismiss Old Audit Findings

Trail of Bits identified this exact rounding direction issue in their **October 2021** audit (TOB-BALANCER-004). It was classified as "minimal impact" at the time and the fix was deferred — leading to $125M in losses 4 years later. **Audit findings must be remediated immediately, regardless of severity rating.**

### 6-2. Encode Mathematical Invariants in Code

The core property of the StableSwap algorithm, `D(after) ≥ D(before)`, should not rely solely on mathematical proofs — it must be verified at runtime via `require` statements. **Mathematical correctness and implementation correctness are distinct concerns.**

### 6-3. Composable Designs Create New Attack Surfaces

A vulnerability that posed no risk in a regular StableSwap became a critical exploit when combined with the **Composable Pool's internal BPT trading feature**. It must be recognized that feature composition can always introduce new attack vectors.

### 6-4. Exhaustively Test Boundary Conditions

The attacker used the formula `trickAmt = 10^(scalingFactor_decimals - 2)` to compute the optimal attack amount for each pool via off-chain simulation. Protocol development teams should have detected such boundary conditions in advance through **fuzz testing** and **formal verification**.

### 6-5. Multi-Chain Deployment Multiplies Risk

Because a single vulnerability was simultaneously deployed across 6 chains, the damage grew exponentially. Multi-chain deployments must incorporate **chain-by-chain sequential rollouts** and **per-chain independent pause authority** as mandatory safeguards.

### 6-6. The Importance of Whitehat Recovery

The $19.3M whitehat recovery was made possible by a rapid community response. DeFi protocols must proactively establish **whitehat emergency response channels** and **explicit return incentive policies** during peacetime.

---

*References:*
- [BlockSec: In-Depth Analysis: The Balancer V2 Exploit](https://blocksec.com/blog/in-depth-analysis-the-balancer-v2-exploit)
- [Trail of Bits: Balancer hack analysis and guidance](https://blog.trailofbits.com/2025/11/07/balancer-hack-analysis-and-guidance-for-the-defi-ecosystem/)
- [Certora: Breaking Down the Balancer Hack](https://www.certora.com/blog/breaking-down-the-balancer-hack)
- [SlowMist: When Small Flaws Collapse a Giant](https://slowmist.medium.com/when-small-flaws-collapse-a-giant-inside-balancers-100m-hack-85b9e92a9ae3)
- [QuillAudits: The Balancer Hack 2025](https://www.quillaudits.com/blog/hack-analysis/the-balancer-hack)
- [Halborn: Explained: The Balancer Hack (November 2025)](https://www.halborn.com/blog/post/explained-the-balancer-hack-november-2025)