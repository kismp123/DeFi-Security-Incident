# Nerve Bridge — MetaSwap Liquidity Removal Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2021-12-21 |
| **Protocol** | Nerve Bridge |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$80,000 |
| **Attacker** | [0xd547...228](https://bscscan.com/address/0xd5476194bdc298b6981f5414b693363f94d69228) |
| **Attack Tx** | [0xea95...f1d](https://bscscan.com/tx/0xea95925eb0438e04d0d81dc270a99ca9fa18b94ca8c6e34272fc9e09266fcf1d) (block 12,653,565) |
| **Vulnerable Contract** | Nerve MetaSwap / Nerve 3Pool |
| **Root Cause** | `remove_liquidity_one_coin()` allowing `min_amount=0` and no restriction on repeated calls within the same block, causing accumulated pool imbalance through sequential MetaSwap + 3Pool interactions |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-12/NerveBridge_exp.sol) |

---
## 1. Vulnerability Overview

Nerve Bridge's MetaSwap is a Curve-style composite AMM that combines a base pool (Nerve 3Pool: BUSD/USDT/USDC) with a meta token (fUSD). The attacker borrowed 50,000 BUSD via a ForTube flash loan, converted it to fUSD on Ellipsis, then repeated a `swapUnderlying()` + `removeLiquidityOneToken()` cycle 7 times through MetaSwap to manipulate the BUSD ratio within the 3Pool and exploit the resulting fUSD/BUSD price imbalance for profit.

---
## 2. Vulnerable Code Analysis

Source: **Sourcify-verified** (partial match) — Nerve 3Pool `Swap.sol` (`0x1B3771a66ee31180906972580adE9b81AFc5fCDc`, BSC)
https://sourcify.dev/server/files/any/56/0x1B3771a66ee31180906972580adE9b81AFc5fCDc

The Nerve 3Pool is a Saddle Finance fork. The `removeLiquidityOneToken()` entry point in `Swap.sol` delegates to `SwapUtils.removeLiquidityOneToken()`. The vulnerability is that the function accepts `minAmount = 0`, meaning a caller can withdraw with zero slippage protection. When called repeatedly in a loop within a single transaction (interleaved with `swapUnderlying()` on the MetaSwap), each iteration skews the pool's internal D-invariant and token reserves, allowing the attacker to extract more base tokens than they are entitled to.

### 2.1 `removeLiquidityOneToken()` — Zero-Slippage Withdrawal Allowed

```solidity
function removeLiquidityOneToken(
    uint256 tokenAmount,
    uint8 tokenIndex,
    uint256 minAmount,   // ❌ caller can pass 0 — no slippage protection enforced
    uint256 deadline
)
    external
    nonReentrant
    whenNotPaused
    deadlineCheck(deadline)
    returns (uint256)
{
    return
        swapStorage.removeLiquidityOneToken(
            tokenAmount,
            tokenIndex,
            minAmount    // ❌ minAmount=0 accepted without revert — no floor check
        );
}
```

### 2.2 `swap()` — Used for Pool Manipulation Between Removal Calls

```solidity
function swap(
    uint8 tokenIndexFrom,
    uint8 tokenIndexTo,
    uint256 dx,
    uint256 minDy,      // ❌ also accepts 0 — each swap shifts reserves with no slippage floor
    uint256 deadline
)
    external
    nonReentrant
    whenNotPaused
    deadlineCheck(deadline)
    returns (uint256)
{
    return swapStorage.swap(tokenIndexFrom, tokenIndexTo, dx, minDy);
}
```

**Why it is exploitable (identify the bug from the code):**

- `minAmount = 0` in `removeLiquidityOneToken()` disables the slippage guard entirely. The Saddle/Nerve AMM uses the StableSwap invariant — each large one-sided withdrawal shifts the pool's reserves and the effective exchange rate of the remaining tokens.
- The attacker exploits this in a 7-iteration loop: each iteration calls `MetaSwap.swapUnderlying(fUSD → Nerve3LP)` followed by `Nerve3Pool.removeLiquidityOneToken(3LP → BUSD, minAmount=0)`. Each cycle extracts BUSD while the pool's internal accounting of the BUSD/3Pool ratio grows more skewed.
- Because `minAmount=0` means no loss is ever rejected, every iteration — no matter how unfavorable the price — is accepted. The aggregate skew across 7 iterations is large enough to generate a profit that exceeds the flash loan fee.
- The lack of per-block or per-transaction interaction limits allows all 7 cycles to execute atomically in a single transaction.

```solidity
// ✅ Fix: enforce a nonzero minAmount floor
function removeLiquidityOneToken(
    uint256 tokenAmount,
    uint8 tokenIndex,
    uint256 minAmount,
    uint256 deadline
) external nonReentrant whenNotPaused deadlineCheck(deadline) returns (uint256) {
    require(minAmount > 0, "Swap: minAmount must be > 0"); // ✅ prevent zero-slippage withdrawals
    return swapStorage.removeLiquidityOneToken(tokenAmount, tokenIndex, minAmount);
}
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Step 1: ForTube flash loan 50,000 BUSD                       │
│ executeOperation() callback executed                         │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 2: Convert BUSD → fUSD on Ellipsis                      │
│ ellipsis.exchange(BUSD_IDX, fUSD_IDX, busd_amount, 0)       │
└─────────────────────┬────────────────────────────────────────┘
                      │ (repeated 7 times)
┌─────────────────────▼────────────────────────────────────────┐
│ Step 3: MetaSwap.swapUnderlying(fUSD → Nerve3LP)            │
│ + Nerve3Pool.remove_liquidity_one_coin(3LP, BUSD_IDX, 0)    │
│ → BUSD ratio in 3Pool gradually decreases                    │
│ → fUSD/BUSD price imbalance accumulates                      │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 4: Final conversion of remaining fUSD → BUSD            │
│         at favorable price                                   │
│ ellipsis.exchange(fUSD_IDX, BUSD_IDX, remaining, 0)         │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 5: Repay ForTube flash loan + realize profit            │
│ ~$80K BUSD profit                                            │
└──────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// executeOperation() — ForTube flash loan callback
function executeOperation(
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata params
) external override {
    // Convert BUSD → fUSD (Ellipsis)
    // IEllipsis(ellipsis).exchange(0, 1, busdAmount, 0)

    // 7 iterations: price manipulation via MetaSwap + Nerve3Pool combination
    for (uint i = 0; i < 7; i++) {
        // fUSD → Nerve3LP (MetaSwap)
        // IMetaSwap(metaSwap).swapUnderlying(fUSD_IDX, 3LP_IDX, fUSDAmount, 0, deadline)

        // 3LP → BUSD (Nerve3Pool liquidity removal)
        // INerve3Pool(nerve3pool).remove_liquidity_one_coin(3lpAmount, BUSD_IDX, 0)

        // Re-convert BUSD → fUSD (Ellipsis + exploiting manipulated price)
        // IEllipsis(ellipsis).exchange(0, 1, busdAmount, 0)
    }

    // Final fUSD → BUSD conversion to realize profit
    // Repay flash loan principal + fee
    IERC20(token).transfer(address(ForTube), amount + fee);
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `remove_liquidity_one_coin()` allows `min_amount=0` — repeated calls without slippage protection cause cumulative reduction of 3Pool BUSD ratio | HIGH | CWE-20 |
| V-02 | No restriction on repeated MetaSwap + 3Pool interactions within the same block — 7-cycle loop accumulates fUSD/BUSD imbalance (contributing factor: flash loan capital) | MEDIUM | CWE-829 |

> **Root Cause**: Allowing `min_amount=0` is the core issue. Enforcing a meaningful minimum received amount in `remove_liquidity_one_coin()` causes the slippage loss from each iteration to offset the arbitrage gain, making the attack unprofitable. Flash loans are merely the funding mechanism.

---
## 6. Remediation Recommendations

```solidity
// ✅ Limit pool interactions within a single transaction in composite AMMs
// ✅ Prohibit slippage parameter of 0

function remove_liquidity_one_coin(
    uint256 _token_amount,
    int128 i,
    uint256 _min_amount
) external nonReentrant returns (uint256) {
    // minAmount=0 means no slippage protection — prohibited
    require(_min_amount > 0, "Nerve3Pool: slippage protection required");

    uint256 dy = calc_withdraw_one_coin(_token_amount, i);
    require(dy >= _min_amount, "Nerve3Pool: slippage exceeded");
    // ...
}
```

---
## 7. Lessons Learned

- **Allowing `min_amount=0` is the root cause.** Enforcing a meaningful minimum received amount on each liquidity removal call eliminates the profitability of the repeated cycle.
- **Flash loans are the funding mechanism.** With slippage protection in place, repeated arbitrage attacks are blocked regardless of flash loan size.
- **In composite AMM structures (MetaSwap + base pool), the state of one pool affects pricing in the other.** Additional protections are required for interactions between coupled pools.