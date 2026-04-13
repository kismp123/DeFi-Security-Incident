# Nerve Bridge — MetaSwap Liquidity Removal Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2021-12-21 |
| **Protocol** | Nerve Bridge |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$80,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | Nerve MetaSwap / Nerve 3Pool |
| **Root Cause** | `remove_liquidity_one_coin()` allowing `min_amount=0` and no restriction on repeated calls within the same block, causing accumulated pool imbalance through sequential MetaSwap + 3Pool interactions |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-12/NerveBridge_exp.sol) |

---
## 1. Vulnerability Overview

Nerve Bridge's MetaSwap is a Curve-style composite AMM that combines a base pool (Nerve 3Pool: BUSD/USDT/USDC) with a meta token (fUSD). The attacker borrowed 50,000 BUSD via a ForTube flash loan, converted it to fUSD on Ellipsis, then repeated a `swapUnderlying()` + `removeLiquidityOneToken()` cycle 7 times through MetaSwap to manipulate the BUSD ratio within the 3Pool and exploit the resulting fUSD/BUSD price imbalance for profit.

---
## 2. Vulnerable Code Analysis

### 2.1 MetaSwap — Price Manipulation via Repeated Liquidity Removal

```solidity
// ❌ Nerve MetaSwap / Nerve3Pool
// Repeated liquidity removal within a single transaction accumulates pool imbalance
// When removeLiquidityOneToken() is called repeatedly after swapUnderlying(),
// internal prices become distorted without slippage protection

interface IMetaSwap {
    // Swap meta pool using base pool tokens
    function swapUnderlying(
        uint8 tokenIndexFrom,
        uint8 tokenIndexTo,
        uint256 dx,
        uint256 minDy,
        uint256 deadline
    ) external returns (uint256);
}

interface INerve3Pool {
    // Remove liquidity as a single token
    function remove_liquidity_one_coin(
        uint256 _token_amount,
        int128 i,
        uint256 _min_amount
    ) external returns (uint256);
    // ❌ minAmount=0 means no slippage protection
    // Repeated calls accumulate pool imbalance → price manipulation
}
```

**Fixed Code**:
```solidity
// ✅ Limit the number of same-pool interactions within a single transaction
// ✅ Enforce minimum received amount validation on liquidity removal

mapping(address => uint256) public lastInteractionBlock;
uint256 public constant MAX_INTERACTIONS_PER_BLOCK = 1;

function remove_liquidity_one_coin(
    uint256 _token_amount,
    int128 i,
    uint256 _min_amount
) external returns (uint256) {
    require(
        block.number > lastInteractionBlock[msg.sender],
        "Nerve3Pool: one interaction per block"
    );
    require(_min_amount > 0, "Nerve3Pool: zero min_amount");
    lastInteractionBlock[msg.sender] = block.number;
    // ...
}
```


### On-Chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable Function** — `remove_liquidity_one_coin()`:
```solidity
// ❌ Root cause: `remove_liquidity_one_coin()` allowing `min_amount=0` and no restriction on repeated calls
// within the same block, causing accumulated pool imbalance through sequential MetaSwap + 3Pool interactions
// Source code unconfirmed — bytecode analysis required
// Vulnerability: `remove_liquidity_one_coin()` allowing `min_amount=0` and no restriction on repeated calls
// within the same block, causing accumulated pool imbalance through sequential MetaSwap + 3Pool interactions
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