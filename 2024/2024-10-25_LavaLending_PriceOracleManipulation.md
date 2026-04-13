# Lava Lending — Price Oracle Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-10-25 |
| **Protocol** | Lava Lending |
| **Chain** | Arbitrum |
| **Loss** | ~130,000 USD |
| **Attacker** | [0x8a0dfb61](https://arbiscan.io/address/0x8a0dfb61cad29168e1067f6b23553035d83fcfb2) |
| **Attack Tx** | [0xb5cfa4ae](https://arbiscan.io/tx/0xb5cfa4ae4d6e459ba285fec7f31caf8885e2285a0b4ff62f66b43e280c947216) |
| **Vulnerable Contract** | [0x6700b021](https://arbiscan.io/address/0x6700b021a8bcfae25a2493d16d7078c928c13151) |
| **Root Cause** | The WETH-USDC LP price directly referenced the UniswapV3 spot price without TWAP, allowing collateral value manipulation via large swaps within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/LavaLending_exp.sol) |

---
## 1. Vulnerability Overview

The WETH-USDC LP token price oracle in the Lava Lending protocol referenced the AlgebraPool (UniswapV3-equivalent) spot price. The attacker borrowed large amounts of assets through multiple flash loans (AlgebraPool, Aave, Balancer, SwapFlashLoan), manipulated the LP token price, and borrowed far more assets than the actual collateral value warranted.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable LP oracle: uses spot price
contract LavaOracle {
    function getLPTokenPrice() external view returns (uint256) {
        // ❌ Uses AlgebraPool spot sqrtPriceX96
        (uint160 sqrtPriceX96,,,,,,) = IAlgebraPool(AlgebraPool).globalState();
        uint256 price = (uint256(sqrtPriceX96) ** 2) >> 192;

        // LP price = sqrt(price_A * price_B) * 2
        return _calculateLPPrice(price);
        // LP price fluctuates sharply when price_A or price_B is manipulated via flash loan
    }
}

// ✅ Fix: use TWAP price
// (uint160 sqrtPriceX96,,) = IAlgebraPool(pool).getTimepoints(...);
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: IonPool.sol
    function collateral(uint8 ilkIndex, address user) external view returns (uint256) {  // ❌ Vulnerability
        IonPoolStorage storage $ = _getIonPoolStorage();
        return $.vaults[ilkIndex][user].collateral;
    }
```

```solidity
// File: SpotOracle.sol
    function getPrice() public view virtual returns (uint256 price);  // ❌ Vulnerability

    // @dev Gets the market price multiplied by the LTV.
    // @return spot value of the asset in ETH [ray]

    /**
     * @notice Gets the risk-adjusted market price.
     * @return spot The risk-adjusted market price.
     */
    function getSpot() external view returns (uint256 spot) {
        uint256 price = getPrice(); // must be [wad]
        uint256 exchangeRate = RESERVE_ORACLE.currentExchangeRate();

        // Min the price with reserve oracle before multiplying by ltv
        uint256 min = Math.min(price, exchangeRate); // [wad]

        spot = LTV.wadMulDown(min); // [ray] * [wad] / [wad] = [ray]
    }
```

```solidity
// File: InterestRate.sol
     * @notice Helper function to pack the collateral configs into 3 words. This
     * function is only called during construction.
     * @param ilkDataList The list of ilk configs.
     * @param index The ilkIndex to pack.
     * @return packedConfig_a
     * @return packedConfig_b
     * @return packedConfig_c
     */
    function _packCollateralConfig(
        IlkData[] memory ilkDataList,
        uint256 index
    )
        private
        view
        returns (uint256 packedConfig_a, uint256 packedConfig_b, uint256 packedConfig_c)  // ❌ Vulnerability
    {
        if (index >= COLLATERAL_COUNT) return (0, 0, 0);

        IlkData memory ilkData = ilkDataList[index];

        packedConfig_a = (
            uint256(ilkData.adjustedProfitMargin) << ADJUSTED_PROFIT_MARGIN_SHIFT
                | uint256(ilkData.minimumKinkRate) << MINIMUM_KINK_RATE_SHIFT
        );

        packedConfig_b = (
            uint256(ilkData.reserveFactor) << RESERVE_FACTOR_SHIFT
                | uint256(ilkData.adjustedBaseRate) << ADJUSTED_BASE_RATE_SHIFT
                | uint256(ilkData.minimumBaseRate) << MINIMUM_BASE_RATE_SHIFT
                | uint256(ilkData.optimalUtilizationRate) << OPTIMAL_UTILIZATION_SHIFT
                | uint256(ilkData.distributionFactor) << DISTRIBUTION_FACTOR_SHIFT
        );

        packedConfig_c = (
            uint256(ilkData.adjustedAboveKinkSlope) << ADJUSTED_ABOVE_KINK_SLOPE_SHIFT
                | uint256(ilkData.minimumAboveKinkSlope) << MINIMUM_ABOVE_KINK_SLOPE_SHIFT
        );
    }
```

## 3. Attack Flow

```
Attacker
  │
  ├─[1]─▶ Multiple flash loan borrows:
  │         AlgebraPool → WETH + USDC
  │         Aave V3 → additional USDC
  │         Balancer → additional WETH
  │         SwapFlashLoan → additional assets
  │
  ├─[2]─▶ Manipulate WETH/USDC price via AlgebraPool swap
  │         Large USDC → WETH swap
  │         └─ WETH price rises → LP price rises
  │
  ├─[3]─▶ Set collateral in LendingPool using manipulated LP price
  │
  ├─[4]─▶ Over-borrow:
  │         Borrow cUSDC, aUSDCe, WBTC, WETH
  │         Total ~130K USD
  │
  ├─[5]─▶ Repay all flash loans
  │
  └─[6]─▶ ~130K USD profit
```

## 4. PoC Code

```solidity
contract AttackerC {
    function attack() external {
        // 1. Multiple flash loans (AlgebraPool)
        IAlgebraPool(AlgebraPool).flash(
            address(this), flashAmountWETH, flashAmountUSDC, ""
        );
    }

    function algebraFlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        // 2. Additional flash loans from Aave, Balancer
        IAavePoolV3(aavePoolV3).flashLoanSimple(address(this), usdc, aaveAmount, "", 0);
    }

    function executeOperation(...) external {
        // 3. Manipulate WETH/USDC price
        IUniswapV3Router(UniswapV3Router2).exactInputSingle(/* USDC → WETH */);

        // 4. ❌ Over-borrow using manipulated LP price
        ILendingPool(LendingPool).borrow(/* cUSDC, WBTC, WETH */);

        // 5. Full repayment
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Oracle Manipulation |
| **Attack Vector** | AMM spot price manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP** | Business Logic Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **TWAP Oracle**: Use the TWAP (Time-Weighted Average Price) from AlgebraPool/UniswapV3
2. **Chainlink LP Oracle**: Use a verified LP pricing methodology
3. **Price Deviation Guard**: Set a maximum allowable price change within a single block
4. **Multi-Oracle Validation**: Block execution when the price deviation across multiple sources exceeds a threshold

## 7. Lessons Learned

- AMM spot price oracle vulnerabilities apply equally on L2 networks such as Arbitrum.
- Combined multi-flash-loan attacks can manipulate oracles with far greater capital than a single flash loan.
- LP token pricing is particularly complex; proven methodologies (Chainlink, TWAP) must always be used.