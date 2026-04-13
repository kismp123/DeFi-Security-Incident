# OceanLife (OLIFE) Exploit — deliver() Reflection Rate Manipulation

## Metadata
| Field | Value |
|---|---|
| Date | 2023-04-14 |
| Project | OceanLife (OLIFE) |
| Chain | BSC |
| Loss | ~unconfirmed address WBNB |
| Attacker | unconfirmed address |
| Attack TX | unconfirmed address (BSC) |
| Vulnerable Contract | OLIFE reflection token (BSC) |
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Reflection Token deliver() + Pair Reserve Drain |

## Summary
OLIFE is a reflection ERC20 on BSC. The attacker used a DODO flash loan of 969 WBNB, swapped to OLIFE, then called `deliver(66.859 billion OLIFE)` 19 times via transfer loops. This progressively reduced `rSupply` and `tSupply` (the reflection denominators), making the LP pair's `rOwned[pair] / currentRate` appear larger than the pair's stored reserve. The attacker then executed a direct `swap()` on the pair to extract the excess WBNB.

## Vulnerability Details
- **CWE-682**: Each `deliver()` call reduces `_rTotal` (reflected total supply). After sufficient calls, `balanceOf(pair) = _rOwned[pair] / (_rTotal / _tTotal)` exceeds `pair.reserve0`, creating a gap. A `Pair.swap()` extracting `balanceOf(pair) - 1` OLIFE triggers a reserve update that rewards the attacker with excess WBNB.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// 파일: PancakeRouter.sol
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(  // ❌

// ...

    function swapExactETHForTokensSupportingFeeOnTransferTokens(  // ❌

// ...

    function swapExactTokensForETHSupportingFeeOnTransferTokens(  // ❌

// ...

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut)  // ❌

// ...

    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut)  // ❌
```

## Attack Flow
```
1. DODO.flashLoan(969 WBNB)
2. swap WBNB → OLIFE via PancakeSwap
3. for i in range(19):
     OLIFE.transfer(Pair, someAmount)   // cycle tokens
     OLIFE.deliver(3_518_895_000e18)    // reduce rSupply each iter
4. Pair.swap(excessOLIFE, 0, this, "") // extract WBNB via price shift
5. swap OLIFE → WBNB
6. Repay DODO
```

## Interfaces from PoC
```solidity
interface IOceanLife {
    function deliver(uint256 tAmount) external;
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
```

## Key Addresses
| Label | Address |
|---|---|
| OLIFE Token | BSC (unconfirmed address) |
| OLIFE/WBNB Pair | BSC PancakeSwap |
| DODO Flash | BSC DODO |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |
| WBNB | 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c |

## Root Cause
Reflection token `deliver()` modifies `_rTotal` without calling `pair.sync()`, enabling reserve desynchronization exploitable via direct `swap()`.

## Fix
```solidity
function deliver(uint256 tAmount) public {
    // ... existing reflection logic ...
    IUniswapV2Pair(olifeWbnbPair).sync(); // sync after every deliver()
}
```

## References
- DODO flash loan + deliver() loop pattern (19 iterations)
- BSC reflection token attack variant