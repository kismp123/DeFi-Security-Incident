# SwapX — Flash Loan Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-17 |
| **Protocol** | SwapX |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | BSC Transaction |
| **Vulnerable Contract** | SwapX Router/Pool |
| **Root Cause** | Price calculation within the pool relies on `getReserves()` spot reserves, making it manipulable via large swaps within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/SwapX_exp.sol) |

---
## 1. Vulnerability Overview

SwapX is a BSC-based DEX that calculates trade prices using the pool's current reserve ratio. The attacker borrowed a large amount of tokens via a flash loan, then drastically altered the reserve ratio of the SwapX pool to obtain a favorable exchange rate and extract profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable spot-price-based exchange
function getAmountOut(uint256 amountIn, address tokenIn, address tokenOut)
    public view returns (uint256) {
    (uint256 reserveIn, uint256 reserveOut) = getReserves(tokenIn, tokenOut);
    // ❌ Calculated solely from current reserves → reserves can be manipulated via flash loan
    return amountIn * reserveOut / (reserveIn + amountIn);
}

// ✅ Fix: TWAP or price deviation check
function getAmountOut(uint256 amountIn, address tokenIn, address tokenOut)
    public view returns (uint256) {
    uint256 spotPrice = calculateSpotPrice(tokenIn, tokenOut);
    uint256 twapPrice = oracle.getTWAP(tokenIn, tokenOut, 30 minutes);
    // ✅ Reject trade if deviation between spot price and TWAP is too large
    require(spotPrice * 100 / twapPrice >= 95, "Price manipulation detected");
    return calculateOutput(amountIn, tokenIn, tokenOut);
}
```

### On-chain Original Code

Source: Bytecode Decompilation

```solidity
// Root Cause: Price calculation within the pool relies on getReserves() spot reserves, making it manipulable via large swaps within a single block
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Flash Loan (borrow large amount of TokenA)
  │
  ├─2─▶ Swap TokenA → TokenB in large volume (alters SwapX pool reserve ratio)
  │
  ├─3─▶ Reverse swap TokenB → TokenA at manipulated price
  │       Acquire more TokenA at favorable ratio
  │
  └─4─▶ Repay flash loan → retain difference as net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function executeArbitrage(uint256 flashAmount) internal {
    // 1. Swap large TokenA for a small amount of TokenB (intentionally unfavorable swap)
    //    → Drastically alters SwapX reserve ratio
    swapAtoB(flashAmount);  // reserves: tokenA increases, tokenB decreases

    // 2. Reverse swap TokenB → TokenA against the manipulated reserves
    //    → tokenB price is now elevated in current reserves, yielding more tokenA
    uint256 bBalance = tokenB.balanceOf(address(this));
    swapBtoA(bBalance);  // over-acquire tokenA at favorable ratio

    // 3. Repay flash loan principal and retain the difference
    repayFlashLoan(flashAmount);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Manipulation |
| **Attack Vector** | Flash Loan + AMM reserve manipulation |
| **Impact Scope** | SwapX pool liquidity |
| **DASP Classification** | Oracle Manipulation |
| **CWE** | CWE-20: Improper Input Validation |

## 6. Remediation Recommendations

1. **Price Deviation Limit**: Restrict the allowable price slippage within a single transaction.
2. **TWAP Price Validation**: Set a deviation threshold between the spot price and TWAP.
3. **Single-Block Large Trade Restriction**: Block abnormally large single transactions.

## 7. Lessons Learned

- AMM-based DEXes must be designed under the assumption that prices can always be manipulated.
- Calculations that rely solely on spot price are vulnerable to flash loan attacks.
- Even if TWAP implementation carries a performance overhead, it is essential for security.