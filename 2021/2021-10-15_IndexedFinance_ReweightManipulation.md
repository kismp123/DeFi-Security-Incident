# Indexed Finance — Re-indexing Price Manipulation DEFI5 Pool Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2021-10-15 |
| **Protocol** | Indexed Finance |
| **Chain** | Ethereum |
| **Loss** | ~$16,000,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | DEFI5 Index Pool |
| **Root Cause** | During re-indexing, `swapExactAmountIn()` allows MAX_IN_RATIO of 50% (excessively high) and `joinswapExternAmountIn()` lacks slippage protection, enabling large swaps to distort the pool's internal price followed by low-cost minting |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-10/IndexedFinance_exp.sol) |

---
## 1. Vulnerability Overview

Indexed Finance's DEFI5 index pool allows external traders to exploit price discrepancies via swaps during component token rebalancing. The attacker flash-loaned 6 tokens (UNI, AAVE, COMP, CRV, MKR, SNX) from Uniswap V2 and used `swapExactAmountIn()` to swap them into the index pool, distorting the composition ratios. The attacker then mass-minted index tokens at the artificially deflated price via `joinswapExternAmountIn()`, took profits, and repaid the flash loan.

---
## 2. Vulnerable Code Analysis

### 2.1 swapExactAmountIn() — MAX_IN_RATIO 50% Permitted, No Price Protection During Re-indexing

```solidity
// ❌ DEFI5 IndexPool — large swaps permitted during re-indexing
uint256 public constant MAX_IN_RATIO = 5 * 10**17; // 50%

function swapExactAmountIn(
    address tokenIn,
    uint256 tokenAmountIn,
    address tokenOut,
    uint256 minAmountOut,
    uint256 maxPrice
) external returns (uint256 tokenAmountOut, uint256 spotPriceAfter) {
    Record storage inRecord = _records[tokenIn];
    Record storage outRecord = _records[tokenOut];

    // Allows a single swap of up to 50% of pool balance
    // Flash loan → mass swap → rapid pool price distortion
    require(
        tokenAmountIn <= bmul(inRecord.balance, MAX_IN_RATIO),
        "ERR_MAX_IN_RATIO"
    );
    // ...
}
```

**Fixed Code**:
```solidity
// ✅ Pause swaps during re-indexing
// ✅ Lower MAX_IN_RATIO to 5%

uint256 public constant MAX_IN_RATIO = 5 * 10**16; // 5%
bool public reindexing;

modifier notReindexing() {
    require(!reindexing, "IndexPool: reindexing in progress");
    _;
}

function swapExactAmountIn(...) external notReindexing returns (...) {
    require(
        tokenAmountIn <= bmul(inRecord.balance, MAX_IN_RATIO),
        "ERR_MAX_IN_RATIO"
    );
    // ...
}
```


### On-chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable Function** — `swapExactAmountIn()`:
```solidity
// ❌ Root Cause: During re-indexing, `swapExactAmountIn()` MAX_IN_RATIO is excessively high at 50% and `joinswapExternAmountIn()` lacks slippage protection, enabling large swaps to distort pool internal price followed by low-cost minting
// Source code unconfirmed — bytecode analysis required
// Vulnerability: During re-indexing, `swapExactAmountIn()` MAX_IN_RATIO is excessively high at 50% and `joinswapExternAmountIn()` lacks slippage protection, enabling large swaps to distort pool internal price followed by low-cost minting
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────────────────┐
│ Step 1: Uniswap V2 flash loan — 6 tokens                   │
│ Borrow large amounts of UNI, AAVE, COMP, CRV, MKR, SNX    │
│ uniswapV2Call() callback                                   │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 2: DEFI5 IndexPool.swapExactAmountIn() repeated       │
│ Swap each token into the DEFI5 pool (exploit MAX_IN_RATIO  │
│ 50%) → distort token ratios in pool, index price drops     │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 3: DEFI5 IndexPool.joinswapExternAmountIn()           │
│ Mass-mint DEFI5 index tokens at distorted low price        │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 4: Additional repeated mint/exit via SUSHI flash loan │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 5: Sell minted DEFI5 tokens + repay flash loans       │
│ ~$16M drained                                              │
└────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// uniswapV2Call() — flash loan callback
function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {
    // Swap 6 tokens into the DEFI5 pool
    // DEFI5Pool.swapExactAmountIn(UNI, uniAmount, DEFI5, 0, maxPrice)
    // DEFI5Pool.swapExactAmountIn(AAVE, aaveAmount, DEFI5, 0, maxPrice)
    // ... (COMP, CRV, MKR, SNX)

    // Mass-mint DEFI5 at distorted price
    // DEFI5Pool.joinswapExternAmountIn(token, amount, minPoolAmountOut)

    // Repeat with additional SUSHI flash loan
    // DEFI5Pool.exitswapPoolAmountIn(...)

    // Repayment
    // Return each Uniswap pair amount with fee
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `swapExactAmountIn()` MAX_IN_RATIO=50% during re-indexing — single swap can distort pool internal price by up to 2x | CRITICAL | CWE-829 |
| V-02 | `joinswapExternAmountIn()` lacks slippage protection — enables mass low-cost minting of index tokens at distorted internal price | CRITICAL | CWE-20 |

> **Root Cause**: The combination of MAX_IN_RATIO 50% and absence of joinswap slippage protection enables internal price distortion followed by low-cost minting. Flash loans are merely the funding mechanism; the core fixes are reducing MAX_IN_RATIO to 5% or below and disabling external swaps during re-indexing.

---
## 6. Remediation Recommendations

```solidity
// ✅ Set MAX_IN_RATIO to 5% or below
// ✅ Disable external swaps during re-indexing
// ✅ Introduce price oracle (Uniswap V2 TWAP)

uint256 public constant MAX_IN_RATIO = 5 * 10**16; // 5%

function startReindex() external onlyController {
    reindexing = true;
    // Disable swapExactAmountIn during re-indexing
    emit ReindexStarted();
}

function finishReindex() external onlyController {
    reindexing = false;
    emit ReindexFinished();
}
```

---
## 7. Lessons Learned

- **MAX_IN_RATIO 50% and unprotected joinswap slippage are the root causes of this attack.** Fixing both parameters makes the attack impossible even without flash loans.
- **Flash loans are simply a mechanism to concentrate large capital in a single transaction.** Reducing MAX_IN_RATIO to 5% limits the magnitude of price distortion even when flash loans are used.
- **External swaps must be disabled during re-indexing.** The rebalancing process itself must be designed so it cannot become an attack vector.