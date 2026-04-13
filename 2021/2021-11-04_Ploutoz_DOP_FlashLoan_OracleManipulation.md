# Ploutoz (DOP) — Flash Loan DOP Price Manipulation Collateral Lending Analysis

| Field | Details |
|------|------|
| **Date** | 2021-11-04 |
| **Protocol** | Ploutoz (DOP Token) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$365,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | [0x844FA82f1E54824655470970F7004Dd90546bB28](https://bscscan.com/address/0x844FA82f1E54824655470970F7004Dd90546bB28) (DOP Token) |
| **Root Cause** | AMM spot price from Twinidex/PancakeSwap used for DOP collateral valuation — manipulable within a single block via large swaps |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-11/Ploutoz_exp.sol) |

---
## 1. Vulnerability Overview

The Ploutoz protocol's lending pool allows users to borrow various tokens using DOP tokens as collateral. The DOP price oracle referenced the current (spot) price from Twinidex and PancakeSwap. The attacker flash loaned 1,000,400 BUSD from PancakeSwap, artificially inflated the DOP price via large swaps on both DEXes, then used the inflated DOP as collateral to borrow various tokens from 6 lending pools, realizing a profit.

---
## 2. Vulnerable Code Analysis

### 2.1 Lending Pool Price Oracle — Direct Use of DOP Spot Price

```solidity
// ❌ Ploutoz lending pool — collateral value calculated using DOP spot price
// DOP @ 0x844FA82f1E54824655470970F7004Dd90546bB28

function getDOPPrice() internal view returns (uint256) {
    // Price calculated from current reserves on Twinidex or PancakeSwap
    // Manipulable via large swaps within a flash loan
    (uint112 reserve0, uint112 reserve1,) = IDEXPair(dopPair).getReserves();
    return uint256(reserve1) * 1e18 / uint256(reserve0); // spot price
}

function borrow(address token, uint256 amount) external {
    uint256 dopBalance = IERC20(DOP).balanceOf(msg.sender);
    uint256 dopPrice = getDOPPrice(); // manipulated price
    uint256 collateralValue = dopBalance * dopPrice / 1e18;
    require(collateralValue >= amount, "insufficient collateral");
    IERC20(token).transfer(msg.sender, amount);
}
```

**Fixed Code**:
```solidity
// ✅ Use Chainlink oracle or TWAP
interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}

AggregatorV3Interface public dopOracle; // Chainlink DOP/USD

function getDOPPrice() internal view returns (uint256) {
    (, int256 price,, uint256 updatedAt,) = dopOracle.latestRoundData();
    require(block.timestamp - updatedAt <= 3600, "Oracle: stale price");
    require(price > 0, "Oracle: invalid price");
    return uint256(price) * 1e10; // 8 decimals → 18 decimals
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**DOP Token_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: AMM spot price from Twinidex/PancakeSwap used for DOP collateral valuation — manipulable within a single block via large swaps
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────────────┐
│ Step 1: Flash loan 1,000,400 BUSD from PancakeSwap     │
│ pancakeCall() callback executed                        │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 2: Large BUSD → DOP swap on Twinidex              │
│ DOP price rises (Twinidex reserve manipulation)        │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 3: Additional BUSD → DOP swap on PancakeSwap      │
│ DOP price rises further (PancakeSwap reserve manip.)   │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 4: Borrow from 6 pools using inflated DOP collat. │
│ Maximum available tokens borrowed from each pool       │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 5: Convert borrowed tokens → BUSD + repay loan    │
│ ~$365K profit realized                                 │
└────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// pancakeCall() — flash loan callback
function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // Large BUSD → DOP swap on Twinidex (price increase)
    // twinidexRouter.swapExactTokensForTokens(busd, 0, [BUSD, DOP], ...)

    // Additional BUSD → DOP swap on PancakeSwap
    // pancakeRouter.swapExactTokensForTokens(busd, 0, [BUSD, DOP], ...)

    // Borrow tokens from 6 lending pools (inflated DOP collateral)
    // lendingPool1.borrow(token1, maxAmount)
    // lendingPool2.borrow(token2, maxAmount)
    // ... (6 pools)

    // Convert borrowed assets → BUSD
    // Repay flash loan principal + fee
    // BUSD.transfer(pair, 1_000_400 * 1e18 * 10030 / 10000)
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | AMM spot price from Twinidex/PancakeSwap used for collateral valuation — manipulable within a single block via large swaps | CRITICAL | CWE-829 |

> **Root Cause**: The lending pool values DOP collateral using AMM spot prices. Flash loans are merely a funding mechanism; replacing the oracle with Chainlink or TWAP is the only true fix. "Single DEX spot price" is a restatement of the same root cause as V-01 and should be removed.

---
## 6. Remediation Recommendations

```solidity
// ✅ Use averaged multiple oracles + TWAP
// ✅ Set price deviation threshold within a single transaction

function getDOPPrice() internal view returns (uint256) {
    uint256 twapPrice = getTWAP(dopPair, 1800); // 30-minute TWAP
    uint256 chainlinkPrice = getChainlinkPrice();

    // If deviation between two prices exceeds 5%, use the lower price
    if (absDiff(twapPrice, chainlinkPrice) * 100 / twapPrice > 5) {
        return twapPrice < chainlinkPrice ? twapPrice : chainlinkPrice;
    }
    return (twapPrice + chainlinkPrice) / 2;
}
```

---
## 7. Lessons Learned

- **Using AMM spot price as an oracle is the root cause.** Replacing it with Chainlink or TWAP blocks the attack regardless of whether a flash loan is used.
- **Flash loans are merely a funding mechanism.** Averaging spot prices across multiple DEXes still allows simultaneous manipulation, making TWAP/Chainlink the only true solution.
- **This pattern is identical to the $130M Cream Finance second attack.** Regardless of scale, using AMM spot prices as a collateral oracle is always vulnerable.