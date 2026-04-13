# 0VIX Protocol — Flash Loan Oracle Manipulation Liquidation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-22 |
| **Protocol** | 0VIX Protocol |
| **Chain** | Polygon / zkEVM |
| **Loss** | ~2M USD |
| **Attacker** | Unknown |
| **Attack Tx** | Polygon Transaction |
| **Vulnerable Contract** | 0VIX Lending Contract |
| **Root Cause** | vGHST token price relied directly on Quickswap getReserves() spot price without TWAP, enabling manipulation within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/0vix_exp.sol) |

---
## 1. Vulnerability Overview

0VIX is a Compound fork lending protocol on Polygon. It accepts vGHST tokens as collateral, and its price oracle relies on the spot price from Quickswap AMM. The attacker borrowed a large amount of GHST tokens via flash loan to manipulate the Quickswap pool price, artificially inflating the vGHST collateral value, then borrowed large quantities of other assets and absconded.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable vGHST price oracle (Quickswap spot-based)
function getUnderlyingPrice(address cToken) external view returns (uint256) {
    if (cToken == address(vGHST)) {
        // ❌ Calculates GHST price from Quickswap current reserves
        (uint112 r0, uint112 r1,) = quickswapGHSTWMATIC.getReserves();
        uint256 ghstPrice = uint256(r1) * 1e18 / uint256(r0);
        return ghstPrice;  // Manipulable via flash loan
    }
}

// ✅ Fix: Combined Chainlink + TWAP usage
function getUnderlyingPrice(address cToken) external view returns (uint256) {
    if (cToken == address(vGHST)) {
        (, int256 price,,,) = chainlinkGHST.latestRoundData();
        return uint256(price) * 1e10;  // Use Chainlink price
    }
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: vGHST token price relied directly on Quickswap getReserves() spot price without TWAP, enabling manipulation within a single block
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Aave Flash Loan (borrow large amount of MATIC/GHST)
  │
  ├─2─▶ Buy large amount of GHST on Quickswap
  │       GHST price spikes → vGHST collateral value inflates
  │
  ├─3─▶ Borrow large amount of USDC/USDT on 0VIX using vGHST as collateral
  │       Borrows more than actual collateral value using manipulated high price
  │
  ├─4─▶ Sell GHST on Quickswap (price reverts)
  │
  ├─5─▶ Repay Aave flash loan
  │       → Borrowed USDC/USDT becomes net profit
  │
  └─6─▶ ~2M USD drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function receiveFlashLoan(/* Aave callback */) external {
    // 1. Buy large amount of GHST → manipulate Quickswap price
    swapMATICtoGHST(largeAmount);

    // 2. Deposit vGHST as collateral on 0VIX
    vGHST.approve(address(ovixMarket), type(uint256).max);
    ovixMarket.mint(vGHSTAmount);  // Deposit collateral

    // 3. Borrow against manipulated high price
    ovixMarket.borrow(address(USDC), borrowAmount);

    // 4. Sell GHST to revert price
    swapGHSTtoMATIC(ghstBalance);

    // 5. Repay Aave (principal only; borrowed USDC is profit)
    repayAave(flashAmount);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Vector** | Flash Loan + Quickswap Spot Price |
| **Impact Scope** | Entire 0VIX lending pool |
| **DASP Classification** | Oracle Manipulation |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |

## 6. Remediation Recommendations

1. **Use Chainlink Oracle**: Eliminate all reliance on AMM spot prices.
2. **Minimum TWAP Duration**: Accept only TWAP of 30 minutes or longer.
3. **Additional Collateral Validation**: Tokens susceptible to manipulation like vGHST should be removed from the collateral whitelist or subjected to special controls.

## 7. Lessons Learned

- Compound forks are repeatedly exposed to the same attack pattern when collateral oracle design is flawed.
- Small AMM-based oracles in the Polygon ecosystem are especially vulnerable.
- When adding new collateral types, always calculate the potential profit from oracle manipulation relative to the cost of the attack.