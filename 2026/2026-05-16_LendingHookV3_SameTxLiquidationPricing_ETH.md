# LendingHookV3 — Same-Tx Liquidation Pricing Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2026-05-16 12:54:35 UTC (block 25,107,861) |
| **Protocol** | LendingHookV3 (Uniswap V4 hook-based lending) |
| **Chain** | Ethereum Mainnet |
| **Loss** | Small (2.2 WETH flash loan + sato token collateral differential; exact profit not disclosed) |
| **Attack Tx** | [0xec9c1a3c...e79](https://etherscan.io/tx/0xec9c1a3c5a26ca035954583e3d589240ed30139a8b8c6d6194a33b3efcd15e79) |
| **Attack Block** | 25,107,861 |
| **Attacker EOA** | `0x62c81a4f66fC9ef8215b6C06F3e3710dE1A6Ea49` |
| **Hook Contract** | `0x356D439f9788f4b247601064D3A5C296CEd2400C` (Uniswap V4 Hook; interacts with Pool Manager `0x000000000004444c5dc75cb358380d2e3de08a90`) |
| **Victim Position** | `0xc74147999890AE1be8F0b1d85D3c70d30b397082` (6,035.25 sato tokens liquidated) |
| **Entry Selector** | `0x90b33475` (liquidation entry point, confirmed on-chain) |
| **Log Count** | 23 |
| **Flash Loan** | 2.2 WETH via Aave V3 |
| **Root Cause** | Liquidation pricing in the Uniswap V4 hook reads a same-tx manipulable sato token spot price from two V4 pools. Attacker borrowed 2.2 WETH via Aave V3, swapped 5,300 sato tokens across both pools to move the price, then liquidated 6,035.25 sato tokens from the victim position at the distorted price. |
| **Deep Dive** | [Full analysis](../../incidents/2026/lendinghookv3-same-tx-liquidation-pricing-deep-dive.md) |

---

## 1. Vulnerability Overview

LendingHookV3 is a lending/hook-based protocol on Ethereum that supports WETH and related token collateral. Its liquidation path contains a critical pricing flaw: the collateral valuation used inside `liquidate()` (or an equivalent entry point) is derived from a spot price source that can be manipulated within the same transaction.

When a liquidator repays a borrower's debt and claims their collateral, the protocol calculates how much collateral to seize based on:

```
collateralToSeize = debtRepaid × LIQUIDATION_BONUS / collateralPrice
```

If `collateralPrice` is sourced from a same-block-manipulable value (e.g., `pair.getReserves()`, Uniswap V3 `slot0.sqrtPriceX96`, or a similar on-chain spot reference), an attacker can:

1. **Depress `collateralPrice`** via a flash swap before calling `liquidate()`, causing `collateralToSeize` to balloon proportionally.
2. **Call `liquidate()` within the same tx** while the manipulated price is active.
3. **Receive excess collateral**, repay the flash loan, and pocket the difference.

The 23 log entries in the attack transaction are consistent with a targeted, single-position liquidation requiring minimal price manipulation — unlike larger oracle attacks that need dozens of swap events. This suggests either a Uniswap V3 `slot0`-based oracle (single swap sufficient) or a self-liquidation pattern where the attacker owns the target position.

---

## 2. Vulnerable Code Analysis

### 2.1 Liquidation Pricing — Reconstructed Vulnerable Pattern

The entry selector `0x90b33475` identifies the liquidation function. Based on the on-chain behavior (23 logs, WETH collateral, single-tx attack), the vulnerable logic is estimated as:

```solidity
// ❌ Vulnerable liquidation pricing (reconstructed)
function liquidate(
    address borrower,
    address collateralToken,
    uint256 debtAmount
) external {
    require(_isLiquidatable(borrower), "Position healthy");

    // ❌ Spot price from AMM — same-tx manipulable
    uint256 collateralPrice = _getSpotPrice(collateralToken);

    // ❌ Price depression → collateralToSeize inflates inversely
    uint256 collateralToSeize = (debtAmount * LIQUIDATION_BONUS) / collateralPrice;

    debtToken.transferFrom(msg.sender, address(this), debtAmount);
    collateralToken.transfer(msg.sender, collateralToSeize); // excess seizure
}

function _getSpotPrice(address token) internal view returns (uint256) {
    // ❌ Uniswap V3 slot0 or V2 getReserves — manipulable in same block
    (uint160 sqrtPriceX96,,,,,,) = IUniswapV3Pool(pool).slot0();
    return _sqrtPriceToPrice(sqrtPriceX96);
}
```

**Why 23 logs and not hundreds?**

Uniswap V3 `slot0.sqrtPriceX96` can be moved sufficiently with a single large swap — unlike V2 `getReserves()` which may require repeated smaller swaps (as seen in the SEA/Arbitrum attack's 60-swap pattern). A single swap event + liquidation call + flash loan repayment fits within ~23 log entries.

### 2.2 Fixed Pattern

```solidity
// ✅ TWAP-based pricing — manipulation resistant
function _getOraclePrice(address token) internal view returns (uint256) {
    uint32[] memory secondsAgo = new uint32[](2);
    secondsAgo[0] = 1800; // 30-minute TWAP
    secondsAgo[1] = 0;
    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgo);
    int56 avgTick = (tickCumulatives[1] - tickCumulatives[0]) / 1800;
    return TickMath.getSqrtRatioAtTick(int24(avgTick));
}

// ✅ Or: Chainlink with staleness check
function _getOraclePrice(address token) internal view returns (uint256) {
    (, int256 price,, uint256 updatedAt,) =
        AggregatorV3Interface(priceFeeds[token]).latestRoundData();
    require(block.timestamp - updatedAt <= MAX_STALENESS, "Stale price");
    require(price > 0, "Invalid price");
    return uint256(price);
}
```

---

## 3. Attack Flow

**[1] Setup**
Flash loan WETH or debt token from a lending protocol or Uniswap V3 flash swap.

**[2] Price Manipulation (same tx)**
Swap into the collateral pool to depress `collateralPrice`:
- e.g., sell large amount of `collateralToken` → pool price drops
- Single large swap sufficient if Uniswap V3 `slot0` is the oracle

**[3] Liquidation (selector `0x90b33475`)**
Call `liquidate(borrower, collateralToken, debtAmount)`:
- `_isLiquidatable` check: passes (LTV exceeded due to depressed price)
- `collateralToSeize` computed at manipulated (depressed) price → value inflated
- `collateralToken.transfer(attacker, inflatedAmount)` executed

**[4] Unwind**
Repay flash loan. Net profit = seized collateral market value − debt repaid − flash loan fee.

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Category |
|----|---------------|----------|-----|----------|
| V-01 | Liquidation oracle uses same-tx manipulable spot price | CRITICAL | CWE-704 | oracle-manipulation |
| V-02 | Flash loan + single swap enables full liquidation price distortion | CRITICAL | CWE-682 | flash-loan, liquidation |
| V-03 | No self-liquidation guard (`msg.sender == borrower` allowed) | HIGH | CWE-20 | business-logic |

### Similar Incidents

| Incident | Loss | Difference |
|----------|------|------------|
| AlkemiEarn (2026-03-10) | Undisclosed | Self-liquidation without price manipulation; LendingHookV3 adds oracle distortion |
| Makina (2026-01-20) | Undisclosed | Direct oracle manipulation; LendingHookV3 manipulates within liquidation path |
| PloutosMarket (2026-02-26) | Undisclosed | Wrong oracle type; LendingHookV3 uses correct-type oracle but lacks manipulation resistance |

---

## 5. Remediation

### Immediate

Replace all spot price reads in the liquidation path with TWAP or Chainlink:

```solidity
// Replace _getSpotPrice() call in liquidate() with:
uint256 collateralPrice = _getTWAPPrice(collateralToken); // 30-min minimum
```

### Structural

| Issue | Fix |
|-------|-----|
| Spot oracle in liquidation | TWAP (≥30 min) or Chainlink with staleness guard |
| Self-liquidation possible | `require(msg.sender != borrower, "No self-liquidation")` |
| No seizure cap | Add `maxCollateralSeizable` param and enforce it |
| No circuit breaker | Cap single-tx liquidation value (e.g., 5% of total pool TVL) |

---

## 6. References

- [Attack Tx](https://etherscan.io/tx/0xec9c1a3c5a26ca035954583e3d589240ed30139a8b8c6d6194a33b3efcd15e79)
- [AlkemiEarn Self Liquidation (2026)](./2026-03-10_AlkemiEarn_Self_Liquidation.md)
- [Makina PriceOracleManipulation (2026)](./2026-01-20_Makina_PriceOracleManipulation.md)
- [Deep Dive](../../incidents/2026/lendinghookv3-same-tx-liquidation-pricing-deep-dive.md)
- CWE-704, CWE-682, CWE-20
