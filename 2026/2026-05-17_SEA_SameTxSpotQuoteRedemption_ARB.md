# SEA — Same-Tx Spot Quote Redemption Analysis

| Item | Details |
|------|------|
| **Date** | 2026-05-17 17:19:35 UTC (Arbitrum block 463,840,994) |
| **Protocol** | SEA (Arbitrum) |
| **Chain** | Arbitrum One |
| **Loss** | **~$153K** (estimated; multiple flagged txs) |
| **Attack Tx** | [0x001cb16e...716](https://arbiscan.io/tx/0x001cb16e17c4c5a5c4d02423c9e9b2f2b11ab6b2a1baf2ba53b8fcaf06167716) |
| **Attack Block** | 463,840,994 |
| **Attacker EOA** | `0x352173FAbF0E67E1cB1fcdF15474D0477D5D3674` |
| **Target Contract** | `0x7B1dE577DA005A58565D6D1fBAd286fDF2f269B7` |
| **Entry Selector** | `0x93a66b22` |
| **SEA/USDT Pair** | [0xeeb9c6b7...0513](https://arbiscan.io/address/0xeeb9c6b73a9ba397fbea320d9e4cce7b8ac10513) |
| **Log Count** | 862 (Transfer: 424, Sync: 60, Swap: 60) |
| **Root Cause** | SEA redemption/burn mechanism reads the SEA/USDT AMM spot quote within the same transaction. Attacker executes 60 swaps on the pair to inflate the spot SEA price, then burns SEA tokens at the inflated rate to redeem USDT from the protocol treasury, extracting ~$153K profit. |
| **Deep Dive** | [Full analysis](../../incidents/2026/sea-arbitrum-same-tx-spot-quote-redemption-deep-dive.md) |

---

## 1. Vulnerability Overview

SEA is a DeFi protocol on Arbitrum One with a treasury redemption mechanism. Its `redeemPosition` function (or an equivalent position-to-cash redemption path) determines the payout amount by reading the current spot price from the SEA/USDT AMM pair at `0xeeb9c6b73a9ba397fbea320d9e4cce7b8ac10513`.

Because AMM spot prices are freely manipulable within a single transaction via flash loans and swaps, the redemption function is vulnerable to a classic same-tx oracle attack:

1. Attacker acquires a SEA position (or a right-to-redeem instrument).
2. In a single transaction: executes **60 swap operations** on the SEA/USDT pair to inflate the apparent SEA/USDT exchange rate.
3. Calls `redeemPosition` — the function reads the manipulated spot quote and pays out treasury assets at the inflated rate.
4. Repays the flash loan; pockets the spread.

The 60 Sync + 60 Swap log events (out of 862 total) directly evidence the repeated price manipulation. At 12–13 Sync/Swap events per manipulated state change, 60 swap iterations are consistent with V2-style `getReserves()` oracle manipulation where large single-step price movement causes excessive slippage, so the attacker staggers the manipulation across many smaller swaps.

---

## 2. Vulnerable Code Analysis

### 2.1 Spot Oracle Feeding `redeemPosition` — Reconstructed Vulnerable Pattern

```solidity
// ❌ Vulnerable redemption pricing (reconstructed from on-chain behavior)
function redeemPosition(uint256 positionId, uint256 seaAmount) external {
    require(positions[positionId].owner == msg.sender, "Not owner");

    // ❌ Reads AMM spot quote — same-tx manipulable
    uint256 seaPerUsdt = _getSpotPrice(SEA_USDT_PAIR); // pair.getReserves() based

    // ❌ Payout calculated at attacker-controlled price
    uint256 usdtOut = seaAmount * seaPerUsdt / 1e18;

    positions[positionId].amount -= seaAmount;
    treasury.transfer(msg.sender, usdtOut); // over-pays
}

function _getSpotPrice(address pair) internal view returns (uint256) {
    // ❌ Uniswap V2-style — 60 sequential swaps move this price incrementally
    (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pair).getReserves();
    return (uint256(reserve1) * 1e18) / uint256(reserve0);
}
```

### 2.2 Why 60 Swaps?

Unlike Uniswap V3 where a single concentrated-liquidity swap can move `slot0.sqrtPriceX96` significantly, a Uniswap V2-style pool has constant-product (`x × y = k`) pricing. A single large swap at the pool's liquidity depth incurs severe slippage, reducing manipulation efficiency. The attacker staggers the manipulation across 60 smaller swaps to:

- Keep individual swap costs (slippage loss per swap) low
- Cumulatively shift the `reserve0/reserve1` ratio enough to produce the desired spot price

Each swap emits exactly one `Swap` and one `Sync` event, explaining the 60+60 pattern.

### 2.3 Fixed Pattern

```solidity
// ✅ TWAP-based pricing — 60 in-tx swaps cannot move a 30-minute TWAP
function _getOraclePrice(address pair) internal view returns (uint256) {
    // Uniswap V2 TWAP via cumulative price accumulators
    (uint256 price0Cumulative, uint256 price1Cumulative, uint32 blockTimestamp)
        = UniswapV2OracleLibrary.currentCumulativePrices(pair);

    uint32 timeElapsed = blockTimestamp - priceSnapshot.timestamp;
    require(timeElapsed >= MIN_TWAP_PERIOD, "TWAP period too short");

    uint256 price0Average = FixedPoint.fraction(
        price0Cumulative - priceSnapshot.price0Cumulative,
        timeElapsed
    ).decode144();
    return price0Average;
}
```

---

## 3. Attack Flow

**[1] Acquire Position / Flash Loan**
Attacker holds a SEA position or acquires one via flash loan to satisfy `redeemPosition`'s input requirement.

**[2] 60× Swap on SEA/USDT Pair (0xeeb9c6b7…)**
Within the same transaction, execute 60 sequential swaps on the pair:
- Each swap moves the reserves incrementally
- Each swap emits 1 `Swap` + 1 `Sync` (→ 60+60 in the log)
- Net effect: `reserve1(USDT)` depleted, `reserve0(SEA)` inflated → `SEA price in USDT` increases

**[3] `redeemPosition()` Call**
With spot price now elevated:
- `_getSpotPrice()` returns inflated `seaPerUsdt`
- `usdtOut = seaAmount × inflatedPrice` → treasury over-pays USDT

**[4] Flash Loan / Swap Unwind**
Reverse the 60 swap positions (implicit unwind during flash repayment). Net profit = inflated payout − flash loan cost − swap fees × 60.

**[5] Log Composition**
424 Transfer events = flash loan (×2) + 60 swap internal transfers (×2 directions, ~120) + seaAmount burn transfers + usdtOut treasury transfer + fee accruals + profit routing.

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Category |
|----|---------------|----------|-----|----------|
| V-01 | Treasury redemption uses same-tx manipulable AMM spot quote | CRITICAL | CWE-704 | oracle-manipulation |
| V-02 | 60-swap staggered manipulation bypasses single-swap slippage limits | CRITICAL | CWE-682 | flash-loan |
| V-03 | No TWAP / manipulation-resistant oracle in redemption path | HIGH | CWE-20 | business-logic |

### Similar Incidents

| Incident | Loss | Pattern | Difference |
|----------|------|---------|------------|
| SEAMAN / SEAMAN Token (2022) | Undisclosed | Fee-reserve desync via LP manipulation | Different mechanism; no redemption oracle |
| Inverse Finance (2022-04) | ~$15.6M | Curve price oracle manipulation | Multi-tx attack; SEA is single-tx |
| Makina (2026-01) | Undisclosed | Price oracle manipulation | Direct oracle; SEA uses AMM spot |
| **SEA Arbitrum (2026-05)** | TBD | **60× same-tx AMM swap → spot oracle → treasury drain** | Single-tx, staggered manipulation |

---

## 5. Remediation

### Immediate

Replace `_getSpotPrice()` (V2 `getReserves()` or V3 `slot0`) with a TWAP oracle in all treasury-facing functions:

```solidity
// Minimum: 30-minute TWAP
// Even a 60-swap same-tx manipulation cannot move a 30-min TWAP by more than a few basis points
require(timeElapsed >= 1800, "TWAP window too short");
```

### Structural

| Issue | Fix |
|-------|-----|
| V2 spot oracle in redemption | TWAP via price accumulators or a separate oracle contract |
| Single-tx manipulation possible | Redemption cooldown (min N blocks between consecutive redeems per address) |
| No per-tx redemption cap | Cap single-tx redemption at X% of treasury balance |
| No monitoring | Alert on: single tx with ≥5 swaps on SEA pair + treasury withdrawal |

---

## 6. References

- [Attack Tx (Arbiscan)](https://arbiscan.io/tx/0x001cb16e17c4c5a5c4d02423c9e9b2f2b11ab6b2a1baf2ba53b8fcaf06167716)
- [SEA/USDT Pair (Arbiscan)](https://arbiscan.io/address/0xeeb9c6b73a9ba397fbea320d9e4cce7b8ac10513)
- [Deep Dive](../../incidents/2026/sea-arbitrum-same-tx-spot-quote-redemption-deep-dive.md)
- [SEAMAN Token (2022)](../2022/2022-11_SEAMAN_FlashLoanPriceManipulation.md)
- CWE-704, CWE-682, CWE-20
