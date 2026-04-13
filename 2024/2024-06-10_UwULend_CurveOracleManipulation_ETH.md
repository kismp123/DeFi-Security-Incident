# UwU Lend — Curve Pool-Based Oracle Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2024-06-10 |
| **Protocol** | UwU Lend (Aave v2 Fork) |
| **Chain** | Ethereum |
| **Loss** | $23,000,000 (3 consecutive attacks) |
| **Attacker** | [0x841d...1f47](https://etherscan.io/address/0x841dDf093f5188989fA1524e7B893de64B421f47) |
| **Attack Contract (1st)** | [0x21C5...312E](https://etherscan.io/address/0x21C58d8F816578b1193AEf4683E8c64405A4312E) |
| **Attack Contract (2nd)** | [0x4e48...3D](https://etherscan.io/address/0x4e48C46779b3B16d63375751467D7eee34D41c3D) |
| **Attack Contract (3rd)** | [0x13F3...890](https://etherscan.io/address/0x13F3fee69160162a78284c64c1100a3dF476D890) |
| **Attack Tx (1st)** | [0x242a...408b](https://etherscan.io/tx/0x242a0fb4fde9de0dc2fd42e8db743cbc197ffa2bf6a036ba0bba303df296408b) |
| **Attack Tx (2nd)** | [0xb3f0...376](https://etherscan.io/tx/0xb3f067618ce54bc26a960b660cfc28f9ea0315e2e9a1a855ede1508eb4017376) |
| **Attack Tx (3rd)** | [0xca1b...2850](https://etherscan.io/tx/0xca1bbf3b320662c89232006f1ec6624b56242850f07e0f1dadbe4f69ba0d6ac3) |
| **Vulnerable Contract (Oracle)** | [0xd252...2e8](https://etherscan.io/address/0xd252953818bdf8507643c237877020398fa4b2e8) — sUSDePriceProviderBUniCatch |
| **UwU Lending Pool** | [0xed15...ec](https://etherscan.io/address/0xed1521ee1558af6087ad6bc6790ba1ee2a4174ec) |
| **Root Cause** | The spot price (`get_p()`) of the Curve sUSDE pool was used directly in the oracle median calculation, making it manipulable via flash loans |
| **PoC Source** | No DeFiHackLabs PoC — direct on-chain analysis |

---

## 1. Vulnerability Overview

UwU Lend is a DeFi lending protocol forked from Aave v2. The oracle contract `sUSDePriceProviderBUniCatch`, which determines the price of the sUSDE (Ethena staked USDe) collateral asset, used Curve Finance's **spot price function `get_p()`** as one of its 5 price sources.

The official Curve Finance documentation explicitly warns that `get_p()` returns an **instantaneous spot price** and is therefore manipulable via a large swap within a single transaction when used for oracle purposes. Despite this warning, the oracle collected two prices from each of the 5 Curve pools — an EMA (Exponential Moving Average) price and a spot price — constructing a total array of 11 prices, using the median as the sUSDE price.

The attacker sourced large funds via flash loans, then executed massive swaps across Curve pools to simultaneously manipulate all 5 spot price (`get_p()`) values. This shifted the median of the 11-price array, artificially inflating the sUSDE collateral value, allowing the attacker to over-borrow from UwU Lend against the inflated collateral. The attack was repeated 3 times for a total loss of $23,000,000.

---

## 2. Vulnerable Code Analysis

### 2.1 `getPrice()` — Median Calculation Including Spot Prices (Core Vulnerability)

**Vulnerable code** (`0xd252...2e8`, sUSDePriceProviderBUniCatch):

```solidity
// ❌ Vulnerability: get_p() is a spot price manipulable instantly via flash loan
function getPrice() external view override returns (uint256) {
    (uint256[] memory prices, bool uniFail) = _getPrices(true); // sorted array of 11 prices

    // ❌ Median = prices[5] (6th of indices 0~10)
    // 5 spot prices based on get_p() are included, making it manipulable
    uint256 median = uniFail ? (prices[5] + prices[6]) / 2 : prices[5];

    require(median > 0, 'Median is zero');

    // sUSDeScalingFactor = 1047 → median * 1.047 = final price
    return FullMath.mulDiv(median, sUSDeScalingFactor, 1e3);
}

function _getPrices(bool sorted) internal view returns (uint256[] memory, bool uniFail) {
    uint256[] memory prices = new uint256[](11);
    // Collect two prices per pool: EMA (price_oracle) + spot (get_p)
    (prices[0], prices[1]) = _getUSDeFraxEMAInUSD();   // prices[1] = get_p() ❌
    (prices[2], prices[3]) = _getUSDeUsdcEMAInUSD();   // prices[3] = get_p() ❌
    (prices[4], prices[5]) = _getUSDeDaiEMAInUSD();    // prices[5] = get_p() ❌
    (prices[6], prices[7]) = _getCrvUsdUSDeEMAInUSD(); // prices[7] = get_p() ❌
    (prices[8], prices[9]) = _getUSDeGhoEMAInUSD();    // prices[9] = get_p() ❌
    try UNI_V3_TWAP_USDT_ORACLE.getPrice() returns (uint256 price) {
        prices[10] = price; // Uniswap V3 TWAP (only safe source)
    } catch {
        uniFail = true;
    }
    if (sorted) { _bubbleSort(prices); }
    return (prices, uniFail);
}

// ❌ Direct reference to spot price (get_p) — manipulable
function _getUSDeFraxEMAInUSD() internal view returns (uint256, uint256) {
    uint256 price = uwuOracle.getAssetPrice(FRAX);
    return (
        FullMath.mulDiv(FRAX_POOL.price_oracle(0), price, 1e18), // EMA (safe)
        FullMath.mulDiv(FRAX_POOL.get_p(0), price, 1e18)         // ❌ Spot (manipulable)
    );
}
// _getUSDeUsdcEMAInUSD, _getUSDeDaiEMAInUSD, _getCrvUsdUSDeEMAInUSD, _getUSDeGhoEMAInUSD follow the same pattern
```

**Fixed code**:

```solidity
// ✅ get_p() fully removed — EMA (price_oracle) only
function _getPrices(bool sorted) internal view returns (uint256[] memory, bool uniFail) {
    uint256[] memory prices = new uint256[](6); // ✅ 5 EMA + 1 TWAP
    prices[0] = _getUSDeFraxEMAInUSD();
    prices[1] = _getUSDeUsdcEMAInUSD();
    prices[2] = _getUSDeDaiEMAInUSD();
    prices[3] = _getCrvUsdUSDeEMAInUSD();
    prices[4] = _getUSDeGhoEMAInUSD();
    try UNI_V3_TWAP_USDT_ORACLE.getPrice() returns (uint256 price) {
        prices[5] = price;
    } catch {
        uniFail = true;
    }
    if (sorted) { _bubbleSort(prices); }
    return (prices, uniFail);
}

// ✅ Returns EMA only (single value)
function _getUSDeFraxEMAInUSD() internal view returns (uint256) {
    uint256 price = uwuOracle.getAssetPrice(FRAX);
    return FullMath.mulDiv(FRAX_POOL.price_oracle(0), price, 1e18); // ✅ EMA only
}
```

**Summary of the issue**: The oracle composed 5 of its 11 prices using Curve AMM spot prices (`get_p()`). Executing large swaps across those pools via flash loan allows all 5 spot prices to be manipulated simultaneously within a single transaction. With 5 of 11 values manipulated, the median (index 5) shifts, causing the sUSDE price to be artificially inflated or deflated.

---

## 3. Attack Flow

### 3.1 Preparation

- Attacker EOA `0x841d...1f47` sourced a small amount of ETH (0.98 ETH + 5 additional transfers) from **Tornado Cash** to cover gas fees
- A new attack contract was deployed for each attack (as a contract creation transaction)
- Attacks were executed at blocks 20061319, 20061322, and 20061352 respectively

### 3.2 Execution Steps (per single attack)

```
Step 1: Flash Loan Acquisition
   ┌─────────────────────────────────────────────────────────────────┐
   │  Attacker contract requests simultaneous flash loans            │
   │  from multiple protocols                                        │
   │  Total: ~$3.796B in assets                                      │
   │  • AAVE V3 / AAVE V2 / Balancer / Maker                        │
   │  • Spark / Morpho / Uniswap V3                                  │
   │  (~40,000 ETH equivalent)                                       │
   └──────────────────────────────┬──────────────────────────────────┘
                                  │
                                  ▼
Step 2: Curve Pool Spot Price Manipulation
   ┌─────────────────────────────────────────────────────────────────┐
   │  Execute large swaps across 5 Curve pools using                 │
   │  a portion of the borrowed funds                                │
   │  (USDe/FRAX, USDe/USDC, USDe/crvUSD, USDe/DAI, GHO/USDe)      │
   │                                                                 │
   │  Pre-attack get_p() values:                                     │
   │    FRAXUSDe: 1.0027  USDe-USDC: 0.9994  USDe-crvUSD: 0.9977   │
   │    USDe/DAI: 0.9994  GHOUSDe: 1.0020                           │
   │                                                                 │
   │  After mass swaps: get_p() values across 5 pools are            │
   │  manipulated                                                    │
   │  → sUSDE oracle median rises (deflated then re-manipulated      │
   │    to ~$0.99 level)                                             │
   └──────────────────────────────┬──────────────────────────────────┘
                                  │
                                  ▼
Step 3: Oracle Read — Manipulated Price Reflected
   ┌─────────────────────────────────────────────────────────────────┐
   │  sUSDePriceProviderBUniCatch.getPrice() is called               │
   │                                                                 │
   │  _getPrices() collects 11 prices:                               │
   │    [0] EMA_FRAX  [1] get_p_FRAX  ← ❌ manipulated              │
   │    [2] EMA_USDC  [3] get_p_USDC  ← ❌ manipulated              │
   │    [4] EMA_DAI   [5] get_p_DAI   ← ❌ manipulated              │
   │    [6] EMA_CRVUSD[7] get_p_CRVUSD← ❌ manipulated              │
   │    [8] EMA_GHO   [9] get_p_GHO   ← ❌ manipulated              │
   │    [10] Uniswap TWAP (cannot be manipulated)                    │
   │                                                                 │
   │  After sorting, median = prices[5] → artificially inflated      │
   │  Final price = median × 1.047 (sUSDeScalingFactor)             │
   └──────────────────────────────┬──────────────────────────────────┘
                                  │
                                  ▼
Step 4: Over-borrowing Against Inflated Collateral
   ┌─────────────────────────────────────────────────────────────────┐
   │  Deposit sUSDE into UwU Lend LendingPool                        │
   │  (collateral value grossly overestimated by manipulated oracle) │
   │                                                                 │
   │  Borrow multiple assets against overvalued collateral:          │
   │    • WETH, WBTC, DAI, USDT, FRAX                               │
   │    • crvUSD, CRV, sDAI, bLUSD, sUSDE                           │
   └──────────────────────────────┬──────────────────────────────────┘
                                  │
                                  ▼
Step 5: Reverse Swap on Curve Pools — Price Normalization
   ┌─────────────────────────────────────────────────────────────────┐
   │  Unwind or reverse-swap the manipulation positions              │
   │  Curve pool prices return to normal levels                      │
   │  Repay flash loans (principal + fees)                           │
   └──────────────────────────────┬──────────────────────────────────┘
                                  │
                                  ▼
Step 6: Profit Extraction
   ┌─────────────────────────────────────────────────────────────────┐
   │  Borrowed assets = flash loan costs + net profit                │
   │  Proceeds laundered via Tornado Cash                            │
   │  • 1,292.98 ETH transferred to 0x48D7...EB6                    │
   │  • 4,000 ETH transferred to 0x050c...B70                       │
   └─────────────────────────────────────────────────────────────────┘
```

### 3.3 Results Across 3 Attacks

| Attack | Block | Transaction Hash | Attack Contract | Profit |
|------|------|--------------|--------------|------|
| 1st | 20061319 | 0x242a...408b | 0x21C5...312E | ~$7.2M |
| 2nd | 20061322 | 0xb3f0...376 | 0x4e48...3D | ~$7.6M |
| 3rd | 20061352 | 0xca1b...2850 | 0x13F3...890 | ~$4.5M |
| **Total** | | | | **~$19.3M** |

> Beyond these 3 attacks, the same attacker executed a second session on June 13th (an additional $3.7M), bringing the total cumulative loss to $23M.

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Curve Spot Price Oracle Manipulation | CRITICAL | CWE-682 (Incorrect Calculation) | 04_oracle_manipulation |
| V-02 | Flash Loan-Based Price Manipulation | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) | 02_flash_loan |
| V-03 | Single-Block Median Shift | HIGH | CWE-330 (Use of Insufficiently Random Values) | 04_oracle_manipulation |

### V-01: Curve Spot Price (`get_p()`) Oracle Manipulation

- **Description**: The `sUSDePriceProviderBUniCatch` oracle composed 5 of its 11 price sources using instantaneous spot prices (`get_p()`) from Curve pools. `get_p()` is an instantaneous derivative of the current AMM state and can be arbitrarily manipulated via a large swap within a single transaction. Curve's official documentation warns against using this function for oracle purposes.
- **Impact**: sUSDE collateral value is inflated, enabling uncollateralized large-scale borrowing from UwU Lend.
- **Attack Condition**: Sufficient capital to move the spot prices of 5 Curve pools significantly (obtainable via flash loans)

### V-02: Flash Loan-Based Collateral Price Inflation

- **Description**: Flash loans enable large-scale capital to be sourced at effectively zero cost for oracle manipulation. UwU Lend itself exists independently of the list of flash loan source protocols (AAVE V3/V2, Balancer, Maker, Spark, Morpho, Uniswap V3), making it technically feasible to manipulate the oracle and borrow within a flash loan callback.
- **Impact**: A small seed capital (0.98 ETH sourced from Tornado Cash) can temporarily deploy $3.796B in funds.
- **Attack Condition**: Source of funds obfuscation (e.g., Tornado Cash) + existence of flash loan-supporting protocols

### V-03: Manipulability of the 11-Source Median Design

- **Description**: 5 of 11 prices (45%) are exposed to the same attack vector (Curve spot prices). When nearly half of the sources are manipulated simultaneously, a shift in the median is a mathematical inevitability.
- **Impact**: The median-based design fails to defend against manipulation of the majority of sources.
- **Attack Condition**: Sufficient capital to move all 5 spot price sources in the same direction simultaneously

---

## 5. Remediation Recommendations

### Immediate Action

**Completely remove `get_p()` spot prices — use EMA (`price_oracle()`) exclusively**:

```solidity
// ✅ Fixed _getUSDeFraxEMAInUSD — returns single EMA value
function _getUSDeFraxEMAInUSD() internal view returns (uint256) {
    uint256 fraxPrice = uwuOracle.getAssetPrice(FRAX);
    // ✅ price_oracle() is EMA-based — cannot be manipulated by a single-block swap
    return FullMath.mulDiv(FRAX_POOL.price_oracle(0), fraxPrice, 1e18);
}

// ✅ Fixed getPrice() — uses only 6 sources: 5 EMA + 1 TWAP
function getPrice() external view override returns (uint256) {
    uint256[] memory prices = new uint256[](6);
    prices[0] = _getUSDeFraxEMAInUSD();
    prices[1] = _getUSDeUsdcEMAInUSD();
    prices[2] = _getUSDeDaiEMAInUSD();
    prices[3] = _getCrvUsdUSDeEMAInUSD();
    prices[4] = _getUSDeGhoEMAInUSD();
    prices[5] = UNI_V3_TWAP_USDT_ORACLE.getPrice();

    _bubbleSort(prices);
    uint256 median = prices[2]; // median of 6 values

    require(median > 0, 'Median is zero');
    return FullMath.mulDiv(median, sUSDeScalingFactor, 1e3);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Use of Curve spot price | Completely remove `get_p()`; use `price_oracle()` (EMA) exclusively |
| Flash loan price manipulation | Include at least one independent external oracle such as Chainlink or Chronicle |
| Single-block manipulation | Set TWAP window to a minimum of 30 minutes (Uniswap V3 TWAP) |
| Collateral spike detection | Revert transaction if collateral price rises more than N% within a single block |
| Oracle source diversity | Design so that sources exposed to the same attack vector constitute less than 1/3 of the total |
| Audit scope | Explicitly designate oracle design as a separate security review target |

---

## 6. Lessons Learned

1. **Never use Curve `get_p()` as an oracle source**: Using a function that Curve Finance's own documentation warns against as the core logic of an oracle was the direct cause. Always review the official documentation and warnings of protocol-dependent libraries.

2. **Median-based oracles are neutralized when a majority of sources are manipulated**: The median approach is effective at filtering outliers from a minority of sources, but it is meaningless when nearly half of all sources are exposed to the same attack vector. Oracle sources must guarantee independence at the attack-vector level.

3. **Flash loans turn oracle attacks into zero-cost operations**: If the collateral oracle of a lending protocol can be manipulated within a single transaction, the cost of the attack approaches zero via flash loans. Oracle manipulation prevention is the highest-priority security requirement for lending protocols.

4. **Aave v2 fork protocols must take full responsibility for their own oracle security**: Aave v2 itself uses Chainlink, but when a fork protocol supports new assets (such as sUSDE), the oracle design must be reviewed from scratch. Even if the original codebase is secure, adding new oracles creates new attack surfaces.

5. **An emergency pause mechanism is necessary to guard against consecutive attacks**: The 2nd attack was launched within 3 minutes (3 blocks) of the 1st using the same vector. Without anomaly detection and an emergency pause capability, consecutive attacks cannot be stopped.

6. **Pay attention to the pattern of attacker fund sourcing via anonymization (Tornado Cash)**: The pattern of sourcing a tiny seed amount from Tornado Cash and then operating billions of dollars via flash loans is a standard strategy among DeFi attackers. Countering this requires strong oracle security within the protocol itself, not tracking the source of funds.

---

## 7. On-Chain Verification

### 7.1 Transaction Block Confirmation (directly verified via cast)

| Attack | Transaction Hash | Block Number | From (Attacker EOA) |
|------|--------------|----------|-------------------|
| 1st | 0x242a...408b | **20061319** | 0x841d...1f47 ✅ |
| 2nd | 0xb3f0...2376 | **20061322** | 0x841d...1f47 ✅ |
| 3rd | 0xca1b...2850 | **20061352** | 0x841d...1f47 ✅ |

All 3 transactions were confirmed to have been executed as contract creation transactions (`to: null`) from the same EOA (`0x841d...1f47`).

### 7.2 Oracle Prices (Pre-Attack — Block 20061318)

| Source | Function | Queried Value |
|------|------|--------|
| `getPrice()` (sUSDE final price) | `0xd252...2e8` | **103,040,982** (~$1.030) |
| FRAXUSDe `get_p(0)` | `0x5dc1...743` | 1,002,728,108,381,191,485 (~1.0027) |
| USDe-USDC `get_p(0)` | `0x0295...d72` | 999,431,064,990,333,686 (~0.9994) |
| USDe-crvUSD `get_p(0)` | `0xF55B...442` | 997,685,493,445,829,531 (~0.9977) |
| USDe/DAI `get_p(0)` | `0xF36a...67d` | 999,398,400,576,676,195 (~0.9994) |
| GHOUSDe `get_p(0)` | `0x670a...a61` | 1,001,990,317,512,417,534 (~1.0020) |

In the normal pre-attack state, `getPrice()` = $1.030, confirming that after applying `sUSDeScalingFactor(1047)`, the result is approximately $1.03.

### 7.3 Oracle Contract Source Verification

The verified source of contract `0xd252...2e8` (`sUSDePriceProviderBUniCatch`, Solidity 0.6.6, BUSL-1.1) was directly confirmed via the Blockscout API. The actual code for key functions including `getPrice()`, `_getPrices()`, and `_getUSDeFraxEMAInUSD()` was confirmed to match the analysis in Section 2.

### 7.4 Attack Contract Verification

| Attack | Creation Transaction | Deployed Contract Address |
|------|--------------|---------------------|
| 1st | 0x242a...408b | **0x21C58d8F816578b1193AEf4683E8c64405A4312E** |
| 2nd | 0xb3f0...376 | **0x4e48C46779b3B16d63375751467D7eee34D41c3D** |
| 3rd | 0xca1b...2850 | **0x13F3fee69160162a78284c64c1100a3dF476D890** |

Each attack tx was confirmed via cast to be a contract deployment transaction in `to: null` form, and the deployed contract addresses are the execution entities for each respective attack.

---

## References

- [SlowMist: Analysis of the UwU Lend Hack](https://slowmist.medium.com/analysis-of-the-uwu-lend-hack-9502b2c06dbe)
- [QuillAudits: Decoding UwU Lend's $19.4 Million Exploit](https://www.quillaudits.com/blog/hack-analysis/uwu-lend-hack)
- [Neptune Mutual: Understanding the UwU Lend Exploit](https://medium.com/neptune-mutual/understanding-the-uwu-lend-exploit-b32ea552f030)
- [Cyvers.ai: UwU Lend $23M Exploit Oracle Vulnerabilities](https://cyvers.ai/blog/uwu-lend-23m-exploit-oracle-vulnerabilities-exposed)
- [Cryptobriefing: UwU Lend second hack $3.7M](https://cryptobriefing.com/uwu-lend-second-hack-update/)
- [Etherscan: 1st Attack Tx](https://etherscan.io/tx/0x242a0fb4fde9de0dc2fd42e8db743cbc197ffa2bf6a036ba0bba303df296408b)
- [Etherscan: sUSDePriceProviderBUniCatch](https://etherscan.io/address/0xd252953818bdf8507643c237877020398fa4b2e8)