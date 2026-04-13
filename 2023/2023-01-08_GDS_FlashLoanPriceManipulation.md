# GDS Token — Flash Loan Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-01-08 |
| **Protocol** | GDS Token |
| **Chain** | BSC |
| **Loss** | Unknown (multiple TXs) |
| **Attacker** | Unknown |
| **Attack Tx** | [0xf9b6cc08...](https://bscscan.com/tx/0xf9b6cc083f6e0e41ce5e5dd65b294abf577ef47c7056d86315e5e53aa662251e) |
| **Vulnerable Contract** | [0xC1Bb1256...](https://bscscan.com/address/0xC1Bb12560468fb255A8e8431BDF883CC4cB3d278) |
| **Root Cause** | `pureUsdtToToken()` uses AMM spot reserves as a price oracle, allowing manipulation within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/GDS_exp.sol) |

---
## 1. Vulnerability Overview

The `pureUsdtToToken()` function in the GDS protocol uses the UniswapV2 pair's spot price when calculating the exchange rate for converting USDT to GDS tokens. The attacker borrowed a large amount of liquidity via a flash loan to artificially manipulate the pair's price, acquired tokens at favorable rates, and then repaid the flash loan to realize a profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: uses spot price directly
function pureUsdtToToken(uint256 _uAmount) external returns (uint256) {
    // Directly queries the current reserves of the UniswapV2 pair
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    // ❌ Spot price-based calculation → reserves can be manipulated via flash loan
    uint256 tokenAmount = _uAmount * reserve1 / reserve0;
    return tokenAmount;
}

// ✅ Fix: use TWAP (Time-Weighted Average Price)
function pureUsdtToToken(uint256 _uAmount) external returns (uint256) {
    // Use Uniswap V3 TWAP or Chainlink oracle
    uint256 twapPrice = getTWAPPrice();  // ✅ Manipulation-resistant price
    uint256 tokenAmount = _uAmount * twapPrice / 1e18;
    return tokenAmount;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: GDS.sol
    function pureUsdtToToken(uint256 _uAmount) public view returns(uint256){  // ❌
        address[] memory routerAddress = new address[](2);
        routerAddress[0] = usdt;
        routerAddress[1] = address(this);
        uint[] memory amounts = uniswapV2Router.getAmountsOut(_uAmount,routerAddress);
        return amounts[1];
    }

// ...

    function _activateAccount(address _from,address _to,uint256 _amount)internal {
        if(enableActivate && !isActivated[_from]){
            uint256 _pureAmount = pureUsdtToToken(minUsdtAmount);  // ❌
            if(_to == dead && _amount >= _pureAmount){
                isActivated[_from] = true;
                inviteCount[inviter[_from]] +=1;
            }
        }
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ AAVE/DODO Flash Loan (borrow large amount of USDT)
  │
  ├─2─▶ Buy GDS in bulk with borrowed USDT
  │       → GDS price spikes (reserve ratio shifts)
  │
  ├─3─▶ Call pureUsdtToToken()
  │       Receive GDS at favorable rate based on manipulated spot price
  │
  ├─4─▶ Leverage ClaimReward contract for additional rewards
  │       Repeatedly call transferToken() / withdraw()
  │
  ├─5─▶ Sell GDS tokens → USDT
  │
  └─6─▶ Repay flash loan → realize net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function executeOperation(/* AAVE flash loan callback */) external {
    // 1. Buy GDS in bulk with flash-loaned USDT → price spikes
    Router.swapExactTokensForTokens(flashAmount, 0, path, address(this), deadline);

    // 2. Deploy ClaimReward factory contracts while price is manipulated
    //    Each contract calls pureUsdtToToken() to receive GDS at favorable rate
    ClaimRewardFactory();

    // 3. Withdraw GDS tokens from each contract
    WithdrawRewardFactory();

    // 4. Sell recovered GDS for USDT to realize profit
    Router.swapExactTokensForTokens(gdsBalance, 0, reversePath, address(this), deadline);

    // 5. Repay flash loan (return principal + fee to AAVE)
    USDT.approve(address(AAVE), flashAmount + premium);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Vector** | Flash Loan + Spot Price Manipulation |
| **Impact Scope** | Entire protocol liquidity |
| **DASP Classification** | Oracle Manipulation |
| **CWE** | CWE-20: Improper Input Validation |

## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Use the Time-Weighted Average Price (TWAP) from UniswapV2/V3 to prevent short-term manipulation.
2. **Integrate Chainlink Oracle**: Leverage externally validated price feeds.
3. **Price Deviation Check**: Block transactions when the difference between the spot price and TWAP exceeds a threshold.

## 7. Lessons Learned

- Any financial calculation that relies on spot prices is vulnerable to flash loan attacks.
- When reward mechanisms (ClaimReward) are combined with price manipulation, the damage is amplified.
- Both PeckShield and BlockSec detected this attack in real time, but no pre-emptive defenses were in place.