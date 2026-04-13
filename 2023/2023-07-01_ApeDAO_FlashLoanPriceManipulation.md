# ApeDAO Flash Loan Price Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | ApeDAO |
| Date | 2023-07-01 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$7,000 USD |
| Attack Type | Flash Loan + Price Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x10703f7114dce7beaf8d23cde4bf72130bb0f56a` |
| Attack Contract | `0x45aa258ad08eeeb841c1c02eca7658f9dd4779c0` |
| Vulnerable Contract | `0xB47955B5B7EAF49C815EBc389850eb576C460092` |
| Fork Block | 30,072,293 |

## 2. Vulnerable Code Analysis

The ApeDAO contract failed to validate token prices within the DPP Oracle flash loan callback, allowing price manipulation through chained flash loans. By sequentially taking flash loans from multiple DPP Oracles to manipulate pair balances and then calling `skim()`, the attacker was able to extract the difference.

```solidity
// Vulnerable pattern: no price validation in flash loan callback
function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
    // Vulnerable: no caller validation, reentrancy possible
    if (msg.sender == address(DPPOracle1)) {
        DPPOracle2.flashLoan(0, IERC20(BUSDT).balanceOf(address(DPPOracle2)) * 99 / 100, address(this), data);
    }
    // ... chained flash loans continue
}
```

**Vulnerability**: The DPP Oracle callback chain allows sequential flash loans to execute without intermediate state validation.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Price Manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker
  │
  ├─1─▶ DPPOracle1.flashLoan() [0xFeAFe253802b77456B4627F8c2306a9CeBb5d681]
  │      └─▶ DPPFlashLoanCall() callback
  │            ├─2─▶ DPPOracle2.flashLoan() [0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A]
  │            │      └─▶ DPPOracle3.flashLoan() [0x26d0c625e5F5D6de034495fbDe1F6e9377185618]
  │            │            └─▶ DPP.flashLoan() [0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476]
  │            │                  └─▶ DPPAdvanced.flashLoan() [0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d]
  │            │
  ├─3─▶ Uni_Router_V2.swapExactTokensForTokens() → BUSDT→APEDAO
  ├─4─▶ Pair.skim() [0xee2a9D05B943C1F33f3920C750Ac88F74D0220c3] → token extraction
  └─5─▶ APEDAO→BUSDT swap, then repay flash loan
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IAPEDAO is IERC20 {}
interface IDPPOracle {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

contract ApeDAOExploit {
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IAPEDAO APEDAO = IAPEDAO(0xB47955B5B7EAF49C815EBc389850eb576C460092);
    IDPPOracle DPPOracle1 = IDPPOracle(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    Uni_Pair_V2 Pair = Uni_Pair_V2(0xee2a9D05B943C1F33f3920C750Ac88F74D0220c3);

    function testExploit() external {
        DPPOracle1.flashLoan(0, BUSDT.balanceOf(address(DPPOracle1)) * 99 / 100, address(this), "");
    }

    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata data) external {
        // Chained flash loans → swap → skim() call
        uint256 amount = BUSDT.balanceOf(address(this));
        // Swap BUSDT → APEDAO
        // Call Pair.skim(address(this))
        // Swap APEDAO → BUSDT
        // Repay flash loan
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Flash loan price manipulation, skim() vulnerability |
| Impact Scope | APEDAO liquidity pool |
| Precondition | DPP Oracle flash loan access |
| Contract Verification | None |

## 6. Security Recommendations

```solidity
// Fix 1: Flash loan callback validation
modifier onlyAuthorizedFlashLoan() {
    require(
        msg.sender == address(DPPOracle1) ||
        msg.sender == address(DPPOracle2),
        "Unauthorized flash loan callback"
    );
    _;
}

// Fix 2: Reentrancy guard + price check
uint256 private _flashLoanDepth;

function DPPFlashLoanCall(...) external onlyAuthorizedFlashLoan {
    require(_flashLoanDepth == 0, "Reentrancy detected");
    _flashLoanDepth++;

    // Validate price change before and after flash loan
    uint256 priceBefore = getPrice();
    // ... logic
    uint256 priceAfter = getPrice();
    require(priceAfter >= priceBefore * 95 / 100, "Price manipulation detected");

    _flashLoanDepth--;
}

// Fix 3: Limit flash loan count within a single transaction
uint256 constant MAX_FLASH_LOANS_PER_TX = 1;
```

## 7. Lessons Learned

1. **Chained Flash Loan Risk**: A pattern that sequentially borrows from multiple DPP Oracles within a single transaction is vulnerable to price manipulation attacks. The number of flash loans per transaction must be limited.
2. **Protect the `skim()` Function**: The `skim()` function extracts the difference between the pair's recorded balance and its actual holdings; calling it after price manipulation enables large-scale token theft. Access control is required.
3. **Mandatory Callback Validation**: Flash loan callbacks (`DPPFlashLoanCall`) must always validate the caller and guard against reentrancy attacks.
4. **Pattern Analysis Required Even for Small Losses**: Although the loss was only $7,000, the same pattern applied to a larger protocol could result in millions of dollars in damage.