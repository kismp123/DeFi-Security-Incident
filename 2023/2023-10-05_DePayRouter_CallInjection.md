# DePay Router — Call Injection Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-10-05 |
| **Protocol** | DePay |
| **Chain** | Ethereum |
| **Loss** | ~827 USDC |
| **Attacker** | [0x7f284235aef12221...](https://etherscan.io/address/0x7f284235aef122215c46656163f39212ffa77ed9) |
| **Attack Tx** | [0x9a036058afb58169...](https://etherscan.io/tx/0x9a036058afb58169bfa91a826f5fcf4c0a376e650960669361d61bef99205f35) |
| **Vulnerable Contract** | [0xae60ac8e69414c2d...](https://etherscan.io/address/0xae60ac8e69414c2dc362d0e6a03af643d1d85b92) |
| **Root Cause** | Router allows arbitrary external calls, enabling token approval hijacking after approval |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/DePayRouter_exp.sol) |

---
## 1. Vulnerability Overview
DePay Router is a payment routing protocol. The router executes arbitrary external calls using user-supplied calldata, allowing an attacker to intercept token approvals and drain USDC.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Vulnerable code: arbitrary calldata execution
function route(
    address[] calldata path,
    uint256[] calldata amounts,
    address[] calldata addresses,
    address[] calldata plugins,
    string[] calldata data
) external payable {
    for (uint i = 0; i < plugins.length; i++) {
        // ❌ Executes arbitrary calls to arbitrary plugins
        IDePayRouterPlugin(plugins[i]).execute{value: msg.value}(...);
    }
}
// ✅ Fix: plugin whitelist
function route(...) external payable {
    for (uint i = 0; i < plugins.length; i++) {
        require(approvedPlugins[plugins[i]], "Not approved"); // ✅
        IDePayRouterPlugin(plugins[i]).execute(...);
    }
}
```

---
### On-chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Router allows arbitrary external calls, enabling token approval hijacking
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Deploy malicious plugin contract
  ├─② Call route(..., [maliciousPlugin], ...)
  │       └─ Router executes malicious plugin
  │       └─ USDC.approve(attacker, MAX) is executed
  ├─③ USDC.transferFrom(router, attacker, balance)
  └─④ ~827 USDC drained
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Malicious plugin
function execute(address[] calldata path, uint256[] calldata amounts, ...) external payable {
    // Approve the router's USDC to the attacker
    IERC20(USDC).approve(attacker, type(uint256).max);
}
// Drain via transferFrom after approval
USDC.transferFrom(address(router), attacker, routerBalance);
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Call Injection |
| Severity | High |

---
## 6. Remediation Recommendations
1. Apply plugin whitelist
2. Minimize token balance held within the router
3. Strengthen validation before executing arbitrary external calls

---
## 7. Lessons Learned
When a payment router executes arbitrary external calls, it is vulnerable to call injection. All plugins/adapters must be managed via a whitelist.