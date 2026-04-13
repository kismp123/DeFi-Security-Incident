# XAI Token — Token Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-07 |
| **Protocol** | XAI Token |
| **Chain** | BSC |
| **Loss** | Unclear |
| **Attacker** | [0xea75aec151f968b8...](https://bscscan.com/address/0xea75aec151f968b8de3789ca201a2a3a7faeefba) |
| **Attack Tx** | [0x2b251e456c434992...](https://bscscan.com/tx/0x2b251e456c434992b9ac7ec56dc166550c4cd7db3adefbf7eb3ab91cef55f9bf) |
| **Vulnerable Contract** | [0x570ce7b89c672007...](https://bscscan.com/address/0x570ce7b89c67200721406525e1848bca6ff5a6f3) |
| **Root Cause** | Balance calculation error in XAI token transfer logic |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/XAI_exp.sol) |

---
## 1. Vulnerability Overview
A balance calculation error in the XAI token transfer logic occurs under certain conditions, allowing the attacker to profit.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Vulnerable code: balance calculation error
function _transfer(address from, address to, uint256 amount) internal override {
    // ❌ Balance can increase under certain conditions
    uint256 adjustedAmount = adjustForTax(amount);
    if (adjustedAmount > amount) { // ❌ This case can occur
        _balances[to] += adjustedAmount;
    }
}
// ✅ Fix: transfer amount must always be less than or equal to the original amount
```

---
### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: balance calculation error in XAI token transfer logic
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Identify error in XAI token transfer logic
  ├─② Trigger balance increase by transferring a specific amount
  └─③ Sell excess balance
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Trigger balance inflation condition
xaiToken.transfer(address(this), triggerAmount);
// Verify excess balance then sell
sellExcessXAI();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Token Logic Error |
| Severity | High |

---
## 6. Remediation Recommendations
1. Enforce balance invariant in the transfer function
2. Mathematically verify the `adjustForTax` function

---
## 7. Lessons Learned
Transfer functions must always enforce the invariant that `input amount >= output amount`.