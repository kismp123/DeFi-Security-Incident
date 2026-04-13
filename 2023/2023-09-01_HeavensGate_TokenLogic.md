# HeavensGate — Token Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-01 |
| **Protocol** | HeavensGate |
| **Chain** | Ethereum |
| **Loss** | ~8 ETH |
| **Attacker** | [0x6ce9fa08f139f5e4...](https://etherscan.io/address/0x6ce9fa08f139f5e48bc607845e57efe9aa34c9f6) |
| **Attack Tx** | [0xe28ca1f43036f476...](https://etherscan.io/tx/0xe28ca1f43036f4768776805fb50906f8172f75eba3bf1d9866bcd64361fda834) |
| **Vulnerable Contract** | [0x8faa53a742fc732b...](https://etherscan.io/address/0x8faa53a742fc732b04db4090a21e955fe5c230be) |
| **Root Cause** | Balance calculation error in token's special transfer logic |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/HeavensGate_exp.sol) |

---
## 1. Vulnerability Overview
There was a balance calculation error in the HeavensGate token's special transfer mechanism. The attacker exploited this to steal approximately 8 ETH.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Vulnerable code: incorrect balance calculation
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 scaledAmount = amount * getScale() / 1e18;
    _balances[from] -= amount;       // ❌ deduct original amount
    _balances[to] += scaledAmount;   // ❌ add scaled amount (mismatch)
}
// ✅ Fix: use consistent units
```

---
### On-chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: balance calculation error in token's special transfer logic
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Identify balance calculation mismatch
  ├─② Acquire more tokens via scale manipulation
  └─③ Sell excess tokens + ~8 ETH
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Increase token balance by exploiting scale mismatch
token.transfer(address(this), amount);
// Actually receives scaledAmount > amount
sellExcessTokens();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Token Logic Error |
| Severity | High |

---
## 6. Remediation Recommendations
1. Validate unit consistency in transfer functions
2. Add balance invariant tests

---
## 7. Lessons Learned
Token scaling/rebase mechanisms can break balance consistency.