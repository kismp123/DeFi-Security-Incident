# QuantumWN — Staking Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-05 |
| **Protocol** | QuantumWN |
| **Chain** | Ethereum |
| **Loss** | ~0.5 ETH |
| **Attacker** | [0x6ce9fa08f139f5e4...](https://etherscan.io/address/0x6ce9fa08f139f5e48bc607845e57efe9aa34c9f6) |
| **Attack Tx** | [0xa4659632a983b3bf...](https://etherscan.io/tx/0xa4659632a983b3bfd1b6248fd52d8f247a9fcdc1915f7d38f01008cff285d0bf) |
| **Vulnerable Contract** | [0x154863eb71de4a34...](https://etherscan.io/address/0x154863eb71de4a34f88ea57450840eab1c71aba6) |
| **Root Cause** | Double reward payout due to incorrect rebase flag handling in the unstake function |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/QuantumWN_exp.sol) |

---
## 1. Vulnerability Overview
The unstake function in QuantumWN staking contained a logic error in its rebase parameter handling, allowing rewards to be paid out twice.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: incorrect rebase flag handling
function unstake(address to, uint256 amount, bool rebase) external {
    if (rebase) {
        // calculate rebase reward
        uint256 rebaseReward = calculateRebaseReward();
        amount += rebaseReward; // ❌ reward included in amount
    }
    // ❌ calling again with rebase=false pays out principal + separate reward twice
    transfer(to, amount);
    pendingRewards[msg.sender] = 0;
}
// ✅ Fix: clear separation of state
```

---
### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: double reward payout due to incorrect rebase flag handling in the unstake function
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Call unstake(to, amount, true) → withdraw with rebase reward included
  ├─② Re-call unstake(to, amount, false) on the same position
  └─③ Double payout + ~0.5 ETH
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Alternate rebase flag to induce double payout
staking.unstake(address(this), amount, true);
staking.unstake(address(this), amount, false); // double withdrawal
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Logic Error / Double Payout |
| Severity | Medium |

---
## 6. Remediation Recommendations
1. Clarify state transition logic
2. Immediately invalidate the position after withdrawal

---
## 7. Lessons Learned
Complex parameter combinations can produce unexpected states. Thorough state transition testing is essential.