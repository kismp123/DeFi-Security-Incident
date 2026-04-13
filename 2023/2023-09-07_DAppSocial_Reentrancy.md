# DAppSocial — Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-07 |
| **Protocol** | DAppSocial |
| **Chain** | Ethereum |
| **Loss** | ~$16K |
| **Attacker** | [0x7d9bc45a9abda926...](https://etherscan.io/address/0x7d9bc45a9abda926a7ce63f78759dbfa9ed72e26) |
| **Attack Tx** | [0xbd72bccec6dd824f...](https://etherscan.io/tx/0xbd72bccec6dd824f8cac5d9a3a2364794c9272d7f7348d074b580e3c6e44312e) |
| **Vulnerable Contract** | [0x319ec3ad98cf8b12...](https://etherscan.io/address/0x319ec3ad98cf8b12a8be5719fec6e0a9bb1ad0d1) |
| **Root Cause** | Reentrancy vulnerability in the reward withdrawal function of the social token staking contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/DAppSocial_exp.sol) |

---
## 1. Vulnerability Overview
DAppSocial's staking contract had no reentrancy protection when transferring ETH rewards. The attacker drained ~$16K.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Vulnerable code: state updated after reward transfer
function claimReward() external {
    uint256 reward = rewards[msg.sender];
    (bool ok,) = msg.sender.call{value: reward}(""); // ❌ reentrancy
    require(ok);
    rewards[msg.sender] = 0; // ❌ too late
}
// ✅ Fix: CEI pattern
function claimReward() external nonReentrant {
    uint256 reward = rewards[msg.sender];
    rewards[msg.sender] = 0; // ✅ reset first
    (bool ok,) = msg.sender.call{value: reward}("");
    require(ok);
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: reentrancy vulnerability in the reward withdrawal function of the social token staking contract
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① calls claimReward()
  ├─② receives ETH → reenters via receive()
  │       └─③ repeatedly calls claimReward()
  └─④ multiple reward withdrawals + ~$16K
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
receive() external payable {
    if (address(this).balance < targetProfit) {
        IDAppSocial(target).claimReward(); // reenter
    }
}
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Reentrancy Attack |
| Severity | High |

---
## 6. Remediation Recommendations
1. Apply `nonReentrant` modifier
2. Follow the CEI (Checks-Effects-Interactions) pattern

---
## 7. Lessons Learned
Reward functions that include ETH transfers must always have reentrancy protection.