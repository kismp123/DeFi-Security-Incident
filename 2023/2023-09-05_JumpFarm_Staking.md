# JumpFarm — Staking Reward Calculation Error Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-05 |
| **Protocol** | JumpFarm |
| **Chain** | Ethereum |
| **Loss** | ~$2.4 ETH |
| **Attacker** | [0x6ce9fa08f139f5e4...](https://etherscan.io/address/0x6ce9fa08f139f5e48bc607845e57efe9aa34c9f6) |
| **Attack Tx** | [0x6189ad07894507d1...](https://explorer.phalcon.xyz/tx/eth/0x6189ad07894507d15c5dff83f547294e72f18561dc5662a8113f7eb932a5b079) |
| **Vulnerable Contract** | [0x154863eb71de4a34...](https://etherscan.io/address/0x154863eb71de4a34f88ea57450840eab1c71aba6) |
| **Root Cause** | Reentrancy possible in reward calculation during unstake in the staking contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/JumpFarm_exp.sol) |

---
## 1. Vulnerability Overview
The JumpFarm staking contract was susceptible to reentrancy during the unstake process, which transfers both rewards and principal together.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: reentrancy possible during unstake
function unstake(address to, uint256 amount, bool rebase) external {
    uint256 reward = pendingRewards[msg.sender];
    // ❌ External transfer before state update
    IStakingToken(stakingToken).transfer(to, amount + reward);
    pendingRewards[msg.sender] = 0; // ❌ Too late
}
// ✅ Fix: nonReentrant + CEI
```

---
### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: reentrancy possible in reward calculation during unstake in the staking contract
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Call unstake()
  ├─② Reenter via token receive callback
  │       └─③ Re-call unstake() (rewards not yet zeroed)
  └─④ Drain multiple reward payouts
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Reentrancy via ERC777 token callback
function tokensReceived(...) external {
    if (reentrancyCount++ < maxReentry) {
        IStaking(target).unstake(address(this), amount, false);
    }
}
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Reentrancy Attack |
| Severity | Medium |

---
## 6. Remediation Recommendations
1. Apply `nonReentrant` modifier
2. Follow CEI (Checks-Effects-Interactions) pattern

---
## 7. Lessons Learned
The callback mechanism of ERC777 tokens can serve as a trigger for reentrancy attacks.