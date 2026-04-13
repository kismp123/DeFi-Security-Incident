# Uwerx — Token Unlock Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-08-30 |
| **Protocol** | Uwerx |
| **Chain** | Ethereum |
| **Loss** | ~176 ETH |
| **Attacker** | [0x6057a831d43c395198...](https://etherscan.io/address/0x6057a831d43c395198a10cf2d7d6d6a063b1fce4) |
| **Attack Tx** | [0x3b19e152943f31fe08...](https://etherscan.io/tx/0x3b19e152943f31fe0830b67315ddc89be9a066dc89174256e17bc8c2d35b5af8) |
| **Vulnerable Contract** | [0x4306b12f8e824ce1fa...](https://etherscan.io/address/0x4306b12f8e824ce1fa9604bbd88f2ad4f0fe3c54) |
| **Root Cause** | Team wallet unlock conditions were arbitrarily modifiable on-chain |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-08/Uwerx_exp.sol) |

---
## 1. Vulnerability Overview

The Uwerx team called a function to shorten the vesting period of locked team tokens, selling tokens worth 176 ETH ahead of schedule. This constitutes a Rug Pull.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable code: team can modify the vesting period
function changeVestingEndDate(uint256 newEndDate) external onlyOwner {
    vestingEndDate = newEndDate; // ❌ Can be set to a past date
}

// ✅ Fix: vesting period cannot be shortened, only extended
function extendVestingEndDate(uint256 newEndDate) external onlyOwner {
    require(newEndDate > vestingEndDate, "Can only extend"); // ✅
    vestingEndDate = newEndDate;
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: team wallet unlock conditions were arbitrarily modifiable on-chain
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Team (Insider)
  ├─① Call changeVestingEndDate(past date)
  │       └─ Vesting period ends immediately
  ├─② Unlock full team token balance
  └─③ Sell on market → 176 ETH realized (investor losses)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Transaction executed directly by the team
IUwerxToken(token).changeVestingEndDate(block.timestamp - 1);
// Lock immediately released
token.transfer(teamWallet, lockedAmount);
// Sell
sellTokens(lockedAmount);
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| Vulnerability Type | Owner Privilege Abuse / Rug Pull |
| Severity | Critical |

---
## 6. Remediation Recommendations

1. Design the vesting period so it cannot be shortened on-chain
2. Store team tokens in a timelock contract
3. Restrict vesting condition changes via multi-signature

---
## 7. Lessons Learned

The team token locking mechanism is the cornerstone of investor protection. Any function that allows the team to unilaterally unlock tokens is a Rug Pull risk.