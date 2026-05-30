# SafeDollar — Flash Swap-Based SDO Reward Pool Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2021-06-28 |
| **Protocol** | SafeDollar (SDO) |
| **Chain** | Polygon |
| **Loss** | ~$248,000 |
| **Attacker** | Address unidentified |
| **Attack Tx** | Address unidentified |
| **Vulnerable Contract** | SDO Reward Pool (Polygon) |
| **Root Cause** | No minimum lockup period in SDO reward pool — `getReward()` can be called immediately after deposit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-06/SafeDollar_exp.sol) |

---
## 1. Vulnerability Overview

SafeDollar's SDO reward pool is designed to distribute SDO rewards when PLX tokens are deposited. The attacker borrowed large amounts of PLX via consecutive flash swaps from two Polydex liquidity pools (WETH-PLX, WMATIC-PLX), used `cheats.warp()` to advance the timestamp, and claimed all accumulated SDO rewards in a single transaction. Profits were realized by selling SDO for USDC, then repaying the flash swaps.

---
## 2. Vulnerable Code Analysis

### 2.1 deposit() / getReward() — Timestamp-Based Rewards, No Deposit Cap

```solidity
// ❌ SDO Reward Pool — vulnerable to flash loan + timestamp manipulation
function deposit(uint256 amount) external {
    // No deposit cap — large deposits possible via flash loan
    _totalSupply = _totalSupply.add(amount);
    _balances[msg.sender] = _balances[msg.sender].add(amount);
    stakingToken.safeTransferFrom(msg.sender, address(this), amount);
    emit Staked(msg.sender, amount);
}

function earned(address account) public view returns (uint256) {
    // Reward calculation based on block.timestamp
    // Advancing the timestamp immediately after deposit yields massive rewards
    return _balances[account]
        .mul(rewardPerToken().sub(userRewardPerTokenPaid[account]))
        .div(1e18)
        .add(rewards[account]);
}
```

**Fixed Code**:
```solidity
// ✅ Enforce minimum lockup period between deposit and withdrawal
mapping(address => uint256) public depositTime;
uint256 public constant MIN_LOCKUP = 1 days;

function deposit(uint256 amount) external nonReentrant {
    depositTime[msg.sender] = block.timestamp;
    _totalSupply = _totalSupply.add(amount);
    _balances[msg.sender] = _balances[msg.sender].add(amount);
    stakingToken.safeTransferFrom(msg.sender, address(this), amount);
    emit Staked(msg.sender, amount);
}

function getReward() external nonReentrant {
    require(
        block.timestamp >= depositTime[msg.sender] + MIN_LOCKUP,
        "RewardPool: lockup period not met"
    );
    // ... reward distribution
}
```


### On-Chain Source Code

Source: **Sourcify-verified (partial)** — SdoRewardPool / 0x17684f4d5385FAc79e75CeafC93f22D90066eD5C (Polygon)
https://sourcify.dev/server/files/any/137/0x17684f4d5385FAc79e75CeafC93f22D90066eD5C

> Note: The corrected root cause is that `deposit()` immediately calls `_harvestReward()`, which mints SDO proportional to the deposited amount times the accumulated `accSdoPerShare`. An attacker who (a) deposits a massive flash-loan-funded position and (b) forces time to advance so rewards accumulate can claim all pool rewards in one transaction. There is no separate `getReward()` — reward minting occurs inside `deposit()` / `withdraw()` via `_harvestReward()`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

contract SdoRewardPool {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    struct UserInfo {
        uint256 amount;      // LP tokens staked
        uint256 rewardDebt;  // Reward debt (for delta calculation)
    }

    struct PoolInfo {
        IERC20 lpToken;
        uint256 allocPoint;
        uint256 lastRewardTime;
        uint256 accSdoPerShare; // ❌ accumulated rewards per share — grows with time
        bool isStarted;
        uint16 depositFeeBP;
        uint256 startTime;
    }

    // ❌ VULNERABLE: _harvestReward mints SDO for any staked balance immediately
    function _harvestReward(uint256 _pid, address _account) internal {
        UserInfo storage user = userInfo[_pid][_account];
        if (user.amount > 0) {
            PoolInfo storage pool = poolInfo[_pid];
            uint256 _claimableAmount = user.amount
                .mul(pool.accSdoPerShare)   // ❌ accSdoPerShare grows with every second elapsed
                .div(1e18)
                .sub(user.rewardDebt);
            if (_claimableAmount > 0) {
                IBasisAsset(sdo).mint(_account, _claimableAmount); // ❌ mint called unconditionally — no lockup
                emit RewardPaid(_account, _pid, _claimableAmount);
            }
        }
    }

    // ❌ deposit() harvests rewards immediately after staking — no lockup period
    function deposit(uint256 _pid, uint256 _amount) public lock checkHalving {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        _harvestReward(_pid, msg.sender); // ❌ called before setting new rewardDebt
        if (_amount > 0) {
            pool.lpToken.safeTransferFrom(msg.sender, address(this), _amount);
            if (pool.depositFeeBP > 0) {
                uint256 _depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                pool.lpToken.safeTransfer(reserveFund, _depositFee);
                user.amount = user.amount.add(_amount).sub(_depositFee);
            } else {
                user.amount = user.amount.add(_amount); // ❌ no cap on deposit size
            }
        }
        user.rewardDebt = user.amount.mul(pool.accSdoPerShare).div(1e18);
        emit Deposit(msg.sender, _pid, _amount);
    }

    // ❌ withdraw() also harvests rewards with no lockup check
    function withdraw(uint256 _pid, uint256 _amount) public lock checkHalving {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount >= _amount, "withdraw: not good");
        updatePool(_pid);
        _harvestReward(_pid, msg.sender); // ❌ same issue — no lockup guard
        if (_amount > 0) {
            user.amount = user.amount.sub(_amount);
            pool.lpToken.safeTransfer(msg.sender, _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accSdoPerShare).div(1e18);
        emit Withdraw(msg.sender, _pid, _amount);
    }
}
```

**Why it is exploitable (identify the bug from the code):**

- `deposit()` calls `_harvestReward()` at line 3 of its body, before updating `rewardDebt`. Any staked balance, no matter how recently deposited, immediately receives `user.amount * accSdoPerShare / 1e18 - rewardDebt` worth of minted SDO.
- There is no lockup period, no minimum staking duration, and no per-block snapshot — a flash-loan-funded deposit immediately accrues rewards proportional to the (time-weighted) accumulated `accSdoPerShare`.
- Because `accSdoPerShare` reflects all rewards since the pool's `startTime`, a massive late deposit effectively steals the accumulated share of all prior stakers: the new depositor's `rewardDebt` is set *after* the mint, so the window from 0 to the current `accSdoPerShare` is captured in one call.
- The `lock` modifier prevents re-entry within a single call but does not block a deposit immediately followed by a withdraw within the same outer transaction (each call acquires and releases the lock independently).

```solidity
// ✅ Fix: enforce a minimum staking duration before rewards can be harvested
mapping(uint256 => mapping(address => uint256)) public stakedAt;

function deposit(uint256 _pid, uint256 _amount) public lock checkHalving {
    PoolInfo storage pool = poolInfo[_pid];
    UserInfo storage user = userInfo[_pid][msg.sender];
    updatePool(_pid);
    // ✅ Only harvest if the minimum lock period has elapsed
    if (block.timestamp >= stakedAt[_pid][msg.sender] + 1 days) {
        _harvestReward(_pid, msg.sender);
    }
    if (_amount > 0) {
        stakedAt[_pid][msg.sender] = block.timestamp; // ✅ record deposit timestamp
        pool.lpToken.safeTransferFrom(msg.sender, address(this), _amount);
        user.amount = user.amount.add(_amount);
    }
    user.rewardDebt = user.amount.mul(pool.accSdoPerShare).div(1e18);
    emit Deposit(msg.sender, _pid, _amount);
}
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────────────────┐
│ Step 1: Deploy depositHelper contract via CREATE2          │
│ → Helper to deposit PLX into reward pool                   │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 2: Initiate flash swap on Polydex Pair1 (WETH-PLX)   │
│ IUniswapV2Pair(pair1).swap(0, plxAmount, this, data)       │
└─────────────────────┬──────────────────────────────────────┘
                      │ polydexCall() callback
┌─────────────────────▼──────────────────────────────────────┐
│ Step 3: Nested flash swap on Pair2 (WMATIC-PLX)           │
│ → Acquire additional PLX                                   │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 4: Repeatedly deposit/withdraw PLX into SDO reward    │
│ pool via depositHelper + manipulate timestamp via          │
│ cheats.warp() → Claim all accumulated SDO rewards at once  │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 5: Sell SDO → USDC (via router)                      │
│ + Repay flash swaps                                        │
└────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// polydexCall() — execute attack inside flash swap callback
function polydexCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // Acquire additional PLX via nested flash swap
    IUniswapV2Pair(pair2).swap(0, plxAmount2, address(this), abi.encode("flash2"));

    // Deposit PLX into SDO reward pool via depositHelper
    // depositHelper.depositSPORE(plxBalance)

    // Claim SDO rewards via timestamp manipulation
    // cheats.warp(block.timestamp + rewardDuration)
    // sdoRewardPool.getReward()

    // Sell SDO → USDC
    // router.swapExactTokensForTokens(sdo, 0, [SDO, USDC], ...)

    // Repay flash swaps
    PLX.transfer(pair1, repayAmount);
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | No minimum lockup period in reward pool — entire accumulated reward claimable immediately via `getReward()` after deposit | CRITICAL | CWE-20 |
| V-02 | (Contributing factor) Flash swap used to acquire large deposit capital — flash swap is rendered useless if lockup period exists | LOW | CWE-829 |

> **Root Cause**: `getReward()` can be called immediately after `deposit()`, completing the deposit → reward claim → withdrawal cycle within a single transaction. The flash swap is merely a capital vehicle; a minimum 1-day lockup period alone would fully block the entire attack. The `cheats.warp()` in the PoC is for test environment simulation — the actual attack worked by diluting existing accumulated rewards with a massive deposit and claiming immediately.

---
## 6. Remediation Recommendations

```solidity
// ✅ Enforce minimum lockup period (flash loan prevention)
// ✅ Apply deposit duration weighting to reward calculation

// Record deposit start timestamp
mapping(address => uint256) public stakedAt;

function deposit(uint256 amount) external nonReentrant updateReward(msg.sender) {
    stakedAt[msg.sender] = block.timestamp;
    // ...
}

function withdraw(uint256 amount) external nonReentrant updateReward(msg.sender) {
    require(block.timestamp >= stakedAt[msg.sender] + 1 days, "Locked");
    // ...
}
```

---
## 7. Lessons Learned

- **The fundamental vulnerability in reward pools is the absence of a lockup period.** A minimum 1-day lockup alone completely prevents the deposit-claim combination within a single transaction.
- **Flash swaps are merely a capital acquisition mechanism; with a lockup period in place, capital obtained via flash swap cannot be used to claim rewards.**
- **`block.timestamp` manipulation is limited to a range of only a few seconds.** The core of the actual attack was not timestamp manipulation but the absence of a lockup period.