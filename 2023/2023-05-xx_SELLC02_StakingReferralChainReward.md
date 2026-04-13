# SELLC02 Exploit — StakingRewards Referral Chain Reward Inflation

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05 |
| Project | SELLC02 (StakingRewards) |
| Chain | BSC |
| Loss | Unconfirmed |
| Attacker | 0xa3aa817587556c023e78b2285d381c68cee17069 |
| Attack TX | Unconfirmed |
| Vulnerable Contract | StakingRewards: 0xeaf83465025b4bf9020fdf9ea5fb6e71dc8a0779 |
| Block | Unconfirmed |
| CWE | CWE-682 (Incorrect Calculation — referral reward distributed without validation) |
| Vulnerability Type | Referral Stake Reward Inflation via Artificial Referral Chain |

## Summary
The SELLC02 `StakingRewards` contract distributed rewards to referrers when their referred addresses staked. The attacker created 10 exploiter contracts linked in a referral chain, staked USDT via each, then extracted disproportionate SELLC rewards by claiming referral bonuses that were not properly bounded or validated.

## Vulnerability Details
- **CWE-682**: The referral reward calculation multiplied the staking reward by the number or size of referred stakes without a ceiling or anti-Sybil check. By creating 10 attacker-controlled contracts as referrers and stakers in a chain, the attacker accumulated rewards many times larger than their actual staked capital.

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: StakingRewards.sol
    function stakedOfTimeSum(address,address,uint)external view returns (uint);  // ❌

// ...

    function stakedSum(address,address)external view returns (uint);  // ❌

// ...

    function myReward(address)external view returns (address);  // ❌

// ...

    function upaddress(address)external view returns (address);  // ❌

// ...

    function users(address,address)external view returns (uint,uint,uint);  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. deal(USDT, address(this), 1_000e18)
// 2. for (uint i = 0; i < 10; i++) {
//       Exploiter e = new Exploiter(address(StakingRewards));
//       exploiters[i] = e;
//    }
// 3. Set up referral chain: exploiters[0] refers exploiters[1]...exploiters[9]
// 4. Each exploiter stakes 100 USDT
// 5. vm.warp(+1 hour)
// 6. Deploy malicious TokenA with 100 supply
// 7. Pair.swap(10_000 QIQI, 0, address(this), data)
//    → flash loan callback: addLiquidity, claim all exploiter rewards, removeL, repay
// 8. Collect excess SELLC rewards
```

## Interfaces from PoC
```solidity
interface IStakingRewards {
    function stake(uint256 amount) external;
    function claim() external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| StakingRewards (Vulnerable) | 0xeaf83465025b4bf9020fdf9ea5fb6e71dc8a0779 |
| SELLC Token | 0xa645995e9801F2ca6e2361eDF4c2A138362BADe4 |
| QIQI Token | 0x0B464d2C36d52bbbf3071B2b0FcA82032DCf656d |
| USDT | 0x55d398326f99059fF775485246999027B3197955 |
| Attacker | 0xa3aa817587556c023e78b2285d381c68cee17069 |
| Attack Contract | 0xc2f54422c995f6c2935bc52b0f55a03c2f3e429c |

## Root Cause
Referral rewards were distributed based on referred stake size without a maximum referral depth or per-address reward cap. Artificial referral chains created by the same attacker multiplied rewards without proportional capital risk.

## Fix
```solidity
// Limit referral depth and add minimum time between stake and claim:
uint256 public constant MAX_REFERRAL_DEPTH = 2;
uint256 public constant MIN_STAKE_DURATION = 7 days;

function _getReferralReward(address staker, uint256 baseReward) internal view returns (uint256) {
    uint256 depth = 0;
    address ref = referrer[staker];
    uint256 bonus = 0;
    while (ref != address(0) && depth < MAX_REFERRAL_DEPTH) {
        bonus += baseReward * REFERRAL_RATE[depth] / 10000;
        ref = referrer[ref];
        depth++;
    }
    return bonus;
}
```

## References
- BSC StakingRewards: 0xeaf83465025b4bf9020fdf9ea5fb6e71dc8a0779
- Related: SELLC (0xa645995e9801F2ca6e2361eDF4c2A138362BADe4)