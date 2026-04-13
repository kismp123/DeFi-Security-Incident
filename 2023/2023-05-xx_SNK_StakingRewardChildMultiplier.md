# SNK Token Exploit — rewardPerToken Multiplied by All Children's Balances

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05 |
| Project | SNK Token |
| Chain | BSC |
| Loss | Unconfirmed |
| Attacker | Unconfirmed |
| Attack TX | Unconfirmed |
| Vulnerable Contract | SNKMinter: 0xA3f5ea945c4970f48E322f1e70F4CC08e70039ee |
| Block | Unconfirmed |
| CWE | CWE-682 (Incorrect Calculation — reward multiplied by children's balances) |
| Vulnerability Type | Hierarchical Staking Reward Inflation via Parent-Child bindParent() Exploit |

## Summary
SNKMinter calculated staking rewards by multiplying `rewardPerToken` by the aggregate staked balance of all child addresses bound to a parent via `bindParent()`. The attacker created 10 parent contracts, staked 100 SNK each, waited 20 days, then flash-swapped 80,000 SNK and bound 10 new child contracts to those parents — triggering reward calculations that multiplied the flash-loan balance across all children, allowing `exit2()` to extract vastly inflated SNK rewards.

## Vulnerability Details
- **CWE-682**: The reward formula was `reward = rewardPerToken × sum(childBalances)` without isolating rewards to only legitimately staked amounts. By creating child contracts at reward-claim time with large flash-loaned balances and binding them to existing parents, the reward numerator multiplied by the flash balance rather than the long-term stake.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: SNKMiner.sol
    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];  // ❌
    }

// ...

    function withdraw(uint256 amount,uint256 feeAmount) internal {
        _totalSupply = _totalSupply.sub(amount);
        _balances[msg.sender] = _balances[msg.sender].sub(amount);  // ❌
        y.transfer(msg.sender, amount.sub(feeAmount));
    }

// ...

    function nodeEarned(address account) public view returns (uint256) {
        if (block.timestamp < starttime) {
            return 0;
        }

        uint256 node = getUserNode(account);

        uint256 e1;
        uint256 e2;
        uint256 e3;
        uint256 e4;
        if (node == 4) {
            e1 = nodeRewardPerToken(1).sub(nodeUserRewardPerTokenPaid1[account]).div(precision);  // ❌
            e2 = nodeRewardPerToken(2).sub(nodeUserRewardPerTokenPaid2[account]).div(precision);  // ❌
            e3 = nodeRewardPerToken(3).sub(nodeUserRewardPerTokenPaid3[account]).div(precision);  // ❌
            e4 = nodeRewardPerToken(4).sub(nodeUserRewardPerTokenPaid4[account]).div(precision);  // ❌
        } else if (node == 3) {
            e1 = nodeRewardPerToken(1).sub(nodeUserRewardPerTokenPaid1[account]).div(precision);  // ❌
            e2 = nodeRewardPerToken(2).sub(nodeUserRewardPerTokenPaid2[account]).div(precision);  // ❌
            e3 = nodeRewardPerToken(3).sub(nodeUserRewardPerTokenPaid3[account]).div(precision);  // ❌
        } else if (node == 2) {
            e1 = nodeRewardPerToken(1).sub(nodeUserRewardPerTokenPaid1[account]).div(precision);  // ❌
            e2 = nodeRewardPerToken(2).sub(nodeUserRewardPerTokenPaid2[account]).div(precision);  // ❌
        } else if (node == 1) {
            e1 = nodeRewardPerToken(1).sub(nodeUserRewardPerTokenPaid1[account]).div(precision);  // ❌
        }

        return e1+e2+e3+e4+nodeRewards[account];
    }

// ...

    function rewardPerToken() internal view returns (uint256) {  // ❌
        if (totalSupply() == 0) {
            return rewardPerTokenStored;  // ❌
        }
        uint256 lastTime = 0;
        if (flag) {
            lastTime = lastUpdateTime;
        } else {
            lastTime = starttime;
        }

        return
            rewardPerTokenStored.add(  // ❌
                lastTimeRewardApplicable()
                    .sub(lastTime)
                    .mul(rewardRate)
                    .mul(precision)
                    .div(totalSupply())
            );
    }

// ...

    function getCommunityBalanceOf(address user) public view returns (uint256) {
        return communityBalances[user];  // ❌
    }
```

## Attack Flow (from testExploit())
```solidity
// 1. Deploy 10 HackerTemplate parent contracts
// 2. Transfer 100 SNK to each, call stake()
// 3. vm.warp(+20 days)
// 4. Pair.swap(80_000e18 SNK, 0, address(this), data)
//    → pancakeCall():
//      a. Deploy 10 new HackerTemplate child contracts
//      b. Each child: SNKMinter.bindParent(parentAddr)
//      c. Transfer accumulated SNK to child contracts
//      d. child.stake()  → stake large flash balance as child
//      e. parent.exit2() → claim rewards inflated by children's balances
//      f. child.exit1()  → exit children
//    e. Repay 85,000 SNK to pair
```

## Interfaces from PoC
```solidity
interface ISNKMinter {
    function bindParent(address parent) external;
    function stake() external;
    function getReward() external;
    function exit() external;
}

interface IPancakePair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| SNK Token | 0x05e2899179003d7c328de3C224e9dF2827406509 |
| SNKMinter | 0xA3f5ea945c4970f48E322f1e70F4CC08e70039ee |
| PancakePool | 0x7957096Bd7324357172B765C4b0996Bb164ebfd4 |
| BUSD | 0x55d398326f99059fF775485246999027B3197955 |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |

## Root Cause
`rewardPerToken` was multiplied by all children's current balances at claim time rather than by each child's time-weighted staked amount. Flash loan-funded child contracts created immediately before `exit2()` inflated the reward denominator.

## Fix
```solidity
// Track per-staker time-weighted balance; reward only based on own long-term stake:
struct StakeInfo {
    uint256 amount;
    uint256 stakedAt;
    uint256 rewardDebt;
}
mapping(address => StakeInfo) public stakes;

// Rewards computed per-staker, not aggregated from children:
function earned(address account) public view returns (uint256) {
    StakeInfo memory s = stakes[account];
    return s.amount * (rewardPerTokenStored - s.rewardDebt) / 1e18;
}
```

## References
- BSC SNKMinter: 0xA3f5ea945c4970f48E322f1e70F4CC08e70039ee
- 10 parent + 10 child contract attack pattern