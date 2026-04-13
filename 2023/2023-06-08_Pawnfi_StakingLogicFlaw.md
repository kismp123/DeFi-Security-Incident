# Pawnfi — APE Staking Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-08 |
| **Protocol** | Pawnfi |
| **Chain** | Ethereum |
| **Loss** | ~820K USD |
| **Attacker** | [0x8f7370d5...](https://etherscan.io/address/0x8f7370d5d461559f24b83ba675b4c7e2fdb514cc) |
| **Attack Contract** | [0xb618d91f...](https://etherscan.io/address/0xb618d91fe014bfcb9c8d440468b6c78e9ada9da1) |
| **Attack Tx** | [0x8d3036371...](https://etherscan.io/tx/0x8d3036371ccf27579d3cb3d4b4b71e99334cae8d7e8088247517ec640c7a59a5) |
| **Vulnerable Contract** | [0x85018CF6...](https://etherscan.io/address/0x85018CF6F53c8bbD03c3137E71F4FCa226cDa92C) |
| **Root Cause** | Arbitrary tokenId staking possible without validating APE staking DepositInfo |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/Pawnfi_exp.sol) |

---
## 1. Vulnerability Overview

Pawnfi provides functionality for staking APE coins using BAYC/MAYC NFTs as collateral. During processing of the `DepositInfo` struct in the `ApeStaking` contract, ownership validation of the `mainTokenIds` and `bakcTokenIds` arrays is insufficient, allowing an attacker to use NFT IDs they do not own to intercept APE staking rewards belonging to other users.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Missing DepositInfo validation
interface ApeStakingStorage {
    struct DepositInfo {
        uint256[] mainTokenIds;   // ❌ No ownership validation
        uint256[] bakcTokenIds;   // ❌ Arbitrary ID can be specified
    }
}

// Vulnerable staking function
function depositWithBAKC(DepositInfo calldata info, ...) external {
    // ❌ No check that msg.sender owns the NFTs in mainTokenIds
    for (uint256 i = 0; i < info.mainTokenIds.length; i++) {
        // Staking with another user's tokenId → rewards accrue to attacker
        apeStaking.depositBAKC(info.mainTokenIds[i], info.bakcTokenIds[i], amount);
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ApeStaking.sol
    function _delUserDepositInfo(address userAddr, address nftAsset, uint256 nftId) internal returns (uint256 iTokenAmount){  // ❌
        NftInfo storage nftInfo = _nftInfo[nftAsset];
        iTokenAmount = nftInfo.iTokenAmount[nftId];
        delete nftInfo.depositor[nftId];
        delete nftInfo.iTokenAmount[nftId];

        UserInfo storage userInfo = _userInfo[userAddr];
        userInfo.depositIds[nftInfo.poolId].remove(nftId);
        userInfo.iTokenAmount[nftInfo.poolId] -= iTokenAmount;
    }

// ...

    function _withdrawNftFromLending(address userAddr, address nftAsset, uint256 nftId) internal {
        uint256 iTokenAmount = _delUserDepositInfo(userAddr, nftAsset, nftId);  // ❌
        (address iTokenAddr, address pTokenAddr, uint256 pieceCount, , ) = INftGateway(nftGateway).marketInfo(nftAsset);

        uint balanceBefore = IERC20Upgradeable(pTokenAddr).balanceOf(address(this));
        ITokenLending(iTokenAddr).redeem(iTokenAmount);
        uint balanceAfter = IERC20Upgradeable(pTokenAddr).balanceOf(address(this));
        uint256 redeemAmount = balanceAfter - balanceBefore;
        require(redeemAmount >= pieceCount,"less");

        uint256[] memory tokenIds = new uint256[](1);  // ❌
        tokenIds[0] = nftId;  // ❌
        IPTokenApeStaking(pTokenAddr).withdraw(tokenIds);  // ❌
        IERC721Upgradeable(nftAsset).safeTransferFrom(address(this), userAddr, nftId);
        uint256 remainingAmount = redeemAmount - pieceCount;
        _transferAsset(pTokenAddr, userAddr, remainingAmount);
        emit WithdrawNftFromStake(userAddr, nftAsset, nftId, redeemAmount, pieceCount);
    }

// ...

    function _withdraw(address userAddr, address nftAsset, uint256 nftId, bool paired) internal {
        NftInfo storage nftInfo = _nftInfo[nftAsset];
        require(userAddr == nftInfo.depositor[nftId],"depositor");
        require(nftInfo.staker[nftId] == address(0),"staker");

        if(!paired) {
            (uint256 tokenId,bool isPaired) = IApeCoinStaking(apeCoinStaking).mainToBakc(nftInfo.poolId, nftId);  // ❌
            if(isPaired){
                require(_nftInfo[BAKC_ADDR].staker[tokenId] == address(0),"pair");  // ❌
            }
        }
        _withdrawNftFromLending(userAddr, nftAsset, nftId);
    }

// ...

    function _onStopStake(address nftAsset, uint256 nftId, RewardAction actionType) private {
        NftInfo storage nftInfo = _nftInfo[nftAsset];
        IApeCoinStaking.SingleNft[] memory _nfts;
        PairVars memory pairVars;

        address userAddr = nftInfo.staker[nftId];
        if(nftAsset == BAYC_ADDR || nftAsset == MAYC_ADDR) {
            pairVars.nftAsset = nftAsset;
            pairVars.mainTokenId = nftId;  // ❌
            ( , uint256 stakingAmount, ) = getStakeInfo(nftInfo.poolId, nftId);
            (pairVars.bakcTokenId, pairVars.isPaired) = IApeCoinStaking(apeCoinStaking).mainToBakc(nftInfo.poolId, nftId);  // ❌

            if(stakingAmount > 0 && userAddr != address(0)) {
                _nfts = new IApeCoinStaking.SingleNft[](1);
                _nfts[0] = IApeCoinStaking.SingleNft({
                    tokenId: uint32(nftId),  // ❌
                    amount: uint224(stakingAmount)
                });
            }
        } else if(nftAsset == BAKC_ADDR) {
            pairVars.nftAsset = BAYC_ADDR;
            pairVars.bakcTokenId = nftId;  // ❌
            (pairVars.mainTokenId, pairVars.isPaired) = IApeCoinStaking(apeCoinStaking).bakcToMain(nftId, _nftInfo[pairVars.nftAsset].poolId);  // ❌
            if(!pairVars.isPaired) {
                pairVars.nftAsset = MAYC_ADDR;
                (pairVars.mainTokenId, pairVars.isPaired) = IApeCoinStaking(apeCoinStaking).bakcToMain(nftId, _nftInfo[pairVars.nftAsset].poolId);  // ❌
            }
        }

        _onStopStakePairNft(userAddr, pairVars, _nfts, actionType);
    }

// ...

    function _onStopStakePairNft(address mainUserAddr, PairVars memory pairVars, IApeCoinStaking.SingleNft[] memory _nfts, RewardAction actionType) internal {
        IApeCoinStaking.PairNftWithdrawWithAmount[] memory _nftPairs;
        address bakcUserAddr = _nftInfo[BAKC_ADDR].staker[pairVars.bakcTokenId];  // ❌
        if(pairVars.isPaired) {
            ( , uint256 stakingAmount, ) = getStakeInfo(_nftInfo[BAKC_ADDR].poolId, pairVars.bakcTokenId);  // ❌
            if(stakingAmount > 0 && bakcUserAddr != address(0)) {
                _nftPairs = new IApeCoinStaking.PairNftWithdrawWithAmount[](1);
                _nftPairs[0] = IApeCoinStaking.PairNftWithdrawWithAmount({
                    mainTokenId: uint32(pairVars.mainTokenId),  // ❌
                    bakcTokenId: uint32(pairVars.bakcTokenId),  // ❌
                    amount: uint184(stakingAmount),
                    isUncommit: true
                });
            }

        }
        if(_nfts.length > 0 || _nftPairs.length > 0) {
            address userAddr = mainUserAddr != address(0) ? mainUserAddr : bakcUserAddr;
            _withdrawApeCoin(userAddr, pairVars.nftAsset, _nfts, _nftPairs, actionType);
        }
    }
```

```solidity
// File: IERC721Upgradeable.sol
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.  // ❌

// ...

    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);  // ❌

// ...

    function ownerOf(uint256 tokenId) external view returns (address owner);  // ❌

// ...

    function approve(address to, uint256 tokenId) external;  // ❌

// ...

    function getApproved(uint256 tokenId) external view returns (address operator);  // ❌
```

```solidity
// File: IApeCoinStaking.sol
        uint32 tokenId;  // ❌

// ...

        uint256 tokenId;  // ❌

// ...

        uint256 mainTokenId;  // ❌

// ...

        uint32 mainTokenId;  // ❌

// ...

        uint32 bakcTokenId;  // ❌
```

```solidity
// File: ApeStakingStorage.sol
        uint256[] mainTokenIds;  // ❌

// ...

        uint256[] bakcTokenIds;  // ❌

// ...

    event StakePairNft(address userAddr, address nftAsset, uint256 mainTokenId, uint256 bakcTokenId, uint256 amount);  // ❌

// ...

    event UnstakePairNft(address userAddr, address nftAsset, uint256 mainTokenId, uint256 bakcTokenId, uint256 amount, uint256 rewardAmount);  // ❌

// ...

    event ClaimPairNft(address userAddr, address nftAsset, uint256 mainTokenId, uint256 bakcTokenId, uint256 rewardAmount);  // ❌
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────┐
│  1. Identify victim's BAYC/MAYC tokenId          │
│     (publicly verifiable via on-chain data)      │
└──────────────────────────────┬───────────────────┘
                               ▼
┌──────────────────────────────────────────────────┐
│  2. depositWithBAKC(mainTokenIds=[victim_id])    │
│     ❌ No ownership validation                   │
│     → Create APE staking position with           │
│       victim's NFT                               │
└──────────────────────────────┬───────────────────┘
                               ▼
┌──────────────────────────────────────────────────┐
│  3. Claim staking rewards                        │
│     → APE rewards associated with victim's NFT  │
│       are paid out to the attacker               │
└──────────────────────────────┬───────────────────┘
                               ▼
┌──────────────────────────────────────────────────┐
│  4. ~820K USD worth of APE tokens stolen         │
└──────────────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // 1. Identify victim's staked BAYC tokenId
    uint256 victimTokenId = getVictimTokenId();

    ApeStakingStorage.DepositInfo memory info;
    info.mainTokenIds = new uint256[](1);
    info.mainTokenIds[0] = victimTokenId;  // ❌ Victim's tokenId
    info.bakcTokenIds = new uint256[](1);
    info.bakcTokenIds[0] = attackerBakcId;

    // 2. Stake using victim's NFT with no ownership validation
    pawnfi.depositWithBAKC(info, apeAmount);

    // 3. Claim rewards
    pawnfi.claimBAKC(info);

    emit log_named_decimal_uint("Stolen APE rewards", ape.balanceOf(address(this)), 18);
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Missing NFT tokenId ownership validation | CRITICAL | CWE-284 | 03_access_control.md |
| V-02 | No input validation on staking DepositInfo | HIGH | CWE-20 | 11_logic_error.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ Validate NFT ownership before staking
function depositWithBAKC(DepositInfo calldata info, ...) external {
    for (uint256 i = 0; i < info.mainTokenIds.length; i++) {
        // ✅ Verify the caller owns the NFT
        require(
            bayc.ownerOf(info.mainTokenIds[i]) == msg.sender ||
            pawnfi.ownerOf(info.mainTokenIds[i]) == msg.sender,
            "Not NFT owner"
        );
    }
}
```

## 7. Lessons Learned

When protocols that use NFTs as collateral accept a tokenId array as input, ownership of each ID must always be validated. Attacks exploiting publicly available on-chain tokenId information can be carried out without any prior off-chain reconnaissance.