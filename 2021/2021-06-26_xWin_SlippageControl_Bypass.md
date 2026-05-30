# xWin Finance — Flash Loan Vulnerability Analysis: Missing Slippage Control

| Field | Details |
|------|------|
| **Date** | 2021-06-26 |
| **Protocol** | xWin Finance |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$80,000 |
| **Attacker** | [0xb63f...d19](https://bscscan.com/address/0xb63f0d8b9aa0c4e68d5630f54bfefc6cf2c2ad19) |
| **Attack Tx** | [0xba0f...c1d](https://bscscan.com/tx/0xba0fa8c150b2408eec9bbbbfe63f9ca63e99f3ff53ac46ee08d691883ac05c1d) (block 8,589,726) |
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


### On-Chain Source Code

Source: **Sourcify-verified** (partial match) — `xWinDefi.sol` / `0x1Bf7fe7568211ecfF68B6bC7CCAd31eCd8fe8092` (BSC)
Sourcify URL: https://sourcify.dev/server/files/any/56/0x1Bf7fe7568211ecfF68B6bC7CCAd31eCd8fe8092

> Note: The orchestrator contract (`xWinDefi`) is Sourcify-verified. The underlying xWin Fund contract (`PCLPXWIN` at `0x8f52e0C41164169818C1FB04B263FDC7c1e56088`) where the swap executes is **not verified on Sourcify**. The Fund's swap logic is reconstructed from the PoC below.

**Verified — xWinDefi.sol `Subscribe()` (orchestrator that forwards TradeParams including attacker-supplied `priceImpactTolerance`):**

```solidity
// Source: Sourcify partial match — xWinDefi.sol (0x1Bf7fe7568211ecfF68B6bC7CCAd31eCd8fe8092, BSC)

// TradeParams struct (from xWinLib):
// struct TradeParams {
//   address xFundAddress;
//   uint256 amount;
//   uint256 priceImpactTolerance;   // ❌ caller-supplied — attacker sets 10_000 (100%)
//   uint256 deadline;               // ❌ caller-supplied — attacker sets 99999999999
//   bool returnInBase;
//   address referral;
// }

function Subscribe(xWinLib.TradeParams memory _tradeParams)
    public nonReentrant onlyNonEmergency payable
{
    require(isxwinFund[_tradeParams.xFundAddress] == true, "not xwin fund");
    xWinLib.xWinReferral memory _xWinReferral = xWinReferral[msg.sender];
    require(msg.sender != _tradeParams.referral, "referal cannot be own address");

    if (_xWinReferral.referral != address(0)) {
        require(_xWinReferral.referral == _tradeParams.referral, "already had referral");
    }
    xWinFund _xWinFund = xWinFund(_tradeParams.xFundAddress);
    TransferHelper.safeTransferBNB(_tradeParams.xFundAddress, _tradeParams.amount);
    // ❌ _tradeParams.priceImpactTolerance (set to 10_000 by attacker) is passed verbatim
    //    into _xWinFund.Subscribe(), which uses it as the slippage tolerance on DEX swaps.
    //    A value of 10_000 (100%) imposes NO effective limit on price impact.
    uint256 mintQty = _xWinFund.Subscribe(_tradeParams, msg.sender); // ❌

    if (rewardRemaining > 0) {
        _storeRewardQty(msg.sender, _tradeParams.amount, mintQty);
        _updateReferralReward(_tradeParams, _xWinFund.getWhoIsManager());
    }
    emit _Subscribe(msg.sender, _tradeParams.xFundAddress, _tradeParams.amount, mintQty);
}
```

**xWin Fund swap — reconstructed (0x8f52, not verified on Sourcify):**

```solidity
// ⚠️ RECONSTRUCTED — not verified source. Derived from PoC + on-chain trace.
// xWinFund (PCLPXWIN) — 0x8f52e0C41164169818C1FB04B263FDC7c1e56088

function Subscribe(xWinLib.TradeParams memory _tradeParams, address _investorAddress)
    external payable returns (uint256 mintQty)
{
    // BNB forwarded by the orchestrator is swapped into fund constituent tokens
    // ❌ priceImpactTolerance from _tradeParams is used directly as slippage limit
    _swapBNBToAllTokens(_tradeParams.amount, _tradeParams.priceImpactTolerance, _tradeParams.deadline);
    // ...mint fund shares to _investorAddress proportionally...
}

function _swapBNBToAllTokens(uint256 _amount, uint256 _priceImpactTolerance, uint256 _deadline) internal {
    for (uint i = 0; i < targetToken.length; i++) {
        uint256 tokenQty = _amount * targetWeight[i] / totalWeight;
        uint256 expectedOut = _getExpectedOut(tokenQty, targetToken[i]);
        // ❌ minOut calculated using caller-supplied priceImpactTolerance
        // With _priceImpactTolerance = 10_000 (100%), minOut = expectedOut * 0 / 10_000 = 0
        uint256 minOut = expectedOut * (10_000 - _priceImpactTolerance) / 10_000; // ❌ = 0
        router.swapExactETHForTokens{value: tokenQty}(
            minOut,           // ❌ effectively 0 — any price accepted
            _getPath(targetToken[i]),
            address(this),
            _deadline         // ❌ 99999999999 — far-future deadline
        );
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- The orchestrator's `Subscribe()` accepts `priceImpactTolerance` from `TradeParams` without validation — the attacker supplies `10_000` (100%).
- Inside `_swapBNBToAllTokens`, `minOut = expectedOut * (10_000 − 10_000) / 10_000 = 0` — the router is told to accept **any output amount**, no matter how bad the price.
- The attacker flash-loans 76,000 BNB and calls `Subscribe()` 20 times. Each call pushes a large BNB amount into the XWIN pair with zero slippage protection, allowing the price to spike freely.
- Because referral rewards accumulate on each `Subscribe()`, the attacker additionally extracts XWIN referral tokens on each call.

```solidity
// ✅ Fix: cap priceImpactTolerance server-side; do not accept it from the caller
uint256 public constant MAX_PRICE_IMPACT_BPS = 200; // 2%

function Subscribe(xWinLib.TradeParams memory _tradeParams) external payable nonReentrant {
    // ✅ Enforce cap regardless of what caller provides
    uint256 safeTolerance = _tradeParams.priceImpactTolerance > MAX_PRICE_IMPACT_BPS
        ? MAX_PRICE_IMPACT_BPS
        : _tradeParams.priceImpactTolerance;
    uint256 safeDeadline = block.timestamp + 300; // ✅ 5-minute max
    _xWinFund.Subscribe(
        // override caller-supplied values
        _tradeParams.xFundAddress, _tradeParams.amount, safeTolerance, safeDeadline, ...
    );
}
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