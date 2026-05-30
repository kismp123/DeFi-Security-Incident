# Wault Finance — WUSDMASTER Price Manipulation Flash Loan Analysis

| Item | Details |
|------|------|
| **Date** | 2021-08-27 |
| **Protocol** | Wault Finance |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$803,000 |
| **Attacker** | Address unidentified |
| **Attack Tx** | Address unidentified |
| **Vulnerable Contract** | WUSDMASTER (WUSD → BUSD redemption and WEX staking) |
| **Root Cause** | `stake()` was called 68 times in a single transaction without slippage protection (`minOut = 0`) and without per-block rate limiting, each call executing a USDT→WEX AMM swap; repeated calls cumulatively distorted WEX/USDT reserves, allowing the attacker to profit from WEX price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-08/WaultFinance_exp.sol) |

---
## 1. Vulnerability Overview

Wault Finance's WUSDMASTER includes a mechanism that stakes WEX tokens upon WUSD redemption. The attacker borrowed nearly all WUSD via a flash loan, then repeatedly triggered WEX staking 68 times through the WUSDMASTER redemption process, artificially manipulating the WEX/USDT pair price. The attacker then profited from arbitrage between USDT and WEX using the distorted price.

---
## 2. Vulnerable Code Analysis

### 2.1 WUSDMASTER.redeem() — Allows Price Manipulation via Repeated Staking

```solidity
// ❌ WUSDMASTER — WEX staking on redemption; repeated calls allow price manipulation
function redeem(uint256 wusdAmount) external {
    // WUSD → BUSD redemption
    uint256 busdOut = wusdAmount; // assumes 1:1 peg
    WUSD.burn(msg.sender, wusdAmount);

    // WEX staking (internally modifies WaultSwap pair state)
    // ❌ Repeated calls continuously shift WEX/USDT pair reserves
    _stakeWEX(busdOut);

    BUSD.transfer(msg.sender, busdOut);
}

function _stakeWEX(uint256 amount) internal {
    // BUSD → WEX swap (changes pair reserves)
    // WEX staking → additional pair state changes
    // 68 repetitions cumulatively distort WEX price
}
```

**Fixed Code**:
```solidity
// ✅ Limit staking count per redeem() call + slippage protection
uint256 public constant MAX_STAKE_PER_REDEEM = 1;

function redeem(uint256 wusdAmount) external nonReentrant {
    require(wusdAmount >= minRedeemAmount, "WUSDMASTER: amount too small");

    WUSD.burn(msg.sender, wusdAmount);

    // Single staking only + slippage limit
    uint256 wexBefore = WEX.balanceOf(address(this));
    _stakeWEXOnce(wusdAmount);
    uint256 wexReceived = WEX.balanceOf(address(this)) - wexBefore;
    require(wexReceived >= minWexOut, "WUSDMASTER: slippage too high");

    BUSD.transfer(msg.sender, wusdAmount);
}
```


### On-Chain Original Code

Source: **Sourcify-verified** — WUSDMASTER / 0xa79Fe386B88FBee6e492EEb76Ec48517d1eC759a (BSC)
BSCScan verified source: https://bscscan.com/address/0xa79Fe386B88FBee6e492EEb76Ec48517d1eC759a#code

> Note: The doc's root cause description incorrectly attributed the vulnerability to `redeem()`. The real vulnerable function is `stake()`. The attacker called `redeem()` once to obtain WEX and USDT, then called `stake()` 68 times in a loop to repeatedly execute USDT→WEX swaps without slippage protection, cumulatively distorting the WEX/USDT pair reserves.

```solidity
// ❌ Vulnerable: WUSDMASTER.stake() — called 68 times by attacker
// Source: BSCScan verified — 0xa79Fe386B88FBee6e492EEb76Ec48517d1eC759a (BSC)
function stake(uint256 amount) external nonReentrant {
    require(amount <= maxStakeAmount, 'amount too high');
    usdt.safeTransferFrom(msg.sender, address(this), amount);
    if (feePermille > 0) {
        uint256 feeAmount = amount * feePermille / 1000;
        usdt.safeTransfer(treasury, feeAmount);
        amount = amount - feeAmount;
    }
    uint256 wexAmount = amount * wexPermille / 1000;
    usdt.approve(address(wswapRouter), wexAmount);
    wswapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens( // ❌ AMM swap with 0 minOut
        wexAmount,
        0,              // ❌ minOut = 0: no slippage protection
        swapPath,       // USDT → WEX
        address(this),
        block.timestamp
    );
    wusd.mint(msg.sender, amount);
    emit Stake(msg.sender, amount);
}

// Also shown for completeness — redeem() is called once, then stake() 68x
function redeem(uint256 amount) external nonReentrant {
    uint256 usdtTransferAmount = amount * (1000 - wexPermille - treasuryPermille) / 1000;
    uint256 usdtTreasuryAmount = amount * treasuryPermille / 1000;
    uint256 wexTransferAmount = wex.balanceOf(address(this)) * amount / wusd.totalSupply(); // ❌ WEX distributed proportionally
    wusd.burn(msg.sender, amount);
    usdt.safeTransfer(treasury, usdtTreasuryAmount);
    usdt.safeTransfer(msg.sender, usdtTransferAmount);
    wex.safeTransfer(msg.sender, wexTransferAmount);
    emit Redeem(msg.sender, amount);
}
```

**Why it is exploitable (identify the bug from the code):**
- `stake()` executes a USDT→WEX swap via `swapExactTokensForTokensSupportingFeeOnTransferTokens` with `minOut = 0` (no slippage protection) on line calling `wswapRouter`.
- Each individual `stake(250_000e18)` call buys WEX from the pair, pushing the WEX price up. Calling this 68 times in one transaction cumulatively moves the WEX/USDT price by a large amount.
- The attacker first calls `redeem()` to extract WEX from the contract, then calls `stake()` 68 times using flash-loaned USDT, driving the WEX price up. Finally, the WEX received from `redeem()` is sold at the inflated price for profit.
- `maxStakeAmount` per call does not prevent repeated calls in a single transaction.

```solidity
// ✅ Fix: add per-block staking rate limit and slippage protection
function stake(uint256 amount) external nonReentrant {
    require(amount <= maxStakeAmount, 'amount too high');
    // ✅ Rate limit: track USDT staked this block
    require(block.number > lastStakeBlock, 'one stake per block');
    lastStakeBlock = block.number;

    usdt.safeTransferFrom(msg.sender, address(this), amount);
    uint256 wexAmount = amount * wexPermille / 1000;
    uint256 minWexOut = getMinWexOut(wexAmount); // ✅ slippage check from TWAP
    usdt.approve(address(wswapRouter), wexAmount);
    wswapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        wexAmount,
        minWexOut,  // ✅ enforce minimum output
        swapPath,
        address(this),
        block.timestamp
    );
    wusd.mint(msg.sender, amount);
}
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────┐
│ Step 1: WaultSwap Flash Loan — borrow nearly all WUSD    │
│ waultSwapPair.swap(wusdAmount, 0, this, data)           │
└─────────────────────┬────────────────────────────────────┘
                      │ waultSwapCall() callback
┌─────────────────────▼────────────────────────────────────┐
│ Step 2: WUSDMASTER.redeem(wusd)                          │
│ Internal _stakeWEX() called 68 times → cumulative        │
│ WEX/USDT price distortion                                │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 3: Arbitrage using distorted WEX price              │
│ USDT → WEX (low price) → USDT (high price)               │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 4: Additional profit settlement in PancakeSwap      │
│ callback (pancakeCall)                                   │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 5: All assets → BUSD conversion + flash loan repay  │
└──────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// waultSwapCall() — flash loan callback
function waultSwapCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // Manipulate WEX/USDT price via WUSDMASTER.redeem()
    // Internally repeats _stakeWEX 68 times
    WUSDMASTER.redeem(WUSD.balanceOf(address(this)));

    // Swap USDT→WEX at distorted price (buy low)
    // waultSwapRouter.swapExactTokensForTokens(usdt, 0, [USDT, WEX], ...)

    // Swap WEX→USDT (sell high) — triggers PancakeSwap callback
    // pancakePair.swap(0, wexAmount, this, data)
}

// pancakeCall() — additional arbitrage
function pancakeCall(...) external {
    // Realize profit via WEX→USDT reverse swap
    // Convert all → BUSD
    // Repay flash loan
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Repeated `_stakeWEX()` calls inside `redeem()` perform AMM swaps without slippage protection — each call cumulatively distorts WEX/USDT reserves | CRITICAL | CWE-20 |
| V-02 | Coupling of `redeem()` with WEX staking logic — unnecessary repeated swaps executed within the redemption function | HIGH | CWE-829 |

> **Root Cause**: A single `redeem()` call executes 68 unslippage-protected internal swaps. The flash loan is merely a vehicle to redeem a large amount of WUSD in one transaction; adding slippage limits and call count limits to `_stakeWEX()` renders this attack impossible even without a flash loan.

---
## 6. Remediation Recommendations

```solidity
// ✅ Limit swaps inside redeem() to once + verify minimum received amount
// ✅ Separate WUSD redemption logic from staking logic

function redeem(uint256 wusdAmount) external nonReentrant {
    WUSD.burn(msg.sender, wusdAmount);

    // Return pure BUSD without staking
    BUSD.transfer(msg.sender, wusdAmount);
    // Staking separated into a dedicated transaction
    emit Redeemed(msg.sender, wusdAmount);
}
```

---
## 7. Lessons Learned

- **The root cause is repeated slippage-unprotected swaps inside `redeem()`.** Adding per-swap slippage limits alone is sufficient to block cumulative price distortion.
- **The flash loan is simply a means to concentrate a large WUSD redemption into a single transaction to maximize the number of swaps.** Once slippage protection and swap count limits are applied, the attack cannot succeed even without a flash loan.
- **Coupling redemption functions with staking logic creates an unnecessary attack surface.** These concerns should be separated according to the single responsibility principle.