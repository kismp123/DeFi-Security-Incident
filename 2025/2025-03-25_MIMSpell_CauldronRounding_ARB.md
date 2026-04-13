# Abracadabra Money (MIM) — Cauldron Phantom Collateral / Accounting Discrepancy Analysis

| Item | Details |
|------|---------|
| **Date** | 2025-03-25 |
| **Protocol** | Abracadabra Money (MIM / Spell) |
| **Chain** | Arbitrum |
| **Loss** | $13,408,309 (≈ 6,262 ETH) |
| **Attacker (primary)** | [0xe9A4...F2f39](https://arbiscan.io/address/0xe9A4034E89608Df1731835A3Fd997fd3a82F2f39) |
| **Attack Contract** | [0xf291...1c9c](https://arbiscan.io/address/0xf29120acd274a0c60a181a37b1ae9119fe0f1c9c) |
| **Attack Tx (largest)** | [0xe93e...6123](https://arbiscan.io/tx/0xe93ec4b5a5c96dbc2cf9321b29f38c7ae3f667986bee37696c8f0ed5e5ca6123) |
| **Vulnerable Contracts** | [GmxV2CauldronRouterOrder + 5 Cauldrons](#vulnerable-contract-list) |
| **Root Cause** | `sendValueInCollateral()` does not update internal accounting variables (`inputAmount`, `minOut`) after actually withdrawing tokens, enabling repeated borrowing against phantom collateral |
| **Attack Duration** | ~100 minutes (07:57 UTC – 09:37 UTC), 56 transactions |
| **References** | [Three Sigma Analysis](https://threesigma.xyz/blog/exploit/abracadabra-gmx-defi-exploit-explained) · [Halborn Explanation](https://www.halborn.com/blog/post/explained-the-abracadabra-money-hack-march-2025) |

---

### Vulnerable Contract List

| Contract | Address | Role |
|----------|---------|------|
| gmETH/ETH Cauldron | [0x625F...bD61](https://arbiscan.io/address/0x625Fe79547828b1B54467E5Ed822a9A8a074bD61) | Primary attack target |
| gmETH Cauldron | [0x2b02...4bFA](https://arbiscan.io/address/0x2b02bBeAb8eCAb792d3F4DDA7a76f63Aa21934FA) | Affected market |
| gmBTC Cauldron | [0xD765...52A](https://arbiscan.io/address/0xD7659D913430945600dfe875434B6d80646d552A) | Affected market |
| gmSOL Cauldron | [0x7962...b7](https://arbiscan.io/address/0x7962ACFcfc2ccEBC810045391D60040F635404fb) | Affected market |
| gmBTC/BTC Cauldron | [0x9fF8...831](https://arbiscan.io/address/0x9fF8b4C842e4a95dAB5089781427c836DAE94831) | Affected market |

---

## 1. Vulnerability Overview

Abracadabra Money operated a **gmCauldron** system that allowed users to borrow MIM (Magic Internet Money) using GMX V2 GM tokens (liquidity pool shares) as collateral. Because GMX V2 uses an asynchronous deposit/withdrawal model, Abracadabra managed GMX orders through an intermediary contract called `GmxV2CauldronRouterOrder`.

This architecture contained two critical accounting flaws:

1. **Phantom Collateral**: The `sendValueInCollateral()` function did not update internal tracking variables (`inputAmount`, `minOut`, `minOutLong`) after withdrawing actual tokens. As a result, `orderValueInCollateral()` continued to return collateral value for tokens that had already been withdrawn.

2. **Self-Liquidation Exploit**: The attacker created intentionally failing GMX deposits to leave USDC stranded in the RouterOrder contract, then self-liquidated to extract real tokens while the phantom collateral persisted.

3. **Bypassing the Final Check in `cook()` Batch Processing**: The `_isSolvent()` check is executed only once at the end of a `cook()` batch, at which point `orderValueInCollateral()` returns a stale value, falsely indicating sufficient collateral.

---

## 2. Vulnerable Code Analysis

### 2.1 `sendValueInCollateral()` — Accounting Variables Not Updated (Core Vulnerability)

```solidity
// ❌ Vulnerable code — no internal state update after actual token withdrawal
function sendValueInCollateral(
    address recipient,
    uint256 shareMarketToken
) public onlyCauldron {
    (uint256 shortExchangeRate, uint256 marketExchangeRate) = getExchangeRates();

    // Transfers actual shortToken (e.g., USDC) to DegenBox
    uint256 amountShortToken = (degenBox.toAmount(IERC20(market), shareMarketToken, true) *
        oracleDecimalScale) / (shortExchangeRate * marketExchangeRate);

    shortToken.safeTransfer(address(degenBox), amountShortToken);
    degenBox.deposit(IERC20(shortToken), address(degenBox), recipient, amountShortToken, 0);

    // ❌ Problem: inputAmount, minOut, minOutLong are never decremented
    // After this function returns, orderValueInCollateral() still returns
    // the same amount as before the withdrawal
}
```

```solidity
// ✅ Fixed code — internal accounting variables proportionally decremented after withdrawal
function sendValueInCollateral(
    address recipient,
    uint256 shareMarketToken
) public onlyCauldron {
    (uint256 shortExchangeRate, uint256 marketExchangeRate) = getExchangeRates();

    uint256 amountShortToken = (degenBox.toAmount(IERC20(market), shareMarketToken, true) *
        oracleDecimalScale) / (shortExchangeRate * marketExchangeRate);

    shortToken.safeTransfer(address(degenBox), amountShortToken);
    degenBox.deposit(IERC20(shortToken), address(degenBox), recipient, amountShortToken, 0);

    // ✅ Fix: decrement internal tracking variables by the actual withdrawn amount
    if (depositType) {
        // Deposit type: decrement inputAmount (in shortToken terms)
        uint256 shortEquivalent = amountShortToken;
        inputAmount = inputAmount >= shortEquivalent ? inputAmount - shortEquivalent : 0;
        if (minOut > shareMarketToken) {
            minOut -= shareMarketToken;
        } else {
            minOut = 0;
        }
    } else {
        // Withdrawal type: decrement inputAmount (in marketToken terms)
        inputAmount = inputAmount >= shareMarketToken ? inputAmount - shareMarketToken : 0;
        uint256 longEquivalent = shareMarketToken / 2; // simplified example
        if (minOutLong > longEquivalent) minOutLong -= longEquivalent;
        if (minOut > shareMarketToken - longEquivalent) minOut -= (shareMarketToken - longEquivalent);
    }
}
```

**Issue**: `sendValueInCollateral()` withdraws real assets but does not update internal state, causing `orderValueInCollateral()` to continue reporting phantom collateral value. This design flaw enables repeated borrowing against the same collateral.

---

### 2.2 `orderValueInCollateral()` — Collateral Valuation Based on Stale Data

```solidity
// ❌ Vulnerable code — collateral calculated using stale inputAmount/minOut
function orderValueInCollateral() public view returns (uint256 result) {
    (uint256 shortExchangeRate, uint256 marketExchangeRate) = getExchangeRates();

    if (depositType) {
        // ❌ inputAmount: still holds original value even after tokens were withdrawn
        uint256 marketTokenFromValue = (inputAmount * shortExchangeRate * marketExchangeRate) /
            oracleDecimalScale;
        // ❌ minOut: also not updated → returns phantom collateral
        result = minOut < marketTokenFromValue ? minOut : marketTokenFromValue;
    } else {
        uint256 marketTokenFromValue = ((minOut + minOutLong) * shortExchangeRate *
            marketExchangeRate) / oracleDecimalScale;
        result = inputAmount < marketTokenFromValue ? inputAmount : marketTokenFromValue;
    }
}
```

**Issue**: Even after `sendValueInCollateral()` has sent out real tokens, this function uses the unchanged `inputAmount` and `minOut` to compute collateral value. As a result, the Cauldron permits additional borrowing against already-exhausted collateral.

---

### 2.3 Deferred Solvency Check Within `cook()` Batch

```solidity
// ❌ Vulnerable pattern — single solvency check after all actions
function cook(
    uint8[] calldata actions,
    uint256[] calldata values,
    bytes[] calldata datas
) external payable returns (uint256 value1, uint256 value2) {
    CookStatus memory status;

    for (uint256 i = 0; i < actions.length; i++) {
        uint8 action = actions[i];
        if (action == ACTION_BORROW) {
            // Borrow → sets needsSolvencyCheck = true
            (status, value1, value2) = _cookActionBorrow(status, ...);
        } else if (action == ACTION_LIQUIDATE) {
            // Self-liquidation: calls sendValueInCollateral() → internal state not updated
            _cookActionLiquidate(...);
        } else if (action == ACTION_CALL) {
            // Allows arbitrary calls
            _cookActionCall(...);
        }
    }

    // ❌ Final check: orderValueInCollateral() returns stale value
    // → tokens already withdrawn are still counted as collateral → false pass
    if (status.needsSolvencyCheck) {
        require(_isSolvent(msg.sender), "Cauldron: user insolvent");
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker used 6 different wallet addresses to bypass per-address limits. Gas was funded via Tornado Cash, and intentionally failing deposits were created by setting an extremely high `minOut` value for GMX deposits.

### 3.2 Execution Phase

**`cook()` batch action sequence per transaction**:

1. **Action 5 (ACTION_BORROW)**: Initial MIM borrow → sets `needsSolvencyCheck = true`
2. **Action 30 (ACTION_CALL)**: Custom contract call to calculate liquidation amount
3. **Action 31 (ACTION_LIQUIDATE)**: Self-liquidation — `sendValueInCollateral()` withdraws real USDC from RouterOrder but internal state is not updated
4. **Action 30 (ACTION_CALL)**: Post-liquidation recalculation
5. **Action 5 (ACTION_BORROW)**: **Additional MIM borrow** backed by phantom collateral
6. **Action 30 (ACTION_CALL)**: Swap borrowed MIM to extract ETH
7. **Batch end**: `_isSolvent()` check → false pass due to stale value from `orderValueInCollateral()`

### 3.3 Attack Flow Diagram

```
Attacker Wallets (6)
    │
    │  Gas funded via Tornado Cash
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Phase 1: Create intentionally failing          │
│           GMX deposits                          │
│  ┌───────────────┐       ┌────────────────────┐ │
│  │ Attacker      │──────▶│ GMX RouterOrder    │ │
│  │ Wallet        │       │ (USDC stranded)    │ │
│  └───────────────┘       │ minOut set extreme │ │
│                          │ → deposit fails    │ │
│                          └────────────────────┘ │
└─────────────────────────────────────────────────┘
    │
    │  GMX deposit fails → USDC remains in RouterOrder
    │  Cauldron treats this as valid collateral
    ▼
┌─────────────────────────────────────────────────┐
│  Phase 2: cook() batch attack (repeated)        │
│                                                 │
│  [1] ACTION_BORROW ─────────────────────────┐  │
│      Initial MIM borrow (needsSolvencyCheck  │  │
│      = true)                                ▼  │
│  [2] ACTION_CALL                     ┌──────────┐│
│      Calculate liquidation amount    │Cauldron  ││
│                                     │(gmETH,   ││
│  [3] ACTION_LIQUIDATE ──────────────▶ etc.)    ││
│      sendValueInCollateral() called │          ││
│      → real USDC withdrawn          │ Internal ││
│      → inputAmount/minOut NOT    ❌ │ state not││
│        updated                      │ updated  ││
│                                     └──────────┘│
│  [4] ACTION_CALL                               │
│      Recalculate                               │
│                                               │
│  [5] ACTION_BORROW ─────────────────────────┐  │
│      Additional MIM borrow against       ❌  │  │
│      phantom collateral                     ▼  │
│  [6] ACTION_CALL                    ┌──────────┐│
│      Swap MIM → ETH                 │  DegenBox││
│                                     │  (MIM)   ││
│  [7] Batch end: _isSolvent() ───────▶          ││
│      orderValueInCollateral()       │ Phantom  ││
│      returns stale value         ❌ │ collateral││
│      → false pass                   │ false pass││
│                                     └──────────┘│
└─────────────────────────────────────────────────┘
    │
    │  5 Cauldrons × 6 wallets × multiple iterations
    │  56 transactions total, ~100 minutes
    ▼
┌─────────────────────────────────────────────────┐
│  Phase 3: Fund laundering and movement          │
│                                                 │
│  Arbitrum ETH ──▶ Arbitrum-Ethereum bridge      │
│                ──▶ Split across 3 Ethereum      │
│                    wallets                      │
│                ──▶ Tornado Cash mixing          │
└─────────────────────────────────────────────────┘

Total Loss: ≈ 6,262 ETH ($13,408,309)
```

### 3.4 Outcome

- **Attacker profit**: ≈ 6,262 ETH ($13,408,309)
- **Protocol loss**: All liquidity drained across 5 gmCauldrons
- **GMX price impact**: $55.20 → $46.92 (-15%)
- **MIM price impact**: $1.20 → $1.08 (-10%)
- **Protocol response**: Borrowing paused at 09:46 UTC, orderAgent set to zero address, ~$260,000 recovered from RouterOrder

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------------|----------|-----|-----------------|
| V-01 | Accounting discrepancy — state variables not updated | CRITICAL | CWE-682 (Incorrect Calculation) | `16_accounting_sync.md` |
| V-02 | Self-liquidation permitted | HIGH | CWE-284 (Improper Access Control) | `18_liquidation.md` |
| V-03 | Deferred Solvency Check | HIGH | CWE-754 (Improper Check) | `11_logic_error.md` |
| V-04 | Async external protocol integration — intermediate state exposure | MEDIUM | CWE-362 (Race Condition) | `12_bridge_crosschain.md` |

### V-01: Accounting Discrepancy — `sendValueInCollateral()` State Not Updated

- **Description**: `sendValueInCollateral()` withdraws real shortTokens (USDC) from the RouterOrder but does not update the internal variables `inputAmount`, `minOut`, or `minOutLong` used to compute collateral value. Consequently, `orderValueInCollateral()` continues to return phantom collateral value for already-exhausted assets.
- **Impact**: Enables repeated MIM borrowing against the same collateral, draining all protocol liquidity.
- **Attack conditions**: (1) Residual funds in RouterOrder, (2) self-liquidation permitted, (3) borrow → liquidate → re-borrow possible in a single transaction within a `cook()` batch

### V-02: Self-Liquidation Permitted

- **Description**: The Cauldron's `cook()` function allows a user to liquidate their own position. This enables the attacker to combine real token withdrawal with additional borrowing within the same batch.
- **Impact**: When combined with the accounting bug, self-liquidation leads to total protocol loss.
- **Attack conditions**: `cook()` does not restrict liquidation where the target is `msg.sender`

### V-03: Deferred Solvency Check

- **Description**: The `_isSolvent()` check executes only once after all actions in a `cook()` batch have completed. There is no validation at intermediate steps.
- **Impact**: The borrow → liquidate → re-borrow sequence within a batch can be manipulated so that phantom collateral appears sufficient at the final check.
- **Attack conditions**: Attacker has full control over action ordering within the batch

### V-04: Async External Protocol Integration — Intermediate State Exposure

- **Description**: Due to GMX V2's asynchronous deposit/withdrawal model, the RouterOrder holds funds in a pending intermediate state. Abracadabra recognizes collateral in this intermediate state, but the handling logic for failed orders is flawed.
- **Impact**: Intentionally failing deposits can leave funds stranded in RouterOrder, which can then be exploited as collateral.
- **Attack conditions**: Even when a GMX deposit fails, the RouterOrder's internal state must remain recognized as valid collateral by the Cauldron

---

## 5. Remediation Recommendations

### Immediate Actions

#### 5.1 `sendValueInCollateral()` — Internal State Synchronization

```solidity
// ✅ Fix: immediately decrement internal tracking variables right after token withdrawal
function sendValueInCollateral(
    address recipient,
    uint256 shareMarketToken
) public onlyCauldron {
    (uint256 shortExchangeRate, uint256 marketExchangeRate) = getExchangeRates();

    uint256 amountShortToken = (degenBox.toAmount(IERC20(market), shareMarketToken, true) *
        oracleDecimalScale) / (shortExchangeRate * marketExchangeRate);

    // Actual transfer
    shortToken.safeTransfer(address(degenBox), amountShortToken);
    degenBox.deposit(IERC20(shortToken), address(degenBox), recipient, amountShortToken, 0);

    // ✅ Key fix: immediately synchronize internal accounting variables
    _decrementAccountingState(amountShortToken, shareMarketToken);
}

// ✅ New function: internal state decrement logic extracted to a separate function
function _decrementAccountingState(
    uint256 amountShortToken,
    uint256 shareMarketToken
) internal {
    if (depositType) {
        inputAmount = inputAmount >= amountShortToken
            ? inputAmount - amountShortToken
            : 0;
        minOut = minOut >= shareMarketToken
            ? minOut - shareMarketToken
            : 0;
    } else {
        inputAmount = inputAmount >= shareMarketToken
            ? inputAmount - shareMarketToken
            : 0;
        // Proportionally decrement minOut and minOutLong
        if (minOut + minOutLong > 0) {
            uint256 ratio = (shareMarketToken * 1e18) / (minOut + minOutLong);
            minOut = minOut - (minOut * ratio / 1e18);
            minOutLong = minOutLong - (minOutLong * ratio / 1e18);
        }
    }
}
```

#### 5.2 Prevent Self-Liquidation

```solidity
// ✅ Fix: prohibit liquidation of msg.sender's own position
function _cookActionLiquidate(
    address borrower,
    /* ... */
) internal {
    // ✅ Prevent self-liquidation
    require(borrower != msg.sender, "Cauldron: self-liquidation forbidden");
    // Existing liquidation logic...
}
```

#### 5.3 Add Intermediate Solvency Checks

```solidity
// ✅ Fix: immediately verify solvency after each borrow action
function cook(
    uint8[] calldata actions,
    uint256[] calldata values,
    bytes[] calldata datas
) external payable returns (uint256 value1, uint256 value2) {
    for (uint256 i = 0; i < actions.length; i++) {
        uint8 action = actions[i];
        if (action == ACTION_BORROW) {
            (status, value1, value2) = _cookActionBorrow(status, ...);
            // ✅ Immediate solvency check after borrow (do not wait for batch end)
            require(_isSolvent(msg.sender), "Cauldron: insolvent after borrow");
        }
        // ...
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------------|-------------------|
| V-01 Accounting discrepancy | Introduce invariant checks in external protocol withdrawal functions: always maintain `actual balance == internal tracking value` |
| V-02 Self-liquidation | Enforce `borrower != msg.sender` condition in liquidation functions |
| V-03 Deferred check | Insert intermediate solvency checks immediately after each high-risk action (borrow, large withdrawal) |
| V-04 Async integration | Implement an order state machine that immediately zeroes out collateral value for failed GMX orders |
| General | Introduce invariant-based fuzzing: continuously verify `totalCollateral >= totalBorrows` |
| General | No re-audit since Guardian Audits (November 2023, 2+ years) → mandate re-audit whenever external protocol integrations change |

---

## 6. Lessons Learned

1. **"Reported value == actually held value" invariant**: In integrations with external protocols, any function reporting collateral value must always match actually withdrawable assets. Internal tracking variables must be updated immediately upon asset movement; deferred updates create phantom collateral.

2. **Risks of async protocol integration**: When integrating external protocols that use asynchronous deposit/withdrawal models like GMX V2, handling must be complete for every order state (pending, failed, cancelled, completed). In particular, funds from failed orders must be immediately excluded from collateral value.

3. **Self-liquidation should be disabled by default**: Self-liquidation can interact with protocol accounting logic to produce unexpected state combinations. When combined with other bugs, the consequences can be catastrophic.

4. **Check timing in batch processing (`cook`) patterns**: Functions that process multiple actions in a batch must perform intermediate solvency checks immediately after high-risk actions (borrows, large withdrawals). A single check at batch end is vulnerable to intermediate state manipulation.

5. **Mandatory re-audit after external integration changes**: There was no follow-up audit of GMX V2 integration changes after the initial Guardian Audits review (November 2023). Changes to external protocol integrations can alter the entire security model and must always trigger a re-audit.

6. **Importance of fuzzing and invariant testing**: If protocol invariants such as `total collateral value >= total borrows` had been continuously validated with Foundry `invariant` tests, this vulnerability could have been discovered before deployment.

---

## 7. On-Chain Verification

On-chain transaction tracing results (based on Three Sigma analysis):

### 7.1 PoC vs. On-Chain Amount Comparison

| Item | On-Chain Actual | Notes |
|------|----------------|-------|
| Total loss | 6,262 ETH ≈ $13,408,309 | Sum across 5 Cauldrons |
| Largest single extraction | ≈ 932 ETH | Tx: 0xe93e...6123 |
| Number of attack transactions | 56 | Spread across 6 wallets |
| Attack duration | ~100 minutes | 07:57 – 09:37 UTC |
| Recovered funds | ≈ $260,000 | RouterOrder residual |

### 7.2 Attacker Wallet Breakdown

| Role | Address |
|------|---------|
| Primary attacker (Wallet 1) | 0xe9A4034E89608Df1731835A3Fd997fd3a82F2f39 |
| Wallet 2 | 0xa47359F87509D783EBB3daA0b75F24ED07888306 |
| Wallet 3 | 0x08606858ee5941af37e46f47012689cf83052b56 |
| Wallet 4 | 0x4Ade855c2240099c20e361796c8f697d1Bdb6938 |
| Wallet 5 | 0x51c9d0264d829a4F6d525dF2357Cd20Ea79b5049 |
| Laundering/funding (Wallet 6) | 0xaf9e33aa03caaa613c3ba4221f7ea3ee2ac38649 |
| Attack contract | 0xf29120acd274a0c60a181a37b1ae9119fe0f1c9c |

### 7.3 Protocol Response Timeline

| Time (UTC) | Event |
|-----------|-------|
| 07:57 | Attack begins (first malicious transaction) |
| 09:37 | Last malicious transaction |
| 09:46 | Abracadabra team executes borrowing pause |
| After | orderAgent set to zero address → new orders blocked |
| After | ~$260,000 in RouterOrder residual funds recovered |
| After | 20% bug bounty (~$2.68M) publicly offered |

---

> **Pattern DB Note**: The "phantom collateral via intermediate state in async external protocol integration" pattern identified as central to this incident is only partially covered by the existing `16_accounting_sync.md`. The specific risks of integrating async order-book models like GMX V2 are recommended for addition as a dedicated section.