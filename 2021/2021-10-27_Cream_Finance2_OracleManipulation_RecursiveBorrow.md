# Cream Finance (2nd Hack) — yUSD Oracle Manipulation Recursive Borrowing Analysis

| Field | Details |
|------|------|
| **Date** | 2021-10-27 |
| **Protocol** | Cream Finance |
| **Chain** | Ethereum |
| **Loss** | ~$130,000,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | Cream crYUSD / crETH Markets |
| **Root Cause** | Collateral value calculated using yUSD vault's `pricePerShare()` as a spot value — manipulable within a single block via recursive mint/borrow |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-10/Cream_2_exp.sol) |

---
## 1. Vulnerability Overview

The second hack of Cream Finance was a highly sophisticated multi-stage attack. The attacker obtained a 500M DAI flash loan from MakerDAO and deposited it into the yUSD vault to mass-mint crYUSD. Simultaneously, a second contract borrowed 524,102 WETH from Aave, converted it to crETH, and recursively minted/borrowed crYUSD to artificially inflate the yUSD vault's `pricePerShare`. This manipulated price caused crYUSD's collateral value to surge tens of times over, enabling the attacker to borrow all liquidity from 14 markets including WBTC and WETH.

---
## 2. Vulnerable Code Analysis

### 2.1 Cream Oracle — Direct Use of yUSD pricePerShare

```solidity
// ❌ Cream Finance yUSD Price Oracle
// Uses the yUSD vault's current pricePerShare() directly as the price
// pricePerShare is the ratio of assets within the vault — manipulable via flash loan

function getUnderlyingPrice(CToken cToken) external view returns (uint) {
    address underlying = CErc20(address(cToken)).underlying();

    if (isYVault(underlying)) {
        // ❌ References current pricePerShare — manipulable within a single block
        uint256 pricePerShare = IYVault(underlying).pricePerShare();
        uint256 basePrice = getBasePrice(underlying);
        return pricePerShare.mul(basePrice).div(1e18);
    }
    // ...
}
```

**Fixed Code**:
```solidity
// ✅ Use TWAP or Chainlink oracle for yVault price
// ✅ Set a cap on single-block pricePerShare fluctuation

uint256 public constant MAX_PRICE_CHANGE_PER_BLOCK = 100; // 1%

function getUnderlyingPrice(CToken cToken) external view returns (uint) {
    address underlying = CErc20(address(cToken)).underlying();

    if (isYVault(underlying)) {
        uint256 currentPPS = IYVault(underlying).pricePerShare();
        uint256 lastPPS = lastPricePerShare[underlying];

        // If change exceeds 1% from previous block, use the prior price
        if (lastPPS > 0) {
            uint256 change = currentPPS > lastPPS
                ? (currentPPS - lastPPS) * 10000 / lastPPS
                : (lastPPS - currentPPS) * 10000 / lastPPS;
            if (change > MAX_PRICE_CHANGE_PER_BLOCK) {
                return lastPPS.mul(getBasePrice(underlying)).div(1e18);
            }
        }
        return currentPPS.mul(getBasePrice(underlying)).div(1e18);
    }
}
```


### On-Chain Original Code

Source: Unconfirmed

> ⚠️ No on-chain source code — bytecode only or source not verified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root Cause: Collateral value calculated using yUSD vault's pricePerShare() as a spot value — manipulable within a single block via recursive mint/borrow
// Source code unconfirmed — bytecode analysis required
// Vulnerability: Collateral value calculated using yUSD vault's pricePerShare() as a spot value — manipulable within a single block via recursive mint/borrow
```

## 3. Attack Flow

```
┌───────────────────────────────────────────────────────────────┐
│ Step 1: MakerDAO Flash Loan 500M DAI                          │
└─────────────────────┬─────────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────────┐
│ Step 2: DAI → yDAI → 4curve → yUSD → crYUSD conversion chain │
│ Deposit large amount into Cream crYUSD market                 │
└─────────────────────┬─────────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────────┐
│ Step 3: Second contract — Aave flash loan 524,102 WETH        │
│ WETH → crETH conversion (~$2B collateral)                     │
└─────────────────────┬─────────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────────┐
│ Step 4: Recursive crYUSD mint/borrow using crETH as collateral│
│ → Artificially inflate yUSD vault pricePerShare               │
│ → crYUSD collateral value skyrockets                          │
└─────────────────────┬─────────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────────┐
│ Step 5: Drain all liquidity from 14 Cream markets             │
│ WBTC, WETH, USDC, USDT, DAI, UNI, LINK, YFI, etc.           │
│ Total $130M stolen                                            │
└─────────────────────┬─────────────────────────────────────────┘
                      │
┌─────────────────────▼─────────────────────────────────────────┐
│ Step 6: Repay flash loans + realize profit                    │
└───────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// Core attack — yUSD pricePerShare manipulation
function exploit() internal {
    // 1. MakerDAO 500M DAI flash loan
    // 2. DAI → yUSD chain conversion → mass-mint crYUSD
    // 3. Second contract: 524,102 WETH → crETH
    // 4. Recursive crYUSD borrow/mint using crETH as collateral
    //    → pricePerShare spikes (crYUSD value explodes)
    // 5. Drain all 14 markets
    //    crYUSD collateral value >> actual value
    // 6. Repay flash loans
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | yUSD vault's `pricePerShare()` used as spot value for collateral calculation — manipulable within a single block via recursive deposits | CRITICAL | CWE-829 |
| V-02 | A single account can borrow the entire liquidity of all 14 markets — no concentration risk limits | CRITICAL | CWE-20 |

> **Root Cause**: Cream's oracle directly uses yUSD's `pricePerShare()` as the current value, so inflating the vault balance via recursive mint/borrow backed by crETH collateral distorts the collateral value. Flash loans (MakerDAO DAI, Aave WETH) serve as the large-scale funding mechanism; applying a TWAP or a single-block price change cap is the key fix.

---
## 6. Remediation Recommendations

```solidity
// ✅ Apply TWAP for composite collateral (yVault) pricing
// ✅ Limit maximum borrow ratio per single account
// ✅ Automatic pause on large collateral fluctuations

uint256 public constant MAX_BORROW_RATIO = 7500; // 75%

function borrow(uint borrowAmount) external {
    (, uint liquidity,) = comptroller.getAccountLiquidity(msg.sender);
    require(
        borrowAmount <= liquidity * MAX_BORROW_RATIO / 10000,
        "CToken: borrow exceeds safe limit"
    );
    // ...
}
```

---
## 7. Lessons Learned

- **Using yVault `pricePerShare()` as a spot oracle is the root cause.** Applying either a TWAP or a single-block change cap is sufficient to block recursive manipulation.
- **Flash loans are a large-scale capital sourcing mechanism.** With a TWAP oracle, no matter how much capital is concentrated in a single block via flash loans, `pricePerShare` manipulation cannot be reflected in collateral value.
- **Complex multi-layered collateral structures (yVault → crYUSD → recursive borrow) exponentially expand the price manipulation attack surface.** When adding new collateral types, the possibility of recursive manipulation must always be assessed.