# PancakeBunny — Flash Loan Oracle Manipulation BUNNY Inflation Analysis

| Item | Details |
|------|------|
| **Date** | 2021-05-19 |
| **Protocol** | PancakeBunny |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$45,000,000 |
| **Attacker** | [0xa0AC...E187](https://bscscan.com/address/0xa0ACC61547f6bd066f7c9663C17A312b6Ad7E187) |
| **Attack Tx** | [0x897c...979](https://bscscan.com/tx/0x897c2de73dd55d7701e1b69ffb3a17b0f4801ced88b0c75fe1551c5fcce6a979) (block 7,556,391) |
| **Vulnerable Contract** | PancakeBunny BunnyMinterV2 / WBNB-USDT Vault |
| **Root Cause** | `mintFor()` uses the AMM spot price of the WBNB-USDT V1 pool as an oracle when calculating BUNNY reward amounts — manipulable within a single block via large swaps |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-05/PancakeBunny_exp.sol) |

---
## 1. Vulnerability Overview

PancakeBunny's BunnyMinterV2 calculates the WBNB/BUNNY ratio using the current reserves (spot price) of the PancakeSwap V1 pool when distributing BUNNY rewards to users. The attacker borrowed a massive amount of WBNB via 7 nested flash loans, dumped it into the WBNB-USDT V1 pool to crash the BNB price to an extreme low, then called `getReward()`. With the distorted price, BUNNY rewards were calculated astronomically, minting millions of BUNNY tokens, which were immediately sold to realize profit.

---
## 2. Vulnerable Code Analysis

### 2.1 mintFor() — BUNNY Mint Amount Calculation Based on Spot Price

```solidity
// ❌ BunnyMinterV2 — BUNNY reward calculation using spot price
function mintFor(address flip, uint _withdrawalFee, uint _performanceFee, address to, uint)
    external override onlyMinter
{
    uint feeSum = _performanceFee.add(_withdrawalFee);
    IBEP20(flip).safeTransferFrom(msg.sender, address(this), feeSum);

    uint bunnyBNBValue = tokenToBunnyBNB(feeSum, flip);
    // tokenToBunnyBNB() references PancakeSwap V1 spot price
    // → bunnyBNBValue spikes when V1 pool is manipulated via flash loan
    uint mintBunny = safeBunnyMintAmount(bunnyBNBValue);
    // mintBunny becomes an abnormally large value, causing excessive minting
    if (mintBunny > 0) {
        _mint(mintBunny, to);
    }
}
```

**Fixed Code**:
```solidity
// ✅ Using TWAP oracle — single-block price manipulation not possible
function mintFor(address flip, uint _withdrawalFee, uint _performanceFee, address to, uint)
    external override onlyMinter
{
    uint feeSum = _performanceFee.add(_withdrawalFee);
    IBEP20(flip).safeTransferFrom(msg.sender, address(this), feeSum);

    // Use TWAP price (minimum 30-minute observation window)
    uint bunnyBNBValue = tokenToBunnyBNBTWAP(feeSum, flip);
    uint mintBunny = safeBunnyMintAmount(bunnyBNBValue);
    if (mintBunny > 0) {
        _mint(mintBunny, to);
    }
}
```


### On-Chain Original Code

> ⚠️ Contract not verified on Sourcify — source unavailable. The behavior below is reconstructed from the attack PoC and on-chain traces, not verified source.

The BunnyMinterV2 contract on BSC (targeted by the PoC at VaultFlipToFlip 0x633e538EcF0bee1a18c2EDFE10C4Da0d6E71e77B) is not verified on Sourcify (chainid 56) and is not publicly verified on BSCscan. The following is reconstructed pseudocode from the DeFiHackLabs PoC and post-mortems:

```solidity
// RECONSTRUCTED — not verified source
// BunnyMinterV2.mintFor() — BUNNY reward calculation using AMM spot price

function mintFor(
    address flip,           // LP token (e.g., WBNB-USDT)
    uint _withdrawalFee,
    uint _performanceFee,
    address to,
    uint
) external onlyMinter {
    uint feeSum = _performanceFee.add(_withdrawalFee);
    IBEP20(flip).safeTransferFrom(msg.sender, address(this), feeSum);

    uint bunnyBNBValue = tokenToBunnyBNB(feeSum, flip); // ❌ calls PancakeSwap V1 reserves() directly — spot price
    // When WBNB-USDT V1 pool is manipulated by dumping ~15,000 WBNB via flash loan,
    // the spot ratio collapses and bunnyBNBValue is computed from the distorted price,
    // causing mintBunny to be orders of magnitude larger than intended.
    uint mintBunny = safeBunnyMintAmount(bunnyBNBValue); // ❌ no upper bound on minted amount
    if (mintBunny > 0) {
        _mint(mintBunny, to); // ❌ mints unbounded BUNNY at distorted spot price
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- `tokenToBunnyBNB()` reads the current PancakeSwap V1 `getReserves()` — a spot price readable within the same block. No TWAP or time-weighted averaging is applied.
- The attacker borrowed ~15,000 WBNB via 7 nested flash loans and dumped them into the WBNB-USDT V1 pool, crashing the effective BNB spot price momentarily.
- With the distorted spot price, `bunnyBNBValue` became astronomically large, causing `mintBunny` to be millions of tokens rather than a few hundred.
- `safeBunnyMintAmount()` applied no per-transaction cap, so the full inflated quantity was minted and immediately sold.

```solidity
// ✅ Fix: replace spot price with a TWAP oracle (minimum 30-minute window)
function mintFor(address flip, uint _withdrawalFee, uint _performanceFee, address to, uint) external onlyMinter {
    uint feeSum = _performanceFee.add(_withdrawalFee);
    IBEP20(flip).safeTransferFrom(msg.sender, address(this), feeSum);
    uint bunnyBNBValue = tokenToBunnyBNBTWAP(feeSum, flip); // ✅ time-weighted price — single-block manipulation impossible
    uint mintBunny = safeBunnyMintAmount(bunnyBNBValue);
    require(mintBunny <= MAX_BUNNY_MINT_PER_TX, "mint limit"); // ✅ cap per transaction
    if (mintBunny > 0) {
        _mint(mintBunny, to);
    }
}
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────────────────────┐
│ Step 1: Deposit 1 BNB → Join WBNB-USDT Vault (qualify for     │
│         reward receipt)                                        │
└─────────────────────┬──────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────┐
│ Step 2-8: 7 nested flash loans (multiple PancakeSwap pairs)    │
│ Accumulate large amount of WBNB via pancakeCall() chain        │
└─────────────────────┬──────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────┐
│ Step 9: Flash loan ~2.96M USDT from FortubeBank                │
│ Execute attack inside executeOperation() callback              │
└─────────────────────┬──────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────┐
│ Step 10: Dump ~15,000 WBNB into WBNB-USDT V1 pool             │
│ → BNB price crashes for BUNNY reward calculation               │
└─────────────────────┬──────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────┐
│ Step 11: Call flip.getReward()                                 │
│ BunnyMinterV2.mintFor() — excessive BUNNY minted at distorted  │
│ spot price                                                     │
└─────────────────────┬──────────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────────┐
│ Step 12: Sell excessively minted BUNNY → WBNB, repay flash     │
│          loans                                                 │
└────────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// exploit() — core price manipulation
function exploit() internal {
    // Artificially add LP tokens to WBNB-USDT V2 pair (reserve inflation)
    // wbnbUsdtPair.transfer(wbnbUsdtPair, lpAmount);

    // Dump ~15,000 WBNB into WBNB-USDT V1 pool → BNB price crashes
    // router.swapExactTokensForTokens(15000e18, 0, [WBNB, USDT], ...)

    // Call getReward() from Vault — BUNNY calculated at distorted price
    // bunnyVault.getReward();
    // → BunnyMinterV2.mintFor() mints millions of BUNNY

    // Sell BUNNY → WBNB to realize profit
    // router.swapExactTokensForTokens(bunny_balance, 0, [BUNNY, WBNB], ...)
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Use of AMM spot price from WBNB-USDT V1 pool for reward calculation — single-block manipulation possible via large swaps | CRITICAL | CWE-829 |
| V-02 | No cap on BUNNY mint amount — allows astronomical issuance when price is distorted | HIGH | CWE-20 |

> **Root Cause**: `mintFor()` uses AMM spot price as an oracle when calculating BUNNY reward amounts. Flash loans are merely the vehicle for providing large swap capital; the same manipulation is possible with real capital if the pool is shallow enough. Introducing TWAP is the essential fix.

---
## 6. Remediation Recommendations

```solidity
// ✅ Apply Uniswap V2 TWAP oracle — short-term manipulation not possible
// ✅ Set per-transaction cap on reward mint amount

uint public constant MAX_BUNNY_MINT_PER_TX = 10_000 * 1e18;

function mintFor(...) external override onlyMinter {
    // ...
    uint mintBunny = safeBunnyMintAmount(bunnyBNBValueTWAP);
    require(mintBunny <= MAX_BUNNY_MINT_PER_TX, "BunnyMinter: mint limit exceeded");
    if (mintBunny > 0) {
        _mint(mintBunny, to);
    }
}
```

---
## 7. Lessons Learned

- **Using AMM spot price as the basis for reward minting makes the protocol a target with a single large swap.** Regardless of whether flash loans are involved, TWAP is a mandatory requirement.
- **Flash loans are the vehicle providing attack capital, not the vulnerability itself.** Replacing the spot oracle with TWAP is the fundamental fix.
- **Placing a cap on reward mint amounts is a secondary defense measure that limits damage.**