# ARA — Flash Loan Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-09 |
| **Protocol** | ARA Token |
| **Chain** | BSC |
| **Loss** | ~125K USD |
| **Attacker** | [0xf84efa8a...](https://bscscan.com/address/0xf84efa8a9f7e68855cf17eaac9c2f97a9d131366) |
| **Attack Contract** | [0x98e241bd...](https://bscscan.com/address/0x98e241bd3be918e0d927af81b430be00d86b04f9) |
| **Attack Tx** | [0xd87cdecd...](https://bscscan.com/tx/0xd87cdecd5320301bf9a985cc17f6944e7e7c1fbb471c80076ef2d031cc3023b2) |
| **Vulnerable Contract** | [0x7ba5dd9b...](https://bscscan.com/address/0x7ba5dd9bb357afa2231446198c75bac17cefcda9) |
| **Root Cause** | Internal swap function calculates exchange rate based on `getReserves()` spot price, allowing reserve manipulation within a single block for arbitrage profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/ARA_exp.sol) |

---
## 1. Vulnerability Overview

The ARA token contract implements a swap function internally via PancakeSwap V3, and price calculation relies on a manipulable LP spot price. The attacker borrowed a large amount of tokens via flash loan to manipulate the LP price, then executed the internal swap function under favorable conditions to extract profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Internal swap based on spot price
interface IPancakeRouterV3 {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;  // ❌ No slippage protection when set to 0
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Internal swap function calculates exchange rate based on getReserves() spot price, allowing reserve manipulation within a single block for arbitrage profit
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌─────────────────────────────────────┐
│  1. Borrow large amount of BUSD     │
│     via flash loan                  │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  2. Large BUSD → ARA purchase       │
│     → ARA/BUSD LP price spikes      │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  3. Call vulnerable contract's      │
│     internal function               │
│     (swap executed at manipulated   │
│      price)                         │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  4. Sell ARA → BUSD                 │
│  5. Repay flash loan + 125K USD     │
│     profit                          │
└─────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // 1. Borrow BUSD via PancakeV3 flash loan
    // 2. Manipulate ARA price with large swap
    // 3. Call internal swap function of vulnerable contract
    // 4. Realize profit via reverse swap
    // 5. Repay flash loan
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matched Pattern |
|----|--------|--------|-----|-----------|
| V-01 | LP Spot Price Oracle Manipulation | CRITICAL | CWE-1041 | 04_oracle_manipulation.md |
| V-02 | Missing Slippage Protection | HIGH | CWE-682 | 02_flash_loan.md |

## 6. Remediation Recommendations

### Immediate Actions
```solidity
// ✅ Set appropriate value for amountOutMinimum (slippage protection)
// ✅ Add TWAP-based price validation
uint256 expectedMin = getTWAP(tokenIn, amountIn) * 95 / 100; // 5% slippage
require(amountOut >= expectedMin, "Excessive slippage");
```

### Structural Improvements
| Vulnerability | Recommended Action |
|--------|-----------|
| Spot price dependency | Use TWAP oracle |
| Unprotected slippage | Enforce strict amountOutMinimum |

## 7. Lessons Learned

1. Setting `amountOutMinimum=0` in PancakeSwap V3's `exactInputSingle` exposes the contract completely to flash loan price manipulation attacks.
2. Internal swap functions require an independent price validation mechanism that does not rely on external LP prices.