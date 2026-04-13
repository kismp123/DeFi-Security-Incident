# BIGFI — Flash Loan Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-03-07 |
| **Protocol** | BIGFI |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | BSC Transaction |
| **Vulnerable Contract** | BIGFI Token/Pool Contract |
| **Root Cause** | Reward calculation uses AMM spot reserves directly without TWAP, enabling reserve manipulation within a single block to claim excess rewards |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-03/BIGFI_exp.sol) |

---
## 1. Vulnerability Overview

The BIGFI protocol calculates rewards for LP token or single-token staking based on the current pool's reserve ratio. The attacker borrowed a large amount of tokens via flash loan to manipulate the price in the BIGFI pool, then executed favorable reward claims or swaps under the manipulated price state to extract profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Reward calculation based on spot price
function calculateReward(address user) public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    // ❌ Reward calculated from current reserve ratio → susceptible to flash loan manipulation
    uint256 price = reserve1 * 1e18 / reserve0;
    return stakedAmount[user] * price / BASE_PRICE;
}

// ✅ Fix: Use TWAP
function calculateReward(address user) public view returns (uint256) {
    uint256 twapPrice = getTWAP(30 minutes);
    return stakedAmount[user] * twapPrice / BASE_PRICE;
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: reward calculation uses AMM spot reserves directly without TWAP, enabling reserve manipulation within a single block to claim excess rewards
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Flash Loan (borrow large amount of WBNB/tokens)
  ├─2─▶ Manipulate BIGFI pool price
  ├─3─▶ Claim rewards or execute favorable swap at manipulated price
  ├─4─▶ Reverse pool manipulation (restore state)
  └─5─▶ Repay flash loan → net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function attack() external {
    // Manipulate price via flash loan then interact under favorable conditions
    flashLoan(largeAmount);
    // In callback: manipulate price → claim rewards → reverse manipulation → repay
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Vector** | Flash Loan + Spot Price |
| **DASP Classification** | Oracle Manipulation |

## 6. Remediation Recommendations
1. Use TWAP oracle to defend against short-term price manipulation.
2. Introduce a time delay in reward calculation.
3. Halt transactions when large price movements are detected within a single TX.

## 7. Lessons Learned
Spot price-based reward mechanisms are prime targets for flash loan attacks. TWAP is the standard defense against such attacks.