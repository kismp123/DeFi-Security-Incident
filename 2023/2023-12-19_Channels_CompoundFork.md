# Channels Compound Fork Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-19 |
| Protocol | Channels |
| Chain | BSC |
| Loss | ~$4.4K |
| Attacker | 0xd227dc77561b58c5a2d2644ac0173152a1a5dc3d |
| Attack Tx | 0xcf729a9392b0960cd315d7d49f53640f000ca6b8a0bd91866af5821fdf36afc5 |
| Vulnerable Contract | 0xca797539f004c0f9c206678338f820ac38466d4b |
| Root Cause | Compound fork exchange rate manipulation |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/Channels_exp.sol |

---

## 1. Vulnerability Overview

A small-scale theft occurred in the Channels protocol (a BSC-based Compound fork) via exchange rate manipulation. The attacker donated a small amount of tokens to an empty market to artificially inflate the cToken exchange rate, then exploited it.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
// Compound fork - cToken exchange rate calculation
function exchangeRateStoredInternal() internal view returns (uint256) {
    if (totalSupply == 0) {
        return initialExchangeRate; // initial value
    }
    // actual balance / total supply = exchange rate
    // numerator can be manipulated via direct transfer
    uint256 totalCash = getCash();
    return (totalCash + totalBorrows - totalReserves) * 1e18 / totalSupply;
}
```

### ✅ Fixed Code
```solidity
// Lock minimum liquidity to prevent empty market attacks
uint256 constant MINIMUM_LIQUIDITY = 1000;

function mint(uint256 mintAmount) external returns (uint256) {
    // First minter locks minimum liquidity
    if (totalSupply == 0) {
        _mint(address(0), MINIMUM_LIQUIDITY);
    }
    // ...
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Compound fork exchange rate manipulation
// Source code unverified — based on bytecode analysis
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─▶ Identifies empty Channels market
  │
  ├─▶ Directly transfers small amount of tokens (donation)
  │    └─▶ Exchange rate inflates significantly
  │
  ├─▶ Mints cTokens (with 1 wei)
  │    └─▶ Acquires large amount of assets at distorted exchange rate
  │
  └─▶ Drains $4.4K
```

---

## 4. PoC Code (Key Portion)

```solidity
function testExploit() external {
    // Directly transfer tokens to empty market
    token.transfer(address(cToken), donationAmount);

    // Mint cTokens at distorted exchange rate
    // Small input yields disproportionately large cToken output
    cToken.mint(1);

    // Redeem assets using inflated cTokens
    // $4.4K drained
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Exchange rate manipulation (empty market attack) |
| Attack Vector | Direct token transfer + exchange rate distortion |
| Impact Scope | Channels market |
| Severity | Low |

---

## 6. Remediation Recommendations

1. **Minimum liquidity lock**: Apply Uniswap V2-style `MINIMUM_LIQUIDITY`
2. **Exchange rate cap**: Block abnormal exchange rate spikes
3. **Initial liquidity validation**: Enforce minimum initial liquidity at market creation

---

## 7. Lessons Learned

The empty market attack is a structural vulnerability in Compound forks. It is essential to adopt Uniswap V2's minimum liquidity locking mechanism or ensure sufficient initial liquidity is seeded during market initialization.