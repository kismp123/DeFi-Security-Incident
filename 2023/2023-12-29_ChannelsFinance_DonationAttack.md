# ChannelsFinance Donation Attack Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-29 |
| Protocol | Channels Finance |
| Chain | BSC |
| Loss | ~$320K |
| Attacker | 0x20395d8e8a11cfd2541b942afdb810b7dcc64681 |
| Attack Tx 1 | 0x711cc4ceb9701d317fe9aa47187425e16dae7d5a0113f1430e891018262f8fb5 |
| Attack Tx 2 | 0x93372ce9c86a25f1477b0c3068e745b5b829d5b58025bb1ab234230d3473b776 |
| Vulnerable Contract | 0x93790c641d029d1cbd779d87b88f67704b6a8f4c |
| Root Cause | Exchange rate manipulation via the gulp() function |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/ChannelsFinance_exp.sol |

---

## 1. Vulnerability Overview

An exchange rate manipulation attack exploiting the `gulp()` function occurred in the cCLP_BTCB_BUSD market of Channels Finance. The attacker inflated the contract balance via a donation (direct token transfer), then called `gulp()` to manipulate the exchange rate, making the collateral value appear higher than its actual worth.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
interface IcCLP_BTCB_BUSD is ICErc20Delegate {
    // gulp function callable by anyone
    function gulp() external;
}

// Internal implementation in Compound fork
function gulp() external {
    // Reflects the contract's actual balance into totalReserves
    // Can be manipulated via direct token transfers (donations)
    uint256 balance = token.balanceOf(address(this));
    totalReserves = balance; // exchange rate updated
}
```

### ✅ Fixed Code
```solidity
function gulp() external onlyAdmin {
    // Only callable by admin
    uint256 balance = token.balanceOf(address(this));
    // Detect abnormal increases
    require(balance <= totalReserves * 110 / 100, "Suspicious balance increase");
    totalReserves = balance;
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: exchange rate manipulation via the gulp() function
// Source code unverified — based on bytecode analysis
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─▶ Acquire BTCB-BUSD LP tokens via flash loan
  │
  ├─▶ Transfer LP tokens directly to cCLP contract (donation)
  │    └─▶ Contract balance surges
  │
  ├─▶ Call gulp()
  │    └─▶ Exchange rate rises sharply
  │
  ├─▶ Borrow from Channels using inflated collateral value
  │    └─▶ Borrow assets beyond their actual value
  │
  ├─▶ Leave loan unpaid + repay flash loan
  │
  └─▶ ~$320K profit
```

---

## 4. PoC Code (Key Sections)

```solidity
function testExploit() external {
    // Attack phase 1: manipulate exchange rate via gulp()
    // Transfer LP tokens directly
    lpToken.transfer(address(cCLP), donationAmount);

    // Call gulp() to update exchange rate
    IcCLP_BTCB_BUSD(cCLP).gulp();

    // Attack phase 2: borrow against inflated collateral
    // Borrow from Channels beyond actual value
    // Drain ~$320K
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Donation attack + exchange rate manipulation |
| Attack Vector | gulp() + direct token transfer |
| Impact Scope | Channels Finance lending pool |
| Severity | High |

---

## 6. Remediation Recommendations

1. **gulp() Access Control**: Restrict to admin-only function
2. **Balance Change Cap**: Limit the balance delta that can be applied in a single call
3. **Compound Fork Security Audit**: Review all gulp/sync patterns

---

## 7. Lessons Learned

The `gulp()` and `sync()` functions in Compound fork protocols are a primary vector for donation attacks. These functions must either have access controls applied to prevent arbitrary external calls, or balance updates should be driven solely by internal logic. Throughout the second half of 2023, attacks following this same pattern were repeated across multiple Compound forks.