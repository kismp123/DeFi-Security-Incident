# BUNN — Reflective Token `deliver()` LP Imbalance Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-22 |
| **Protocol** | BUNN Token |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0x24a68d2a...](https://bscscan.com/tx/0x24a68d2a4bbb02f398d3601acfd87b09f543d935fc24862c314aaf64c295acdb) |
| **Vulnerable Contract** | BUNN Token Contract |
| **Root Cause** | Calling the reflective token `deliver()` function reduces LP pair balance, enabling profit via swap |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/BUNN_exp.sol) |

---
## 1. Vulnerability Overview

BUNN is a reflective token where calling the `deliver()` function burns the caller's balance while reducing the reflected balances of all remaining holders. As the LP pair's actual token balance decreases, the pair price shifts relative to the UniswapV2 reserve, allowing the attacker to extract profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ BUNN reflective deliver — LP pair balance manipulation
interface Bunn is IERC20 {
    // ❌ Calling deliver reduces reflected balances of all holders (including LP pair)
    function deliver(uint256 tAmount) external;
}

// deliver() call flow:
// _rOwned[sender] -= rAmount
// _rTotal -= rAmount
// → LP pair's tokenFromReflection(rOwned) decreases
// → pair.balance < pair.reserve → sync() required
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Calling reflective token `deliver()` reduces LP pair balance, enabling profit via swap
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌─────────────────────────────────────┐
│  1. Borrow WBNB via flash loan      │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  2. Buy large amount of BUNN        │
│     with WBNB                       │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  3. BUNN.deliver(amount)            │
│     → LP pair reflected balance     │
│       decreases                     │
│     → reserve > balance imbalance   │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  4. Realize profit via swap         │
│  5. Repay flash loan                │
└─────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // 1. Borrow WBNB via flash loan
    // 2. Buy large amount of BUNN
    uint256 bunnBalance = bunn.balanceOf(address(this));

    // 3. Manipulate LP pair balance via deliver
    bunn.deliver(bunnBalance / 2);

    // 4. Swap to extract profit from imbalanced state
    // 5. Repay WBNB
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Reflective `deliver` LP Imbalance | HIGH | CWE-682 | 07_token_integration.md |
| V-02 | LP reserve/balance Sync Failure | HIGH | CWE-664 | 16_accounting_sync.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ Add LP pair to excluded list
function excludeFromReward(address account) external onlyOwner {
    _isExcluded[account] = true;
}
// Register LP pair address as excluded immediately at deployment or after addLiquidity
```

## 7. Lessons Learned

The same reflective `deliver`/`skim` pattern seen in BEVO, BRA, HODL Capital, and others has been repeated more than 10 times in 2023 alone. When deploying reflective token templates, registering the LP pair address in the excluded list is a mandatory checklist item.