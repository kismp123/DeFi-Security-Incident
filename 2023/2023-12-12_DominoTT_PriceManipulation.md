# DominoTT Price Manipulation Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-12 |
| Protocol | DominoTT |
| Chain | BSC |
| Loss | ~5 WBNB |
| Attacker | 0x835b45d38cbdccf99e609436ff38e31ac05bc502 |
| Attack Tx | 0x1ee617cd739b1afcc673a180e60b9a32ad3ba856226a68e8748d58fcccc877a8 |
| Vulnerable Contract | 0x0dabdc92af35615443412a336344c591faed3f90 |
| Root Cause | Forced `sync()` call updates reserves to match manipulated balances, distorting spot price and enabling arbitrage |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/DominoTT_exp.sol |

---

## 1. Vulnerability Overview

A price manipulation attack combining a DODO flash loan with the `sync()` function occurred on the DominoTT-WBNB liquidity pool. The attacker borrowed a large amount of WBNB via flash loan, forcibly synchronized the pool's reserves to manipulate the token price, and extracted approximately 5 WBNB.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
interface IDominoTTWBNBN {
    // sync callable by anyone
    function sync() external;
}

// Uniswap V2 fork - sync implementation
function sync() external lock {
    // Force-updates reserves to current balances
    // Manipulable by transferring tokens directly then calling sync
    _update(
        IERC20(token0).balanceOf(address(this)),
        IERC20(token1).balanceOf(address(this)),
        reserve0,
        reserve1
    );
}
```

### ✅ Fixed Code
```solidity
// Flash loan defense: detect large balance changes within the same block
function sync() external lock {
    uint256 balance0 = IERC20(token0).balanceOf(address(this));
    uint256 balance1 = IERC20(token1).balanceOf(address(this));
    // Block abnormal balance changes
    require(balance0 <= reserve0 * 2, "Suspicious balance");
    require(balance1 <= reserve1 * 2, "Suspicious balance");
    _update(balance0, balance1, reserve0, reserve1);
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: forced sync() call updates reserves to match manipulated balances, distorting spot price and enabling arbitrage
// Source code unverified — analysis based on bytecode
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─▶ DODO DPP Advanced flash loan
  │    └─▶ Borrow large amount of WBNB
  │
  ├─▶ Transfer WBNB directly to DominoTT-WBNB pool
  │    └─▶ Induce pool imbalance
  │
  ├─▶ Call sync()
  │    └─▶ Force reserve update → price manipulation
  │
  ├─▶ Swap DominoTT tokens at manipulated price
  │
  ├─▶ Repay flash loan
  │
  └─▶ Realize profit of 5 WBNB
```

---

## 4. PoC Code (Key Sections)

```solidity
function testExploit() external {
    // Initiate DODO flash loan
    IDPPAdvanced(dppAdvanced).flashLoan(
        wbnbAmount, 0, address(this), abi.encode("exploit")
    );
}

function DPPFlashLoanCall(address, uint256 baseAmount, uint256, bytes calldata) external {
    // Transfer WBNB directly to the pool
    WBNB.transfer(address(dominoPool), baseAmount / 2);

    // Force reserve update via sync()
    IDominoTTWBNBN(dominoPool).sync();

    // Swap at manipulated price to profit 5 WBNB
    // Repay flash loan
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Flash loan + `sync()` price manipulation |
| Attack Vector | DODO flash loan + direct transfer |
| Impact Scope | DominoTT-WBNB pool |
| Severity | Low |

---

## 6. Remediation Recommendations

1. **Protect `sync()`**: Detect and block large reserve changes within a single block
2. **TWAP Oracle**: Use time-weighted average price instead of spot price
3. **Flash Loan Detection**: Implement logic to detect large inflows within the same block

---

## 7. Lessons Learned

DominoTT and HNet were attacked on the same day, by the same attacker (0x835b...), using the same method. This is an example of automated vulnerability scanners being used to attack multiple protocols sharing similar patterns in bulk. When protocols with identical patterns exist, one being exploited should be recognized as a signal that the rest are equally at risk.