# Cellframe — Flash Loan PancakeV3 Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-01 |
| **Protocol** | Cellframe Network |
| **Chain** | BSC |
| **Loss** | ~76K USD |
| **Attacker** | [0x2525c811...](https://bscscan.com/address/0x2525c811ecf22fc5fcde03c67112d34e97da6079) |
| **Attack Contract** | [0x1e2a251b...](https://bscscan.com/address/0x1e2a251b29e84e1d6d762c78a9db5113f5ce7c48) |
| **Attack Tx** | [0x943c2a5f...](https://bscscan.com/tx/0x943c2a5f89bc0c17f3fe1520ec6215ed8c6b897ce7f22f1b207fea3f79ae09a6) |
| **Vulnerable Contract** | Cellframe contract integrated with PancakeV3 |
| **Root Cause** | Using PancakeSwap V3 slot0 spot price as oracle |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/Cellframe_exp.sol) |

---
## 1. Vulnerability Overview

The Cellframe contract reads the current sqrtPriceX96 from `slot0` of the PancakeSwap V3 pool to calculate prices. The V3 slot0 price can be manipulated within a single block via flash loan, enabling a two-phase attack: a pre-attack Tx to manipulate the price, followed by execution of the main attack.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Using PancakeV3 slot0 spot price
function getCurrentPrice() internal view returns (uint256) {
    (uint160 sqrtPriceX96,,,,,,) = pancakeV3Pool.slot0();
    // ❌ slot0 reflects the latest swap price → manipulable via flash loan / large swap
    uint256 price = uint256(sqrtPriceX96) ** 2 / (2 ** 192);
    return price;
}
```

```solidity
// ✅ Fix: Use V3 TWAP (time-weighted)
function getTWAPPrice(uint32 twapInterval) internal view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval;
    secondsAgos[1] = 0;
    (int56[] memory tickCumulatives,) = pancakeV3Pool.observe(secondsAgos);
    int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
    int24 avgTick = int24(tickDiff / int32(twapInterval));
    return TickMath.getSqrtRatioAtTick(avgTick);
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Using PancakeSwap V3 slot0 spot price as oracle
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────┐
│  Pre-Attack Tx: Pre-manipulate PancakeV3    │
│  pool price                                 │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  1. Borrow large amount of tokens via       │
│     flash loan                              │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  2. Large swap on PancakeV3 → manipulate    │
│     slot0 price                             │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  3. Call Cellframe contract                 │
│     Execute favorable exchange using        │
│     manipulated slot0 price                 │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  4. Reverse swap + repay flash loan +       │
│     76K profit                              │
└─────────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
// Pre-attack: manipulate slot0 price
function preAttack() external {
    // Manipulate sqrtPriceX96 via large swap on PancakeV3 pool
    pancakeV3Router.exactInputSingle(params);
}

// Main attack
function mainAttack() external {
    // Call Cellframe internal function with manipulated slot0 price
    cellframe.interactWithProtocol(amount);
    // Realize profit via reverse swap
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | V3 slot0 spot price oracle | CRITICAL | CWE-1041 | 04_oracle_manipulation.md |
| V-02 | Pre-attack price manipulation (pre-attack) | HIGH | CWE-682 | 02_flash_loan.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ V3 TWAP observation (minimum 30 minutes)
uint32 twapInterval = 1800; // 30 minutes
```

### Structural Improvements
| Vulnerability | Recommended Action |
|--------|-----------|
| slot0 oracle | Calculate TWAP via observe() |
| Pre-attack price manipulation | Block price deviation threshold (±10%) |

## 7. Lessons Learned

`slot0` in Uniswap/PancakeSwap V3 is susceptible to within-block manipulation just like V2 reserves. Even in V3 environments, TWAP via `observe()` is mandatory. This is the same V3 slot0 oracle vulnerability as SiloFinance (April).