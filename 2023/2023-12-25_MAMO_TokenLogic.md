# MAMO Token Logic Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-25 |
| Protocol | MAMO |
| Chain | BSC |
| Loss | ~$3.3K |
| Attacker | 0x829fe73463ceae6579973b8bcd1e018976040ec4 |
| Attack Tx | 0x189a8dc1e0fea34fd7f5fa78c6e9bdf099a8d575ff5c557fa30d90c6acd0b29f |
| Vulnerable Contract | 0x5813d7818c9d8f29a9a96b00031ef576e892def4 |
| Root Cause | Token fee logic vulnerability |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/MAMO_exp.sol |

---

## 1. Vulnerability Overview

The MAMO token contract contained a flaw in its transfer fee logic that an attacker exploited to steal approximately $3.3K. The root cause was a calculation error in the token tax mechanism.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
// MAMO token transfer logic
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 fee = 0;

    if (isPair[to]) {
        // Sell fee calculation
        fee = amount * sellFee / 100;
    } else if (isPair[from]) {
        // Buy fee calculation
        fee = amount * buyFee / 100;
    }

    // Fee accumulation — manipulable
    accumulatedFees += fee;

    // Auto-swap triggered when accumulation exceeds threshold
    if (accumulatedFees > swapThreshold) {
        // Swap timing and price are manipulable
        _swapFeesForBNB(accumulatedFees);
        accumulatedFees = 0;
    }
}
```

### ✅ Fixed Code
```solidity
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 fee = calculateFee(from, to, amount);

    // Reentrancy guard
    require(!inSwap, "Reentrant call");

    if (fee > 0) {
        super._transfer(from, address(this), fee);
        amount -= fee;
    }
    super._transfer(from, to, amount);
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Token fee logic vulnerability
// Source code unverified — based on bytecode analysis
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─▶ Analyzed MAMO token fee logic
  │    └─▶ Identified fee accumulation + auto-swap mechanism
  │
  ├─▶ Triggered fee threshold via large transfers
  │    └─▶ Auto-swap triggered
  │
  ├─▶ Manipulated swap price (sandwich)
  │
  └─▶ Realized ~$3.3K profit
```

---

## 4. PoC Code (Key Sections)

```solidity
function testExploit() external {
    vm.createSelectFork("bsc", 34_629_027);

    // Acquire MAMO tokens
    // Trigger fee logic
    // Execute sandwich attack timed to auto-swap
    // Profit ~$3.3K
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Token fee mechanism vulnerability |
| Attack Vector | Auto-swap timing manipulation |
| Impact Scope | MAMO token holders |
| Severity | Low |

---

## 6. Remediation Recommendations

1. **Auto-swap protection**: Apply slippage protection and minimum output amount during auto-swaps
2. **Reentrancy guard**: Block reentrancy using an `inSwap` flag
3. **Fee limits**: Cap maximum fee rates and enforce transparent disclosure

---

## 7. Lessons Learned

Token tax mechanisms combined with auto-swap functionality are susceptible to sandwich attacks. MEV protection and slippage limits must always be applied when executing auto-swaps.