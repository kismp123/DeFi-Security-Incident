# KEST Flash Loan Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-14 |
| Protocol | KEST |
| Chain | BSC |
| Loss | ~$2.3K |
| Attacker | 0x90c4c1aa895a086215765ec9639431309633b198 |
| Attack Tx | 0x2fcee04e64e54f3dd9c15db9ae44e4cbdd57ab4c6f01941a3acf470dc60bfc16 |
| Vulnerable Contract | 0x7dda132dd57b773a94e27c5caa97834a73510429 |
| Root Cause | Price calculation logic relies on AMM spot reserves, allowing price distortion via reserve manipulation within a single block |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/KEST_exp.sol |

---

## 1. Vulnerability Overview

The KEST protocol was targeted by a price manipulation attack using flash loans. The attacker borrowed a large amount of funds to manipulate the price of the KEST token and extracted approximately $2.3K. While the loss was small, the same attack pattern poses a risk if applied to larger protocols.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
// Price-dependent logic inside the KEST token
function getKestValue(uint256 amount) public view returns (uint256) {
    // Spot-price based — manipulable via flash loan
    (uint112 r0, uint112 r1,) = IUniswapV2Pair(kestPair).getReserves();
    return amount * uint256(r1) / uint256(r0);
}

function processTransaction(uint256 kestAmount) external {
    uint256 value = getKestValue(kestAmount); // Uses manipulated price
    // Processing based on value — exploitable
}
```

### ✅ Fixed Code
```solidity
function getKestValue(uint256 amount) public view returns (uint256) {
    // Use TWAP or Chainlink oracle
    uint256 price = chainlinkOracle.latestAnswer();
    return amount * price / 1e8;
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: price calculation logic relies on AMM spot reserves, allowing price distortion via reserve manipulation within a single block
// Source code unverified — based on bytecode analysis
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─▶ Obtain large funds via flash loan
  │
  ├─▶ Manipulate KEST token price
  │    └─▶ Distort spot price through large buy/sell
  │
  ├─▶ Interact with KEST protocol using distorted price
  │
  ├─▶ Realize arbitrage profit
  │
  └─▶ Repay flash loan, net $2.3K profit
```

---

## 4. PoC Code (Key Sections, with Comments)

```solidity
function testExploit() external {
    vm.createSelectFork("bsc", 34_218_641);

    // Initiate flash loan
    flashLoanProvider.flashLoan(attackAmount);
}

function receiveFlashLoan(uint256 amount) external {
    // Manipulate KEST price
    // Exploit spot-price-based vulnerability
    // Acquire $2.3K then repay flash loan
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Flash Loan Price Manipulation |
| Attack Vector | Spot Price Oracle Manipulation |
| Impact Scope | KEST Protocol |
| Severity | Low |

---

## 6. Remediation Recommendations

1. **Integrate External Oracle**: Use Chainlink or Band Protocol price feeds
2. **Apply TWAP**: Prevent single-block price manipulation
3. **Volume Caps**: Limit maximum throughput per transaction

---

## 7. Lessons Learned

Although the loss was small at $2.3K, the same vulnerability pattern applied to a protocol with greater TVL would result in far larger losses. Regardless of protocol size, reliance on spot price oracles is always dangerous.