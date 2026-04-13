# CCV Flash Loan Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-05 |
| Protocol | CCV |
| Chain | BSC |
| Loss | ~3,200 BUSD |
| Attacker | 0x835b45d38cbdccf99e609436ff38e31ac05bc502 |
| Attack Tx | 0x6ba4152db9da45f5751f2c083bf77d4b3385373d5660c51fe2e4382718afd9b4 |
| Vulnerable Contract | 0x37177ccc66ef919894cef37596bbebd76e7a40b2 |
| Root Cause | Price calculation logic relies on AMM spot reserves, enabling price manipulation via reserve manipulation within a single block |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/CCV_exp.sol |

---

## 1. Vulnerability Overview

The CCV protocol was attacked via a price manipulation exploit that abused DODO's DPP Advanced flash loan functionality. The attacker obtained a large amount of funds through a flash loan, manipulated the price of the CCV token, and extracted approximately 3,200 BUSD.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
// Price calculation within the CCV protocol
function getTokenPrice() public view returns (uint256) {
    // Uses spot price that can be manipulated within a single block
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    return uint256(reserve1) * 1e18 / uint256(reserve0);
}

function swap(uint256 amount) external {
    uint256 price = getTokenPrice(); // Uses manipulated price
    // Swap executed based on manipulated price
}
```

### ✅ Fixed Code
```solidity
function getTokenPrice() public view returns (uint256) {
    // Uses TWAP oracle to prevent manipulation
    return twapOracle.consult(token, 1e18);
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Price calculation logic relies on AMM spot reserves, enabling price manipulation via reserve manipulation within a single block
// Source code unverified — based on bytecode analysis
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─▶ Execute DODO DPP Advanced flash loan
  │    └─▶ Obtain large amount of BUSD
  │
  ├─▶ Manipulate CCV token pool price
  │    └─▶ Drive price up via large buy
  │
  ├─▶ Interact with CCV protocol at manipulated price
  │
  ├─▶ Realize arbitrage profit
  │
  └─▶ Repay flash loan, net 3,200 BUSD profit
```

---

## 4. PoC Code (Key Sections)

```solidity
function testExploit() external {
    // Initiate DODO DPP Advanced flash loan
    IDPPAdvanced(dppAdvanced).flashLoan(
        0,
        busdAmount,  // Borrow large amount of BUSD
        address(this),
        abi.encode("exploit")
    );
}

function DPPFlashLoanCall(address, uint256, uint256, bytes calldata) external {
    // Flash loan callback: execute price manipulation
    // Profit from arbitrage after manipulating CCV price
    // 3,200 BUSD profit
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Flash loan price manipulation |
| Attack Vector | DODO flash loan + spot price oracle |
| Impact Scope | CCV liquidity pool |
| Severity | Low |

---

## 6. Remediation Recommendations

1. **Adopt TWAP Oracle**: Use time-weighted average price instead of single-block spot price
2. **Flash Loan Defense**: Detect and block large liquidity changes within the same block
3. **Slippage Limits**: Revert transactions on abnormal price movements

---

## 7. Lessons Learned

Although the loss was small ($3,200), the same pattern applied to a larger protocol could cause significant damage. Spot-price-based oracles are always vulnerable to flash loan attacks; TWAP or external oracles such as Chainlink should be used instead.