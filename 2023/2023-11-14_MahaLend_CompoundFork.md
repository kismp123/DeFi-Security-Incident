# MahaLend — Compound Fork Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-14 |
| **Protocol** | MahaLend |
| **Chain** | Ethereum |
| **Loss** | ~$20K |
| **Attacker** | [0x0ec330df28ae6106...](https://etherscan.io/address/0x0ec330df28ae6106a774d0add3e540ea8d226e3b) |
| **Attack Tx** | [0x2881e839d4d562fa...](https://etherscan.io/tx/0x2881e839d4d562fad5356183e4f6a9d427ba6f475614ce8ef64dbfe557a4a2cc) |
| **Vulnerable Contract** | [0xfd11aba71c06061f...](https://etherscan.io/address/0xfd11aba71c06061f446ade4eec057179f19c23c4) |
| **Root Cause** | Exchange rate donation attack on Compound fork |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/MahaLend_exp.sol) |

---
## 1. Vulnerability Overview
MahaLend is a Compound fork lending protocol. The exchange rate calculation relied on `balanceOf()`, making it manipulable via direct transfers. This resulted in a $20K loss.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Vulnerable code: balanceOf-based exchange rate
function exchangeRateCurrent() public returns (uint256) {
    uint256 cash = getCash(); // underlying.balanceOf(this) ❌
    return computeExchangeRate(cash, totalBorrows, totalReserves, totalSupply);
}
// ✅ Fix: track cash via internal _cash variable
```

---
### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: MathUtils.sol
 * @notice Provides functions to perform linear and compounded interest calculations  // ❌

// ...

  function calculateLinearInterest(uint256 rate, uint40 lastUpdateTimestamp)

// ...

  function calculateCompoundedInterest(  // ❌

// ...

  function calculateCompoundedInterest(uint256 rate, uint40 lastUpdateTimestamp)  // ❌
```

```solidity
// File: ReserveLogic.sol
  function getNormalizedDebt(DataTypes.ReserveData storage reserve)

// ...

  function _accrueToTreasury(

// ...

  function _updateIndexes(
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Deposit small amount to obtain shares
  ├─② Directly transfer large amount of underlying tokens
  ├─③ Exchange rate spikes dramatically
  └─④ Execute over-collateralized borrow
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
mahaCToken.mint(1);
underlying.transfer(address(mahaCToken), largeAmount);
mahaCToken.borrow(manipulatedAmount);
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Donation Attack |
| Severity | High |

---
## 6. Remediation Recommendations
1. Track cash balance via an internal `_cash` variable
2. Permanently lock a minimum liquidity amount

---
## 7. Lessons Learned
The donation attack on Compound forks was a recurring pattern throughout 2023.