# WECO — Token Logic Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2023-11-24 |
| **Protocol** | WECO |
| **Chain** | BSC |
| **Loss** | ~$18K |
| **Attacker** | [0xf5f21746ff9351f1...](https://bscscan.com/address/0xf5f21746ff9351f16a42fa272d7707cc35760e4b) |
| **Attack Tx** | [0x2040a481c933b50e...](https://bscscan.com/tx/0x2040a481c933b50ee31aba257c2041c48bb7a0b4bf4b4fad1ac165f19c4269e8) |
| **Vulnerable Contract** | [0xd672b766d66662f5...](https://bscscan.com/address/0xd672b766d66662f5c6fd798a999e1193a7945451) |
| **Root Cause** | Combined vulnerability from WECO token's rebase mechanism and fee logic |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/WECO_exp.sol) |

---
## 1. Vulnerability Overview
A balance discrepancy occurred when the WECO token's rebase mechanism was combined with transfer fees. The attacker exploited this to drain ~$18K.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: rebase + fee discrepancy
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 rebased = amount * rebaseIndex / 1e18; // rebase calculation
    uint256 fee = rebased * feeRate / 100;
    // ❌ precision mismatch between rebased and fee causes balance error
    super._transfer(from, feeCollector, fee);
    super._transfer(from, to, amount - fee); // ❌ should use rebased, not amount
}
// ✅ Fix: use consistent units
```

### On-chain Source Code

Source: bytecode decompilation

```solidity
// Root cause: combined vulnerability from WECO token's rebase mechanism and fee logic
// Source code unverified — based on bytecode analysis
```

---
## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Identify rebase + fee discrepancy
  ├─② Repeatedly transfer a specific amount
  ├─③ Generate tokens via discrepancy
  └─④ Sell generated tokens + ~$18K
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Exploit rebase discrepancy
for (uint i = 0; i < iterations; i++) {
    weco.transfer(address(this), exploitAmount);
}
// Excess balance accumulates due to discrepancy
sellExcessTokens();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Rebase + fee discrepancy |
| Severity | High |

---
## 6. Remediation Recommendations
1. Use consistent units for rebase and fee calculations
2. Test balance invariants before and after transfers

---
## 7. Lessons Learned
Implementing rebase mechanisms and fees simultaneously introduces complex interactions that give rise to vulnerabilities.