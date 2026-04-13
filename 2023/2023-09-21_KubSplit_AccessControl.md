# Kub Split — Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-21 |
| **Protocol** | Kub Split |
| **Chain** | BSC |
| **Loss** | ~$78K |
| **Attacker** | [0x7ccf451d3c48c8bb...](https://bscscan.com/address/0x7ccf451d3c48c8bb747f42f29a0cde4209ff863e) |
| **Attack Tx** | [0x2b0877b5495065e9...](https://bscscan.com/tx/0x2b0877b5495065e90d956e44ffde6aaee5e0fcf99dd3c86f5ff53e33774ea52d) |
| **Vulnerable Contract** | [0xc98e183d2e975f05...](https://bscscan.com/address/0xc98e183d2e975f0567115cb13af893f0e3c0d0bd) |
| **Root Cause** | No access control on critical functions, allowing arbitrary callers to manipulate internal state |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/Kub_Split_exp.sol) |

---
## 1. Vulnerability Overview
A missing access control on certain functions in the Kub Split contract enabled an attack combined with a flash loan, resulting in a $78K loss.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: callable by anyone externally
function splitFunds(address recipient, uint256 amount) external {
    // ❌ Anyone can call this
    token.transfer(recipient, amount);
}
// ✅ Fix
function splitFunds(address recipient, uint256 amount) external onlyOwner {
    token.transfer(recipient, amount);
}
```

---
### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: no access control on critical functions, allowing arbitrary callers to manipulate internal state
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Borrow KUB tokens via flash loan
  ├─② Call splitFunds(attacker, amount)
  └─③ Drain contract tokens + ~$78K
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
flashLoan(kubAmount);
// Direct call to function with no access control
kubSplit.splitFunds(address(this), contractBalance);
repayFlashLoan();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Missing Access Control |
| Severity | High |

---
## 6. Remediation Recommendations
1. Apply strict access control to all fund transfer functions
2. Audit permissions on all public/external functions before deployment

---
## 7. Lessons Learned
Fund transfer functions require the strictest possible access controls.