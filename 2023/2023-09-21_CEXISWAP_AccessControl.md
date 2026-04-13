# CEXISWAP — Swap Function Access Control Analysis

| Item | Details |
|------|------|
| **Date** | 2023-09-21 |
| **Protocol** | CEXISWAP |
| **Chain** | Ethereum |
| **Loss** | ~$30K |
| **Attacker** | [0x060c169c4517d52c...](https://etherscan.io/address/0x060c169c4517d52c4be9a1dd53e41a3328d16f04) |
| **Attack Tx** | [0xede72a74d8398875...](https://etherscan.io/tx/0xede72a74d8398875b42d92c550539d72c830d3c3271a7641ee1843dc105de59e) |
| **Vulnerable Contract** | [0xb8a5890d53df78de...](https://etherscan.io/address/0xb8a5890d53df78dee6182a6c0968696e827e3305) |
| **Root Cause** | Arbitrary token approvals executable without parameter validation in the swap router |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/CEXISWAP_exp.sol) |

---
## 1. Vulnerability Overview
CEXISWAP's swap router did not sufficiently validate user-supplied parameters, allowing an attacker to set unlimited approvals on tokens held within the contract.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: arbitrary token approval possible
function executeSwap(address tokenIn, address router, bytes calldata data) external {
    IERC20(tokenIn).approve(router, type(uint256).max); // ❌ approves arbitrary router
    (bool success,) = router.call(data); // ❌ executes arbitrary data
}
// ✅ Fix: allow only whitelisted routers
function executeSwap(address tokenIn, address router, bytes calldata data) external {
    require(approvedRouters[router], "Not approved router"); // ✅
    IERC20(tokenIn).approve(router, amountNeeded);
    (bool success,) = router.call(data);
}
```

---
### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: arbitrary token approvals executable without parameter validation in the swap router
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① calls executeSwap(token, maliciousRouter, maliciousData)
  ├─② executes unlimited approve to malicious router
  ├─③ drains all contract tokens via transferFrom
  └─④ ~$30K profit
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Malicious router contract
function maliciousSwap(address token) external {
    // First, trick CEXISWAP into approving itself
    cexiswap.executeSwap(token, address(this), abi.encodeWithSelector(...));
    // Immediately call transferFrom after approval
    IERC20(token).transferFrom(address(cexiswap), attacker, balance);
}
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Missing Input Validation |
| Severity | Critical |

---
## 6. Remediation Recommendations
1. Maintain a whitelist of approved routers
2. Approve only the minimum required amount
3. Enforce strict parameter validation before external calls

---
## 7. Lessons Learned
Failing to validate external call parameters can result in critical vulnerabilities. In particular, the combination of `approve` + `call` is extremely dangerous.