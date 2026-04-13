# BCT Token Vulnerability Analysis (December 2023)

## Metadata

| Field | Details |
|------|------|
| Date | 2023-12-05 |
| Protocol | BCT Token |
| Chain | BSC |
| Loss | ~10.2 BNB |
| Attacker | 0x9c66b0c68c144ffe33e7084fe8ce36ebc44ad21e |
| Attack Tx | 0xdae0b85e01670e6b6b317657a72fb560fc388664cf8bfdd9e1b0ae88e0679103 |
| Vulnerable Contract | 0x88b3eb62e363d9f153beab49c5c2ef2e785a375a |
| Root Cause | Token logic manipulation (multi-phase attack) |
| PoC Source | https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/BCT_exp.sol |

---

## 1. Vulnerability Overview

The BCT token contract was exploited via a two-phase attack. The attacker first deployed 5 self-initiated Tool contracts to prepare the environment, then in a second transaction leveraged a flaw in the token logic to steal approximately 10.2 BNB.

---

## 2. Vulnerable Code Analysis

### ❌ Vulnerable Code
```solidity
// BCT token internal logic
function _transfer(address from, address to, uint256 amount) internal {
    // No handling for multi-transfers through Tool contracts
    // No state validation between the preparation and execution phases
    balances[from] -= amount;
    balances[to] += amount;
}
```

### ✅ Fixed Code
```solidity
function _transfer(address from, address to, uint256 amount) internal {
    require(!isToolContract(from), "Tool contract transfers blocked");
    require(amount <= maxTransferAmount, "Exceeds max transfer");
    balances[from] -= amount;
    balances[to] += amount;
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Token logic manipulation (multi-phase attack)
// Source code unverified — based on bytecode analysis
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[Tx 1]─▶ Deploy 5 Tool contracts
  │           (prepare attack environment)
  │
  └─[Tx 2]─▶ Call BCT token contract
               │
               ├─▶ Execute Tool contracts 1–5 sequentially
               │    └─▶ Manipulate token balances
               │
               └─▶ Realize profit of 10.2 BNB
```

---

## 4. PoC Code (Key Sections, English Comments)

```solidity
contract ContractTest is Test {
    function testExploit() external {
        // Phase 1: Deploy 5 Tool contracts (environment preparation)
        // Tx: 0xd4c19d575ea5b3a415cc288ce09942299ca3a3b49ef9718cda17e4033dd4c250

        // Phase 2: Execute the actual attack
        // Tx: 0xdae0b85e01670e6b6b317657a72fb560fc388664cf8bfdd9e1b0ae88e0679103

        // Abnormal token manipulation via Tool contracts
        // Final profit: 10.2 BNB
    }
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| Vulnerability Type | Token logic manipulation |
| Attack Vector | Multi-phase preparation attack |
| Impact Scope | BCT token holders |
| Severity | Medium |

---

## 6. Remediation Recommendations

1. **Contract address whitelisting**: Block abnormal callers such as Tool contracts
2. **Single-transaction restrictions**: Strengthen state validation to prevent multi-phase preparation attacks
3. **Transfer limit enforcement**: Cap the maximum transfer amount per single transaction

---

## 7. Lessons Learned

Multi-phase attacks (2-phase attacks) are difficult to detect during the preparation phase. Monitoring contract deployment patterns and detecting abnormal pre-interaction activity through on-chain analysis is critical.