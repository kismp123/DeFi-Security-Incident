# Rari Capital — ERC-20 Hook Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-05-08 |
| **Protocol** | Rari Capital (Fuse Pool) |
| **Chain** | Ethereum |
| **Loss** | ~$11,000,000 |
| **Attacker** | Address unidentified |
| **Attack Tx** | Address unidentified (fork block: 12,394,009) |
| **Vulnerable Contract** | Rari Bank Vault (work() function) |
| **Root Cause** | Reentrancy via malicious ERC-20 token callback during vault.work() call, allowing vault state manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-05/RariCapital_exp.sol) |

---
## 1. Vulnerability Overview

The Rari Capital Fuse Pool vault manages assets through its `work()` function. The attacker deployed a fake (malicious) ERC-20 token contract and gained access to the vault by providing that token as collateral. When a token transfer occurred inside `work()`, the malicious token's `transfer()` or `transferFrom()` callback was triggered, causing reentrancy — allowing additional borrowing before the vault's balance update was completed.

---
## 2. Vulnerable Code Analysis

### 2.1 work() — Reentrancy Allowed During External Token Transfer

```solidity
// ❌ Rari Bank Vault
// work() internally triggers a transfer of an external token (malicious fake token),
// allowing reentrancy before vault state update is complete
function work(
    uint256 id,
    address worker,
    uint256 principalAmount,
    uint256 loan,
    uint256 maxReturn,
    bytes calldata data
) external payable nonReentrant {
    // Calls external worker before updating position state
    // Inside worker: malicious token transfer → reentrancy callback
    IWorker(worker).work(id, msg.sender, loan, data);
    // State update happens after → reentrancy breaks consistency
}
```

**Fixed Code**:
```solidity
// ✅ CEI pattern applied — update state first, external calls last
function work(...) external payable nonReentrant {
    // 1. Checks
    require(positions[id].owner == msg.sender || id == 0, "not owner");

    // 2. Effects: update state first
    positions[id].debtShare = newDebtShare;
    positions[id].worker = worker;

    // 3. Interactions: external call last
    IWorker(worker).work(id, msg.sender, loan, data);
}
```


### On-Chain Original Code

Source: Source unverified

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: reentrancy via malicious ERC-20 token callback during vault.work() call, allowing vault state manipulation
// Source code unverified — bytecode analysis required
// Vulnerability: reentrancy via malicious ERC-20 token callback during vault.work() call, allowing vault state manipulation
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────┐
│ Step 1: Deploy fake malicious token contract              │
│ FakeToken: triggers reentrancy via transfer() hook        │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 2: donate() 1,031 ETH to FakeToken contract          │
│ Prepare fake collateral funds                             │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 3: Call vault.work() with encoded malicious data     │
│ (principalAmount=1031 ETH, loan=large amount)             │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 4: FakeToken.transfer() callback fires inside work() │
│ → Reentrancy re-invokes vault.work()                      │
│ → Additional borrowing executed against pre-update state  │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 5: ~$11M worth of assets drained and exfiltrated     │
└──────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — fork block 12,394,009
function testExploit() public {
    // 1. Donate ETH to FakeToken contract
    fakeToken.donate{value: 1031 ether}();

    // 2. Call vault.work() with malicious encoded data
    // vault @ Rari Capital Bank
    vault.work(
        0,                    // position id (new)
        worker,               // worker address
        1031 ether,          // principalAmount
        loanAmount,          // loan
        type(uint256).max,   // maxReturn
        abi.encode(          // malicious callback data
            address(fakeToken),
            abi.encodeWithSignature("maliciousCallback()")
        )
    );
    // FakeToken.transfer() callback → reentrancy → additional borrowing
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Reentrancy during external token transfer — re-entry possible before vault state update | CRITICAL | CWE-841 |
| V-02 | Malicious ERC-20 token accepted as collateral | HIGH | CWE-284 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Strictly follow CEI (Checks-Effects-Interactions) pattern
// ✅ Only allow whitelisted approved tokens as collateral

mapping(address => bool) public approvedTokens;

function work(...) external payable nonReentrant {
    require(approvedTokens[token], "Vault: token not approved");

    // Effects: update state first
    _updatePosition(id, newDebtShare);

    // Interactions: external call last
    IWorker(worker).work(id, msg.sender, loan, data);
}
```

---
## 7. Lessons Learned

- **DeFi protocols that accept arbitrary ERC-20 tokens are exposed to reentrancy vulnerabilities.** Whitelist validation is essential.
- **A nonReentrant guard alone may not be sufficient.** If an external call occurs before internal state updates are complete, state inconsistency can arise even with the guard in place.
- **The CEI pattern (Check → Effect → Interaction) is the cornerstone of reentrancy defense.** External calls must always be performed after all state changes are finalized.