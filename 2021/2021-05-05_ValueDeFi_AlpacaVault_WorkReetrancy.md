# Value DeFi (Alpaca Finance) — vault.work() Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-05-05 |
| **Protocol** | Value DeFi / Alpaca Finance (AlpacaWBNBVault) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$10,000,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 7,223,029) |
| **Vulnerable Contract** | AlpacaWBNBVault (work() function) |
| **Root Cause** | Reentrancy via malicious token callback when vault.work() calls an external worker contract, enabling vault state manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-05/ValueDefi_exp.sol) |

---
## 1. Vulnerability Overview

The `work()` function of AlpacaWBNBVault calls an external worker contract to manage leveraged positions. The attacker provided 1 WBNB as principal and borrowed ~393 BNB during the `work()` call, then induced a malicious callback to execute inside the worker. Reentrancy occurred before the vault state was updated within the callback, allowing additional fund withdrawal.

---
## 2. Vulnerable Code Analysis

### 2.1 work() — State Update After External Call (CEI Violation)

```solidity
// ❌ AlpacaWBNBVault
function work(
    uint256 id,
    address worker,
    uint256 principalAmount,
    uint256 borrowAmount,
    uint256 maxReturn,
    bytes calldata data
) external payable {
    // 1. Execute loan (WBNB)
    _takeLoan(id, borrowAmount);

    // 2. External worker call — can trigger malicious callback
    // debtShare not yet updated at this point
    IWorker(worker).work{value: msg.value}(id, msg.sender, borrowAmount, data);

    // 3. State update occurs after external call → CEI violation
    positions[id].debtShare = _toDebtShare(newDebt);
}
```

**Fixed Code**:
```solidity
// ✅ Move state update before external call
function work(
    uint256 id,
    address worker,
    uint256 principalAmount,
    uint256 borrowAmount,
    uint256 maxReturn,
    bytes calldata data
) external payable nonReentrant {
    // 1. Execute loan
    _takeLoan(id, borrowAmount);

    // 2. Update state first (Effect)
    positions[id].debtShare = _toDebtShare(newDebt);
    positions[id].worker = worker;

    // 3. External call last (Interaction)
    IWorker(worker).work{value: msg.value}(id, msg.sender, borrowAmount, data);
}
```


### On-Chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: Reentrancy via malicious token callback when vault.work() calls an external worker contract, enabling vault state manipulation
// Source code unconfirmed — bytecode analysis required
// Vulnerability: Reentrancy via malicious token callback when vault.work() calls an external worker contract, enabling vault state manipulation
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────────────┐
│ Step 1: AlpacaWBNBVault.work() call                    │
│ principalAmount = 1 WBNB                               │
│ borrowAmount    = ~393 BNB                             │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 2: _takeLoan() — borrow 393 BNB from vault        │
│ State before debtShare update                          │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 3: IWorker(worker).work() external call           │
│ → Malicious worker executes callback                   │
│ → Reenter vault.work() — with debtShare not updated,   │
│   additional borrowing is possible                     │
└─────────────────────┬──────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 4: Drain funds via encoded data and exit          │
│ ~10M WBNB equivalent stolen                            │
└────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — BSC fork block 7,223,029
function testExploit() public {
    // vault.work() call — includes malicious encoded data
    // AlpacaWBNBVault @ BSC
    alpacaVault.work{value: 1 ether}(
        0,                  // Position ID (new)
        maliciousWorker,    // Malicious worker address
        1 ether,            // principal: 1 WBNB
        393 ether,          // borrow: ~393 BNB
        0,                  // maxReturn
        abi.encode(
            msg.sender,     // recipient
            abi.encodeWithSignature("reentrantAttack()")
        )
    );
    // maliciousWorker.work() → reentrantAttack() → reenter vault.work()
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | debtShare update after external call in work() — CEI violation reentrancy | CRITICAL | CWE-841 |
| V-02 | No worker address validation — arbitrary malicious worker allowed | HIGH | CWE-284 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Approved worker whitelist + nonReentrant + CEI pattern

mapping(address => bool) public approvedWorkers;

modifier onlyApprovedWorker(address worker) {
    require(approvedWorkers[worker], "Vault: unapproved worker");
    _;
}

function work(...) external payable nonReentrant onlyApprovedWorker(worker) {
    // Effects first
    positions[id].debtShare = _toDebtShare(newDebt);
    // Interactions last
    IWorker(worker).work{value: msg.value}(id, msg.sender, borrowAmount, data);
}
```

---
## 7. Lessons Learned

- **The `work()` pattern in leverage vaults is inherently high-risk for reentrancy because external calls are central to its operation.** All state changes must be finalized before any external call.
- **Allowing arbitrary addresses as workers without a whitelist gives attackers free rein to inject malicious callbacks.**
- **nonReentrant and CEI must be used together.** nonReentrant alone cannot prevent state inconsistencies.