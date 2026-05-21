# Value DeFi (Alpaca Finance) — vault.work() Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-05-07 |
| **Protocol** | Value DeFi / Alpaca Finance (AlpacaWBNBVault) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$10,000,000 |
| **Attacker** | [0xcb36...2233](https://bscscan.com/address/0xcb36b1ee0af68dce5578a487ff2da81282512233) |
| **Attack Tx** | [0xa00d...006](https://bscscan.com/tx/0xa00def91954ba9f1a1320ef582420d41ca886d417d996362bf3ac3fe2bfb9006) (block 7,223,030) |
| **Vulnerable Contract** | AlpacaWBNBVault (work() function) |
| **Root Cause** | Invalid share calculation: during Alpaca's `work()` execution, ValueDeFi read the WBNB vault balance after the transfer to the worker but before the debt was recorded, causing the vault to over-issue vSafeWBNB shares (accounting/logic error — stale balance read during transient state, not reentrancy) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-05/ValueDefi_exp.sol) |

---
## 1. Vulnerability Overview

ValueDeFi's vSafeWBNB vault used Alpaca Finance's `AlpacaWBNBVault.work()` to deploy borrowed WBNB into leveraged yield strategies. The vulnerability was a **stale balance read during transient execution state**: when Alpaca's `work()` transferred WBNB to the worker contract (reducing the vault's WBNB balance), ValueDeFi calculated new vSafeWBNB share issuances using `balanceOf(vault)` at that intermediate moment — after the WBNB had left the vault but before the corresponding debt was recorded. This made the vault appear to have fewer backing assets than the outstanding shares warranted, causing subsequent share minting to use an inflated exchange rate. The attacker exploited this by timing their deposit to coincide with an in-flight `work()` call, receiving more vSafeWBNB shares than the deposited WBNB entitled them to. This is a **logic/accounting error** (read-during-transient-state), not a reentrancy attack. Confirmed on BSC block 7,223,030 (2021-05-07); Inspex post-mortem corroborates the May 7 date.

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
| V-01 | Stale vault balance read during transient work() state — shares issued against reduced (mid-transfer) WBNB balance before debt is recorded | CRITICAL | CWE-362 |
| V-02 | Vault share calculation does not snapshot state atomically before external calls | HIGH | CWE-682 |

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

- **Read vault balance only after all state transitions complete**: Any share issuance formula that reads `balanceOf(vault)` must do so after every pending deposit and debt-recording step is finalized. Reading it mid-transfer creates a window where the balance is artificially low.
- **Snapshot, don't observe**: Vault accounting should commit a pre-call snapshot of total assets and use that snapshot for share math, rather than querying live balances during or after external calls.
- **This is not reentrancy**: No callback re-entered ValueDeFi. The attacker timed a legitimate deposit to coincide with Alpaca's in-flight work() call. The fix is correct atomic accounting, not a reentrancy guard.
- **Protocol composition risk**: Integrating with a leverage protocol (Alpaca) where an external `work()` call temporarily shifts the vault's reported balance requires explicit handling of that transient state.