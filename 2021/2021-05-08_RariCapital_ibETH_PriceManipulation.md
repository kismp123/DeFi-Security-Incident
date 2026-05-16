# Rari Capital — ERC-20 Hook Reentrancy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-05-08 |
| **Protocol** | Rari Capital (Fuse Pool) |
| **Chain** | Ethereum |
| **Loss** | ~$11,000,000 |
| **Attacker** | Address unidentified |
| **Attack Tx** | Address unidentified (fork block: 12,394,009) |
| **Vulnerable Contract** | Rari Capital Fuse Pool (CEther market `borrow()`) |
| **Root Cause** | ibETH (Alpha Finance) exposes a `work()` function that makes arbitrary external calls and updates `totalETH()` — the internal balance tracker Rari used to price ibETH collateral. Attacker crafted a `work()` call that inflated `totalETH()` without adding real ETH, raising the apparent ibETH price and enabling over-borrowing (protocol incompatibility / price manipulation, not reentrancy) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-05/RariCapital_exp.sol) |

---
## 1. Vulnerability Overview

Rari Capital's Fuse is a permissionless Compound V2 fork. Pool 18 accepted ibETH (Alpha Finance's interest-bearing ETH token) as collateral. Rari priced ibETH using `ibETH.totalETH() / ibETH.totalSupply()` — a ratio tracked internally by the Alpha Finance vault.

Alpha Finance's ibETH exposes a `work()` function that allows the vault owner (or authorized callers) to invoke arbitrary external contracts and update `totalETH()` in the process. The attacker exploited a **protocol incompatibility**: by calling `ibETH.work()` with crafted calldata that manipulated the internal `totalETH()` accounting (inflating it without depositing proportional real ETH), the attacker made their ibETH collateral appear worth more than it actually was. Rari's borrow allowance calculation read this inflated price and permitted borrowing well beyond the real collateral value.

This is **price manipulation via a privileged internal function**, not an ERC-677 transfer callback reentrancy. SlowMist and Halborn both classify this as "protocol incompatibility / price oracle manipulation." The ERC-677 reentrancy description belongs to the **April 2022** Rari Fuse exploit ($80M, Pool 127), a different incident on a different contract.

---
## 2. Vulnerable Code Analysis

### 2.1 CEther.borrow() — State Updated After External Call (CEI Violation)

```solidity
// ❌ Rari Fuse Pool — CEther (Compound fork) borrow()
// ibETH.transferFrom() fires a callback before borrow balance is recorded
function borrowFresh(address payable borrower, uint borrowAmount) internal returns (uint) {
    // 1. Check: verify borrower has sufficient collateral
    uint allowed = comptroller.borrowAllowed(address(this), borrower, borrowAmount);
    require(allowed == 0, "borrow not allowed");

    // 2. Interaction: transfer ibETH collateral (fires ERC-677 hook on recipient)
    //    ❌ Attacker's callback reenters borrow() here — borrow balance still = 0
    doTransferOut(borrower, borrowAmount);  // sends ETH, triggering receive()

    // 3. Effect: borrow balance updated AFTER the external call
    //    ❌ Too late — reentrancy already exploited the stale state
    accountBorrows[borrower].principal = accountBorrowsNew;
    totalBorrows = totalBorrowsNew;
}
```

**Fixed Code**:
```solidity
// ✅ CEI pattern: Effects before Interactions, plus nonReentrant guard
function borrowFresh(address payable borrower, uint borrowAmount) internal nonReentrant returns (uint) {
    // 1. Checks
    uint allowed = comptroller.borrowAllowed(address(this), borrower, borrowAmount);
    require(allowed == 0, "borrow not allowed");

    // 2. Effects: update borrow state FIRST
    accountBorrows[borrower].principal = accountBorrowsNew;
    totalBorrows = totalBorrowsNew;

    // 3. Interactions: external call last — reentrancy now harmless
    doTransferOut(borrower, borrowAmount);
}
```

### On-Chain Original Code

Source: Source unverified

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable Function** — `borrowFresh()`:
```solidity
// ❌ Root cause: ibETH ERC-677 transfer hook triggers reentrancy into borrow() before
//    borrow balance is updated, allowing over-borrowing against the same ibETH collateral.
//    Source code unverified — bytecode analysis required.
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Step 1: Deposit ibETH (Alpha Finance) as collateral          │
│ into Rari Capital Fuse Pool 18/19                            │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 2: Call CEther.borrow(borrowAmount) on Fuse Pool        │
│ Liquidity check passes (sufficient ibETH collateral)         │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 3: doTransferOut() sends ETH to attacker contract       │
│ → attacker.receive() fires (borrow balance NOT yet updated)  │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 4: receive() callback reenters CEther.borrow()          │
│ → liquidity check passes again (stale balance still = 0)     │
│ → second borrow succeeds against same collateral             │
└─────────────────────┬────────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│ Step 5: Control returns; original borrow balance finally set  │
│ Attacker holds 2× borrowed ETH with collateral for only 1×   │
│ ~$11M in assets drained from Fuse Pool                       │
└──────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — fork block 12,394,009
// Attack uses ibETH ERC-677 callback to reenter borrow()

contract RariAttacker {
    IRariFusePool pool;
    IibETH ibETH;

    // Called when ETH is sent during pool.borrow()
    receive() external payable {
        // Reenter borrow() before first borrow's balance is written
        // Liquidity check sees stale (zero) borrow balance → allows second borrow
        pool.borrow(borrowAmount);
    }

    function attack() external {
        // Supply ibETH as collateral
        ibETH.approve(address(pool), type(uint256).max);
        pool.mint(collateralAmount);        // deposit ibETH
        pool.enterMarkets(new address[](1)); // register as collateral

        // First borrow — triggers receive() → reentrancy → second borrow
        pool.borrow(borrowAmount);
        // Both borrows succeed; attacker holds 2× ETH for 1× collateral
    }
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Protocol incompatibility: ibETH.work() can manipulate totalETH() used by Rari as a price oracle | CRITICAL | CWE-829 |
| V-02 | Rari priced ibETH collateral from a manipulable internal vault accounting variable rather than a hardened external oracle | CRITICAL | CWE-668 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Two defenses required together:

// 1. Apply nonReentrant to all state-mutating functions
function borrow(uint borrowAmount) external nonReentrant returns (uint) {
    return borrowFresh(payable(msg.sender), borrowAmount);
}

// 2. Strictly follow CEI: update accountBorrows BEFORE doTransferOut()
function borrowFresh(address payable borrower, uint borrowAmount) internal returns (uint) {
    // Checks
    uint allowed = comptroller.borrowAllowed(address(this), borrower, borrowAmount);
    require(allowed == 0, "not allowed");

    // Effects (state first)
    accountBorrows[borrower].principal = accountBorrowsNew;
    totalBorrows = totalBorrowsNew;

    // Interactions (external call last)
    doTransferOut(borrower, borrowAmount);
    return uint(Error.NO_ERROR);
}
```

---
## 7. Lessons Learned

- **Protocol incompatibility is as dangerous as code bugs**: Rari correctly implemented Compound's borrow logic, but failed to assess whether ibETH's internal accounting functions (`work()`, `totalETH()`) could be exploited to manipulate the price used for collateral valuation.
- **Do not use a vault's own internal balance tracker as a price oracle**: `totalETH()` reflects Alpha Finance's bookkeeping, which can be updated via privileged calls. A manipulation-resistant oracle (Chainlink TWAP, time-weighted average) must be used instead.
- **Collateral compatibility audit**: Before listing any token as collateral, its full interface must be reviewed — including admin/privileged functions that could affect the variables used for pricing.
- **Distinct from the April 2022 Rari Fuse exploit**: The April 2022 incident ($80M, Pool 127) involved classic ETH-transfer reentrancy via `receive()` fallback — a different contract, different mechanism, different attacker. The May 2021 incident was price manipulation via ibETH.work().
