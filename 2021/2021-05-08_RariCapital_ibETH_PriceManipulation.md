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

Source: **Sourcify-verified** (partial match) — Alpha Finance Bank / ibETH (`0x67B66C99D3Eb37Fa76Aa3Ed1ff33E8e39F0b9c7A`, Ethereum)
https://sourcify.dev/server/files/any/1/0x67B66C99D3Eb37Fa76Aa3Ed1ff33E8e39F0b9c7A

The vulnerable contract is Alpha Finance's `Bank.sol` — the ibETH vault. Rari Capital's Fuse Pool used `ibETH.totalETH() / ibETH.totalSupply()` to price ibETH collateral. The attacker manipulated `totalETH()` by calling `work()`, which sends ETH to a goblin contract and uses `address(this).balance` as part of the debt accounting — a value the attacker could shift without depositing proportional ETH.

### 2.1 `work()` — The Manipulation Vector

```solidity
function work(uint256 id, address goblin, uint256 loan, uint256 maxReturn, bytes calldata data)
    external payable
    onlyEOA accrue(msg.value) nonReentrant
{
    // 1. Sanity check the input position, or add a new position of ID is 0.
    if (id == 0) {
        id = nextPositionID++;
        positions[id].goblin = goblin;
        positions[id].owner = msg.sender;
    } else {
        require(id < nextPositionID, "bad position id");
        require(positions[id].goblin == goblin, "bad position goblin");
        require(positions[id].owner == msg.sender, "not position owner");
    }
    emit Work(id, loan);
    // 2. Make sure the goblin can accept more debt and remove the existing debt.
    require(config.isGoblin(goblin), "not a goblin");
    require(loan == 0 || config.acceptDebt(goblin), "goblin not accept more debt");
    uint256 debt = _removeDebt(id).add(loan);
    // 3. Perform the actual work, using a new scope to avoid stack-too-deep errors.
    uint256 back;
    {
        uint256 sendETH = msg.value.add(loan);
        require(sendETH <= address(this).balance, "insufficient ETH in the bank");
        uint256 beforeETH = address(this).balance.sub(sendETH);
        Goblin(goblin).work.value(sendETH)(id, msg.sender, debt, data); // ❌ External call to attacker-controlled goblin
        back = address(this).balance.sub(beforeETH);
    }
    // 4. Check and update position debt.
    uint256 lessDebt = Math.min(debt, Math.min(back, maxReturn));
    debt = debt.sub(lessDebt);
    if (debt > 0) {
        require(debt >= config.minDebtSize(), "too small debt size");
        uint256 health = Goblin(goblin).health(id);
        uint256 workFactor = config.workFactor(goblin, debt);
        require(health.mul(workFactor) >= debt.mul(10000), "bad work factor");
        _addDebt(id, debt);
    }
    // 5. Return excess ETH back.
    if (back > lessDebt) SafeToken.safeTransferETH(msg.sender, back - lessDebt);
}
```

### 2.2 `totalETH()` — The Oracle Read by Rari

```solidity
function totalETH() public view returns (uint256) {
    return address(this).balance.add(glbDebtVal).sub(reservePool);
    // ❌ address(this).balance reflects the Bank's actual ETH balance
    //    During work(), ETH is transferred out to the goblin and can be returned
    //    via crafted payloads that inflate glbDebtVal without corresponding real ETH
}
```

### 2.3 `deposit()` — Share Minting Uses totalETH()

```solidity
function deposit() external payable accrue(msg.value) nonReentrant {
    uint256 total = totalETH().sub(msg.value);
    uint256 share = total == 0 ? msg.value : msg.value.mul(totalSupply()).div(total);
    // ❌ totalETH() is the oracle Rari reads for ibETH collateral price
    //    If totalETH() is inflated (more ETH "accounted" than really present),
    //    each ibETH share appears more valuable than it truly is
    _mint(msg.sender, share);
}
```

**Why it is exploitable (identify the bug from the code):**

- `work()` allows any authorized EOA to invoke a goblin contract with ETH from the Bank. The goblin is an external, attacker-controlled contract — in the original Alpha Finance design, goblins were whitelisted yield strategies.
- `totalETH()` reads `address(this).balance + glbDebtVal - reservePool`. The `glbDebtVal` accumulates debt records which, if manipulated via crafted `work()` calls, cause `totalETH()` to diverge from the true backing.
- Rari Capital priced ibETH collateral as `ibETH.totalETH() / ibETH.totalSupply()`. By making the Bank report a higher `totalETH()` than the ETH actually backing the shares, the attacker inflated the apparent per-share price of ibETH, enabling over-borrowing from Rari's Fuse pools.
- The root cause is **protocol incompatibility**: Rari used a mutable internal accounting variable (`totalETH()`) of a third-party protocol as a collateral price oracle, without recognizing that `work()` could shift that variable without proportional real ETH backing.

```solidity
// ✅ Fix: Never use an AMM's or vault's own internal balance tracker as a price oracle.
// Use a hardened external oracle (Chainlink TWAP) for ibETH/ETH pricing.
// Additionally, whitelist acceptable collateral types and audit their full interfaces
// before listing — specifically any privileged functions that affect balance accounting.
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
