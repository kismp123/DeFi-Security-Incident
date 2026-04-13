# Security Incident Analysis: Movie Token (MT) PendingBurn LP Burn Attack

---

## Overview

| Field | Details |
|------|------|
| **Date** | 2026-03-10 00:05:23 UTC |
| **Network** | BNB Smart Chain (BSC) |
| **Block** | 85,677,691 |
| **TX** | `0xfb57c980286ea8755a7b69de5a74483c44b1f74af4ab34b7c52e733fc62dfca6` |
| **Attacker EOA** | `0xDB0901A3254f47c0CE57fFFCE2C730Bc33A1c0e1` |
| **Attack Contract** | `0xDf7eD22d1FA65eAc11A0806b7bb5F35d4A1e957D` |
| **Victim Token** | Movie Token (MT) `0xb32979f3a5b426a4a6ae920f2b391d885abf4c18` |
| **Attack Entry Function** | `exploit(address,address,address,address)` |
| **Net Profit** | **381.75 WBNB (~$229,050)** |

---

## Attack Summary

The attacker borrowed WBNB via a flash loan and manipulated the **Movie Token (MT) `PendingBurn` execution mechanism** to forcibly burn **99.7% (6,735,516 MT)** of the MT held by the LP pool to `0xDead`.
After the burn, the MT quantity in the LP pool dropped sharply, causing the MT price to **surge 322x**.
The attacker then sold pre-purchased tokens at the inflated price, stealing **381.75 WBNB**.

This attack exploits a vulnerability where the token's **deflationary burn mechanism directly debits the LP pool's balance**,
sharing the same root cause as the HERMES HB token attack (tax deductions debited from the pool balance).

---

## Contracts Involved

| Role | Address | Protocol |
|------|------|----------|
| Flash Loan Provider | `0x8f73b65b4caaf64fba2af91cc5d4a2a1318e5d8c` | Flash Loan Provider (BSC) |
| PancakeSwap Router v2 | `0x10ed43c718714eb63d5aa57b78b54704e256024e` | PancakeSwap |
| MT/WBNB LP Pool | `0x037e6eb26275dbfe3a5244239bbe973f1a56b449` | PancakeSwap LP |
| Victim Token | `0xb32979f3a5b426a4a6ae920f2b391d885abf4c18` | Movie Token (MT) |
| WBNB | `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c` | Wrapped BNB |

---

## Movie Token (MT) Deflationary Mechanism

Movie Token employs the following composite tax/burn structure:

| Event | 4byte | Description |
|--------|-------|------|
| `ReferralPending(address,address)` | `0xc0a13dbe` | Registers pending referral reward on transfer |
| `PendingBurnRecorded(address,uint256)` | `0x74c09668` | Records the scheduled burn amount |
| `FeesProcessed(uint256,uint256)` | `0x6e6f4592` | Fee distribution completed |
| `PendingBurnExecuted(uint256)` | `0x3587533d` | Executes the scheduled burn |
| `DeflationStopped()` | `0x7dd84aa6` | Deflationary mechanism halted |

**Key vulnerable behavior**: When `PendingBurnExecuted` is triggered, it internally calls
`_transfer(from=LP_pool, to=0xDead, amount=pendingBurnAmount)`,
**burning directly from the LP pool's token balance**.

---

## LP Pool Reserve Changes (Based on Sync Events)

| Stage | Log | MT Reserve | WBNB Reserve | k Value | Notes |
|------|-----|----------|------------|------|------|
| Initial (estimated) | - | 17,756,517 | 384.27 | 6.83e9 | Before attack |
| After 1st buy | 0x31 | 17,756,517 | 384.27 | - | Includes LP Mint |
| 1st buy complete | 0x36 | **7,756,517** | 880.93 | 6.84e9 | Purchased 10M MT |
| LP minor removal | 0x3e | 7,756,517 | 880.93 | - | Minor adjustment |
| 1st sell/transfer | 0x4a | 16,756,517 | 483.60 | 8.11e9 | 9M MT returned |
| 2nd buy complete | 0x4f | **6,756,517** | 1,201.15 | 8.12e9 | Purchased 10M MT |
| LP minor removal | 0x56 | 6,756,517 | 1,201.15 | - | |
| **PendingBurnExecuted** | **0x5c** | **21,000** | **1,201.15** | **25.2M** | **🔴 6.74M MT burned** |
| After final sell | 0x61 | 10,021,000 | 2.52 | 25.3M | Sold 10M MT |

**k collapse**: 8,115,601,707 → 25,224,185 (**322x decrease**)

---

## Attack Flow

```
Attacker EOA (0xDB09...)
  │
  └─▶ exploit(MT, PancakeRouter, LP_pool, ?) called
        │
        ├─[1] FlashLoan: Borrow 358,681 WBNB (flash pool → ATK)
        │
        ├─[2] Small buy/sell (0.2 MT) → Trigger ReferralPending (x2)
        │      └─ Initialize referral state in token contract
        │
        ├─[3] Add small LP liquidity (Mint LP)
        │
        ├─[4] 1st Buy: 496.66 WBNB → LP → Receive 10,000,000 MT
        │      LP state: MT=7,756,517, WBNB=880.93
        │
        ├─[5] 1M MT → Transfer to MT contract
        │      └─ Contract distributes fees then moves to fee address
        │
        ├─[6] 9M MT → Transfer to LP (sell)
        │      └─ PendingBurnRecorded(9,000,000 MT)
        │      └─ FeesProcessed event
        │      → Receive +397.33 WBNB
        │
        ├─[7] 2nd Buy: 717.55 WBNB → LP → Receive 10,000,000 MT
        │      LP state: MT=6,756,517, WBNB=1,201.15, k=8.12e9
        │
        ├─[8] LP Burn (remove liquidity) executed
        │
        ├─[9] ██ PendingBurnExecuted ██
        │      └─ _transfer(from=LP_pool, to=0xDead, 6,735,516 MT)
        │      LP state: MT=21,000, WBNB=1,201.15
        │      k: 8.12e9 → 25.2M (322x decrease!)
        │      MT price: 0.000178 → 0.0572 WBNB (322x surge!)
        │
        ├─[10] DeflationStopped() triggered (burn mechanism halted)
        │
        ├─[11] 10,000,000 MT → LP sell
        │       LP: MT 10,021,000 / WBNB 2.52
        │       → Receive +1,198.63 WBNB
        │
        ├─[12] Repay FlashLoan: Return 358,681 WBNB
        │
        └─[13] Transfer 381.75 WBNB to attacker EOA (net profit)
```

---

## Event Log Summary (Key Segments)

| Log | Event | Details |
|-----|--------|------|
| 0x25 | `FlashLoan` | Flash loan of 358,681.54 WBNB |
| 0x26 | Transfer WBNB | Flash Pool → ATK: 358,681.54 |
| 0x28 | Transfer MT | LP → ATK: 0.2 MT (small buy) |
| 0x2a | `ReferralPending` | ATK, LP (referral state registered) |
| 0x32 | `Mint` (LP) | Liquidity added |
| 0x36 | Sync | MT=7,756,517, WBNB=880.93 (after 1st buy) |
| 0x43 | Transfer MT | ATK → TOKEN: 1,000,000 MT |
| 0x44 | `PendingBurnRecorded` | Scheduled burn of 9,000,000 MT recorded |
| 0x45 | Transfer MT | ATK → LP: 9,000,000 MT (sell) |
| 0x46-48 | Transfer MT | Token contract fee distribution |
| 0x49 | `FeesProcessed` | Fee processing complete |
| 0x4f | Sync | MT=6,756,517, WBNB=1,201.15 (after 2nd buy) |
| **0x5a** | **Transfer MT** | **🔴 LP → 0xDead: 6,735,516 MT** |
| **0x5b** | **`PendingBurnExecuted`** | **🔴 6,735,516 MT burn complete** |
| **0x5c** | **Sync** | **MT=21,000, WBNB=1,201.15 (k decreased 322x)** |
| 0x5f | `DeflationStopped` | Deflation halted |
| 0x60 | Transfer WBNB | LP → ATK: 1,198.63 WBNB |
| 0x62 | Swap | Final 10M MT → 1,198 WBNB |
| 0x64 | Transfer WBNB | ATK → Flash Pool: 358,681.54 (repayment) |
| 0x66 | Transfer WBNB | ATK → Attacker EOA: **381.75 WBNB** |

---

## Profit Analysis

### WBNB Flow

| Direction | Amount | Description |
|------|------|------|
| **IN** | 358,681.54 WBNB | Flash loan received |
| **IN** | 397.33 WBNB | 1st sell proceeds (9M MT) |
| **IN** | 1,198.63 WBNB | 2nd sell proceeds (10M MT after burn-driven surge) |
| **OUT** | 496.66 WBNB | 1st buy (10M MT) |
| **OUT** | 717.55 WBNB | 2nd buy (10M MT) |
| **OUT** | 358,681.54 WBNB | Flash loan repayment |
| **OUT** | **381.75 WBNB** | **Net profit (attacker EOA)** |

### LP Manipulation Profit

| Cycle | WBNB In | WBNB Out | P&L |
|--------|----------|----------|------|
| 1st buy → 9M sell | 496.66 | 397.33 | **-99.33** |
| 2nd buy → 10M sell (post-burn) | 717.55 | 1,198.63 | **+481.08** |
| **Total** | **1,214.21** | **1,595.96** | **+381.75 WBNB** |

---

## Root Cause: Direct Burn from LP Pool Balance

### Vulnerable Behavior

```
On PendingBurnExecuted:
  _transfer(from = LP_Pool_Address,  ← ❌ Debits from pool's token balance
            to   = 0x000...dEaD,
            amount = pendingBurnAmount)
```

From the AMM (PancakeSwap) perspective:
- `_transfer` modifies ERC20-level balances
- The LP pool cannot update its internal `reserve0` without a `Sync`
- Result: **LP actual balance < LP internal reserve0** → k invariant broken

### Comparison: Similar Attack Patterns

| Attack | Vulnerable Mechanism | LP Balance Deduction Method |
|------|-------------|------------------|
| HERMES HB (2026-04-07) | `_handleBuy` tax | `super._transfer(from=LP, contract, tax)` |
| Movie Token MT (2026-03-10) | `PendingBurnExecuted` | `_transfer(from=LP, 0xDead, pendingBurn)` |
| TR/NOBEL (2026-03-26) | Burn-redistribution ratio | Deducted via separate distributor |

**Common pattern**: The token's tax/burn logic uses the **LP pool address as `from`** to move tokens
→ AMM k invariant broken → price manipulation possible

### LP k Invariant Collapse Process

```
[Before burn]
  LP.reserve_MT   = 6,756,517  (LP internal record)
  IERC20(MT).balanceOf(LP) = 6,756,517  (actual balance)
  k = 6,756,517 × 1,201 = 8.12e9

[PendingBurnExecuted called]
  MT._transfer(from=LP, to=0xDead, 6,735,517)
  → IERC20(MT).balanceOf(LP) = 21,000  ← actual balance plummets!
  → LP.reserve_MT still holds 6,756,517 (no Sync yet)

[On next Swap/Sync]
  LP.sync() called → reserve_MT = 21,000  
  → new k = 21,000 × 1,201 = 25.2M  (322x decrease!)
  → MT price surges 322x
```

---

## Vulnerable Code Pattern (Estimated)

```solidity
// ❌ Vulnerable: Burn directly from LP pool balance — breaks AMM k invariant
function _executePendingBurn(address lpPool) internal {
    uint256 burnAmount = pendingBurnAmount;
    if (burnAmount == 0) return;
    pendingBurnAmount = 0;

    // Uses LP pool address as from → corrupts LP reserve integrity!
    _transfer(lpPool, address(0xdead), burnAmount);
    
    emit PendingBurnExecuted(burnAmount);
    emit DeflationStopped();
}
```

### Remediation

```solidity
// ✅ Fix 1: Burn from contract's own balance
function _executePendingBurn() internal {
    uint256 burnAmount = pendingBurnAmount;
    if (burnAmount == 0) return;
    pendingBurnAmount = 0;
    
    // Burn only from tokens collected by the contract as fees
    require(balanceOf(address(this)) >= burnAmount, "Insufficient burn reserve");
    _transfer(address(this), address(0xdead), burnAmount);
    
    emit PendingBurnExecuted(burnAmount);
}

// ✅ Fix 2: Force sync() after LP burn (not recommended — still risky)
function _executePendingBurnFromLP(address lpPool) internal {
    uint256 burnAmount = pendingBurnAmount;
    pendingBurnAmount = 0;
    _transfer(lpPool, address(0xdead), burnAmount);
    IPancakePair(lpPool).sync();  // Force AMM internal state update
    emit PendingBurnExecuted(burnAmount);
}
```

---

## Flash Loan Usage Pattern

```
Flash loan size: 358,681 WBNB (actual used: 1,214 WBNB)
Repayment: 358,681 WBNB (same amount, zero or negligible fee)

→ The attack only required ~1,214 WBNB in actual capital,
   yet an unnecessarily large flash loan was taken
   (likely to ensure sufficient repayment buffer or due to attack script design)
```

---

## Attack Outcome

| Metric | Value |
|------|------|
| LP MT burned | 6,735,516 MT (99.7% of pool holdings) |
| MT total supply | 21,000,000 MT |
| LP k decrease ratio | 322x (8.12e9 → 25.2M) |
| MT price increase | 322x (0.000178 → 0.0572 WBNB/MT) |
| Attacker net profit | **381.75 WBNB (~$229,050)** |
| Damage (LP liquidity) | 99%+ of LP real value destroyed |

---

## Reference Links

- **Phalcon Explorer**: https://app.blocksec.com/phalcon/explorer/tx/eth/0xfb57c980286ea8755a7b69de5a74483c44b1f74af4ab34b7c52e733fc62dfca6
- **BSCScan TX**: https://bscscan.com/tx/0xfb57c980286ea8755a7b69de5a74483c44b1f74af4ab34b7c52e733fc62dfca6
- **Movie Token (MT)**: https://bscscan.com/token/0xb32979f3a5b426a4a6ae920f2b391d885abf4c18
- **MT/WBNB LP**: https://bscscan.com/address/0x037e6eb26275dbfe3a5244239bbe973f1a56b449

---

## Lessons Learned

1. **Any token transfer using the LP pool address as `from` is dangerous**
   Regardless of the justification — tax, burn, rebase, etc. — directly debiting the LP address
   breaks the AMM's k invariant.

2. **Pending/delayed burn mechanisms carry additional risk**
   Unlike immediate burns (with instant sync), delayed burns cannot predict the LP state
   at execution time, leading to far greater price impact.

3. **Deflationary token design must account for AMM integration**
   Burn logic must be designed to be AMM-aware: always pair with the LP pool's `sync()` or `skim()`,
   or explicitly exclude LP pool addresses from burn targets.