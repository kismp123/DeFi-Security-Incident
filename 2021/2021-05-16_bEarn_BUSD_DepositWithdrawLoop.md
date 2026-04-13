# bEarn Fi — Flash Loan-Based deposit/withdraw Loop Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-05-16 |
| **Protocol** | bEarn Fi (bVault) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$11,000,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 7,457,124) |
| **Vulnerable Contract** | [0xB390B07fcF76678089cb12d8E615d5Fe494b01Fb](https://bscscan.com/address/0xB390B07fcF76678089cb12d8E615d5Fe494b01Fb) (bVault) |
| **Root Cause** | Repeated deposit→emergencyWithdraw cycle on bVault pool 13 manipulates internal accounting to enable duplicate withdrawals |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-05/bEarn_exp.sol) |

---
## 1. Vulnerability Overview

bEarn Fi's bVault manages BUSD using an Alpaca Finance strategy. By borrowing all available BUSD via a flash loan from CreamFi, then repeatedly cycling through deposit into bVault pool 13 followed by an immediate emergencyWithdraw — 10 times in total — the vault's internal accounting (share calculation) becomes corrupted, allowing withdrawal of more BUSD than was actually deposited.

---
## 2. Vulnerable Code Analysis

### 2.1 emergencyWithdraw() — Share Recalculation Error on Repeated Calls

```solidity
// ❌ bVault — accounting inconsistency on repeated emergencyWithdraw calls
// CreamFi @ 0x2Bc4eb013DDee29D37920938B96d353171289B7C
// bVault @ 0xB390B07fcF76678089cb12d8E615d5Fe494b01Fb

function emergencyWithdraw(uint256 _pid) external {
    PoolInfo storage pool = poolInfo[_pid];
    UserInfo storage user = userInfo[_pid][msg.sender];

    uint256 amount = user.amount;
    user.amount = 0;
    user.rewardDebt = 0;

    // Transfers actual tokens without decrementing totalStaked
    // On repeated calls, the same amount can be withdrawn multiple times
    pool.lpToken.safeTransfer(address(msg.sender), amount);
    emit EmergencyWithdraw(msg.sender, _pid, amount);
}
```

**Fixed Code**:
```solidity
// ✅ Immediately update pool totalStaked after emergencyWithdraw
function emergencyWithdraw(uint256 _pid) external nonReentrant {
    PoolInfo storage pool = poolInfo[_pid];
    UserInfo storage user = userInfo[_pid][msg.sender];

    uint256 amount = user.amount;
    // Clear state first (CEI)
    user.amount = 0;
    user.rewardDebt = 0;
    pool.totalStaked -= amount; // also update totalStaked

    // Transfer last
    pool.lpToken.safeTransfer(address(msg.sender), amount);
    emit EmergencyWithdraw(msg.sender, _pid, amount);
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**bVault_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: repeated deposit→emergencyWithdraw cycle on bVault pool 13 manipulates internal accounting to enable duplicate withdrawals
    function admin() external {}  // 0xf851a440
```

## 3. Attack Flow

```
┌────────────────────────────────────────────────────────────┐
│ Step 1: CreamFi Flash Loan — borrow all available BUSD     │
│ CreamFi @ 0x2Bc4eb013DDee29D37920938B96d353171289B7C      │
└─────────────────────┬──────────────────────────────────────┘
                      │ (repeated 10 times)
┌─────────────────────▼──────────────────────────────────────┐
│ Step 2: bVault.deposit(pid=13, busd_amount)               │
│ bVault @ 0xB390B07fcF76678089cb12d8E615d5Fe494b01Fb      │
│ → shares minted                                            │
└─────────────────────┬──────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────────┐
│ Step 3: bVault.emergencyWithdraw(pid=13)                   │
│ → amount withdrawn without burning shares                  │
│ → internal accounting inconsistency introduced             │
└─────────────────────┬──────────────────────────────────────┘
                      │ (after 10 repetitions)
┌─────────────────────▼──────────────────────────────────────┐
│ Step 4: Repay flash loan principal + fee                   │
│ Attacker retains surplus BUSD (~$11M)                      │
└────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// 10-cycle loop inside CreamFi flash loan callback
function flashCallback(address token, uint256 amount) external {
    // Repeat deposit → emergencyWithdraw 10 times
    for (uint i = 0; i < 10; i++) {
        // Deposit BUSD into bVault pool 13
        bVault.deposit(13, BUSD.balanceOf(address(this)));
        // Immediately emergency withdraw — accounting errors accumulate
        bVault.emergencyWithdraw(13);
    }

    // Repay flash loan to CreamFi
    uint256 repayAmount = amount + fee;
    BUSD.transfer(address(CreamFi), repayAmount);
    // Transfer surplus BUSD to attacker wallet
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing `totalStaked` update on repeated `emergencyWithdraw()` calls — even after `user.amount` is zeroed, re-deposit/re-withdraw cycles allow internal accounting inconsistency and duplicate withdrawals | CRITICAL | CWE-841 |
| V-02 | Repeated deposit-emergencyWithdraw within the same block is permitted (contributing factor: flash loan used to source funds) | MEDIUM | CWE-20 |

> **Root Cause**: `emergencyWithdraw()` zeroes `user.amount` but does not decrement `totalStaked`, making it possible to over-withdraw on each re-deposit/re-withdraw cycle. The flash loan is merely a means to obtain large capital; the attack is also feasible at smaller scale with the attacker's own funds.

---
## 6. Remediation Recommendations

```solidity
// ✅ Enforce minimum block delay between deposit and withdraw
// ✅ Apply nonReentrant to emergencyWithdraw + strictly follow CEI pattern

mapping(address => mapping(uint256 => uint256)) public lastDepositBlock;

function deposit(uint256 _pid, uint256 _amount) external nonReentrant {
    lastDepositBlock[msg.sender][_pid] = block.number;
    // ... deposit logic
}

function emergencyWithdraw(uint256 _pid) external nonReentrant {
    require(
        block.number > lastDepositBlock[msg.sender][_pid],
        "bVault: same block deposit-withdraw"
    );
    // ... withdraw following CEI pattern
}
```

---
## 7. Lessons Learned

- **The core bug in `emergencyWithdraw` is the missing `totalStaked` update.** This is the root cause; fixing it makes the attack impossible even without a flash loan.
- **The flash loan is a means to extract greater profit in a single transaction, not the vulnerability itself.** Blocking same-block deposit-withdraw is a supplementary defense.
- **`emergencyWithdraw` requires stricter state synchronization than a normal withdraw.** The CEI pattern and decrementing `totalStaked` are both mandatory.