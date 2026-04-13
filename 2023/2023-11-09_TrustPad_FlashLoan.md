# TrustPad — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-09 |
| **Protocol** | TrustPad |
| **Chain** | BSC |
| **Loss** | ~$155K |
| **Attacker** | [0x1a7b15354e2f6564...](https://bscscan.com/address/0x1a7b15354e2f6564fcf6960c79542de251ce0dc9) |
| **Attack Tx** | [0x191a34e6c0780c3d...](https://explorer.phalcon.xyz/tx/bsc/0x191a34e6c0780c3d1ab5c9bc04948e231d742b7d88e0e4f85568d57fcdc03182) |
| **Vulnerable Contract** | [0xe613c058701c768e...](https://bscscan.com/address/0xe613c058701c768e0d04d1bf8e6a6dc1a0c6d48a) |
| **Root Cause** | TPAD staking reward calculation relies on AMM spot reserve-based pricing, allowing over-reward collection via reserve manipulation within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/TrustPad_exp.sol) |

---
## 1. Vulnerability Overview
TrustPad's TPAD token staking rewards depend on real-time price, which was manipulated via a flash loan. This resulted in a $155K loss.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: reward calculated using spot price
function claimReward() external {
    uint256 tpadPrice = getTpadSpotPrice(); // ❌ manipulable
    uint256 reward = stakedAmount * tpadPrice * rewardRate;
    tpad.transfer(msg.sender, reward);
}
// ✅ Fix: use TWAP
```

---
### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: TPAD staking reward calculation relies on AMM spot reserve-based pricing, allowing over-reward collection via reserve manipulation within a single block
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Buy TPAD (manipulate price upward)
  ├─② Call claimReward() → excess rewards
  ③ Sell TPAD
  └─④ ~$155K profit
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// First, buy TPAD with BNB to pump the price
buyTPAD(bnbAmount);
// Claim rewards at inflated price
tpad.claimReward();
// Sell TPAD
sellTPAD();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Price Manipulation |
| Severity | High |

---
## 6. Remediation Recommendations
1. TWAP-based reward calculation
2. Cooldown period to prevent reward claims immediately after purchase

---
## 7. Lessons Learned
Tying staking rewards to the current token price makes the protocol vulnerable to price manipulation attacks.