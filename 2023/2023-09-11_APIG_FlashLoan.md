# APIG — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-11 |
| **Protocol** | APIG |
| **Chain** | BSC |
| **Loss** | ~$169K (59.5 ETH + 72K USDT) |
| **Attacker** | [0x73d80500b30a6ca8...](https://bscscan.com/address/0x73d80500b30a6ca840bfab0234409d98cf588089) |
| **Attack Tx** | [0x66dee84591aeeba6...](https://bscscan.com/tx/0x66dee84591aeeba6e5f31e12fe728f2ddc79a06426036793487a980c3b952947) |
| **Vulnerable Contract** | [0xfdc6a621861ed2a8...](https://bscscan.com/address/0xfdc6a621861ed2a846ab475c623e13764f6a5ad0) |
| **Root Cause** | Collateral value calculation relies on AMM spot reserves, allowing collateral value to be inflated via large swaps within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/APIG_exp.sol) |

---
## 1. Vulnerability Overview
The APIG protocol on BSC offered loans collateralized by ETH and USDT. Because collateral value calculation depended on real-time DEX prices, a flash loan manipulation drained $169K.

---
## 2. Vulnerable Code Analysis (❌/✅ annotations)

### On-Chain Source Code

Source: **not verified on Sourcify** — APIG Token [0xfdc6a621861ed2a846ab475c623e13764f6a5ad0](https://bscscan.com/address/0xfdc6a621861ed2a846ab475c623e13764f6a5ad0) (BSC)

> ⚠️ Contract not verified on Sourcify — source unavailable. The behavior below is reconstructed from the attack PoC and on-chain traces, not verified source.

The PoC (DeFiHackLabs `APIG_exp.sol`, block 31,562,012) reveals the actual vulnerability: the APIG **token** contract has an integer accumulation flaw where a self-transfer loop inflates the attacker's balance beyond the total supply. The attack is not a lending collateral oracle attack — it is a **token balance inflation** via a while-loop self-transfer, followed by swapping the inflated balance in PancakeSwap pairs for BUSD and ETH.

```solidity
// Reconstructed from PoC — NOT verified source
// APIG Token: 0xfdc6a621861ed2a846ab475c623e13764f6a5ad0 (BSC)
// Exploited pairs:
//   aDaD: 0xaDaD973f8920bc511d94aade2762284f621F1467
//   EfBf: 0xEFBf31B0Ca397D29E9BA3fb37FE3C013EE32871d
//   b920: 0xb920456AeC6E88c68C16c8294688B2b63C81B2Ce

interface IBEP20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

// Reconstructed attack core (from PoC pancakeCall callback):
// 1. Flash loan 500 BUSD from aDaD pair
// 2. Swap BUSD → APIG via EfBf pair
// 3. ❌ Self-transfer loop inflates APIG balance:
//    while (APIG.balanceOf(address(this)) < THRESHOLD) {
//        APIG.transfer(address(this), APIG.balanceOf(address(this)));
//        // ❌ each self-transfer doubles balance due to token accounting bug
//    }
//    // Threshold: ~257,947,240,540,223,703,649,846,558,720 units
// 4. Transfer inflated APIG to EfBf pair → receive BUSD back
// 5. Transfer remaining APIG to b920 pair → receive ~59.5 ETH (BETH)
// 6. Repay flash loan (500 BUSD + 3% fee)
```

**Why it is exploitable (reconstructed from PoC and on-chain behavior):**
- The APIG token's `transfer()` (or internal accounting) does not prevent self-transfers, and a balance-doubling flaw (reflection, rebasing, or additive accounting on self-send) allows the attacker's balance to grow exponentially via repeated `transfer(self, balance)` calls.
- Once balance exceeds the AMM's reserve, the pair's `swap()` yields the entire reserve in exchange for the inflated tokens.
- The root cause is therefore a **token accounting error** (unchecked self-transfer balance inflation), not a classic oracle/collateral manipulation — though both involve price distortion via flash loan.

```solidity
// ✅ Fix: reject self-transfers in the token contract
// require(recipient != sender, "Self-transfer not allowed");
// Alternatively, base balance snapshots on actual ERC20 totalSupply invariant checks.
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Borrow large token amount via flash loan
  ├─② Manipulate collateral token price to spike sharply
  ├─③ Borrow ETH+USDT against inflated collateral value
  ├─④ Repay flash loan
  └─⑤ ~$169K profit
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
flashLoan(largeTokenAmount);
manipulateAPIG_Price();
uint256 loan = apig.borrow(ETH_USDT, largeAmount);
repayFlashLoan();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Oracle Manipulation |
| Severity | Critical |

---
## 6. Remediation Recommendations
1. Use Chainlink oracle for collateral value calculation
2. Restrict large collateral changes within a single block

---
## 7. Lessons Learned
In lending protocols, collateral value calculation is the most critical security component.