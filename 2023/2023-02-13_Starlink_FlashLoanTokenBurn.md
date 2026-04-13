# Starlink Token — Flash Loan + Token Burn Mechanism Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-13 |
| **Protocol** | Starlink (STARL) Token |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | BSC Transaction |
| **Vulnerable Contract** | Starlink Token Contract |
| **Root Cause** | Burn mechanism alters LP pair reserve ratio, enabling buy/burn/sell cycle arbitrage within the same block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/Starlink_exp.sol) |

---
## 1. Vulnerability Overview

The Starlink token employs a deflationary mechanism that automatically burns a fixed percentage of tokens on each transfer. The attacker used a flash loan to swap large amounts of tokens via the LP pair, then exploited the LP ratio shift caused by the burn to generate profit. The reduction in total supply from burning creates an imbalance against the LP reserves.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable deflationary burn mechanism
function _transfer(address sender, address recipient, uint256 amount) internal {
    uint256 burnAmount = amount * burnRate / 100;
    uint256 transferAmount = amount - burnAmount;

    // ❌ When burn occurs from LP pair balance, reserve mismatch arises
    if (isLPPair[sender] || isLPPair[recipient]) {
        _burn(address(lp), burnAmount);  // Direct burn from LP
        // ❌ No sync() call → reserve > actual balance → skimmable
    }

    _balances[sender] -= amount;
    _balances[recipient] += transferAmount;
}

// ✅ Fix
function _transfer(address sender, address recipient, uint256 amount) internal {
    // Handle burn in a way that does not affect LP
    _burn(sender, burnAmount);  // Burn from sender
    IUniswapV2Pair(lp).sync();  // ✅ Sync reserves
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: burn mechanism alters LP pair reserve ratio, enabling buy/burn/sell cycle arbitrage within the same block
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Flash Loan (borrow large amount of WBNB)
  │
  ├─2─▶ WBNB → STARL bulk purchase
  │       Burn triggered → LP balance changes
  │
  ├─3─▶ Swap or skim against imbalanced LP state
  │       Extract excess relative to reserves
  │
  ├─4─▶ STARL → WBNB swap back
  │
  └─5─▶ Repay flash loan → profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function exploitStarlink(uint256 flashAmount) internal {
    // 1. Flash loan WBNB to bulk-buy STARL
    // Burn mechanism triggers during purchase, altering LP balance
    swapWBNBtoSTARL(flashAmount);

    // 2. Check imbalance between LP reserves and actual balance
    (uint112 r0, uint112 r1,) = starlWbnbPair.getReserves();
    uint256 actualBalance = IERC20(starl).balanceOf(address(starlWbnbPair));

    // 3. Exploit imbalance: skim or perform a favorable swap
    if (actualBalance > r0) {
        starlWbnbPair.skim(address(this));  // Extract excess
    }

    // 4. Swap held STARL back to WBNB
    swapSTARLtoWBNB(IERC20(starl).balanceOf(address(this)));
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Deflationary Token Mechanism Flaw |
| **Attack Vector** | Flash Loan + Burn Mechanism + Reserve Imbalance |
| **Impact Scope** | LP Liquidity Providers |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-682: Incorrect Calculation |

## 6. Remediation Recommendations

1. **Prohibit burns from LP balance**: Burns should be handled in a way that does not draw from the LP pair balance.
2. **Call sync() after burns**: Synchronize reserves after any burn that affects the LP.
3. **Adjust deflation rate**: The higher the burn rate, the greater the risk of LP imbalance.

## 7. Lessons Learned

- A burn mechanism can create LP reserve imbalances in the same way as reflective tax mechanisms.
- Custom tokenomics must undergo dedicated audits that include interaction scenarios with AMMs.
- This pattern is especially prevalent on BSC, where low gas costs make repeated attacks easy.