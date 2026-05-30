# AST Token — Double Withdrawal + skim() Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-25 |
| **Protocol** | AST Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$65,000 |
| **Attacker** | [0x56f7...EA4f](https://bscscan.com/address/0x56f77AdC522BFfebB3AF0669564122933AB5EA4f) |
| **Attack Tx** | [0x80dd...3927](https://bscscan.com/tx/0x80dd9362d211722b578af72d551f0a68e0dc1b1e077805353970b2f65e793927) |
| **Vulnerable Contract** | [0xc10E0319...](https://bscscan.com/address/0xc10E0319337c7F83342424Df72e73a70A29579B2) |
| **Root Cause** | Bug where AST token is withdrawn twice during liquidity removal, leaving the LP balance 1 unit higher than expected; the surplus is extractable via `skim()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Ast_exp.sol) |

---

## 1. Vulnerability Overview

The AST token contract had a bug in its internal logic during liquidity removal operations where tokens were withdrawn twice. Specifically, when 6,688,350,004,594,453,500 AST was added, the LP retained 6,688,350,004,594,453,501 — a discrepancy of 1 unit. The attacker amplified this imbalance by flash-borrowing 30 million BUSD from PancakeSwap V3 to bulk-purchase AST, then extracted the surplus via the `skim()` function, swapped back to BUSD, and stole $65,000.

## 2. Vulnerable Code Analysis

### On-Chain Source Code (verified)

Source: **Sourcify-verified** — `AST` token `0xc10E0319337c7F83342424Df72e73a70A29579B2` (BSC), Solidity v0.8.28
(`https://sourcify.dev/server/files/any/56/0xc10E0319337c7F83342424Df72e73a70A29579B2`)

The vulnerability lives entirely inside the token's custom `_transfer` override. Two interacting defects create a tiny, repeatable accounting surplus inside the PancakeSwap pair:

```solidity
function _transfer(address from, address to, uint256 amount) internal virtual {
    require(from != address(0), "ERC20: transfer from the zero address");
    _beforeTokenTransfer(from, to, amount);

    uint256 fromBalance = _balances[from];
    require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
    unchecked {
        _balances[from] = fromBalance - amount;   // (1) sender debited the FULL `amount`
    }
    // ❌ DEFECT A: when the entire balance is moved, the local `amount` is silently
    //    shaved by 1e14 — but `_balances[from]` was already reduced by the full amount above.
    if (fromBalance == amount && fromBalance >= 1e14) {
        amount -= 1e14;                            // 1e14 "vanishes" from the credited side
    }

    if (from != uniswapV2Pair && !wList[from] && !wList[to] && to != uniswapV2Pair) {
        _balances[to] += (amount);
        emit Transfer(from, to, (amount));
    } else if (wList[from] || wList[to]) {
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    } else {
        uint feeAmount;
        if (to == uniswapV2Pair) {
            if (!checkLiquidityAdd(from)) {
                if (saleFeeRate > 0) { feeAmount = amount * saleFeeRate / 100;
                    _balances[sellfee] += feeAmount; emit Transfer(from, sellfee, feeAmount); }
            }
        }
        if (from == uniswapV2Pair) {
            if (checkLiquidityRm(to)) {
                // ❌ DEFECT B: on liquidity removal the pair is the sender; `_burn` uses the
                //    ALREADY-shaved `amount`, so the pair burns 1e14 LESS than it was debited.
                _burn(from, amount);
                amount = 0;
            } else {
                if (buyFeeRate > 0) { feeAmount = amount * buyFeeRate / 100;
                    _balances[buyfee] += feeAmount; emit Transfer(from, buyfee, feeAmount); }
            }
        }
        _balances[to] += (amount - feeAmount);
        emit Transfer(from, to, (amount - feeAmount));
    }
    _afterTokenTransfer(from, to, amount);
}

// Detects a liquidity-removal transfer by watching the caller's LP-token balance shrink.
function checkLiquidityRm(address user) internal returns (bool) {
    IERC20 lpToken = IERC20(uniswapV2Pair);
    uint256 currentBalance = lpToken.balanceOf(user);
    uint256 previousBalance = lastBalance[user];
    if (currentBalance < previousBalance) {           // LP balance fell → user removed liquidity
        emit LiquidityRemoved(user, previousBalance - currentBalance);
        lastBalance[user] = currentBalance;
        return true;
    }
    return false;
}
```

**Why it is exploitable (identify the bug from the code):**
- At **(1)** the contract debits `_balances[from]` by the *full* `amount`.
- **DEFECT A** then reduces the local `amount` by `1e14` whenever the full balance is moved, so every downstream credit/burn that uses `amount` is `1e14` short of what was debited.
- **DEFECT B**: during liquidity removal the pair (`from == uniswapV2Pair`) burns only the shaved `amount`. The pair's *real* AST balance therefore ends up `1e14` higher than the `reserve` the AMM recorded. That stranded `1e14` is exactly what `skim()` (which pays out `balanceOf(pair) - reserve` to the caller) hands to the attacker — repeatedly, once per crafted full-balance removal.

```solidity
// ✅ Fix: never mutate the working `amount` after the balance has been debited, and make
//    burn/credit amounts derive from a single source of truth.
function _transfer(address from, address to, uint256 amount) internal virtual {
    require(from != address(0), "ERC20: transfer from the zero address");
    uint256 fromBalance = _balances[from];
    require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
    _balances[from] = fromBalance - amount;
    // no `amount -= 1e14` shaving; burn and credit use the same `amount` that was debited
    if (from == uniswapV2Pair && checkLiquidityRm(to)) { _burn(from, amount); return; }
    _balances[to] += amount;
    emit Transfer(from, to, amount);
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