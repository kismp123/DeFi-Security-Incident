# BurgerSwap — Reentrancy + Stale Reserve Reference Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-05-28 |
| **Protocol** | BurgerSwap |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$7,200,000 |
| **Attacker** | Address unidentified |
| **Attack Tx** | Address unidentified |
| **Vulnerable Contract** | BurgerSwap Pair (BURGER/WBNB) |
| **Root Cause** | Reentrancy via a fake token with a custom transferFrom() hook causes swap amounts to be calculated using stale reserve values before the internal swap completes |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-05/BurgerSwap_exp.sol) |

---
## 1. Vulnerability Overview

BurgerSwap's router reads the current reserve values from the pair contract when calculating swap amounts. The attacker created a fake token (FAKE) with a `transferFrom()` hook and established a FAKE/BURGER pair. When the router called `transferFrom()` on the FAKE token during a swap, the attacker's code executed, triggering reentrancy. As a result, the BURGER output amount was calculated using stale reserve values — captured before the internal swap completed — enabling excess withdrawal.

---
## 2. Vulnerable Code Analysis

### 2.1 swapExactTokensForTokens() — Reserve Reference Before Swap Completion

```solidity
// ❌ BurgerSwap Router
// When calculating getAmountOut inside swap() after the transferFrom() call,
// the reserve already modified by reentrancy is not used —
// instead the stale reserve from before transferFrom() is used for calculation
function swapExactTokensForTokens(
    uint amountIn,
    uint amountOutMin,
    address[] calldata path,
    address to,
    uint deadline
) external returns (uint[] memory amounts) {
    amounts = getAmountsOut(amountIn, path);
    // FAKE token's transferFrom() call → reentrancy triggered
    TransferHelper.safeTransferFrom(path[0], msg.sender, pair, amounts[0]);
    // After reentrancy, amounts is already stale → more BURGER paid out than actual
    _swap(amounts, path, to);
}
```

**Fixed Code**:
```solidity
// ✅ Reentrancy prevention + real-time balance recalculation inside swap()
uint private _status = 1; // non-reentrant

modifier nonReentrant() {
    require(_status == 1, "ReentrancyGuard: reentrant call");
    _status = 2;
    _;
    _status = 1;
}

function swapExactTokensForTokens(...) external nonReentrant returns (uint[] memory amounts) {
    // Block reentrancy with nonReentrant
    amounts = getAmountsOut(amountIn, path);
    TransferHelper.safeTransferFrom(path[0], msg.sender, pair, amounts[0]);
    _swap(amounts, path, to);
}
```


### On-Chain Original Code

Source: Unverified

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: amount calculated using stale reserve values before internal swap completes
//               when reentered via a fake token with a custom transferFrom() hook
// Source code unverified — bytecode analysis required
// Vulnerability: amount calculated using stale reserve values before internal swap completes
//                when reentered via a fake token with a custom transferFrom() hook
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Flash loan — borrow 6,047 WBNB                  │
│ USDT-WBNB PancakeSwap pair                              │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 2: Artificially inflate price via WBNB → BURGER    │
│ BurgerSwap Router.swapExactTokensForTokens()            │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 3: Create FAKE/BURGER pair + add liquidity          │
│ FAKE token: transferFrom() callback triggers reentrancy │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 4: Reentrancy triggered — BURGER amount calculated  │
│ with stale reserves; excess BURGER withdrawn before     │
│ internal swap completes                                 │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 5: Final normalizing swap + flash loan repayment    │
│ Profit locked in: 110,791 BURGER + 8,956 WBNB           │
└─────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// pancakeCall() — attack execution in flash loan callback
function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    // 1. Price inflated via WBNB → BURGER swap
    // router.swapExactTokensForTokens(wbnb_amount, 0, [WBNB, BURGER], ...)

    // 2. Create fake FAKE token, create FAKE/BURGER pair
    // FakeToken fake = new FakeToken();
    // burgerFactory.createPair(address(fake), BURGER);

    // 3. Reentrancy trigger: FAKE token transferFrom() → nested swap
    // router.swapExactTokensForTokens([FAKE→BURGER path])
    // BURGER over-calculated with stale reserves inside the callback

    // 4. Reverse swap BURGER → WBNB + flash loan repayment
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Missing nonReentrant on swap function — reentrancy possible via custom transferFrom() hook | CRITICAL | CWE-841 |
| V-02 | Swap amount calculated with stale reserves during reentrancy — CEI violation allows reentrancy before reserve update | CRITICAL | CWE-682 |

> **Root Cause**: `swapExactTokensForTokens()` lacks reentrancy protection, and the external token `transferFrom()` is called after `getAmountsOut()` but before the reserves are updated. The flash loan is a supplementary funding mechanism; the reentrancy attack is viable with a single fake token alone.

---
## 6. Remediation Recommendations

```solidity
// ✅ Apply nonReentrant guard before all external token transfers
// ✅ Use real-time balanceOf() instead of cached reserves inside pair.swap()

// BurgerSwap Pair: move reserve update inside swap() to before transferFrom
function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external nonReentrant {
    // Calculate new reserves before token transfer (CEI pattern)
    _update(balance0, balance1, _reserve0, _reserve1);

    if (amount0Out > 0) _safeTransfer(_token0, to, amount0Out);
    if (amount1Out > 0) _safeTransfer(_token1, to, amount1Out);
    // ...
}
```

---
## 7. Lessons Learned

- **The missing nonReentrant on the DEX swap function combined with a CEI violation is the root cause of this attack.** The custom token hook is merely the trigger mechanism.
- **Reserve updates must be performed before any external token transfers.** When swap amounts are calculated using stale reserves, excess withdrawals become possible.
- **The flash loan is a supplementary tool used to pre-inflate the BURGER price.** With nonReentrant + CEI in place, the attack is blocked regardless of whether a flash loan is used.