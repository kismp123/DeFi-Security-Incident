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


### On-Chain Source Code

Source: **Sourcify partial match** — DemaxPlatform (BurgerSwap Router) / 0xBf6527834dBB89cdC97A79FCD62E6c08B19F8ec0 (BSC)
https://sourcify.dev/server/files/any/56/0xBf6527834dBB89cdC97A79FCD62E6c08B19F8ec0

> Note: The DemaxPair contract (LP pair, 0x7ac55ac530f2c29659573bde0700c6758d69e677) is not verified on Sourcify. The router (DemaxPlatform) is partial-matched. The code below is verbatim from the verified router source.

```solidity
// File: DemaxPlatform.sol — BurgerSwap Router (partial match, BSC)

function swapExactTokensForTokens(
    uint256 amountIn,
    uint256 amountOutMin,
    address[] calldata path,
    address to,
    uint256 deadline
) external ensure(deadline) returns (uint256[] memory amounts) {
    uint256 percent = _getSwapFeePercent();
    amounts = _getAmountsOut(amountIn, path, percent); // ❌ amounts computed here from current reserves
    require(amounts[amounts.length - 1] >= amountOutMin, 'DEMAX PLATFORM : INSUFFICIENT_OUTPUT_AMOUNT');
    address pair = DemaxSwapLibrary.pairFor(FACTORY, path[0], path[1]);
    _innerTransferFrom(                                // ❌ external call to path[0].transferFrom()
        path[0],                                       //    if path[0] is the FAKE token, the attacker's
        msg.sender,                                    //    transferFrom() hook fires here, allowing a
        pair,                                          //    nested call back into swapExactTokensForTokens()
        SafeMath.mul(amountIn, SafeMath.sub(PERCENT_DENOMINATOR, percent)) / PERCENT_DENOMINATOR
    );
    _swap(amounts, path, to);                          // ❌ uses stale amounts[] from before the re-entry
    _innerTransferFrom(path[0], msg.sender, pair, SafeMath.mul(amounts[0], percent) / PERCENT_DENOMINATOR);
    _swapFee(amounts, path, percent);
}

// No nonReentrant modifier on swapExactTokensForTokens — reentrancy is possible

function _swap(
    uint256[] memory amounts,
    address[] memory path,
    address _to
) internal {
    require(!isPause, "DEMAX PAUSED");
    require(swapPrecondition(path[path.length - 1]), 'DEMAX PLATFORM : CHECK DGAS/TOKEN TO VALUE FAIL');
    for (uint256 i; i < path.length - 1; i++) {
        (address input, address output) = (path[i], path[i + 1]);
        require(swapPrecondition(input), 'DEMAX PLATFORM : CHECK DGAS/TOKEN VALUE FROM FAIL');
        require(IDemaxConfig(CONFIG).checkPair(input, output), 'DEMAX PLATFORM : SWAP PAIR CONFIG CHECK FAIL');
        (address token0, address token1) = DemaxSwapLibrary.sortTokens(input, output);
        uint256 amountOut = amounts[i + 1];
        (uint256 amount0Out, uint256 amount1Out) = input == token0 ? (uint256(0), amountOut) : (amountOut, uint256(0));
        address to = i < path.length - 2 ? DemaxSwapLibrary.pairFor(FACTORY, output, path[i + 2]) : _to;
        IDemaxPair(DemaxSwapLibrary.pairFor(FACTORY, input, output)).swap(amount0Out, amount1Out, to, new bytes(0));
        // ❌ _transferNotify is called after swap — reserves in the pair are updated only here,
        //    but re-entrant call already used pre-swap amounts[] from the outer call's _getAmountsOut
        if (amount0Out > 0) _transferNotify(DemaxSwapLibrary.pairFor(FACTORY, input, output), to, token0, amount0Out);
        if (amount1Out > 0) _transferNotify(DemaxSwapLibrary.pairFor(FACTORY, input, output), to, token1, amount1Out);
    }
    emit SwapToken(_to, path[0], path[path.length - 1], amounts[0], amounts[path.length - 1]);
}

function _getAmountsOut(
    uint256 amount,
    address[] memory path,
    uint256 percent
) internal view returns (uint256[] memory amountOuts) {
    amountOuts = new uint256[](path.length);
    amountOuts[0] = amount;
    for (uint256 i = 0; i < path.length - 1; i++) {
        address inPath = path[i];
        address outPath = path[i + 1];
        (uint256 reserveA, uint256 reserveB) = DemaxSwapLibrary.getReserves(FACTORY, inPath, outPath); // ❌ snapshot reserves
        uint256 outAmount = SafeMath.mul(amountOuts[i], SafeMath.sub(PERCENT_DENOMINATOR, percent));
        amountOuts[i + 1] = DemaxSwapLibrary.getAmountOut(outAmount / PERCENT_DENOMINATOR, reserveA, reserveB);
    }
}
```

**Why it is exploitable (identify the bug from the code):**

- `swapExactTokensForTokens()` has **no `nonReentrant` modifier**. Any external call within the function body can re-enter it.
- `_getAmountsOut()` snapshots reserves at the time of the outer call. The resulting `amounts[]` array is then passed into `_swap()`.
- `_innerTransferFrom()` makes an **external ERC-20 `transferFrom()` call** to `path[0]` before `_swap()` executes. If `path[0]` is the attacker's FAKE token, the `transferFrom()` hook triggers a re-entrant call to `swapExactTokensForTokens()` on a different (BURGER/WBNB) pair.
- The re-entrant call completes first, draining BURGER from the pair and updating reserves. When control returns to the outer call, `_swap(amounts, ...)` executes using the **stale pre-reentry `amounts[]`**, resulting in a second excessive BURGER payout.
- The DemaxDelegate factory allows permissionless pair creation (`_createPair()`), so the attacker can freely create a FAKE/BURGER pair to serve as the reentrancy vector.

```solidity
// ✅ Fix: add nonReentrant to swapExactTokensForTokens and recalculate amounts inside _swap
//         using live balanceOf() rather than cached reserve snapshots

uint256 private _locked = 1;
modifier nonReentrant() {
    require(_locked == 1, "DEMAX: REENTRANT");
    _locked = 2;
    _;
    _locked = 1;
}

function swapExactTokensForTokens(
    uint256 amountIn,
    uint256 amountOutMin,
    address[] calldata path,
    address to,
    uint256 deadline
) external nonReentrant ensure(deadline) returns (uint256[] memory amounts) {
    // amounts computed and used consistently; external transferFrom cannot re-enter
    uint256 percent = _getSwapFeePercent();
    amounts = _getAmountsOut(amountIn, path, percent);
    require(amounts[amounts.length - 1] >= amountOutMin, 'DEMAX PLATFORM : INSUFFICIENT_OUTPUT_AMOUNT');
    address pair = DemaxSwapLibrary.pairFor(FACTORY, path[0], path[1]);
    _innerTransferFrom(path[0], msg.sender, pair,
        SafeMath.mul(amountIn, SafeMath.sub(PERCENT_DENOMINATOR, percent)) / PERCENT_DENOMINATOR);
    _swap(amounts, path, to);
    _innerTransferFrom(path[0], msg.sender, pair, SafeMath.mul(amounts[0], percent) / PERCENT_DENOMINATOR);
    _swapFee(amounts, path, percent);
}
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