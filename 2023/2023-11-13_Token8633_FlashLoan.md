# Token8633/9419 — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-13 |
| **Protocol** | Token 8633/9419 |
| **Chain** | BSC |
| **Loss** | ~$52K |
| **Attacker** | [0xe9fac789c947f364...](https://bscscan.com/address/0xe9fac789c947f364f53c3bc28bb6e9e099526468) |
| **Attack Tx** | [0xf6ec3c22b718c3da...](https://explorer.phalcon.xyz/tx/bsc/0xf6ec3c22b718c3da17746416992bac7b65a4ef42ccf5b43cf0716c82bffc2844) |
| **Vulnerable Contract** | [0x11cd2168fc420ae1...](https://bscscan.com/address/0x11cd2168fc420ae1375626655ab8f355f0075bd6) |
| **Root Cause** | Both token contracts use unvalidated AMM spot reserves for reward/price calculation, allowing manipulation within a single transaction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/Token8633_9419_exp.sol) |

---
## 1. Vulnerability Overview
The attacker simultaneously exploited two vulnerable contracts, Token 8633 and Token 9419, draining $52K. Both tokens shared the same vulnerable pattern.

---
## 2. Vulnerable Code Analysis (❌/✅ annotations)
```solidity
// ❌ Both tokens share the same vulnerable pattern
// Price calculation based on pool balance
function getPrice() public view returns (uint256) {
    return token.balanceOf(pool) * 1e18 / BUSD.balanceOf(pool); // ❌
}
// ✅ Use TWAP instead
```

---
### On-chain Original Code

> ⚠️ Contract not verified on Sourcify — source unavailable. The vulnerable behavior below is reconstructed from the attack PoC and on-chain traces, not from verified source.

Token8633 (0x11Cd2168fc420ae1375626655ab8f355F0075Bd6, BSC) and its helper contract (0x128112aF3aF5478008c84d77c63561885FBBC438) are not verified on BSCScan or Sourcify. The exploit calls `autoSwapAndAddToMarketing()` (900 times) and `autoAddLp()` (130 times), indicating these functions read spot reserves from an AMM pair without validation.

The following is reconstructed from the PoC and on-chain traces:

```solidity
// ❌ RECONSTRUCTED — not verified source.
// Token8633 / helper contract pattern — spot reserve price used directly

function autoSwapAndAddToMarketing() external {
    // ❌ Reads current AMM spot reserves without TWAP or manipulation check
    (uint112 reserve0, uint112 reserve1,) = IPancakePair(pair).getReserves();
    uint256 price = uint256(reserve1) * 1e18 / uint256(reserve0); // ❌ spot price, manipulable

    uint256 tokenBalance = IERC20(token).balanceOf(address(this));
    if (tokenBalance > threshold) {
        // Calculates swap/reward amount based on manipulated spot price
        uint256 swapAmount = tokenBalance * price / 1e18;
        _swapTokensForMarketing(swapAmount); // sends to marketing wallet
    }
}

function autoAddLp() external {
    // ❌ Uses spot reserves to determine LP add ratio — inflated by flash loan
    (uint112 reserve0, uint112 reserve1,) = IPancakePair(pair).getReserves();
    uint256 half = IERC20(token).balanceOf(address(this)) / 2;
    uint256 otherHalf = half * uint256(reserve1) / uint256(reserve0); // ❌ spot price ratio
    _addLiquidity(half, otherHalf); // adds LP at manipulated ratio → mints inflated LP tokens
}
```

**Why it is exploitable (identify the bug from the code):**

- Both functions use `IPancakePair(pair).getReserves()` at the moment of call to determine price or ratio — this is the classic spot price oracle vulnerability.
- The attacker flash-borrows 1.1e24 USDT, dumps it into the pair, making `reserve1` (USDT) spike dramatically, which inflates the computed `price`.
- With the inflated price, calling `autoSwapAndAddToMarketing()` 900 times drains accumulated token value at a false rate; calling `autoAddLp()` 130 times mints LP tokens at the manipulated ratio.
- Because both functions are callable by anyone with no cooldown or access control, the attacker can invoke them repeatedly within a single flash-loan transaction.

```solidity
// ✅ Fix: replace spot price oracle with Uniswap V2 TWAP
// Use price0CumulativeLast / price1CumulativeLast over a sufficient window (e.g. 30 min)
// Also add: onlyOwner or caller whitelist, and a per-block call frequency limit
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Borrow BUSD via flash loan
  ├─② Manipulate Token 8633 pool price → profit
  ├─③ Manipulate Token 9419 pool price → profit
  └─④ Repay flash loan + ~$52K
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
// Simultaneously attack both vulnerable tokens
flashLoan(busdAmount);
attackToken8633();
attackToken9419();
repayFlashLoan();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Price Manipulation (multiple tokens) |
| Severity | High |

---
## 6. Remediation Recommendations
1. Adopt a TWAP oracle
2. Apply batch patches across all tokens sharing the same codebase

---
## 7. Lessons Learned
Multiple tokens sharing the same vulnerable codebase can be exploited simultaneously in a single attack.