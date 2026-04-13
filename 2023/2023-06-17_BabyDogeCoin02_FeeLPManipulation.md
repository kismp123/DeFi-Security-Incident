# BabyDogeCoin #2 — Fee LP Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2023-06-17 |
| **Protocol** | Baby Doge Coin (2nd Incident) |
| **Chain** | BSC |
| **Loss** | ~100K USD |
| **Attacker** | [0xee6764ac...](https://bscscan.com/address/0xee6764ac7aa45ed52482e4320906fd75615ba1d1) |
| **Attack Contract** | [0x9a6b9262...](https://bscscan.com/address/0x9a6b926281b0c7bc4f775e81f42b13eda9c1c98e) |
| **Attack Tx** | [0xbaf3e484...](https://bscscan.com/tx/0xbaf3e4841614eca5480c63662b41cd058ee5c85dc69198b29e7ab63b84bc866c) |
| **Vulnerable Contract** | [0xc748673057...](https://bscscan.com/address/0xc748673057861a797275CD8A068AbB95A902e8de) |
| **Root Cause** | Fee mechanism not synchronized with LP reserves, allowing imbalance extraction via FeeFreeRouter |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/BabyDogeCoin02_exp.sol) |

---
## 1. Vulnerability Overview

BabyDogeCoin's transfer fee mechanism retains a portion of each token transfer as a fee within the LP pair. This causes the LP's actual token balance to exceed its recorded reserves. The attacker exploited this imbalance by executing `addLiquidity`/`removeLiquidity` through the `FeeFreeRouter` without incurring fees, extracting profit from the discrepancy. The same vulnerability from the May attack remained unpatched.

## 2. Vulnerable Code Analysis

```solidity
// ❌ No LP sync() call after fee collection
function _transfer(address from, address to, uint256 amount) internal {
    uint256 fee = amount * transferFee / 100;
    // ❌ fee remains in LP pair but reserves are not updated
    _balances[to] += (amount - fee);
    _balances[address(lpPair)] += fee;  // ❌ reserve imbalance
    // IUniswapV2Pair(lpPair).sync() missing
}

// FeeFreeRouter: allows addLiquidity without fees
interface IFeeFreeRouter {
    function addLiquidity(address tokenA, address tokenB, ...) external;
    // ❌ Fee-free LP token minting → exploits excess balance
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: fee mechanism not synchronized with LP reserves, allowing imbalance extraction via FeeFreeRouter
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌──────────────────────────────────────┐
│  1. Borrow WBNB via flash loan       │
└──────────────────┬───────────────────┘
                   ▼
┌──────────────────────────────────────┐
│  2. Buy large amount of BabyDoge     │
│     → Fee accumulation deepens LP    │
│       imbalance                      │
└──────────────────┬───────────────────┘
                   ▼
┌──────────────────────────────────────┐
│  3. FeeFreeRouter.addLiquidity()     │
│     Obtain LP tokens without fees    │
└──────────────────┬───────────────────┘
                   ▼
┌──────────────────────────────────────┐
│  4. removeLiquidity to reclaim       │
│     excess tokens                    │
│  5. Sell BabyDoge back to WBNB      │
│  6. Repay flash loan + ~100K USD    │
│     profit                           │
└──────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // 1. Borrow WBNB via flash loan
    // 2. Buy large amount of BabyDoge (fee accumulation)

    // 3. Obtain LP tokens fee-free via FeeFreeRouter
    babyDoge.approve(address(feeFreeRouter), type(uint256).max);
    feeFreeRouter.addLiquidity(
        address(babyDoge), address(wbnb),
        babyDogeBalance, wbnbBalance,
        0, 0, address(this), block.timestamp
    );

    // 4. Remove LP tokens → receive excess balance
    lpPair.approve(address(feeFreeRouter), type(uint256).max);
    feeFreeRouter.removeLiquidity(...);

    // 5. Sell back + repay
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Missing LP sync() after fee transfer | HIGH | CWE-664 | 16_accounting_sync.md |
| V-02 | Insecure FeeFreeRouter integration | HIGH | CWE-284 | 07_token_integration.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ Call sync() after transfer
function _transfer(...) internal {
    // ... fee processing
    IUniswapV2Pair(lpPair).sync();  // ✅ synchronize reserves
}
```

## 7. Lessons Learned

A second attack exploiting the same vulnerability occurred following the May BabyDogeCoin incident. Protocols that leave vulnerabilities unpatched become repeat targets. Interactions with specialized routers such as FeeFreeRouter must always be included in security reviews.