# Zunami Protocol Price Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Zunami Protocol (UZD) |
| Date | 2023-08-22 |
| Chain | Ethereum Mainnet |
| Loss | ~$2,000,000 USD |
| Attack Type | Flash Loan + Donation Attack + Oracle Manipulation |
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Attacker Address | `0x5f4c21c9bb73c8b4a296cc256c0cde324db146df` |
| Attack Contract | `0xa21a2b59d80dc42d332f778cbb9ea127100e5d75` |
| Vulnerable Contract | `0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c` (UZD) |
| Attack TX | `0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb` |
| Fork Block | 17,908,949 |

## 2. Vulnerable Code Analysis

Zunami's UZD contract cached its internal price via the `cacheAssetPrice()` function. By directly transferring (donating) SDT tokens to the ETH-SDT pool — a donation attack — the attacker manipulated the SDT price upward; a subsequent call to `cacheAssetPrice()` then stored the inflated price in the cache.

```solidity
// Vulnerable pattern: manipulable price cache
contract UZD {
    uint256 public cachedAssetPrice;

    function cacheAssetPrice() external {
        // Vulnerable: directly caches a manipulated pool price
        cachedAssetPrice = getAssetPrice();
    }

    function getAssetPrice() public view returns (uint256) {
        // Vulnerable: uses a single Curve pool spot price
        uint256 sdtPrice = ETH_SDT_POOL.get_dy(/* ETH→SDT price */);
        return calculateUZDPrice(sdtPrice);
    }

    function mint(uint256 uzdAmount) external {
        // Value calculation based on inflated cachedAssetPrice
        uint256 value = uzdAmount * cachedAssetPrice / 1e18;
        // ...
    }
}
```

**Vulnerability**: Donating a large amount of SDT to the ETH-SDT Curve pool drives the SDT price up; calling `cacheAssetPrice()` persists that inflated price in the cache. This enabled arbitrage against UZD at an artificially elevated valuation.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Donation Attack + Oracle Manipulation
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0x5f4c21c9bb73c8b4a296cc256c0cde324db146df]
  │
  ├─1─▶ Uniswap V3.flash() [USDT/USDC Pair]
  │      Borrow 7,000,000 USDT
  │
  ├─2─▶ Balancer.flashLoan() [0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      Borrow 7,000,000 USDC + 10,011 WETH
  │
  ├─3─▶ Curve Pool Manipulation:
  │      - FRAX_USDC_POOL: USDC → crvFRAX
  │      - UZD_crvFRAX_POOL: crvFRAX → acquire UZD
  │      - crvUSD_USDC_POOL: USDC → crvUSD
  │      - crvUSD_UZD_POOL: crvUSD → acquire UZD
  │
  ├─4─▶ SDT Donation Attack:
  │      Directly transfer SDT to the ETH-SDT Curve pool
  │      [ETH_SDT_POOL address]
  │      Artificially inflate SDT price
  │
  ├─5─▶ Call UZD.cacheAssetPrice()
  │      Cache manipulated SDT price (high UZD valuation)
  │
  ├─6─▶ Swap UZD → USDT/USDC (at inflated price)
  │
  └─7─▶ Repay all flash loans + realize ~$2M USD profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IUZD is IERC20 {
    function cacheAssetPrice() external;
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}

interface ICurve {
    function add_liquidity(uint256[2] calldata amounts, uint256 min_mint_amount) external returns (uint256);
    function remove_liquidity_one_coin(uint256 token_amount, int128 i, uint256 min_amount) external returns (uint256);
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
}

contract ZunamiExploit {
    IUZD UZD = IUZD(0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    ICurve ETH_SDT_POOL = ICurve(/* ETH-SDT pool address */);
    IERC20 SDT = IERC20(/* SDT token address */);

    function testExploit() external {
        // Obtain flash loans (USDT + USDC + WETH)
        // Acquire UZD from Curve pools
        // Manipulate price via SDT donation attack
        SDT.transfer(address(ETH_SDT_POOL), SDT.balanceOf(address(this)));
        // Call cacheAssetPrice()
        UZD.cacheAssetPrice();
        // Swap at inflated UZD price
        // Repay flash loans
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| Vulnerability Type | Donation Attack, Oracle Price Cache Manipulation |
| Impact Scope | Entire UZD token value |
| Explorer | [Etherscan](https://etherscan.io/address/0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c) |

## 6. Security Recommendations

```solidity
// Fix 1: Add time delay + access control to cacheAssetPrice
contract UZD {
    uint256 public lastCacheUpdate;
    uint256 public constant CACHE_UPDATE_INTERVAL = 1 hours;
    address public priceManager;

    function cacheAssetPrice() external {
        require(msg.sender == priceManager, "Only price manager");
        require(block.timestamp >= lastCacheUpdate + CACHE_UPDATE_INTERVAL, "Too frequent");
        lastCacheUpdate = block.timestamp;

        uint256 newPrice = getAssetPrice();
        // Reject sharp price movements
        require(newPrice <= cachedAssetPrice * 105 / 100, "Price spike detected");
        require(newPrice >= cachedAssetPrice * 95 / 100, "Price drop detected");
        cachedAssetPrice = newPrice;
    }
}

// Fix 2: Defend against donation attacks — use EMA instead of spot price
function getSDTPrice() internal view returns (uint256) {
    // Use Curve V2 EMA oracle (resistant to donation attacks)
    return CurvePool.price_oracle();  // EMA price
}

// Fix 3: Multi-oracle averaging
function getAssetPrice() public view returns (uint256) {
    uint256 curvePrice = getCurvePrice();
    uint256 chainlinkPrice = getChainlinkPrice();
    // Revert if the two prices deviate significantly
    require(abs(curvePrice - chainlinkPrice) <= chainlinkPrice * 5 / 100);
    return (curvePrice + chainlinkPrice) / 2;
}
```

## 7. Lessons Learned

1. **Price Cache Vulnerability**: When a cache-update function such as `cacheAssetPrice()` is publicly callable, an attacker can inject a manipulated price into the cache.
2. **Donation Attack**: Directly transferring tokens into a pool to manipulate its price neutralizes oracles that rely on Curve spot prices. EMA-based prices must be used instead.
3. **Composable Protocol Dependencies**: Zunami's composite architecture — bridging Curve, SDT, and UZD — means a vulnerability in any one layer can propagate and affect the entire system.
4. **Curve V2 EMA Oracle**: The `price_oracle()` of Curve V2 pools is based on an Exponential Moving Average (EMA), making it significantly more robust against single-block donation attacks.