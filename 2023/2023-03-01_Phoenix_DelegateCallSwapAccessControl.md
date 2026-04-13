# Phoenix Finance Exploit — delegateCallSwap() Missing Access Control

## Metadata
| Field | Value |
|---|---|
| Date | 2023-03-01 |
| Project | Phoenix Finance (PhxProxy) |
| Chain | Polygon |
| Loss | ~Address unconfirmed USDC |
| Attacker | Address unconfirmed |
| Attack TX | https://polygonscan.com/tx/0x6fa6374d43df083679cdab97149af8207cda2471620a06d3f28b115136b8e2c4 |
| Vulnerable Contract | PhxProxy: 0x65BaF1DC6fA0C7E459A36E2E310836B396D1B1de |
| Block | 40,066,946 (Polygon) |
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | delegateCallSwap() — Unchecked External Call to Arbitrary Router |

## Summary
The PhxProxy contract's `delegateCallSwap()` function had no access control and accepted arbitrary `data` bytes that were executed via delegatecall or external call to any target. The attacker used `buyLeverage()` to deposit USDC into PhxProxy (converting to WETH internally), then called `delegateCallSwap()` with crafted data to swap all WETH held by PhxProxy to the attacker's own malicious token, then swapped that token back to USDC via Quickswap for profit.

## Vulnerability Details
- **CWE-284**: `delegateCallSwap(bytes memory data)` executed the provided `data` against a user-specified router without any caller restriction or data validation. Any address could call this function, and any router with any calldata could be specified.

### On-Chain Original Code

Source: Bytecode Decompile

```solidity
// Root Cause: `delegateCallSwap()` lacked an `onlyOwner` or `onlyAuthorized` modifier and accepted fully arbitrary calldata with no router allowlist.
// Source code unverified — based on bytecode analysis
```

## Attack Flow (from testExploit())
```solidity
// 1. DODO flash loan: 8000 USDC
// 2. Create malicious SHITCOIN token and add SHITCOIN/WETH liquidity
// 3. phxProxy.buyLeverage(8000e6, 0, deadline, bytes(""))
//    → PhxProxy holds WETH internally
// 4. Build delegateCallSwap payload:
bytes memory swapData = abi.encodeWithSelector(
    0xa9678a18,
    address(Router),    // QuickSwap router
    address(WETH),      // tokenIn
    address(MYTOKEN),   // tokenOut (attacker's token)
    swapAmount);
// 5. phxProxy.delegateCallSwap(swapData)
//    → PhxProxy swaps its WETH → SHITCOIN (attacker's token)
// 6. Router.swapExactTokensForTokens(SHITCOIN → WETH → USDC)
// 7. Repay DODO flash loan
```

## Interfaces from PoC
```solidity
interface IPHXPROXY {
    function buyLeverage(uint256 amount, uint256 minAmount,
                         uint256 deadLine, bytes calldata) external;
    function delegateCallSwap(bytes memory data) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| PhxProxy | 0x65BaF1DC6fA0C7E459A36E2E310836B396D1B1de |
| USDC (Polygon) | 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 |
| WETH (Polygon) | 0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619 |
| QuickSwap Router | 0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff |
| DODO (Polygon) | 0x1093ceD81987Bf532c2b7907B2A8525cd0C17295 |

## Root Cause
`delegateCallSwap()` lacked an `onlyOwner` or `onlyAuthorized` modifier and accepted fully arbitrary calldata with no router allowlist.

## Fix
```solidity
mapping(address => bool) public approvedRouters;

function delegateCallSwap(bytes memory data) external onlyAuthorized {
    (address router, , , ) = abi.decode(data, (address, address, address, uint256));
    require(approvedRouters[router], "Router not approved");
    // ... execute
}
```

## References
- HypernativeLabs: https://twitter.com/HypernativeLabs/status/1633090456157401088
- Polygonscan TX: 0x6fa6374d43df083679cdab97149af8207cda2471620a06d3f28b115136b8e2c4