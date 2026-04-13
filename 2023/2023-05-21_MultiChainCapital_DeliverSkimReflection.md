# MultiChain Capital (MCC) Exploit — deliver() Reflection Manipulation + skim() Drain

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05-21 |
| Project | MultiChain Capital (MCC) |
| Chain | Ethereum |
| Loss | ~10 ETH |
| Attacker | Address unconfirmed |
| Attack TX | Address unconfirmed |
| Vulnerable Contract | MCC Token: 0x1a7981D87E3b6a95c1516EB820E223fE979896b3 |
| Block | 17,221,445 |
| CWE | CWE-682 (Incorrect Calculation — reflection ratio manipulation) |
| Vulnerability Type | Reflection Token deliver() + Excluded Address skim() Drain |

## Summary
MCC is a reflection ERC20 on Ethereum. The attacker flash-borrowed 600 WETH from Aave V3, swapped to MCC, then repeatedly called `deliver()` to reduce `_rTotal`. Once the reflection rate was manipulated, the excluded-from-fee address (`0xfA21382cDF68ccA1B3A7107a8Cc80688eefBEEBc`) was used to bypass transfer tax. The pair's `skim()` transferred the excess MCC balance (which now exceeded stored reserves due to deflated `rTotal`) to the attacker, who swapped back to WETH for profit.

## Vulnerability Details
- **CWE-682**: `deliver(uint256 tAmount)` reduces `_rTotal` without calling `pair.sync()`. After sufficient `deliver()` calls, `tokenFromReflection(rOwned[pair])` exceeds the pair's recorded `reserve0`, creating skimmable excess. The excluded-from-fee address allowed round-tripping MCC without paying the reflection tax, maximizing the exploitable imbalance.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: multichain.sol
        function removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(  // ❌

// ...

        function swapExactTokensForTokensSupportingFeeOnTransferTokens(  // ❌

// ...

        function swapExactETHForTokensSupportingFeeOnTransferTokens(  // ❌

// ...

        function swapExactTokensForETHSupportingFeeOnTransferTokens(  // ❌

// ...

            require(!_isExcluded[sender], "Excluded addresses cannot call this function");  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. Aave.flashLoan([WETH], [600 ether], 0, "")
// 2. executeOperation():
//    a. func1f46(): WETH → MCC via Router
//    b. func21b0(): MCC.deliver(large_amount) × multiple iterations
//       → reduce _rTotal, inflate balanceOf(pair)
//    c. func1d89(): transfer via excluded address (bypass fee)
//    d. func19c():  pair.skim(address(this))  → collect excess MCC
//    e. Repeat deliver/skim cycles
//    f. MCC → WETH via Router
// 3. Repay 600 WETH + Aave fee
```

## Interfaces from PoC
```solidity
interface IMCC is IERC20 {
    function deliver(uint256 amount) external;
    function isExcluded(address account) external view returns (bool);
    function isExcludedFromFee(address account) external view returns (bool);
    function reflectionFromToken(uint256 tAmount, bool deductTransferFee) external view returns (uint256);
    function tokenFromReflection(uint256 rAmount) external view returns (uint256);
}

interface IAaveFlashloan {
    function flashLoan(
        address receiverAddress, address[] calldata assets,
        uint256[] calldata amounts, uint256[] calldata modes,
        address onBehalfOf, bytes calldata params, uint16 referralCode
    ) external;
}

interface IUniswapV2Pair {
    function skim(address to) external;
    function sync() external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| MCC Token | 0x1a7981D87E3b6a95c1516EB820E223fE979896b3 |
| MCC-WETH Pair | 0xDCA79f1f78b866988081DE8a06F92b5e5D316857 |
| WETH | 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 |
| Excluded From Fee | 0xfA21382cDF68ccA1B3A7107a8Cc80688eefBEEBc |
| Aave Pool V3 | 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 |
| Uniswap V2 Router | 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D |

## Root Cause
`deliver()` reduced `_rTotal` without syncing LP pair reserves. The excluded-from-fee address allowed fee-free round-trips, amplifying the reflection ratio drift until `skim()` extracted the surplus.

## Fix
```solidity
// Restrict deliver() and force sync on every call:
function deliver(uint256 tAmount) public onlyOwner {
    // ... existing reflection math ...
    _rTotal -= rAmount;
    _tFeeTotal += tAmount;
    // Mandatory: sync all registered pairs to prevent reserve drift
    for (uint i = 0; i < registeredPairs.length; i++) {
        IUniswapV2Pair(registeredPairs[i]).sync();
    }
}
```

## References
- Ethereum block 17,221,445
- Aave V3: 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2