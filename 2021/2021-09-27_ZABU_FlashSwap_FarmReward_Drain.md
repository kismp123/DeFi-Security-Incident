# ZABU Finance — Nested Flash Swap LP Value Manipulation Farm Reward Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2021-09-27 |
| **Protocol** | ZABU Finance |
| **Chain** | Avalanche |
| **Loss** | ~$3,200,000 |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 4,177,751) |
| **Vulnerable Contract** | ZABU Farm (SPORE token pool 38) |
| **Root Cause** | Farm's accZABUPerShare calculation references current LP balanceOf() (spot), causing reward-per-unit distortion when reserves are manipulated |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-09/ZABU_exp.sol) |

---
## 1. Vulnerability Overview

ZABU Finance's farm accepts SPORE tokens as LP stakes and distributes ZABU rewards. The attacker used nested flash swaps against Pangolin liquidity pools to withdraw large amounts of SPORE, causing a sharp drop in pool reserves. Because the farm's reward calculation depends on the current LP value, the attacker deposited while LP value was depressed, collected a large amount of ZABU rewards, then restored the pool state — draining approximately $3.2M in total.

---
## 2. Vulnerable Code Analysis

### 2.1 deposit() / pendingZABU() — Reward Calculation Based on Current LP Value

```solidity
// ❌ ZABU Farm — Reward calculation based on current LP reserves
// If Pangolin SPORE/WAVAX pair reserves are manipulated, rewards are also manipulated
function pendingZABU(uint256 _pid, address _user) external view returns (uint256) {
    PoolInfo storage pool = poolInfo[_pid];
    UserInfo storage user = userInfo[_pid][_user];

    uint256 accZABUPerShare = pool.accZABUPerShare;
    uint256 lpSupply = pool.lpToken.balanceOf(address(this));

    if (block.number > pool.lastRewardBlock && lpSupply != 0) {
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 zabuReward = multiplier.mul(zabuPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
        accZABUPerShare = accZABUPerShare.add(zabuReward.mul(1e12).div(lpSupply));
    }
    // If lpSupply is distorted by reserve manipulation, accZABUPerShare spikes
    return user.amount.mul(accZABUPerShare).div(1e12).sub(user.rewardDebt);
}
```

**Fixed Code**:
```solidity
// ✅ Use TWAP or time-weighted reserves for LP price calculation
// ✅ Prohibit same-block deposit-withdraw

mapping(uint256 => mapping(address => uint256)) public lastDepositBlock;

function deposit(uint256 _pid, uint256 _amount) external nonReentrant {
    lastDepositBlock[_pid][msg.sender] = block.number;
    // ...
}

function withdraw(uint256 _pid, uint256 _amount) external nonReentrant {
    require(
        block.number > lastDepositBlock[_pid][msg.sender],
        "ZABU: same block deposit-withdraw"
    );
    // ...
}
```


### On-Chain Original Code

Source: Source unconfirmed

> ⚠️ No on-chain source code — bytecode only or source unverified

**Vulnerable Function** — `vulnerableFunction()`:
```solidity
// ❌ Root cause: Farm's accZABUPerShare calculation references current LP balanceOf() (spot), causing reward-per-unit distortion when reserves are manipulated
// Source code unconfirmed — bytecode analysis required
// Vulnerability: Farm's accZABUPerShare calculation references current LP balanceOf() (spot), causing reward-per-unit distortion when reserves are manipulated
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Pre-deposit SPORE (depositSPORE)                    │
│ Swap WAVAX → SPORE, then deposit into ZABU Farm pool 38     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Step 2: Initiate flash swap on Pangolin Pair1 (SPORE/WAVAX) │
│ pair1.swap(sporeAmount, 0, this, data)                      │
└─────────────────────┬───────────────────────────────────────┘
                      │ pangolinCall() callback
┌─────────────────────▼───────────────────────────────────────┐
│ Step 3: Nested flash swap on Pair2                          │
│ pair2.swap(sporeAmount2, 0, this, data2)                    │
│ → SPORE reserves drop sharply                               │
└─────────────────────┬───────────────────────────────────────┘
                      │ inner callback
┌─────────────────────▼───────────────────────────────────────┐
│ Step 4: Drain SPORE reserves via repeated deposit/withdraw  │
│ Collect large amounts of ZABU rewards from Farm pool 38     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│ Step 5: Repay flash swaps + sell ZABU for profit            │
│ Based on Avalanche block 4,177,751                          │
└─────────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// pangolinCall() — Pangolin flash swap callback
function pangolinCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
    if (/* first callback */) {
        // Acquire additional SPORE via nested flash swap on Pair2
        pair2.swap(sporeAmount2, 0, address(this), abi.encode("inner"));
    } else {
        // Inner callback: manipulate Farm with SPORE
        // withdrawSPORE() — withdraw existing deposit + collect ZABU rewards
        // Drain reserves via repeated deposit/withdraw

        // Repay flash swap pair2
        SPORE.transfer(pair2, repayAmount2);
    }
    // Repay flash swap pair1
    SPORE.transfer(pair1, repayAmount1);
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Farm reward calculation depends on current LP balance (spot) — bulk withdrawal from Pangolin reserves causes reward-per-unit to spike | CRITICAL | CWE-829 |
| V-02 | Same-block deposit-withdraw permitted (contributing factor: flash swap provides funding) | MEDIUM | CWE-841 |

> **Root Cause**: The farm's `accZABUPerShare` calculation references the current LP `balanceOf()`, causing reward-per-unit distortion when reserves are manipulated. The flash swap is merely the funding mechanism; TWAP-based LP value calculation or a block delay is the essential fix.

---
## 6. Remediation Recommendations

```solidity
// ✅ Apply block delay + deposit lock period
// ✅ Use time-weighted reserves for LP value calculation (Uniswap V2 TWAP)

function getPoolValue(address lpToken) internal view returns (uint256) {
    // Use cumulative TWAP instead of spot price
    (uint price0Cumulative, uint price1Cumulative,) =
        UniswapV2OracleLibrary.currentCumulativePrices(lpToken);
    // Observation window of at least 30 minutes required
    return calculateTWAPValue(price0Cumulative, price1Cumulative);
}
```

---
## 7. Lessons Learned

- **Calculating farm rewards using the current LP balance (spot) is the root cause.** This can be resolved with TWAP-based LP value calculation or a block delay, regardless of whether flash swaps are involved.
- **Flash swaps are merely a funding mechanism.** Once TWAP is applied, concentrating any amount of capital into a single transaction cannot make reserve manipulation affect reward calculations.
- **The same code pattern carries the same vulnerability across chains.** The identical pattern that appeared on BSC was repeated on Avalanche.