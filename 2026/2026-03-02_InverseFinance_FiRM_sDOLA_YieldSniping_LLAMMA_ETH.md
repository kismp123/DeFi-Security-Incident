# Inverse Finance FiRM — sDOLA Yield Sniping + LLAMMA Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2026-03-02 |
| **Protocol** | Inverse Finance FiRM (sDOLA/crvUSD Market) |
| **Chain** | Ethereum Mainnet |
| **Block** | 24566937 |
| **Loss** | ~227,326 DOLA + 6.74 WETH (~$242,000) |
| **Attacker** | [0x33a0...be2](https://etherscan.io/address/0x33a0aab2642c78729873786e5903cc30f9a94be2) |
| **Attack Contract** | [0xd8e8...982](https://etherscan.io/address/0xd8e8544e0c808641b9b89dfb285b5655bd5b6982) (deployed in same TX) |
| **Helper Contract** | [0xc6c2...ac0](https://etherscan.io/address/0xc6c2fcdf688baeb7b03d9d9c088c183dbb499ac0) (executes batch liquidations) |
| **Attack Tx** | [0xb935...8a4](https://etherscan.io/tx/0xb93506af8f1a39f6a31e2d34f5f6a262c2799fef6e338640f42ab8737ed3d8a4) |
| **Vulnerable Contracts** | FiRM Controller [0xad44...86](https://etherscan.io/address/0xad444663c6c92b497225c6ce65fee2e7f78bfb86), sDOLA [0xb45a...05](https://etherscan.io/address/0xb45ad160634c528cc3d2926d9807104fa3157305), DBREarn [0xe5f2...b4](https://etherscan.io/address/0xe5f24791e273cb96a1f8e5b67bc2397f0ad9b8b4) |
| **Root Cause** | ERC4626 sDOLA vault yield sniping + cascading liquidations via LLAMMA price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

Inverse Finance's FiRM protocol operates a market that uses sDOLA as collateral to borrow crvUSD, where sDOLA is a yield-bearing vault token conforming to the ERC4626 standard. Yields from the sDOLA vault accumulate in the DBREarn contract and are sent in bulk to the sDOLA vault upon invocation of the `earn()` function. Within this structure, ERC4626's "immediate yield attribution proportional to current share holdings" mechanism harbors a critical vulnerability: it hands over the entirety of accumulated yield to any party that holds a large share of sDOLA at harvest time.

The attacker temporarily secured approximately $50M in capital via flash loans from Bunni and Curve, then accumulated 90.1% of the total sDOLA supply within a single transaction through multiple routes (alUSD/sDOLA Curve pool, scrvUSD/SaveDola, direct LLAMMA swap). The attacker then called DBREarn's yield distribution function and siphoned approximately 90% of the 12,613,130 DOLA in accumulated yield.

Additionally, the attacker injected a large amount of crvUSD into LLAMMA to shift the price band, causing the sDOLA collateral of existing FiRM borrowers to fall below liquidation thresholds. The attacker then used a helper contract to cascade-liquidate dozens of positions for additional profit. The entire sequence executed atomically within a single block (24566937), with total damages estimated at approximately $242,000.

---

## 2. Vulnerable Code Analysis

### 2.1 ERC4626 Yield Sniping (Core Vulnerability)

sDOLA is a yield-bearing vault token conforming to the ERC4626 standard, where increases in `totalAssets()` proportionally attribute yield to existing share holders. The DBREarn contract accumulates DOLA yield and sends it in bulk to the sDOLA vault upon `earn()` invocation.

**Vulnerable Code (Conceptual Reconstruction):**

```solidity
// DBREarn.earn() — distributes accumulated DOLA yield to the sDOLA vault in bulk
// Contract: 0xe5f24791e273cb96a1f8e5b67bc2397f0ad9b8b4
function earn() external {
    uint256 accumulated = dola.balanceOf(address(this));

    // ❌ Vulnerable: yield is immediately attributed based on sDOLA holdings at call time
    // Holding 90% of supply via flash loan captures 90% of accumulated yield
    dola.transfer(address(sDOLA), accumulated);

    // ERC4626 internals: totalAssets += accumulated
    // Each holder's yield = accumulated * (heldShares / totalShares)
    // Attacker holding 90.1% → receives 90.1% of yield
}
```

**Issues:**
- Yield accumulated in DBREarn is immediately distributed proportional to share holdings at call time
- No temporal isolation between yield distribution and share acquisition
- Single-block accumulate/harvest/return via flash loan is possible

**Fixed Code:**

```solidity
// ✅ Fix: yield distribution based on time-weighted average balance (TWAB)
// or require minimum holding period + limit distribution frequency
contract DBREarnFixed {
    uint256 public lastEarnBlock;
    uint256 public constant MIN_EARN_INTERVAL = 7200; // ~1 day (in blocks)

    // Distribute yield based on snapshots so that
    // flash loan attackers cannot snipe yield within a single block
    function earn() external {
        require(
            block.number > lastEarnBlock + MIN_EARN_INTERVAL,
            "DBREarn: distribution interval not met"
        );

        uint256 accumulated = dola.balanceOf(address(this));
        require(accumulated > 0, "DBREarn: no yield to distribute");

        lastEarnBlock = block.number;

        // ✅ Distribute based on TWAB snapshot from the previous epoch
        // Large deposits within a single block are not reflected in the TWAB
        _distributeWithTWAB(accumulated);
    }
}
```

### 2.2 LLAMMA Price Manipulation → Cascading Liquidations

FiRM's LLAMMA (Lending-Liquidating AMM Algorithm) is based on Curve's crvUSD mechanism and manages soft liquidation of collateral through the sDOLA/crvUSD price bands. The attacker injected 13,254,734 crvUSD into LLAMMA in a single swap, causing the sDOLA/crvUSD price band to shift sharply.

This caused the sDOLA collateral of existing FiRM borrowers to fall below liquidation thresholds. The attacker then cascade-liquidated dozens of positions through the helper contract ([0xc6c2...ac0](https://etherscan.io/address/0xc6c2fcdf688baeb7b03d9d9c088c183dbb499ac0)), recovering 7,093,231 crvUSD from an input of 4,745,266 crvUSD (net liquidation profit: +2,347,964 crvUSD). While this profit was ultimately offset against the cost of the attacker's own FiRM position, it played a role in establishing the overall economic viability of the attack when combined with the yield sniping.

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker deployed the attack contract ([0xd8e8...982](https://etherscan.io/address/0xd8e8544e0c808641b9b89dfb285b5655bd5b6982)) at block 24566937 and received two flash loans within the same transaction:

1. **Bunni Flash Loan** ([0xbbbb...bcb](https://etherscan.io/address/0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb)): 15,986 WETH + USDC
2. **Curve crvUSD Flash Loan** ([0xa920...635](https://etherscan.io/address/0xa920de414ea4ab66b97da1bfe9e6eca7d4219635)): 25,000,000 crvUSD

### 3.2 Execution Phase

**[Step 1] Receive Flash Loans and Secure Capital**
- Receive 15,986 WETH + USDC flash loan from Bunni
- Receive 25,000,000 crvUSD flash loan from Curve crvUSD pool

**[Step 2] Accumulate sDOLA at Scale (Secure 90.1% of Supply)**
- (2-a) Convert USDC to 6,187,490 alUSD via alUSD/USDC pool ([0xb30d...37](https://etherscan.io/address/0xb30da237))
- (2-b) Swap 650,000 alUSD for 454,997 sDOLA via alUSD/sDOLA Curve pool ([0x4606...f6](https://etherscan.io/address/0x460638e6f7605b866736e38045c0de8294d7d87f))
- (2-c) Deposit 7,000,000 crvUSD into scrvUSD vault ([0x0655...67](https://etherscan.io/address/0x0655977feb2f289a4ab78af67bab0d17aab84367)), route through SaveDola ([0x76a9...37](https://etherscan.io/address/0x76a962ba6770068bcf454d34dde17175611e6637)) to obtain 327,300 sDOLA
- (2-d) **Core swap**: Inject 13,254,734 crvUSD directly into LLAMMA ([0x0079...f7](https://etherscan.io/address/0x0079885e248b572cdc4559a8b156745e2d8ea1f7)) to obtain 9,825,506 sDOLA
- **Total accumulated**: ~10,607,802 sDOLA (**90.1%** of total supply 11,770,912)

**[Step 3] DBREarn Yield Harvest (Yield Sniping)**
- Call `earn()` on DBREarn ([0xe5f2...b4](https://etherscan.io/address/0xe5f24791e273cb96a1f8e5b67bc2397f0ad9b8b4))
- 12,613,130 DOLA of accumulated yield is sent in bulk to the sDOLA vault
- Attacker's 90.1% sDOLA position captures the majority of the yield
- Burn 10,607,802 sDOLA → receive 12,613,130 DOLA

**[Step 4] Batch Liquidations of FiRM Positions via Helper**
- Transfer 4,745,266 crvUSD to helper ([0xc6c2...ac0](https://etherscan.io/address/0xc6c2fcdf688baeb7b03d9d9c088c183dbb499ac0))
- Helper liquidates dozens of FiRM borrow positions through LLAMMA (repeated Liquidate events)
- Helper returns 7,093,231 crvUSD to attack contract (net liquidation profit: +2,347,964 crvUSD)

**[Step 5] Unwind Own FiRM Position**
- Deposit 8,286,547 sDOLA as collateral into FiRM/LLAMMA, execute liquidation cycle
- FiRM Controller → attack contract: return 10,904,021 crvUSD
- Unwind remaining sDOLA/DOLA positions through stake/unstake cycle

**[Step 6] Repay Flash Loans and Finalize Profit**
- Redeem scrvUSD to recover 7,002,748 crvUSD
- Repay 25,000,000 crvUSD flash loan
- Swap remaining USDC for WETH on Uniswap V2 ([0xb4e1...01](https://etherscan.io/address/0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc))
- Repay 15,986 WETH Bunni flash loan (remaining: +6.74 WETH)

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Attack Transaction (Block 24566937)                  │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐    15,986 WETH + USDC     ┌──────────────────┐
  │  Bunni       │ ──────────────────────────▶│                  │
  │  FlashLoan   │                            │                  │
  └──────────────┘                            │                  │
                                              │  Attack Contract  │
  ┌──────────────┐    25,000,000 crvUSD      │   (0xd8e8)       │
  │ Curve crvUSD │ ──────────────────────────▶│                  │
  │  FlashLoan   │                            │                  │
  └──────────────┘                            └────────┬─────────┘
                                                       │
                    ┌──────────────────────────────────┘
                    │
                    ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  [Step 2] Accumulate sDOLA at Scale (Secure 90.1%)          │
  │                                                             │
  │  ┌────────────┐  alUSD   ┌────────────┐  sDOLA             │
  │  │ USDC→alUSD │ ───────▶ │ alUSD/sDOLA│ ──────▶ 454,997   │
  │  │ Pool       │ 6.18M    │ Curve Pool  │         sDOLA      │
  │  └────────────┘          └────────────┘                     │
  │                                                             │
  │  ┌────────────┐ scrvUSD  ┌────────────┐  sDOLA             │
  │  │ crvUSD →   │ ───────▶ │  SaveDola  │ ──────▶ 327,300   │
  │  │ scrvUSD    │ 7M       │            │         sDOLA      │
  │  └────────────┘          └────────────┘                     │
  │                                                             │
  │  ┌──────────────────────────────────────┐                   │
  │  │ ★ LLAMMA Direct Swap (Core)           │                   │
  │  │ 13,254,734 crvUSD ──▶ 9,825,506 sDOLA│                   │
  │  │ (Price band shift → liquidation trigger)                  │
  │  └──────────────────────────────────────┘                   │
  │                                                             │
  │  Total accumulated: 10,607,802 sDOLA (90.1%)               │
  └─────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  [Step 3] Yield Sniping                                     │
  │                                                             │
  │  ┌──────────┐  earn()   ┌──────────┐  12.6M DOLA           │
  │  │ DBREarn  │ ────────▶ │  sDOLA   │ ──────────▶ Attacker  │
  │  │ (0xe5f2) │  accum.   │  Vault   │  (90.1% share)        │
  │  └──────────┘  yield    └──────────┘                        │
  │                                                             │
  │  Burn 10,607,802 sDOLA → Receive 12,613,130 DOLA            │
  └─────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  [Step 4] Cascading Liquidations (Helper Contract)          │
  │                                                             │
  │  Attack Contract ──4,745,266 crvUSD──▶ ┌────────────┐      │
  │                                        │   Helper    │      │
  │  Attack Contract ◀──7,093,231 crvUSD── │ (0xc6c2)   │      │
  │                                        │ Dozens of   │      │
  │                                        │ liquidations│      │
  │                                        └──────┬─────┘      │
  │                                               │             │
  │                                               ▼             │
  │                                        ┌────────────┐      │
  │                                        │  LLAMMA    │      │
  │                                        │ (0x0079)   │      │
  │                                        │ Liquidate  │      │
  │                                        └────────────┘      │
  └─────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  [Steps 5-6] Cleanup and Flash Loan Repayment               │
  │                                                             │
  │  Unwind own FiRM position → recover 10,904,021 crvUSD       │
  │  Redeem scrvUSD → 7,002,748 crvUSD                          │
  │  Repay 25M crvUSD flash loan                                │
  │  USDC → WETH swap (Uniswap V2)                              │
  │  Repay 15,986 WETH flash loan                               │
  │                                                             │
  │  ★ Net profit: +227,326 DOLA + 6.74 WETH (~$242,000)        │
  └─────────────────────────────────────────────────────────────┘
```

### 3.4 Results

| Item | Amount |
|------|------|
| **crvUSD circulation** | Inflow ~50M = Outflow ~50M (net 0; liquidation profits offset by FiRM position costs) |
| **DOLA net profit** | +227,326 DOLA |
| **WETH net profit** | +6.74 WETH (~$15,000) |
| **Total profit** | **~$242,000** |
| **sDOLA ratio change** | 1.1890 → 1.3531 DOLA/sDOLA (+13.8%) |
| **Victims** | FiRM borrowers (force-liquidated), DBREarn yield beneficiaries (yield stolen) |

---

## 4. PoC Code Structure (Reconstructed)

The following is a conceptual Solidity representation of the attack logic reconstructed from on-chain verification data.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Attack flow reconstruction based on on-chain verification data
// Actual attack TX: 0xb93506af...ed3d8a4

interface IBunniFlash {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface ICurveFlashLoan {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

interface ILLAMMA {
    function exchange(uint256 i, uint256 j, uint256 in_amount, uint256 min_amount) external returns (uint256);
}

interface IsDOLA {
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

interface IDBREarn {
    function earn() external;
}

contract InverseFiRMExploit {
    // ===== Core Contract Addresses =====
    address constant BUNNI         = 0xBbBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb;
    address constant CURVE_FLASH   = 0xa920De414eA4Ab66b97dA1bFE9e6ECA7d4219635;
    address constant LLAMMA        = 0x0079885e248b572cDC4559a8b156745e2d8ea1f7;
    address constant SDOLA         = 0xb45ad160634c528Cc3D2926d9807104FA3157305;
    address constant DBREARN       = 0xe5f24791E273Cb96A1f8E5B67Bc2397F0AD9b8B4;
    address constant FIRM_CTRL     = 0xAd444663C6c92b497225c6CE65FEe2E7f78BfB86;
    address constant HELPER        = 0xC6c2FCDf688BaeB7B03d9D9C088c183DBB499AC0;
    address constant ALUSD_SDOLA   = 0x460638e6F7605b866736e38045C0de8294D7d87f;
    address constant SAVE_DOLA     = 0x76a962Ba6770068BCf454D34dde17175611e6637;
    address constant SCRVUSD       = 0x0655977FEb2f289A4aB78af67BAb0d17aAb84367;

    // ===== Execute Attack =====
    function attack() external {
        // Step 1: Bunni flash loan (15,986 WETH + USDC)
        IBunniFlash(BUNNI).flash(
            address(this),
            15986 ether,  // WETH
            0,
            abi.encode(uint8(1))
        );
    }

    // Bunni flash loan callback
    function bunniFlashCallback(uint256, uint256, bytes calldata) external {
        // Take additional 25,000,000 crvUSD flash loan from Curve crvUSD pool
        ICurveFlashLoan(CURVE_FLASH).flashLoan(
            address(this),
            address(0xf939E0A03FB07F59A73314E73794Be0E57ac1b4E), // crvUSD
            25_000_000e18,
            ""
        );
    }

    // Curve flash loan callback — core attack logic
    function onFlashLoan(address, address, uint256, uint256, bytes calldata)
        external returns (bytes32)
    {
        // ===== Step 2: Accumulate sDOLA at Scale (90.1%) =====

        // 2-a: USDC → alUSD → sDOLA (454,997 sDOLA)
        _swapAlUSDToSDOLA();

        // 2-b: crvUSD → scrvUSD → SaveDola → sDOLA (327,300 sDOLA)
        _swapCrvUSDViaSaveDola();

        // 2-c: ★ Core — LLAMMA large-scale swap (9,825,506 sDOLA)
        // 13,254,734 crvUSD → LLAMMA → 9,825,506 sDOLA
        // This swap shifts the price band, triggering liquidations
        ILLAMMA(LLAMMA).exchange(
            0,             // crvUSD input
            1,             // sDOLA output
            13_254_734e18,
            9_800_000e18
        );
        // Total accumulated: ~10,607,802 sDOLA (90.1% of supply)

        // ===== Step 3: Yield Sniping =====
        // DBREarn.earn() → distribute 12,613,130 DOLA of accumulated yield
        // Attacker holds 90.1% → captures majority of yield
        IDBREarn(DBREARN).earn();

        // Burn all sDOLA → receive DOLA
        uint256 sDolaBalance = IsDOLA(SDOLA).balanceOf(address(this));
        IsDOLA(SDOLA).redeem(sDolaBalance, address(this), address(this));
        // Burn 10,607,802 sDOLA → receive 12,613,130 DOLA

        // ===== Step 4: Cascading Liquidations via Helper =====
        // Input 4,745,266 crvUSD → recover 7,093,231 crvUSD
        _executeLiquidationsViaHelper();

        // ===== Step 5: Unwind Own FiRM Position =====
        // 8,286,547 sDOLA collateral → recover 10,904,021 crvUSD
        _cleanupFiRMPositions();

        // ===== Step 6: Repay Flash Loans =====
        // Redeem scrvUSD → 7,002,748 crvUSD
        // Repay 25,000,000 crvUSD → convert USDC → WETH
        // Repay 15,986 WETH → ★ net profit: +227,326 DOLA + 6.74 WETH

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    // Internal functions (simplified)
    function _swapAlUSDToSDOLA() internal { /* USDC→alUSD→sDOLA */ }
    function _swapCrvUSDViaSaveDola() internal { /* crvUSD→scrvUSD→sDOLA */ }
    function _executeLiquidationsViaHelper() internal { /* helper liquidations */ }
    function _cleanupFiRMPositions() internal { /* FiRM position cleanup */ }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | ERC4626 Yield Sniping | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-02 | LLAMMA Single-Block Price Manipulation | HIGH | CWE-682 (Incorrect Calculation) |
| V-03 | Flash Loan Capital Amplification | MEDIUM | CWE-807 (Reliance on Untrusted Inputs in a Security Decision) |

### V-01: ERC4626 Yield Sniping

- **Description**: When the DBREarn contract distributes accumulated yield in bulk to the sDOLA vault, yield is immediately attributed based on the share holdings at the time of the call. Because there is no temporal isolation between yield distribution and share acquisition, securing a large share position just before distribution via flash loans allows theft of the entire accumulated yield.
- **Impact**: The attacker accumulated 90.1% of sDOLA supply within a single block and called DBREarn.earn() to steal 12,613,130 DOLA in yield.
- **Attack Conditions**: (1) Access to large-scale flash loans, (2) Access to sDOLA liquidity pools, (3) Significant yield accumulated in DBREarn

### V-02: LLAMMA Single-Block Price Manipulation

- **Description**: LLAMMA's price bands can be shifted sharply by a large-scale swap within a single transaction. A single swap of 13,254,734 crvUSD shifted the price band sufficiently to make existing borrowers' positions eligible for liquidation.
- **Impact**: Dozens of FiRM borrow positions were cascade-liquidated, and the attacker secured +2,347,964 crvUSD in liquidation rewards.
- **Attack Conditions**: (1) Large-scale crvUSD flash loan, (2) Swap size sufficient relative to LLAMMA pool liquidity

### V-03: Flash Loan Capital Amplification

- **Description**: Flash loans enabled temporarily securing approximately $50M in capital without collateral, dramatically expanding the exploitability of vulnerabilities V-01 and V-02.
- **Impact**: Enabled completing the attack in a single transaction without permanent capital, effectively eliminating the economic barrier to entry.
- **Attack Conditions**: Access to Bunni and Curve flash loan pools

---

## 6. Remediation Recommendations

### Immediate Actions

**1. Introduce Minimum Distribution Interval for DBREarn Yield Distribution**

```solidity
// ✅ Fix: enforce minimum distribution interval + TWAB-based distribution
contract DBREarnFixed {
    uint256 public lastEarnBlock;
    uint256 public constant MIN_EARN_INTERVAL = 7200; // ~24 hours

    function earn() external {
        require(
            block.number > lastEarnBlock + MIN_EARN_INTERVAL,
            "too frequent"
        );
        lastEarnBlock = block.number;

        uint256 accumulated = dola.balanceOf(address(this));
        // Distribute based on TWAB snapshot: average holdings over the past N blocks
        _distributeWithTWAB(accumulated);
    }
}
```

**2. Require Minimum Holding Period in sDOLA Vault**

```solidity
// ✅ Fix: block redeem/withdraw before minimum N blocks have elapsed after deposit/mint
mapping(address => uint256) public depositBlock;

function redeem(uint256 shares, address receiver, address owner)
    public override returns (uint256)
{
    require(
        block.number >= depositBlock[owner] + MIN_HOLD_BLOCKS,
        "minimum hold period not met"
    );
    return super.redeem(shares, receiver, owner);
}
```

**3. Limit Maximum Single-Block Volume in LLAMMA**

```solidity
// ✅ Fix: cap cumulative swap volume per block
mapping(uint256 => uint256) public blockSwapVolume;
uint256 public constant MAX_BLOCK_VOLUME = 5_000_000e18;

function exchange(uint256 i, uint256 j, uint256 in_amount, uint256 min_amount)
    external returns (uint256)
{
    blockSwapVolume[block.number] += in_amount;
    require(
        blockSwapVolume[block.number] <= MAX_BLOCK_VOLUME,
        "block volume limit exceeded"
    );
    return _exchange(i, j, in_amount, min_amount);
}
```

### Structural Improvements

| Area | Current State | Recommended Direction | Priority |
|------|----------|----------|---------|
| **Yield distribution mechanism** | Immediate distribution at call-time share ratio | TWAB or epoch-based snapshot distribution | CRITICAL |
| **Deposit/withdrawal temporal isolation** | Same-block deposit+withdrawal allowed | Enforce minimum holding period (e.g., 1 epoch) | CRITICAL |
| **LLAMMA price protection** | Unlimited single-block swaps allowed | Per-block maximum volume cap or TWAP oracle reference | HIGH |
| **Liquidation rate limiting** | Unlimited batch liquidations | Introduce liquidation rate limiting and minimum delay | HIGH |
| **Flash loan defense** | Key functions callable within flash loan callbacks | Add `nonFlashLoan` guard to critical functions | MEDIUM |
| **Monitoring** | Post-hoc detection | Real-time alert system for large share movements | MEDIUM |

---

## 7. Lessons Learned

1. **ERC4626 vault yield distribution must be protected with time-weighted averaging.** ERC4626's "immediate attribution based on current ratio" structure is inherently vulnerable to flash loan yield sniping by design. Introducing TWAB or epoch-based snapshots for yield distribution fundamentally prevents short-term holders from stealing long-term accumulated yield.

2. **Temporal isolation between yield accumulation and distribution is essential.** A structure where yield accumulates in DBREarn over a long period and is distributed all at once is a target for "just-in-time attacks." Yield should be distributed continuously (streaming) or allocated based on the average holdings over a defined historical period.

3. **AMM-based collateral systems must guard against single-block price manipulation.** AMM-based liquidation mechanisms like LLAMMA are vulnerable to price band manipulation via large-scale swaps. Per-block maximum volume limits, multi-block TWAP oracle references, or price movement circuit breakers must be introduced.

4. **Flash loans effectively eliminate the capital barrier to attack.** Protocol security models must be designed with flash loans as a given. The assumption that "attacks are difficult because large capital is required" is no longer valid in the DeFi environment. Consider enforcing single-block execution restrictions on critical state-changing functions.

5. **Composable protocol integrations expand the attack surface exponentially.** This attack was executed by chaining more than 7 protocols: Bunni, Curve, LLAMMA, FiRM, sDOLA, DBREarn, and SaveDola. Security audits of individual contracts alone are insufficient to discover composite attack paths; integrated security analysis of cross-protocol interactions is essential.

---

## 8. On-Chain Verification

### 8.1 Key On-Chain Measured Values

| Item | On-Chain Actual Value |
|------|-------------|
| Bunni flash loan | 15,986 WETH + USDC |
| Curve crvUSD flash loan | 25,000,000 crvUSD |
| alUSD/USDC pool swap | USDC → 6,187,490 alUSD |
| alUSD/sDOLA pool swap | 650,000 alUSD → 454,997 sDOLA |
| scrvUSD/SaveDola route | 7,000,000 crvUSD → 327,300 sDOLA |
| LLAMMA swap (crvUSD→sDOLA) | 13,254,734 crvUSD → 9,825,506 sDOLA |
| sDOLA share captured | 10,607,802 / 11,770,912 = **90.1%** |
| DBREarn distribution | 12,613,130 DOLA |
| sDOLA burned → DOLA received | 10,607,802 sDOLA → 12,613,130 DOLA |
| Liquidation profit (helper) | Input 4,745,266 crvUSD → recover 7,093,231 crvUSD |
| Own FiRM position | 8,286,547 sDOLA collateral → recover 10,904,021 crvUSD |
| scrvUSD redemption | 7,002,748 crvUSD |
| **Net profit DOLA** | **+227,326 DOLA** |
| **Net profit WETH** | **+6.74 WETH** |
| **Total estimated profit** | **~$242,000** |

### 8.2 sDOLA Ratio Change (Direct cast call Query)

| Timing | Ratio (DOLA/sDOLA) | Notes |
|------|---------|------|
| Pre-attack (block 24566936) | **1.1890** | sDOLA total supply: 11,770,912 / total assets: 13,996,117 DOLA |
| Post-attack (block 24566937) | **1.3531** | Ratio after DBREarn yield distribution + large-scale burn |
| **Change** | **+13.8%** | Abnormal single-block ratio increase |

### 8.3 Key Event Sequence (Based on Log Index)

```
Block 24566937 — TX: 0xb93506af8f1a39f6a31e2d34f5f6a262c2799fef6e338640f42ab8737ed3d8a4

[Log 0x00-0x03] Flash loan receipts
  → Bunni: FlashCallback — 15,986 WETH + USDC
  → Curve: FlashLoan — 25,000,000 crvUSD

[Log 0x04-0x17] sDOLA accumulation (alUSD/scrvUSD routes)
  → 0xdcef: USDC/3CRV pool swap → alUSD acquired
  → 0xbc6da0: alUSD → sDOLA (Curve pool 0x460638)
  → 0x0655: scrvUSD deposit → 0x76a9(SaveDola) → sDOLA acquired

[Log 0x26-0x28] LLAMMA large-scale swap (core)
  → 0x0079 (LLAMMA): TokenExchange
  → crvUSD 13,254,734 → sDOLA 9,825,506

[Log 0x29-0x2d] Yield Sniping
  → 0xe5f2 (DBREarn) → 0xb45a (sDOLA): distribute 12,613,130 DOLA
  → 0xd8e8 → 0x0000: burn 10,607,802 sDOLA
  → 0xb45a → 0xd8e8: receive 12,613,130 DOLA

[Log 0x30-0x9f] Cascading liquidations (helper)
  → 0xd8e8 → 0xc6c2: transfer 4,745,266 crvUSD
  → 0xad44 (Controller): multiple Liquidate(0x642dd4d3) events
  → LLAMMA → 0xc6c2: multiple liquidation reward transfers
  → 0xc6c2 → 0xd8e8: return 7,093,231 crvUSD

[Later logs] FiRM cleanup and flash loan repayment
  → 0xad44 → 0xd8e8: 10,904,021 crvUSD (position cleanup)
  → 0xd8e8 → 0xa920: repay 25,000,000 crvUSD
  → 0xb4e1 (Uniswap V2): convert remaining USDC → WETH
  → 0xd8e8 → 0xbbbb: repay 15,986 WETH
```

### 8.4 Pre-condition Verification (As of Block 24566936)

| Item | Queried Value |
|------|--------|
| sDOLA totalSupply | 11,770,912 sDOLA |
| sDOLA totalAssets | 13,996,117 DOLA |
| sDOLA/DOLA ratio (convertToAssets 1e18) | 1,189,042,662,706,965,487 (~1.189) |
| Post-attack ratio (block 24566937) | 1,353,066,283,233,106,054 (~1.353) |

---

> **Disclaimer**: This analysis report was prepared using on-chain log data and direct contract queries, and should be used for educational and security research purposes only. The Solidity code in the vulnerable code sections is a conceptual reconstruction and may differ from the actual deployed contract code.