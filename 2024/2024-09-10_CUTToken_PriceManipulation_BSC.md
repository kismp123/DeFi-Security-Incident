# CUT Token — Price Dependency Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-10 |
| **Protocol** | CUT Token (Caterpillar Coin) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$1,448,974 (USDT) |
| **Attacker EOA** | [0x560a...eB45](https://bscscan.com/address/0x560a77bc06dcc77eee687acb65d46b580a63eb45) |
| **Attack Contract** | [0x87EF...56Dd](https://bscscan.com/address/0x87EFb39a716860eCd2324A944Cb40EC5128e56Dd) |
| **Attack Tx** | [0x6262...c8a](https://bscscan.com/tx/0x6262c0f15c88aed6f646ed1996eb6aae9ccc5d5704d5faccd1e1397dd047bc8a) |
| **CUT Token** | [0x7057...36a7](https://bscscan.com/address/0x7057f3b0f4d0649b428f0d8378a8a0e7d21d36a7) |
| **Price Protection Contract** | [0x7b2e...cbaf](https://bscscan.com/address/0x7b2e7cb89824236cb7096cde7a153af30f3ecbaf) |
| **LP Future Yield Contract** | [0x0917...1154](https://bscscan.com/address/0x0917914b0a70ee7f1f2460fcd487696856e31154) |
| **Victim LP Pool** | [0x8368...3249](https://bscscan.com/address/0x83681F67069A154815a0c6C2C97e2dAca6eD3249) (USDT-CUT PancakeSwap) |
| **Root Cause** | Price dependency vulnerability — reward calculation based on manipulable spot price |
| **Attack Block** | [#42,132,018](https://bscscan.com/block/42132018) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/tree/main/src/test/2024-09) |

---

## 1. Vulnerability Overview

CUT Token (Caterpillar Coin) implemented a "Price Protection Reward" mechanism that grants rewards to users who provide liquidity to the PancakeSwap USDT-CUT pool. This mechanism relies on two external contracts:

- **Price Protection Contract** (`transferFunDealTypeContractAddress`, `0x7b2e...cbaf`): Creates an orderID and reward record (reserve ratio) when LP is added
- **LP Future Yield Contract** (`lpFutureYieldContractAddress`, `0x0917...1154`): Compares historical records against current price and distributes CUT token rewards when LP is removed

The core vulnerability is that the reward calculation logic **depends on a spot price that can be manipulated within a single transaction**. An attacker borrows massive liquidity via flash loan, then within the same transaction, drastically skews the LP pool's reserve ratio and records this distorted state as the "reference price" in the order record. When the reserves are restored, the attacker can collect excess CUT rewards equivalent to the apparent price difference between the historical record (low CUT price) and the present (high CUT price). This process was repeated approximately 40 times to steal a total of ~$1.45M.

Both external contracts were in an unverified (source code not published) state on BSCScan, and the attack function selector `0x7a50b2b8` does not exist in the CUT token main contract — it is invoked via `ILPFutureYieldContract`.

---

## 2. Vulnerable Code Analysis

### 2.1 Reward Calculation Based on Manipulable Spot Price ❌

**Vulnerable Logic (estimated — source unverified)**:

```solidity
// ❌ Vulnerable reward calculation — transferFunDealTypeContractAddress contract
function createOrder(uint256 orderId, address user) external {
    // Records the reserve ratio at the time of LP addition
    // Problem: this value can be skewed by flash loan within the same transaction
    (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(LP_POOL).getReserves();

    // ❌ Stores the spot reserve ratio directly as the reference price
    uint256 priceRatio = uint256(reserve0) * PRECISION / uint256(reserve1);
    orders[orderId] = Order({
        user: user,
        baseRatio: priceRatio,   // manipulated ratio is stored as-is
        timestamp: block.timestamp
    });
}

// Reward calculation on LP removal
function valuePreservationByRemoveLP(uint256 orderId) external returns (uint256 cutReward) {
    Order memory order = orders[orderId];
    (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(LP_POOL).getReserves();

    // ❌ CUT reward calculated from the difference between stored (manipulated) base ratio and current ratio
    uint256 currentRatio = uint256(reserve0) * PRECISION / uint256(reserve1);
    uint256 ratioDiff = currentRatio - order.baseRatio;  // larger diff → more CUT paid out

    // ❌ Excessive CUT minted/paid proportional to the inflated ratioDiff
    cutReward = ratioDiff * CUT_PER_RATIO_UNIT;
    _mintCUT(order.user, cutReward);
}
```

**Fixed Code (✅)**:

```solidity
// ✅ Use TWAP-based price — cannot be manipulated in a single block
function createOrder(uint256 orderId, address user) external {
    // ✅ Retrieve price from Chainlink or TWAP oracle (tamper-resistant)
    uint256 priceRatio = _getTWAPPrice();  // 30-minute TWAP
    orders[orderId] = Order({
        user: user,
        baseRatio: priceRatio,
        timestamp: block.timestamp
    });
}

function valuePreservationByRemoveLP(uint256 orderId) external returns (uint256 cutReward) {
    Order memory order = orders[orderId];

    // ✅ Enforce minimum cooldown period (prevents flash loan attacks)
    require(block.timestamp >= order.timestamp + MIN_COOLDOWN, "Cooldown period active");

    // ✅ Calculate current ratio using TWAP price
    uint256 currentRatio = _getTWAPPrice();

    // ✅ Apply maximum reward cap
    uint256 ratioDiff = currentRatio > order.baseRatio
        ? currentRatio - order.baseRatio
        : 0;
    cutReward = Math.min(ratioDiff * CUT_PER_RATIO_UNIT, MAX_REWARD_PER_TX);
    _mintCUT(order.user, cutReward);
}

// ✅ Example TWAP implementation
function _getTWAPPrice() internal view returns (uint256) {
    // TWAP based on UniswapV2 cumulative price (minimum 30 minutes)
    uint256 price0Cumulative = IUniswapV2Pair(LP_POOL).price0CumulativeLast();
    // ... TWAP calculation logic
}
```

**The Problem**: The spot reserve ratio read via `getReserves()` can be arbitrarily manipulated within the same transaction using large-scale swaps. Once this manipulated value is stored as the reward baseline, when the reserves return to normal, the system incorrectly calculates that "the price has risen significantly," resulting in excessive CUT rewards being paid out.

---

### 2.2 Dependency on Unverified External Contracts ❌

```solidity
// ❌ Vulnerable CUT token contract — entirely dependent on unverified external contracts
contract CUTToken {
    address public transferFunDealTypeContractAddress; // 0x7b2e...cbaf (source unverified)
    address public lpFutureYieldContractAddress;       // 0x0917...1154 (source unverified)

    function addLiquidity(...) external {
        // ❌ Passes LP addition info to unverified contract — internal logic cannot be reviewed
        ITransferFunDealType(transferFunDealTypeContractAddress).createOrder(orderId, msg.sender);
        // ...
    }

    function removeLiquidity(...) external {
        // ❌ Unverified contract has unconstrained ability to mint CUT tokens
        ILPFutureYield(lpFutureYieldContractAddress).valuePreservationByRemoveLP(orderId);
        // ...
    }
}
```

```solidity
// ✅ Fix: Mandatory source verification for external contracts + permission restrictions
contract CUTToken {
    // ✅ Integrate reward calculation logic directly into the main contract
    // ✅ If external contracts are unavoidable, BSCScan source verification is mandatory
    // ✅ Design so that external contracts cannot hold CUT minting privileges
    // ✅ Enforce reward caps directly within the main contract
}
```

---

## 3. Attack Flow

### 3.1 On-Chain Verified Data

| Field | Value |
|------|-----|
| Attack Block | 42,132,018 |
| Attack Contract | 0x87EFb39a716860eCd2324A944Cb40EC5128e56Dd |
| Input Data | `0x7a50b2b8` (single function call) |
| Total Log Count | 419 |
| USDT Transfer Count | 76 |
| Gas Used | 12,681,968 (out of 20M limit) |
| Flash Loan Principal | 50,000 USDT |
| Balance After Repayment | 58,290.51 USDT → distributed to beneficiary |

**LP Pool Reserve Changes (USDT-CUT PancakeSwap)**:

| Field | Before Attack | After Attack |
|------|---------|---------|
| USDT Reserve | 9,480.49 USDT | 1,190.23 USDT |
| USDT Decrease | — | **-8,290.26 USDT** |
| CUT Reserve | 123.71 (units) | 1,025.91 (units) |
| CUT/USDT Price | 76.63 | **1.16** (−98.5%) |

### 3.2 Attack Flow Diagram

```
┌──────────────────────────────────────────────────────────┐
│  Attacker EOA (0x560a...eB45)                            │
│  USDT Balance: 0                                         │
└─────────────────────┬────────────────────────────────────┘
                      │ Deploy attack contract, then call
                      │ input: 0x7a50b2b8
                      ▼
┌──────────────────────────────────────────────────────────┐
│  Attack Contract (0x87EF...56Dd)                         │
│  executeAttack()                                         │
└──────────┬────────────────────────────────┬──────────────┘
           │ [1] Flash loan 50,000 USDT     │
           ▼                                │
┌──────────────────────┐                   │
│  PancakeSwap V3      │                   │
│  Flash Loan Provider │                   │
│  (0x16b9...dae)      │                   │
└──────────┬───────────┘                   │
           │ Receive 50,000 USDT           │
           ▼                               │
┌──────────────────────────────────────────┴──────────────┐
│  Attack Loop (~40 iterations)                            │
│                                                          │
│  [2] Bulk swap USDT → CUT                                │
│      PancakeSwap USDT-CUT pool                           │
│      (CUT price spikes: reserve ratio manipulated)       │
│         │                                                │
│         ▼                                                │
│  [3] Add LP under manipulated reserve state              │
│      → transferFunDealTypeContractAddress (0x7b2e)       │
│        createOrder() called                              │
│        ┌─────────────────────────────────────────┐       │
│        │ Base price = manipulated spot price      │       │
│        │ (very low — lots of CUT, little USDT)   │       │
│        └─────────────────────────────────────────┘       │
│         │                                                │
│         ▼                                                │
│  [4] Bulk swap CUT → USDT (restore reserves)             │
│      CUT price crashes → returns to original level       │
│         │                                                │
│         ▼                                                │
│  [5] Remove LP → valuePreservationByRemoveLP()           │
│      lpFutureYieldContractAddress (0x0917)               │
│      ┌──────────────────────────────────────────────┐    │
│      │ Current price (high) - Base price            │    │
│      │ (artificially low via manipulation)          │    │
│      │ = Inflated ratioDiff → massive CUT minted    │    │
│      └──────────────────────────────────────────────┘    │
│         │                                                │
│         ▼                                                │
│  [6] Swap excess CUT received → USDT (accumulate profit) │
│      (USDT balance increases with each iteration)        │
└──────────────────────────────────────────────────────────┘
           │
           │ [7] Repay flash loan: 50,130 USDT
           ▼
┌──────────────────────┐
│  Flash Loan Provider │
│  Principal + fee     │
│  repaid              │
└──────────────────────┘
           │
           ▼ [8] Distribute net profit
┌──────────────────────────────────────┐
│  Attacker Beneficiary (0x5766...33F8)│
│  Received: 8,160.51 USDT             │
│  (This TX alone / 4 total = ~$1.45M) │
└──────────────────────────────────────┘
```

### 3.3 Outcome

| Field | Value |
|------|-----|
| This TX Profit | ~8,160 USDT (1 of 4 transactions) |
| Total Attack Profit | ~$1,448,974 USDT (4 transactions combined) |
| LP Pool USDT Loss | 9,480 → 1,190 USDT (−87.4%) |
| CUT Price Impact | −98.5% (76.63 → 1.16 USDT/CUT) |
| Flash Loan Principal | 50,000 USDT (fully repaid) |

---

## 4. PoC Code (DeFiHackLabs)

The PoC file could not be confirmed due to a GitHub 404, but the core logic has been reconstructed based on on-chain data and CertiK/SolidityScan analysis.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// [Attack input data] input: 0x7a50b2b8 (simple function selector — no arguments)

interface ILPFutureYieldContract {
    // ❌ Vulnerable function: pays CUT rewards based on manipulated price
    function valuePreservationByRemoveLP(uint256 orderId) external;
}

interface ITransferFunDealType {
    // Records spot price on LP addition (manipulation point)
    function createOrder(uint256 orderId, address user) external;
}

contract CUTAttacker {
    // [1] Flash loan callback
    function pancakeV3FlashCallback(
        uint256 fee0, uint256 fee1, bytes calldata data
    ) external {
        // [2] Received 50,000 USDT → bulk buy CUT (manipulate reserves)
        _swapUSDTForCUT(50_000e18 * 60 / 100);

        // [3] Add LP under distorted price state
        //     → internally calls createOrder() → low CUT price recorded as baseline
        _addLiquidity(remainingUSDT, smallCUT);

        // [4] Bulk sell CUT → USDT (restore reserves, normalize price)
        _swapCUTForUSDT(allCUTHeld);

        // [5] Remove LP → receive excess CUT from base(low) vs current(high) price delta
        //     valuePreservationByRemoveLP() mints ratioDiff * CUT_PER_UNIT
        _removeLiquidity(lpTokens);

        // [6] Immediately sell excess CUT received → USDT (realize profit)
        _swapExcessCUTForUSDT();

        // [above process repeated ~40 times]

        // [7] Repay flash loan + fee
        USDT.transfer(msg.sender, flashLoanAmount + fee0);
    }

    function execute() external {
        // Request 50,000 USDT flash loan from PancakeSwap V3
        pancakeV3Pool.flash(address(this), 50_000e18, 0, "");
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Reward calculation based on manipulable spot price | CRITICAL | CWE-1041 |
| V-02 | Dependency on unverified external contracts | HIGH | CWE-829 |
| V-03 | Insufficient flash loan protection (no cooldown/cap) | HIGH | CWE-400 |
| V-04 | Exploitation of single-transaction atomicity in reward calculation logic | MEDIUM | CWE-362 |

### V-01: Reward Calculation Based on Manipulable Spot Price

- **Description**: Reward calculation uses the spot reserve ratio read via `getReserves()`. This value can be arbitrarily manipulated within the same transaction using flash loans + swaps.
- **Impact**: Attacker manipulates the base price to an extreme low, then restores the reserves — the system is deceived into treating this as a "major price increase," resulting in excessive CUT rewards. These are immediately swapped to USDT, draining the LP pool.
- **Attack Conditions**: Sufficient liquidity (obtainable via flash loan), LP add/remove access (permissionless)

### V-02: Dependency on Unverified External Contracts

- **Description**: Both `transferFunDealTypeContractAddress` (0x7b2e) and `lpFutureYieldContractAddress` (0x0917) have not completed BSCScan source verification. Internal logic is opaque and unauditable.
- **Impact**: Users cannot trust contract behavior; the hidden vulnerable reward logic goes undetected until discovered through external investigation.
- **Attack Conditions**: All CUT token operations that interact with these contracts

### V-03: Insufficient Flash Loan Protection

- **Description**: LP can be removed and rewards claimed within the same transaction immediately after LP addition. No minimum holding period (cooldown) and no maximum reward cap per transaction exist.
- **Impact**: The entire attack cycle can be completed in a single transaction.
- **Attack Conditions**: Flash loan access (permissionless)

### V-04: Exploitation of Single-Transaction Atomicity in Reward Calculation Logic

- **Description**: Due to blockchain's atomic transaction nature, LP addition (record creation) and LP removal (reward collection) can occur within the same block. No time-based validation exists.
- **Impact**: Rewards meant for long-term liquidity providers can be stolen via one-off manipulation.
- **Attack Conditions**: Contract implementation that performs LP add/remove within the same transaction

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Introduce TWAP Oracle (eliminate spot price dependency)**

```solidity
// ✅ Use minimum 30-minute TWAP to block single-block manipulation
function _getSecurePrice() internal view returns (uint256) {
    // TWAP based on UniswapV2 cumulative price
    uint256 timeElapsed = block.timestamp - lastUpdateTime;
    require(timeElapsed >= MIN_TWAP_PERIOD, "TWAP period insufficient"); // minimum 1800 seconds
    uint256 price0Average = price0Cumulative / timeElapsed;
    return price0Average;
}
```

**2) Enforce Cooldown Period**

```solidity
// ✅ Allow LP removal only after minimum N blocks/time has elapsed since LP addition
mapping(address => uint256) public lastAddLiquidityBlock;

function removeLiquidity(...) external {
    require(
        block.number >= lastAddLiquidityBlock[msg.sender] + MIN_BLOCKS,
        "Cooldown: too soon after adding liquidity"
    );
    // ...
}
```

**3) Set Reward Cap**

```solidity
// ✅ Limit maximum reward per transaction and per user
uint256 public constant MAX_REWARD_PER_TX = 1000e18; // e.g., max 1,000 CUT/TX

cutReward = Math.min(calculatedReward, MAX_REWARD_PER_TX);
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Spot price dependency | Apply Chainlink oracle or UniswapV3 TWAP (30+ minutes) |
| V-02 Unverified external contracts | Publish source for all external contracts and conduct independent audits |
| V-03 Flash loan protection | Enforce minimum time interval between LP add and remove (disallow same block) |
| V-04 Atomicity exploitation | Block number-based cooldown + reentrancy prevention within single TX |
| Overall design | Integrate reward logic into main contract for transparency |
| Monitoring | Alert on large-scale LP add/remove patterns within a single TX |

---

## 7. Lessons Learned

1. **Do not use spot price as the basis for reward calculations**: Values obtained via `getReserves()` can be manipulated by tens of multiples within the same transaction using flash loans. Any reward or price-based logic must use time-weighted average prices (TWAP) or an independent oracle.

2. **Source verification is mandatory when depending on external contracts**: Delegating core business logic (reward calculation, minting privileges) to unverified contracts creates a black box for both users and auditors. All critical contracts must have their source code published on-chain.

3. **Introduce time locks on LP add/remove cycles**: Rewards intended for long-term liquidity providers must enforce a minimum holding period to prevent one-off flash loan attacks.

4. **Review whether reward creation and collection can occur simultaneously within a single transaction**: Any structure where "record creation → condition verification → reward collection" completes within the same TX is inherently exposed to flash loan attacks.

5. **Reward caps are the last line of defensive safety**: Even if a logic vulnerability exists, a maximum reward limit per TX or per block can significantly constrain the scale of damage.

6. **Expand the scope of pre-deployment audits to include external dependency contracts**: An audit that covers only the main contract while excluding external contracts can miss critical vulnerabilities, as demonstrated in this case.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Field | Value | PoC Match |
|------|-----|---------|
| Attacker EOA | 0x560a77bc06dcc77EEe687acB65D46B580a63eB45 | ✅ |
| Attack Contract (to) | 0x87EFb39a716860eCd2324A944Cb40EC5128e56Dd | ✅ |
| Input Function Selector | `0x7a50b2b8` | ✅ (function not present in CUT main contract) |
| Attack Block | 42,132,018 | ✅ |
| Transaction Status | Success (0x1) | ✅ |
| Gas Used | 12,681,968 / 20,000,000 | — |
| Total Event Log Count | 419 | — |

### 8.2 LP Pool Reserve Changes (On-Chain Measured)

| Field | Pre-Attack Block #42,132,017 | Post-Attack Block #42,132,018 | Change |
|------|------------------------|------------------------|------|
| USDT Reserve | 9,480.49 USDT | 1,190.23 USDT | **−87.4%** |
| CUT Reserve | 123.71 (base units) | 1,025.91 (base units) | +729.6% |
| Implied CUT/USDT Price | 76.63 | 1.16 | **−98.5%** |

### 8.3 Fund Flow (This TX)

| Step | Sender | Recipient | Amount | Token |
|------|--------|--------|------|------|
| Flash loan received | Flash Provider (0x16b9) | Attack Contract | 50,000 | USDT |
| Flash intermediate transfer | Attack Contract | Router (0xd9ad) | 50,000 | USDT |
| Flash loan repayment | Router → Settlement | Flash Provider | 50,130 | USDT |
| Net attack profit (this TX) | Settlement Contract | Beneficiary (0x5766) | **8,160.51** | USDT |

### 8.4 Precondition Verification

| Field | Pre-Attack State |
|------|------------|
| Attacker EOA USDT Balance | 0 USDT (flash loan only) |
| Attack Contract Pre-existing LP | None (no preparation required before attack) |
| Attack Contract Code Size | 7,206 bytes (separately deployed) |
| lpFutureYield Code Size | 19,848 bytes (unverified) |
| Price Protection Contract Size | 32,898 bytes (unverified) |

> **Note**: On-chain confirmation that the attacker EOA had 0 USDT pre-attack. The entire principal was sourced via flash loan, proving this was an attack executable with zero upfront capital.

---

*Analysis basis: On-chain data (BSC Block #42,132,018), CertiK incident analysis, SolidityScan hack analysis, Web3IsGoingGreat report*