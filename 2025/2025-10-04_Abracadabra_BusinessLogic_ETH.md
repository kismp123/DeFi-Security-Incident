# Abracadabra (MIM) — Business Logic Vulnerability Analysis (2025-10)

| Field | Details |
|------|------|
| **Date** | 2025-10-04 |
| **Protocol** | Abracadabra (MIM / Spell) |
| **Chain** | Ethereum |
| **Loss** | ~$1,793,766 MIM (~$1.7M) · converted to ~395 ETH |
| **Attacker** | [0x1aaa...354d](https://etherscan.io/address/0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d) |
| **Attack Contract** | [0xB8e0...B993](https://etherscan.io/address/0xB8e0A4758Df2954063Ca4ba3d094f2d6EdA9B993) (self-destructed after attack) |
| **Attack Tx** | [0x842a...e5e6](https://etherscan.io/tx/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6) |
| **Vulnerable Contract** | CauldronV4 (6 deprecated Cauldrons, ETH Mainnet) |
| **Root Cause** | An unimplemented Action (ID=0) in the `cook()` function initializes `CookStatus` to its default value, allowing bypass of the solvency check |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/tree/main/src/test/2025-10) |

> **Note**: This incident (ETH, 2025-10, business logic) is a **separate event** from the [2025-03-25 MIMSpell Cauldron Rounding ARB](./2025-03-25_MIMSpell_CauldronRounding_ARB.md) incident (ARB, GMX V2 collateral accounting discrepancy).

---

### Affected Cauldron List

| Cauldron Address | Role |
|---------------|------|
| [0x46f5...82c](https://etherscan.io/address/0x46f54d434063e5F1a2b2CC6d9AAa657b1B9ff82c) | deprecated CauldronV4 #1 |
| [0x2894...3ED](https://etherscan.io/address/0x289424aDD4A1A503870EB475FD8bF1D586b134ED) | deprecated CauldronV4 #2 |
| [0xce45...65b](https://etherscan.io/address/0xce450a23378859fB5157F4C4cCCAf48faA30865B) | deprecated CauldronV4 #3 |
| [0x40d9...DA3](https://etherscan.io/address/0x40d95C4b34127CF43438a963e7C066156C5b87a3) | deprecated CauldronV4 #4 |
| [0x6bcd...DA2](https://etherscan.io/address/0x6bcd99D6009ac1666b58CB68fB4A50385945CDA2) | deprecated CauldronV4 #5 |
| [0xC6D3...20D](https://etherscan.io/address/0xC6D3b82f9774Db8F92095b5e4352a8bB8B0dC20d) | deprecated CauldronV4 #6 |

---

## 1. Vulnerability Overview

Abracadabra's `CauldronV4` contract provides a `cook()` function that bundles multiple operations into a single transaction. This function processes each action sequentially, and is designed to set `CookStatus.needsSolvencyCheck = true` when executing risky operations (borrowing, collateral withdrawal), performing a **solvency check after all actions complete**.

The core of the vulnerability is that the `_additionalCookAction()` function (Action ID=0) **returns the default value `CookStatus(false)` with no logic whatsoever**. The attacker exploited the `cook([5, 0])` pattern — executing borrow (Action 5) immediately followed by the unimplemented Action (0) — to reset the `needsSolvencyCheck` flag back to `false`, completely bypassing the solvency check.

This vulnerability existed **for 961 days since February 2023**, and was exploited simultaneously across 6 deprecated CauldronV4 contracts on Ethereum Mainnet on October 4, 2025. The attacker successfully borrowed a total of **1,793,766 MIM** without any collateral.

---

## 2. Vulnerable Code Analysis

### 2.1 `CookStatus` Struct

```solidity
// CauldronV4.sol
struct CookStatus {
    bool needsSolvencyCheck;  // Whether a solvency check is required
    bool targetSuccess;       // Whether the external call succeeded
}
```

### 2.2 `cook()` Main Function — State Flag Handling (❌ Vulnerable)

```solidity
// ❌ Vulnerable: processes the actions array sequentially, updating CookStatus
function cook(
    uint8[] calldata actions,
    uint256[] calldata values,
    bytes[] calldata datas
) external payable returns (uint256 value1, uint256 value2) {
    CookStatus memory status;  // default: needsSolvencyCheck = false

    for (uint256 i = 0; i < actions.length; i++) {
        uint8 action = actions[i];

        if (action == ACTION_BORROW) {          // action == 5
            // ❌ Sets solvency check flag after executing borrow
            (status.needsSolvencyCheck, ) = _borrow(abi.decode(datas[i], (address, uint256)));
            // → needsSolvencyCheck is set to true
        } else {
            // ❌ Core vulnerability: unknown action ID → calls _additionalCookAction
            // → returns CookStatus(false, false) → overwrites status!
            status = _additionalCookAction(status, action, values[i], datas[i]);
        }
    }

    // ❌ Final solvency check: already reset to false, so check is skipped
    if (status.needsSolvencyCheck) {
        require(_isSolvent(msg.sender, exchangeRate), "Cauldron: user insolvent");
    }
}
```

### 2.3 `_additionalCookAction()` — Flag Reset Function (❌ Vulnerable)

```solidity
// ❌ Core vulnerable function: unimplemented action resets the safety flag
function _additionalCookAction(
    CookStatus memory,       // ❌ Ignores the existing status (unused)
    uint8 /*action*/,
    uint256 /*value*/,
    bytes calldata /*data*/
) internal virtual returns (CookStatus memory) {
    // ❌ Returns default value with no logic → needsSolvencyCheck = false
    return CookStatus(false, false);
}
```

### 2.4 Fixed Code (✅ Post-Patch)

```solidity
// ✅ Fix Method 1: Preserve existing status using OR operation
function cook(
    uint8[] calldata actions,
    uint256[] calldata values,
    bytes[] calldata datas
) external payable returns (uint256 value1, uint256 value2) {
    CookStatus memory status;

    for (uint256 i = 0; i < actions.length; i++) {
        uint8 action = actions[i];

        if (action == ACTION_BORROW) {
            (bool needsCheck, ) = _borrow(abi.decode(datas[i], (address, uint256)));
            // ✅ Preserve existing flag using OR (once true, never revert to false)
            status.needsSolvencyCheck = status.needsSolvencyCheck || needsCheck;
        } else {
            CookStatus memory newStatus = _additionalCookAction(status, action, values[i], datas[i]);
            // ✅ OR the new status flag with the existing flag
            status.needsSolvencyCheck = status.needsSolvencyCheck || newStatus.needsSolvencyCheck;
        }
    }

    if (status.needsSolvencyCheck) {
        require(_isSolvent(msg.sender, exchangeRate), "Cauldron: user insolvent");
    }
}

// ✅ Fix Method 2: Explicitly reject unknown action IDs
function _additionalCookAction(
    CookStatus memory status,
    uint8 action,
    uint256 value,
    bytes calldata data
) internal virtual returns (CookStatus memory) {
    // ✅ Immediately revert on unrecognized action IDs
    revert("Cauldron: unknown action");
}
```

**Summary of the issue**: `_additionalCookAction()` ignores the existing `CookStatus` and returns `CookStatus(false, false)`, overwriting the `needsSolvencyCheck = true` set by the preceding `ACTION_BORROW` back to `false`. This causes the final solvency check to be skipped, enabling uncollateralized borrowing.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- **Funding source**: Initial ETH sourced from Tornado Cash
- **Money laundering preparation**: Deployed attack contract (0xB8e0...B993) (destroyed via `selfdestruct` after the attack)
- **Multi-address strategy**: Used 6 attacker addresses to bypass per-Cauldron borrow limits

### 3.2 Execution Phase

The following pattern was repeated for each Cauldron:

```
1. cook([ACTION_BORROW=5, ACTION_ADDITIONAL=0], ...)
   ├─ Action 5 executed: borrow(attacker, large MIM amount)
   │     → needsSolvencyCheck = true is set
   └─ Action 0 executed: _additionalCookAction() called
         → returns CookStatus(false, false)
         → overwrites status.needsSolvencyCheck = false

2. Final check: if(status.needsSolvencyCheck) → false → check skipped

3. ~300,000 MIM borrowed successfully without collateral
```

6 addresses × 6 Cauldrons → total ~1,793,766 MIM drained

Borrowed MIM swapped to USDC/USDT via DEX aggregator, then converted to ETH → total 395 ETH

### 3.3 Attack Flow Diagram

```
Attacker EOA (0x1aaa...354d)
      │
      │ deploys
      ▼
┌─────────────────────────┐
│   Attack Contract       │  (0xB8e0...B993, selfdestruct after attack)
│  (AttackContract)       │
└────────────┬────────────┘
             │ calls cook([5, 0])
             │
             ▼
┌─────────────────────────────────────────────────────┐
│              CauldronV4 (deprecated, x6)             │
│                                                      │
│  1. Process Action 5 (BORROW)                        │
│     → _borrow(attacker, 300,000 MIM)                 │
│     → needsSolvencyCheck = true ← flag set           │
│                                                      │
│  2. Process Action 0                                 │
│     → _additionalCookAction() called                 │
│     → return CookStatus(false, false)  ← ❌ reset    │
│     → status.needsSolvencyCheck = false              │
│                                                      │
│  3. Final check: needsSolvencyCheck == false         │
│     → Solvency check skipped!                        │
│     → 300,000 MIM uncollateralized borrow confirmed  │
└──────────────┬──────────────────────────────────────┘
               │
               │ repeated × 6 Cauldrons
               ▼
┌─────────────────────────┐
│  Drained: 1,793,766 MIM │
└────────────┬────────────┘
             │ DEX swap (MIM → USDC → ETH)
             ▼
┌─────────────────────────┐
│  Acquired: ~395 ETH     │
└────────────┬────────────┘
             │ Tornado Cash (46+ transactions)
             ▼
      [Laundering complete]
```

### 3.4 Outcome

| Item | Amount |
|------|------|
| MIM Drained | 1,793,766 MIM (~$1.7M) |
| ETH Converted | ~395 ETH |
| Tornado Cash Laundered | 395 ETH (51 ETH immediately + 344 ETH subsequently) |

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Unimplemented Action resets safety flag | CRITICAL | CWE-841 | 11_logic_error.md (Pattern 2: State Update Error) |
| V-02 | Non-monotonic state management in batch function | HIGH | CWE-693 | 11_logic_error.md (Pattern 3: Validation Order Error) |
| V-03 | Deprecated contracts not deactivated | HIGH | CWE-1188 | 03_access_control.md |
| V-04 | Implicit allowance of unrecognized Action IDs | MEDIUM | CWE-754 | 11_logic_error.md |

### V-01: Unimplemented Action ID Resets Safety Flag (CRITICAL)

- **Description**: `_additionalCookAction()` is a fallback function that handles unknown action IDs; it ignores the existing `CookStatus` and returns the default `CookStatus(false, false)`. In the `cook()` loop, this return value overwrites `status`, resetting `needsSolvencyCheck` to `false`.
- **Impact**: Enables unlimited uncollateralized borrowing → entire protocol liquidity can be drained
- **Attack Conditions**: Permission to call `cook()` (anyone), passing ID 0 (unimplemented) after ID 5 (BORROW), MIM liquidity remaining in the Cauldron

### V-02: Non-Monotonic State Management in Batch Function (HIGH)

- **Description**: A safety-related flag (`needsSolvencyCheck`) **must never be reverted to false once set to true within the same transaction**. `cook()` does not guarantee this monotonicity property.
- **Impact**: Any action can invalidate previously established security requirements
- **Attack Conditions**: A `cook()` call containing two or more actions

### V-03: Deprecated Contracts Not Deactivated (HIGH)

- **Description**: 6 CauldronV4 contracts were labeled "deprecated" yet remained fully functional. The last audit was in November 2023, approximately 2 years before the attack.
- **Impact**: Vulnerabilities accumulated since the audit impacted live production
- **Attack Conditions**: Contracts marked as deprecated but not actually deactivated (borrowing not paused, functionality not restricted)

### V-04: Implicit Allowance of Unrecognized Action IDs (MEDIUM)

- **Description**: The `cook()` function routes unknown action IDs to the `_additionalCookAction()` fallback instead of reverting. This is an implicit allowance pattern that can produce unexpected behavior.
- **Impact**: Potential for various bypass attacks using new unimplemented actions in the future
- **Attack Conditions**: A `cook()` call containing an invalid action ID

---

## 5. Remediation Recommendations

### Immediate Actions

**5.1 Enforce Safety Flag Monotonicity (OR Operation)**

```solidity
// ✅ Recommended: use OR operation to ensure flag is never reverted to false
for (uint256 i = 0; i < actions.length; i++) {
    CookStatus memory newStatus = _processAction(actions[i], values[i], datas[i]);
    // OR operation: once true, stays true
    status.needsSolvencyCheck = status.needsSolvencyCheck || newStatus.needsSolvencyCheck;
    status.targetSuccess = status.targetSuccess || newStatus.targetSuccess;
}
```

**5.2 Explicitly Reject Unknown Action IDs**

```solidity
// ✅ Recommended: validate against whitelist, immediately revert on unrecognized actions
function _additionalCookAction(
    CookStatus memory status,
    uint8 action,
    uint256 value,
    bytes calldata data
) internal virtual returns (CookStatus memory) {
    // Explicitly revert instead of silently succeeding on unimplemented actions
    revert("Cauldron: unrecognized action");
}
```

**5.3 Immediate Inline Check After Risky Actions**

```solidity
// ✅ Alternative: immediate inline solvency check right after borrow/collateral withdrawal
if (action == ACTION_BORROW) {
    _borrow(to, amount);
    // Verify immediately instead of deferring
    require(_isSolvent(msg.sender, exchangeRate), "Cauldron: insolvent after borrow");
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Safety flag reset | Unify all state merges in `cook()` using OR operations |
| V-02 Non-monotonic state | Design safety flag type as monotonically increasing (`bool`→`uint8` + bitwise OR) |
| V-03 Not deactivated | Apply `borrowingPaused = true` and `maxBorrow = 0` to deprecated contracts |
| V-04 Implicit allowance | Validate all action IDs against an allowlist at `cook()` entry, revert otherwise |

**Additional Recommendations:**
- Establish a regular audit cycle for core borrow logic (CauldronV4) — at minimum annually
- Establish a deprecated contract lifecycle policy: disable core functionality immediately upon "deprecated" labeling
- Add invariant tests: `"needsSolvencyCheck must be true after a borrow"`, `"external actions cannot lower the solvency flag"`

---

## 6. Lessons Learned

1. **Safety flags must be monotonically increasing**: If any logic in a transaction sets a security requirement flag, no execution path should be able to lower that flag. The OR operator is a simple and effective pattern to guarantee this.

2. **Fallback/default-returning functions should always be suspect**: Functions like `_additionalCookAction()` that do nothing and return a default value can implicitly reset security state. A "do-nothing function" may in practice be a "state-erasing function."

3. **Deprecated ≠ Safe**: Labeling a contract "deprecated" does not deactivate it. Legacy contracts must be explicitly paused or deactivated via migration. A production contract that has not been audited for 2 years is a high-risk factor.

4. **Batch Functions are a weak point for state consistency**: Functions that bundle multiple operations — `cook()`, `multicall()`, `executeBatch()` — require careful scrutiny of state transitions between each action. It must be formally proven or tested that no sub-action can violate security invariants.

5. **Monitor forked codebases**: This attack occurred just 3 days after Synnax (an Abracadabra fork) paused its contracts on October 1, 2025 due to the same vulnerability. Security issues in open-source fork projects can apply to the original project immediately. Fork repository monitoring should be included in security processes.

6. **Principle of Least Privilege — Action ID Allowlist**: The "allowlist" principle in input validation applies equally to smart contracts. Explicitly rejecting unknown inputs rather than implicitly handling them is far safer.

---

## 7. On-Chain Verification

### 7.1 Transaction Details

| Field | Value |
|------|-----|
| Attack Tx | [0x842a...e5e6](https://etherscan.io/tx/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6) |
| Timestamp | 2025-10-04 12:54:23 UTC |
| From (Attacker) | 0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d |
| Initial Funding Address | 0x1FF8Ea9b29aa10713774b60134D53529301Ca9C5 |
| Attack Contract | 0xB8e0A4758Df2954063Ca4ba3d094f2d6EdA9B993 (selfdestruct after attack) |

### 7.2 PoC vs On-Chain Amount Comparison

| Item | On-Chain Actual | Notes |
|------|-------------|------|
| Total MIM Drained | 1,793,766 MIM | Sum across 6 Cauldrons |
| Average per Cauldron | ~299,000 MIM | ~300,000 MIM each |
| ETH Converted | ~395 ETH | MIM → USDC/USDT → ETH route |
| Tornado Cash Laundered | 395 ETH | 51 ETH (immediate) + 344 ETH (subsequent, 36+ txs) |

### 7.3 Pre-Attack Timeline

| Date | Event |
|------|------|
| 2023-11 | Last CauldronV4 audit |
| 2024-11 | PeckShield audits Synnax Labs (Abracadabra fork) — vulnerability not found |
| 2025-10-01 | Synnax Labs emergency pause of contracts due to the same vulnerability |
| 2025-10-03 | PeckShield removes Synnax audit report and issues refund |
| 2025-10-04 | Abracadabra CauldronV4 attack occurs |
| 2025-10-06 | Abracadabra official announcement (2-day delay) |

### 7.4 Response Actions

- Abracadabra: Immediately paused borrowing on all Cauldrons
- DAO Treasury: Repurchased 1,793,766 MIM from the market to maintain the MIM peg
- Incident disclosed via Discord (0xMerlin) rather than official channels

---

## References

- [Three Sigma: MIM Spell Third Exploit Breakdown](https://threesigma.xyz/blog/exploit/mimspell-abracadabra-hack-breakdown)
- [Halborn: Explained — The Abracadabra Hack (October 2025)](https://www.halborn.com/blog/post/explained-the-abracadabra-hack-october-2025)
- [QuillAudits: The Abracadabra Hack ($1.8M Logic Error)](https://www.quillaudits.com/blog/hack-analysis/abracadabra-hack-explained)
- [Rekt News: Abracadabra — Rekt III](https://rekt.news/abracadabra-rekt3)
- [InfyniSec Medium: A deep examination of the Abracadabra exploit](https://medium.com/@InfyniSec/a-deep-examination-of-the-abracadabra-exploit-183da57485cf)
- [DeFiHackLabs GitHub](https://github.com/SunWeb3Sec/DeFiHackLabs/tree/main/src/test/2025-10)
- [Attack Tx (Etherscan)](https://etherscan.io/tx/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6)
- [Attacker Address (Etherscan)](https://etherscan.io/address/0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d)