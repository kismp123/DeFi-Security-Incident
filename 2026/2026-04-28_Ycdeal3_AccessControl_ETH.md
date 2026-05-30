# Ycdeal3 — Unprotected Privileged Function Drain

| Item | Details |
|------|------|
| **Date** | 2026-04-28 |
| **Protocol** | Ycdeal3 |
| **Chain** | Ethereum |
| **Loss** | ~$398K |
| **Root Cause** | ERC4626 `withdraw()` override missing caller authorization check — `msg.sender` is never validated against `owner` and `_spendAllowance()` is never called, allowing any address to withdraw any depositor's funds by supplying the victim as `owner` and themselves as `receiver` |
| **Attack Tx** | `0x6b04344d5627df59d3bc645e7454f4605a90272852a91e435e370376643353b3` |
| **Reference** | [exvulsec on X](https://x.com/exvulsec/status/2049156204757446960) |

---

## 1. Vulnerability Overview

Ycdeal3 (RWAVault, contract `0xB9C7C84A1Aa0dD40b5B38Aae815AD0CDD2E5F88a`) is an ERC4626-based fixed-term RWA vault on Ethereum. The protocol implemented a custom override of the ERC4626 `withdraw(assets, receiver, owner)` function that **omits the EIP-4626 required caller authorization check**.

EIP-4626 mandates that when `msg.sender != owner`, the caller must have been granted an allowance and the implementation must call `_spendAllowance(owner, msg.sender, shares)`. The RWAVault's custom `withdraw()` override performs no such check: it accepts any `owner` and any `receiver`, looks up `owner`'s deposit info, burns their shares, and transfers funds to `receiver` — without ever verifying that `msg.sender` is `owner` or has been authorized.

The attacker called `withdraw(amount, attacker, victim)` for each depositor in the vault, draining ~$398K USDC. The on-chain log emitted by the attack contract read: `"root cause: no check on the relationship between receiver and owner"`.

## 2. Vulnerable Code Analysis

Source: **Sourcify-verified** — RWAVault / 0xB9C7C84A1Aa0dD40b5B38Aae815AD0CDD2E5F88a (Ethereum)
Etherscan verified source: https://etherscan.io/address/0xB9C7C84A1Aa0dD40b5B38Aae815AD0CDD2E5F88a#code

```solidity
// SPDX-License-Identifier: MIT
// File: RWAVault.sol (ERC4626 Fixed-term vault)
// Source: Etherscan verified — 0xB9C7C84A1Aa0dD40b5B38Aae815AD0CDD2E5F88a (Ethereum)

contract RWAVault is ERC4626, AccessControl, Pausable, ReentrancyGuard, IRWAVault {
    // ...

    // ❌ Missing caller authorization — any address can pass any `owner` + `receiver`
    function withdraw(
        uint256 assets,
        address receiver,  // ❌ arbitrary receiver — attacker sets this to themselves
        address owner      // ❌ arbitrary owner — attacker sets this to any depositor
    )
        public
        override(ERC4626, IERC4626)
        nonReentrant
        whenNotPaused
        returns (uint256 shares)
    {
        // Phase check (Matured or Defaulted) — bypassable if vault is in Matured phase
        if (currentPhase != Phase.Matured && currentPhase != Phase.Defaulted) {
            revert RWAErrors.InvalidPhase();
        }
        if (withdrawalStartTime == 0 || block.timestamp < withdrawalStartTime) {
            revert RWAErrors.WithdrawalNotAvailable();
        }

        _claimRemainingInterest(owner); // ❌ called for arbitrary owner address

        DepositInfo storage info = _depositInfos[owner]; // ❌ looks up victim's deposit
        if (info.shares == 0) revert RWAErrors.ZeroAmount();

        uint256 grossValue = convertToAssets(info.shares);
        uint256 userDebt   = _userClaimedInterest[owner];
        uint256 netValue   = grossValue - userDebt;
        if (assets > netValue) { assets = netValue; }
        if (assets == 0) revert RWAErrors.ZeroAmount();

        shares = Math.mulDiv(assets, info.shares, netValue, Math.Rounding.Ceil);

        // ... deduct proportional principal and debt from victim's DepositInfo ...
        _burn(owner, shares);                          // ❌ burns victim's shares
        IERC20(asset()).safeTransfer(receiver, assets); // ❌ sends funds to attacker-controlled address

        // ❌ NO allowance check: msg.sender is never compared to owner
        // ❌ NO _spendAllowance() call — EIP-4626 §4 requires it when msg.sender != owner
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- ERC4626 standard (and OpenZeppelin's implementation) requires: when `msg.sender != owner`, the caller must have been granted an allowance via `approve()`, enforced by `_spendAllowance(owner, msg.sender, shares)`.
- This custom `withdraw()` override **never checks `msg.sender`** against `owner` and **never calls `_spendAllowance()`**.
- The attacker called `withdraw(amount, attacker_address, victim_address)` for each victim depositor, burning the victim's shares and receiving the underlying USDC.
- The on-chain log message was: `"root cause: no check on the relationship between receiver and owner"`.
- The attack transaction (`0x6b04344d5627...`) drained ~398K USDC via 26 ERC-20 token transfers from depositor accounts.

```solidity
// ✅ Fix: enforce ERC4626 allowance semantics
function withdraw(
    uint256 assets,
    address receiver,
    address owner
) public override returns (uint256 shares) {
    // ... phase checks ...

    // ✅ Require caller to be owner OR have sufficient allowance
    if (msg.sender != owner) {
        uint256 allowed = allowance(owner, msg.sender);
        if (allowed != type(uint256).max) {
            // Compute shares first, then check allowance
            // _spendAllowance handles the check + deduction
            _spendAllowance(owner, msg.sender, previewWithdraw(assets));
        }
    }

    // ... rest of withdraw logic ...
}
```

## 3. Attack Flow

1. Attacker identifies that the RWAVault is in `Matured` phase with `withdrawalStartTime` set, making the `withdraw()` function callable.
2. Attacker enumerates all depositor addresses and their USDC balances via on-chain events.
3. For each victim depositor, attacker calls `vault.withdraw(victim_balance, attacker_address, victim_address)`.
4. `withdraw()` burns the victim's shares and sends their USDC to the attacker — no allowance check performed.
5. 26 transfer events drain ~$398K USDC across all depositors in a single transaction.
6. The attack contract logs `"Hack the world"` and `"root cause: no check on the relationship between receiver and owner"` as inline event messages.
7. Final USDC balance of ~387K USDC returned to the attacker's EOA (`0x7137804200a073f616D92E87007f1f100100B56A`).

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Access Control — Missing Authorization on Privileged Function |
| **Severity** | Critical |
| **CWE** | CWE-284 (Improper Access Control) |

## 5. Remediation Recommendations

- When overriding ERC4626 `withdraw()` or `redeem()`, always preserve the allowance-check behavior from the base implementation: call `_spendAllowance(owner, msg.sender, shares)` whenever `msg.sender != owner`.
- Use OpenZeppelin's `ERC4626._withdraw()` internal as the base, which already contains the correct allowance enforcement.
- Alternatively, add a simple guard at the top of the override: `if (msg.sender != owner) { _spendAllowance(owner, msg.sender, previewWithdraw(assets)); }`.
- Run Slither's `arbitrary-send-erc20` and `unprotected-upgrade` detectors, and use `4naly3er` / `aderyn` ERC4626 checkers as part of CI/CD before deployment.
- Add a test that verifies: calling `withdraw(amount, attacker, victim)` from `attacker` (with no allowance) reverts.

## References

- [exvulsec — X post](https://x.com/exvulsec/status/2049156204757446960)
- [Etherscan — Attack Tx](https://etherscan.io/tx/0x6b04344d5627df59d3bc645e7454f4605a90272852a91e435e370376643353b3)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
