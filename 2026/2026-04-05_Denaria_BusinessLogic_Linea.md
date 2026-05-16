# Denaria Finance — Business Logic Exploit on Linea

| Item | Details |
|------|------|
| **Date** | 2026-04-05 |
| **Protocol** | Denaria Finance |
| **Chain** | Linea |
| **Loss** | ~$166K |
| **Root Cause** | Business Logic Flaw — incorrect or manipulable share/asset accounting during withdrawal allows attacker to extract more than their proportional entitlement |
| **Attacker** | Unverified (not independently confirmed) |
| **Attack Tx** | `0xcb0744a0d453e5556f162608fae8275dabd14292bffbfcd8394af4610c606447` |
| **Vulnerable Contract** | Unverified (Denaria Finance vault contract on Linea; address not independently confirmed) |
| **PoC Source** | None on record |
| **Reference** | [DenariaFinance on X](https://x.com/DenariaFinance/status/2042589690415427933) |

---

## 1. Vulnerability Overview

Denaria Finance is a DeFi yield protocol deployed on Linea, Ethereum's ZK-rollup L2. On April 5, 2026, a business logic vulnerability in the Denaria contract was exploited for ~$166K. Linea's EVM compatibility means the same vulnerability classes found on Ethereum mainnet apply directly. The flaw resided in the share-to-asset conversion or the withdrawal execution path: the amount of underlying assets returned to the caller was computed from a state variable (`totalAssets()` or equivalent) that could be stale, inflated by a donation, or read at a point in time that diverged from the moment funds were actually transferred out.

Vault-style protocols that track user ownership via share tokens are particularly susceptible to this pattern. If `totalAssets()` can be temporarily inflated (e.g., via a direct token donation to the vault or a flash loan that manipulates the accounting state), the share-to-asset ratio increases, allowing a user to redeem shares for more underlying assets than they deposited. The attacker profits from the difference between the inflated redemption value and the actual cost of acquiring the shares.

## 2. Vulnerable Code Analysis

```solidity
// VULNERABLE — totalAssets() can be stale or externally manipulated
function withdraw(uint256 shares) external {
    // BUG: totalAssets() reads the contract's current token balance,
    // which can be inflated by a prior donation or flash-loan deposit.
    // The amount is calculated before shares are burned, but the
    // token transfer happens after — a reentrancy window also exists
    // if the token has callback hooks.
    uint256 amount = shares * totalAssets() / totalSupply();
    _burn(msg.sender, shares);
    token.transfer(msg.sender, amount);
}

function totalAssets() public view returns (uint256) {
    // BUG: returns raw balance — susceptible to donation manipulation
    return token.balanceOf(address(this));
}

// FIXED — snapshot totalAssets before any state change; use stored accounting
function withdraw(uint256 shares) external nonReentrant {
    // Lock in the exchange rate at the start of the call using
    // internally tracked assets (not live balanceOf)
    uint256 _totalAssets = _trackedAssets;
    uint256 _totalSupply = totalSupply();
    uint256 amount = shares * _totalAssets / _totalSupply;
    require(amount > 0, "zero amount");
    // Burn shares and update tracked assets atomically before transfer
    _burn(msg.sender, shares);
    _trackedAssets -= amount;
    // Transfer last (checks-effects-interactions)
    token.transfer(msg.sender, amount);
}
```

The fixed version uses an internally maintained `_trackedAssets` counter rather than the live `balanceOf`, applies `nonReentrant`, and follows checks-effects-interactions ordering to eliminate both the manipulation vector and any reentrancy window.

## 3. Attack Flow

1. Attacker acquires Denaria shares (either by depositing legitimately or buying on secondary market).
2. Attacker donates tokens directly to the Denaria vault contract (or uses a flash loan to temporarily inflate the vault's balance), increasing `totalAssets()` without minting new shares.
3. Attacker calls `withdraw(shares)` — the inflated `totalAssets()` causes the share-to-asset ratio to be higher than at deposit time.
4. Attacker receives more tokens than the proportional share value at the time of deposit, netting a profit of ~$166K.
5. If a flash loan was used to inflate the balance, the loan is repaid from the excess withdrawn assets.

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Business Logic Flaw — Share/Asset Accounting Manipulation |
| **Severity** | High |
| **CWE** | CWE-682 (Incorrect Calculation) |

## 5. Remediation Recommendations

- Track vault assets using an internal accounting variable updated on deposits, withdrawals, and yield accruals rather than relying on `token.balanceOf(address(this))`, which is susceptible to direct donations and flash-loan inflation.
- Apply `nonReentrant` to all deposit and withdrawal functions and follow checks-effects-interactions ordering: calculate amounts, update state, then perform external transfers.
- Add a minimum deposit amount and a per-block or per-transaction withdrawal cap to limit the profitability of one-shot manipulation attacks.

## References

- [DenariaFinance — X post](https://x.com/DenariaFinance/status/2042589690415427933)
- [Linea Explorer — Attack Tx](https://lineascan.build/tx/0xcb0744a0d453e5556f162608fae8275dabd14292bffbfcd8394af4610c606447)
- [CWE-682: Incorrect Calculation](https://cwe.mitre.org/data/definitions/682.html)
