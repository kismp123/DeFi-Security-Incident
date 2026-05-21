# Ycdeal3 — Unprotected Privileged Function Drain

| Item | Details |
|------|------|
| **Date** | 2026-04-28 |
| **Protocol** | Ycdeal3 |
| **Chain** | Ethereum |
| **Loss** | ~$398K |
| **Root Cause** | Access Control Issue — privileged withdrawal function missing `onlyOwner` guard, callable by any address |
| **Attack Tx** | `0x6b04344d5627df59d3bc645e7454f4605a90272852a91e435e370376643353b3` |
| **Reference** | [exvulsec on X](https://x.com/exvulsec/status/2049156204757446960) |

---

## 1. Vulnerability Overview

Ycdeal3 is a DeFi protocol on Ethereum. The protocol contract exposed a privileged function — such as `emergencyWithdraw`, `sweep`, or an equivalent administrative drain — that lacked any access control modifier. Because the function was declared `external` without `onlyOwner` or an equivalent role check, any Ethereum address could invoke it and redirect the contract's token holdings to themselves.

Missing access control on admin-level fund-movement functions is one of the most consistently exploited vulnerability classes in DeFi. The attack requires no flash loan, no complex setup, and no upfront capital: the attacker simply calls the unprotected function with themselves as the recipient. The full ~$398K balance was drained in a single transaction, demonstrating how a single missing modifier can result in total loss of protocol funds.

## 2. Vulnerable Code Analysis

```solidity
// VULNERABLE — no access control
function emergencyWithdraw(address token, uint256 amount) external {
    // BUG: any caller can invoke this and receive protocol funds
    IERC20(token).transfer(msg.sender, amount);
}

// FIXED — restrict to contract owner
function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
    // Only the owner can withdraw; funds go to owner(), not an arbitrary caller
    IERC20(token).transfer(owner(), amount);
}
```

The fix requires a single modifier. OpenZeppelin's `Ownable` (or `AccessControl` for multi-role setups) provides this out of the box. All privileged state-changing and fund-movement functions must declare their authorization at the type level so static analysis tools and auditors can identify coverage gaps.

## 3. Attack Flow

1. Attacker discovers the unprotected `emergencyWithdraw` (or equivalent) function via Etherscan source code inspection or bytecode analysis.
2. Attacker checks the Ycdeal3 contract's token balances to confirm available funds (~$398K).
3. Attacker sends a transaction calling the unprotected function, passing their own address as the recipient parameter.
4. The contract executes `IERC20(token).transfer(attacker, amount)` without any authorization check.
5. ~$398K in tokens are transferred to the attacker's address in a single call.
6. Attacker swaps or bridges the proceeds.

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Access Control — Missing Authorization on Privileged Function |
| **Severity** | Critical |
| **CWE** | CWE-284 (Improper Access Control) |

## 5. Remediation Recommendations

- Apply `onlyOwner` (OpenZeppelin `Ownable`) or `onlyRole(ADMIN_ROLE)` (OpenZeppelin `AccessControl`) to every function that moves funds, mints tokens, or changes protocol parameters.
- Run Slither's `unprotected-upgrade`, `suicidal`, and `arbitrary-send-erc20` detectors as part of CI/CD; these patterns are machine-detectable before deployment.
- For emergency functions specifically, prefer a time-locked multisig as the owner so that even a compromised owner key cannot drain funds instantly.

## References

- [exvulsec — X post](https://x.com/exvulsec/status/2049156204757446960)
- [Etherscan — Attack Tx](https://etherscan.io/tx/0x6b04344d5627df59d3bc645e7454f4605a90272852a91e435e370376643353b3)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
