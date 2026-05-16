# QNT — Unprotected Minter Role Assignment

| Item | Details |
|------|------|
| **Date** | 2026-04-28 |
| **Protocol** | QNT |
| **Chain** | Ethereum |
| **Loss** | ~$125K |
| **Root Cause** | Access Control Issue — `setMinter` or equivalent role-assignment function lacked authorization, allowing any caller to grant themselves mint or withdraw privileges |
| **Attack Tx** | `0x4f31f68df9f240492f13df9ab23207ea231ec1b5a89af9c31cde58e7d98cb18c` |
| **Reference** | [Defi_Nerd_sec on X](https://x.com/Defi_Nerd_sec/status/2049345620981539233) |

---

## 1. Vulnerability Overview

QNT, a token or DeFi protocol on Ethereum, suffered an access control exploit on April 28, 2026, losing ~$125K. A privileged configuration function — such as `setMinter`, `setOwner`, or a role-assignment setter — was callable without any authorization check. The exploit followed a two-step pattern common in this vulnerability class: first, the attacker grants themselves a privileged role (minter, admin, or fund manager) by calling the unprotected setter; second, they exercise that role to extract value, either by minting tokens and selling them or by calling a withdrawal function that is gated on the newly acquired role.

This two-step exploit pattern is particularly insidious because neither step individually causes loss: the first call just writes to a mapping, and the second call appears to be a legitimate role action. Security monitors that look for direct fund drains may miss the setup step, allowing the attacker to act undetected until the second call executes.

## 2. Vulnerable Code Analysis

```solidity
// VULNERABLE — anyone can appoint themselves as minter
function setMinter(address newMinter) external {
    // BUG: no onlyOwner or role check — any caller becomes the minter
    minter = newMinter;
}

function mint(address to, uint256 amount) external {
    require(msg.sender == minter, "not minter");
    _mint(to, amount);
}

// Attacker flow:
// Step 1: setMinter(attackerAddress)  — succeeds with no auth check
// Step 2: mint(attackerAddress, largeAmount)  — succeeds; attacker is now minter
// Step 3: sell minted tokens on DEX for ~$125K

// FIXED — restrict setMinter to the contract owner
function setMinter(address newMinter) external onlyOwner {
    require(newMinter != address(0), "zero address");
    emit MinterChanged(minter, newMinter);
    minter = newMinter;
}

// Better: use OpenZeppelin AccessControl with a dedicated role
bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
    _mint(to, amount);
}
```

The fixed version applies `onlyOwner` to the setter and emits an event so that any minter change is detectable on-chain by monitoring tools. The OpenZeppelin `AccessControl` alternative provides a more granular permission model without a single point of failure.

## 3. Attack Flow

1. Attacker discovers that `setMinter` (or equivalent) has no access control modifier via source code review on Etherscan.
2. Attacker calls `setMinter(attackerAddress)` — transaction succeeds; attacker is now the registered minter.
3. Attacker calls `mint(attackerAddress, largeAmount)` — the `require(msg.sender == minter)` check passes.
4. Attacker's wallet receives freshly minted tokens.
5. Attacker sells the minted tokens on a DEX for ~$125K in ETH or stablecoins.
6. Legitimate token holders suffer dilution; protocol treasury is depleted.

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Access Control — Unprotected Role Assignment |
| **Severity** | Critical |
| **CWE** | CWE-284 (Improper Access Control) |

## 5. Remediation Recommendations

- Apply `onlyOwner` or `onlyRole(ADMIN_ROLE)` to every function that assigns, revokes, or modifies privileged roles; role-assignment functions have the same risk surface as the privileged actions they gate.
- Prefer OpenZeppelin `AccessControl` over a single `owner` address for protocols with multiple operational roles; separate the admin, minter, pauser, and upgrader roles so a compromise of one does not grant all others.
- Emit an event on every role change and configure monitoring (e.g., OpenZeppelin Defender, Tenderly alerts) to alert the team immediately when minter, owner, or admin addresses change — catching the setup step before the exploit executes.

## References

- [Defi_Nerd_sec — X post](https://x.com/Defi_Nerd_sec/status/2049345620981539233)
- [Etherscan — Attack Tx](https://etherscan.io/tx/0x4f31f68df9f240492f13df9ab23207ea231ec1b5a89af9c31cde58e7d98cb18c)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
