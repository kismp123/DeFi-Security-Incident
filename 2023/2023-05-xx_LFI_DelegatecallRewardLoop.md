# LFI / VLFI Exploit — Unsafe delegatecall in claimRewards() Loops 200 Times

## Metadata
| Field | Value |
|---|---|
| Date | 2023-05 |
| Project | LFI / VLFI |
| Chain | Polygon |
| Loss | ~$36,000 |
| Attacker | 0x11576cb3d8d6328cf319e85b10e09a228e84a8de |
| Attack TX | Address unconfirmed |
| Vulnerable Contract | VLFI: 0xfc604b6fD73a1bc60d31be111F798dd0D4137812 |
| Block | 43,025,776 |
| CWE | CWE-284 (Improper Access Control — unsafe delegatecall) |
| Vulnerability Type | Unsafe delegatecall in Claimer.delegate() Enables Repeated claimRewards() |

## Summary
VLFI staking allowed users to `stake()` LFI on behalf of another address. The attacker staked LFI on behalf of a `Claimer` contract, then executed 200 iterations where each call to `Claimer.delegate()` used `delegatecall` to invoke `claimReward()` in VLFI's context, claiming rewards repeatedly without the staking or lockup period requirement.

## Vulnerability Details
- **CWE-284**: `VLFI.claimRewards(address to)` was callable via `delegatecall` from `Claimer.delegate()`. Because `delegatecall` executes in the caller's storage context but the callee's code, the reward claim bypassed msg.sender checks — each iteration created a new `Claimer` instance and harvested rewards before the previous claim was recorded.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ERC1967Upgrade.sol
import "../../utils/Address.sol";  // ❌

// ...

 * @custom:oz-upgrades-unsafe-allow delegatecall  // ❌

// ...

     * @dev Storage slot with the address of the current implementation.  // ❌

// ...

    event Upgraded(address indexed implementation);  // ❌

// ...

     * @dev Returns the current implementation address.  // ❌
```

```solidity
// File: TransparentUpgradeableProxy.sol
    function implementation() external ifAdmin returns (address implementation_) {  // ❌
        implementation_ = _implementation();
    }

// ...

    function changeAdmin(address newAdmin) external virtual ifAdmin {  // ❌
        _changeAdmin(newAdmin);
    }

// ...

    function upgradeTo(address newImplementation) external ifAdmin {  // ❌
        _upgradeToAndCall(newImplementation, bytes(""), false);
    }

// ...

    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable ifAdmin {  // ❌
        _upgradeToAndCall(newImplementation, data, true);
    }

// ...

    function _admin() internal view virtual returns (address) {  // ❌
        return _getAdmin();
    }
```

```solidity
// File: Proxy.sol
     * @dev This is a virtual function that should be overriden so it returns the address to which the fallback function  // ❌

// ...

    function _implementation() internal view virtual returns (address);  // ❌

// ...

     * This function does not return to its internall call site, it will return directly to the external caller.  // ❌

// ...

     * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if no other  // ❌

// ...

     * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if call data  // ❌
```

```solidity
// File: ProxyAdmin.sol
    function getProxyImplementation(TransparentUpgradeableProxy proxy) public view virtual returns (address) {  // ❌
        // We need to manually run the static call since the getter cannot be flagged as view
        // bytes4(keccak256("implementation()")) == 0x5c60da1b
        (bool success, bytes memory returndata) = address(proxy).staticcall(hex"5c60da1b");  // ❌
        require(success);
        return abi.decode(returndata, (address));  // ❌
    }

// ...

    function getProxyAdmin(TransparentUpgradeableProxy proxy) public view virtual returns (address) {  // ❌
        // We need to manually run the static call since the getter cannot be flagged as view
        // bytes4(keccak256("admin()")) == 0xf851a440
        (bool success, bytes memory returndata) = address(proxy).staticcall(hex"f851a440");  // ❌
        require(success);
        return abi.decode(returndata, (address));  // ❌
    }

// ...

    function changeProxyAdmin(TransparentUpgradeableProxy proxy, address newAdmin) public virtual onlyOwner {  // ❌
        proxy.changeAdmin(newAdmin);
    }

// ...

    function upgrade(TransparentUpgradeableProxy proxy, address implementation) public virtual onlyOwner {  // ❌
        proxy.upgradeTo(implementation);
    }

// ...

    function upgradeAndCall(TransparentUpgradeableProxy proxy, address implementation, bytes memory data) public payable virtual onlyOwner {  // ❌
        proxy.upgradeToAndCall{value: msg.value}(implementation, data);
    }
```

## Attack Flow (from testExploit())
```solidity
// 1. Allocate 86,000 LFI to test contract
// 2. LFI.approve(address(VLFI), 86_000e18)
// 3. VLFI.stake(address(claimer), 86_000e18)
//    → stake LFI on behalf of Claimer contract
// 4. for (uint i = 0; i < 200; i++) {
//       claimer.delegate()
//       → delegatecall to VLFI.claimRewards(address(this))
//       → claims rewards in VLFI context
//       newClaimer = new Claimer(address(VLFI))
//       claimer = newClaimer
//    }
// 5. Collect all harvested LFI rewards
```

## Interfaces from PoC
```solidity
interface IVLFI is IERC20 {
    function claimRewards(address to) external;
    function stake(address onBehalfOf, uint256 amount) external;
}
```

## Key Addresses
| Label | Address |
|---|---|
| LFI Token | 0x77D97db5615dFE8a2D16b38EAa3f8f34524a0a74 |
| VLFI (Vulnerable) | 0xfc604b6fD73a1bc60d31be111F798dd0D4137812 |
| Attack Contract | 0x43623b96936e854f8d85f893011f22ac91e58164 |
| Attacker EOA | 0x11576cb3d8d6328cf319e85b10e09a228e84a8de |

## Root Cause
`claimRewards()` could be reached via `delegatecall` from external Claimer contracts, bypassing per-address claim tracking. No check prevented claiming rewards multiple times within a single transaction or from freshly deployed Claimer contracts.

## Fix
```solidity
// Track claims per address per epoch and validate caller:
mapping(address => uint256) public lastClaimEpoch;

function claimRewards(address to) external {
    require(msg.sender == to || msg.sender == owner, "Unauthorized");
    require(lastClaimEpoch[to] < currentEpoch(), "Already claimed this epoch");
    lastClaimEpoch[to] = currentEpoch();
    uint256 pending = pendingRewards(to);
    require(pending > 0, "No rewards");
    IERC20(lfi).safeTransfer(to, pending);
}
```

## References
- Polygon block 43,025,776
- VLFI: 0xfc604b6fD73a1bc60d31be111F798dd0D4137812