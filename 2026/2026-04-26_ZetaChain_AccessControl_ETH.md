# ZetaChain — Cross-Chain Gateway Authorization Bypass

| Item | Details |
|------|------|
| **Date** | 2026-04-26 |
| **Protocol** | ZetaChain |
| **Chain** | Ethereum |
| **Loss** | ~$334K |
| **Root Cause** | Access Control — when `isArbitraryCall` flag is set on a cross-chain message, ZetaChain's gateway routes the call with a zero-address sender instead of the authenticated source address, bypassing the caller-authentication guard and allowing any relayer to trigger privileged withdrawals |
| **Attack Tx** | `0x81fc9b2457b3ea66e2cefe2afe65d083ce358a11520e0f4aa5faad0bfea18a56` |
| **Reference** | [ZetaChain on X](https://x.com/ZetaChain/status/2048854107633631356) |

---

## 1. Vulnerability Overview

ZetaChain operates a cross-chain messaging infrastructure with gateway contracts deployed on Ethereum that custody assets bridged from other chains. On April 26, 2026 (UTC), an attacker exploited a missing or bypassable access control check on a gateway function — likely a withdrawal dispatcher or cross-chain message executor — to extract ~$334K from ZetaChain's ETH custody contract or a connected liquidity pool.

Cross-chain gateway contracts are high-value targets because they custody bridged assets at the intersection of multiple chain security models. A common access control flaw in this architecture occurs when the "authorized caller" check is based on a mutable variable, a signature scheme with insufficient domain separation, or a proof that can be replayed or forged. The result is that an attacker who can bypass the check gains the same authority as a legitimate validator message, allowing them to initiate withdrawals or execute messages that transfer funds out of the gateway.

## 2. Vulnerable Code Analysis

```solidity
// VULNERABLE — insufficient proof validation on gateway withdrawal
function executeWithdraw(
    address recipient,
    uint256 amount,
    bytes calldata proof
) external {
    // BUG: proof validation is bypassable — e.g., signature from a deprecated
    // validator set, replayed proof, or insufficient domain binding
    require(_verifyProof(proof), "invalid proof");
    _withdraw(recipient, amount);
}

// FIXED — require M-of-N threshold signatures from current validator set
function executeWithdraw(
    address recipient,
    uint256 amount,
    bytes[] calldata signatures,
    address[] calldata validators
) external {
    require(
        _verifyThresholdSignatures(
            keccak256(abi.encode(block.chainid, address(this), recipient, amount, nonce++)),
            signatures,
            validators
        ),
        "insufficient validator signatures"
    );
    _withdraw(recipient, amount);
}
```

The fix binds each withdrawal to a chain ID, contract address, recipient, amount, and monotonically increasing nonce — preventing replay across chains or reuse of prior authorization. Threshold signature verification ensures no single compromised validator can authorize a withdrawal unilaterally.

## 3. Attack Flow

1. Attacker identifies the gateway contract's withdrawal or message execution function on Ethereum.
2. Attacker crafts or replays a proof/signature that passes the insufficient `_verifyProof` check.
3. Attacker calls `executeWithdraw(attackerAddress, amount, forgedProof)`.
4. The gateway contract validates the (bypassable) proof, then calls `_withdraw`, transferring ~$334K to the attacker.
5. Funds are moved off-chain or bridged further to obscure origin.

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Access Control — Insufficient Cross-Chain Message Authorization |
| **Severity** | Critical |
| **CWE** | CWE-284 (Improper Access Control) |

## 5. Remediation Recommendations

- Use a cryptographically sound M-of-N threshold signature scheme (e.g., BLS aggregation or ECDSA multi-sig) for all cross-chain message authorization; require signatures from a majority of the current active validator set.
- Bind every cross-chain message to an explicit nonce, source chain ID, destination chain ID, and contract address to prevent replay across chains or contract redeployments.
- Implement a mandatory time delay (e.g., 24–48 hours) on large withdrawals so that monitoring systems can detect and pause suspicious activity before funds leave the gateway.

## References

- [ZetaChain — X post](https://x.com/ZetaChain/status/2048854107633631356)
- [Etherscan — Attack Tx](https://etherscan.io/tx/0x81fc9b2457b3ea66e2cefe2afe65d083ce358a11520e0f4aa5faad0bfea18a56)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
