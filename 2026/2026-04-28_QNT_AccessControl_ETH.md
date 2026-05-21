# QNT — EIP-7702 BatchExecutor Permissionless Drain

| Item | Details |
|------|------|
| **Date** | 2026-04-28 (SlowMist reports 2026-04-29; TX resolves ambiguity) |
| **Protocol** | QNT (reserve pool on Ethereum) |
| **Chain** | Ethereum |
| **Loss** | ~$125K (~1,988.5 QNT ≈ 54.93 ETH) |
| **Root Cause** | EIP-7702 misconfiguration (Pectra upgrade) — admin EOA delegated code to a `BatchExecutor` contract, but `BatchExecutor` designated a permissionless `BatchCall` contract as its authorized caller; `BatchCall.batch()` had no permission checks, allowing any address to execute arbitrary calls through the admin's delegated code context |
| **Attack Tx** | [0x4f31f68d...b18c](https://etherscan.io/tx/0x4f31f68df9f240492f13df9ab23207ea231ec1b5a89af9c31cde58e7d98cb18c) |
| **Reference** | [Defi_Nerd_sec on X](https://x.com/Defi_Nerd_sec/status/2049345620981539233), [CryptoTimes](https://www.cryptotimes.io/2026/04/29/eip-7702-flaw-drains-1988-qnt-from-ethereum-pool/) |

---

## 1. Vulnerability Overview

QNT suffered an access control exploit on April 28–29, 2026, losing ~$125K (~1,988.5 QNT). The root cause was a **EIP-7702 (Pectra upgrade) misconfiguration** — one of a wave of similar exploits immediately following Ethereum's Pectra hardfork, which introduced EIP-7702 account delegation.

The QNT protocol's admin EOA used EIP-7702 to delegate its account to a `BatchExecutor` contract, intending to enable atomic multi-call operations. However, `BatchExecutor` was configured with a permissionless `BatchCall` contract as its authorized caller, and `BatchCall.batch()` contained no access control check — any Ethereum address could invoke it. Since `BatchCall.batch()` executed calls through the admin's EIP-7702 delegated code context, the attacker could craft calldata to execute `transferFrom(reservePool, attacker, balance)` and drain QNT tokens from the pool.

## 2. Vulnerable Code Analysis

```solidity
// EIP-7702 delegation: admin EOA delegates to BatchExecutor
// (set via EIP-7702 authorization in Pectra)

// BatchExecutor — intended for admin-only batch ops
contract BatchExecutor {
    address public authorizedCaller; // set to BatchCall contract

    function execute(Call[] calldata calls) external {
        require(msg.sender == authorizedCaller); // checks BatchCall, not admin EOA
        for (uint i = 0; i < calls.length; i++) {
            (bool success,) = calls[i].target.call(calls[i].data);
            require(success);
        }
    }
}

// ❌ VULNERABLE — BatchCall has no access control
contract BatchCall {
    function batch(address executor, Call[] calldata calls) external {
        // BUG: no msg.sender check — anyone can call this
        IBatchExecutor(executor).execute(calls);
        // executor runs in admin EOA's delegated context via EIP-7702
    }
}

// Attacker flow:
// Step 1: Call BatchCall.batch(adminBatchExecutor, [{target: QNTtoken, data: transferFrom(...)}])
// Step 2: BatchCall calls BatchExecutor.execute() — passes auth check (BatchCall == authorizedCaller)
// Step 3: BatchExecutor executes transferFrom in admin EOA's delegated context
// Step 4: QNT tokens drained from reserve pool

// FIXED — add access control to BatchCall.batch()
contract BatchCall {
    mapping(address => bool) public authorizedAdmins;

    function batch(address executor, Call[] calldata calls) external {
        require(authorizedAdmins[msg.sender], "not authorized");
        IBatchExecutor(executor).execute(calls);
    }
}
```

## 3. Attack Flow

1. Attacker identifies admin EOA's EIP-7702 delegation on-chain, noting `BatchExecutor` as the delegated code.
2. Attacker inspects `BatchCall.batch()` and discovers it lacks any access control.
3. Attacker calls `BatchCall.batch(adminBatchExecutor, [{target: QNTToken, data: transferFrom(pool, attacker, 1988.5e18)}])`.
4. `BatchCall` forwards the call to `BatchExecutor.execute()` — passes the `authorizedCaller` check.
5. `BatchExecutor` executes `transferFrom` within the admin EOA's EIP-7702 delegated context, draining 1,988.5 QNT (~$125K) from the reserve pool.

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | EIP-7702 Misconfiguration / Access Control |
| **Severity** | Critical |
| **CWE** | CWE-284 (Improper Access Control) |
| **Context** | Post-Pectra EIP-7702 exploitation wave (April–May 2026) — see also Turing NOBEL (2026-03-26) |

## 5. Remediation Recommendations

- **Validate EIP-7702 delegated code**: when delegating an EOA to a contract, ensure every entry point in the delegated code is gated on the original EOA owner, not an intermediary contract that can be freely called by anyone.
- **Audit the full call chain**: `BatchCall → BatchExecutor` appears to have two access checks but effectively has only one — the outer gate was unprotected.
- **Prefer tightly scoped delegations**: EIP-7702 delegations should only expose the minimum required operations; general-purpose batch executors are high-risk.
- **Monitor EIP-7702 delegations**: add on-chain monitoring for new delegations involving privileged EOAs.

## References

- [Defi_Nerd_sec — X post](https://x.com/Defi_Nerd_sec/status/2049345620981539233)
- [CryptoTimes — EIP-7702 flaw drains 1,988 QNT](https://www.cryptotimes.io/2026/04/29/eip-7702-flaw-drains-1988-qnt-from-ethereum-pool/)
- [Etherscan — Attack Tx](https://etherscan.io/tx/0x4f31f68df9f240492f13df9ab23207ea231ec1b5a89af9c31cde58e7d98cb18c)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
