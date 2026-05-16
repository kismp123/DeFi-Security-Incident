# DeXe DAO — Multi-Step Access Control Exploit on BSC (~$640K)

| Item | Details |
|------|------|
| **Date** | 2024-12-10 |
| **Protocol** | DeXe DAO (BSC) |
| **Chain** | BNB Smart Chain |
| **Loss** | ~$640K |
| **Root Cause** | Access Control Issue — multi-step exploit contract (`step3()`) exploited an unprotected privileged function in DeXe DAO governance or treasury contracts, draining approximately $640K in tokens |
| **Attack Tx** | [`0xc96287cadfc96afd715ffeae25fd07b19d3c06b83dff54ffd7ad4633882d7b24`](https://bscscan.com/tx/0xc96287cadfc96afd715ffeae25fd07b19d3c06b83dff54ffd7ad4633882d7b24) |
| **Attacker** | `0x71DECBFC8BE353C56052b04b44Fcea2227FF1876` (labeled "DeXe DAO exploiter1" on BSCScan) |
| **Reference** | [Phalcon_xyz on X](https://x.com/Phalcon_xyz/status/1866392519895847183) |

---

## 1. Vulnerability Overview

On December 10, 2024, the DeXe DAO protocol on BNB Smart Chain suffered an access control exploit resulting in approximately $640K in losses. BSCScan labels the attacker address (`0x71DECBFC8BE353C56052b04b44Fcea2227FF1876`) as **"DeXe DAO exploiter1"**, directly identifying the targeted protocol.

The on-chain attack transaction calls `step3()` (method ID `0xdf4ec249`) on an attacker-deployed exploit contract at `0x31aBe92D7f6E8549B637b186F4839d5D4d7b8e0e`. The structured `step1/step2/step3` naming pattern indicates a deliberate multi-step exploit sequence, where each step stages the next phase of the attack — a common pattern when the exploit requires multiple contract interactions to circumvent authorization checks, build up state, or drain funds across multiple assets.

The attack involved transfers of 37,778 WBNB and multiple BSC tokens (GRANAN, GRA, TAPE, FLOK, GM, VALGRA). The specific access control vulnerability in DeXe DAO's smart contracts enabled the attacker to trigger unauthorized fund movements without holding the required governance role or admin credentials.

---

## 2. Vulnerable Code Analysis

### Multi-Step Exploit Pattern (Reconstructed)

```solidity
// Attacker-deployed exploit contract (0x31aBe92D7f6E8549B637b186F4839d5D4d7b8e0e)
// step3() is the final drain step — earlier steps stage the attack

contract DeXeExploit {
    address constant DEXE_DAO = 0x...;      // DeXe governance/treasury contract
    address constant DEXE_TOKEN = 0x...;    // DeXe token contract

    // step1: sets up state — e.g., obtains flash loan, registers exploiter as delegate
    function step1() external { ... }

    // step2: intermediate preparation — e.g., triggers proposal execution, sets allowances
    function step2() external { ... }

    // step3: final drain — calls the unprotected withdrawal/distribution function
    function step3() external {
        // BUG: DeXe DAO's privileged function (e.g., distributeRewards, emergencyWithdraw,
        // or executeProposal) lacks proper access control, allowing any caller to invoke it.
        IDeXeDAO(DEXE_DAO).privilegedWithdraw(address(this), type(uint256).max);
        // OR: exploits a flash-loan-powered governance vote executed atomically
    }
}
```

### Access Control Flaw in Governance/Treasury (Generic Pattern)

```solidity
// VULNERABLE — DeXe DAO treasury/reward function (reconstructed)
function distributeRewards(address recipient, uint256 amount) external {
    // BUG: missing role check — should require governorRole or multisig approval
    // Any caller can trigger reward distribution to themselves
    rewardToken.transfer(recipient, amount);
}

// FIXED
function distributeRewards(address recipient, uint256 amount)
    external
    onlyRole(GOVERNOR_ROLE)  // require governance approval
{
    require(amount <= pendingRewards[recipient], "exceeds entitlement");
    pendingRewards[recipient] -= amount;
    rewardToken.transfer(recipient, amount);
}
```

---

## 3. Attack Flow

```
Attacker (0x71DECBFC... — "DeXe DAO exploiter1")
  │
  ├─[step1 tx] Stage 1: acquire flash loan / manipulate governance state
  │
  ├─[step2 tx] Stage 2: prepare exploit state (allowances, proposal, delegation)
  │
  ├─[step3 tx — 0xc96287ca...]
  │   Call step3() on exploit contract 0x31aBe92D7f6E8549B637b186F4839d5D4d7b8e0e
  │   ↓ exploit contract calls DeXe DAO privileged function without authorization
  │   ↓ WBNB + GRANAN/GRA/TAPE/FLOK/GM/VALGRA tokens drained
  │   Block 44,743,004 — Dec 10, 2024 05:52:11 UTC
  │
  └─[Result] ~$640K extracted across multiple token types
             Funds moved through PancakeSwap and dispersed
```

---

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Access Control — Missing Authorization on Privileged DAO/Treasury Function |
| **Severity** | Critical |
| **CWE** | CWE-284 (Improper Access Control) |
| **Protocol** | DeXe DAO (confirmed via BSCScan attacker label) |
| **Attack Pattern** | Multi-step structured exploit (`step1/step2/step3`) |

---

## 5. Remediation Recommendations

- Apply role-based access control (`onlyRole(GOVERNOR_ROLE)`) to all functions that move tokens, execute proposals, or modify governance parameters. No fund-movement function should be publicly callable without explicit authorization.
- Require time-locks on governance proposal execution: flash-loan-amplified governance attacks are only possible when proposals can be created and executed within a single transaction or block. A minimum 24–48 hour time-lock prevents same-block execution.
- Monitor and alert on any call to privileged functions from non-whitelisted addresses. An anomaly detection system should have flagged `step3()` being called from a newly deployed contract.
- Publish and verify all contract source code on BscScan before receiving user funds. Source availability enables community auditing and earlier detection of access control gaps.
- Conduct regular third-party security audits of governance and treasury contracts, particularly after upgrades or parameter changes.

---

## References

- [Phalcon_xyz — X post](https://x.com/Phalcon_xyz/status/1866392519895847183)
- [BscScan — Attack Tx](https://bscscan.com/tx/0xc96287cadfc96afd715ffeae25fd07b19d3c06b83dff54ffd7ad4633882d7b24)
- [BSCScan — Attacker address (labeled "DeXe DAO exploiter1")](https://bscscan.com/address/0x71DECBFC8BE353C56052b04b44Fcea2227FF1876)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
