# MIM Spell — Flash Loan Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-16 |
| **Protocol** | MIM Spell (Abracadabra) |
| **Chain** | Ethereum |
| **Loss** | ~17K USD |
| **Attacker** | [0x9d4fd681...](https://etherscan.io/address/0x9d4fd681aacbc49d79c6405c9aa70d1afd5accf3) |
| **Attack Contract** | [0x26fe8475...](https://etherscan.io/address/0x26fe84754a1967d67b7befaa01b10d7b35bbaf0a) |
| **Attack Tx** | [0x2c9f87e2...](https://etherscan.io/tx/0x2c9f87e285026601a2c8903cf5f10e5b3655fbd0264490c41514ce073c42a9c3) |
| **Vulnerable Contract** | [0xa5564a2d...](https://etherscan.io/address/0xa5564a2d1190a141cac438c9fde686ac48a18a79) |
| **Root Cause** | Inflating collateral value via DegenBox vault share price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/MIMSpell_exp.sol) |

---
## 1. Vulnerability Overview

The DegenBox vault in MIM Spell (Abracadabra) relies on spot balances for share price calculation, making it manipulable. The attacker directly transferred tokens into DegenBox to artificially inflate the asset-per-share ratio, then over-borrowed MIM against the inflated collateral value.

## 2. Vulnerable Code Analysis

```solidity
// ❌ DegenBox: share price based on spot balance
interface IDegenBox {
    function deposit(address token_, address from, address to, uint256 amount, uint256 share)
        external returns (uint256 amountOut, uint256 shareOut);

    // ❌ toShare/toAmount rely on current balance
    function toShare(address token, uint256 amount, bool roundUp) external view returns (uint256 share);
    function toAmount(address token, uint256 share, bool roundUp) external view returns (uint256 amount);
}

// Vulnerable share calculation
function toShare(address token, uint256 amount, bool roundUp) external view returns (uint256 share) {
    Rebase memory total = totals[token];
    // ❌ total.elastic can be increased via direct transfer
    share = amount * total.base / total.elastic;
}
```

### On-chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Inflating collateral value via DegenBox vault share price manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌─────────────────────────────────────────────┐
│  1. Borrow large amount of tokens via        │
│     flash loan                               │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  2. Directly transfer tokens into DegenBox  │
│     → total.elastic increases → share price │
│     spikes                                  │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  3. Inflate collateral value using           │
│     manipulated share price                  │
│  4. Execute over-borrowing of MIM           │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  5. Sell borrowed MIM + repay flash loan    │
│     + pocket profit                          │
└─────────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // 1. Borrow tokens via flash loan
    // 2. Manipulate share price via direct transfer into DegenBox
    token.transfer(address(degenBox), inflateAmount);

    // 3. Deposit collateral at manipulated price → inflated value recognized
    degenBox.deposit(address(token), address(this), address(this), collateralAmount, 0);

    // 4. Over-borrow MIM
    cauldron.borrow(address(this), borrowAmount);

    // 5. Sell MIM + repay + pocket profit
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Vault share price manipulation | CRITICAL | CWE-682 | 04_oracle_manipulation.md |
| V-02 | Balance manipulation via direct transfer | HIGH | CWE-664 | 16_accounting_sync.md |

## 6. Remediation Recommendations

### Immediate Mitigation
```solidity
// ✅ Prevent direct transfer: track balance changes
uint256 expectedBalance = totalDeposited;
require(token.balanceOf(address(this)) == expectedBalance, "Unexpected balance");
```

### Structural Improvements
| Vulnerability | Recommended Action |
|--------|-----------|
| Share price manipulation | Price validation via external oracle |
| Direct transfer | Ignore balance changes outside the deposit function |

## 7. Lessons Learned

In ERC-4626 and similar vault architectures, if `totalAssets()` depends on `balanceOf(address(this))`, it can be manipulated via direct transfers. This vulnerability is analogous to the `donateToReserves` pattern found in Compound V2 cTokens.