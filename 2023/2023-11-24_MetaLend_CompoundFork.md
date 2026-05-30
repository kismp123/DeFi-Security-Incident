# MetaLend — Compound Fork Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-24 |
| **Protocol** | MetaLend |
| **Chain** | Ethereum |
| **Loss** | ~$4K |
| **Attacker** | [0x0c06340f5024c114...](https://etherscan.io/address/0x0c06340f5024c114fe196fcb38e42d20ab00f6eb) |
| **Attack Tx** | [0x4c684fb2618c2974...](https://etherscan.io/tx/0x4c684fb2618c29743531dec9253ede1b757bda0b323dc2f305e3b50ab1773da7) |
| **Vulnerable Contract** | [0x5578f2e245e932a5...](https://etherscan.io/address/0x5578f2e245e932a599c46215a0ca88707230f17b) |
| **Root Cause** | Donation attack against an empty Compound fork market |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/MetaLend_exp.sol) |

---
## 1. Vulnerability Overview
MetaLend suffered a $4K loss via the same Compound fork donation attack pattern. Although small in scale, it is a repeat of the identical attack vector.

---
## 2. Vulnerable Code Analysis (❌/✅ Comments)
```solidity
// ❌ Same pattern: balanceOf-based rate
function getCash() public view returns (uint256) {
    return underlying.balanceOf(address(this)); // ❌
}
// ✅ Use internal variable instead
```

### On-Chain Source Code

> ⚠️ Contract not verified on Sourcify or Etherscan — source unavailable; reconstructed from PoC.

Source: **not verified on Sourcify or Etherscan** — `0x5578f2e245e932a599c46215a0ca88707230f17b` (Ethereum, chainid 1)
Sourcify URL: https://sourcify.dev/server/files/any/1/0x5578f2e245e932a599c46215a0ca88707230f17b (404 — not found); Etherscan V2 API also returns empty source.

MetaLend is an unverified Compound fork. The donation attack pattern is structurally identical across all Compound v2 forks. The following is reconstructed from the Compound v2 reference implementation and the PoC ([MetaLend_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/MetaLend_exp.sol)):

```solidity
// ⚠️ RECONSTRUCTED — not verified source. Based on Compound v2 pattern + PoC trace.
// CToken (MetaLend fork): 0x5578f2e245e932a599c46215a0ca88707230f17b (Ethereum)

contract CToken {
    IERC20 public underlying;
    uint256 public totalSupply;      // shares (cTokens) outstanding

    // ❌ getCash() reads token balance directly from the ERC-20 contract
    // Anyone can inflate this by sending tokens directly to this contract address
    function getCash() public view returns (uint256) {
        return underlying.balanceOf(address(this)); // ❌ manipulable via direct transfer
    }

    // Exchange rate = (cash + totalBorrows - totalReserves) / totalSupply
    // When totalSupply is 1 (1 wei deposited), a large direct transfer inflates cash:
    // exchangeRate = (1_donation + 1_wei) / 1 = 1_donation + 1 ← enormous
    function exchangeRateStoredInternal() internal view returns (uint256) {
        if (totalSupply == 0) {
            return initialExchangeRateMantissa;
        }
        // ❌ getCash() is the attack vector — inflated by direct ERC-20 transfer
        uint256 cashPlusBorrowsMinusReserves = getCash() + totalBorrows - totalReserves; // ❌
        return cashPlusBorrowsMinusReserves * expScale / totalSupply;
    }

    // Borrow checks that the borrower has sufficient collateral at the current exchange rate
    function borrowInternal(uint256 borrowAmount) internal {
        // collateral value = cToken balance * exchangeRate (now massively inflated)
        // ❌ attacker's 1-wei cToken deposit appears worth billions after donation
        uint256 accountLiquidity = getAccountLiquidity(msg.sender); // ❌ inflated
        require(accountLiquidity >= borrowAmount, "insufficient liquidity");
        doTransferOut(msg.sender, borrowAmount);
    }
}
```

**Why it is exploitable (identify the bug from the code):**
- `getCash()` returns `underlying.balanceOf(address(this))` — any direct ERC-20 transfer to the cToken contract address inflates this value without minting any cTokens.
- The attacker mints 1 wei of cTokens (establishing `totalSupply = 1`), then directly transfers a large amount of the underlying token to the cToken contract.
- `exchangeRateStoredInternal()` now computes `(1_donation_amount) / 1 = 1_donation_amount` — 1 wei of cToken appears to back the full donated amount.
- The attacker borrows against this inflated collateral value, draining the market.

```solidity
// ✅ Fix: track cash with an internal accounting variable, never read balanceOf()
uint256 internal _cash; // incremented on mint/repay, decremented on borrow/redeem

function getCash() public view returns (uint256) {
    return _cash; // ✅ immune to direct token transfers
}
// Also: seed the market with protocol-owned liquidity at deployment so totalSupply > 0
// and exchangeRate starts at a safe value, making the inflation attack uneconomical.
```

---
## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Deposit 1 wei into empty market
  ├─② Manipulate exchange rate via direct transfer
  └─③ Borrow inflated amount
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
cToken.mint(1);
underlying.transfer(address(cToken), giftAmount);
cToken.borrow(inflatedAmount);
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Donation Attack |
| Severity | Medium |

---
## 6. Remediation Recommendations
1. Use an internal cash-tracking variable
2. Review the security patch checklist when forking Compound

---
## 7. Lessons Learned
Throughout 2023, the same Compound donation attack was repeated dozens of times. Any fork must patch this vulnerability before deployment.