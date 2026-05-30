# KR Token — Token Sell Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-08 |
| **Protocol** | KR Token |
| **Chain** | BSC |
| **Loss** | ~5 ETH |
| **Attacker** | [0x835b45d38cbdccf9...](https://bscscan.com/address/0x835b45d38cbdccf99e609436ff38e31ac05bc502) |
| **Attack Tx** | [0x2abf871eb91d03bc...](https://bscscan.com/tx/0x2abf871eb91d03bc8145bf2a415e79132a103ae9f2b5bbf18b8342ea9207ccd7) |
| **Vulnerable Contract** | [0x15b1ed79ca9d7955...](https://bscscan.com/address/0x15b1ed79ca9d7955af3e169d7b323c4f1eeb5d12) |
| **Root Cause** | Price calculation error in `sellKr()` forcing a sell under unfavorable conditions |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-11/KR_exp.sol) |

---
## 1. Vulnerability Overview
A price calculation error in the KR Token `sellKr()` function allowed an attacker to sell tokens under favorable conditions.

---
## 2. Vulnerable Code Analysis (❌/✅ comments)
```solidity
// ❌ Vulnerable code: sell price calculation error
interface IKR is IERC20 {
    function sellKr(uint256 tokenToSell) external;
    // Internally uses an incorrect price calculation that favors the seller
}
// ✅ Fix: apply correct pricing formula
```

---
### On-Chain Original Code

> ⚠️ Contract not verified on Sourcify — source unavailable. The behavior below is reconstructed from the attack PoC and on-chain traces, not verified source.

The KR token contract (0x15b1Ed79cA9D7955AF3E169d7B323c4F1eeb5D12, BSC) is not verified on Sourcify (chainid 56) and is not publicly verified on BSCscan. The following is reconstructed from the DeFiHackLabs PoC (`KR_exp.sol`):

```solidity
// RECONSTRUCTED — not verified source
// KR token: sellKr() — sell at a price that does not correctly account for pool state

interface IKR is IERC20 {
    function sellKr(uint256 tokenToSell) external; // ❌ price formula favors seller under specific pool conditions
}

// PoC core: attacker calls sellKr with 94% of the balance held by address 0xAD1e7BF0...
// The function computes the BUSD proceeds using an incorrect formula that yields more
// BUSD than the market price justifies when a large amount is sold in one call.
// Result: ~5 ETH equivalent drained from the contract's BUSD balance.

// Example of the flawed calculation pattern (reconstructed):
function sellKr(uint256 tokenToSell) external {
    // ❌ price derived from reserves without accounting for slippage or after-sale state
    uint256 busdOut = tokenToSell * busdReserve / totalSupply; // ❌ should use AMM formula: dx*y/(x+dx)
    _burn(msg.sender, tokenToSell);
    BUSD.transfer(msg.sender, busdOut); // ❌ pays out inflated amount
}
```

**Why it is exploitable (identify the bug from the code):**
- The sell price formula uses a simple proportional ratio (`tokenToSell * reserve / supply`) rather than the correct constant-product AMM formula `(dx * y) / (x + dx)`.
- A large single sell (94% of the held balance) yields proportionally more BUSD than the AMM formula would allow, extracting value from the contract's BUSD reserves.
- No flash loan is strictly necessary — the attacker exploits the pricing error directly.

```solidity
// ✅ Fix: use the constant-product AMM formula for sell price
function sellKr(uint256 tokenToSell) external {
    uint256 busdOut = (tokenToSell * busdReserve) / (totalKRSupply + tokenToSell); // ✅ correct AMM pricing
    _burn(msg.sender, tokenToSell);
    BUSD.transfer(msg.sender, busdOut);
}
```

## 3. Attack Flow (ASCII Diagram)
```
Attacker
  ├─① Borrow BNB via flash loan
  ├─② Buy KR tokens (at low price)
  ├─③ Call sellKr() (at favorable price)
  └─④ ~5 ETH profit
```

---
## 4. PoC Code (Core Logic + Comments)
```solidity
flashLoan(bnbAmount);
buyKR(bnbAmount);
uint256 proceeds = krToken.sellKr(krBalance); // sell at favorable price
repayFlashLoan();
```

---
## 5. Vulnerability Classification (Table)
| Category | Details |
|------|------|
| Vulnerability Type | Price Calculation Error |
| Severity | Medium |

---
## 6. Remediation Recommendations
1. Mathematically verify the sell price formula
2. Confirm buy/sell price parity

---
## 7. Lessons Learned
The pricing formula in token sell functions must always be independently verified.