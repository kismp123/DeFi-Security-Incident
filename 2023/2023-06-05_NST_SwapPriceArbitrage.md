# NST Simple Swap — Fixed-Price Arbitrage Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-05 |
| **Protocol** | NST Simple Swap (Milktech) |
| **Chain** | Polygon |
| **Loss** | Unknown |
| **Attacker** | Unknown |
| **Attack Tx** | [0xa1f2377f...](https://polygonscan.com/tx/0xa1f2377fc6c24d7cd9ca084cafec29e5d5c8442a10aae4e7e304a4fbf548be6d) |
| **Vulnerable Contract** | NST Swap Contract |
| **Root Cause** | Logic flaw in the NST↔USDT fixed-price swap contract enabling infinite arbitrage |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/NST_exp.sol) |

---
## 1. Vulnerability Overview

Milktech's NST token operates a swap contract that maintains a 1:1 fixed price with USDT. NST is an ERC-20 token with an added Minter role, where only the swap contract holds minting privileges. However, a flaw in the swap logic allows an attacker to drain all USDT held by the contract through repeated swaps with minimal initial capital.

## 2. Vulnerable Code Analysis

```solidity
// NST Swap Contract Vulnerability (estimated)
// ❌ Swap direction or quantity validation flaw

contract NSTSwap {
    IERC20 public usdt;
    IERC20 public nst;  // Holds Minter role
    uint256 public constant PRICE = 1e18; // 1 NST = 1 USDT

    // ❌ Only one-way swap considered, reverse arbitrage possible
    function swapUSDTforNST(uint256 usdtAmount) external {
        usdt.transferFrom(msg.sender, address(this), usdtAmount);
        INSTToken(address(nst)).mint(msg.sender, usdtAmount); // mint
    }

    function swapNSTforUSDT(uint256 nstAmount) external {
        // ❌ USDT returned without burning NST, or price calculation error
        nst.transferFrom(msg.sender, address(this), nstAmount);
        usdt.transfer(msg.sender, nstAmount); // ❌ No ratio validation
    }
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root Cause: Logic flaw in the NST↔USDT fixed-price swap contract enabling infinite arbitrage
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
┌─────────────────────────────────────────┐
│  1. Purchase NST with a small amount    │
│     of USDT                             │
└─────────────────────┬───────────────────┘
                      ▼
┌─────────────────────────────────────────┐
│  2. Exploit swap logic flaw to exchange │
│     NST → USDT, receiving more USDT     │
│     than originally deposited           │
└─────────────────────┬───────────────────┘
                      ▼
┌─────────────────────────────────────────┐
│  3. Repeat to drain all USDT from       │
│     the contract                        │
└─────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // Polygon fork environment
    // 1. Buy NST with USDT (fixed price)
    // 2. Exploit swap logic flaw to receive excess USDT
    // 3. Repeat to drain contract assets
    for (uint256 i = 0; i < iterations; i++) {
        nstSwap.swapUSDTforNST(amount);
        // Flaw: excess USDT received on reverse NST → USDT swap
        nstSwap.swapNSTforUSDT(nst.balanceOf(address(this)));
    }
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Fixed-price swap logic flaw | HIGH | CWE-682 | 11_logic_error.md |
| V-02 | No arbitrage prevention mechanism | MEDIUM | CWE-284 | 11_logic_error.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ NST burn + fee + slippage protection
function swapNSTforUSDT(uint256 nstAmount) external {
    INSTToken(address(nst)).burnFrom(msg.sender, nstAmount); // ✅ burn
    uint256 fee = nstAmount * FEE_RATE / 10000;
    usdt.transfer(msg.sender, nstAmount - fee); // ✅ deduct fee
}
```

## 7. Lessons Learned

Fixed-price swap (peg-maintaining) contracts must be designed so that the bidirectional swap ratio is exactly 1:1, and a fee or rate limit is required to prevent repeated arbitrage. Even closed internal token systems are exposed to the same attack risks once deployed on a public blockchain.