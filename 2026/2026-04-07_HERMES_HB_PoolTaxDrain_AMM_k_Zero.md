# HERMES (HB) — Pool Tax Drain & AMM k=0 Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2026-04-07 |
| **Protocol** | HERMES (HB Token) |
| **Chain** | BNB Chain (BSC) |
| **Loss** | ~$193,937 USDT (entire liquidity of PancakeSwap HB/USDT pool) |
| **Attacker** | [0x2E358F7E...63F23](https://bscscan.com/address/0x2E358F7E323b9E615231873F17b099b833163F23) |
| **Attack Contract** | [0x4aCaF838...8F1a](https://bscscan.com/address/0x4aCaF8388C97dEF668E0c3b01E3d18260c6A8F1a) |
| **Attack Tx** | [0x19671f57...94ed](https://bscscan.com/tx/0x19671f5781acc3f5e3a869491a880aa9ee894911f4898a43254fa942d71594ed) |
| **Vulnerable Contract** | [0x86dDbfc6...0AEF](https://bscscan.com/address/0x86dDbfc6F2E3cf096E80cA79E46042392bd90AEF) (HB Token Proxy) |
| **Implementation** | [0x62ceb08b...a4b0](https://bscscan.com/address/0x62ceb08b078b277c3a708d9943ce9dbbd987a4b0) |
| **Attack Block** | 91,158,398 |
| **Root Cause** | `_handleBuy` directly deducts the buy tax from the LP pool's HB balance → pool k=0 collapse |

---

## 1. Vulnerability Overview

The `_handleBuy` function of the HERMES (HB) token, upon a buy occurring, **directly deducts the tax from the LP pool's own HB balance instead of deducting it from the recipient's (buyer's) received amount**.

The attacker exploited this to:
1. Raise large capital via flash loans from Venus Protocol (100M USDT) + Lista DAO Moolah (405K WBNB)
2. Buy 73.6M HB with 72.1M USDT → the buy tax (0.27%) is deducted from the pool, making **pool HB reserve = 0**
3. PancakeSwap k invariant collapses: `k = USDT × 0 = 0`
4. **25 rounds** of repeated extraction under k=0 state: depositing small amounts of HB + USDT to drain large amounts of USDT
5. Total profit of 193,937 USDT (the pool's entire original liquidity)

---

## 2. Vulnerable Code Analysis

### 2.1 `_handleBuy` — Direct Tax Deduction from Pool Balance (Core Vulnerability)

```solidity
function _handleBuy(address from, address to, uint256 amount) private {
    // from = swapPair (LP pool), to = buyer
    if (_isWhitelist(to)) {
        super._transfer(from, to, amount);
        return;
    }
    if (_cs.startBlock == 0 || !_checkAndOpenSwap()) {
        revert("Not Open Swap");
    }
    (, uint rOther, uint balanceOther) = _getReserves();
    uint swapValue = getSwapValueUSDT(amount);
    if (balanceOther >= rOther - (swapValue * (100 - _cs.removeRate)) / 100) {
        userAmounts[to] += swapValue;
        uint256 every = amount / TAX_BASE;
        // ❌ Vulnerability: tax is deducted directly from from=LP pool!
        // Reduces the pool's token balance, not the buyer's received amount
        super._transfer(from, address(this), every * TAX_TOTAL);
        _cs.rewardNode += every * TAX_NODE;
        super._transfer(from, to, amount - every * TAX_TOTAL);
    } else {
        // If condition not met: burn HB from pool to dead (further reduces pool balance!)
        super._transfer(from, _dead, amount);
    }
}
```

**Fixed Code (Safe Version):**

```solidity
function _handleBuy(address from, address to, uint256 amount) private {
    if (_isWhitelist(to)) {
        super._transfer(from, to, amount);
        return;
    }
    // ... omitted ...
    if (balanceOther >= rOther - (swapValue * (100 - _cs.removeRate)) / 100) {
        userAmounts[to] += swapValue;
        uint256 taxAmount = amount * TAX_TOTAL / TAX_BASE;
        // ✅ Fix: pool sends full amount to buyer first
        super._transfer(from, to, amount);
        // ✅ Fix: tax is then deducted from what the buyer received
        super._transfer(to, address(this), taxAmount);
        _cs.rewardNode += taxAmount * TAX_NODE / TAX_TOTAL;
    } else {
        super._transfer(from, _dead, amount);
    }
}
```

**The Problem**: The `super._transfer(from=LP_pool, address(this), TAX)` call directly reduces the LP pool's actual token balance. PancakeSwap V2 updates its reserves based on `balanceOf(pair)` during `pair.sync()`, so this tax deduction causes the reserve to be lower than it should be. When cumulative taxes on a large buy equal the remaining HB reserve, **pool.reserve1 = 0**.

### 2.2 PancakeSwap k=0 Invariant Collapse

```
// k verification inside PancakeSwap V2 swap()
uint balance0Adjusted = balance0.mul(1000).sub(amount0In.mul(3));
uint balance1Adjusted = balance1.mul(1000).sub(amount1In.mul(3));

// ❌ If reserve1=0, right side=0, any swap passes!
require(
    balance0Adjusted.mul(balance1Adjusted) >=
    uint(_reserve0).mul(_reserve1).mul(1000**2),
    'Pancake: K'
);
// reserve1=0 → _reserve1=0 → right side=0 → left side >= 0 → always true
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker interacted with the HB token the day before (2026-04-06) to verify state.
On the day of the attack, the attack contract was deployed first, then executed.

### 3.2 Execution Phase

```
[Step 1] Flash Loan Funding
┌─────────────────────────────────────────────────────┐
│ Lista DAO Moolah → AttackContract: 405,231 WBNB     │
│ AttackContract → Venus vBNB: deposit 405,231 WBNB   │
│ Venus vUSDT → AttackContract: borrow 100,000,000 USDT│
└─────────────────────────────────────────────────────┘
                          │
                          ▼
[Step 2] Large-Scale HB Purchase (Price Manipulation)
┌────────────────────────────────────────────────────────────┐
│ Input: 72,117,360 USDT → PCS HB/USDT Pool                 │
│ Received: 73,608,753 HB (to attacker)                      │
│                                                             │
│ Buy Tax: 200,000 HB → HB Contract (deducted directly from pool)│
│                                                             │
│ Pool State Change:                                          │
│   BEFORE: 195,469 USDT + 73,808,753 HB  (k = 1.44×10^49)  │
│   AFTER:  72,312,818 USDT + 0 HB        (k ≈ 0) ❌         │
└────────────────────────────────────────────────────────────┘
                          │
                          ▼
[Step 3] Exploiting k=0 State — 25 Rounds of Repeated Extraction
┌────────────────────────────────────────────────────────────┐
│ Round  3: 21.7M USDT + 0.000582 HB → 37.6M USDT (+15.9M) │
│ Round  4: 33.9M USDT + 0.001503 HB → 53.9M USDT (+20.0M) │
│ Round  5: 21.8M USDT + 0.002377 HB → 34.8M USDT (+12.9M) │
│ Round  6: 14.1M USDT + 0.003761 HB → 22.4M USDT  (+8.3M) │
│ ...                                                         │
│ Round 27:  1.4M USDT + 36.26 HB  →   2.3M USDT   (+0.8M) │
│                                                             │
│ HB input increases by ~1.58x each round                    │
│ Total: 4,319.91 HB input → 193,947.99 USDT net extracted  │
└────────────────────────────────────────────────────────────┘
                          │
                          ▼
[Step 4] Loan Repayment and Profit Realization
┌─────────────────────────────────────────────────────┐
│ AttackContract → Venus: repay USDT                  │
│ AttackContract → Venus: return vBNB                 │
│ AttackContract → Lista DAO Moolah: repay 405,231 WBNB│
│ Final Profit: 193,937 USDT                          │
└─────────────────────────────────────────────────────┘
```

### 3.3 Results

| Item | Amount |
|------|------|
| Flash Loan Size | 405,231 WBNB + 100,000,000 USDT |
| HB Purchase Cost | 72,117,360 USDT |
| Pool HB Reserve After Purchase | 0 HB (k=0 collapse) |
| USDT Extracted over 25 Rounds | 72,311,308 USDT (net) |
| Total Profit | **193,937 USDT (~$193,937)** |
| Pool Damage | 195,468 USDT → 1,520 USDT (98.7% drained) |

---

## 4. On-Chain Verification

### 4.1 Pool State Comparison

| Item | Before Attack | After Attack |
|------|---------|---------|
| Pool USDT Reserve | 195,468.92 USDT | 1,520.92 USDT |
| Pool HB Reserve | 73,808,753 HB | 155.92 HB |
| HB Price | 0.00265 USDT/HB | 9.76 USDT/HB |
| Pool k Value | 1.44 × 10^49 | ~0 |

### 4.2 Key Event Sequence

```
[Log  1] Transfer WBNB: ListaDAO_Moolah → AttackContract: 405,231.90 WBNB
[Log  6] Transfer vBNB: Venus_vBNB → AttackContract: vBNB minted
[Log 11] Transfer USDT: Venus_vUSDT → AttackContract: 100,000,000 USDT
[Log 13] Transfer HB: AttackContract → HB_Token: 1,496.82 HB (threshold trigger)
[Log 19] SWAP (Round 1): HB 4,163.99 → USDT 11.00 (_swapAndLiquify)
[Log 37] SWAP (Round 2): USDT 72,117,360 → HB 73,608,753 (large buy)
[Log 39] SYNC: r0=72,312,818 USDT, r1=0 HB ← k=0 collapse!
[Log 51] SWAP (Round 3): 21.7M USDT+0.000582 HB → 37.6M USDT
[Log 57] SWAP (Round 4): 33.9M USDT+0.001503 HB → 53.9M USDT
...total 27 SWAP events, 207 logs emitted
```

### 4.3 Buy Tax Calculation

- Total HB transferred (pool → attacker): 73,608,753 HB
- HB tax (pool → HB contract): **200,000 HB** (= entire pool.r1!)
- Tax rate: 200,000 / 73,808,753 = **0.271%**
- This tax completely exhausted the pool's remaining 200,000 HB

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Buy tax deducted directly from pool balance | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | Unlimited extraction after AMM k=0 invariant collapse | CRITICAL | CWE-682 |
| V-03 | Flash loan-based price manipulation (no oracle) | HIGH | CWE-840 |

### V-01: Buy Tax Deducted Directly from Pool

- **Description**: In `_handleBuy`, the `super._transfer(from=LP_pool, address(this), TAX)` call directly reduces the LP pool's ERC20 balance. Since PancakeSwap updates reserves based on `balanceOf(pair)` during `pair.sync()`, the tax deduction is reflected in the pool's reserves.
- **Impact**: On a large buy, when cumulative taxes equal the remaining token reserve, it leads to k=0 collapse.
- **Attack Condition**: Must be able to execute a single buy with sufficient capital to bring the pool's token balance below the accumulated tax amount.

### V-02: AMM k=0 Invariant Collapse

- **Description**: PancakeSwap V2's k verification is `new_k >= reserve0 * reserve1 * 1000²`. If reserve1=0, the right side becomes 0, allowing any swap to pass. The attacker can extract arbitrary USDT under the k=0 state.
- **Impact**: Repeated extraction possible until the pool's entire original liquidity is drained.
- **Attack Condition**: V-01 is a prerequisite.

### V-03: Flash Loan-Based Price Manipulation

- **Description**: Token logic that operates solely based on PancakeSwap pool price with no on-chain oracle. Instantaneous price manipulation is possible with large flash loans.
- **Impact**: Provides sufficient capital to enable the V-01 attack.
- **Attack Condition**: Lista DAO Moolah (WBNB collateral) + Venus (USDT borrowing).

---

## 6. Remediation Recommendations

### Immediate Actions

**① Fix Tax Deduction Method**: Deduct from the buyer's received amount, not the pool balance

```solidity
// ❌ Current: deducted directly from pool
super._transfer(from, address(this), every * TAX_TOTAL);  // from = pool!
super._transfer(from, to, amount - every * TAX_TOTAL);

// ✅ Fixed: deducted after buyer receives funds
uint256 taxAmount = amount * TAX_TOTAL / TAX_BASE;
super._transfer(from, to, amount);                        // full amount to buyer
super._transfer(to, address(this), taxAmount);             // tax deducted from buyer
```

**② Cap the Maximum Tax Amount**

```solidity
// Prevent tax from exceeding a certain percentage of the reserve
uint256 maxTax = rThis / 1000;  // 0.1% maximum
uint256 taxAmount = Math.min(amount * TAX_TOTAL / TAX_BASE, maxTax);
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Pool Tax Deduction | Fee-on-transfer tokens must not directly manipulate pool balances; use UniswapV2-compatible approach |
| V-02 k=0 Collapse | Add minimum reserve protection logic to the pool; `require(reserve1 > MIN_RESERVE)` |
| V-03 Price Manipulation | Switch to Chainlink oracle or TWAP-based price reference |
| General | Tokens with tax logic must undergo a separate security audit before AMM integration |

---

## 7. Lessons Learned

1. **Dangerous Combination of Fee-on-Transfer Tokens and AMMs**: Deducting tax directly from the `from` address (LP pool) allows external manipulation of the AMM's k invariant. Token taxes must always be deducted from the recipient (buyer).

2. **k=0 State Is an Infinite Extraction Gate**: When `reserve1=0` in PancakeSwap V2, the k verification is neutralized. This is not a mere precision issue but a complete security breakdown — all of the pool's liquidity becomes extractable.

3. **Flash Loans Remove Capital Barriers**: By combining Lista DAO + Venus, the attacker mobilized approximately $243M in capital temporarily. Even with a tax of only 0.27%, a single buy of 72M USDT is enough to drain 200,000 HB = the pool's entire HB supply.

4. **Small Pool + Large Token Tax = High Risk**: The shallower the pool's liquidity, the easier it is to bring reserves to 0 with a single transaction. The higher the tax rate relative to pool TVL, the greater the risk.

5. **AMM Integration Must Be Considered at Token Design Time**: Tokens with `_transfer` overrides must be designed with a thorough understanding of how UniswapV2/PancakeSwap works (reserve synchronization, k verification logic).

---

## 8. Additional Information

- **Attacker Post-Attack Actions**: Converted proceeds to BNB and deposited 310 BNB into Tornado.Cash (money laundering)
- **HB Token Deployment**: Approximately 21 days before the attack (around 2026-03-17), deployer 0x55A6e574...
- **Lista DAO Moolah**: Provided flash loan with WBNB collateral (405,231 WBNB ≈ $243M)
- **Venus Protocol**: Provided 100M USDT flash loan

| Contract | Address |
|---------|------|
| HB Token (Proxy) | 0x86dDbfc6F2E3cf096E80cA79E46042392bd90AEF |
| HB Token (Impl) | 0x62ceb08b078b277c3a708d9943ce9dbbd987a4b0 |
| PCS HB/USDT Pool | 0x67a63609cf1c317196724666cc39b2da63545a96 |
| Lista DAO Moolah | 0x8f73b65b4caaf64fba2AF91cc5D4a2a1318e5D8c |
| Venus vBNB | 0xa07c5b74c9b40447a954e1466938b865b6bbea36 |
| Venus vUSDT | 0xfd5840cd36d94d7229439859c0112a4185bc0255 |
| Attack Contract | 0x4aCaF8388C97dEF668E0c3b01E3d18260c6A8F1a |