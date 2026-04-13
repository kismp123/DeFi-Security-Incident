# Security Incident Analysis: Bunni Flash Loan + Aave v3 Liquidation Attack

---

## Overview

| Field | Details |
|------|------|
| **Date** | 2026-03-10 11:46:11 UTC |
| **Network** | Ethereum Mainnet |
| **Block** | 24,626,860 |
| **TX** | `0x9064b507f16bd8b85fb5aea0185153b01fa23b3205f7153f986e5107ce988a9c` |
| **Attacker EOA** | `0x07De4e70Ff80bc47546ef7c5D081a4a1FF8bD98E` |
| **Attack Contract** | `0xbD32122bAD41A09f2405Bb374A83877d8245079C` (unverified) |
| **Victim Address** | `0x4f962bb0ea0785c539f8ab52a17f1f873ddc355f` |
| **Victim Position Owner** | `0x08d49c032f268d3ac4265d1909c28dfaab440040` (EOA) |
| **Net Profit** | **240.570 ETH (~$769,825)** |

---

## Attack Summary

The attacker borrowed 6,304 WETH via a **Bunni Protocol flash loan**, then liquidated a wstETH/WETH leveraged position on **Aave v3** that was severely undercollateralized (HF ≈ 0.84).  
The 5,327 wstETH acquired through liquidation was swapped for 6,545 WETH on **Fluid Protocol DEX**,  
the flash loan was repaid, and **240.57 ETH** was pocketed as net profit.

---

## Relevant Contracts

| Role | Address | Protocol |
|------|------|----------|
| Flash loan provider | `0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb` | Bunni (Uniswap v4-based AMM) |
| Liquidation executor | `0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2` | Aave v3 Pool |
| wstETH collateral aToken | `0x0b925ed163218f6662a35e0f0371ac234f9e9371` | aEthwstETH |
| WETH variable-rate debt | `0xea51d7853eefb32b6ee06b1c12e6dcca88be0ffe` | variableDebtEthWETH |
| WETH aToken | `0x4d5f47fa6a74757f35c14fd3a6ef8e3c9bc514e8` | aEthWETH |
| wstETH swap DEX | `0x52aa899454998be5b000ad077a46bbe360f4e497` | Fluid Protocol Vault |
| Swap router | `0x0b1a513ee24972daef112bc777a5610d4325c9e7` | Fluid DEX Router |
| Collateral token | `0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0` | Lido wstETH |
| Debt token | `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` | WETH |
| Victim position | `0x4f962bb0ea0785c539f8ab52a17f1f873ddc355f` | Smart account (leveraged position) |

---

## Victim Position State Analysis (Pre-Attack)

Victim position `0x4f962bb0ea` was in the following state on Aave v3 before the attack:

| Field | Amount |
|------|------|
| Collateral (aEthwstETH) | 5,327.964 wstETH |
| Debt (variableDebt) | 6,276.396 WETH (principal) |
| wstETH market price | 1.2284 WETH/wstETH |
| Collateral market value | **6,545.14 WETH** |
| LT (Liquidation Threshold) | 80.5% |
| Liquidation HF | `(5,327.96 × 1.2284 × 0.805) / 6,276.39` = **0.839 < 1** |

The position was already liquidatable at **HF ≈ 0.84**.  
While the collateral's market value (6,545 WETH) exceeded the debt (6,276 WETH),  
applying Aave's LT discount (80.5%) caused the effective collateral to fall below the debt.

---

## Attack Flow

```
Attacker EOA (0x07De...)
  │
  └─▶ Attack contract smallBribe() (0xbD32...)
        │
        ├─[1] Bunni FlashLoan(WETH, 6,304.565 WETH)
        │      └─ 0xbbbbbbbb → Attack contract
        │
        ├─[2] Aave v3 Pool.liquidationCall(
        │      collateralAsset: wstETH,
        │      debtAsset: WETH,
        │      user: 0x4f962bb0ea,
        │      debtToCover: 6,304.565 WETH,
        │      receiveAToken: false
        │    )
        │      ├─ WETH 6,304.565 → aEthWETH reserve (debt repayment)
        │      ├─ variableDebtEthWETH 6,276.395 burn (0x4f962bb0ea → 0x0)
        │      ├─ aEthwstETH 5,327.709 burn (0x4f962bb0ea → 0x0)
        │      └─ wstETH 5,327.964 → Attack contract (collateral withdrawal)
        │
        ├─[3] wstETH 5,327.964 → Fluid Protocol swap
        │      ├─ Approve Fluid Router (0x0b1a5...)
        │      ├─ wstETH → Fluid Vault (0x52aa89...)
        │      └─ Fluid Swap: 5,327.964 wstETH → 6,545.135 WETH
        │
        ├─[4] WETH 6,304.565 → Bunni flash loan repayment
        │
        └─[5] Attacker net profit: 240.570 ETH (WETH → ETH withdrawal)
```

---

## Event Log Analysis

### Key Event Sequence (Block 24,626,860)

| Log | Contract | Event | Description |
|-----|----------|--------|------|
| 0x3 | Bunni | `FlashLoan(address,address,uint256)` | Flash loan issued: 6,304.565 WETH |
| 0x4 | WETH | `Transfer` | Bunni → Attack contract 6,304.565 WETH |
| 0x5 | variableDebtEthWETH | `Transfer` | 0x4f962bb0ea → 0x0 (debt burn) |
| 0x6 | variableDebtEthWETH | `Burn(address,address,uint256,uint256,uint256)` | 6,276.395 WETH debt burn |
| 0x7 | Aave v3 Pool | `ReserveDataUpdated` | WETH reserve state update |
| 0x8 | Aave v3 Pool | `ReserveDataUpdated` | wstETH reserve state update |
| 0x9 | aEthwstETH | `Transfer` | 0x4f962bb0ea → 0x0 (collateral aToken burn) |
| 0xa | aEthwstETH | `Burn(address,address,uint256,uint256,uint256)` | 5,327.709 aToken burn |
| 0xb | wstETH | `Transfer` | aEthwstETH → Attack contract 5,327.964 wstETH |
| 0xc-0xf | aEthwstETH | `Mint`, `BalanceTransfer` | Aave liquidation fee processing |
| 0x10 | WETH | `Transfer` | Attack contract → aEthWETH 6,304.565 WETH |
| **0x11** | **Aave v3 Pool** | **`LiquidationCall`** | **Liquidation complete event** |
| 0x12 | wstETH | `Transfer` | Attack contract → Fluid Vault 5,327.964 wstETH |
| 0x13 | wstETH | `Approval` | Attack contract → Fluid Router MAX |
| 0x14-15 | Fluid Vault | `LogOperate` | wstETH deposit, WETH withdrawal |
| 0x16 | Fluid Router | `Swap(bool,uint256,uint256,address)` | 5,327 wstETH → 6,545 WETH |
| 0x17 | WETH | `Deposit` | Attack contract ETH wrap |
| 0x18 | WETH | `Transfer` | Attack contract → Bunni 6,304.565 WETH repayment |
| 0x19 | WETH | `Withdrawal` | Attack contract 240.570 ETH withdrawal |

### LiquidationCall Event Decoding (Log 0x11)

```
event LiquidationCall(
  address indexed collateralAsset,  = wstETH (0x7f39c581...)
  address indexed debtAsset,        = WETH (0xc02aaa...)
  address indexed user,             = 0x4f962bb0ea (victim position)
  uint256 debtToCover,              = 6,304,565,167,623,755,951,957 wei
  uint256 liquidatedCollateralAmount = 5,327,964,413,223,143,335,971 wei
  address liquidator,               = 0xbD32122bad... (attack contract)
  bool receiveAToken                = false
)
```

---

## Profit Analysis

```
Revenue:
  5,327.964 wstETH × 1.2284 WETH = 6,545.14 WETH (Fluid DEX rate)

Expenditure:
  Aave v3 debt repayment WETH:       6,304.57 WETH
  (= Bunni flash loan repayment amount)

Net profit:                          240.57 WETH ≈ $769,825
```

| Item | Amount | Notes |
|------|------|------|
| Bunni FlashLoan | 6,304.565 WETH | Flash loan (zero or negligible fee) |
| Aave liquidation WETH payment | 6,304.565 WETH | Covers victim's entire debt |
| wstETH acquired | 5,327.964 wstETH | Aave collateral liquidation proceeds |
| Fluid swap output | 6,545.135 WETH | 1 wstETH = 1.2284 WETH |
| FlashLoan repayment | 6,304.565 WETH | |
| **Attacker net profit** | **240.570 ETH** | **≈ $769,825** |

---

## Price Analysis: Liquidation Discount Structure

| Metric | Value |
|------|-----|
| wstETH market price (Fluid DEX) | 1.2284 WETH/wstETH |
| WETH cost per wstETH at liquidation | 1.1833 WETH/wstETH (= 6,304 / 5,327) |
| Discount rate (liquidation bonus) | ≈ 3.8% |
| Victim loss vs. self-repayment | 240.57 WETH |

Aave v3 provides a **liquidation bonus** to liquidators.  
The attacker acquired wstETH at 3.8% below market price  
and sold it at market rate, capturing the spread as profit.

---

## Root Cause Analysis

### 1. Undercollateralized Position (HF < 1)

Victim position `0x4f962bb0ea` had **HF ≈ 0.839** at the time of the attack,  
well below Aave v3's liquidation threshold (HF < 1).

```
Health Factor = (collateral amount × price × LT) / total debt
             = (5,327.964 × 1.2284 × 0.805) / 6,276.396
             = 5,267.65 / 6,276.396
             ≈ 0.839
```

This position was a leveraged structure where **WETH was over-borrowed against wstETH collateral**,  
and the HF fell below 1 due to wstETH/WETH price decline or position management failure.

### 2. Liquidation Incentive Structure

Aave v3 liquidation guarantees profit for liquidators through the following structure:
- Liquidator: repays the full debt → acquires collateral below market value
- Victim: forced to sell all collateral below market price

Even when collateral market value (6,545 WETH) exceeds debt (6,276 WETH),  
liquidation is possible if effective collateral falls below debt after applying the LT discount (80.5%).

### 3. Bunni + Fluid Chain Composition

Within a single transaction, the attacker:
1. **Bunni flash loan** → secured liquidation capital with zero upfront capital
2. **Aave v3 liquidation** → acquired collateral cheaply including liquidation bonus
3. **Fluid DEX swap** → immediately converted the acquired wstETH to WETH

This chain enabled a **zero-capital** liquidation attack.

---

## Vulnerable Contracts and Structure

### Vulnerability Summary

| Category | Description |
|------|------|
| **Direct cause** | Victim position HF < 1 (severely undercollateralized) |
| **Liquidation monetization** | Zero-capital liquidation via Bunni FlashLoan + Fluid DEX swap chain |
| **Position management failure** | Position owner failed to detect and respond to HF decline |

### Position Management Failure Analysis

Victim position structure:
```
[EOA owner 0x08d49c032...]
      │
      └─▶ [Smart account 0x4f962bb0ea] ← owner() return value
                │
                ├─ Supplied 5,327 wstETH to Aave v3
                └─ Borrowed 6,276 WETH from Aave v3
```

- Debt (6,276 WETH) exceeded effective collateral value (5,327 × 1.2284 × 0.805 = 5,268 WETH)
- **HF 0.839** is far outside the safe range (>1.5)
- No automatic health factor monitoring or re-collateralization mechanism in place

---

## Scenario-Based Defense Strategies

### From the Position Manager's Perspective

```solidity
// ✅ Recommended: auto-repay or add collateral when HF falls below threshold
function checkAndRebalance() external {
    (,,,,,uint256 hf) = aavePool.getUserAccountData(address(this));
    require(hf > SAFE_HF_THRESHOLD, "Position unhealthy: repay or add collateral");
}

// ✅ Recommended: integrate automation bots to guarantee minimum HF
// (e.g., Gelato, Chainlink Automation)
```

### Understanding the Aave v3 Liquidation Structure

```
Aave v3 liquidation formula:
  collateral_seized = debtToCover / oracle_price × (1 + liquidationBonus)
  
  Where liquidationBonus(wstETH) = 5.5% (Aave v3 Ethereum)
  
In this victim position's case:
  Total collateral (5,327 wstETH) < Formula-derived collateral (6,304/1.228 × 1.055 = 5,415)
  → Undercollateral liquidation: entire collateral seized due to insufficient collateral
```

---

## Protocol Role Summary

| Protocol | Role | Usage |
|----------|------|-----------|
| **Bunni** | Flash loan provider | 6,304 WETH zero-interest flash loan from wstETH/WETH Uniswap v4 pool |
| **Aave v3** | Liquidation executor | Liquidated HF < 1 position → acquired collateral |
| **Fluid Protocol** | Swap DEX | Converted 5,327 wstETH → 6,545 WETH |
| **Lido wstETH** | Collateral token | Wrapped stETH token accumulating staking yield |

---

## Timeline

| Time (UTC) | Event |
|-----------|------|
| 2026-03-10 11:46:11 | Attack transaction executed (block 24,626,860) |
| Same block | Flash loan → liquidation → swap → repayment completed in one step |

---

## Reference Links

- **Phalcon Explorer**: https://app.blocksec.com/phalcon/explorer/tx/eth/0x9064b507f16bd8b85fb5aea0185153b01fa23b3205f7153f986e5107ce988a9c
- **Etherscan TX**: https://etherscan.io/tx/0x9064b507f16bd8b85fb5aea0185153b01fa23b3205f7153f986e5107ce988a9c
- **Aave v3 Ethereum Risk Parameters**: https://app.aave.com/reserve-overview/?underlyingAsset=0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0&marketName=proto_mainnet_v3
- **Bunni Protocol**: https://bunni.pro
- **Fluid Protocol DEX**: https://fluid.instadapp.io

---

## Lessons Learned and Conclusion

This incident is a textbook example of a **liquidation MEV attack resulting from position management failure**.

1. **The liquidation bonus is not a vulnerability**: Aave's liquidation mechanism itself operated as designed.  
   The attacker legitimately utilized the protocol's liquidation incentive mechanism.

2. **Flash loan chain composition**: The single-transaction chain of Bunni (capital sourcing) + Aave (liquidation) + Fluid (conversion)  
   demonstrates that **zero-capital liquidation monetization** is achievable.

3. **Importance of position management**: HF 0.84 is an extremely dangerous level.  
   DeFi leveraged positions require **automated HF monitoring and re-collateralization systems**.

4. **Methods to minimize liquidation damage**:
   - Maintain minimum HF > 1.5
   - Implement automatic debt repayment logic when liquidation is imminent
   - Integrate automation bots such as Chainlink Automation / Gelato
   - Configure position monitoring alerts