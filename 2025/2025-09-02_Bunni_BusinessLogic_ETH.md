# Bunni v2 — Uniswap v4 Hook Share Accounting Business Logic Flaw

| Item | Details |
|------|------|
| **Date** | 2025-09-02 |
| **Protocol** | Bunni v2 |
| **Chain** | Ethereum Mainnet + Unichain (chainId 130) |
| **Loss** | ~$8,300,000 |
| **Root Cause** | Business Logic Flaw — incorrect state update ordering in the Bunni hook allowed share accounting manipulation; internal state was finalized after external token transfers, creating an exploitable inconsistency window |
| **Attack Tx 1** | `0x1c27c4d625429acfc0f97e466eda725fd09ebdc77550e529ba4cbdbc33beb97b` |
| **Attack Tx 2** | `0x4776f31156501dd456664cd3c91662ac8acc78358b9d4fd79337211eb6a1d451` |
| **Reference** | https://x.com/Phalcon_xyz/status/1962743751568433416 |

---

## 1. Vulnerability Overview

Bunni v2 is a liquidity management protocol built on top of Uniswap v4 hooks. It extends Uniswap v4's `PoolManager` with custom concentrated liquidity accounting, automated fee compounding, and incentive distribution. The hook contract tracks virtual liquidity shares for each depositor and processes fee accrual during swaps.

**Core Vulnerability**: Bunni's hook did not follow the **checks-effects-interactions pattern**. In the `afterAddLiquidity` callback — invoked by the Uniswap v4 `PoolManager` after a liquidity deposit — the hook performed external token settlement (`_settleOrTake`) before updating its internal share accounting (`_updateShareAccounting`). This out-of-order execution created a window in which an attacker could observe stale share state and exploit it to receive inflated share-to-token redemptions.

The flaw was exploitable within the same Uniswap v4 lock context because v4's lock mechanism serialises PoolManager interactions but does not prevent a hook from performing external calls that temporarily expose inconsistent internal state. The attacker drained approximately $8.3M across ETH mainnet and Unichain by adding liquidity, exploiting the stale accounting window to inflate their share valuation, and then removing liquidity at the inflated rate.

---

## 2. Vulnerable Code Analysis

### 2.1 Incorrect State Update Order in `afterAddLiquidity`

```solidity
// Bunni Hook — afterAddLiquidity (simplified, vulnerable)
function afterAddLiquidity(
    address sender,
    PoolKey calldata key,
    IPoolManager.ModifyLiquidityParams calldata params,
    BalanceDelta delta,
    BalanceDelta feesAccrued,
    bytes calldata hookData
) external override onlyPoolManager returns (bytes4, BalanceDelta) {

    // Step 1: Settle token balances with the PoolManager (external interaction)
    _settleOrTake(key.currency0, delta.amount0());
    _settleOrTake(key.currency1, delta.amount1());

    // BUG: share accounting updated AFTER external interaction
    // Between the external call above and this update, share state is stale.
    // An attacker can observe or trigger a second operation that reads the
    // pre-update share price and receives excess tokens on withdrawal.
    _updateShareAccounting(key, params.liquidityDelta); // ← must be first

    return (Hooks.AFTER_ADD_LIQUIDITY_FLAG, toBalanceDelta(0, 0));
}
```

```solidity
// Fixed: apply checks-effects-interactions — update state before external calls
function afterAddLiquidity(
    address sender,
    PoolKey calldata key,
    IPoolManager.ModifyLiquidityParams calldata params,
    BalanceDelta delta,
    BalanceDelta feesAccrued,
    bytes calldata hookData
) external override onlyPoolManager nonReentrant returns (bytes4, BalanceDelta) {

    // ✅ Fix: update internal share accounting FIRST (effects before interactions)
    _updateShareAccounting(key, params.liquidityDelta);

    // ✅ Then perform external token settlement
    _settleOrTake(key.currency0, delta.amount0());
    _settleOrTake(key.currency1, delta.amount1());

    return (Hooks.AFTER_ADD_LIQUIDITY_FLAG, toBalanceDelta(0, 0));
}
```

**Impact**: Any code path that reads share prices or share-to-token ratios between the external settlement call and the accounting update will observe a stale (pre-deposit) share state. In this stale state, the attacker's newly minted shares appear to entitle them to more underlying tokens than they actually deposited.

### 2.2 Missing Reentrancy Guard on Hook Liquidity Functions

```solidity
// Vulnerable: no reentrancy protection on afterRemoveLiquidity
function afterRemoveLiquidity(
    address sender,
    PoolKey calldata key,
    IPoolManager.ModifyLiquidityParams calldata params,
    BalanceDelta delta,
    BalanceDelta feesAccrued,
    bytes calldata hookData
) external override onlyPoolManager returns (bytes4, BalanceDelta) {
    // No nonReentrant modifier
    // External calls inside _settleOrTake can trigger re-entry before
    // share burn is recorded
    _settleOrTake(key.currency0, delta.amount0());
    _settleOrTake(key.currency1, delta.amount1());
    _burnShareAccounting(key, params.liquidityDelta); // ← share burn after transfer
    return (Hooks.AFTER_REMOVE_LIQUIDITY_FLAG, toBalanceDelta(0, 0));
}
```

```solidity
// Fixed: add nonReentrant + effects-before-interactions
function afterRemoveLiquidity(
    address sender,
    PoolKey calldata key,
    IPoolManager.ModifyLiquidityParams calldata params,
    BalanceDelta delta,
    BalanceDelta feesAccrued,
    bytes calldata hookData
) external override onlyPoolManager nonReentrant returns (bytes4, BalanceDelta) {
    // ✅ Burn shares first
    _burnShareAccounting(key, params.liquidityDelta);
    // ✅ Then transfer tokens
    _settleOrTake(key.currency0, delta.amount0());
    _settleOrTake(key.currency1, delta.amount1());
    return (Hooks.AFTER_REMOVE_LIQUIDITY_FLAG, toBalanceDelta(0, 0));
}
```

---

## 3. Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Step 1: Add Liquidity                         │
│  Attacker calls Bunni's deposit function for a target pool        │
│  Uniswap v4 PoolManager invokes afterAddLiquidity hook            │
│  Hook: _settleOrTake executes → tokens transferred externally     │
│  ⚠ Share accounting NOT yet updated (stale state window opens)   │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│          Step 2: Exploit Stale Share State Window                 │
│  Within the same v4 lock context, attacker triggers a second      │
│  operation that reads share-to-token ratio                        │
│  Ratio computed against PRE-update share supply                   │
│  Attacker's share position appears worth more than deposited      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Step 3: Remove Liquidity at Inflated Value       │
│  Attacker removes liquidity using inflated share valuation        │
│  Receives more tokens than originally deposited                   │
│  Excess comes from other LPs' pooled assets                       │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│              Step 4: Repeat Across Multiple Pools                 │
│  Attack replicated across multiple Bunni pools on Ethereum        │
│  Attack replicated on Unichain (chainId 130) as well             │
│  Attack Tx 1: 0x1c27c4d6... (Ethereum)                           │
│  Attack Tx 2: 0x4776f311... (Unichain)                           │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Step 5: Funds Extracted                        │
│  Total loss: ~$8.3M drained from multiple Bunni liquidity pools  │
│  Attacker holds excess tokens; LPs hold devalued share positions  │
└─────────────────────────────────────────────────────────────────┘
```

**Attack Flow Summary**:

```
Attacker
  │
  ├──▶ [Uniswap v4 PoolManager — lock acquired]
  │
  ├──▶ [Bunni Hook: afterAddLiquidity]
  │    _settleOrTake() → external token transfer executes
  │    _updateShareAccounting() → NOT YET RUN (stale state)
  │
  ├──▶ [Second hook operation within same lock]
  │    Reads share-to-token ratio from STALE accounting
  │    Attacker shares → inflated token entitlement computed
  │
  ├──▶ [Bunni Hook: afterRemoveLiquidity]
  │    Withdraw at inflated ratio → excess tokens received
  │
  └──▶ Repeat on Ethereum pools + Unichain pools → ~$8.3M drained
```

---

## 4. Vulnerability Classification

| ID | Vulnerability | Category | CWE | Severity |
|----|--------------|---------|-----|----------|
| V-01 | Share accounting updated after external token transfer | Business Logic Flaw / Checks-Effects-Interactions Violation | CWE-362 (Race Condition / Improper Synchronization) | **CRITICAL** |
| V-02 | Missing reentrancy guard on hook liquidity callbacks | Missing Reentrancy Protection | CWE-841 (Improper Enforcement of Behavioral Workflow) | **CRITICAL** |
| V-03 | Share-to-token ratio readable during state inconsistency window | Inconsistent State Exposure | CWE-367 (Time-of-check Time-of-use Race Condition) | **HIGH** |
| V-04 | No cross-chain isolation — same flaw deployed on Unichain | Multi-Chain Deployment Risk | CWE-657 (Violation of Secure Design Principles) | **MEDIUM** |

---

## 5. Remediation Recommendations

### Immediate Actions

1. **Apply checks-effects-interactions in all hook callbacks**: All internal state updates (share minting, accounting, price snapshots) must complete before any external token transfers or calls to `PoolManager.settle` / `PoolManager.take`.

2. **Add `nonReentrant` modifier to hook liquidity functions**: Even within a v4 lock context, external calls inside `_settleOrTake` can trigger callbacks. Reentrancy guards prevent a second entry from observing partially updated state.

3. **Pause the protocol immediately on all chains**: When a multi-chain deployment shares the same vulnerable code, all deployments must be paused simultaneously to prevent parallel exploitation.

### Structural Improvements

| Vulnerability | Recommended Action |
|--------------|-------------------|
| V-01 (Wrong update order) | Restructure all hook callbacks: compute and record state changes first, then perform token transfers |
| V-02 (No reentrancy guard) | Add OpenZeppelin `ReentrancyGuard` or equivalent to all `afterAddLiquidity` / `afterRemoveLiquidity` functions |
| V-03 (Stale state readable) | Use a commit-reveal or locked-state pattern during the settlement phase so ratios are not readable mid-operation |
| V-04 (Multi-chain risk) | Implement a single canonical deployment verification step before going live on additional chains |

```solidity
// Pattern: safe hook callback structure
function afterAddLiquidity(...) external override onlyPoolManager nonReentrant returns (...) {
    // 1. CHECKS — validate inputs, access controls
    require(params.liquidityDelta > 0, "Zero liquidity");

    // 2. EFFECTS — update all internal state first
    _updateShareAccounting(key, params.liquidityDelta);
    _snapshotFeeState(key);

    // 3. INTERACTIONS — external calls last
    _settleOrTake(key.currency0, delta.amount0());
    _settleOrTake(key.currency1, delta.amount1());

    return (Hooks.AFTER_ADD_LIQUIDITY_FLAG, toBalanceDelta(0, 0));
}
```

---

## 6. Lessons Learned

1. **Uniswap v4 hooks introduce new ordering attack surfaces**: The hook callback system invokes protocol code at precise moments in the PoolManager execution flow. Protocols must rigorously apply checks-effects-interactions within these callbacks, as the PoolManager's lock does not protect against state inconsistencies inside the hook itself.

2. **"Effects before interactions" is not optional in DeFi**: This is one of the oldest rules in smart contract security. It must be enforced not just at the top-level entry point but at every internal function that touches both state and external calls.

3. **Reentrancy remains relevant in v4 hook contexts**: The Uniswap v4 PoolManager's lock provides sequential access control at the PoolManager level, but hook functions can still be re-entered through callbacks in ERC-20 `transfer` / `transferFrom` (e.g., ERC-777 tokens or tokens with hooks). Always add reentrancy guards.

4. **Multi-chain deployments multiply risk exposure**: The same bug executing on two chains simultaneously doubled the attacker's opportunity and increased total losses. Security reviews should be mandatory for every new chain deployment, and a coordinated pause mechanism across all chains is essential.

5. **Similar incidents**: Pickle Finance (November 2020, $19.7M, logic flaw in jar strategy), CREAM Finance (October 2021, $130M, reentrancy in compound fork), Euler Finance (March 2023, $197M, donation + liquidation logic error) — all exploited incorrect state update ordering combined with external interactions.

---

## References

- [Phalcon (BlockSec) Incident Alert (Twitter/X)](https://x.com/Phalcon_xyz/status/1962743751568433416)
- [Attack Transaction 1 (Etherscan)](https://etherscan.io/tx/0x1c27c4d625429acfc0f97e466eda725fd09ebdc77550e529ba4cbdbc33beb97b)
- [Attack Transaction 2 (Etherscan)](https://etherscan.io/tx/0x4776f31156501dd456664cd3c91662ac8acc78358b9d4fd79337211eb6a1d451)
- [Uniswap v4 Hooks Documentation](https://docs.uniswap.org/contracts/v4/concepts/hooks)
- [Checks-Effects-Interactions Pattern — Solidity Docs](https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)
