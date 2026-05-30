# dYdX v3 — Insurance Fund Drain via YFI Market Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2023-11-17 |
| **Protocol** | dYdX v3 (perpetual DEX on StarkEx L2) |
| **Chain** | Ethereum (dYdX StarkEx rollup) |
| **Loss** | ~$9,000,000 (dYdX v3 insurance fund drained; no direct user losses — fund absorbed the shortfall) |
| **Attacker** | Unknown |
| **Vulnerable Contract** | dYdX v3 perpetuals market (YFI-USD market) |
| **Root Cause** | The attacker accumulated a large leveraged long position in the thin YFI-USD perpetuals market on dYdX, then coordinated a sharp crash of the YFI spot price on external markets (CEXs), triggering mass liquidations on dYdX whose insurance fund could not fully cover the resulting bad debt |
| **CWE** | CWE-682: Incorrect Calculation (insurance fund sizing relative to market concentration risk); CWE-400: Uncontrolled Resource Consumption |
| **PoC Source** | dYdX Foundation official post-mortem (Nov 2023); Chainalysis on-chain analysis |

---
## 1. Vulnerability Overview

dYdX v3 is a decentralized perpetual futures exchange operating on StarkEx (ZK-rollup). It maintains an insurance fund to cover bad debt when liquidations result in positions going below zero (i.e., the liquidated collateral is insufficient to cover losses).

On November 17, 2023, an attacker executed a sophisticated multi-step market manipulation attack:

1. Built up a large, highly-leveraged long position in the YFI-USD perpetuals market on dYdX, which has thin liquidity relative to the position size.
2. Coordinated a rapid crash of the YFI spot price on centralized exchanges (selling YFI aggressively on Binance, OKX, and others), causing a ~30% price drop within a short window.
3. The oracle used by dYdX updated to reflect the crashed spot price, triggering forced liquidations of the attacker's own long position — but the position was so large that the insurance fund had to absorb the difference between liquidation proceeds and the losses.

The dYdX v3 insurance fund was drained of approximately $9M in this event. A similar attack had occurred about two weeks earlier on dYdX's SUSHI market (the attacker made ~$5M profit in that event). The ~$38M figure sometimes cited in media refers to the total value of YFI positions liquidated during the November 17 event itself — not a separate BTC fund drain.

---
## 2. Attack Mechanics

```
Attacker
    │
    ├─[1] Accumulate large leveraged long YFI-USD position on dYdX v3
    │       Position size: disproportionately large relative to YFI market liquidity
    │       Collateral posted: significant (attacker willing to lose collateral)
    │
    ├─[2] Aggressively sell YFI on Binance, OKX, and other CEXs
    │       YFI spot price drops ~30% rapidly
    │       → dYdX's oracle (Chainlink / market-weighted) reflects crash
    │
    ├─[3] dYdX liquidation engine triggers:
    │       Forced liquidation of attacker's long position at crashed price
    │       Liquidation proceeds < position losses (thin liquidity, slippage)
    │       → Bad debt created (shortfall not covered by collateral)
    │
    ├─[4] dYdX insurance fund absorbs bad debt shortfall
    │       Insurance fund drained: ~$9M (Nov 17 YFI attack alone)
    │       Attacker's cost: spot market selling losses + initial collateral
    │       Attacker's gain: funded from insurance fund drain via market impact
    │
    └─[5] dYdX Foundation discloses incident; v3 fund partially drained
              Attacker profited from the delta between CEX selling impact and dYdX insurance fund extraction
```

---
## 2a. Vulnerable Code Analysis

**Language**: Solidity 0.5.16 (on-chain settlement layer) + off-chain economic design flaw
**Source provenance**: Real Solidity source from the open-source `dydxprotocol/perpetual` repository.
Repository: https://github.com/dydxprotocol/perpetual

> **Important framing**: dYdX v3 operates on StarkEx (ZK-rollup). Order matching runs off-chain; the on-chain Solidity contracts handle deposits, withdrawals, liquidations, and final settlement via ZK-proofs. The attack exploited **no code bug in the Solidity contracts** — the contracts functioned exactly as designed. The exploitable flaw was entirely in the **economic risk model**: position size limits were too permissive for thin-market assets (YFI), and the insurance fund was large enough relative to the cost of manipulation to make the attack profitable.
>
> The Solidity code below is real, verified, and deployed. It is shown to illustrate precisely which design decisions created the attack surface.

### The Collateralization Check — `P1Liquidation.sol` (real source)

```solidity
// File: contracts/protocol/v1/traders/P1Liquidation.sol
// Source: https://github.com/dydxprotocol/perpetual/blob/master/contracts/protocol/v1/traders/P1Liquidation.sol
// License: Apache 2.0

pragma solidity 0.5.16;

contract P1Liquidation is P1TraderConstants {
    using SafeMath for uint256;
    using Math for uint256;
    using P1BalanceMath for P1Types.Balance;

    /**
     * @notice Allows an account below the minimum collateralization to be liquidated.
     * @dev Called by P1Trade.trade() when a global operator submits a liquidation.
     */
    function trade(
        address sender,
        address maker,      // ← the account being liquidated (attacker's long position)
        address taker,      // ← the liquidator (dYdX engine or backstop provider)
        uint256 price,      // ← oracle price at time of liquidation
        bytes calldata data,
        bytes32 /* traderFlags */
    )
        external
        returns (P1Types.TradeResult memory)
    {
        TradeData memory tradeData = abi.decode(data, (TradeData));
        P1Types.Balance memory makerBalance = P1Getters(perpetual).getAccountBalance(maker);

        _verifyTrade(tradeData, makerBalance, perpetual, price);

        // Bound execution amount by maker's position size
        uint256 amount = Math.min(tradeData.amount, makerBalance.position);

        // Liquidator receives (margin / position) * liquidated_amount from the maker
        uint256 marginAmount;
        if (tradeData.isBuy) {
            marginAmount = uint256(makerBalance.margin).getFractionRoundUp(
                amount,
                makerBalance.position
            );
        } else {
            marginAmount = uint256(makerBalance.margin).getFraction(amount, makerBalance.position);
        }

        // ⚠️ KEY DESIGN POINT: if makerBalance.margin < liquidation loss,
        //    this function still succeeds — it returns whatever margin is available.
        //    The SHORTFALL (loss > collateral) must be absorbed by the insurance fund.
        //    There is no on-chain cap on the shortfall amount per liquidation.

        return P1Types.TradeResult({
            marginAmount: marginAmount,
            positionAmount: amount,
            isBuy: tradeData.isBuy,
            traderFlags: TRADER_FLAG_LIQUIDATION
        });
    }

    function _isUndercollateralized(
        P1Types.Balance memory balance,
        address perpetual,
        uint256 price
    )
        private
        view
        returns (bool)
    {
        uint256 minCollateral = P1Getters(perpetual).getMinCollateral();
        (uint256 positive, uint256 negative) = balance.getPositiveAndNegativeValue(price);

        // ⚠️ minCollateral is a STATIC parameter set by governance.
        //    It does not scale with YFI market liquidity depth or concentration risk.
        //    A motivated attacker can size a position such that the expected liquidation
        //    shortfall (absorbed by insurance fund) > attacker's total cost.
        return positive.mul(BaseMath.base()) < negative.mul(minCollateral);
    }
}
```

### The Settlement Context — `P1Settlement.sol` (real source)

```solidity
// File: contracts/protocol/v1/impl/P1Settlement.sol
// Source: https://github.com/dydxprotocol/perpetual/blob/master/contracts/protocol/v1/impl/P1Settlement.sol

/**
 * @dev Load context: get the oracle price, update the global funding index.
 * @return Context containing current oracle price and min collateral ratio.
 */
function _loadContext()
    internal
    returns (P1Types.Context memory)
{
    // get Price (P) — reads from the registered oracle contract
    uint256 price = I_P1Oracle(_ORACLE_).getPrice();
    // ⚠️ The oracle price here reflects the crashed YFI spot price from CEX sell pressure.
    //    When the attacker dumps YFI on Binance/OKX, this price updates accordingly,
    //    triggering _isUndercollateralized() to return true for the attacker's long position.

    // ... funding rate update ...

    return P1Types.Context({
        price: price,                      // ← crashed price from oracle
        minCollateral: _MIN_COLLATERAL_,  // ← static parameter, not liquidity-adjusted
        index: index
    });
}

/**
 * @dev Returns true if a balance is collateralized.
 *      Used in _verifyAccountsFinalBalances after every trade/liquidation.
 */
function _isCollateralized(
    P1Types.Context memory context,
    P1Types.Balance memory balance
)
    internal
    pure
    returns (bool)
{
    (uint256 positive, uint256 negative) = balance.getPositiveAndNegativeValue(context.price);

    // positive * BASE >= negative * minCollateral
    // ⚠️ When context.price crashes 30%, a large leveraged long goes deeply negative.
    //    If the resulting shortfall > insurance fund, the fund is drained entirely.
    return positive.mul(BaseMath.base()) >= negative.mul(context.minCollateral);
}
```

**Why the design is exploitable (identified from the code):**

- `P1Liquidation.trade()` has no cap on the per-liquidation insurance fund draw. When a liquidated position's loss exceeds its posted margin, the contract simply transfers whatever margin is available — the shortfall falls to the insurance fund with no on-chain limit.
- `_isCollateralized()` uses a single static `_MIN_COLLATERAL_` value that is not calibrated to individual market liquidity. For thin markets like YFI, the collateral requirement should be higher (requiring more margin per unit of position) to account for the higher price impact of forced liquidations.
- `I_P1Oracle(_ORACLE_).getPrice()` reflects the current Chainlink/weighted market price with no manipulation circuit breaker. A 30% CEX spot dump triggers the oracle update instantly, initiating forced liquidations before any protective mechanism can respond.
- The attack is therefore entirely within the contract's intended behavior: no invariant is violated, no access control is bypassed. The flaw is that the risk parameters (`_MIN_COLLATERAL_`, open interest limits) were set without accounting for the cost of an intentional large-position/thin-market manipulation strategy.

**No code fix was possible for this attack vector within the existing contract architecture.** The remediation required governance changes to open interest caps and dynamic collateral requirements — implemented in dYdX v4's off-chain risk engine.

## 3. Why This Was Profitable

The attack was economically viable because:
- The insurance fund was large enough to absorb the bad debt (attacker could extract the fund)
- YFI's spot market liquidity on CEXs allowed a determined seller to move the price significantly
- The position size needed was achievable given dYdX's open interest limits at the time
- The attacker's cost (CEX losses from selling + initial collateral) was less than the insurance fund extraction

This is a form of "insurance fund extraction" — not a smart contract bug, but an economic attack on the incentive design of a thin-market perpetuals DEX.

---
## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Thin-market perpetuals oracle manipulation draining exchange insurance fund |
| **CWE** | CWE-682: Incorrect Calculation (market risk model); CWE-400: Uncontrolled Resource Consumption |
| **OWASP DeFi** | Oracle price manipulation; insurance fund design flaw |
| **Attack Vector** | CEX spot market manipulation triggers dYdX oracle update → forced liquidations → insurance fund drain |
| **Preconditions** | Large position allowed in thin-liquidity YFI market; insurance fund large enough to make attack profitable |
| **Impact** | ~$9M insurance fund drain; no direct user losses (fund absorbed shortfall); long-term protocol solvency concern |

---
## 5. Remediation Recommendations

1. **Open interest caps per market relative to liquidity**: Position size limits should be dynamically calibrated to each market's liquidity depth, not fixed absolute limits.
2. **Market concentration risk scoring**: Before accepting large leveraged positions in thin markets, protocols should assess how much price impact would be required to create bad debt, and whether that impact is achievable by a motivated attacker.
3. **Insurance fund extraction limits**: Cap the total insurance fund payout in a single liquidation event or rolling window to limit the attacker's achievable gain.
4. **Multi-source oracle with manipulation circuit breakers**: If spot price drops by >X% within a short window (suggesting manipulation rather than organic movement), pause new position taking and trigger a time-delayed oracle price for liquidations.

---
## 6. Lessons Learned

- **Insurance funds are targets**: A large, well-funded insurance pool is an attractive target if an attacker can design a strategy to extract from it. dYdX's v3 insurance fund was publicly visible, making the attack's economics calculable in advance.
- **Economic attacks don't require smart contract bugs**: This exploit required no code vulnerability — it was a pure economic attack on the protocol's market design. Traditional audits would not catch it.
- **Thin market + high leverage = systemic risk**: Adding high-leverage perpetuals for low-liquidity assets (small-cap tokens like YFI) creates insurance fund risk even when individual position limits are set. The attack surface is the combination of leverage × thin market × large insurance fund.
- **November 2023 pattern**: An earlier attack hit dYdX's SUSHI market (~$5M profit for attacker) approximately two weeks before the YFI event. The repeated attacks suggest the attacker was testing and refining the strategy before executing the full YFI extraction. The $38M figure in some reporting refers to total YFI position liquidation volume, not a separate prior fund drain.
