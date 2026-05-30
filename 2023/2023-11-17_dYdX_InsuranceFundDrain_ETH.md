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
## 2a. On-Chain Source Code

> ⚠️ Contract not verified on Sourcify — source unavailable. dYdX v3 operates on StarkEx (ZK-rollup): order matching runs off-chain; settlement is handled by the StarkEx operator, not a user-facing Solidity function. There is no single Solidity `mintFor` / `depositSafe` style function that embodies the vulnerability. The attack surface is the **economic design** of the perpetuals market, not a code bug in a deployed contract.

The relevant on-chain artifacts are the StarkEx perpetuals contract (`0xD54f502e184B6B739d7D27a6410a67dc462D69c8` on Ethereum) — which handles ZK-proof settlement — and the dYdX v3 insurance fund contract. Neither contains the vulnerable logic; the flaw lies in the off-chain market risk model (open-interest limits, insurance fund sizing relative to thin-market position concentration). No Solidity source is applicable.

**not verified on Sourcify** — dYdX v3 StarkEx perpetuals (Ethereum L1 settlement contract only; vulnerable logic is off-chain)

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
