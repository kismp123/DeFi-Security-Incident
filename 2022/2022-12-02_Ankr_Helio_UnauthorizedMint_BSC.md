# Ankr / Helio — Unauthorized aBNBc Mint + Collateral Liquidation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12-02 |
| **Protocol** | Ankr Protocol / Helio Money |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$20,000,000 combined (Ankr: ~$5M in aBNBc liquidated; Helio: ~$15M HAY drained via underpriced aBNBc collateral) |
| **Attacker** | [0xF0A6adeF0a8F7B13BB22eba8D1e8a4a8b2f0a85b](https://bscscan.com/address/0xF0A6adeF0a8F7B13BB22eba8D1e8a4a8b2f0a85b) (Ankr exploiter) |
| **Vulnerable Contract** | Ankr aBNBc token (deployer key compromise); Helio HAY stablecoin (oracle delayed price update) |
| **Root Cause** | Ankr's aBNBc contract deployer private key was compromised (likely via infrastructure breach), allowing unlimited aBNBc minting. A secondary attack on Helio exploited the time lag between the aBNBc depeg and Helio's oracle price update to borrow HAY at the pre-crash aBNBc price |
| **CWE** | CWE-284: Improper Access Control (Ankr key compromise); CWE-829: Untrusted Oracle (Helio delayed price) |
| **PoC Source** | PeckShield, BlockSec, Ankr post-mortem |

---
## 1. Vulnerability Overview

This was a two-stage attack on two separate protocols that shared the aBNBc token:

**Stage 1 — Ankr aBNBc unlimited mint**: The attacker compromised Ankr's deployer/admin private key (the exact method — phishing, infrastructure breach, or insider — was not publicly confirmed). Using this key, the attacker called the aBNBc token's `mint()` function to mint **~6 quadrillion** (6×10¹⁵) aBNBc tokens, then dumped them on PancakeSwap for approximately 5,000 BNB (~$1.5M in direct profit, with aBNBc price collapsing from ~$300 to near zero).

**Stage 2 — Helio HAY drain**: Helio Money is a CDP (collateralized debt position) protocol that accepted aBNBc as collateral for minting its HAY stablecoin. Helio's oracle had a **price update delay** — it did not immediately reflect the aBNBc crash. A separate attacker (or the same attacker with a different account) quickly purchased collapsed aBNBc on the open market at near-zero prices, then used it as collateral in Helio at the stale pre-crash oracle price to borrow ~$15M in HAY stablecoins.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Ankr aBNBc — unbounded mint with single-key authorization
contract aBNBc {
    address public deployer;  // ❌ Single point of failure for minting
    
    function mint(address to, uint256 amount) external {
        require(msg.sender == deployer, "Not deployer");  // ❌ No multisig, no timelock
        _mint(to, amount);  // ❌ Unbounded mint if deployer key compromised
    }
}

// ❌ Vulnerable Helio HAY — stale oracle used during aBNBc crash
contract HelioCollateralManager {
    IPriceOracle oracle;
    
    function borrow(address collateral, uint256 amount) external {
        uint256 price = oracle.getPrice(collateral); // ❌ Oracle lags real price by minutes
        uint256 collateralValue = IERC20(collateral).balanceOf(msg.sender) * price;
        // ❌ During aBNBc crash, oracle still returns pre-crash price
        // Attacker borrows HAY at vastly inflated collateral valuation
        _mintHAY(msg.sender, amount);
    }
}

// ✅ Correct patterns:
// Ankr: Use multisig or DAO governance for mint authority; set per-period mint caps
// Helio: Use manipulation-resistant oracle with deviation threshold; halt if price drops >X% in one block
```

---
## 3. Attack Flow

```
Stage 1: Ankr Deployer Key Compromise
    │
    ├─[1] Attacker obtains Ankr deployer private key
    │       (method unconfirmed: phishing / infrastructure breach)
    │
    ├─[2] Call aBNBc.mint(attacker, 6e15) — mint 6 quadrillion aBNBc
    │
    ├─[3] Swap aBNBc for BNB on PancakeSwap
    │       aBNBc price: ~$300 → ~$0 (massive sell pressure)
    │       Direct profit: ~5,000 BNB (~$1.5M)
    │
Stage 2: Helio Stale Oracle Exploit
    │
    ├─[4] Third party (or same attacker) buys crashed aBNBc at near-zero market price
    │
    ├─[5] Deposit aBNBc into Helio as collateral
    │       Helio oracle: still showing ~$300 per aBNBc (stale)
    │       Market price: ~$0 per aBNBc
    │
    ├─[6] Borrow maximum HAY against stale collateral valuation
    │       ~$15M HAY minted against near-worthless collateral
    │
    └─[7] Swap HAY for USDC/BNB; Helio left with $15M undercollateralized debt
              Helio depegged HAY; eventually recapitalized via protocol reserves
```

---
## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type (Ankr)** | Compromised admin key enabling unbounded token mint |
| **Vulnerability Type (Helio)** | Stale oracle price lag exploited during collateral crash |
| **CWE** | CWE-284: Improper Access Control; CWE-829: Untrusted Oracle |
| **OWASP DeFi** | Key management failure; oracle manipulation |
| **Impact** | ~$5M Ankr direct loss; ~$15M Helio HAY drain; HAY stablecoin depeg |

---
## 5. Remediation Recommendations

1. **Multisig for all privileged mint functions**: No single EOA should control token minting. Require 3-of-5 or similar multisig with hardware wallets.
2. **Per-period mint caps**: Even with valid authorization, `mint()` should enforce maximum issuance per epoch (e.g., no more than 1% of supply per 24h).
3. **Oracle circuit breakers for collateral protocols**: Helio should have paused new borrows if the collateral oracle price dropped more than a threshold (e.g., 20%) within one update cycle.
4. **Multi-source oracle aggregation**: Combine DEX TWAP + Chainlink + internal checks; reject outlier inputs; refuse to use a price that diverges >threshold from the median.

---
## 6. Lessons Learned

- **Cascading exploits across composable protocols**: The Ankr compromise directly enabled the Helio exploit. When protocol A is breached and protocol B uses A's token as collateral, B is implicitly exposed to A's security failures.
- **Oracle freshness is a security property**: Helio's delayed oracle update was not a theoretical risk — it was exploited within minutes of the aBNBc price collapse. Oracles must update fast enough to prevent arbitrage against their stale values.
- **Key management is DeFi's weakest link**: Despite sophisticated smart contract design, a single compromised EOA key with admin privileges can cause catastrophic losses. Hardware security modules and on-chain multisig are mandatory for all admin functions.
- **HAY stablecoin recovery**: Helio responded by absorbing the bad debt through protocol reserves and a community-backed recapitalization, ultimately restoring the HAY peg over several weeks.
