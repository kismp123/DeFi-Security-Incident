# BetterBank — Rogue LP Pool Exploits Unchecked Bonus Minting on PulseChain (~$5M)

| Item | Details |
|------|------|
| **Date** | 2025-08-26 |
| **Protocol** | BetterBank (FAVOR / ESTEEM reward ecosystem, PulseChain) |
| **Chain** | PulseChain (chainId 369) |
| **Loss** | ~$5,000,000 |
| **Root Cause** | Business Logic Flaw — the FAVOR token's bonus minting system (FavorRouterWrapper) did not validate the legitimacy of the AMM pool used for trading, allowing an attacker-created rogue LP pair to trigger unlimited ESTEEM bonus minting with zero sell tax |
| **Attack Tx** | `0x74534b1f86a63c6c722d5845f2b4c08867c2e66b922a6c95cd6b4290664c19bd` |
| **Attack Tx 2** | `0x9c7237a00fa276c5f10ca1c61d6821869a7fdcd1ade8059729cdc35c9ff7689a` |
| **Reference** | [shoucccc on Twitter](https://x.com/shoucccc/status/1960534610485633369) |

---

## 1. Vulnerability Overview

BetterBank is a DeFi reward ecosystem on PulseChain centered around the FAVOR token (PLSF) and its companion ESTEEM bonus token. The FAVOR protocol includes a `FavorRouterWrapper` contract (`0x30dcc4e72dcd2702449190ce8b88d21f2178cd9c`) that intercepts FAVOR trades on AMM pools, records buy/sell volumes, and mints ESTEEM bonus tokens to buyers at a configured rate. Additionally, FAVOR normally charges a 50% sell tax — but the tax logic reads from the LP pair contract to determine whether a transaction is a sell; it does not validate whether the LP pair itself is on the official/authorized pool whitelist.

The attacker exploited this gap by deploying a worthless attacker-controlled token (`0xff7f62dc531d709863bc23d7423de11694aa3ab8`) and creating a custom PulseXPair LP pool pairing FAVOR with this junk token. Since the junk token has no real value:
1. No sell tax applies — FAVOR sold into this rogue pool does not trigger the 50% tax logic, because the pair contract is not the official FAVOR/WPLS pair.
2. The FavorRouterWrapper records trades on this rogue LP as legitimate FAVOR buy volume and mints ESTEEM bonus tokens at the maximum rate.

The attacker called FavorRouterWrapper 101 times via a cyclic buy/claim loop (`0xc45c87bd` + `0x10f04583` alternating selectors), accumulating a massive ESTEEM balance, then redeemed ESTEEM for real PulseChain assets (DAI, PLSX, WPLS) totaling ~$5M.

---

## 2. Vulnerable Code Analysis

### FavorRouterWrapper — Rogue LP Not Validated (Reconstructed)

```solidity
// FavorRouterWrapper — VULNERABLE
// Records trades from any AMM pair that holds FAVOR, minting ESTEEM to buyers.
function swapAndRecord(
    address pair,           // LP pair address — caller-supplied
    uint256 favorAmount,
    address buyer
) external {
    // BUG: 'pair' is caller-controlled.
    // No check that 'pair' is the official FAVOR/WPLS or FAVOR/USDC pool.
    // Any PulseXPair containing FAVOR qualifies — including attacker-created pairs.

    // Perform swap via PulseXRouter using the supplied pair
    IPulseXRouter(ROUTER).swapExactTokensForTokens(
        favorAmount, 0, [FAVOR, junkToken], address(this), block.timestamp
    );

    // Mint ESTEEM bonus to buyer proportional to trade size
    // Since junkToken pair has no sell tax, attacker nets full FAVOR back via a
    // reverse swap, while still claiming ESTEEM bonus for the "buy"
    uint256 bonus = favorAmount * ESTEEM_RATE / 1e18;
    ESTEEM.mint(buyer, bonus);
}

// FAVOR sell tax — only applies to the official pair; rogue pair bypasses it
function _transfer(address from, address to, uint256 amount) internal override {
    if (isPair[to] && to == OFFICIAL_FAVOR_WPLS_PAIR) {
        // BUG: tax only checked against official pair
        // Selling into rogue pair: to == rogueAttackerPair → no tax applied
        uint256 tax = amount * 50 / 100;
        super._transfer(from, TREASURY, tax);
        super._transfer(from, to, amount - tax);
    } else {
        super._transfer(from, to, amount);  // no tax for rogue pair sells
    }
}
```

### Fixed Version

```solidity
// Fixed: maintain a whitelist of authorized LP pairs
mapping(address => bool) public authorizedPairs;

function addAuthorizedPair(address pair) external onlyOwner {
    authorizedPairs[pair] = true;
}

function swapAndRecord(
    address pair,
    uint256 favorAmount,
    address buyer
) external {
    // Reject swaps through unauthorized LP pairs
    require(authorizedPairs[pair], "pair not authorized");

    // Now safe to proceed: only official pools can trigger bonus minting
    ...
}

// Apply sell tax to ALL pairs, not just the official one
function _transfer(address from, address to, uint256 amount) internal override {
    if (to != address(this) && authorizedPairs[to]) {
        uint256 tax = amount * 50 / 100;
        super._transfer(from, TREASURY, tax);
        super._transfer(from, to, amount - tax);
    } else {
        // Unknown pair — treat as sell for tax purposes
        if (_isPotentialSell(to)) {
            uint256 tax = amount * 50 / 100;
            super._transfer(from, TREASURY, tax);
            super._transfer(from, to, amount - tax);
        } else {
            super._transfer(from, to, amount);
        }
    }
}
```

---

## 3. Attack Flow

```
Attacker (0x48c9f537...)
  │
  ├─[Pre-attack] Deploy worthless junk token (0xff7f62dc...)
  │             Create PulseXPair: FAVOR / junk token
  │             This rogue LP is not on BetterBank's authorized pool list
  │
  ├─[Tx 1 — 0x9c7237...] Deploy first exploit contract (0x18Dd9E3F...)
  │                       Test: call FavorRouterWrapper via rogue LP
  │                       Claim initial ESTEEM bonus (~DAI proceeds to attacker)
  │
  ├─[Tx 2 — 0x74534b...] Deploy main exploit contract (0x792CDc4...)
  │   │
  │   ├─[101× loop] Alternate calls to FavorRouterWrapper:
  │   │   ├─ 0xc45c87bd: swap FAVOR into rogue pair (no sell tax, no sell detection)
  │   │   └─ 0x10f04583: claimBonus() — mint ESTEEM at maximum rate
  │   │
  │   └─ ESTEEM accumulated → redeemed for real assets:
  │       DAI: ~890,874,504 DAI
  │       PLSX: ~9,051,537,270 PLSX
  │       WPLS: ~7,409,330,692 WPLS
  │       Total: ~$5M
  │
  └─[Result] ~$5M extracted via 101-iteration rogue LP bonus farming loop
             BetterBank ESTEEM redemption pool drained; protocol insolvent
```

---

## 4. Vulnerability Classification

| Category | Details |
|------|------|
| **Type** | Business Logic Flaw — Unchecked Bonus Minting via Unauthorized LP Pool |
| **Severity** | Critical |
| **CWE** | CWE-284 (Improper Access Control); CWE-840 (Business Logic Errors) |
| **Attack Pattern** | Rogue LP pool creation + iterative swap/claim loop (101 iterations) |
| **Chain** | PulseChain (chainId 369) |

---

## 5. Remediation Recommendations

- **LP pool whitelist**: The `FavorRouterWrapper` must maintain a whitelist of authorized AMM pairs. Any call referencing an unauthorized pair should revert immediately. This single change prevents the entire attack vector.
- **Sell tax must apply universally**: The 50% sell tax logic must apply to transfers to **any** external address that could be an AMM pair, not only the known official pair. Use a registry of pairs and apply tax to all of them, or apply the tax by default when the recipient is a non-EOA contract that is not whitelisted as a known safe recipient.
- **Rate limit bonus minting**: Apply a per-block or per-epoch cap on total ESTEEM minted. 101 iterations of bonus claiming in a single block should trigger a circuit breaker.
- **Monotonicity invariant**: Maintain an invariant that total ESTEEM outstanding is always backed by a corresponding real asset reserve. Automated invariant monitoring would have flagged the 101-iteration loop as anomalous.
- **Redeem caps**: Limit how much ESTEEM can be redeemed against the protocol's real asset reserves in a single transaction or per block.

---

## 6. Lessons Learned

- **Caller-controlled pool addresses are dangerous**: Whenever an address parameter specifies which LP pool to interact with, and that pool affects reward calculations or tax logic, it must be validated against a whitelist. User-supplied addresses should never have trust without verification.
- **Tax evasion via unofficial pools is a known BSC/PulseChain pattern**: Multiple exploits have used rogue LP pairs to bypass sell taxes. On chains with high numbers of user-deployed tokens and AMM pools (PulseChain, BSC), this attack surface is particularly wide.
- **Iterative loops amplify logic flaws**: A bug that yields a small profit per call becomes catastrophic when exploited in a tight loop. Protocol invariants should be checked at the transaction level, not just per call.
- **Fee-on-transfer and reflection mechanics add complexity**: Protocols built around transfer-tax tokens must model all the paths through which tokens flow, including adversarially crafted pools designed to circumvent the tax routing logic.

---

## References

- [shoucccc on Twitter](https://x.com/shoucccc/status/1960534610485633369)
- [PulseChain Explorer — Attack Tx](https://scan.pulsechain.com/tx/0x74534b1f86a63c6c722d5845f2b4c08867c2e66b922a6c95cd6b4290664c19bd)
- [PulseChain Explorer — Attack Tx 2](https://scan.pulsechain.com/tx/0x9c7237a00fa276c5f10ca1c61d6821869a7fdcd1ade8059729cdc35c9ff7689a)
- [FavorRouterWrapper Contract](https://scan.pulsechain.com/address/0x30dcc4e72dcd2702449190ce8b88d21f2178cd9c)
