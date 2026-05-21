# Dango — Insurance Fund Donation Logic Flaw (Perps Contract, ~$410K USDC)

| Field | Details |
|------|------|
| **Date** | 2026-04-13 |
| **Protocol** | Dango (DeFi Protocol — perps + AMM on T.E.A.M Blockchain) |
| **Chain** | T.E.A.M Blockchain (exploit); Ethereum (bridge exit via Hyperlane) |
| **Loss** | ~$410,010 USDC bridged to Ethereum; additional ~$1.49M held on-chain by bridge rate limits |
| **Root Cause** | Donation logic flaw in Dango's perpetuals insurance fund contract — the donation function failed to validate the amount credited, allowing an attacker to extract more USDC than deposited |
| **Outcome** | **White-hat resolution — 100% of funds returned; zero user losses; white-hat received bug bounty** |
| **Bridge Exit Tx 1** | [`0x06c2c3109999500fe3a0213bf33c3a1e99e3b6c86b0595d7804e57193bb4d9ae`](https://etherscan.io/tx/0x06c2c3109999500fe3a0213bf33c3a1e99e3b6c86b0595d7804e57193bb4d9ae) |
| **Bridge Exit Tx 2** | [`0x7c846ed31368320f146af1290fceafa75c29ccb33c9c652409823f8b31d071aa`](https://etherscan.io/tx/0x7c846ed31368320f146af1290fceafa75c29ccb33c9c652409823f8b31d071aa) |
| **Reference** | [Dango Incident Report](https://x.com/dango/status/2043669424805216745) |

---

## 1. Vulnerability Overview

Dango is a DeFi protocol on T.E.A.M Blockchain offering perpetuals, AMM, and cross-chain functionality. Its perpetuals contract maintains an **insurance fund** that absorbs losses when liquidated positions are under-collateralised. The insurance fund exposes a `donate()` entry point that allows external actors to top up the fund voluntarily.

On April 13, 2026, an attacker identified a **logic flaw in the insurance fund's donation accounting**: the function credited the fund (and/or the caller) with a token balance that did not match the amount actually transferred in. By calling `donate()` with crafted parameters, the attacker effectively manufactured a larger USDC credit than the tokens they deposited, then withdrew the excess.

The Ethereum-side Hyperlane Mailbox transactions (`0x06c2c3...` and `0x7c846e...`) are **bridge exit transactions** — the attacker used Hyperlane's warp route to bridge extracted USDC from T.E.A.M Blockchain to Ethereum. **Hyperlane itself was not the vulnerability**; the root cause was entirely in Dango's on-chain perps contract.

The attack extracted ~$410,010 USDC before the Hyperlane bridge rate limiter halted further outflow (~$1.49M was frozen on-chain). A white-hat researcher subsequently negotiated with the attacker and obtained a full refund; Dango paid a bug bounty.

---

## 2. Vulnerable Code Analysis

### 2.1 Donation Logic Flaw (Reconstructed Pattern)

```solidity
// VULNERABLE — Dango perps insurance fund (reconstructed from post-mortem)
contract InsuranceFund {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    IERC20 public usdc;

    // ❌ donate() credits shares before verifying actual transfer amount
    function donate(uint256 amount) external {
        uint256 sharesBefore = totalShares;

        // ❌ shares minted relative to declared `amount`, not actual tokens received
        uint256 newShares = (sharesBefore == 0)
            ? amount
            : (amount * totalShares) / usdc.balanceOf(address(this));

        shares[msg.sender] += newShares;
        totalShares += newShares;

        // Transfer executed after share calculation — attacker can manipulate
        // balanceOf snapshot or pass an inflated `amount`
        usdc.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 shareAmount) external {
        uint256 usdcOut = (shareAmount * usdc.balanceOf(address(this))) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        usdc.transfer(msg.sender, usdcOut);
    }
}
```

### 2.2 Fixed Version

```solidity
// FIXED — measure actual tokens received, not the declared amount
function donate(uint256 amount) external {
    uint256 balanceBefore = usdc.balanceOf(address(this));
    usdc.transferFrom(msg.sender, address(this), amount);
    uint256 received = usdc.balanceOf(address(this)) - balanceBefore; // ✅ actual received

    uint256 newShares = (totalShares == 0)
        ? received
        : (received * totalShares) / balanceBefore; // ✅ use pre-transfer balance

    shares[msg.sender] += newShares;
    totalShares += newShares;
}
```

---

## 3. Attack Flow

```
Attacker (on T.E.A.M Blockchain)
  │
  ├─[Step 1] Call InsuranceFund.donate() with crafted parameters
  │           Donation logic flaw credits more shares than tokens deposited
  │
  ├─[Step 2] Call InsuranceFund.withdraw() to redeem inflated shares for USDC
  │           Extract ~$1.9M USDC total from the insurance fund
  │
  ├─[Step 3 — bridge rate limiter fires at ~$1.49M on-chain]
  │           Hyperlane bridge halts further outflow
  │
  ├─[Bridge Exit Tx 1 — 0x06c2c3... on ETH]
  │   Hyperlane Mailbox.process() releases ~99,999.9 USDC to attacker on Ethereum
  │
  ├─[Bridge Exit Tx 2 — 0x7c846e... on ETH]
  │   Releases additional ~9,999.9 USDC to attacker on Ethereum
  │   Total bridged to ETH: ~$410,010 USDC
  │
  └─[White-hat Resolution]
      White-hat contacts attacker and negotiates return
      100% of funds returned to Dango protocol
      Dango pays bug bounty; zero user losses
```

---

## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Business Logic — Insurance Fund Donation Accounting Error |
| **CWE** | CWE-682: Incorrect Calculation; CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | Internal — crafted call to insurance fund donate() on T.E.A.M Blockchain |
| **DApp Category** | Perpetuals / Derivatives Protocol |
| **Chain** | T.E.A.M Blockchain (exploit); Ethereum (bridge exit) |
| **Impact** | ~$410K USDC bridged to ETH; ~$1.49M frozen on-chain; all funds returned |
| **Severity** | High (fully remediated; zero net user loss) |
| **DASP Classification** | Business Logic / Accounting Error |

---

## 5. Remediation Recommendations

1. **Measure actual tokens received**: Always compute the received amount as `balanceAfter - balanceBefore` rather than trusting a caller-supplied `amount` parameter, especially in functions that derive shares or credits from the deposited amount.
2. **Separate donation from share issuance**: Insurance fund donations that do not grant the donor redemption rights should use a simpler accounting model with no share issuance (just increment a balance tracked separately from user shares).
3. **Invariant checks**: After every deposit or withdrawal, assert that `totalShares * tokenPrice == totalTokenBalance` within an acceptable rounding tolerance.
4. **Bridge rate limits**: The Hyperlane bridge rate limit did function as intended and capped on-chain extraction to ~$410K. This is a useful defense-in-depth layer even when the primary contract is exploited.
5. **White-hat contact channel**: Dango's ability to negotiate a full refund was aided by having a clear public contact channel. Maintaining a responsible disclosure / bug bounty program materially reduces net loss.

---

## 6. Lessons Learned

- **On-chain bridge exit transactions can mislead root-cause analysis**: The two Hyperlane `Mailbox.process()` calls on Ethereum are the fund-exit path, not the exploit itself. Attributing the incident to "Hyperlane ISM bypass" was incorrect — the vulnerability was in Dango's perps contract on T.E.A.M Blockchain.
- **Donation functions are underrated attack surfaces**: Any function that mints shares or credits in exchange for an incoming token transfer must measure the actual received amount, not trust the caller's declared `amount`.
- **Bridge rate limits limit blast radius**: Though not a primary security control, the Hyperlane bridge rate limiter prevented the attacker from extracting the full ~$1.9M, containing Ethereum-side losses to ~$410K.
- **White-hat bounties are cost-effective**: Paying a bounty to recover 100% of funds cost less than the $1.49M that remained on-chain and far less than a complete loss scenario.

---

## References

- [Dango Incident Report (X)](https://x.com/dango/status/2043669424805216745)
- [AMBCrypto: Dango White Hat Resolution](https://ambcrypto.com/dango-exploit-resolved-after-white-hat-returns-funds-users-unaffected/)
- [Phemex: Dango Suffers $410K USDC Loss](https://phemex.com/news/article/dango-defi-platform-suffers-410010-usdc-exploit-due-to-logic-flaw-72936)
- [PANews: White-Hat Returns Funds](https://www.panewslab.com/en/articles/019d898e-f42a-739c-ab2a-3e26b912bbdf)
- [Bridge Exit Tx 1 — Etherscan](https://etherscan.io/tx/0x06c2c3109999500fe3a0213bf33c3a1e99e3b6c86b0595d7804e57193bb4d9ae)
- [Bridge Exit Tx 2 — Etherscan](https://etherscan.io/tx/0x7c846ed31368320f146af1290fceafa75c29ccb33c9c652409823f8b31d071aa)
