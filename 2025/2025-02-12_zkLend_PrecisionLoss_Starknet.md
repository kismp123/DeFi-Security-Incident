# zkLend — Precision Loss / Share Inflation Attack on Starknet Money Market

| Field | Details |
|------|------|
| **Date** | 2025-02-12 |
| **Protocol** | zkLend |
| **Chain** | Starknet |
| **Loss** | ~$9,500,000 |
| **Attacker EOA** | (Starknet address — see attack tx) |
| **Vulnerable Contract** | zkLend zToken lending pool |
| **Root Cause** | Precision loss in accumulator-based share calculation: an empty pool can be seeded with 1 wei of shares, then artificially inflated via direct donation, allowing an attacker to borrow far more than their collateral is legitimately worth |
| **Attack Tx** | [`0x0160a5841b3e99679691294d1f18904c557b28f7d5fe61577e75c8931f34a16f`](https://starkscan.co/tx/0x0160a5841b3e99679691294d1f18904c557b28f7d5fe61577e75c8931f34a16f) |
| **Trace Source** | [zkLend official statement](https://x.com/zklend/status/1890389052492509362) |

---

## 1. Vulnerability Overview

zkLend is a money market lending protocol on Starknet. On February 12, 2025, an attacker exploited a precision loss vulnerability — the same class of inflation attack seen in Compound v2 forks and ERC4626 vault implementations — to borrow approximately $9.5M in excess assets.

zkLend's lending pools track user deposits as "z-shares" using an accumulator system. When the pool is empty (or `totalShares` is very small), the share price is determined purely by the ratio of `totalAssets` to `totalShares`. An attacker can:

1. Be the first depositor, obtaining shares at a 1:1 ratio.
2. Donate assets directly to the pool contract without going through the deposit function, inflating `totalAssets` while leaving `totalShares` unchanged.
3. Use the now-inflated share value as collateral to borrow against, receiving far more than the attacker's actual economic contribution.

This is a classic first-depositor share inflation attack (also known as "ERC4626 inflation attack" or "Compound v2 donation attack"). The root cause is integer division truncation: when `totalAssets` is large and `totalShares` is 1, any subsequent depositor who deposits less than `totalAssets` receives 0 shares due to rounding, while the single existing shareholder's position is worth the entire pool.

---

## 2. Vulnerable Code Analysis

> ⚠️ Contract not verified on Sourcify — Starknet is a non-EVM chain (Cairo language); Sourcify does not index Starknet contracts. The code below is Cairo pseudocode reconstructed from zkLend's official post-mortem, the attack transaction trace, and the known ERC4626 inflation attack pattern. It is not retrieved verified source.

### Share Minting Logic (Cairo pseudocode)

```cairo
// zToken deposit — vulnerable accumulator math
fn deposit(ref self: ContractState, amount: u256) {
    let total_supply = self.total_supply.read();
    let total_assets = self.total_assets.read();  // includes direct donations

    let shares = if total_supply == 0 {
        // First depositor: 1:1 ratio — attacker gets 1 share for 1 wei
        amount
    } else {
        // BUG: integer division truncates toward zero.
        // If total_assets was inflated by donation, subsequent depositors
        // round down to 0 shares. The first (attacker) share is now worth
        // the entire pool.
        amount * total_supply / total_assets
    };

    // Mint shares and update state
    self._mint(get_caller_address(), shares);
    self.total_assets.write(total_assets + amount);
}
```

### Why Direct Donation Inflates Share Price

```cairo
// Direct token transfer bypasses deposit(), increasing total_assets
// without minting new shares:
//
//   IERC20(underlying).transfer(zToken_contract, large_amount);
//
// After donation:
//   total_assets = 1 (deposited) + large_amount (donated)
//   total_supply = 1 (attacker's share)
//
// Attacker's 1 share is now redeemable for (1 + large_amount) assets.
// Borrow function uses share value as collateral → attacker borrows
// large_amount + profit while only economically at risk for 1 wei deposit.
```

### Borrow Collateral Valuation (simplified)

```cairo
fn get_collateral_value(account: ContractAddress) -> u256 {
    let shares = self.shares_of(account);
    let total_supply = self.total_supply.read();
    let total_assets = self.total_assets.read();

    // BUG: total_assets includes donated funds not belonging to depositor
    // shares=1, total_supply=1, total_assets=(donation + 1 wei)
    // → collateral_value = full pool (donation amount)
    shares * total_assets / total_supply
}
```

### Fixed Version

```cairo
// Mitigation 1: virtual shares — add 1 to both numerator and denominator
fn deposit(ref self: ContractState, amount: u256) {
    let total_supply = self.total_supply.read();
    let total_assets = self.total_assets.read();

    // Virtual offset makes inflation attack economically infeasible:
    // attacker would need to donate 2^N times the minimum deposit
    let shares = (amount * (total_supply + VIRTUAL_SHARES))
        / (total_assets + VIRTUAL_ASSETS);

    self._mint(get_caller_address(), shares);
    self.total_assets.write(total_assets + amount);
}

// Mitigation 2: require minimum initial deposit burned to dead address
// so total_supply is never near 0 after first interaction
```

---

## 3. Attack Flow

```
Attacker
  │
  ├─[1] Identify near-empty zkLend pool (totalShares ≈ 0)
  │
  ├─[2] Deposit 1 wei of underlying token
  │       → receive 1 share (1:1 ratio, first depositor path)
  │       totalShares = 1, totalAssets = 1 wei
  │
  ├─[3] Donate large amount X directly to zToken contract
  │       → transfer(zToken, X) — does NOT call deposit()
  │       totalShares = 1 (unchanged)
  │       totalAssets = 1 wei + X (inflated)
  │
  ├─[4] Attacker's 1 share is now valued at (X + 1 wei)
  │       Collateral value = full inflated pool
  │
  ├─[5] Call borrow() against inflated collateral
  │       Borrow limit based on share value = X + 1 wei
  │       Attacker borrows Y ≈ X × LTV ratio
  │
  ├─[6] Profit = Y - (1 wei deposit + X donation)
  │       Net gain only if Y > X + 1 wei (achieved when LTV > 100%
  │       relative to donation, which the inflated accounting permits)
  │
  ├─[7] Repeat across multiple pools / asset pairs
  │
  └─[8] Total extracted: ~$9,500,000
          zkLend pauses protocol and begins post-mortem investigation
```

---

## 4. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Precision Loss / Share Inflation (First-Depositor Attack) |
| **CWE** | CWE-682: Incorrect Calculation; CWE-190: Integer Overflow or Wraparound (truncation) |
| **Attack Vector** | External — no flash loan required; direct token donation + small initial deposit |
| **DApp Category** | Lending / Money Market |
| **Chain** | Starknet (Cairo language) |
| **Impact** | Excess borrowing against artificially inflated collateral — protocol insolvency |
| **Severity** | Critical |
| **DASP Classification** | Arithmetic Issues / Business Logic Error |
| **Related CVEs / Attacks** | Compound v2 donation attack, ERC4626 inflation attack (EIP-4626 reference implementation), Silo Finance first-depositor issue |

---

## 5. Remediation Recommendations

1. **Virtual shares offset**: Add a constant `VIRTUAL_SHARES` (e.g., 1000) and `VIRTUAL_ASSETS` to both sides of the share calculation. This makes the economic cost of inflation attacks scale with the virtual offset, rendering them unprofitable.
2. **Minimum initial liquidity**: Require the deployer to permanently lock a minimum amount of shares (burned to `address(0xdead)`) at pool creation. This ensures `totalSupply` is never trivially small.
3. **Track internal balance separately**: Maintain an internal `stored_assets` variable updated only by deposit/withdraw functions. Do not read `token.balanceOf(address(this))` directly for share price calculations, since direct transfers bypass accounting.
4. **Borrow cap per block**: Limit total borrows in a single block to a configurable fraction of pool TVL. This does not fix the root cause but limits blast radius.
5. **First-depositor check**: If `totalSupply == 0` after a deposit, enforce that the deposit amount exceeds a minimum threshold (e.g., 10^18 wei) to prevent dust-seed attacks.
6. **Formal verification of share math**: Cairo's felt252 and u256 types have different overflow semantics than Solidity. Formally verify all fixed-point arithmetic functions against an overflow-free specification.

---

## 6. Lessons Learned

- **ERC4626-class inflation attacks are not EVM-specific**: The same first-depositor precision loss pattern that affected Compound v2 forks on Ethereum manifests identically in Cairo-based money markets on Starknet. Protocols on any chain must explicitly defend against it.
- **Direct token transfers are a persistent threat surface**: Any contract that uses `balanceOf(address(this))` for pricing must account for the fact that anyone can donate tokens without going through the protocol's accounting functions.
- **Virtual shares are the standard industry fix**: OpenZeppelin's ERC4626 implementation introduced virtual shares after the inflation attack class was documented. Protocol teams should adopt this pattern or an equivalent before mainnet deployment.
- **Empty pools are especially vulnerable**: Inflation attacks require a near-zero initial state. Protocols should either seed pools at deployment or treat the first-depositor case as a special critical path requiring extra validation.
- **Starknet's ecosystem maturity**: At the time of the exploit, auditing tooling and security research coverage for Cairo contracts lagged behind the EVM ecosystem. Teams deploying to Starknet should apply known EVM attack patterns proactively rather than waiting for them to be rediscovered on-chain.

---

## References

- [zkLend Official Statement (Twitter/X)](https://x.com/zklend/status/1890389052492509362)
- [Attack Transaction on Starkscan](https://starkscan.co/tx/0x0160a5841b3e99679691294d1f18904c557b28f7d5fe61577e75c8931f34a16f)
- [ERC4626 Inflation Attack — OpenZeppelin Blog](https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks)
- [Compound v2 Donation Attack Analysis](https://dacian.me/lending-borrowing-defi-attacks#heading-first-depositor-inflation-attack)
