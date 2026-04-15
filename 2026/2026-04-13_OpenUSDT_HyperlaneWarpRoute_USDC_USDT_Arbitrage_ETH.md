# OpenUSDT (oUSDT) — Hyperlane Warp Route USDC/USDT Peg Arbitrage

| Item | Details |
|------|------|
| **Date** | 2026-04-13 |
| **Protocol** | OpenUSDT (oUSDT) / Hyperlane Warp Routes |
| **Chains** | Ethereum (unwrap leg), Base (mint leg), Celo (redeem leg) |
| **Loss** | ~410,010 USDC extracted on Ethereum across 8 withdrawals (representative attacker; open vulnerability enabled repeated arbitrage) |
| **Attacker EOA** | [0x8Fb45368...290E](https://etherscan.io/address/0x8Fb453687947adb8135ba7d4A739B11d2095290E) |
| **Profit Sink EOA** | [0x271d1f2f...762A](https://etherscan.io/address/0x271d1f2f4194E61f2a17Ea82D82e31cEA9f6762A) |
| **Vulnerable Warp Route (ETH USDC)** | [0xd0590985...f36c](https://etherscan.io/address/0xd05909852aE07118857f9D071781671D12c0f36c) (TransparentUpgradeableProxy) |
| **Related Prior Attacker (GitHub #5639 example)** | 0x9800511C5082C3aA6F4335A75dC78b1A87eA307A |
| **Attack Block Range** | 24,869,021 – 24,869,783 |
| **Root Cause** | oUSDT warp route mints oUSDT 1:1 against USDC on Base but oUSDT is redeemable 1:1 for native USDT on Celo — USDC/USDT price divergence becomes free arbitrage |

---

## 1. Vulnerability Overview

OpenUSDT (oUSDT) is Hyperlane's Superchain stablecoin. Its warp route accepts **USDC** as collateral on Base and issues oUSDT at a **hard-coded 1:1 rate**, while on Celo the same oUSDT is backed by / redeemable for **native USDT** at 1:1.

Because USDC and USDT trade at slightly different prices on spot markets (~0.9998 USDT per USDC on Binance at attack time), minting oUSDT with USDC at 1.0 and redeeming it for USDT at 1.0 on Celo creates a **risk-free positive spread** of ~$200 per $1,000,000 cycle, repeatable indefinitely.

The Ethereum-side USDC warp route proxy (`0xd059...f36c`) is the exit liquidity the attacker drew from when unwinding positions back to USDC on mainnet.

---

## 2. Attack Flow

```
┌──────────────────────────────────────────────────────────────────┐
│ (1) Base: deposit N USDC → Hyperlane oUSDT warp route           │
│     mint N oUSDT                     (fixed 1:1, ignores market) │
├──────────────────────────────────────────────────────────────────┤
│ (2) Bridge oUSDT (Base → Celo) via Hyperlane (cents of gas)     │
├──────────────────────────────────────────────────────────────────┤
│ (3) Celo: burn N oUSDT → receive N USDT                         │
│     (USDT market price > USDC by ~0.02%)                         │
├──────────────────────────────────────────────────────────────────┤
│ (4) Sell USDT for USDC on Celo DEX or bridge out to Ethereum    │
│     USDC Hyperlane warp route (0xd059…f36c) and withdraw         │
├──────────────────────────────────────────────────────────────────┤
│ (5) Net profit ≈ (priceUSDT − priceUSDC) × N, repeat            │
└──────────────────────────────────────────────────────────────────┘
```

### 2.1 Observed Ethereum-side USDC Withdrawals

Subject EOA `0x8Fb4…290E` triggered the USDC warp route proxy which released USDC to sink `0x271d…762A`:

| # | Tx Hash | Block | USDC Out |
|---|---------|-------|----------|
| 1 | 0x2ebfd1cd…dfc9c8 | 24,869,021 | 10.9 |
| 2 | 0x9f0ab90c…bce190 | 24,869,219 | 49,999.9 |
| 3 | 0x09690b50…cde350 | 24,869,224 | 99,999.9 |
| 4 | 0xc74ad3c3…46ec2 | 24,869,228 | 99,999.9 |
| 5 | 0xbf51b9b0…55205 | 24,869,237 | 29,999.9 |
| 6 | 0xa7f9754a…eb342 | 24,869,594 | 19,999.9 |
| 7 | 0x7c846ed3…071aa | 24,869,596 | 99,999.9 |
| 8 | 0x06c2c310…b4d9ae | 24,869,783 | 9,999.9 |
| **Σ** | | | **~410,010.2 USDC** |

Tx #1 (10.9 USDC) is a probe; subsequent txs are full cycles. Each withdrawal rounds to `…99900000` (10 bps spread), consistent with programmatic arbitrage batching rather than a one-shot vault drain.

---

## 3. Vulnerable Design

### 3.1 Fixed-rate mint against wrong asset

```
// Pseudocode of the Base oUSDT warp route
function mint(uint256 usdcAmount) external {
    USDC.transferFrom(msg.sender, address(this), usdcAmount);
    _mintOUsdt(msg.sender, usdcAmount);     // ❌ 1:1 against USDC
}
```

On Celo:

```
function redeem(uint256 oUsdtAmount) external {
    _burnOUsdt(msg.sender, oUsdtAmount);
    USDT.transfer(msg.sender, oUsdtAmount); // ❌ 1:1 against USDT
}
```

Both sides are 1:1, but the **collateral asset differs** (USDC ↔ USDT), so any non-zero USDC/USDT basis is pocketed by the caller.

### 3.2 Why it is structurally drainable

- USDC and USDT are not the same asset; their cross rate is a free market parameter (~0.9998).
- Hyperlane warp route economics assume perfect peg of underlying collateral.
- Bridging oUSDT is nearly free (only Hyperlane messaging gas) so the per-cycle cost is dominated by fixed gas, making it profitable for N ≥ ~$50K.
- The warp route imposes **no slippage, oracle, or rate-limit** on the mint/redeem path.

---

## 4. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|---------------|----------|-----|
| V-01 | Fixed 1:1 mint of oUSDT against USDC while oUSDT ↔ USDT 1:1 elsewhere | HIGH | CWE-682 (Incorrect Calculation) |
| V-02 | Missing peg/oracle check on multi-collateral redemption | HIGH | CWE-20 (Improper Input Validation) |
| V-03 | No per-tx / per-epoch rate limits on warp route | MEDIUM | CWE-770 (Allocation without Limits) |

### V-01 / V-02
Treating two distinct stablecoins as fungible at a fixed ratio leaks the market spread to arbitrageurs. A Chainlink USDC/USDT feed or a TWAP-based peg check would neutralize the attack.

### V-03
Without rate limits on the warp route's mint/burn, the exploit scales linearly with attacker capital; a per-block cap forces the attacker into many more transactions, shrinking net profit after gas and increasing detection time.

---

## 5. Remediation (per Hyperlane issue #5639)

1. **Disable oUSDT minting from USDC on Base** — only allow USDT as collateral input so oUSDT is fully backed by the same asset it redeems to.
2. **Introduce a peg oracle** — if cross-collateral mint is desired, price the input asset via Chainlink and mint oUSDT at the oracle ratio minus a safety buffer.
3. **Per-epoch mint / redeem caps** on warp routes to bound single-attacker throughput.
4. **Circuit breaker** triggered by sustained one-way flow (mint-on-Base-vs-redeem-on-Celo imbalance).

---

## 6. Lessons Learned

1. **Multi-collateral stablecoin bridges are arbitrage magnets**: fixing a 1:1 exchange across two near-pegged but distinct assets is always exploitable by the basis.
2. **"Hard peg" is not the same as "real peg"**: USDC ≠ USDT. Any protocol that assumes they are interchangeable at par loses money on every cycle.
3. **Warp routes need oracles**: permissionless mint/burn of a wrapped asset must consult an external price feed whenever the underlying and the redemption asset differ.
4. **Small spread × unlimited capital = real loss**: a 2 bp spread is trivial per cycle but unbounded in aggregate. Rate-limiting is a necessary defense-in-depth layer.

---

## 7. Additional Information

- **GitHub report**: hyperlane-xyz/hyperlane-monorepo issue #5639 ("Arbitrage Exploit Risk in oUSDT Minting Mechanism — disable oUSDT minting via USDC on Base")
- **Documented precedent**: wallet `0x9800511C5082C3aA6F4335A75dC78b1A87eA307A` executed a 169,999.9 USDC arbitrage cycle using the same flow prior to this batch.
- **Same-day unrelated incident**: Hyperbridge (distinct from Hyperlane) Token Gateway forged-MMR-proof exploit (~$237K loss in bridged DOT on Ethereum).
- **Chain ID map**: Ethereum mainnet (1), Base (8453), Celo (42220).

| Address | Role |
|---------|------|
| 0x8Fb453687947adb8135ba7d4A739B11d2095290E | Attacker EOA (tx subject) |
| 0x271d1f2f4194E61f2a17Ea82D82e31cEA9f6762A | Attacker profit sink (USDC recipient) |
| 0xd05909852aE07118857f9D071781671D12c0f36c | Hyperlane USDC warp route proxy on Ethereum |
| 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 | USDC (Ethereum) |
