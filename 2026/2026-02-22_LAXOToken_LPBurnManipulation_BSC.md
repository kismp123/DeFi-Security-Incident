# LAXO Token — Liquidity Drain via LP Burn Trigger Mechanism Analysis

## Incident Overview

| Field | Details |
|------|------|
| **Date** | 2026-02-22 |
| **Protocol** | LAXO Token (BSC) |
| **Chain** | BNB Smart Chain |
| **Loss** | ~263,904 USDT lost by LP liquidity providers |
| **Attacker Profit** | ~137,320 USDT |
| **Attacker EOA** | [0x17f9132E66A78b93195b4B186702Ad18Fdcd6E3D](https://bscscan.com/address/0x17f9132E66A78b93195b4B186702Ad18Fdcd6E3D) |
| **Attack Contract** | [0x6588ACB7dd37887C707C08AC710A82c9F9A7C1E9](https://bscscan.com/address/0x6588ACB7dd37887C707C08AC710A82c9F9A7C1E9) |
| **Attack Tx** | [0xd58f3ef6414b59f95f55dae1acb3d5d6e626acf5333917c6d43fe422d98ac7d3](https://bscscan.com/tx/0xd58f3ef6414b59f95f55dae1acb3d5d6e626acf5333917c6d43fe422d98ac7d3) |
| **Vulnerable Contract** | [0x62951cad7659393bf07fbe790cf898a3b6d317cb](https://bscscan.com/address/0x62951cad7659393bf07fbe790cf898a3b6d317cb) (LAXO Token) |
| **Root Cause** | LAXO token's LP burn trigger mechanism — small self-transfer triggers 19x LP burn |
| **PoC Source** | Unregistered |

---

## Technical Context

**Relevant Contract Addresses (with BscScan links)**:
- LAXO Token: [0x62951cad7659393bf07fbe790cf898a3b6d317cb](https://bscscan.com/address/0x62951cad7659393bf07fbe790cf898a3b6d317cb)
- LP1 (USDT/LAXO PancakeSwap V2): [0xf05a6361e6f851bbff39c4f1d9ad4b661d3180b3](https://bscscan.com/address/0xf05a6361e6f851bbff39c4f1d9ad4b661d3180b3)
- PancakeSwap V3 Flash Source (TARGET): [0x4f31fa980a675570939b737ebdde0471a4be40eb](https://bscscan.com/address/0x4f31fa980a675570939b737ebdde0471a4be40eb)
- Profit Recipient Address: [0x6de0499e347f07582505930498d01a68b8d7ffa5](https://bscscan.com/address/0x6de0499e347f07582505930498d01a68b8d7ffa5)
- USDT (BSC): [0x55d398326f99059ff775485246999027b3197955](https://bscscan.com/address/0x55d398326f99059ff775485246999027b3197955) (18 decimals)
- WBNB: [0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c](https://bscscan.com/address/0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c)

**LAXO Token Key Characteristics**:
- Total supply: 200,000,000 LAXO (2e26 wei, 18 decimals)
- MAX_BURN(): 186,900,000 LAXO (93.45% of total supply can be burned from LP!)
- uniswapV2Pair(): 0xF05a6361e6F851BbFf39C4f1d9aD4b661d3180B3 (LP1 registered)
- enableBuy() call reverts (some functionality restricted)
- Function selector list includes `watch_tg_invmru_*` patterns (common BSC meme token template)

---

## Vulnerability Mechanism

**Core Vulnerability: LP Burn Trigger Mechanism**

The LAXO token contract can directly burn large amounts of tokens from the registered LP pair (`uniswapV2Pair`) via an internal burn function. The attacker exploited this through the following steps:

1. Transfer a small amount of LAXO to the LAXO contract's own address (2,161,718 LAXO)
2. This transfer triggers a burn of 41,072,653 LAXO from LP1 (→ 0xdead)
3. Burn ratio: 19x amplification (1 LAXO transferred → 19 LAXO burned from LP)

This causes LP1's LAXO balance to drop sharply, driving the price to spike.

---

## LP1 Reserve Data (Before and After Attack)

| Field | Just Before Attack (block-1) | After Attack (block) |
|------|---------------------|-----------------|
| USDT Balance | 420,327.57 USDT | 156,423.97 USDT |
| LAXO Balance | 95,295,738.39 LAXO | 54,218,804.94 LAXO |
| LAXO Price (USDT) | $0.004411 | $0.002884 (normalized post-manipulation) |
| USDT Loss | | -263,903.60 USDT |
| LAXO Burned | | -41,072,653.45 LAXO (→ 0xdead) |

---

## Attack Flow Detail

**PancakeSwap V3 Flash Event (log 41)**:
```
Flash(
  sender=0x6588...,
  recipient=0x6588..., 
  amount0=350,000 USDT,
  amount1=0,
  paid0=175 USDT (fee = 0.05%),
  paid1=0
)
```

**Event Log Sequence**:
1. [log 0] USDT Transfer: TARGET(PancakeV3) → EXPLOITER: 350,000 USDT (flash loan)
2. [log 2] USDT Transfer: EXPLOITER → LP1: 350,000 USDT (buy LAXO)
3. [log 4] LAXO Transfer: LP1 → 0xe256024e: 43,238,694.72 LAXO (swap output)
4. [log 8] PairCreated: PancakeFactory → LP2 newly created (LAXO/WBNB)
5. [logs 9-22] LP2 small liquidity add/remove (0.0001 BNB + dust LAXO)
6. [log 23] LAXO Transfer: 0xe256024e → EXPLOITER: 43,238,694.72 LAXO returned
7. [log 25] LAXO Transfer: EXPLOITER → LAXO Contract: 2,161,718.59 LAXO (trigger!)
8. [log 26] LAXO Transfer: LP1 → 0x000dead: 41,072,653.26 LAXO (burned! ← vulnerability)
9. [log 28] LAXO Transfer: LAXO Contract → LP1: 2,161,761.26 LAXO (redistribution)
10. [log 29] USDT Transfer: LP1 → fee: 126,408.42 USDT (LAXO transfer tax fee)
11. [log 36] LAXO Transfer: EXPLOITER → LP1: 41,072,653.26 LAXO (sell)
12. [log 37] USDT Transfer: LP1 → EXPLOITER: 487,495.18 USDT (sell proceeds)
13. [log 40] USDT Transfer: EXPLOITER → TARGET: 350,175 USDT (flash loan repayment)
14. [log 42] USDT Transfer: EXPLOITER → 0x6de0...: 137,320.18 USDT (net profit)

---

## Price Manipulation Analysis

| Step | LP1 USDT | LP1 LAXO | LAXO Price | vs. Baseline |
|------|----------|----------|-----------|------|
| Before attack | 420,327 | 95,295,738 | $0.004411 | baseline |
| After buying 43.2M LAXO | 770,328 | 52,057,044 | $0.014798 | 3.4x |
| After burning 41M from LP1 | 643,919 | 13,146,152 | $0.048982 | **11.1x** |
| After selling 41M LAXO | 156,124 | 54,218,805 | $0.002879 | 0.65x (crash) |

---

## P&L Summary

| Item | Amount |
|------|------|
| PancakeSwap V3 Flash Loan | +350,000 USDT |
| Buy 43.2M LAXO | -350,000 USDT |
| Sell 41M LAXO (price at 11.1x) | +487,495.18 USDT |
| Flash loan repayment (principal + 0.05% fee) | -350,175 USDT |
| **Net Profit** | **+137,320.18 USDT** |
| Return on Investment | 39.2% ROI |

**LP Damage**:
- USDT loss: 263,903.60 USDT (attacker 137K + fees 126K)
- LAXO burned: 41,072,653 LAXO → 0xdead (permanently burned)

---

## Vulnerable Code Pattern (Estimated)

Estimated vulnerable code pattern based on LAXO token on-chain characteristics:

```solidity
// LAXO token vulnerable code (estimated) — LP burn logic embedded in transfer hook
mapping(address => bool) private _isExcludedFromFees;
address public uniswapV2Pair;  // = registered as LP1 address
uint256 public MAX_BURN = 186_900_000 * 10**18;  // 93.45% of supply!

function _transfer(address from, address to, uint256 amount) internal override {
    // ❌ Transfer to the token contract itself triggers LP burn
    if (to == address(this)) {
        _triggerLPBurn(amount);  // ← callable by anyone!
        return;
    }
    // ...normal transfer logic
}

function _triggerLPBurn(uint256 triggerAmount) private {
    // ❌ 19x amplification: burns 19x the transferred amount from LP
    uint256 burnAmount = triggerAmount * 19;
    
    // ❌ Only MAX_BURN check exists, no access control
    if (burnAmount > MAX_BURN) burnAmount = MAX_BURN;
    
    // ❌ Burns directly from LP pair (ERC20 _burn typically only reduces balance)
    _burn(uniswapV2Pair, burnAmount);  // Direct burn from LP!
    
    // Call LP sync to update AMM reserves
    IUniswapV2Pair(uniswapV2Pair).sync();
    
    // Small redistribution
    _transfer(address(this), uniswapV2Pair, triggerAmount);
}
```

Fixed code:
```solidity
// ✅ Fix: LP burn trigger restricted to owner only
modifier onlyOwner() {
    require(msg.sender == owner(), "not owner");
    _;
}

function triggerLPBurn(uint256 amount) external onlyOwner {  // ✅ Access restricted
    // Only owner can burn from LP
    _burn(uniswapV2Pair, amount);
    IUniswapV2Pair(uniswapV2Pair).sync();
}

// ✅ Fix: Remove self-transfer trigger
function _transfer(address from, address to, uint256 amount) internal override {
    require(to != address(this), "cannot send to contract");  // ✅ Block self-transfer
    // ...normal transfer logic only
}
```

---

## Remediation Recommendations

| Vulnerability | Recommended Action |
|--------|-----------|
| No access control on LP burn | Apply `onlyOwner` or `timelock` |
| Self-transfer trigger | Add `to != address(this)` validation |
| 19x amplification factor | Strengthen burn cap and implement phased execution |
| Flash loan exposure | Set per-block burn limit (e.g., 0.1% of total supply) |

---

## Lessons Learned

1. **Tokens with LP burn functionality must always have access control validated.** In particular, when callable by anyone, it becomes an entry point for flash loan attacks.
2. **Mechanisms with a high amplification factor are extremely dangerous.** A 19x multiplier enables large-scale price manipulation with minimal capital.
3. **Auto-burn mechanisms in BSC "reflection" tokens must undergo verified audits.** Tokens containing suspicious functions such as `watch_tg_invmru_*` patterns are difficult to trust.
4. **Modifying internal state before calling `sync()` on an AMM is a price manipulation vector.** Changing an LP's token balance and then calling `sync()` force-updates the AMM's reserves, manipulating the price.

---

## On-Chain Verification

### Attack Block Information
- Block: 82730141
- Timestamp: 2026-02-22 15:32:44 UTC

### PoC vs. On-Chain Amount Comparison

| Item | On-Chain Actual Value |
|------|-------------|
| Flash loan USDT | 350,000 USDT (PancakeSwap V3) |
| Flash loan fee | 175 USDT (0.05%) |
| LAXO buy price | 350,000 USDT → 43,238,694.717 LAXO |
| LP burn trigger | 2,161,718.592 LAXO → 0x62951cad |
| LP1 burn amount | 41,072,653.255 LAXO → 0xdead |
| Amplification factor | ~19x |
| Sell proceeds | 487,495.177 USDT |
| Flash loan repayment | 350,175 USDT |
| Net profit | 137,320.177 USDT |

### Preconditions

| Item | Pre-Attack State |
|------|-------------|
| LP1 USDT Balance | 420,327.57 USDT |
| LP1 LAXO Balance | 95,295,738.39 LAXO |
| LAXO Price | $0.004411/LAXO |
| LAXO MAX_BURN | 186,900,000 LAXO (93.45% of 200M) |