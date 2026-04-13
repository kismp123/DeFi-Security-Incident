# Silo Finance Exploit — WETH Donation Inflates Interest Accrual

## Metadata
| Field | Value |
|---|---|
| Date | 2023-04-30 |
| Project | Silo Finance |
| Chain | Ethereum |
| Loss | Address Unconfirmed |
| Attacker | Address Unconfirmed |
| Attack TX | Address Unconfirmed |
| Vulnerable Contract | Silo: 0xcB3B879aB11F825885d5aDD8Bf3672596d35197C |
| Block | 17,139,470 |
| CWE | CWE-682 (Incorrect Calculation — interest accrual on donated assets) |
| Vulnerability Type | Token Donation to Inflate accrueInterest() Calculation |

## Summary
Silo Finance's `accrueInterest()` function incorrectly processed markets with zero initial deposits when tokens were donated directly to the Silo contract. By depositing a small amount of WETH and then donating a large amount, the attacker inflated the interest rate calculation, allowing uncollateralized borrowing of LINK and XAI tokens.

## Vulnerability Details
- **CWE-682**: `accrueInterest()` used `totalDeposits` from `AssetStorage` for calculations. When WETH was donated (transferred directly, not via `deposit()`), the contract balance exceeded recorded `totalDeposits`, creating a discrepancy that the interest model interpreted as accumulated interest yield, enabling artificially high borrow capacity.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: BaseSilo.sol
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";  // ❌

// ...

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";  // ❌

// ...

import "./interfaces/IInterestRateModel.sol";  // ❌

// ...

    mapping(address => AssetInterestData) private _interestData;  // ❌

// ...

        uint256 allDeposits = _assetState.totalDeposits + _assetState.collateralOnlyDeposits;  // ❌
```

```solidity
// File: IInterestRateModel.sol
    function getCurrentInterestRate(  // ❌

// ...

    function calculateCurrentInterestRate(  // ❌

// ...

    function calculateCompoundInterestRateWithOverflowDetection(  // ❌

// ...

    function calculateCompoundInterestRate(  // ❌

// ...

    function interestRateModelPing() external pure returns (bytes4);  // ❌
```

```solidity
// File: Solvency.sol
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";  // ❌

// ...

import "../interfaces/IInterestRateModel.sol";  // ❌

// ...

    function getRcomp(ISilo _silo, ISiloRepository _siloRepository, address _asset, uint256 _timestamp)

// ...

    function totalDepositsWithInterest(uint256 _assetTotalDeposits, uint256 _protocolShareFee, uint256 _rcomp)  // ❌

// ...

    function totalBorrowAmountWithInterest(uint256 _totalBorrowAmount, uint256 _rcomp)  // ❌
```

```solidity
// File: ERC20.sol
 * that a supply mechanism has to be added in a derived contract using {_mint}.  // ❌

// ...

 * We have followed general OpenZeppelin Contracts guidelines: functions revert  // ❌

// ...

    mapping(address => uint256) private _balances;  // ❌

// ...

    function balanceOf(address account) public view virtual override returns (uint256) {  // ❌
        return _balances[account];  // ❌
    }

// ...

    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        uint256 accountBalance = _balances[account];  // ❌
        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");  // ❌
        unchecked {
            _balances[account] = accountBalance - amount;  // ❌
        }
        _totalSupply -= amount;

        emit Transfer(account, address(0), amount);

        _afterTokenTransfer(account, address(0), amount);
    }
```

## Attack Flow (from testExploit())
```solidity
// 1. deposit small WETH amount via silo.deposit(WETH, smallAmount, false)
//    → totalDeposits = smallAmount
// 2. WETH.transfer(address(silo), largeAmount)
//    → contract balance >> totalDeposits (donation)
// 3. silo.accrueInterest(WETH)
//    → calculates interest on donated balance, inflating borrow capacity
// 4. From secondary account: silo.deposit(LINK, collateralAmount, true)
//    → deposit LINK as collateral-only
// 5. silo.borrow(WETH, maxAmount)
//    → borrow inflated WETH using manipulated interest state
// 6. silo.borrow(XAI, maxAmount)
//    → borrow XAI tokens exploiting same manipulated state
```

## Interfaces from PoC
```solidity
interface ISilo {
    function deposit(address asset, uint256 amount, bool collateralOnly) external returns (uint256 collateralAmount, uint256 collateralShare);
    function borrow(address asset, uint256 amount) external returns (uint256 debtAmount, uint256 debtShare);
    function accrueInterest(address asset) external;
    function assetStorage(address asset) external view returns (IBaseSilo.AssetStorage memory);
}

interface IBaseSilo {
    struct AssetStorage {
        address collateralToken;
        address collateralOnlyToken;
        address debtToken;
        uint256 totalDeposits;
        uint256 collateralOnlyDeposits;
        uint256 totalBorrowAmount;
    }
}
```

## Key Addresses
| Label | Address |
|---|---|
| Silo | 0xcB3B879aB11F825885d5aDD8Bf3672596d35197C |
| WETH | 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 |
| LINK | 0x514910771AF9Ca656af840dff83E8264EcF986CA |
| XAI | 0xd7C9F0e536dC865Ae858b0C0453Fe76D13c3bEAc |

## Root Cause
`accrueInterest()` processed interest on markets with zero recorded `totalDeposits` when the contract's actual token balance exceeded `totalDeposits` due to direct donations. The model treated the discrepancy as accrued yield, artificially inflating borrower capacity without corresponding real depositor capital.

## Fix
```solidity
function accrueInterest(address _asset) external override returns (uint256 interest) {
    AssetStorage storage _state = _assetStorage[_asset];

    // Guard: skip accrual if no deposits exist
    if (_state.totalDeposits == 0) return 0;

    // Guard: cap effective balance at recorded totalDeposits to prevent donation inflation
    uint256 effectiveBalance = IERC20(_asset).balanceOf(address(this));
    if (effectiveBalance > _state.totalDeposits + _state.totalBorrowAmount) {
        // Donations do not count as yield
        effectiveBalance = _state.totalDeposits + _state.totalBorrowAmount;
    }

    // ... rest of accrual logic using effectiveBalance
}
```

## References
- Silo Finance postmortem — block 17,139,470
- Ethereum: 0xcB3B879aB11F825885d5aDD8Bf3672596d35197C