# Bao Finance Exchange Rate Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Bao Finance (bdbSTBL) |
| Date | 2023-07-01 |
| Chain | Ethereum Mainnet |
| Loss | ~$46,000 USD |
| Attack Type | Flash Loan + Exchange Rate Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x00693a01221a5e93fb872637e3a9391ef5f48300` |
| Attack Contract | `0x3f99d5cd830203a3027eb0ed6548db7f81c3408f` |
| Vulnerable Contract | `0xb0f8fe96b4880adbdede0ddf446bd1e7ef122c4e` (bdbSTBL) |
| Attack TX | `0xdd7dd68cd879d07cfc2cb74606baa2a5bf18df0e3bda9f6b43f904f4f7bbdfc1` |
| Fork Block | 17,620,870 |

## 2. Vulnerable Code Analysis

Bao Finance's bdbSTBL contract used Balancer pool-based collateral, and its exchange rate could be manipulated via token donations. By directly transferring a large amount of tokens to inflate the contract's asset/share ratio, an attacker could then borrow an excessive amount of ETH against the inflated collateral.

```solidity
// Vulnerable pattern: exchange rate calculated from raw balance
function exchangeRate() public view returns (uint256) {
    uint256 totalSupply = totalSupply();
    if (totalSupply == 0) return initialRate;

    // Vulnerable: totalAssets includes directly transferred tokens
    uint256 totalAssets = IERC20(underlying).balanceOf(address(this));
    return totalAssets * 1e18 / totalSupply;  // manipulable
}

function borrow(uint256 amount) external {
    uint256 collateral = balanceOf(msg.sender) * exchangeRate() / 1e18;
    require(collateral >= amount * collateralFactor, "Insufficient collateral");
    // Inflated exchangeRate() allows excessive borrowing
    _transfer(underlying, msg.sender, amount);
}
```

**Vulnerability**: Because `exchangeRate()` reads directly from the contract balance, a donation attack can manipulate the rate and enable excessive borrowing.

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: CToken.sol
    function exchangeRateStored() public view returns (uint);  // ❌

// ...

     * @dev This function does not accrue interest before calculating the exchange rate  // ❌

// ...

    function exchangeRateStored() public view returns (uint) {  // ❌
        (MathError err, uint result) = exchangeRateStoredInternal();  // ❌
        require(err == MathError.NO_ERROR, "exchangeRateStored: exchangeRateStoredInternal failed");  // ❌
        return result;
    }

// ...

     * @dev This function does not accrue interest before calculating the exchange rate  // ❌

// ...

    function exchangeRateStoredInternal() internal view returns (MathError, uint) {  // ❌
        uint _totalSupply = totalSupply;
        if (_totalSupply == 0) {
            /*
             * If there are no tokens minted:
             *  exchangeRate = initialExchangeRate  // ❌
             */
            return (MathError.NO_ERROR, initialExchangeRateMantissa);  // ❌
        } else {
            /*
             * Otherwise:
             *  exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply  // ❌
             */
            uint totalCash = getCashPrior();
            uint cashPlusBorrowsMinusReserves;
            Exp memory exchangeRate;  // ❌
            MathError mathErr;

            (mathErr, cashPlusBorrowsMinusReserves) = addThenSubUInt(totalCash, totalBorrows, totalReserves);
            if (mathErr != MathError.NO_ERROR) {
                return (mathErr, 0);
            }

            (mathErr, exchangeRate) = getExp(cashPlusBorrowsMinusReserves, _totalSupply);  // ❌
            if (mathErr != MathError.NO_ERROR) {
                return (mathErr, 0);
            }

            return (MathError.NO_ERROR, exchangeRate.mantissa);  // ❌
        }
    }
```

```solidity
// File: CErc20Delegator.sol
     * @param initialExchangeRateMantissa_ The initial exchange rate, scaled by 1e18  // ❌

// ...

                uint initialExchangeRateMantissa_,  // ❌

// ...

                                                            initialExchangeRateMantissa_,  // ❌

// ...

     * @dev This function does not accrue interest before calculating the exchange rate  // ❌

// ...

    function exchangeRateStored() public view returns (uint) {  // ❌
        bytes memory data = delegateToViewImplementation(abi.encodeWithSignature("exchangeRateStored()"));  // ❌
        return abi.decode(data, (uint));
    }
```

```solidity
// File: ErrorReporter.sol
    function failOpaque(Error err, FailureInfo info, uint opaqueError) internal returns (uint) {
        emit Failure(uint(err), uint(info), opaqueError);

        return uint(err);
    }
```

## 3. Attack Flow

```
Attacker [0x00693a01221a5e93fb872637e3a9391ef5f48300]
  │
  ├─1─▶ Aave V2.flashLoan() [0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9]
  │      Borrow 17.55M USDC + 17.51M DAI
  │
  ├─2─▶ Deposit USDC/DAI into Aave V2
  │
  ├─3─▶ Balancer.joinPool() → receive bSTBL shares
  │      [bSTBL: 0x5ee08f40b637417bcC9d2C51B62F4820ec9cF5D8]
  │
  ├─4─▶ Mint bSTBL → bdbSTBL
  │      [bdbSTBL: 0xb0f8Fe96b4880adBdEDE0dDF446bd1e7EF122C4e]
  │
  ├─5─▶ Donation attack: directly transfer bSTBL to inflate exchange rate
  │
  ├─6─▶ Borrow ETH from bdbaoETH using inflated collateral
  │      [bdbaoETH: 0xe853E5c1eDF8C51E81bAe81D742dd861dF596DE7]
  │
  ├─7─▶ Repay inflated bdbSTBL position
  │
  ├─8─▶ Balancer → swap baoETH → WETH
  │      [Balancer Vault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │
  ├─9─▶ Uniswap V3: convert WETH → USDC/DAI
  │      [Uni Router V3: 0xE592427A0AEce92De3Edee1F18E0157C05861564]
  │
  └─10─▶ Repay Aave flash loan + realize profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract BaoExploit {
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 DAI = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IbSTBL bSTBL = IbSTBL(0x5ee08f40b637417bcC9d2C51B62F4820ec9cF5D8);
    IbdbSTBL bdbSTBL = IbdbSTBL(0xb0f8Fe96b4880adBdEDE0dDF446bd1e7EF122C4e);
    IAaveFlashloan aaveV2 = IAaveFlashloan(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    function testExploit() external {
        address[] memory assets = new address[](2);
        assets[0] = address(USDC);
        assets[1] = address(DAI);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 17_550_000e6;   // 17.55M USDC
        amounts[1] = 17_510_000e18;  // 17.51M DAI
        aaveV2.flashLoan(address(this), assets, amounts, new uint256[](2), address(this), "", 0);
    }

    function executeOperation(address[] calldata, uint256[] calldata amounts, uint256[] calldata premiums, ...) external {
        // Deposit into Aave
        // Enter Balancer pool → receive bSTBL
        // Mint bSTBL → bdbSTBL
        // Manipulate exchange rate via donation
        // Borrow ETH from bdbaoETH
        // Realize profit and repay flash loan
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Exchange Rate Manipulation, Donation Attack |
| Impact Scope | bdbSTBL, bdbaoETH leveraged positions |
| Explorer | [Etherscan](https://etherscan.io/address/0xb0f8fe96b4880adbdede0ddf446bd1e7ef122c4e) |

## 6. Security Recommendations

```solidity
// Fix 1: Use virtual price accounting to prevent donation attacks
contract bdbSTBL {
    uint256 private _virtualTotalAssets;  // ignores directly transferred tokens

    function mint(uint256 amount) external {
        uint256 shares = amount * totalSupply() / _virtualTotalAssets;
        _virtualTotalAssets += amount;  // tracked internally
        _mint(msg.sender, shares);
        IERC20(underlying).transferFrom(msg.sender, address(this), amount);
    }

    // Donated (directly transferred) tokens are NOT reflected in _virtualTotalAssets
    function exchangeRate() public view returns (uint256) {
        return _virtualTotalAssets * 1e18 / totalSupply();
    }
}

// Fix 2: Use TWAP-based exchange rate
uint256 private _lastRate;
uint256 private _lastUpdateTime;
uint256 constant RATE_UPDATE_INTERVAL = 1 hours;

function exchangeRate() public view returns (uint256) {
    // Returns the average rate over the last 1 hour (not manipulable in a single block)
    return _twapRate;
}
```

## 7. Lessons Learned

1. **Donation Attack Defense**: Exchange rate calculations that read directly from the contract balance are vulnerable to donation attacks. Internal accounting variables must always be used instead.
2. **Composability Attack Surface**: A combined attack chaining Aave + Balancer + Bao is difficult to detect at any individual protocol level.
3. **Leveraged Collateral Ratio**: Using a manipulable value in the collateral ratio calculation for leveraged positions enables excessive borrowing.
4. **ERC-4626 Standard**: Implementing vaults according to the ERC-4626 standard provides built-in protection against donation attacks.